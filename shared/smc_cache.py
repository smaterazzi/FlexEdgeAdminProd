"""
Process-local TTL cache for SMC reads — platform layer.

Why this exists
---------------
The smc-python SDK is slow on every read: listing engines, browsing
policies, walking interface trees, etc. — every call hits the SMC HTTP
API. Most of the data we read is stable for at least an hour at a time,
so we cache it per (tenant, domain, api_key) triple with a TTL.

Per the operator spec (2026-04-29):
  * Default TTL: 1 hour.
  * Max TTL:    24 hours (operator wants stale-data protection).
  * Per-section refresh button on every page that reads cached data.

The cache is process-local — gunicorn workers don't share it. With ``-w 2``
that means up to 2 cache misses per page on a fresh deploy; for a
single-operator admin tool that's fine. If we ever go multi-process at
real scale, swap the in-memory ``TTLCache`` for Redis behind the same
``cache_get_or_fetch`` interface.

Public API
----------
* ``cache_get_or_fetch(section, key_parts, fetcher, *, ttl, refresh)`` —
  returns a ``CachedValue(data, cached_at, served_from_cache, ...)``.
* ``invalidate(section, key_parts=None)`` — drop one entry or every entry
  whose key starts with ``section:``. Call after a write op (e.g. after
  bootstrapping a node, after pushing reservations) so the next read
  doesn't serve stale.
* ``invalidate_all()`` — global wipe. Used on profile / domain switch.
* ``stats()`` — diagnostic snapshot (size + hit/miss counts).

Standing pattern (memory: feedback_caching_pattern)
---------------------------------------------------
Every new platform feature that reads SMC data MUST go through this
helper, with:
  1. A logical section name (``"engines.list"``, ``"smc.explorer.hosts"``).
  2. A cache key including tenant_id + domain + api_key_hash so two
     tenants on the same SMC URL don't clobber each other.
  3. A refresh button surfaced in the UI (``?refresh=1``).
  4. A "served from cache · Nm ago" footer so the operator can see
     freshness at a glance.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from cachetools import TTLCache

log = logging.getLogger(__name__)

# Defaults from the operator spec.
DEFAULT_TTL = 3600          # 1 hour
MAX_TTL     = 86400         # 24 hours (cap; callers asking for more are clamped)
MAX_ENTRIES = 1024          # per section


# ── Named TTL levels (operator-facing labels) ────────────────────────────
#
# Two cache "speeds" the codebase picks at every call site. Naming is
# operator-facing: when discussing caching with Simone, talk about
# "Loose" vs "Quick" — not raw seconds.
#
#   LOOSE_REFRESH_TTL  ("Loose refresh", 24 h default)
#       For inventory data FlexEdge does NOT mutate (engine lists,
#       cluster details, policy lists, TLS settings on engines, scope
#       discovery results). The push runner auto-invalidates on writes
#       anyway, and the drift detector hook (Q11, planned) will drop
#       sections when out-of-band changes are detected — so even 24h
#       is rarely actually stale.
#
#   QUICK_REFRESH_TTL  ("Quick refresh", 1 h default)
#       For data FlexEdge DOES mutate through the queue (host /
#       network / service / group / fqdn elements, policy rules,
#       reservation Hosts). Short enough that operator edits feel
#       current even on the unlikely path where queue-runner
#       invalidation didn't fire.
#
# Both are operator-overridable through `platform_settings` keys
# `cache_ttl_loose_seconds` and `cache_ttl_quick_seconds`. The admin
# page at `/admin/cache-settings` exposes the form. Read once per
# process and memoised — call `reload_ttl_settings()` after a change
# to pick up the new values without a process restart.
#
# **TTL changes only affect newly-CREATED sections** (per the
# `_get_section_cache` semantics: TTL is set-and-stuck at section
# creation). Sections created before a setting change keep their
# original TTL until the process is restarted. The admin page
# documents this.

LOOSE_REFRESH_TTL = 24 * 3600   # 24 hours
QUICK_REFRESH_TTL = 1 * 3600    # 1 hour

# Memoised overrides — populated lazily on first access, cleared by
# `reload_ttl_settings()` after the operator saves a new value.
_loose_ttl_override: int | None = None
_quick_ttl_override: int | None = None
_overrides_loaded = False
_overrides_lock = threading.Lock()


def _read_platform_setting_int(key: str) -> int | None:
    """Read an integer from `platform_settings`. Returns None on any
    failure (DB not ready, row missing, value not an int) — caller
    falls back to the hard-coded default."""
    try:
        from webapp.models import PlatformSetting
        row = PlatformSetting.query.filter_by(key=key).first()
        if row and row.value:
            return int(row.value)
    except Exception:
        pass
    return None


def _ensure_overrides_loaded():
    global _loose_ttl_override, _quick_ttl_override, _overrides_loaded
    if _overrides_loaded:
        return
    with _overrides_lock:
        if _overrides_loaded:
            return
        _loose_ttl_override = _read_platform_setting_int(
            "cache_ttl_loose_seconds")
        _quick_ttl_override = _read_platform_setting_int(
            "cache_ttl_quick_seconds")
        _overrides_loaded = True


def _clamp_ttl(seconds: int) -> int:
    """Clamp a TTL into [60, MAX_TTL]. Anything below 60 s is treated
    as a typo / config bug and bumped up; anything above 24 h hits the
    hard cap."""
    return max(60, min(int(seconds), MAX_TTL))


def get_loose_ttl() -> int:
    """Effective Loose-refresh TTL, in seconds.

    Reads `platform_settings.cache_ttl_loose_seconds` once per process
    (cached). Falls back to ``LOOSE_REFRESH_TTL`` (24 h) when the
    setting is absent or the DB isn't available."""
    _ensure_overrides_loaded()
    base = _loose_ttl_override if _loose_ttl_override is not None else LOOSE_REFRESH_TTL
    return _clamp_ttl(base)


def get_quick_ttl() -> int:
    """Effective Quick-refresh TTL, in seconds.

    Reads `platform_settings.cache_ttl_quick_seconds` once per process
    (cached). Falls back to ``QUICK_REFRESH_TTL`` (1 h) when the
    setting is absent or the DB isn't available."""
    _ensure_overrides_loaded()
    base = _quick_ttl_override if _quick_ttl_override is not None else QUICK_REFRESH_TTL
    return _clamp_ttl(base)


def reload_ttl_settings():
    """Re-read the TTL overrides from `platform_settings` on the next
    `get_loose_ttl()` / `get_quick_ttl()` call. Existing cache sections
    keep their original TTLs (set-and-stuck per `_get_section_cache`);
    a process restart is needed for full effect on long-lived sections.
    Safe to call from a request handler after the operator saves a
    new value on `/admin/cache-settings`."""
    global _overrides_loaded
    with _overrides_lock:
        _overrides_loaded = False


# ── Result wrapper ───────────────────────────────────────────────────────

@dataclass
class CachedValue:
    """Wrapper returned by ``cache_get_or_fetch`` — bundles the actual
    data with metadata the renderer needs to surface freshness to the
    operator (badge + refresh button).
    """
    data: Any
    cached_at: datetime
    served_from_cache: bool
    section: str
    cache_key: str

    @property
    def age_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.cached_at).total_seconds()

    @property
    def age_minutes(self) -> float:
        return self.age_seconds / 60.0

    @property
    def age_hours(self) -> float:
        return self.age_seconds / 3600.0


# ── Section-keyed TTLCache pool ──────────────────────────────────────────

# Each section gets its own TTLCache so we can tune TTLs independently.
# Fragmenting the cache also means an explosion of one section can't
# evict entries from another (cachetools is LRU within a single instance).
_section_caches: dict[str, TTLCache] = {}
_section_locks: dict[str, threading.Lock] = {}
_global_lock = threading.Lock()

# H12 (audit fix-up, 2026-05-09): in-flight fetch coalescing.
# When N requests miss the same (section, key) in close succession the
# previous behaviour was to dispatch N independent fetchers — each
# acquiring the SMC global lock in turn. On a cold cache after a
# Domain switch this serialises gunicorn workers behind one fetch each,
# eating thread capacity. Now: the first arrival creates a Future and
# runs the fetcher; followers wait on the same Future. Only one SMC
# round-trip per coalesced burst.
_inflight: dict[str, "object"] = {}  # cache_key -> concurrent.futures.Future
_inflight_lock = threading.Lock()

# Diagnostic counters — read-only via stats().
_hit_count = 0
_miss_count = 0
_coalesced_count = 0  # H12: followers that piggy-backed on an in-flight fetch


def _get_section_cache(section: str, ttl: int) -> tuple[TTLCache, threading.Lock]:
    """Return (cache, lock) for ``section``, creating both on first use.

    ``ttl`` is set on first creation; subsequent callers using a different
    TTL keep the original. Section TTL is set-and-stuck — change it by
    editing the call site, not by passing different values per request.
    """
    with _global_lock:
        cache = _section_caches.get(section)
        if cache is None:
            ttl_clamped = max(1, min(int(ttl), MAX_TTL))
            cache = TTLCache(maxsize=MAX_ENTRIES, ttl=ttl_clamped)
            _section_caches[section] = cache
            _section_locks[section] = threading.Lock()
            log.info("smc_cache: created section %r ttl=%ds maxsize=%d",
                     section, ttl_clamped, MAX_ENTRIES)
        return cache, _section_locks[section]


def _build_key(section: str, key_parts) -> str:
    """Stable string key from a tuple of cache-key parts.

    Hashes the serialised parts so:
      * Sensitive values (raw API keys) never end up plaintext in the
        cache index — the caller should already pass a hash, but this is
        a second line of defence.
      * Very long values don't bloat memory.
      * Order is preserved (tuples → ``|``-joined string).
    """
    raw = "|".join(str(p) for p in key_parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"{section}:{digest}"


# ── Public read-through API ──────────────────────────────────────────────

def cache_get_or_fetch(section: str,
                       key_parts,
                       fetcher: Callable[[], Any],
                       *,
                       ttl: int = DEFAULT_TTL,
                       refresh: bool = False) -> CachedValue:
    """Cache-or-fetch primitive.

    Args:
      section: Logical bucket name. Use dotted-namespace style:
        ``"engines.list"``, ``"smc.explorer.hosts"``, ``"tls.engines"``.
        Each section has its own LRU + TTL.
      key_parts: Sequence of values that uniquely identify this entry
        within the section. Typical shape: ``(tenant_id, domain,
        api_key_hash)``. Use a HASH of the api key, never plaintext.
      fetcher: Zero-arg callable returning fresh data on miss/refresh.
        It runs OUTSIDE the section lock — long-running SMC calls do not
        block other lookups in the same section.
      ttl: Section TTL on first creation; ignored thereafter for that
        section. Default 1h, capped at 24h.
      refresh: If True, bypass the cache and the in-flight coalescer,
        fetch fresh, repopulate, and return ``served_from_cache=False``.
        Wire this to a query param like ``?refresh=1`` driven by an
        operator button.

    H12 (audit fix-up, 2026-05-09): concurrent non-refresh misses on the
    same key share one fetch. The first arrival claims an in-flight
    Future; followers block on `Future.result()` and pick up the same
    payload (or the same exception). Eliminates the cold-cache
    fan-in stampede where N gunicorn workers each acquired the SMC
    global lock for the same fetch. `refresh=True` always does its own
    fetch — explicit invalidations should not piggy-back on a stale
    leader's call.
    """
    from concurrent.futures import Future as _Future

    global _hit_count, _miss_count, _coalesced_count
    cache, lock = _get_section_cache(section, ttl)
    cache_key = _build_key(section, key_parts)

    if not refresh:
        with lock:
            cached = cache.get(cache_key)
        if cached is not None:
            data, cached_at = cached
            _hit_count += 1
            return CachedValue(
                data=data,
                cached_at=cached_at,
                served_from_cache=True,
                section=section,
                cache_key=cache_key,
            )

    # H12 — claim or join the in-flight slot. `refresh=True` skips this
    # entirely: an explicit invalidation should always do its own
    # network round-trip, never wait on a stale leader.
    leader_future = None
    leader = False
    if not refresh:
        with _inflight_lock:
            existing = _inflight.get(cache_key)
            if existing is not None:
                leader_future = existing
            else:
                leader_future = _Future()
                _inflight[cache_key] = leader_future
                leader = True

        if not leader:
            # Re-check the cache before blocking — the leader may have
            # finished + cleared the inflight slot between our two
            # lock acquisitions, in which case the value is now in
            # the section cache and we should serve from there.
            with lock:
                cached = cache.get(cache_key)
            if cached is not None:
                data, cached_at = cached
                _hit_count += 1
                return CachedValue(
                    data=data, cached_at=cached_at,
                    served_from_cache=True,
                    section=section, cache_key=cache_key,
                )
            _coalesced_count += 1
            log.debug("smc_cache: COALESCED key=%s — joining in-flight fetch",
                      cache_key)
            data, cached_at = leader_future.result()  # raises on leader fail
            return CachedValue(
                data=data, cached_at=cached_at,
                # The leader did the network round-trip; we still served
                # this caller from a fresh fetch (not a cache hit), so
                # served_from_cache=False is the honest answer.
                served_from_cache=False,
                section=section, cache_key=cache_key,
            )

    # Leader path (or refresh=True). Run the fetcher OUTSIDE both locks
    # so SMC I/O doesn't block other lookups or other in-flight slots.
    _miss_count += 1
    log.debug("smc_cache: %s key=%s", "REFRESH" if refresh else "MISS", cache_key)
    started = time.monotonic()
    try:
        fresh_data = fetcher()
    except BaseException as exc:
        # Surface the failure to any followers waiting on the Future.
        if leader and leader_future is not None:
            try:
                leader_future.set_exception(exc)
            except Exception:
                pass
        if leader:
            with _inflight_lock:
                _inflight.pop(cache_key, None)
        raise
    fetch_ms = int((time.monotonic() - started) * 1000)
    if fetch_ms > 1000:
        log.info("smc_cache: %s fetch took %dms (key=%s)",
                 section, fetch_ms, cache_key)

    cached_at = datetime.now(timezone.utc)
    with lock:
        cache[cache_key] = (fresh_data, cached_at)
    if leader and leader_future is not None:
        # Set result BEFORE releasing the inflight slot so any follower
        # that grabbed the Future before we cleared the dict still sees
        # the resolved future.
        try:
            leader_future.set_result((fresh_data, cached_at))
        except Exception:
            pass
        with _inflight_lock:
            _inflight.pop(cache_key, None)
    return CachedValue(
        data=fresh_data,
        cached_at=cached_at,
        served_from_cache=False,
        section=section,
        cache_key=cache_key,
    )


# ── Invalidation ─────────────────────────────────────────────────────────

def invalidate(section: str, key_parts=None) -> int:
    """Drop matching entries. Returns the number of entries removed.

    * ``section`` only: drops every entry in that section. Use after a
      mutation that may have changed the data shape (e.g. enrolling a
      node, pushing a policy, importing reservations).
    * ``section`` + ``key_parts``: drops the single entry. Use when you
      know exactly which (tenant, domain, key) was touched.
    """
    cache, lock = _get_section_cache(section, DEFAULT_TTL)
    with lock:
        if key_parts is None:
            n = len(cache)
            cache.clear()
            log.info("smc_cache: invalidated section %r (%d entries)",
                     section, n)
            return n
        cache_key = _build_key(section, key_parts)
        if cache_key in cache:
            del cache[cache_key]
            log.debug("smc_cache: invalidated %s", cache_key)
            return 1
        return 0


def peek(section: str, key_parts):
    """Return the cached payload for ``(section, key_parts)`` without
    triggering a fetch. Returns ``None`` on miss.

    Used by code paths that want to consume the cache *only* if it's
    already populated — e.g. quick-search needs to look up names
    scoped to the active Domain WITHOUT pulling in cross-Domain entries.
    Walking ``_section_caches`` directly is dangerous because cache
    keys are SHA-256 prefixes — you can't tell which Domain owns an
    entry without re-deriving its key.
    """
    if section not in _section_caches:
        return None
    cache = _section_caches[section]
    lock = _section_locks[section]
    cache_key = _build_key(section, key_parts)
    with lock:
        cached = cache.get(cache_key)
    if cached is None:
        return None
    return cached[0]


def list_sections() -> list[str]:
    """Snapshot of the section names that currently exist. Used by
    quick-search to enumerate ``element_list.<type_key>`` sections
    without poking inside ``_section_caches``."""
    with _global_lock:
        return list(_section_caches.keys())


def invalidate_all() -> int:
    """Drop every entry in every section.

    Called on profile/domain switch (the cached views were tied to the
    previous selection, so they're meaningless now).
    """
    total = 0
    with _global_lock:
        sections = list(_section_caches.items())
    for section, cache in sections:
        with _section_locks[section]:
            total += len(cache)
            cache.clear()
    log.info("smc_cache: global invalidate (%d total entries)", total)
    return total


# ── Diagnostics ──────────────────────────────────────────────────────────

def stats() -> dict:
    """Diagnostic snapshot for the future Admin → Logs / Settings page."""
    with _global_lock:
        sizes = {section: len(c) for section, c in _section_caches.items()}
    with _inflight_lock:
        inflight_count = len(_inflight)
    total_entries = sum(sizes.values())
    total_lookups = _hit_count + _miss_count
    return {
        "hits": _hit_count,
        "misses": _miss_count,
        "coalesced": _coalesced_count,
        "inflight_now": inflight_count,
        "hit_ratio": (_hit_count / total_lookups) if total_lookups else 0.0,
        "sections": sizes,
        "total_entries": total_entries,
    }
