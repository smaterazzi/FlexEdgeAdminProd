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

# Diagnostic counters — read-only via stats().
_hit_count = 0
_miss_count = 0


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
        block other lookups in the same section. (Two concurrent misses
        on the same key will both fetch; we accept that minor duplicate
        work in exchange for not holding the lock across SMC I/O.)
      ttl: Section TTL on first creation; ignored thereafter for that
        section. Default 1h, capped at 24h.
      refresh: If True, bypass the cache, fetch fresh, repopulate, and
        return ``served_from_cache=False``. Wire this to a query param
        like ``?refresh=1`` driven by an operator button.
    """
    global _hit_count, _miss_count
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

    # Miss / refresh — fetch live (outside the lock so SMC I/O doesn't
    # block other lookups in this section).
    _miss_count += 1
    log.debug("smc_cache: %s key=%s", "REFRESH" if refresh else "MISS", cache_key)
    started = time.monotonic()
    fresh_data = fetcher()
    fetch_ms = int((time.monotonic() - started) * 1000)
    if fetch_ms > 1000:
        log.info("smc_cache: %s fetch took %dms (key=%s)",
                 section, fetch_ms, cache_key)

    cached_at = datetime.now(timezone.utc)
    with lock:
        cache[cache_key] = (fresh_data, cached_at)
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
    total_entries = sum(sizes.values())
    total_lookups = _hit_count + _miss_count
    return {
        "hits": _hit_count,
        "misses": _miss_count,
        "hit_ratio": (_hit_count / total_lookups) if total_lookups else 0.0,
        "sections": sizes,
        "total_entries": total_entries,
    }
