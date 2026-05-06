"""SMC registry — lazy population of `smc_objects`.

Q21 (Round 3) decided: lazy-on-read backfill. Every SMC read path
(DHCP scope discovery, TLS engine list, explorer browse, etc.) calls
`register_smc_object_seen()` as a side-effect of fetching an element.
Within a few sessions of normal use the registry covers every SMC
element FEA actually touches; objects nobody touches stay untracked
(that's fine — drift detection in Phase G only needs to cover what we
care about).

Registry maintenance is best-effort: failures log but never propagate.
A read view that crashes because the registry write hiccupped would be
worse than a missing strikethrough on the next page load.

Public API
----------

  register_smc_object_seen(domain, smc_type, smc_href, smc_name,
                           managed_by_flexedge=False)
    Upsert one row by `(domain_id, smc_href)`. Updates `last_seen_at`
    on existing rows; sets `managed_by_flexedge=True` only if the
    caller asserts it (we never *downgrade* a row from True → False).

  register_many(domain, items)
    Batched form for readers that fetch lists. Same upsert semantics
    per-item; commits once at the end.

Both helpers can be called inside or outside a request context. They
look up `g.domain` if `domain` is None.
"""

import logging
from typing import Iterable, Optional

log = logging.getLogger(__name__)


def _resolve_domain(domain):
    """Pick the active Domain when caller passes None.

    Returns the Domain instance or None if we're out-of-band.
    """
    if domain is not None:
        return domain
    try:
        from flask import g, has_request_context
        if has_request_context():
            return getattr(g, "domain", None)
    except Exception:
        pass
    return None


def register_smc_object_seen(domain, smc_type: str, smc_href: str,
                             smc_name: str = "",
                             managed_by_flexedge: bool = False,
                             last_seen_hash: str = "") -> None:
    """Upsert one row in `smc_objects`. Best-effort.

    Args:
      domain: Domain instance, or None to use `g.domain`.
      smc_type: e.g. 'host', 'engine', 'policy', 'rule', 'service'.
      smc_href: SMC-side identity (URL path under the SMC API root).
      smc_name: human-readable element name; updated on every call.
      managed_by_flexedge: True only when FEA created/owns this object.
        Existing True flag is never downgraded to False.
      last_seen_hash: optional digest of the element payload — populated
        when the caller has it cheap (typically the SMC SDK's `data`
        attribute). Drift detection in Phase G compares this against a
        fresh fetch.
    """
    if not smc_href:
        return
    domain = _resolve_domain(domain)
    if domain is None:
        return

    try:
        from shared.db import db
        from webapp.models import SmcObject
        from datetime import datetime, timezone

        existing = (SmcObject.query
                    .filter_by(domain_id=domain.id, smc_href=smc_href)
                    .first())
        now = datetime.now(timezone.utc)

        if existing is None:
            row = SmcObject(
                domain_id=domain.id,
                smc_href=smc_href,
                smc_type=smc_type or "",
                smc_name=smc_name or "",
                managed_by_flexedge=bool(managed_by_flexedge),
                last_seen_at=now,
                last_seen_hash=last_seen_hash or "",
            )
            db.session.add(row)
        else:
            if smc_type and not existing.smc_type:
                existing.smc_type = smc_type
            if smc_name and existing.smc_name != smc_name:
                existing.smc_name = smc_name
            existing.last_seen_at = now
            if last_seen_hash:
                existing.last_seen_hash = last_seen_hash
            if managed_by_flexedge and not existing.managed_by_flexedge:
                existing.managed_by_flexedge = True

        db.session.commit()
    except Exception as exc:
        try:
            from shared.db import db
            db.session.rollback()
        except Exception:
            pass
        log.debug("smc_registry: register_smc_object_seen failed "
                  "(type=%s, href=%s): %s", smc_type, smc_href, exc)


def register_many(domain, items: Iterable[dict]) -> int:
    """Batched upsert. Returns the count of rows touched.

    Each `item` is a dict::

        {"smc_type": "host", "smc_href": "...", "smc_name": "...",
         "managed_by_flexedge": False, "last_seen_hash": "..."}

    `smc_type` and `smc_href` are required; the rest are optional.
    Commits once at the end. Best-effort — failures log + swallow.
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return 0

    touched = 0
    try:
        from shared.db import db
        from webapp.models import SmcObject
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        for item in items:
            href = (item.get("smc_href") or "").strip()
            if not href:
                continue
            smc_type = (item.get("smc_type") or "").strip()
            smc_name = (item.get("smc_name") or "")
            managed = bool(item.get("managed_by_flexedge"))
            last_hash = item.get("last_seen_hash") or ""

            existing = (SmcObject.query
                        .filter_by(domain_id=domain.id, smc_href=href)
                        .first())
            if existing is None:
                db.session.add(SmcObject(
                    domain_id=domain.id, smc_href=href,
                    smc_type=smc_type, smc_name=smc_name,
                    managed_by_flexedge=managed,
                    last_seen_at=now, last_seen_hash=last_hash,
                ))
            else:
                if smc_type and not existing.smc_type:
                    existing.smc_type = smc_type
                if smc_name and existing.smc_name != smc_name:
                    existing.smc_name = smc_name
                existing.last_seen_at = now
                if last_hash:
                    existing.last_seen_hash = last_hash
                if managed and not existing.managed_by_flexedge:
                    existing.managed_by_flexedge = True
            touched += 1
        db.session.commit()
    except Exception as exc:
        try:
            from shared.db import db
            db.session.rollback()
        except Exception:
            pass
        log.debug("smc_registry: register_many failed (%d items): %s",
                  touched, exc)
        touched = 0
    return touched


def get_to_be_deleted_set(domain=None) -> set:
    """Return the set of (href, name) flagged is_to_be_deleted in this Domain.

    Used by the Q12 strikethrough Jinja helper. Returns an empty set on
    any failure (out-of-band, no Domain, table missing).
    """
    domain = _resolve_domain(domain)
    if domain is None:
        return set()
    try:
        from webapp.models import SmcObject
        rows = (SmcObject.query
                .filter_by(domain_id=domain.id, is_to_be_deleted=True)
                .with_entities(SmcObject.smc_href, SmcObject.smc_name)
                .all())
        out = set()
        for href, name in rows:
            if href:
                out.add(href)
            if name:
                out.add(name)
        return out
    except Exception:
        return set()
