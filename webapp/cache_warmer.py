"""Background SMC cache warmer (audit CE2 + M18, 2026-06-11).

Q6 from the caching plan, finally landed: a successful profile pick
(login auto-select, manual pick, or topbar Domain switch) spawns a
daemon thread that pre-fetches the active Domain's two hottest cache
sections:

* ``engines`` — backs /engines/clusters, the scan picker, the DHCP
  credentials cascade and the TLS deploy cascade.
* ``element_list.tcp_services`` — backs the scan-tool port picker and
  /browse/tcp_services, and feeds the quick-search index (M18 — the
  "fresh login → quick-search only finds menu items" surprise goes
  away because the cache is warm before the operator types).

Failure-tolerant by design: the warmer never raises into the request
path, never blocks login, and logs at INFO when SMC is unreachable.
Two rapid warms for the same Domain coalesce inside
``shared.smc_cache`` (H12 in-flight Future coalescing), so spawning
liberally is safe.
"""

from __future__ import annotations

import logging
import threading

log = logging.getLogger("cache_warmer")


def warm_active_domain_async(app, domain_slug: str) -> bool:
    """Spawn a daemon thread pre-fetching ``engines`` +
    ``element_list.tcp_services`` for the Domain with ``domain_slug``.

    ``app`` is the real Flask app object (callers inside a request pass
    ``current_app._get_current_object()``). Returns True when a warmer
    thread was started — purely informational.
    """
    if not domain_slug or app is None:
        return False

    def _run():
        try:
            with app.app_context():
                from webapp import domain_objects
                from webapp.models import Domain

                domain = Domain.query.filter_by(slug=domain_slug).first()
                if domain is None or domain.api_key is None:
                    return
                ak = domain.api_key
                cfg = {
                    "smc_url":      ak.smc_url,
                    "api_key":      ak.decrypted_key,
                    "verify_ssl":   bool(ak.verify_ssl),
                    "timeout":      int(ak.timeout or 120),
                    "domain":       domain.smc_domain_name or "",
                    "retry_on_busy": True,
                }
                try:
                    domain_objects.engines(domain, cfg)
                    log.info("cache warm: engines primed for domain %s",
                             domain_slug)
                except Exception as exc:
                    log.info("cache warm: engines fetch failed for %s: %s",
                             domain_slug, exc)
                try:
                    domain_objects.elements(domain, cfg, "tcp_services")
                    log.info("cache warm: tcp_services primed for domain %s",
                             domain_slug)
                except Exception as exc:
                    log.info("cache warm: tcp_services fetch failed for %s: %s",
                             domain_slug, exc)
        except Exception as exc:
            log.info("cache warm aborted for %s: %s", domain_slug, exc)

    threading.Thread(
        target=_run, daemon=True, name=f"smc-cache-warmer-{domain_slug}",
    ).start()
    return True
