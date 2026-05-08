# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.2.0-dev] - 2026-04-29 → 2026-05-08

### Caching rollout phase 1: engines.detail + tools_scan inventory share (2026-05-08)

TODO-item-2 phase 1 — first slice of the engine-objects caching plan.
Operator-confirmed picks (TODO.md Round 2): TTL rule = "by FlexEdge
write-or-not" (B); Refresh button placement = per-page; Refresh
scope = family-wide.

- **`engines.detail` section** — `/engines/clusters/<engine>` now goes
  through `cache_get_or_fetch` ([webapp/engines_manager.py:cluster_detail](webapp/engines_manager.py)).
  Cache key `(domain_id, engine_name)`, TTL 24 h (read-only inventory
  per Q1.B). Refresh button + freshness footer added to
  [webapp/templates/engines/cluster_detail.html](webapp/templates/engines/cluster_detail.html).
- **`engines.list` shared by Tools/Scan** — the GET handler at
  `/engines/tools/scan` previously opened its own SMC session and
  re-fetched the cluster list. Now reads from the same `engines.list`
  cache as `/engines/clusters` (key `(domain_id,)`, TTL 24 h). Refresh
  button added to the Tools/Scan picker. Eliminates a redundant SMC
  fetch when the operator navigates Clusters → Tools/Scan.
- **Family-wide refresh** — `engines.list?refresh=1` (from either
  Clusters or Tools/Scan) now also invalidates the entire
  `engines.detail` section. Operator's mental model is "give me
  current data on the whole engines feature" — no surprise stale
  per-engine page after a top-level refresh.
- **Forget extended** — `cluster_forget` now drops both `engines.list`
  AND the engine's `engines.detail` entry, since Forget is the
  "I'm done with this engine" signal.

Scoping note: the TLS deploy form's "engine cascade" calls a
different function (`smc_tls_client.list_engines` — multi-stage
discovery, dict shape) than `engine_inquiry.list_clusters`. It will
get its own `tls.engines` section in the TLS rollout step (step 6
in TODO.md), not consolidated with `engines.list`.

Remaining caching work (separate commits): `smc.explorer.<type>`,
`smc.policy.<name>`, `dhcp.scopes.<engine>`, `dhcp.host.<name>`,
TLS sections; plus background warming on login (Q6) and drift-
detector → cache invalidation hook (Q11).

### Fix: BuildError on Tools/Scan + 5 other broken `dhcp.credentials` refs (2026-05-08)

The credentials route is `dhcp.credentials_list`, not `dhcp.credentials`.
Six call sites used the wrong endpoint name and would raise
`werkzeug.routing.BuildError` whenever the `url_for` evaluated:

- `webapp/templates/engines/tools_scan.html` — two banners I added today
  for credential-gating; pages crashed when the inventory was filtered
  to zero or any clusters were hidden.
- `webapp/templates/dhcp/scopes.html` — two banners I added today for
  the same reason.
- `webapp/engines_manager.py` — pre-existing breakage in
  `/engines/credentials` redirect (line 383) and the terminal route's
  unverified-credential redirect (line 943). Both unreachable from
  the happy path so they hadn't surfaced before.

All six fixed to `dhcp.credentials_list`.

### Stale-form detection for DHCP + Credentials POSTs (2026-05-08)

TODO-item-3 — fixes the cryptic "Refresh failed: no enrollment record
for engine 'X' on domain 'Y'" error users hit after switching the
topbar Domain selector.

**Root cause.** Many `/dhcp/credentials/*` and `/dhcp/scopes/discover`
routes still POST a legacy `tenant_id` (and sometimes `api_key_id`)
hidden field that's baked into the page HTML at render time. After
the operator switches Domain in the topbar, any AJAX form still in
the DOM (wizard buttons, refresh-state, modals) submits with the OLD
context. The pre-Multi-Domain-Revamp resolution path
(`Domain.query.join(ApiKey).filter(ApiKey.tenant_id == form_tid)`)
sometimes coincidentally resolved to the *new* session Domain,
producing the unhelpful "no enrollment record for X on Y" downstream
when the engine actually only existed in the OLD Domain's data.

**Fix.** New helper `_check_stale_form_or_response()` in
[webapp/dhcp_manager.py](webapp/dhcp_manager.py) compares the form's
`tenant_id` / `api_key_id` against `g.domain.id`,
`g.domain.api_key.tenant_id`, and `g.domain.api_key.id`
(authoritative). On mismatch, refuses with a clear message —
HTTP 409 + JSON for AJAX (`code: stale_form`), flash + redirect for
form POSTs:

> This page was loaded for a different Domain than the one currently
> active in the topbar. Reload the page and try again — the form
> data references stale context.

Applied at the entry of every form-tenant_id route (11 sites): scope
discover; credentials refresh / discover-nodes / rule install /
policy install / rule remove; drift recovery overwrite / add; per-node
bootstrap / force-reset / bulk-bootstrap. Form fields stay (existing
downstream code reads them); the helper is a guard that fires before
domain mis-resolution can happen.

The detection is permissive on the form value's *name* — templates
sometimes send `tenant_id` carrying a real `Tenant.id`, sometimes
carrying a `Domain.id` (the credentials.html template historically
conflated `tid` with `c.domain_id`). Both interpretations are
accepted as valid when they match the active session; only when
*neither* matches do we flag stale.

Operator-visible improvement: instead of being told an engine doesn't
exist when it visibly does on screen, they now get a clear "your page
is out of sync, reload" message that points at the actual cause.

### Credential-gated visibility across DHCP and Tools/Scan (2026-05-08)

TODO-item-1 — operator-facing pages now hide engines/scopes that have
no fully-verified SSH credentials in the active Domain. Hard-filter
style (entries are removed, not greyed-out); admins can reveal them
for cleanup via `?show_all=1`.

**Validity rule** (in `webapp/engine_credentials.py`):

- New helpers `is_engine_credentials_valid(domain_id, engine_name)`
  and `valid_engines_for_domain(domain_id)`.
- "Valid" = at least one credential row exists AND every credential
  row for the engine has `last_verify_status='ok'`. Partial enrolment
  (cluster has 2 nodes but only 1 enrolled) can't be detected from
  the DB alone — accepted trade-off, the bulk-enroll workflow always
  covers every node.

**Where the gate fires:**

| Surface | Behaviour |
| --- | --- |
| `/dhcp/scopes` | Filters out scopes whose engine isn't valid; shows a `+N hidden` info banner with **Show all** escape hatch (`?show_all=1`) for cleanup. Empty state explains the situation when every scope is hidden. |
| `/dhcp/scopes/<id>` and every operation behind it (leases viewer, subnet scan, Phase-4 deploy/preview/resync, reservation new/edit/bulk-delete, leases-→-reservation promote) | Redirect to `/dhcp/scopes` with a flash. New helper `_scope_with_creds_or_redirect()`; pure-FlexEdge ops (`enable` / `disable` / `delete` / `sync`) keep the lenient `_scope_or_404()` so admins can still clean up stale rows. |
| `/engines/tools/scan` GET | Cluster inventory filtered to valid engines. Banner reports the hidden count and points at `/dhcp/credentials`. Empty-state copy when zero engines pass. |
| `/engines/tools/scan` POST | Server-side gate refuses if `engine_name` isn't valid. Defence in depth — a direct curl can't bypass the GET filter. |
| Terminal | Already correctly per-node gated (template button disabled, HTTP route guard, WebSocket handshake). No change. |
| sgInfo collection (cluster_detail "Collect" button) | **Exempt.** Rides the SMC management channel, doesn't need SSH. |

### UI: top-center search bar, pinned bookmarks, evident sidebar sections (2026-05-08)

Three quality-of-life improvements landing together in
[webapp/templates/base.html](webapp/templates/base.html):

- **Sidebar section labels are now obvious.** Bumped from `0.7rem
  #6b7280` (gray-on-gray, lost against the sidebar bg) to
  `0.78rem #d1d5db` **bold**, with a top border separating each
  section + extra top padding. The `.nav-link` font shrank to
  `0.86rem` so the section header visually dominates its items.
  First-section border is masked so the sidebar doesn't open with a
  stray line. Operators stop hunting for which section a feature
  belongs to.
- **Top-center quick search** with `Cmd/Ctrl+K` to focus from
  anywhere. Debounced 200 ms; queries `<2` chars don't fire. Results
  group **Features** (every menu destination, label/href/icon
  curated server-side) and **Cached SMC elements** (best-effort walk
  of `shared.smc_cache._section_caches` for items with a `name`
  field — translated to navigable URLs: `smc.explorer.<type>` →
  `/browse/<type>`, `engines.list` → `/engines/clusters`). Arrow
  keys + Enter navigate; Esc / outside-click closes. Backed by the
  new `GET /api/quick-search?q=...` endpoint (admin-protected,
  capped at 30 results, deduped).
- **Pinned bookmarks bar.** Star button on the topbar pins the
  current page (label inferred from the active sidebar entry or
  document title; icon inherited from the active link). Pin chips
  render in a thin bar between topbar and content; each has an X to
  remove. localStorage-backed (`flexedge_pins_v1`), per-browser, max
  12 (FIFO past that). Bar self-hides when empty. Star icon flips
  to `bi-star-fill` (yellow) when the current page is pinned.

No backend schema change. No new dependency. ~150 LoC across one
template file + 80 LoC for the search endpoint.

### Domain-Scoping audit + 7 fixes (2026-05-08)

Spec: [docs/DomainScopingAudit.md](docs/DomainScopingAudit.md). The
operator's mental model is "the topbar Domain selector controls
everything I see"; the audit surfaced six places where that wasn't
strictly true and one where the audit-trail couldn't tell you who did
what. All seven landed in this commit batch.

| # | Severity | Location | Fix |
| - | -------- | -------- | --- |
| D1 | **HIGH** — direct exfil via URL crafting | 4 DHCP cascade endpoints `/dhcp/api/tenants/<tid>/api-keys/...` | New `_assert_active_domain_match(tid, kid)` helper at the top of [webapp/dhcp_manager.py](webapp/dhcp_manager.py); 403 if URL IDs don't match `g.domain.api_key_id` / its tenant. |
| D2 | **MEDIUM** — cross-Domain data loss | DHCP `sweep_old_logs` and `cli/sweep_dhcp_logs.py` | New `domain_id` parameter on the sweeper (and on `shared.logging.sweep_old_logs`). Web button scopes to active Domain; CLI iterates every Domain explicitly so each gets its own audit row. New `--domain <slug>` flag for targeted sweeps. |
| A | LOW (defense-in-depth) | `webapp/app.py:1915` `_load_submission_in_active_domain` | `OptimizationSubmission.query.filter_by(id=sub_id, domain_id=g.domain.id).first_or_404()` — filter at query level instead of post-load check. |
| B | MEDIUM — log visibility leak | `webapp/app.py` `view_logs` | Removed the "show all my Domains" widen branch entirely. `/logs` is now strictly scoped to the active Domain (system-feature rows with `domain_id IS NULL` still visible — they're domain-agnostic bootstrap markers). Toggle removed from the template. |
| C | MEDIUM — visibility leak | `webapp/tls_manager.py` 3 cert listing routes | New `_certs_in_active_domain(domain_id)` helper using a `TLSDeployment` subquery (Path I, no schema change). Dashboard + certificates list scoped to it. Deploy form's cert dropdown intentionally NOT scoped (write-side picker; chicken-and-egg if you've never deployed in this Domain yet) — comment explains. |
| D3 | LOW (defensive comment) | `webapp/migration_dhcp_writer.py` | `DhcpReservation` has no `domain_id` column — Domain inherits via `scope_id → DhcpScope.domain_id`. Added a defense-in-depth note at the insert site so future refactors don't try to add a `domain_id=` kwarg to a column that doesn't exist. |
| E2 | Audit-trail gap | `webapp/tls_scheduler.py` `handle_renewal_webhook` | Bucket renewal results by `dep.domain_id`; emit one `audit("tls", "renew.cross_domain", ...)` row per affected Domain with the `engines=[...]` list and `deployed/failed/skipped` counts. Operators reading `/logs` in their Domain see exactly the renewals that touched THEIR engines, not a cryptic global "the cert renewed" line. |

Plus three secondary fixes folded into the same batch after the user
flagged related leaks:

- DHCP `credentials_list`, DHCP `scopes_list`, TLS `deploy_form` —
  the "Tenant" dropdown narrowed from `Tenant.query.all()` to just
  the one Tenant bound to the active Domain's API key. Operator
  never sees another Domain's Tenant in any picker.
- `/dhcp/scopes/<id>/leases` no longer redirects to `/dhcp/credentials`
  when no SSH credentials are enrolled. The route now renders the
  leases page in place with an inline empty-state alert that names
  the active Domain so a "creds enrolled under another Domain"
  mismatch becomes visible at a glance, plus a one-click button to
  the credentials wizard. Operator stays in their context.
- Browser link to `/browse/l3_firewalls` (Infrastructure → "Layer-3
  Firewall Engines") relabeled to "Engines" and hard-redirects to
  `/engines/clusters`. The legacy SDK-class-filtered explorer only
  showed the `Layer3Firewall` subclass, missing clusters / virtual
  engines / IPS / masters; the dedicated Engines page covers
  everything.

Intentionally cross-Domain (no change): admin portal Tenants /
Users / API Keys / Domains pages (Super Admin infrastructure
management), TLS certbot renewal webhook (host-level, fires across
Domains by design).

### Web UX hardening: AJAX error transparency + auth-redirect bounce (2026-05-08)

Two related fixes. Symptom that motivated them: operators seeing
*"Failed at stage network: SyntaxError: Unexpected token '<', '<!doctype'... is not valid JSON"*
in the credentials wizard whenever the server returned an HTML
response (Flask's default 500 page or the login redirect) to an
AJAX call.

- **`window.fetch` patch** in
  [webapp/templates/base.html](webapp/templates/base.html). When the
  response was redirected to `/login` or `/auth/`, OR the status is
  `401` / `403`, redirect the page to `/login?next=<current>` and
  throw so any caller `.catch` fires. Skip the bounce if we're
  already on a login-ish path (avoids loops). Patches `window.fetch`
  itself rather than only `fexFetch`, so raw `fetch(...)` callers
  (graph, scan watchers, TLS deploy form, DHCP credentials, etc.)
  benefit without per-template edits.
- **Generic AJAX exception handler** in
  [webapp/app.py](webapp/app.py). When any uncaught exception or
  `HTTPException` fires inside a request that looks AJAX
  (`X-Requested-With: XMLHttpRequest` or `Accept: application/json`),
  return JSON like `{"error": "TypeError: ...", "code": 500}`
  instead of Flask's HTML debug page. Non-AJAX requests fall through
  to the default HTML rendering. **Beneficial side-effect:** the
  pre-existing `tcp_probe` `NameError` in `credentials_apply` (top-
  level import was missing) is now visible as a clean error message
  instead of Flask's HTML 500 page that JS choked on. Fixed the
  import too: `tcp_probe` is now in the module-level
  `from webapp.dhcp_ssh import ...` block.

### Queue runner: SMC error humanizer (2026-05-08)

[shared/queue_runner.py](shared/queue_runner.py) `_mark_push_failed`
now runs the raw SMC error through `_humanize_smc_error()` before
persisting to `pending_changes.push_error_text` and the audit log.
First pattern covered: policy lock contention. Patterns matched
(case-insensitive substrings on the SMC error string):

- `policy is locked`
- `is currently locked`
- `currently locked by`
- `locked by another`
- `locked by user` / `locked by the user`
- `cannot obtain lock`
- `lock is owned by`
- `unable to obtain lock`

Any of those triggers prepended remediation:
*"Policy is locked by another SMC session — somebody is currently
editing it in SMC Management Client (or another automation holds the
lock). Ask the holder to commit or discard their changes, then retry
this row from /changes/. [raw: ...]"*. Raw SMC string preserved at
the end so debugging stays sharp. Anything unmatched falls through
unchanged. Single chokepoint means **every** queue handler — `install_ssh_rule`, `deploy_tls`, `create_*`, `update`, `upload_policy`, anything future — automatically inherits the friendlier message.

### Engines → Tools → Scan: VLAN sub-interface picker fix (2026-05-08)

The cascading interface picker on `/engines/tools/scan` was missing
every VLAN sub-interface — only physical parent interfaces appeared
in the dropdown. Three layers of bug, one root cause: the SDK
`PhysicalInterface.data.data` returns the SMC payload, but
`engine_inquiry._walk_interfaces` was reading `pi.data` directly
(without the second `.data` unwrap), then keying VLANs by a
`vlan_id` field that doesn't exist (the SDK encodes the VLAN id
inside the entry's `interface_id` as `"1.42"`).

Fixes in [webapp/engine_inquiry.py](webapp/engine_inquiry.py):

1. Unwrap `pi.data.data` like
   [webapp/smc_dhcp_client.py](webapp/smc_dhcp_client.py) already
   does for DHCP scope discovery.
2. Read VLAN identity from the entry's composite `interface_id`
   (`"1.42"`) and split on `.` to get `(parent_id="1", vlan_id="42")`.
3. Handle wrapped payloads (`{"physical_interface": {...}}`) +
   snake_case `vlan_interfaces` key variant — same defensive
   pattern as DHCP.

[webapp/engines_manager.py](webapp/engines_manager.py)
`api_cluster_interfaces` deduplicates on the composite
`(interface_id, vlan_id)` key (was just `interface_id`, which
collapsed every VLAN into the parent) and sorts iface-then-vlan
numerically. The picker form gains a hidden `vlan_id` input that
the JS syncs from each option's `data-vlan-id` so the scan-start
POST has both halves of the composite key.

Same fix benefits the cluster_detail Interfaces tab — VLAN IDs
finally render in their column.

### Engines → Tools → Scan history (Phases 1-3 of the spec) (2026-05-08)

Spec: [docs/Engines-ScanHistory.md](docs/Engines-ScanHistory.md).
Three phases of the four-phase plan landed in one session.
Phase 4 (scheduler) is deferred to a focused commit so the
in-process ticker thread under multi-worker gunicorn can be
lab-validated without entangling the rest of the work.

**Phase 1 — persistence + history list + detail + retention.**

- Two new tables in [webapp/models.py](webapp/models.py):
  `engine_scan_records` (one row per scan; comment, starred,
  source_correlation, scope keys, summary stats), `engine_scan_hosts`
  (one row per IP per scan with `ip_int` for numeric sort, port CSVs
  for compact storage). `db.create_all()` picks them up; no manual
  migration.
- New re-usable sub-package `webapp/scan_history/` with one public
  service API: `register_scan(domain, report, ...)`,
  `list_scans(domain, ...)`, `get_scan(domain, id)`, `set_comment`,
  `set_starred`, `delete_scan`, `bulk_set_starred`, `bulk_delete`,
  `get_settings`, `set_settings`. Any future feature that produces
  an `EngineScanReport`-shaped dataclass plugs in via
  `register_scan` and gets the entire UI for free.
- Routes at `/engines/scans/*` (Blueprint at
  [webapp/scan_history/routes.py](webapp/scan_history/routes.py)):
  history list with filters (engine / iface / starred / date) +
  bulk star + bulk delete + retention form, detail view with comment
  editor + star toggle + CSV export + IP-numeric-sorted host table
  with live filter, manual sweep button.
- Retention rotation: count or days mode (default `count = 20`,
  per-scope), starred always survive. Lazy hourly sweep fires when
  someone visits the history page.
- `engines_manager.tools_scan` wired to call `register_scan` on
  scan complete and redirect to `/engines/scans/<id>` so the
  operator lands on a URL that survives the in-memory 15-min TTL.
- Audit feature `engine_scan_history` registered in
  [webapp/app.py](webapp/app.py); every state change emits
  `audit("engine_scan_history", "scan.persist|comment|star|unstar|delete|retention.sweep|settings.update", ...)`.
- Engines sidebar gains "Scan history" sub-entry.

**Phase 2 — compare 2-10 scans of the same scope.**

- New [webapp/scan_history/compare.py](webapp/scan_history/compare.py)
  with pure-diff helpers: `CompareReport`, `HostTimeline`,
  `HostCell` dataclasses; `compare_scans(domain, ids)` fetches
  records + hosts in two queries, scope-checks `(engine, iface)`,
  sorts ASC by `started_at`, computes per-host port-set deltas vs
  the nearest previous-seen cell.
- `GET|POST /engines/scans/compare` accepts `scan_ids[]` from a
  POST form OR `?ids=1,2,3` for deep-linkable URLs.
- Compare button on the history list, with selection-aware JS:
  enabled only when 2-10 rows selected AND all share `(engine,
  iface)`. Cross-scope selection keeps it disabled with explanatory
  tooltip.
- Compare template: sticky-header table, IP rows × scan columns,
  reachability badges + open-port set with `+22` (newly open) /
  `−3389` (closed since previous) / `new` (first sighting) /
  `gone` (host disappeared) markers. "Diff only" toggle hides
  unchanged rows.

**Phase 3 — time graph.**

- New [webapp/templates/scan_history/graph.html](webapp/templates/scan_history/graph.html)
  with a vanilla SVG line renderer (~250 lines of JS, zero deps).
  Two series: *Online IPs* (solid green) + *Hosts w/ open* (dashed
  cyan). Per-point markers: ⭐ for starred, triangle for scheduled,
  dot for manual. Hover tooltip shows ts / scan id / counts /
  engine / iface / source / comment. Click any point → deep-link
  to `/engines/scans/<id>`. Auto-resize on window resize.
- `GET /engines/scans/graph` (HTML page) +
  `GET /engines/scans/graph.json` (data feed) — both honor
  `?engine=&iface=&days=` filters.
- New `aggregate_for_graph(domain, ...)` helper on the service layer.
- Vanilla SVG instead of Chart.js: zero deploy steps for the
  operator (no vendor download), works air-gapped, full control over
  click-through + per-point markers. Honors the
  `feedback_deployment_scenarios` standing rule (vendor functional
  assets locally — by avoiding the dependency entirely).
- "Time graph" sub-entry in the Engines sidebar.

### Engines → Tools → Scan landed (2026-05-07)

Engine-level network scan tool — pick a node + interface from the
cascading picker, run an active-discovery sweep against any target
range from that interface's vantage point. Operator guide:
[docs/Engines-ScanTool.md](docs/Engines-ScanTool.md). Plan-to-live
delta: ~5 h, no new external dependencies.

- **Decision blocker resolved.** Forcepoint NGFW BusyBox does NOT
  ship `nmap`, but `nc -z` (TCP zero-I/O scan), `nslookup`, `arping`,
  `ip neighbor show`, and `ip route get` are all there. The full
  feature builds on the existing tools — no static binary to bundle.
- **Generic background-job runtime** in
  [webapp/scan_jobs.py](webapp/scan_jobs.py): module-local `_JOBS`
  dict + `threading.Lock` + 15-min TTL eviction + per-user ownership
  check. Public API: `register_job` / `update_progress` /
  `increment` / `append_log` / `mark_done` / `mark_failed` /
  `spawn_runner` / `get_status` / `consume_report` / `discard`.
- **DHCP scan refactored.** [webapp/dhcp_scan_jobs.py](webapp/dhcp_scan_jobs.py)
  is now a thin wrapper around the shared runtime. Public API
  unchanged — DHCP routes import unchanged. Runtime is now
  feature-agnostic.
- **Engine scanner** [webapp/engine_scan.py](webapp/engine_scan.py):
  4-phase shell script — Phase 1 ICMP (parallel ping +
  `ip neighbor show` for MAC), Phase 2 arping fallback for
  ICMP-failed (L2 visibility), Phase 3 port scan (`nc -z -w1` per
  reachable IP × port), Phase 4 reverse DNS (`nslookup`). Output
  streams line-by-line for live progress. `parse_port_list()`
  handles comma / whitespace / range syntax (`1-1024`).
- **Routes** in [webapp/engines_manager.py](webapp/engines_manager.py):
  - `GET /engines/tools/scan` — picker / watcher / results dispatch
  - `POST /engines/tools/scan` — validate, build IP list, enforce
    caps + warn threshold, kick off background job
  - `GET /engines/tools/scan/status?id=X` — JSON poll target
  - `GET /engines/api/clusters/<engine>/interfaces` — cascading
    picker JSON: nodes (with `verified` flag) + interfaces (with
    attached subnet)
  - `GET /engines/tools/scan/<id>/csv` — export results as CSV
- **Template** [webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html):
  cluster→node→interface cascading picker (backed by the JSON
  endpoint), target-mode radio (subnet / single IP / custom range),
  ports input pre-filled with the curated default + reset/clear
  shortcuts + skip-port-scan checkbox, JS op-count estimator with
  warning gate, watcher card identical to DHCP scan, result table
  with ICMP / MAC / hostname / open-port columns + 5 filter buttons
  with live counters + click-to-sort + CSV export.
- **Default port set (TCP-only, locked):** 25 ports —
  `20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 389,
  443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080`.
  /24 × default = 6,375 ops, fits under the 8000 warn threshold.
  UDP probing intentionally NOT supported in v1.
- **Limits:** 4096 hosts cap (= /20), 256 ports cap, 8000 ops soft
  warn, 16384 ops hard cap.
- **Audit** via `audit("engines", "scan_started" / "scan_complete",
  ...)` with the scan_id as `source_correlation_id`.

### Policy rules viewer: section detection fix + full-text search (2026-05-07)

- **Sections were silently rendered as rules.** The detection in
  `get_policy_rules` / `get_policy_nat_rules` checked
  `"section" in rule.typeof.lower()`, but in `fp-NGFW-SMC-python`
  v1.x both rules AND sections share the same `typeof`
  (`fw_ipv4_access_rule` / `fw_ipv4_nat_rule`). Sections are
  distinguished by data shape: they lack `sources` / `destinations`
  / `services` and carry their label in `comment` (where
  `create_rule_section(name=...)` writes it). The check now uses
  `Rule.is_rule_section` (the SDK's documented property) with a
  data-dict shape fallback for older SDK builds. Section headers
  render correctly again on `/policy/<name>`.
- **Full-text search bar** added to the policy rules viewer with
  the same UX as the Engines cluster-detail search: AND / OR token
  grammar (case-insensitive, mixed → AND), matched substrings
  highlighted in-place via `<mark.search-hit>`, rule + section
  counters update to "M of N" while a query is active. Section
  headers stay visible when any rule under them matches OR when
  the section name matches — preserves operator context. Esc
  clears, × button on the input, debounced 80 ms.

### DHCP Manager: subnet active-discovery scan (2026-05-07)

Active-discovery sweep that turns the **Active leases** page into a
richer view showing every device on the subnet, not just the ones
holding a DHCP lease. Operator guide:
[docs/DHCP-SubnetScan.md](docs/DHCP-SubnetScan.md).

- **New "Scan subnet" button** on `/dhcp/scopes/<id>/leases`. Opens a
  range-picker modal with three radio options:
  - **Scope (pool only)** — `dhcp_pool_start … dhcp_pool_end`. Default
    when subnet > /24.
  - **Full subnet** — every host in the CIDR minus
    gateway/network/broadcast. Default when subnet ≤ /24.
  - **Custom range** — operator-typed start/end IPs, server-validated
    to fit inside the subnet.

  Anything resolving to >256 hosts requires a confirmation checkbox.
  Hard cap at 4096 hosts (= /20) refuses /16 sweeps.
- **Async + live progress.** POST `/scan` starts a background daemon
  thread, redirects to `/leases?scan_id=X` which renders a watcher
  card (progress bar + 10-line rolling log). JS polls
  `/scan/status` every 800 ms; on `state=done` the page reloads with
  `?scan_id=X` so the leases route consumes the report and renders
  the enriched view.
- **6-state classifier.** Joining the scan results with
  `dhcpd.leases`, every IP is classified into:
  - `active` — lease + ICMP/ARP reply (healthy)
  - `leased-silent` — lease but no reply (powered off?)
  - `firewalled` — L2-visible (ARP) but drops ICMP
  - `free` — pool slot, no occupant
  - `active-untracked` — replies, no DHCP lease (static IP)
  - `firewalled-untracked` — L2-visible, drops ICMP, no lease
- **Promotion: in-pool scan responders join the upper table.**
  Discovered hosts whose IP falls inside the pool are merged into the
  upper lease table with `binding_state="no-lease"` so the operator
  can tick them and add to reservations like an ordinary lease.
  Out-of-pool responders stay in a separate "Discovered hosts (no
  DHCP lease)" card below.
- **Click-to-sort columns + numeric IP sort.** Every header in the
  upper table is clickable. **IP** uses a numeric octet-tuple
  comparator so `192.168.1.6` sorts before `192.168.1.69`. Other
  columns sort as text. Click toggles asc/desc; ▲/▼ indicator.
  Default = IP ascending, also enforced server-side.
- **Live counters on every filter button.** Lease-state filters
  (All / Active / Expired-free / Reserved / IP mismatch) plus five
  new discovery-state filters that appear after a scan
  (`active` / `silent` / `firewalled` / `untracked` /
  `untracked + firewalled`). Each button shows a badge with the
  count of matching rows, painted on `DOMContentLoaded` so the
  operator gets an at-a-glance overview without clicking. Discovery
  counters include rows from both tables (upper + lower card);
  clicking a discovery filter scopes both tables to that state.
- **MAC capture for ICMP_OK hosts.** Shell script reads the kernel
  ARP cache via `ip neighbor show <ip>` immediately after each
  successful ping, so ICMP-only responders also carry their MAC into
  the result and can be reserved without a follow-up arping.
- **New modules:**
  [webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py) —
  `enumerate_subnet_targets`, `enumerate_range_targets`,
  `_run_scan_streaming` (with `on_event` callback for live progress),
  `scan_subnet`, `classify`. Pure / no Flask deps.
  [webapp/dhcp_scan_jobs.py](webapp/dhcp_scan_jobs.py) — background
  job runtime: `start_scan` / `get_status` / `consume_report` /
  `discard`. Module-local `_JOBS` dict + `threading.Lock` + 15-min
  TTL eviction. Per-user ownership check on every access (no
  cross-user leaks).
- **Routes added** in [webapp/dhcp_manager.py](webapp/dhcp_manager.py):
  `POST /dhcp/scopes/<id>/scan`,
  `GET /dhcp/scopes/<id>/scan/status?id=X`. The existing
  `GET /dhcp/scopes/<id>/leases` route now also handles
  `?scan_id=X`: renders the watcher when running, consumes the
  report and renders the enriched view when done.

### Bug fixes (2026-05-06 → 2026-05-07)

- **Super Admin couldn't log in after Multi-Domain Revamp on
  existing data.** `_get_profiles_from_db` only iterated explicit
  `user_domain_access` grants, but the spec says Super Admin sees
  every Domain "including ones added later". Fixed: when
  `User.is_super_admin=True`, the profile list is built from every
  active Domain (with an active ApiKey). Self-heals deployments where
  the bootstrap admin had no UDA rows.
- **Container crash on import:** `shared/queue_runner._CREATE_DISPATCH`
  was defined at line 972 but referenced `_create_rule` /
  `_create_nat_rule` declared further down. Module-level dict literals
  evaluate at import time, so workers boot-looped with `NameError`.
  Moved the dispatch table to after the function definitions.
- **Jinja can't parse `<<` bitshift** in
  `templates/dhcp/leases.html` subnet-size calc — replaced with `**`.
- **`{% set %}` doesn't cross block scopes.** A var set in
  `{% block content %}` was read in `{% block extra_js %}`,
  producing `Undefined` and breaking `tojson`. Moved the value to
  the render context (passed from Python).
- **DHCP lease list rendered in lexicographic IP order** — server
  now sorts by numeric octet tuple before render, fixing cases where
  `192.168.1.6` sorted after `192.168.1.69`.

### Change Management Phase G — drift detector landed (2026-05-01)

Closes the loop on the `smc_objects` registry that Phase A introduced:
the registry's `last_seen_hash` is now actually *used* to flag SMC
elements that have been modified outside FlexEdgeAdmin.

- **New module [shared/smc_drift.py](shared/smc_drift.py).** Stable
  per-type SHA-256 hash (`compute_drift_hash`) over a whitelist of
  meaningful fields per `smc_type` (host, network, address_range, fqdn,
  tcp_service, udp_service, ip_service, icmp_service, group,
  service_group). Volatile keys (`link`, `key`, `mod_time`, `mod_user`,
  `read_only`) excluded; comments stripped of `[flexedge:audit ...]` +
  `[flexedge:mac=...]` markers before hashing so our own writes don't
  trip drift on the next scan.
- **Schema additions on `smc_objects`** (Phase G migration in
  [webapp/db_init.py](webapp/db_init.py)): `drift_state` ∈ {`unknown`,
  `clean`, `drifted`, `gone`}, `last_drift_check_at`, `drift_detail`.
  Idempotent ALTER TABLE — pre-existing rows default to `unknown` and
  baseline as `clean` on the first scan that successfully fetches them.
- **`scan_domain_drift(domain)`** opens ONE SMC session, walks every
  registry row for the Domain, fetches each by href via
  `Element.from_href`, classifies as clean / drifted / gone / errored,
  and updates the row in place. Per-row commits keep one bad element
  from poisoning the batch. Top-level audit entry summarises the run.
- **`reconcile_one(smc_object_id)`** re-baselines a drifted row to the
  current SMC state — the operator's "yes, accept this drift" button
  for intentional out-of-band changes. Audit-emits `drift.reconcile`.
- **UI: `/changes/drift`** — full list view filtered by drift_state
  (default: drifted + gone). Per-row Reconcile button (Domain Admin+).
  Scan-now button (Domain Admin+) runs `scan_domain_drift` synchronously
  and flashes a summary.
- **UI: drift summary card on `/changes/`** — appears when there's
  anything non-clean to flag, or when the registry has rows but never
  scanned. Counts + last-scan timestamp + deep-link to `/changes/drift`.
- **Per-row drift badge on listings** — new Jinja global
  `smc_drift_state(href_or_name)` returns `'drifted' | 'gone' | None`.
  Wired into the DHCP scope detail listing today; the same one-liner
  drops into TLS / Engines / explorer in a follow-up. Lookup is
  request-scoped (one query per page, lazy on first call).
- **Sidebar entry** — new "Drift detector" link under the "Change Queue"
  section, visible to Operator+.

**Phase E (Foundations + non-DHCP migration writers) and Phase G (drift
detector) close out the originally-planned Change Management surface.**
What remains is per-feature wiring of the bypass-queue capability into
admin UI workflows that haven't been touched yet, plus polishing the
Reconcile flow with a payload diff (deferred — current implementation
shows the "now" state, the previous state lives in platform_logs).

### Change Management Process — Phases A–D landed (2026-05-01)

Two-phase commit queue for every SMC mutation, gated by a four-tier
role model. Spec: [docs/ChangeManagementProcess.md](docs/ChangeManagementProcess.md).

- **Phase A — Foundation.** New `smc_objects` registry (the SMCRelated
  index, drives drift detection in Phase G) and `pending_changes` queue
  (state machine: QUEUED → PUSHED → APPLIED, plus ABORTED / PUSH_FAILED
  / CONFLICT). New role columns: `User.is_super_admin` (singular
  bootstrap admin) and `UserDomainAccess.role` ∈ {`global_admin`,
  `admin`, `operator`}. Idempotent `_phase_change_mgmt_a` migration
  renames yesterday's `is_global_admin` → `is_super_admin`, narrows
  Super status to the lowest-id admin, promotes other previous-admins
  to per-Domain `global_admin` so they keep power within their assigned
  Domains.
- **Phase B — Role enforcement.** New `webapp/auth_roles.py` with a
  five-tier `Role` IntEnum (VIEWER < DOMAIN_OPERATOR < DOMAIN_ADMIN <
  GLOBAL_ADMIN < SUPER_ADMIN). Decorators: `@super_admin_required`,
  `@global_admin_required`, `@domain_admin_required`,
  `@domain_operator_required` — each is "this tier or higher". Resolver
  `current_role_for_active_domain()` reads `User.is_super_admin` first,
  then `UserDomainAccess.role` for the active Domain; result cached on
  `g`. `user_manager.is_admin()` widened to accept all admin flavors so
  existing `@admin_required` decorators pass through unchanged. Sidebar
  split: Operator+ sees TLS / DHCP / Engines / Logs / Change Queue;
  Admin+ adds Admin Portal + Optimizer Review Queue.
- **Phase C — Push runner.** New `shared/queue_runner.py` with
  `push_one` / `push_batch` / `push_all_for_domain` / `abort_one` /
  `confirm_to_be_deleted` / `revoke_to_be_deleted` / `register_handler`.
  Halt-on-failure batch (Q4); auto cache invalidation after every PUSH
  (Q5); state-transition audit emission via `audit("changes", ...)` so
  every queue / push / apply / abort / push_failed lands on the unified
  Logs page with `source_correlation_id` for batch grouping. One
  proof-of-concept handler (`upload_policy`); the rest land in Phase E.
- **Phase D — Operator queue UI.** New blueprint `webapp/changes.py`
  at `/changes`. List view with filters (scope, state, source-batch,
  free-text search), Time vs Object views, conflict resolver with
  side-by-side payload diff + winner picker (Q11), `to_be_deleted`
  Confirm/Revoke buttons gated to Global Admin (Q12), per-row Push /
  Abort, bulk Push-all / Abort-all, sidebar entry with pending-count
  badge.
- **Gunicorn `--preload`** added to the Dockerfile to fix a worker race
  on first-boot table creation. `db.create_all()` was racing across the
  two workers — both saw "table doesn't exist", both tried to CREATE,
  the loser crashed. Preload imports the app once in the master before
  fork; defensive retry-on-already-exists wraps `create_all` for any
  non-preload deployments.
- **Round 2 questions** (Q11–Q14) captured in the spec doc with
  operator answers covering batch-promotion conflict semantics,
  operator-delete UX, invite flow, and `to_be_deleted` row TTL.

### Change Management Phase E.1 — Foundations (2026-05-01)

Phase E.2 (writer-by-writer enqueue conversion) is gated on Round 3
operator answers, so this slice ships the foundations needed when those
land.

- **Queue handlers (`shared/queue_runner.py`).** Added `create`,
  `update`, `delete`, `to_be_deleted`, `create_section`, `reload_dhcp`
  to the registry alongside the proof-of-concept `upload_policy`.
  `create`/`update`/`delete` dispatch by `smc_type` — `host` is the
  only type with a real implementation today (call paths through
  `webapp.smc_dhcp_client.host_create/update/delete`); other types
  return an explicit "no handler for type" error so a hand-crafted
  queue row can't silently no-op. `to_be_deleted` rejects direct push
  (must go via the queue's Confirm action which transitions to
  `delete` first). `create_section` and `reload_dhcp` are stubs that
  return "not implemented" until Phase E.2 wires their writers.
  Successful create / update reconciles the linked `SmcObject`
  registry row (upsert by `(domain_id, smc_href)`); delete retires
  the row. Registry maintenance is best-effort — failures log but
  never propagate.
- **Q12 strikethrough rendering.** New Jinja global
  `is_smc_to_be_deleted(href_or_name)` — request-scoped, lazy lookup
  against `smc_objects` filtered by active Domain, ONE query per page
  regardless of row count. Templates toggle the new
  `.smc-to-be-deleted` CSS class on listing rows; the row also gets a
  small "to be deleted" badge with a tooltip pointing the operator at
  the Change Queue. Applied to the DHCP reservation listing as a demo
  hook ([webapp/templates/dhcp/scope_detail.html](webapp/templates/dhcp/scope_detail.html));
  inert today (no writer populates `is_to_be_deleted=True` yet) and
  activates as soon as the first delete writer converts in Phase E.2.
- **Q13 invite-operator form.** New route
  `/admin/users/invite-operator` — Domain Admin (or higher) enters an
  Azure AD email + picks a Domain they admin, FEA creates the User
  row (display name fills in on first OIDC login) and grants
  `UserDomainAccess(role='operator')`. Super and Global Admin can
  invite into any active Domain; a Domain Admin only sees Domains
  where they hold `role IN ('admin', 'global_admin')`. Audit emits
  `audit('admin', 'user.invite_operator', ...)`. The Users listing
  shows the new "Invite Operator" button alongside "Add User", gated
  by `is_domain_admin`. Email-magic-link is parked as Q13a (TODO,
  needs SMTP + token table).
- **Round 3 questions raised** (Q15–Q22) — eight new dilemmas that
  surfaced as soon as we started planning per-writer conversion:
  auto-push UX for Domain Admin and above, listing UX for queued-
  but-unpushed rows, push-failure UX, cross-writer ordering between
  reservation create + Phase 4 deploy, TLS deployment chaining,
  migration import staging, `smc_objects` registry backfill strategy,
  and the strikethrough helper's row-vs-href identity model. All
  answers needed before Phase E.2 starts converting writers.

### Change Management Phase E.2 — DHCP reservation CRUD via queue (2026-05-01)

Round 3 (Q15–Q22) answered, first writer family converts to the queue.
Spec: [docs/ChangeManagementProcess.md § Phase E.2 implementation summary](docs/ChangeManagementProcess.md#phase-e2--implementation-summary-per-round-3-answers-2026-05-01).

- **DHCP reservation create / edit / delete** now go through
  `pending_changes`. New helper module
  [webapp/dhcp_reservation_queue.py](webapp/dhcp_reservation_queue.py)
  carries `enqueue_reservation_create / _update / _delete` and
  `try_auto_push_for_admins`. Routes
  [reservation_new / reservation_edit / reservation_delete](webapp/dhcp_manager.py)
  no longer call `host_create` / `host_update` / `host_delete` directly
  — they queue + auto-push for admins (Q15/a) or queue-only for
  Operators (who must visit `/changes/`).
- **Domain Admin and above:** UX feels identical to today —
  `push_one()` runs inline within the same request and the operator
  lands on the success page. The queue row becomes the audit trail.
- **Operator role:** the reservation appears in the scope listing
  with a `queued` badge and the operator gets redirected to
  `/changes/?source=dhcp_reservation:<id>`.
- **Push failure UX (Q17/b):** reservation row keeps a `push_failed`
  status; the scope listing shows the formatted SMC error inline
  below the row with a yellow **Retry** button that re-invokes
  `push_one()` on the same `pending_changes` row. New route
  `/dhcp/reservations/<id>/retry-push`.
- **Operator-submitted delete (Q12 + Q14):** flips
  `smc_objects.is_to_be_deleted=True` on the linked SMC Host so the
  Q12 strikethrough fires across listings; reservation row stays
  visible (struck-through) until a Global Admin Confirms / Revokes
  from `/changes/`. No auto-revoke (Q14).
- **Edits to a not-yet-pushed reservation** mutate the existing
  PendingChange's payload — no second queue row (Q16/a). Still-
  queued reservations support address/MAC edits via the same form.
- **SMC Host name auto-derived** as `dhcp-<engine>-<ip-dashed>`
  when the form name field is blank (Q16). Operator-supplied names
  honored as override.
- **Comment audit marker (Q21 feature request).** New module
  [webapp/smc_audit_marker.py](webapp/smc_audit_marker.py) — every
  successful `host` create / update stamps the SMC element's comment
  field with `[flexedge:audit ts=2026-05-01T... user=… prev="…20chars…"]`,
  visible in SMC Management Client without round-tripping through
  FlexEdgeAdmin. Idempotent (replaces previous marker, doesn't stack);
  coexists with the existing `[flexedge:mac=...]` marker. Operator-
  visible comment stays clean — both markers are stripped from
  `DhcpHostView.comment`.
- **Lazy registry population (Q21/a).** New module
  [shared/smc_registry.py](shared/smc_registry.py) with
  `register_smc_object_seen()` + `register_many()`. Wired into
  `webapp/smc_dhcp_client.host_get` and
  `list_scopes_for_engine` so the registry organically populates as
  operators use the DHCP feature. Best-effort: failures log + swallow,
  never break the surrounding read.
- **`reload_dhcp` queue handler removed** per Q18 — DHCP Phase 4 SSH
  push stays out of the queue (it's an SSH file write, not an SMC
  mutation; the existing scope-deploy button is unchanged).
- **Schema:** new `dhcp_reservations.pending_change_id` FK linking a
  reservation to the queue row controlling it when it's queued or
  push_failed (cleared on successful push). Idempotent migration in
  `webapp/db_init._migrate_post_create`.
- **Status states added** to `dhcp_reservations.status`: `queued`
  (waiting for push) and `push_failed` (push attempted, SMC rejected).
  No DB schema change needed — column was already a string.
- **What's next in E.2:** TLS deployment writer (Q19/b — single row,
  internal orchestrator with sub-action list); migration import
  writer (Q20 — direct submit to main queue, collapsed-with-expand
  row UI; descopes the originally-planned Phase F migration_review
  staging); DHCP credentials rule install/remove; reservation
  bulk-delete; broader `register_many` rollout (TLS, explorer,
  engine_inquiry).

### Change Management Phase E.2 — bulk-delete + registry rollout (2026-05-01)

Second slice of E.2 — completes DHCP reservation queue coverage and
rolls the lazy `smc_objects` registry out to the busiest read paths.

- **DHCP reservation bulk-delete via queue.** Operator selects N rows +
  ticks "also delete SMC Host" → one PendingChange per reservation,
  all sharing a `dhcp_reservation_bulk:<scope>:<token>` correlation
  id so `/changes/?source=<corr>` shows the whole group. Domain Admin
  and above hit `push_batch` (halt-on-failure per Q4 — first SMC
  rejection halts the batch, remaining rows stay QUEUED for inspect /
  resolve / retry; partial-success summary in the flash). Operators
  enqueue all rows as `to_be_deleted` (the linked SMC Hosts get
  `is_to_be_deleted=True` so Q12 strikethrough fires across listings
  while a Global Admin Confirms each from the queue UI). DB-only
  bulk-delete (operator unticks "also delete SMC Host") still fires
  immediately — no SMC mutation, no queue. Reservations that were
  still QUEUED (never pushed) get their in-flight create change
  aborted in one shot, the DB row dropped — no SMC delete needed
  since the Host doesn't exist there yet.
- **Lazy `smc_objects` registry rollout** — `register_many()` wired
  into three high-traffic read paths so the registry organically
  populates on every operator click:
  - [webapp/engine_inquiry.list_clusters](webapp/engine_inquiry.py)
    — registers every engine seen on `/engines/clusters`.
  - [webapp/smc_tls_client.list_engines](webapp/smc_tls_client.py)
    and `list_tls_credentials()` — registers engines + TLS credentials
    seen during TLS Manager flows.
  - [webapp/smc_client.list_elements](webapp/smc_client.py)
    — registers every Host / Network / Service / Group / etc. seen
    on `/browse/<type>` explorer pages, with the explorer's plural
    `type_key` mapped to a singular `smc_type` label (`hosts` →
    `host`, `tcp_services` → `tcp_service`, etc.).
  - All three call sites are best-effort (failures log + swallow
    in the registry helper) and add zero load when there's no
    active Domain (CLI invocations).

### Change Management Phase E.2 — DHCP credentials rule via queue (2026-05-01)

Third slice of E.2 — converts the SSH-allow rule install/remove +
force-policy-install operator buttons to go through the queue.

- **Two new queue operations** registered in
  [shared/queue_runner.py](shared/queue_runner.py):
  - `install_ssh_rule` — bundle handler (Q19/b internal-orchestrator
    pattern): find-or-create source Host + dest Hosts; create or
    detect rule in the engine's installed policy; persist the
    `DhcpEngineSshAccess` row; reconcile the linked `SmcObject`
    registry entry for the rule; upload the policy. ONE queue row,
    `applied=True` on success because the policy upload activates
    on the engine.
  - `remove_ssh_rule` — bundle handler: remove the rule from the
    policy + upload the policy. The DB-side
    `DhcpEngineSshAccess` row is dropped by the calling route
    after a successful push (so retry semantics stay clean — a
    failed first attempt leaves the access row so retry can find
    the policy/rule names).
- **New helper module:**
  [webapp/dhcp_credentials_queue.py](webapp/dhcp_credentials_queue.py)
  — `enqueue_install_ssh_rule`, `enqueue_remove_ssh_rule`,
  `enqueue_policy_upload`, `try_auto_push`. All reuse the same
  `source_correlation_id` shape (`dhcp_credentials_rule:<engine>` /
  `dhcp_credentials_policy:<engine>`) so a sequence of operator
  actions on the same engine groups cleanly on `/changes/`.
- **Three routes converted** in [webapp/dhcp_manager.py](webapp/dhcp_manager.py):
  - `POST /credentials/rule/install` — enqueue + auto-push for
    Domain Admin+. Source-IP drift detection still happens in the
    route (refuses install before enqueueing if drift is detected).
    Queue change is the audit record; on success the AJAX wizard
    sees the same flash + state-refresh as before.
  - `POST /credentials/rule/remove` (via `_do_rule_teardown`) —
    enqueue + auto-push. The local access row is deleted only
    after the push succeeds, so a push failure leaves both the
    access row AND the queue row available for Retry.
  - `POST /credentials/policy-install` — enqueue an `upload_policy`
    row (reuses the Phase C handler) + auto-push. Same audit /
    retry benefits.
- **Source-IP drift recovery** (`/rule/source/overwrite` and
  `/rule/source/add`) intentionally stays out-of-queue. They're
  one-shot fixes on an already-broken rule and queueing would just
  add latency without meaningful audit benefit (the `_log_activity`
  trail already covers it).

### Change Management Phase E.2 — DHCP migration import via queue (2026-05-01)

Fourth slice of E.2 — addresses the operator's original complaint that
started this whole spec ("the system says is done but I don't see it
in real"). Migration import no longer calls SMC directly; it stages
the batch in the Change Queue for explicit operator push.

- **`webapp/migration_dhcp_writer.py` rewritten** per Q20:
  - Drops the per-scope SMC session and the `host_create` / `host_update`
    direct calls.
  - Drops the rollback machinery (`created_hosts` tracking,
    `_rollback_created_hosts`, `_try_delete_host`) — the queue IS the
    rollback. A push failure leaves a `push_failed` row that operators
    can Retry or Abort from the Change Queue.
  - Inserts each `DhcpReservation` in `status='queued'` with `source=
    "migration:<project_id>"`, then enqueues a
    `pending_changes(operation='create', smc_type='host')` row sharing
    `source_correlation_id="migration:<project_id>"`.
  - Conflict-overwrite path enqueues an `update` row (was
    `host_update` direct call) with `audit_previous_value` carrying
    the prior IP for the in-SMC comment marker.
  - Returns two new fields in the result dict (`changes_enqueued` +
    `correlation_id`) so the import-summary UI can link to the
    queue.
- **Migration import-summary UI** (`webapp/templates/migration/import.html`)
  surfaces the staged batch with a prominent CTA:
  *"N DHCP reservation change(s) staged in the Change Queue. They are
  queued, not yet pushed to SMC. [Open Change Queue]"*. Replaces the
  previous "X reservations created" — the operator now sees explicitly
  that *nothing has hit SMC yet* and where to go next.
- **Phase F descoped** per Q20. The originally-planned
  `scope='migration_review'` queue isn't built — migration writes
  directly to the main queue with a shared correlation id, and the
  Change Queue UI's existing source-filter + collapsed-with-expand
  rendering handles the "review batch before push" workflow.
- The non-DHCP migration writer (`webapp/smc_writer.py` for FortiGate
  hosts/networks/services/rules) still calls SMC directly. Conversion
  needs new queue handlers for `network`, `service`, `service_group`,
  `rule`, `nat_rule` types — deferred to a focused follow-up.

### Change Management Phase E.2 — TLS deployment via queue (2026-05-01)

Fifth slice of E.2 — converts the TLS Manager deployment pipeline to
the Q19/b "single queue row + internal orchestrator + sub-action list"
pattern.

- **`deploy_tls` handler** registered in
  [shared/queue_runner.py](shared/queue_runner.py). Bundle: imports
  the TLS credential, creates source + dest Host elements, assigns
  the credential to the engine, finds-or-creates the policy rule,
  uploads the policy. ONE queue row, `applied=True` on success
  (the policy upload activates on the engine). Persists the
  populated `DeployResult` back into the `TLSDeployment` row +
  `TLSDeploymentLog` entry just like the legacy `run_deployment`
  did, then writes the `steps[]` array into the change's
  `payload_json` so the queue UI can render it.
- **`webapp/tls_deployer.py` refactored.** New
  `execute_deployment_inside_session(dep, fullchain, privkey)` runs
  the 5-step pipeline assuming an SMC session is already open (used
  by the queue handler — the runner opens its own session). The
  legacy `execute_deployment(dep, smc_cfg, ...)` now opens its own
  session and delegates here, so it stays usable for any
  out-of-queue caller.
- **`/tls/deploy/<id>/execute` route converted** in
  [webapp/tls_manager.py](webapp/tls_manager.py). Domain Admin+ gets
  inline auto-push (Q15/a) — UX feels identical to today, including
  the `tls/deploy_execute.html` step-by-step result table. Push
  failure surfaces the SMC error and leaves the queue row available
  for Retry from `/changes/`. Non-admin path (defensive — this is
  admin-only normally) queues + redirects to the queue.
- **Queue UI sub-action display.** New `from_json` Jinja filter
  registered in [webapp/app.py](webapp/app.py). The Change Queue's
  expanded detail panel
  ([webapp/templates/changes/_rows_table.html](webapp/templates/changes/_rows_table.html))
  parses `payload.steps` and renders an ordered list with per-step
  status badges (`ok` / `failed` / `warning`) so the operator sees
  *exactly which sub-step failed* without leaving the queue page.
  Q19/b answer satisfied: "ONE queue row but listing the actions in
  the order in which they will be instantiated."
- The same expanded-detail rendering also benefits future bundle
  handlers (`install_ssh_rule` already exposes a similar shape;
  Phase E.2 follow-up handlers for non-DHCP migration will too).

### Change Management Phase E.2 — Bypass Queue (per-domain, per-user) (2026-05-01)

Per-feature, per-domain, per-user "bypass queue" toggle. When enabled
for a (user, domain, feature) triple, the user's actions on that
feature in that domain skip the queue review model — they auto-push
within the same request and the queue row is deleted on success
(transient). Audit log entry stays. Failed pushes leave the row
visible so the operator can retry from `/changes/`.

- **Schema** — new `feature_bypass_settings` table
  ([webapp/models.py:FeatureBypassSetting](webapp/models.py)). Two
  row shapes coexist:
  - `(domain_id=X, user_id=NULL, feature=F, enabled)` — domain
    capability flag. Permission gate: when ON, Domain Admins of X
    are allowed to grant per-user bypass for F. Toggling does NOT
    change operator behavior on its own.
  - `(domain_id=X, user_id=Y, feature=F, enabled)` — per-user
    override. The operative bit: when ON, user Y's actions on F in
    X bypass the queue. Default for everyone everywhere is OFF
    (queue is the default).
- **Lookup** — [shared/queue_settings.py](shared/queue_settings.py)
  with `should_bypass_queue(feature, domain=None, user_email=None)`,
  `is_capability_enabled(domain, feature)`,
  `can_edit_capability(domain, feature)`,
  `can_edit_user_bypass(domain, feature)`, plus the mutators
  `set_capability` and `set_user_bypass`. Resolution is most-specific
  wins: per-user row first; otherwise False. Domain capability is
  consulted only by the UI permission helper, never by the bypass
  decision itself.
- **Authority cascade** —
  - Domain capability flag: Domain Admin in the Domain, Global
    Admin, Super Admin can flip.
  - Per-user override: Super and Global Admins can always edit;
    Domain Admins can edit only when domain capability for that
    feature is ON.
  - Operators: read-only (badge tells them when they're in bypass
    mode for a feature in this Domain).
- **Bypass feature registry** — V1 covers the four converted
  features: `dhcp_reservation`, `dhcp_credentials`, `tls_deploy`,
  `migration_dhcp`. The registry is independent of `feature_source`
  / `platform_log` feature names so bypass naming is finer-grained.
- **Wiring** — every existing converted enqueue helper now checks
  `should_bypass_queue(...)`:
  - [webapp/dhcp_reservation_queue.try_auto_push_for_admins](webapp/dhcp_reservation_queue.py)
    — admin OR bypass triggers inline push; on success when bypass
    applies, the queue row is deleted and a
    `<feature>.<op>.bypass_queue` audit marker is emitted.
  - [webapp/dhcp_credentials_queue.try_auto_push](webapp/dhcp_credentials_queue.py)
    — same pattern.
  - [webapp/tls_manager.deploy_execute](webapp/tls_manager.py) —
    same; identifiers captured before deletion so the success flash
    still works.
  - [webapp/app.py](webapp/app.py) migration-import path —
    when bypass is on, calls `push_batch` on the whole correlation
    group + deletes successful rows + emits per-row audit markers.
    Failed rows stay so the operator can recover from `/changes/`.
- **UI** —
  - `/admin/log-settings` extended with a "Bypass Queue — domain
    capabilities" matrix for the active Domain. Domain Admin sees
    only their own Domain (toggles disabled cross-Domain); Super /
    Global Admin can edit any Domain via the topbar switcher.
  - `/admin/users/<id>/edit` gets a "Per-feature Bypass" panel
    below the user form: a Domain × Feature matrix of toggles,
    each disabled when the editor isn't allowed to flip that
    combination (with a tooltip explaining why). New POST route
    `/admin/users/<id>/bypass` saves it.
  - New Jinja global `bypass_active(feature)` (request-scoped,
    memoized on `g`). Renders a small "Bypass active" badge on
    the DHCP scope detail page, the DHCP credentials wizard, and
    the TLS deploy execute page so operators see when their next
    action will commit immediately.
- **Audit emission** — every toggle change emits
  `audit("admin", "queue_bypass.capability"|"queue_bypass.user", ...)`.
  Each successful bypassed push emits
  `audit("<feature>", "<operation>.bypass_queue", ...)` with the
  source correlation id preserved, so log queries can find every
  action that ran in bypass mode.

### Change Management Phase E.2 — FortiGate object import via queue (2026-05-01)

Seventh slice of E.2 — converts the non-DHCP migration writer's
object creation path (hosts / networks / address ranges / FQDNs /
services / groups / NAT hosts) to enqueue. Rules and NAT rules
remain on the legacy direct path — they need policy + section +
position model work that warrants its own focused conversion.

- **New queue handlers** in [shared/queue_runner.py](shared/queue_runner.py):
  `network`, `address_range`, `fqdn`, `tcp_service`, `udp_service`,
  `group`, `service_group`. Joins the existing `host` handler.
  Refactored `_handle_create` to dispatch via a `_CREATE_DISPATCH`
  table so adding new types is a one-line registration. Each handler:
  - Parses the type-specific payload + stamps the Q21 audit comment
    marker (`[flexedge:audit ts=… user=…]`) into the SMC element's
    `comment` field.
  - Calls the SMC SDK's `Class.create(...)` and reconciles the
    linked `SmcObject` registry row.
  - Treats "already exists" / "must be unique" / "duplicate" as
    soft success — the migration importer is now idempotent.
    Re-running the same import produces zero churn.
  - Group handlers resolve members from the names list across the
    candidate SMC classes (Network / Host / AddressRange / Group /
    DomainName for address groups; TCPService / UDPService /
    ServiceGroup for service groups). Unresolvable members are
    skipped with a note in the queue row's `detail`.
- **New helper module**
  [webapp/migration_object_writer.py](webapp/migration_object_writer.py)
  exposes `enqueue_object_imports(parsed_objects, dedup_results,
  domain, project_id) -> dict`. Stages every selected object as a
  queue row in five tiers (addresses → services → address groups →
  service groups → NAT hosts). The natural `created_at` push order
  honors group dependencies — members push before groups, and
  halt-on-failure stops the cascade if a member create fails so
  groups don't try to push with unresolvable members.
- **Migration import route** ([webapp/app.py](webapp/app.py))
  swaps `smc_writer.create_objects(parsed, dedup, cfg)` for the new
  enqueue helper. Two parallel correlation ids are surfaced:
  `migration_dhcp_correlation_id` (DHCP reservations from the prior
  slice) and `migration_object_correlation_id` (FortiGate objects).
  Both use the prefix `migration:<project_id>`, so
  `/changes/?source=migration:<id>` shows the whole import grouped.
- **Bypass mode** — new `migration_object` feature in the bypass
  registry. When enabled for the (user, domain) pair, `push_batch`
  runs immediately on the object batch, successful rows are
  deleted, and `<op>.bypass_queue` audit markers are emitted.
  Failed rows stay queued for Retry from `/changes/`.
- **Migration import-summary template**
  ([webapp/templates/migration/import.html](webapp/templates/migration/import.html))
  surfaces the object batch with the same "Open Change Queue" CTA
  pattern as the DHCP path. Includes a per-type breakdown
  ("host: N, network: M, ...") so the operator sees the shape of
  what was staged.
- **What's still on the legacy direct path:**
  - `smc_writer.create_rules` (firewall rules) — needs a `rule`
    queue handler + a real `create_section` handler.
  - `smc_writer.create_nat_rules` — needs a `nat_rule` handler.
  - `smc_writer.create_vpn_infrastructure` — VPN profiles +
    gateways + policies; complex enough to warrant its own
    dedicated turn.

### Change Management Phase E.2 — FortiGate rule + NAT import via queue (2026-05-01)

Eighth slice of E.2 — converts the firewall rule + NAT writer paths
to enqueue. Combined with the prior object-import slice this means
every FortiGate import sub-batch (DHCP / objects / rules / NAT)
lands in the change queue with full audit trail and dependency-
honoring push order. Only VPN remains on the direct path.

- **New queue handlers** in [shared/queue_runner.py](shared/queue_runner.py):
  - `rule` — creates a firewall rule in a policy's `fw_ipv4_access_rules`
    (with optional section). Resolves source / destination / service
    names across every candidate SMC class at push time; unresolvable
    members fall back to `"any"` (legacy semantics preserved).
  - `nat_rule` — creates a NAT rule in `fw_ipv4_nat_rules`. Pre-
    resolves SNAT/DNAT IPs → SMC Host names at enqueue time via the
    import's `nat_host_map`, so the handler only sees names.
  - `create_section` — replaces the prior "not implemented" stub.
    Calls `policy.fw_ipv4_access_rules.create_rule_section(...)`.
    Idempotent on already-exists.
  - All three stamp the Q21 audit comment marker, treat
    "already exists" as soft success (idempotent re-import), and
    reconcile `SmcObject` so the registry covers rules + sections.
- **Helper** `_ensure_firewall_policy(policy_name)` does idempotent
  find-or-create on the `FirewallPolicy` at the start of each
  rule / section / NAT handler so a missing policy doesn't crash the
  cascade. Plus shared `_resolve_element_name` /
  `_resolve_service_name` / `_resolve_member_list` helpers used by
  both rule + NAT handlers (and exposed for any future writer that
  needs the same lookup pattern).
- **New helper module**
  [webapp/migration_rule_writer.py](webapp/migration_rule_writer.py)
  with two functions:
  - `enqueue_rule_imports(converted, domain, project_id, policy_name)`
    — stages sections + rules in dependency order. For each section
    in `converted_rules.sections`: enqueue the section first, then
    every selected rule under it. Push runner's natural created_at
    order ensures sections push before their rules.
  - `enqueue_nat_rule_imports(converted, dedup, domain, project_id,
    policy_name)` — stages NAT rules with pre-resolved Host names.
- **Migration import route** ([webapp/app.py](webapp/app.py))
  swaps `smc_writer.create_rules(...)` → `enqueue_rule_imports(...)`
  and `smc_writer.create_nat_rules(...)` → `enqueue_nat_rule_imports(...)`.
  All four migration tiers (DHCP, objects, rules, NAT) share the
  prefix `migration:<project_id>` for the source correlation id.
- **Bypass mode** — two new features registered: `migration_rule`,
  `migration_nat`. Refactored the inline bypass-push logic from the
  prior slices into a shared helper `_bypass_push_migration_batch`
  in [webapp/app.py](webapp/app.py) that DHCP / objects / rules / NAT
  all delegate to. Single source of truth for "find queued rows in
  this batch, push, delete-on-success, audit-mark."
- **Migration import-summary template**
  ([webapp/templates/migration/import.html](webapp/templates/migration/import.html))
  consolidated into ONE alert showing the total enqueued count +
  per-tier breakdown (objects with by-type detail, sections + rules,
  NAT rules). Single "Open Change Queue" link points at the unified
  `migration:<id>` view since all tiers share the correlation id —
  operator now sees the whole import as one logical batch.
- **Push order in the unified queue** is dependency-honored without
  any explicit `scheduled_after` plumbing because the migration
  enqueue is single-threaded inside the import request:
  1. Objects (host / network / address_range / fqdn / tcp_service /
     udp_service / group / service_group / NAT host)
  2. Rule sections per converted section
  3. Firewall rules under each section
  4. NAT rules
  Halt-on-failure (Q4) stops the cascade so dependent rows don't
  push if a member fails.

### Change Management Phase E.2 — FortiGate VPN import via queue (2026-05-01)

Ninth slice of E.2 — converts the last remaining direct-write
migration path. **Phase E.2 complete:** every mutating writer in
FlexEdgeAdmin goes through the queue.

- **New `deploy_vpn` queue handler** in [shared/queue_runner.py](shared/queue_runner.py).
  Q19/b internal-orchestrator pattern (same as `deploy_tls`):
  ONE queue row per VPN config, the handler runs the 6-step
  pipeline inside the queue runner's SMC session and persists per-
  step status into `payload.steps[]` so the queue UI's expanded
  detail panel renders the same per-step badges as TLS.
- **New helper module** [webapp/migration_vpn_writer.py](webapp/migration_vpn_writer.py)
  carries the orchestration body in
  `execute_vpn_pipeline_inside_session(config, engine_name)` and
  the enqueue entry in `enqueue_vpn_imports(...)`. The 6 steps:
  - Step 1: VPN profile (find-or-create with crypto capabilities,
    `sa_life_time` and `tunnel_life_time_seconds` from config).
  - Step 2: External gateway (find-or-create with `trust_all_cas=True`).
  - Step 3: External endpoint (remote peer IP on the gateway).
  - Step 4: VPN site + member networks (resolves remote subnets
    against existing Network/Host elements; creates `FGT-VPN-<name>-
    <subnet>` placeholders for unresolvable subnets).
  - Step 5: PolicyVPN container (with `nat=True` + the VPN profile).
  - Step 6: Topology — open + add satellite gateway + add central
    gateway (engine) + save + close. Skipped on re-import if the
    PolicyVPN already existed, to avoid appending duplicate gateway
    entries.
  - Each step is `ok` / `warning` / `failed` in the per-step trace.
    Idempotent on already-exists. `vpn_site` falls back to a
    warning when no resolvable subnets exist (rather than failing
    the whole VPN config).
- **Migration import route** ([webapp/app.py](webapp/app.py)) swaps
  `smc_writer.create_vpn_infrastructure(...)` →
  `enqueue_vpn_imports(...)`. Reuses the shared
  `_bypass_push_migration_batch` helper.
- **Bypass mode** — new `migration_vpn` feature in the bypass
  registry. Same per-user, per-domain semantics as every other
  feature; when enabled, the VPN batch pushes inline + successful
  rows are deleted + `vpn.deploy_vpn.bypass_queue` audit markers
  emitted.
- **Migration import-summary template** updated to count VPN
  configs in the unified CTA's total + per-tier breakdown. All 5
  migration tiers (DHCP / objects / rules / NAT / VPN) share the
  `migration:<project_id>` correlation id so the operator opens
  ONE queue page that shows the full import.
- **Phase E.2 complete.** Every mutating writer FlexEdgeAdmin owns
  now goes through the queue:
  - DHCP reservation CRUD (single + bulk) — slice 1 + 2
  - DHCP credentials rule install/remove + force-policy-install — slice 3
  - DHCP migration import — slice 4
  - TLS certificate deployment — slice 5
  - Bypass-queue (per-domain, per-user) — slice 6
  - FortiGate object import — slice 7
  - FortiGate firewall rule + section import + NAT rule import — slice 8
  - FortiGate VPN topology — slice 9
- **What's next:** Phase G (drift detector) — compares
  `smc_objects.last_seen_hash` vs live SMC fetch. The lazy-on-read
  registry rollout from earlier slices already covers what
  operators touch; drift detection now has data to work with.

### Cross-Domain leak hardening + UX improvements (2026-05-01)

- **Cross-Domain read scoping** — DHCP, TLS, Optimizer list views now
  filter by `g.domain.id` instead of `.query.all()`. Optimizer
  submission detail/decide routes patched to 404 on cross-Domain row
  access (audit found admins in Domain A could view/decide rows from
  Domain B via direct URL).
- **Topbar Domain switcher** — dropdown in the upper right listing
  every Domain the user has `UserDomainAccess` for. Switching invokes
  `/switch-domain` which invalidates the SMC read cache so the next
  page load is fresh.
- **Single-profile auto-skip** — Azure AD callback for users with one
  profile sets `active_domain` immediately and lands on `/`, skipping
  the legacy `/select-domain` step entirely.
- **Dual-frame scroll layout** — sidebar and main content scroll
  independently; topbar is sticky in the main pane. Sidebar `scrollTop`
  persisted to `sessionStorage` so navigation doesn't reset the menu
  position.

### Platform log unification — standing rule satisfied (2026-05-01)

The standing rule "every feature funnels its audit + operational
entries through one platform log system" (memory:
`feedback_logging_standing_rule`) is now operative.

- **New `platform_logs` table** (`id, timestamp, level, feature, action,
  status, user_email, target, detail, domain_id,
  source_correlation_id`). Replaces the per-feature
  `dhcp_activity_logs` + `tls_activity_logs` writes. Existing legacy
  rows are backfilled into `platform_logs` once at boot via
  `_phase_log_unification`; legacy tables remain read-only.
- **New `platform_settings` table** (key/value config). Known keys:
  `log_mode` ∈ {`normal`, `verbose`}, `log_retention_days`,
  `feature_log_<name>` ∈ {`on`, `off`}, `legacy_logs_migrated`.
- **New `shared/logging.py`** — `audit(feature, action, ...)`, `op(...)`,
  `register_feature(name, label)`, `is_feature_enabled(feature)`,
  `current_log_mode()`, `current_retention_days()`, `sweep_old_logs()`.
  Writes never break the request — `_write` is fully wrapped in
  try/except with rollback. `op()` only persists when log mode is
  `verbose`.
- **Existing helpers repointed** — `_log_activity` in `dhcp_manager.py`,
  `tls_manager.py`, and `_log_activity_engines` in `engines_manager.py`
  now call `audit("dhcp"/"tls"/"engines", ...)` and route to the
  unified table.
- **Phase 0 gate cross-table reader** — `is_phase0_validated()` and
  `get_phase0_validation()` check BOTH `platform_logs` AND legacy
  `dhcp_activity_logs` so the Phase 4 deploy gate stays effective
  across the cutover.
- **New `/logs` page** (admin only) — multi-feature filterable viewer
  with date / status / level / free-text search, "active Domain only"
  toggle for cross-Domain visibility, expandable detail panels.
- **New `/admin/log-settings` page** — log mode toggle, retention
  days input, per-feature on/off matrix with row counts, manual sweep
  button.
- **Sidebar reorg** — "Activity Logs" moved out of DHCP Manager into a
  new top-level "Logs" section that also hosts DHCP/TLS deployment
  history and log settings.
- **Legacy `/dhcp/activity`** redirects to `/logs?feature=dhcp&active_only=1`.

### Multi-Domain Revamp landed (2026-04-29 → 2026-04-30)

Operators now see **Domain** as the only scope unit. Each Domain is one
`(api_key, smc_domain_name)` pair with its own slug, display name, and
CLI back-compat token. The legacy two-step "Profile → SMC domain" flow
is gone — a single profile pick auto-sets the SMC admin-domain and
lands the operator on the dashboard.

- **Schema**: every feature table is keyed by `domain_id`. SMC config
  (`smc_url`, `verify_ssl`, `timeout`, `api_version`,
  `flexedge_source_ip`) absorbed onto `api_keys`. `user_tenant_access`
  table dropped. `tenants` table kept admin-internal as a legacy
  compat shim for the API Keys form's find-or-create on URL match.
  Vestigial `tenant_id` / `api_key_id` columns on feature tables sit
  populated but unread (SQLite can't `DROP COLUMN` under composite
  UNIQUEs without table recreation — deferred to a focused commit).
- **Admin Portal**: API Keys + Domains + Users as the three primary
  pages. New API Keys form takes the SMC URL + SSL/timeout/api_version
  /source_ip directly and auto-creates a default Domain. Domains CRUD
  page added. Users form switches to a per-Domain checkbox grid +
  default radio. Hard-delete API keys (refuses if Domains still
  reference the key).
- **Bulk-delete reservations** on the scope detail page (select-all
  checkbox + optional "also delete SMC Host elements" toggle).
- **`/select-domain` skipped** after profile pick — Domain pins the
  SMC domain.
- **SQLite FK enforcement on**: `PRAGMA foreign_keys=ON` registered as
  a SQLAlchemy `connect` event listener so declared FKs are actually
  enforced (SQLite default is OFF per-connection).
- Plan + per-section operator decisions:
  [docs/MultiDomainRevamp.md](docs/MultiDomainRevamp.md).

### DHCP scope discovery — Address-Range element refs

The pool resolver now handles three SMC payload shapes:

1. Inline `dhcp_address_range = "start-end"` (most common).
2. Per-node list `dhcp_range_per_node[*].dhcp_address_range`.
3. Element reference via `dhcp_range_ref` (Forcepoint NGFW 7.1 shape
   observed on GUYFW interface 0.0.2) — resolved by fetching the SMC
   `AddressRange` element and reading its `data.ip_range`. Older
   `dhcp_address_range_ref` / `address_range_ref` shapes also covered.

Per-interface error isolation in `list_scopes_for_engine` so one bad
payload no longer aborts the whole traversal silently. Always-on per-
scope INFO log + per-failure WARNING dump of the raw cfg dict so
the next missing-shape report can pinpoint the field name without a
debug-endpoint round-trip.

### Removed — Sandbox

Per the operator's MultiDomainRevamp Q1 answer, Sandbox is gone:

- `GET /sandbox` HTML route + `GET /api/sandbox` JSON route
- `smc_client.sandbox_rules_check()`
- `webapp/templates/sandbox.html`
- Sidebar nav link + dashboard quick-action card + per-policy and
  per-rule-page Sandbox buttons

The Optimizer (live findings on a policy) and the Migration Manager
(import-time validation) cover rule validation with strictly more
depth than the legacy Sandbox summary.

### Added — Engines feature Phase A (read-only inventory + cache + search)

- **`/engines/clusters`** — engine inventory, served through the new
  process-local SMC read cache (`shared/smc_cache.py`). Header shows
  "cached · N min ago" or "fresh from SMC" + a `?refresh=1` button
  forces a live re-fetch.
- **`/engines/clusters/<name>`** — per-cluster detail with tabs (Nodes,
  Interfaces, Routing, Contact addresses). Full-text **search bar**
  above the tabs supports `AND` / `OR` operators (case-insensitive,
  implicit AND on whitespace), filters every tab in place, highlights
  matching tokens with `<mark.search-hit>`, updates per-tab counts to
  `(M of N)` when filtered.
- **Cluster Forget** — admin button on each engine in the Clusters
  list (only visible when the engine has FlexEdge state). Removes
  every `DhcpEngineCredential` row + the SMC SSH allow rule + uploads
  policy + invalidates cache. Engine itself stays in SMC, reachable
  via SMC Management Client. SMC-side cleanup is attempted FIRST so
  failures don't strand DB state.
- **Terminal icon off-by-one fix** — cluster_detail's
  `creds_by_node.get(n.nodeid)` lookup uses 1-based SMC nodeids; the
  DB stores `node_index` 0-based. The lookup was missing on every
  freshly enrolled node, leaving the terminal icon greyed out. Fixed
  in `_credentials_for_engine`.
- **Cluster detail SMC Element leak fix** — the Routing tab's
  `routing_node_element` field used to leak a live SDK Element object
  past the `with smc_session()` block; Jinja's `str()` cast then
  triggered an API call after the session closed → "No session found"
  500. New `_stringify()` helper materialises every value to a plain
  string at extraction time.

### Added — Platform-wide caching layer (`shared/smc_cache.py`)

`cache_get_or_fetch(section, key_parts, fetcher, ttl, refresh)` —
process-local TTL cache for SMC reads, per-section LRU + TTL,
section names like `engines.list`, `smc.explorer.<type>`, etc.
Default TTL 1 h, hard cap 24 h. Cache key SHA-256s the key parts so
plaintext API keys never end up in the index. Standing rule saved
to memory: every SMC-read view goes through this helper with a
freshness footer + Refresh button. **Reference impl: engines.list**;
rollout to other sections is planned.

### Added — Platform-wide CSRF protection (flask-wtf)

`CSRFProtect(app)` enabled in `webapp/app.py`. Every POST form gets a
`{{ csrf_token() }}` hidden input — patched 26 templates / 40 forms.
Bearer-token webhooks (`tls.api_renew`, `tls.api_check_renewals`)
explicitly exempted. A `<meta name="csrf-token">` in base.html plus a
`window.fexFetch()` wrapper auto-attaches `X-CSRFToken` to AJAX calls.

### Added — SMC global session lock (`shared/smc_lock.py`)

`smc-python` keeps session state in a module-level singleton. Under
gunicorn `-k gthread --threads 8`, two concurrent requests would race
on `session.login` / `session.logout` — symptoms ranged from
intermittent "No session found" errors to domain bleeding between
users. New process-wide re-entrant lock serialises every entry into
`smc_session(...)` (and the ad-hoc `session.login` paths in
admin-portal probes). Throughput drops to "one in-flight SMC op per
worker process" — fine for an admin tool.

### Added — DHCP credentials wizard redesign (status-aware, AJAX)

Full rewrite per the operator's linear-flow spec:

- **Live credential test at discover** — `/credentials/discover-nodes`
  runs a TCP probe + SSH `verify_credential` for every existing cred.
  Each node returns `cred_status ∈ {not_enrolled, working, broken}`.
- **Status-aware per-node UI**: `not_enrolled` → green Auto-enroll
  (rotates pwd); `working` → green badge + blue **Apply** (DB-only
  metadata update, no rotation); `broken` → red badge + reason +
  yellow **Overwrite credential** (rotates pwd).
- **Bulk button** is intent-aware: counts new / verified / broken in
  a confirm dialog, routes each node to the right endpoint
  sequentially. No more "rotate all unenrolled" hammer.
- **Live source-IP drift detection** — discover reads each rule's
  source Host's actual IP from SMC and compares against the tenant's
  current `flexedge_source_ip`. On drift, the Rule card shows the
  live IPs + **Overwrite source** / **Add source** buttons.
- **Single canonical rule per engine** — never duplicate. The
  versioned-name approach was reverted on operator feedback.
  `update_source_host_address(...)` and `add_source_host_to_rule(...)`
  mutate the existing rule's source(s).
- **AJAX everywhere — no page refresh on rule actions.** Install
  rule, Push policy, Overwrite source, Add source all return JSON.
  Page-level submit delegator intercepts these forms; on success,
  auto re-runs Discover (silently) so the wizard repaints with the
  new live state. Wizard selections, scroll position, per-node
  panels are preserved.
- **Card 3 inline refresh** — after any successful enrollment, apply,
  or overwrite, `refreshCard3()` swaps just the Card-3 contents from
  a fresh page fetch — no full reload.
- **Auto-select API key** when the chosen tenant has only one active
  key.
- **`/credentials/apply`** new route — DB-only metadata update for
  working credentials. Pre-flights TCP+auth before committing.
- **`/credentials/policy-install`** new route — force a policy upload
  to an engine without changing the rule (Push policy button on Card 3).

### Added — DHCP credentials cache freshness (`webapp/engine_credentials.py`)

Engines-agnostic helper module:

- `state_refreshed_at` columns on `DhcpEngineCredential` and
  `DhcpEngineSshAccess` (additive migration in db_init).
- `get_engine_freshness(...)` returns a `FreshnessSummary`
  (green/amber/red bands; 24 h hard cap).
- `refresh_engine_state(...)` runs the live probe (SMC rule + per-node
  TCP + SSH verify) and returns a structured `RefreshReport` with
  per-component drift messages. Bumps timestamps on rows that
  verified ok.
- New AJAX route `POST /dhcp/credentials/refresh` returns JSON when
  called via `Accept: application/json`; the per-engine "Refresh
  state" button on Card 3 uses it to update the badge + render an
  inline result panel **without reloading the page**.
- All existing ops (bootstrap, verify, force-reset, rule install,
  Phase 4 deploy) bump `state_refreshed_at` on success.

### Added — Phase 0 validation gate for DHCP Phase 4

DHCP Phase 4 is now blocked at preflight until an operator clicks
"I validated Phase 0" on the dashboard. Validation recorded as a
`DhcpActivityLog` row (category=`system`, action=`phase0_validated`);
revoking deletes the row. Dry-run / Preview path bypasses the gate.

### Added — DHCP Phase 4 dry-run / preview

`preview_scope(scope_id, op)` runs the full SSH read + render + diff
pipeline, persists `DhcpDeployment` rows with `action="dry_run"`, but
skips `put_file` and the dhcpd reload. New page
`templates/dhcp/scope_preview.html` shows per-node sha256 before/after,
the unified diff, plus a final "Looks good — Deploy now" button.

### Added — Migration importer: auto-install policy + transactional safety

- **Auto-install checkbox** in the migration import form — default
  off. When ticked, `Engine(<engine_name>).upload(...)` runs at the
  end of the import. Flash messages and the "Engine activation"
  badge in the Import Summary differentiate four states:
  installed-and-live (green), install-failed (red), install-skipped
  (yellow), or rules-not-yet-live (yellow with NEXT STEP pointer).
- **Orphan-Host rollback** in `migration_dhcp_writer.py` — when a per-
  reservation DB write fails after an SMC `host_create` succeeded,
  the Host is immediately deleted. Outer scope-level failures roll
  back every `created_hosts[]` in a fresh SMC session and surface
  unrecoverable orphans by name.

### Hardening (security + correctness)

- **Source-IP drift banner** also surfaced passively on Card 3
  (yellow per-engine banner with Add / Overwrite buttons).
- **Fingerprint-change audit** — `force_reset_password` recovering
  via TOFU after a host-key mismatch records both old and new
  fingerprints in the audit log + flashes a yellow warning.
- **`DhcpDeployment.reload_warning`** column split from `error`.
- **`host_delete` tri-state** — True (deleted), False (not found,
  idempotent ok), raise (real failure). Both callers updated.
- **MAC marker hardening** — case-insensitive prefix, internal
  whitespace tolerated, multiple markers → last wins + WARN-log
  earlier ones, malformed MAC inside well-formed brackets is stripped.
- **Reservation uniqueness** — `(scope_id, mac_address)` AND
  `(scope_id, ip_address)` UNIQUE constraints.
- **Per-engine push lock** — Phase 4 deploy wraps in `engine_op_lock`.
- **Per-scope block markers** — different scopes on the same engine
  no longer strip each other's reservation blocks.
- **`pkill -HUP -x`** exact-match — never accidentally HUPs an
  editor session.
- **Multi-tenant `smc_url` fallback** — `find_tenant_for_target`
  refuses to guess when multiple tenants share an SMC URL and no
  API-key hash matches; surfaces an actionable warning.

### Added — Log retention sweep + CLI

`sweep_old_logs(retention_days)` deletes `dhcp_activity_logs` and
`dhcp_deployments` older than the cutoff (Phase 0 validation rows
preserved). Admin-only `POST /dhcp/system/sweep-logs` triggers
manually; `cli/sweep_dhcp_logs.py` for cron-based runs.

### Architecture decisions saved to memory

Standing rules now persisted across sessions (in
`~/.claude/projects/.../memory/`):

- **`feedback_logging_standing_rule.md`** — every new feature must
  integrate with the platform audit + op log; per-feature toggle +
  retention configurable from Admin Portal (planned).
- **`feedback_credentials_are_engines_level.md`** — DHCP-namespaced
  `DhcpEngineCredential` / `/dhcp/credentials/*` is legacy naming;
  rename + URL move pending. New code uses
  `webapp/engine_credentials.py`.
- **`feedback_caching_pattern.md`** — every SMC-read view goes
  through `shared/smc_cache.py` with refresh button + freshness
  footer.
- **`project_change_management_plan.md`** + **`docs/ChangeManagementProcess.md`** —
  PLANNED two-phase queue between operator clicks and SMC commits.
  Subsumes ad-hoc push paths (migration writer, TLS deploy, DHCP rule
  install, DHCP Phase 4). 6-8 days total.

## [2.2.0-dev] - 2026-04-25

### Added — FortiGate DHCP migration (phases A, B, C, D landed 2026-04-25)

The FortiGate import now handles `config system dhcp server` blocks
end-to-end and feeds them into the existing DHCP Manager:

- **Phase A** (parser + read-only review tab) — `_extract_dhcp_servers()`
  in fgt_parser, "DHCP" tab on parsed.html with per-scope cards.
  See e184773.
- **Phase B** (target mapping + DHCP-ready guard) — `webapp/dhcp_readiness.py`
  resolves migration target → tenant + lists candidate scopes with
  ready/not-ready tags. New `/migration/<id>/dhcp-map` route + template
  persists `target.dhcp_mappings`. See 412f61d.
- **Phase C** (dedup) — `_dedup_dhcp_reservations()` in dedup_engine.py
  classifies each parsed reservation against existing DhcpReservation
  rows on the mapped target scope (already_migrated / mac_conflict /
  ip_conflict / new). DB-only, no SMC session required. New "DHCP" tab
  on dedup.html with per-FG-scope cards + per-reservation checkboxes
  and a "⚙ Overwrite" button for conflicts (operator opts into making
  the FG value win at import).
- **Phase D** (importer) — `webapp/migration_dhcp_writer.py`
  `import_dhcp_reservations()` calls `smc_dhcp_client.host_create()`
  (same path the DHCP Manager UI uses, same `[flexedge:mac=...]` comment
  marker) for every selected reservation, inserts a DhcpReservation row
  with `source="migration:<project_id>"` and `status="pending"` so it
  appears in the existing DHCP Manager UI ready for the existing Phase 4
  "Deploy" button. **Migration never pushes** — it only stages.
- **Locked design constraints** (chat with operator, 2026-04-25):
  imported config wins in staging (conflicts default off; operator opts
  into overwrite); migration reuses DHCP Manager primitives entirely;
  un-ready scopes are blocked at import with deep links to enroll/enable
  rather than auto-enrolling.
- **Schema additions** (additive, lightweight): `DhcpReservation.source`
  column for traceability ("migration:&lt;project_id&gt;"). Migrated rows
  show a "From migration" source tag in the DHCP Manager UI.

Files: webapp/dhcp_readiness.py, webapp/migration_dhcp_writer.py,
webapp/dedup_engine.py (extended), webapp/db_init.py (ALTER TABLE for
.source), webapp/templates/migration/{dhcp_map,dedup,parsed}.html,
webapp/app.py (new routes: /dhcp-map GET/POST, /dhcp/update AJAX,
/import wired to the writer).

### Added — DHCP Reservation Manager (in progress — phases 0, 1, 1b, 1c, 2, 3, 4 landed)

**Phase 4 — engine-side reservation push (2026-04-25):**

- **`webapp/dhcp_pusher.py`** — new module: renders FlexEdge-managed reservations as ISC dhcpd `host { hardware ethernet ...; fixed-address ...; }` blocks, merges them into `/data/config/base/dhcp-server.conf` between `# FLEXEDGE-RESERVATIONS-BEGIN` / `# FLEXEDGE-RESERVATIONS-END` markers (idempotent: replaces existing block in place), and atomically writes via `put_file()` (tmp + posix_rename). SMC's subnet block is never touched — host blocks at top level work because ISC matches them by IP into the surrounding subnet.
- **Per-node orchestration** — `push_scope_to_engine(scope_id, operator_email, action)` runs against every cluster node in order: TCP probe → credential verify → read current file → render + merge → atomic write → re-read verify (sha256 round-trip) → best-effort `pkill -HUP` reload. Each node gets a `DhcpDeployment` audit row with sha256_before/after, unified diff (trimmed to 200 lines), duration, and any reload warning. Reservation rows flip to `synced` on full success, `error` on partial / total failure (with `last_error` populated).
- **Pre-flight guard** — `_check_preconditions()` blocks the push if the scope isn't `enabled_in_flexedge`, any cluster node lacks a verified credential, or the SSH allow rule is missing — surfacing a clear operator-facing message + `dhcp_activity_logs` row instead of attempting and failing per-node.
- **Wired into existing routes** — `POST /dhcp/scopes/<id>/deploy` and `POST /dhcp/scopes/<id>/resync` now call the pusher (replacing the Phase-3 stubs that only flashed warnings). The existing "Deploy to engine" button on `scope_detail.html` works without template changes.
- **Per-node failure isolation** — failures on one node never abort the loop; aggregate status is `ok` (all nodes), `partial` (some), or `failed` (none). Operator gets per-node detail in flash messages and the deployment-history card.
- **Reload best effort** — `pkill -HUP` against `dhcp-server` then `dhcpd` (Forcepoint engines run the daemon under either name); if neither matches we surface a warning and tell the operator to refresh the policy in SMC. Never fails the deployment over a reload issue.

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

- **Multi-IP SSH allow rule** — `add_ssh_access_rule(... destination_ips: list)` now creates one rule with N Host elements (`<rule_name>-dst-0`, `<rule_name>-dst-1`, …) so a single rule covers every cluster node. Multi-checkbox picker in the UI; SMC-initiated cluster pre-checks all IPs, node-initiated requires explicit operator selection. Cleanup symmetrically removes both the new `-dst-<n>` shape and the legacy single `-dst` shape.
- **Bulk enrollment** — new `POST /credentials/bootstrap-batch` endpoint enrolls every unenrolled node for an engine within ONE `smc_session` and ONE per-engine lock. Green "Enroll all (N)" button at the top of the cluster nodes section reads each node form's data and submits a single POST. Per-node "Auto-enroll" buttons retained for surgical operations.
- **Dashboard summary** — `/dhcp/` now has a second stats row (Enrolled engines, Total node credentials, Verified, SSH allow rules in policies) and an "Enrolled clusters & nodes" table grouped by (tenant, engine) showing node count, status pills, rule name with multi-IP indicator (`+N more`), and last-verified timestamp.
- **NDI-based node discovery** — `list_cluster_nodes()` now walks `engine.physical_interface` config (instead of the runtime `interface_status` probe that returned empty). Picks up `NodeInterface` and `SingleNodeInterface` entries from physical + VLAN children, groups by `nodeid`. Skips `cluster_virtual_interface` (CVI) — those are shared cluster IPs, not per-node targets.
- **Node-initiated contact detection** — new `is_node_initiated_contact()` reads the `reverse_connection` flag on every primary mgmt interface (the SDK's name for what the SMC GUI calls "Node-Initiated Contact"). Banner in the rule install card; per-node IP picker requires explicit selection vs auto-suggesting the primary mgt IP.

- **Phase 1c — Auto-enrollment via SMC API**. Replaces the Phase 1 password-prompt flow.
  - **No password ever typed by the operator.** FlexEdgeAdmin generates a 64-char random root password and sets it via SMC's `node.change_ssh_pwd` endpoint.
  - **No public-key install.** Auth is **password-only** (Fernet-encrypted in DB, pinned host fingerprint), engine `authorized_keys` left untouched.
  - **SSH allow rule** auto-installed on the engine's active policy (name `flexedge-dhcp-mgmt-ssh-<engine>`), with operator-confirmed source IP. Rule is removed when last credential for the engine is deleted, or via a manual "Remove SSH rule" button. Detected if removed externally — banner asks operator to recreate.
  - **Per-engine concurrency lock** prevents two enrollments racing on the same node's password.
  - **A3 recovery path**: when verify fails with `paramiko.AuthenticationException` (someone changed root pw out of band), an operator-confirmed "Force re-bootstrap" button rotates the password again via SMC API.
  - **Pre-flight TCP probe** to the chosen node IP before mutating anything — fails fast with a clear error if the rule push didn't open the path.
  - **Public-IP probe** (api.ipify.org / ifconfig.me / icanhazip) suggests the FEA source IP per tenant; operator confirms or overrides.
- **Schema changes (auto-migrating on boot)**:
  - `tenants.flexedge_source_ip` (new column, ALTER TABLE on existing DBs).
  - `dhcp_engine_credentials` — replaces `public_key_openssh` + `private_key_pem` with `encrypted_password`. Existing key-based rows from earlier dev-only Phase 1 are dropped on first boot of the new schema (logged warning); re-enroll affected nodes.
  - `dhcp_engine_ssh_access` (new) — tracks the FlexEdge-managed SSH allow rule per engine with the rule name as the stable lookup tag.
- **CLAUDE.md DB schema section** to be updated in Phase 6 along with all docs.

### Phase summary (cumulative across earlier 2.2.0-dev iterations)

- **Phase 0** — [docs/DHCP-Phase0-LabTest.md](docs/DHCP-Phase0-LabTest.md): operator-ready procedure to verify whether `/data/config/base/dhcp-server.conf` survives policy refresh/upload/reboot. Gates Phase 4.
- **Phase 2** — DB tables `dhcp_scopes`, `dhcp_reservations`, `dhcp_deployments`, `dhcp_activity_logs`, `dhcp_engine_credentials`, `dhcp_engine_ssh_access`.
- **Phase 3** — DHCP Manager Blueprint at `/dhcp/*` (admin-only): scope discovery (recursive walker handling multiple DHCP-config shapes), reservation CRUD with `[flexedge:mac=...]` marker on SMC Host comment, sync-from-SMC, deploy stub, diagnostic endpoint, activity log.
- **Phase 1b** — Cluster lease viewer: ISC `dhcpd.leases` parser, per-engine cluster lease table with reservation cross-check (mismatch flagged red).

### Changed — DHCP Reservation Manager

- `webapp/models.py` docstring updated to list the new DHCP tables.
- Sidebar nav gained a "DHCP Manager" section (admin-only).
- `docs/DHCP-ResrvationStrategy.md` → `docs/DHCP-ReservationStrategy.md` (filename typo fix via `git mv`).

## [2.1.0] - 2026-04-15

### Added

- **TLS Manager** — new admin-only feature (`/tls/*`) that automates TLS certificate lifecycle for Forcepoint NGFW engines, bridging Let's Encrypt (certbot) with the SMC API:
  - Track certbot-managed certificates (reads `/etc/letsencrypt/live/`)
  - Deploy pipeline: import cert as `TLSServerCredential`, create host objects, assign to engine TLS inspection, create access rule with deep inspection + file filtering + decryption, upload policy
  - Reuses existing `Tenant` + `ApiKey` models — no duplicate SMC connection config
  - Renewal webhook (`POST /tls/api/renew`, Bearer-token auth) callable by certbot's deploy-hook
  - In-app deploy-hook generator + auto-installer (writes to `/etc/letsencrypt/renewal-hooks/deploy/`)
  - Activity log on dashboard: every operation, full error details, filterable by status
  - Supports domain-scoped API keys (keys that can't enumerate admin domains use their API client name as a domain hint)
- **Certbot in the main Docker image** — `apt install certbot` added to `docker/Dockerfile`
- **`/etc/letsencrypt` volume mount** added to `docker/docker-compose.yml` (read-only)
- **New DB tables** (auto-created on first boot): `managed_certificates`, `tls_deployments`, `tls_deployment_logs`, `tls_activity_logs`
- **Documentation**: TLS Manager feature documented inline in `CLAUDE.md` (developer reference) and `docs/deployment-guide.md` (operator setup + troubleshooting) — same treatment as Admin Portal and Migration Manager

### Changed

- Sidebar nav now includes a "TLS Manager" section (admin-only)
- `CLAUDE.md` updated with the TLS Manager feature description and DB schema additions

### Fixed

- **Engine discovery in TLS Manager** now covers all SMC engine types via a three-stage cascade: (1) generic `Engine.objects.all()`, (2) per-subclass enumeration (Layer 2 / cluster / virtual / master / IPS / cloud), (3) **raw REST fallback** against `/elements/engine_clusters` and every specific-type endpoint. Each engine gets a list of which stages saw it, exposed via the new diagnostic endpoint. Previously only `Layer3Firewall` and `FirewallCluster` were queried.
- **Deploy.sh path with spaces** — the script now uses relative compose paths with an upfront `cd "$PROJECT_DIR"`, fixing the "unknown docker command" word-splitting bug when the project lives under a folder with spaces (e.g. iCloud Drive).

### Added — developer/operator visibility

- **Running build version in the web UI** — sidebar footer now shows `v{version} ({commit})` with a tooltip containing the full commit SHA and ISO build date. Click the version to open the `/version` JSON endpoint.
- **New `/version` endpoint** — returns `{version, commit, commit_full, build_date, display}` as JSON. Unauthenticated, safe for monitoring / uptime checks.
- **Version metadata injection** — `deploy.sh` auto-computes `FLEXEDGE_VERSION` (from CHANGELOG.md top entry), `FLEXEDGE_COMMIT` (short git SHA), `FLEXEDGE_COMMIT_FULL`, `FLEXEDGE_BUILD_DATE` (UTC ISO-8601) before `docker compose build` and passes them as build args. Dockerfile accepts the args and bakes them into `ENV`. `shared/version.py` reads env vars first, falls back to a committed `.version.json` file (stamped by `pack-release.sh`), then to live `git` commands, and finally to CHANGELOG parsing for the version string.
- **Coolify-compatible version stamping** — `scripts/pack-release.sh` writes a `.version.json` file into `FlexEdgeAdminProd/` on every release, containing `version`, `commit`, `commit_full`, and `build_date`. The Dockerfile copies it into the image via a glob wildcard (`COPY .version.jso[n] ./` — silent when the file is absent in the private repo). Coolify customers building directly from the public repo get the correct version displayed in the UI without any Coolify-side configuration.
- **Customer deployment verification** — `pack-release.sh --verify <URL>` polls `<URL>/version` every 5 seconds after pushing until the customer's running build matches the pushed commit. Repeatable (pass `--verify` multiple times for several customers), with a configurable `--verify-timeout` (default 30 seconds). Prints per-customer OK / FAIL summary at the end. Useful for confirming Coolify redeploys landed.
- **TLS engine-fetch activity logging** — every `/api/tenants/<id>/api-keys/<id>/engines` call now writes an entry to `tls_activity_logs` with the returned engine list, so you can see from the dashboard what the API returned without re-opening the browser inspector.
- **New TLS diagnostic endpoint** `/tls/api/tenants/<tid>/api-keys/<kid>/engines/debug` — returns the full engine list with per-source attribution (which discovery stage saw each engine), used for troubleshooting missing-engine cases.

### Removed

- Standalone `FlexEdgeTLSManagement/` folder and its `.gitignore` entry (merged into the main webapp as a Blueprint)

### Changed — developer ergonomics

- `deploy.sh --dev` — new explicit dev flag that runs the guided bootstrap (Docker check, `.env` setup, Azure AD prompt), then `docker compose up --build` in the **foreground** with live logs (Ctrl+C to stop)
- `make dev` now routes through `./deploy.sh --dev` so first-time setup works without manually creating `.env`. Previously it failed if `.env` was missing.
- `make prod` now routes through `./deploy.sh` (production with TLS)
- `make dev-raw` / `make prod-raw` — new escape hatches for the raw `docker compose` commands (CI, debugging) that skip the bootstrap
- `--no-tls` kept as a detached (background) dev mode for CI/automation

## [2.0.0] - 2026-04-12

### Added

- **Three deployment options** documented and supported:
  - **Standalone**: new `scripts/install-standalone.sh` — native install with
    Python venv at `/opt/flexedge/`, config at `/etc/flexedge/`, systemd service
    (`flexedge.service`), nginx site config, certbot-ready
  - **Docker + nginx**: unchanged `./deploy.sh` flow (full stack via compose)
  - **Coolify / Traefik**: new `docker/docker-compose.coolify.yml` — no bundled
    nginx/certbot (Coolify handles TLS, routing, Let's Encrypt via Traefik)
  - Full 3-option comparison table and per-option instructions in
    `docs/deployment-guide.md`
- **Uninstall support** in `deploy.sh`:
  - `--uninstall` — stop/remove containers, preserve all data and config
  - `--uninstall --purge` — full clean slate: deletes DB, encryption key, .env,
    Docker images, certbot volumes (requires typing "PURGE" to confirm)
- **Azure setup automation** (`scripts/azure-setup.sh`) — single command to:
  - Create Entra ID App Registration with OIDC configuration
  - Enable ID tokens, set redirect URIs (dev + production)
  - Create client secret (2-year expiry)
  - Add Microsoft Graph permissions (openid, email, profile)
  - Grant admin consent
  - Generate Flask secret key
  - Write complete `.env` file
  - Flags: `--domain`, `--app-name`, `--skip-consent`
  - Integrated into `deploy.sh` (offers to run automatically)
- **Admin Portal** (`/admin/`) — web-based CRUD for tenants, users, and API keys
  - Tenant management: create, edit, soft-delete SMC server connections
  - User management: create, edit, role assignment (admin/viewer), tenant access mapping
  - API Key management: Fernet-encrypted storage, one-time plaintext display on creation, revoke
  - Backup: download ZIP of database + encryption key from Admin Portal
  - JSON Migration: one-click import from legacy `tenants.json` + `users.json`
  - Admin dashboard with stats, backup, and migration controls
- **Encrypted database** — SQLite with Fernet field-level encryption (AES-128-CBC + HMAC-SHA256)
  - Binary encryption key file (`FXEK` magic header format) auto-generated on first run
  - Without the key file, encrypted API keys are permanently irrecoverable (by design)
  - SQLite WAL mode enabled for concurrent read performance
  - Database schema: `tenants`, `users`, `api_keys`, `user_tenant_access` tables
- **Setup wizard** — one-time `/setup` page on first run
  - Requires Azure AD login first (security: only valid Azure AD users can claim admin)
  - Creates the first admin user, then becomes permanently inaccessible
- **DB-backed data layer** — user profiles and tenant config read from DB with JSON fallback
  - `webapp/user_manager.py` queries DB first, falls back to `users.json`
  - `shared/tenant_config.py` queries DB first, falls back to `tenants.json`
  - CLI tools automatically use JSON fallback (no Flask context needed)
- **New files**: `webapp/admin.py`, `webapp/setup.py`, `webapp/models.py`, `webapp/db_init.py`,
  `shared/encryption.py`, `shared/db.py`, 10 admin templates

### Changed

- **Configuration model** — JSON files replaced by Admin Portal as primary config method
  - `.env` is the only file to edit before first start (Azure AD credentials)
  - Tenants, users, and API keys managed via web UI instead of JSON files
- **Docker volumes** — `config/` directory mounted as a whole (contains DB + key + legacy JSONs)
- **deploy.sh** — no longer creates `tenants.json` / `users.json`; points users to setup wizard
- **requirements.txt** — added `flask-sqlalchemy>=3.1`, `cryptography>=42.0`
- **`.gitignore`** — added `*.db`, `encryption.key`
- **Sidebar** — admin link visible only to admin-role users
- **`scripts/pack-release.sh`** — production release packer
  - Builds a clean `./production/` folder with zero client-specific data
  - Sanitizes firewall names, IP ranges, server URLs, client references
  - Automated verification scan — aborts on any leaked secrets
  - `--no-push` flag to skip pushing (default: commit and push)
  - `--message "msg"` for custom commit messages
  - Preserves `production/.git` across rebuilds (remote config, history retained)

### Security

- Removed `__pycache__/connect.cpython-314.pyc` from git tracking
- Sanitized `scripts/service_mapping.json` (replaced real SMC URL with placeholder)
- Sanitized `config/smc_config.yml.example` (removed client name)
- `production/` folder gitignored — clean public release with no git history leak

---

## [1.0.0] - 2026-04-12

### Added

- **FlexEdgeAdmin branding** — unified project identity replacing "SMC Explorer"
- **Shared tenant configuration** (`shared/tenant_config.py`) — single source of truth
  for SMC connection definitions, used by both CLI and webapp
  - `config/tenants.json` defines URL, SSL, timeout, domain per tenant
  - API keys remain per-user (in `users.json` for web, env var for CLI)
- **Unified Docker setup** — single image containing webapp + CLI + migration scripts
  - `docker/Dockerfile` — python:3.12-slim with gunicorn
  - `docker/docker-compose.yml` — development compose
  - `docker/docker-compose.prod.yml` — production overlay with nginx + certbot TLS
  - `docker/nginx.conf` — reverse proxy with security headers
- **Deployment automation**
  - `deploy.sh` — one-command VPS setup (installs Docker, creates configs, starts services)
  - `Makefile` — convenience targets (dev, prod, stop, logs, cli, update)
  - `docs/deployment-guide.md` — complete operator guide
- **Configuration templates** — `.example` files for all secrets
  - `config/tenants.json.example`, `config/users.json.example`
  - `config/.env.example`, `config/config.ini.example`
- **APP_TITLE env var** — customizable branding per deployment

### Changed

- **Repository restructured** into `cli/`, `webapp/`, `shared/`, `scripts/`, `config/`, `docker/`, `docs/`
- **CLI connect.py** — now supports `--tenant` flag + `SMC_API_KEY` env var; falls back to legacy `config.ini`
- **CLI smc.sh** — passes `--tenant` flag, sets PYTHONPATH, venv at project root
- **webapp/user_manager.py** — resolves tenant references from `tenants.json`; backward compatible with old embedded `smc_url` format
- **users.json format** — profiles now reference tenants by ID instead of embedding full connection details
- Unified `requirements.txt` at project root (merged CLI + webapp deps)

### Security

- Removed `config.ini` from git tracking (contained real API key)
- All secret files added to `.gitignore`: `config.ini`, `tenants.json`, `users.json`, `.env`, `smc_config.yml`
- Docker never bakes secrets into images — always volume-mounted

---

## [0.3.0] - 2026-04-11

### Added

- **Microsoft Entra ID OIDC login** — all webapp routes protected
- **Multi-user support** — per-user SMC API profiles via `users.json`
- **SMC admin domain selection** per session
- **ProxyFix** for correct HTTPS redirect URIs behind reverse proxies

---

## [0.2.0] - 2026-03-11

### Added

- **SMC Explorer webapp** — read-only browser for all SMC objects and policies
- **Migration Manager** — 7-step guided FortiGate-to-Forcepoint migration workflow
- **NAT rules migration** — SNAT dynamic, DNAT static, combined
- **IPsec VPN migration** — profiles, gateways, sites, PolicyVPN
- **Docker deployment** — Dockerfile, docker-compose.yml

---

## [0.1.0] - 2026-01-20

### Added

- Initial CLI tools: `connect.py`, `inquiry.py`, `firewall.py`, `smc.sh`
- Firewall management: list, show, interfaces, add/delete/update interface, VLAN, policy refresh/upload
- Object query and inspection with type/name filtering
- Cluster support: CVI, NDI, multi-node configuration
- Documentation: guides for each CLI module
