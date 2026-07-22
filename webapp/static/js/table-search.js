/*
 * FlexEdgeAdmin — generic search for tables. Pairs with table-sort.js and
 * table-export.js off the SAME marker: any `table.managed-table` gets all
 * three (see table-core.js for the contract). A table with its own bespoke
 * search opts this pillar out with a table-level `data-no-search`.
 *
 * Two searches per table (see CLAUDE.md § Table search):
 *
 *   1. GLOBAL box (rendered above the table): matches across ALL data
 *      columns at once. A row matches if the query matches its combined
 *      column text.
 *   2. PER-COLUMN row (rendered under the header): one input per data
 *      column — a "selective" filter that narrows just that field. Active
 *      per-column filters combine with AND (a row must satisfy every one).
 *
 * Token grammar (identical in both the global box and each column box):
 *   - Whitespace separates tokens.
 *   - Default is logical OR — the row/cell matches if ANY token is found.
 *   - Include a capital `AND` token to switch that box to logical AND — the
 *     row/cell must then contain EVERY token. (lowercase "and" is a literal
 *     search term, not the operator.)
 *   - Matching is case-insensitive substring.
 *
 * Columns marked `data-no-sort` (or an empty `<th>`) — typically the
 * checkbox / Actions column — get no filter input and are excluded from the
 * global match, so searching never keys off button labels.
 *
 * Interop: the per-column inputs live in a `<tr class="fe-filter-row">`
 * inside <thead>; table-sort.js skips that row. Detail/continuation rows
 * (matched by column count, e.g. a push_failed reservation's colspan error
 * row) are hidden/shown together with their parent data row.
 *
 * Row visibility goes through FERowFilter under the key "search" rather
 * than writing `row.style.display` directly, so a page that ALSO filters
 * with its own controls (leases state chips, scan reachability buttons,
 * TLS activity status buttons) composes with this search instead of
 * overwriting it. See table-core.js.
 *
 * Caveat: like sort, this is client-side over the rendered rows — on a
 * server-paginated table it searches the current page only.
 *
 * AJAX tables: call window.FEATableSearch.enhance(tableEl) after injecting.
 */
(function () {
  "use strict";

  var DEBOUNCE_MS = 120;

  // Several managed tables live INSIDE a <form> (the leases viewer sits in
  // the "Add to reservations" form). A bare Enter in one of our injected
  // inputs would submit that form — on the leases page that would create
  // reservations. Swallow Enter; the inputs carry no `name`, so they are
  // never submitted as fields either.
  function makeInput(cls, placeholder) {
    var el = document.createElement("input");
    el.type = "search";
    el.className = "form-control form-control-sm " + cls;
    el.placeholder = placeholder;
    el.autocomplete = "off";
    el.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") ev.preventDefault();
    });
    return el;
  }

  function parseQuery(q) {
    var raw = (q || "").trim();
    if (!raw) return { tokens: [], mode: "or" };
    var mode = "or";
    var tokens = [];
    raw.split(/\s+/).forEach(function (p) {
      if (p === "AND") { mode = "and"; return; }   // capital AND = operator
      tokens.push(p.toLowerCase());
    });
    return { tokens: tokens, mode: mode };
  }

  function matches(text, parsed) {
    if (!parsed.tokens.length) return true;          // inactive filter
    var hay = (text || "").toLowerCase();
    if (parsed.mode === "and") {
      return parsed.tokens.every(function (t) { return hay.indexOf(t) !== -1; });
    }
    return parsed.tokens.some(function (t) { return hay.indexOf(t) !== -1; });
  }

  var headerRow = function (t) { return window.FETable.headerRow(t); };
  var partition = function (tb, n) { return window.FETable.partition(tb, n); };

  function isSearchable(th) {
    return !th.hasAttribute("data-no-sort") &&
           !th.hasAttribute("data-no-export") &&
           (th.textContent || "").trim() !== "";
  }

  function enhance(table) {
    if (!table || table.__feSearchWired) return;
    var hr = headerRow(table);
    var tbody = table.tBodies && table.tBodies[0];
    if (!hr || !tbody) return;
    table.__feSearchWired = true;

    var headers = Array.prototype.slice.call(hr.cells);
    var colCount = headers.length;

    // ── Per-column filter row ────────────────────────────────────────────
    var filterRow = document.createElement("tr");
    filterRow.className = "fe-filter-row";
    var colInputs = [];      // { index, input }
    headers.forEach(function (th, idx) {
      var cell = document.createElement("th");
      if (isSearchable(th)) {
        var inp = makeInput("fe-col-search", "filter…");
        inp.setAttribute("aria-label",
          "Filter by " + (th.textContent || "").trim());
        cell.appendChild(inp);
        colInputs.push({ index: idx, input: inp });
      }
      filterRow.appendChild(cell);
    });
    table.tHead.appendChild(filterRow);

    var searchIndices = colInputs.map(function (ci) { return ci.index; });
    function rowText(row) {
      return searchIndices.map(function (i) {
        var td = row.children[i];
        return td ? (td.textContent || "") : "";
      }).join("  ");
    }
    function cellText(row, idx) {
      var td = row.children[idx];
      return td ? (td.textContent || "") : "";
    }

    // ── Global search bar (above the table / its .table-responsive) ───────
    var anchor = (table.parentElement &&
                  table.parentElement.classList.contains("table-responsive"))
      ? table.parentElement : table;
    var bar = document.createElement("div");
    bar.className = "fe-table-search d-flex align-items-center gap-2 mb-2";
    var gbox = makeInput("fe-global-search", "Search all columns…");
    gbox.title = "Space-separated tokens match with OR by default; " +
                 "include a capital AND to require every token.";
    var counter = document.createElement("span");
    counter.className = "small text-muted fe-search-count";
    bar.appendChild(gbox);
    bar.appendChild(counter);
    if (anchor.parentNode) anchor.parentNode.insertBefore(bar, anchor);

    function apply() {
      var gParsed = parseQuery(gbox.value);
      var colParsed = colInputs.map(function (ci) {
        return { index: ci.index, parsed: parseQuery(ci.input.value) };
      });
      var anyActive = gParsed.tokens.length > 0 ||
        colParsed.some(function (c) { return c.parsed.tokens.length > 0; });

      var parts = partition(tbody, colCount);
      var visible = 0;
      parts.groups.forEach(function (g) {
        var ok = matches(rowText(g.lead), gParsed);
        if (ok) {
          for (var i = 0; i < colParsed.length; i++) {
            if (!matches(cellText(g.lead, colParsed[i].index), colParsed[i].parsed)) {
              ok = false; break;
            }
          }
        }
        // Veto under our own key — a page's own filter buttons keep theirs.
        window.FERowFilter.setGroup(g, "search", ok);
        if (ok) visible++;
      });
      counter.textContent = anyActive
        ? (visible + " of " + parts.groups.length)
        : "";
    }

    var timer = null;
    function schedule() {
      if (timer) clearTimeout(timer);
      timer = setTimeout(apply, DEBOUNCE_MS);
    }
    gbox.addEventListener("input", schedule);
    colInputs.forEach(function (ci) { ci.input.addEventListener("input", schedule); });
  }

  function enhanceAll(root) {
    window.FETable.eachTable(root, "search", enhance);
  }

  window.FEATableSearch = { enhance: enhance, enhanceAll: enhanceAll };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { enhanceAll(); });
  } else {
    enhanceAll();
  }
})();
