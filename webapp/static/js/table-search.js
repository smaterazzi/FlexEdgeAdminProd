/*
 * FlexEdgeAdmin — generic search for tables. Pairs with table-sort.js and
 * keys off the SAME marker: any `table.sortable-table` automatically gets
 * search too (sort + search = the standard "managed table" treatment).
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
 * Caveat: like sort, this is client-side over the rendered rows — on a
 * server-paginated table it searches the current page only.
 *
 * AJAX tables: call window.FEATableSearch.enhance(tableEl) after injecting.
 */
(function () {
  "use strict";

  var DEBOUNCE_MS = 120;

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

  function headerRow(table) {
    var thead = table.tHead;
    if (!thead) return null;
    var rows = Array.prototype.slice.call(thead.rows).filter(function (r) {
      return !r.classList.contains("fe-filter-row");
    });
    return rows.length ? rows[rows.length - 1] : null;
  }

  function isSearchable(th) {
    return !th.hasAttribute("data-no-sort") && (th.textContent || "").trim() !== "";
  }

  // Mirror table-sort.js: group each data row with the non-data rows that
  // follow it, so a detail row hides/shows with its parent.
  function partition(tbody, colCount) {
    var leading = [], groups = [], current = null;
    Array.prototype.forEach.call(tbody.rows, function (r) {
      var isData = r.children.length === colCount && !r.hasAttribute("data-no-sort");
      if (isData) { current = { lead: r, extra: [] }; groups.push(current); }
      else if (current) { current.extra.push(r); }
      else { leading.push(r); }
    });
    return { leading: leading, groups: groups };
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
        var inp = document.createElement("input");
        inp.type = "search";
        inp.className = "form-control form-control-sm fe-col-search";
        inp.placeholder = "filter…";
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
    var gbox = document.createElement("input");
    gbox.type = "search";
    gbox.className = "form-control form-control-sm fe-global-search";
    gbox.placeholder = "Search all columns…";
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
        g.lead.style.display = ok ? "" : "none";
        g.extra.forEach(function (e) { e.style.display = ok ? "" : "none"; });
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
    var scope = root || document;
    Array.prototype.forEach.call(
      scope.querySelectorAll("table.sortable-table"), enhance);
  }

  window.FEATableSearch = { enhance: enhance, enhanceAll: enhanceAll };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { enhanceAll(); });
  } else {
    enhanceAll();
  }
})();
