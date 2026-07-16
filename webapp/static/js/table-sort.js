/*
 * FlexEdgeAdmin — generic click-to-sort for tables.
 *
 * STANDARD (use this on every new data table): add `class="sortable-table"`
 * to the <table>. That's it. Every non-empty header becomes clickable;
 * click to sort, click again to toggle asc/desc. A ▲/▼ indicator marks the
 * active column. Column type (ip / number / date / text) is auto-detected
 * from the cell values, so IP and numeric columns sort naturally
 * (192.168.1.6 before 192.168.1.69) with no extra markup.
 *
 * Opt-outs / overrides:
 *   - <th data-no-sort>        → this column is not sortable (e.g. an
 *                                 "Actions" column). Empty <th></th> headers
 *                                 are auto-skipped too.
 *   - <th data-sort-type="ip|num|date|text"> → force a column's sort type
 *                                 instead of auto-detecting.
 *   - <td data-sort-value="…">  → sort this cell by a canonical value that
 *                                 differs from what's displayed (e.g. an ISO
 *                                 timestamp behind a "2 days ago" label, or a
 *                                 raw byte count behind "1.5 MB").
 *
 * Rows are matched to the header by column count, so a full-width
 * placeholder row (`<td colspan=…>No rows</td>`) is left untouched. Only the
 * first <tbody> is sorted. Empty / "—" cells always sort to the bottom
 * regardless of direction.
 *
 * Dynamically-added tables: call window.FEATableSort.enhance(tableEl) after
 * you inject one (idempotent — safe to call twice).
 */
(function () {
  "use strict";

  var IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/;
  var NUM_RE = /^-?\d+(\.\d+)?$/;

  function isEmptyVal(v) {
    return v === "" || v === "—" || v === "-" || v == null;
  }

  function cellValue(row, colIndex) {
    var td = row.children[colIndex];
    if (!td) return "";
    if (td.dataset && td.dataset.sortValue != null) {
      return td.dataset.sortValue.trim();
    }
    return (td.textContent || "").trim();
  }

  function detectType(values) {
    var seen = false;
    var allIp = true, allNum = true, allDate = true;
    for (var i = 0; i < values.length; i++) {
      var v = values[i];
      if (isEmptyVal(v)) continue;
      seen = true;
      if (!IP_RE.test(v)) allIp = false;
      if (!NUM_RE.test(v.replace(/,/g, ""))) allNum = false;
      // Only treat as a date when it actually looks like one (has a
      // separator) AND parses — otherwise plain integers get mis-typed.
      if (!(/[-/:]/.test(v) && v.length > 6 && !isNaN(Date.parse(v)))) {
        allDate = false;
      }
    }
    if (!seen) return "text";
    if (allIp) return "ip";
    if (allNum) return "num";
    if (allDate) return "date";
    return "text";
  }

  function ipKey(s) {
    var m = s.split("/");
    var parts = m[0].split(".");
    if (parts.length !== 4) return [0, 0, 0, 0, 0];
    var out = parts.map(function (p) { return parseInt(p, 10) || 0; });
    out.push(m.length > 1 ? (parseInt(m[1], 10) || 0) : 0);
    return out;
  }

  function makeComparator(type) {
    if (type === "ip") {
      return function (a, b) {
        var ka = ipKey(a), kb = ipKey(b);
        for (var i = 0; i < 5; i++) {
          if (ka[i] !== kb[i]) return ka[i] - kb[i];
        }
        return 0;
      };
    }
    if (type === "num") {
      return function (a, b) {
        return (parseFloat(a.replace(/,/g, "")) || 0) -
               (parseFloat(b.replace(/,/g, "")) || 0);
      };
    }
    if (type === "date") {
      return function (a, b) {
        return (Date.parse(a) || 0) - (Date.parse(b) || 0);
      };
    }
    return function (a, b) {
      return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
    };
  }

  function firstBody(table) {
    var bodies = table.tBodies;
    return bodies && bodies.length ? bodies[0] : null;
  }

  function headerCells(table) {
    var thead = table.tHead;
    if (!thead || !thead.rows.length) return [];
    // Use the last header row (some tables have a group row above).
    var row = thead.rows[thead.rows.length - 1];
    return Array.prototype.slice.call(row.cells);
  }

  function sortableRows(tbody, colCount) {
    return Array.prototype.slice.call(tbody.rows).filter(function (r) {
      return r.children.length === colCount && !r.hasAttribute("data-no-sort");
    });
  }

  function enhance(table) {
    if (!table || table.__feSortWired) return;
    var tbody = firstBody(table);
    var headers = headerCells(table);
    if (!tbody || !headers.length) return;
    table.__feSortWired = true;

    var colCount = headers.length;
    var state = { key: null, dir: "asc" };

    headers.forEach(function (th, colIndex) {
      var label = (th.textContent || "").trim();
      var skip = th.hasAttribute("data-no-sort") || label === "";
      if (skip) return;

      th.classList.add("fe-sortable");
      var indicator = document.createElement("span");
      indicator.className = "fe-sort-indicator";
      th.appendChild(indicator);

      th.addEventListener("click", function () {
        var rows = sortableRows(tbody, colCount);
        if (!rows.length) return;

        var type = th.dataset.sortType ||
                   detectType(rows.map(function (r) { return cellValue(r, colIndex); }));
        var base = makeComparator(type);

        if (state.key === colIndex) {
          state.dir = state.dir === "asc" ? "desc" : "asc";
        } else {
          state.key = colIndex;
          state.dir = "asc";
        }
        var mul = state.dir === "asc" ? 1 : -1;

        rows.sort(function (ra, rb) {
          var va = cellValue(ra, colIndex), vb = cellValue(rb, colIndex);
          var ea = isEmptyVal(va), eb = isEmptyVal(vb);
          if (ea && eb) return 0;
          if (ea) return 1;      // empties always sink to the bottom …
          if (eb) return -1;     // … regardless of direction
          return mul * base(va, vb);
        });

        rows.forEach(function (r) { tbody.appendChild(r); });

        headers.forEach(function (h) {
          h.classList.remove("fe-sort-asc", "fe-sort-desc");
        });
        th.classList.add(state.dir === "asc" ? "fe-sort-asc" : "fe-sort-desc");
      });
    });
  }

  function enhanceAll(root) {
    var scope = root || document;
    var tables = scope.querySelectorAll("table.sortable-table");
    Array.prototype.forEach.call(tables, enhance);
  }

  window.FEATableSort = { enhance: enhance, enhanceAll: enhanceAll };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { enhanceAll(); });
  } else {
    enhanceAll();
  }
})();
