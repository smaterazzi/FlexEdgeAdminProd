/*
 * FlexEdgeAdmin — shared core for the "managed table" treatment.
 *
 * Load order: this file FIRST, then table-sort.js, table-search.js,
 * table-export.js (see base.html). It owns the three things all of them
 * need, so none of them re-implements it:
 *
 *   1. The marker/opt-out contract  — FETable.SELECTOR + FETable.enabled()
 *   2. Table anatomy               — headerRow() / partition() / dataColumns()
 *   3. Row visibility arbitration  — FERowFilter
 *
 * ── The marker contract ──────────────────────────────────────────────
 * Put `class="managed-table"` on a data-listing <table> and it gets
 * sortable columns + search + Excel/CSV export. `sortable-table` and
 * `exportable-table` are accepted as aliases so older templates keep
 * working.
 *
 * A table that already ships a bespoke implementation of one pillar opts
 * that pillar out with a TABLE-level attribute, keeping the other two:
 *
 *   <table class="managed-table" data-no-sort>    → search + export only
 *   <table class="managed-table" data-no-search>  → sort + export only
 *   <table class="managed-table" data-no-export>  → sort + search only
 *
 * (The same attribute names on a <th> mean "skip this column" and on a
 * <tr> "this is not a data row" — different element, different scope.)
 *
 * ── Why the row-visibility arbiter exists ────────────────────────────
 * Several pages filter rows with their own controls: the leases viewer's
 * lease-state / discovery-state chips, the scan tool's reachability
 * buttons, the TLS activity log's status buttons. Those and the standard
 * search box all want to hide rows, and if each writes `row.style.display`
 * directly the last one to run silently undoes the other — search a
 * filtered table and the filter evaporates.
 *
 * FERowFilter fixes that by making visibility a CONSENSUS: each source
 * registers a veto under its own key, and a row is shown only when NO
 * source vetoes it. Sources never read or clobber each other's state.
 *
 *   FERowFilter.set(row, "search", ok);   // the standard search box
 *   FERowFilter.set(row, "state", ok);    // a page's own filter buttons
 *   FERowFilter.visible(row);             // → boolean, the net result
 *
 * Vetoes live on a JS property (not a class or dataset), so they never
 * leak into the DOM or into exported cell text.
 */
(function () {
  "use strict";

  // ── Marker contract ───────────────────────────────────────────────────

  var SELECTOR = "table.managed-table, table.sortable-table, table.exportable-table";

  // feature ∈ "sort" | "search" | "export"
  function enabled(table, feature) {
    return !!table && !table.hasAttribute("data-no-" + feature);
  }

  function eachTable(root, feature, fn) {
    var scope = root || document;
    Array.prototype.forEach.call(scope.querySelectorAll(SELECTOR), function (t) {
      if (enabled(t, feature)) fn(t);
    });
  }

  // ── Table anatomy ─────────────────────────────────────────────────────

  // The header row that describes the columns: the LAST row of <thead>
  // that isn't the per-column filter row table-search.js injects (some
  // tables also carry a grouping row above the real header).
  function headerRow(table) {
    var thead = table.tHead;
    if (!thead || !thead.rows.length) return null;
    var rows = Array.prototype.slice.call(thead.rows).filter(function (r) {
      return !r.classList.contains("fe-filter-row");
    });
    return rows.length ? rows[rows.length - 1] : null;
  }

  // Columns that hold data — i.e. everything except the checkbox column
  // (empty <th>) and the Actions column (<th data-no-sort>). Sorting,
  // searching and exporting all agree on this set, so a stray button
  // label can never be sorted on, searched, or exported.
  function dataColumns(hr) {
    var cols = [];
    Array.prototype.forEach.call(hr.cells, function (th, index) {
      if (th.hasAttribute("data-no-sort") || th.hasAttribute("data-no-export")) return;
      var label = (th.textContent || "").replace(/\s+/g, " ").trim();
      if (!label) return;
      cols.push({ index: index, label: label, th: th });
    });
    return cols;
  }

  // Split a <tbody> into groups of { lead, extra }: a data row plus the
  // non-data rows that follow it (a `<td colspan>` error/detail row, a
  // collapsible panel). Detail rows must travel WITH their parent when
  // sorting and hide WITH it when filtering, or they orphan.
  // A data row is one with exactly colCount cells and no data-no-sort.
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

  // ── Row visibility arbiter ────────────────────────────────────────────

  var RowFilter = {
    // Register/clear `key`'s veto on `row`, then apply the consensus.
    set: function (row, key, visible) {
      if (!row) return;
      var vetoes = row.__feVetoes || (row.__feVetoes = {});
      if (visible) { delete vetoes[key]; }
      else { vetoes[key] = true; }
      row.style.display = RowFilter.visible(row) ? "" : "none";
    },
    visible: function (row) {
      var vetoes = row && row.__feVetoes;
      if (!vetoes) return row ? row.style.display !== "none" : false;
      for (var k in vetoes) { if (Object.prototype.hasOwnProperty.call(vetoes, k)) return false; }
      return true;
    },
    // Apply one source's verdict to a data row and its detail rows at once.
    setGroup: function (group, key, visible) {
      RowFilter.set(group.lead, key, visible);
      group.extra.forEach(function (e) { RowFilter.set(e, key, visible); });
    }
  };

  window.FETable = {
    SELECTOR: SELECTOR,
    enabled: enabled,
    eachTable: eachTable,
    headerRow: headerRow,
    dataColumns: dataColumns,
    partition: partition
  };
  window.FERowFilter = RowFilter;
})();
