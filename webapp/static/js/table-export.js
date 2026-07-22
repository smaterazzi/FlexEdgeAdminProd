/*
 * FlexEdgeAdmin — generic Excel / CSV export for tables.
 *
 * STANDARD (third pillar of the "managed table" treatment, alongside
 * table-sort.js and table-search.js): any `table.managed-table` gets an
 * Export button automatically — see table-core.js for the marker contract
 * and the table-level `data-no-export` opt-out.
 *
 * What gets exported is WHAT THE OPERATOR SEES:
 *   - current sort order (rows are read in DOM order),
 *   - every active filter — the global/per-column search boxes and any
 *     page-specific filter controls, because visibility is arbitrated in
 *     one place (FERowFilter, table-core.js) rather than each source
 *     writing `style.display` behind the others' backs.
 * That is the whole point of doing this client-side: no server route has
 * to re-derive the operator's filter state, so there is exactly one
 * export implementation for all ~25 tables instead of one per view.
 *
 * Markup hooks (all optional):
 *   - <table data-export-name="dhcp-leases">   → filename stem + sheet name.
 *                                                 Falls back to the table id,
 *                                                 then the page <h2>/<title>.
 *   - <th data-no-sort> / <th data-no-export>  → column omitted (checkbox and
 *                                                 Actions columns, same rule
 *                                                 the search uses).
 *   - <td data-export-value="…">               → export a canonical value that
 *                                                 differs from the display
 *                                                 (falls back to data-sort-value,
 *                                                 then the cell text).
 *
 * The .xlsx is a genuine OOXML workbook: a minimal SpreadsheetML sheet
 * packed by the store-only (uncompressed) ZIP writer below. No vendored
 * spreadsheet library and no CDN — per the M11 "vendor functional assets
 * locally" rule, here satisfied by vendoring nothing at all.
 *
 * AJAX tables: call window.FEATableExport.enhance(tableEl) after injecting.
 */
(function () {
  "use strict";

  // ── Value extraction ──────────────────────────────────────────────────

  var NUM_RE = /^-?\d+(\.\d+)?$/;

  // Mirror of shared/csv_safe.csv_safe(). Excel treats a cell starting with
  // any of these as a formula, so an SMC element name or a hostile PTR
  // record like `=cmd|'/c calc'!A1` would execute on open. A leading
  // apostrophe is Excel's string-mode escape: the text renders verbatim.
  var FORMULA_TRIGGERS = "=+-@\t\r";

  function formulaSafe(s) {
    if (s && FORMULA_TRIGGERS.indexOf(s.charAt(0)) !== -1) return "'" + s;
    return s;
  }

  function cellText(td) {
    if (!td) return "";
    var ds = td.dataset || {};
    var raw = ds.exportValue != null ? ds.exportValue
            : ds.sortValue != null ? ds.sortValue
            : (td.textContent || "");
    // Collapse the whitespace Jinja leaves around badges/icons so a cell
    // reads as one clean value rather than a multi-line blob.
    return raw.replace(/\s+/g, " ").trim();
  }

  // Net visibility across every filter source (standard search + any
  // page-specific controls) — see FERowFilter in table-core.js.
  function isVisible(row) {
    return window.FERowFilter.visible(row) && !row.hidden;
  }

  var headerRow = function (t) { return window.FETable.headerRow(t); };
  var exportableColumns = function (hr) { return window.FETable.dataColumns(hr); };

  // Rows are read in DOM order (= current sort), skipping hidden ones and
  // any row whose cell count doesn't match the header — that's how both
  // sort and search identify a real data row vs a colspan detail/placeholder
  // row, and detail rows have no meaning in a spreadsheet.
  function collect(table) {
    var hr = headerRow(table);
    var tbody = table.tBodies && table.tBodies[0];
    if (!hr || !tbody) return null;
    var cols = exportableColumns(hr);
    if (!cols.length) return null;

    var colCount = hr.cells.length;
    var rows = [];
    Array.prototype.forEach.call(tbody.rows, function (r) {
      if (r.children.length !== colCount) return;
      if (!isVisible(r)) return;
      rows.push(cols.map(function (c) { return cellText(r.children[c.index]); }));
    });
    return { header: cols.map(function (c) { return c.label; }), rows: rows };
  }

  // ── Naming ────────────────────────────────────────────────────────────

  function pageLabel() {
    var h = document.querySelector("main h2, main h1, h2");
    var t = h ? h.textContent : document.title;
    return (t || "table").replace(/\s+/g, " ").trim();
  }

  function slugify(s) {
    return (s || "table").toLowerCase()
      .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "table";
  }

  function baseName(table) {
    var ds = table.dataset || {};
    var name = ds.exportName || table.id || pageLabel();
    var d = new Date();
    var stamp = d.getFullYear() + "-" +
      String(d.getMonth() + 1).padStart(2, "0") + "-" +
      String(d.getDate()).padStart(2, "0");
    return slugify(name) + "_" + stamp;
  }

  // Excel sheet names: ≤31 chars, and : \ / ? * [ ] are illegal.
  function sheetName(table) {
    var ds = table.dataset || {};
    var raw = ds.exportName || table.id || pageLabel();
    return (raw.replace(/[:\\\/?*\[\]]/g, " ").replace(/\s+/g, " ").trim() || "Sheet1")
      .slice(0, 31);
  }

  // ── CSV ───────────────────────────────────────────────────────────────

  function toCsv(data) {
    function cell(v) {
      var s = formulaSafe(v);
      return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }
    var lines = [data.header.map(cell).join(",")];
    data.rows.forEach(function (r) { lines.push(r.map(cell).join(",")); });
    // BOM so Excel detects UTF-8 rather than mangling accented names.
    return "﻿" + lines.join("\r\n") + "\r\n";
  }

  // ── Minimal XLSX writer ───────────────────────────────────────────────

  function xmlEscape(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
      // Strip control chars Excel refuses to load (keep tab/LF/CR).
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
  }

  function colLetter(n) {                 // 0 → A, 25 → Z, 26 → AA
    var s = "";
    n += 1;
    while (n > 0) {
      var rem = (n - 1) % 26;
      s = String.fromCharCode(65 + rem) + s;
      n = Math.floor((n - 1) / 26);
    }
    return s;
  }

  function sheetXml(data) {
    var rowsXml = [];

    function rowXml(values, rowIdx, bold) {
      var cells = values.map(function (v, ci) {
        var ref = colLetter(ci) + rowIdx;
        // Numeric cells go in as numbers so Excel can sum/sort them; the
        // formula guard only applies to the text branch.
        if (!bold && v !== "" && NUM_RE.test(v.replace(/,/g, ""))) {
          return '<c r="' + ref + '"><v>' + v.replace(/,/g, "") + "</v></c>";
        }
        var s = xmlEscape(formulaSafe(v));
        // Attribute order r, s, t is the canonical one Excel writes itself.
        return '<c r="' + ref + '"' + (bold ? ' s="1"' : "") + ' t="inlineStr"' +
               "><is><t xml:space=\"preserve\">" + s + "</t></is></c>";
      }).join("");
      return '<row r="' + rowIdx + '">' + cells + "</row>";
    }

    rowsXml.push(rowXml(data.header, 1, true));
    data.rows.forEach(function (r, i) { rowsXml.push(rowXml(r, i + 2, false)); });

    // Freeze the header row and auto-filter the used range — the two things
    // an operator does by hand on every exported sheet otherwise.
    var lastCol = colLetter(Math.max(data.header.length - 1, 0));
    var lastRow = data.rows.length + 1;
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<sheetViews><sheetView workbookViewId="0" tabSelected="1">' +
      '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>' +
      "</sheetView></sheetViews>" +
      "<sheetData>" + rowsXml.join("") + "</sheetData>" +
      '<autoFilter ref="A1:' + lastCol + lastRow + '"/>' +
      "</worksheet>";
  }

  function workbookParts(data, sheet) {
    return [
      { name: "[Content_Types].xml", data:
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
        '<Default Extension="xml" ContentType="application/xml"/>' +
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        "</Types>" },
      { name: "_rels/.rels", data:
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
        "</Relationships>" },
      { name: "xl/workbook.xml", data:
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ' +
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
        '<sheets><sheet name="' + xmlEscape(sheet) + '" sheetId="1" r:id="rId1"/></sheets>' +
        "</workbook>" },
      { name: "xl/_rels/workbook.xml.rels", data:
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' +
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
        "</Relationships>" },
      // Two styles: 0 = default, 1 = bold (the header row).
      { name: "xl/styles.xml", data:
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>' +
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>' +
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>' +
        '<borders count="1"><border/></borders>' +
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>' +
        // Readers warn about a workbook with no "Normal" named style.
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
        "</styleSheet>" },
      { name: "xl/worksheets/sheet1.xml", data: sheetXml(data) }
    ];
  }

  // ── Store-only ZIP writer (no compression → no deflate dependency) ────

  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(bytes) {
    var c = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) {
      c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    }
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function utf8(str) { return new TextEncoder().encode(str); }

  function dosDateTime(d) {
    var time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
    var date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    return { time: time & 0xFFFF, date: date & 0xFFFF };
  }

  function zip(files) {
    var dt = dosDateTime(new Date());
    var chunks = [];      // local headers + data, in order
    var central = [];
    var offset = 0;

    files.forEach(function (f) {
      var nameBytes = utf8(f.name);
      var dataBytes = utf8(f.data);
      var crc = crc32(dataBytes);

      var local = new DataView(new ArrayBuffer(30));
      local.setUint32(0, 0x04034b50, true);   // local file header signature
      local.setUint16(4, 20, true);           // version needed
      local.setUint16(6, 0x0800, true);       // flags: UTF-8 names
      local.setUint16(8, 0, true);            // method 0 = stored
      local.setUint16(10, dt.time, true);
      local.setUint16(12, dt.date, true);
      local.setUint32(14, crc, true);
      local.setUint32(18, dataBytes.length, true);
      local.setUint32(22, dataBytes.length, true);
      local.setUint16(26, nameBytes.length, true);
      local.setUint16(28, 0, true);           // extra field length
      chunks.push(new Uint8Array(local.buffer), nameBytes, dataBytes);

      var cen = new DataView(new ArrayBuffer(46));
      cen.setUint32(0, 0x02014b50, true);     // central directory signature
      cen.setUint16(4, 20, true);             // version made by
      cen.setUint16(6, 20, true);             // version needed
      cen.setUint16(8, 0x0800, true);
      cen.setUint16(10, 0, true);
      cen.setUint16(12, dt.time, true);
      cen.setUint16(14, dt.date, true);
      cen.setUint32(16, crc, true);
      cen.setUint32(20, dataBytes.length, true);
      cen.setUint32(24, dataBytes.length, true);
      cen.setUint16(28, nameBytes.length, true);
      cen.setUint32(42, offset, true);        // relative offset of local header
      central.push(new Uint8Array(cen.buffer), nameBytes);

      offset += 30 + nameBytes.length + dataBytes.length;
    });

    var centralSize = central.reduce(function (n, c) { return n + c.length; }, 0);
    var end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);       // end of central directory
    end.setUint16(8, files.length, true);
    end.setUint16(10, files.length, true);
    end.setUint32(12, centralSize, true);
    end.setUint32(16, offset, true);

    return new Blob(chunks.concat(central, [new Uint8Array(end.buffer)]),
                    { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
  }

  // ── Download plumbing ─────────────────────────────────────────────────

  function download(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function exportTable(table, format) {
    var data = collect(table);
    if (!data) return;
    if (!data.rows.length) {
      window.alert("Nothing to export — no rows match the current filters.");
      return;
    }
    if (format === "csv") {
      download(new Blob([toCsv(data)], { type: "text/csv;charset=utf-8" }),
               baseName(table) + ".csv");
    } else {
      download(zip(workbookParts(data, sheetName(table))), baseName(table) + ".xlsx");
    }
  }

  // ── UI ────────────────────────────────────────────────────────────────

  function buildControl(table) {
    var wrap = document.createElement("div");
    wrap.className = "btn-group btn-group-sm fe-table-export";

    var xlsx = document.createElement("button");
    xlsx.type = "button";                     // never submit a wrapping <form>
    xlsx.className = "btn btn-outline-success";
    xlsx.innerHTML = '<i class="bi bi-file-earmark-excel"></i> Excel';
    xlsx.title = "Download the rows currently shown (respects sort + filters) as .xlsx";
    xlsx.addEventListener("click", function () { exportTable(table, "xlsx"); });

    var csv = document.createElement("button");
    csv.type = "button";
    csv.className = "btn btn-outline-secondary";
    csv.textContent = "CSV";
    csv.title = "Same rows as .csv (UTF-8)";
    csv.addEventListener("click", function () { exportTable(table, "csv"); });

    wrap.appendChild(xlsx);
    wrap.appendChild(csv);
    return wrap;
  }

  function enhance(table) {
    if (!table || table.__feExportWired) return;
    if (!collect(table)) return;              // no usable header → nothing to do
    table.__feExportWired = true;

    var control = buildControl(table);

    // Prefer the search bar table-search.js already put above this table, so
    // the two controls share one row. It runs first (script order in
    // base.html), so the bar exists by now on sortable tables.
    var anchor = (table.parentElement &&
                  table.parentElement.classList.contains("table-responsive"))
      ? table.parentElement : table;
    var prev = anchor.previousElementSibling;
    if (prev && prev.classList.contains("fe-table-search")) {
      prev.appendChild(control);
      control.classList.add("ms-auto");
      return;
    }
    var bar = document.createElement("div");
    bar.className = "fe-table-export-bar d-flex justify-content-end mb-2";
    bar.appendChild(control);
    if (anchor.parentNode) anchor.parentNode.insertBefore(bar, anchor);
  }

  function enhanceAll(root) {
    var scope = root || document;
    window.FETable.eachTable(scope, "export", enhance);
  }

  window.FEATableExport = {
    enhance: enhance,
    enhanceAll: enhanceAll,
    exportTable: exportTable      // for a bespoke button elsewhere on a page
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { enhanceAll(); });
  } else {
    enhanceAll();
  }
})();
