"""Output-encoding helpers.

CSV-injection guard + Content-Disposition filename sanitiser. Both are
about preventing user-controlled data (SMC element names, reverse-DNS
PTR records, archive member paths) from breaking the structure of a
file the operator's browser is about to render or download.
"""

_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Return `value` as a CSV-safe string.

    Excel / Google Sheets / LibreOffice treat any cell that begins with
    `=`, `+`, `-`, `@`, TAB, or CR as a formula. A hostile reverse-DNS
    PTR like `=cmd|'/c calc'!A1` exported into a CSV cell will execute
    when the file is opened. We neutralise by prefixing with a single
    quote — Excel treats it as a string-mode escape and renders the
    original text verbatim. OWASP CSV Injection cheat sheet:
    https://owasp.org/www-community/attacks/CSV_Injection

    Non-strings round-trip through `str()`. Empty / None → empty string.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in _FORMULA_TRIGGERS:
        return "'" + s
    return s


# Characters that break the structure of an HTTP `Content-Disposition`
# header's `filename="..."` value: CR / LF (header injection), TAB
# (some parsers split), `"` and `\` (close the quote / start an escape).
_FILENAME_FORBIDDEN = '\r\n\t"\\'


def safe_filename(name, default: str = "download.bin") -> str:
    """Return a string safe to interpolate into ``filename="..."``.

    M4 (audit fix-up, 2026-05-09). SMC-derived names (engine slugs,
    interface labels, archive member paths) feed straight into download
    Content-Disposition headers. A `"` mid-name closes the quote; a
    raw CRLF injects a new header line. Strip both, plus path
    separators (so an attacker can't pre-fill a directory traversal),
    cap length at 200 chars, and fall back to ``default`` on empty.

    Operators wanting Unicode-friendly filenames should pair this
    sanitiser with an RFC 5987 ``filename*=UTF-8''…`` parameter on the
    same header — out of scope here, but the two-arg pattern this
    function returns is compatible with that future addition.
    """
    if name is None:
        return default
    s = str(name)
    cleaned = "".join(c for c in s if c not in _FILENAME_FORBIDDEN)
    cleaned = cleaned.replace("/", "_").replace("\\", "_").strip()
    cleaned = cleaned.lstrip(".") or default
    return cleaned[:200] or default
