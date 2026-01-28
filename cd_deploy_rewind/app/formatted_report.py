import html

def _unescape_and_sanitize(val):
    """Convert to string, unescape HTML, and normalize whitespace."""
    if val is None:
        s = "-"
    else:
        s = str(val)
    s = html.unescape(s)           # Fixes &amp; &lt; &gt; etc.
    s = s.replace("\r", " ").replace("\n", " ")  # keep single-line cells
    return s

def _chars(style="unicode"):
    """Return border characters for 'unicode' or 'ascii' styles."""
    if style == "ascii":
        return {
            "H": "-", "V": "|",
            "TL": "+", "TM": "+", "TR": "+",
            "ML": "+", "MM": "+", "MR": "+",
            "BL": "+", "BM": "+", "BR": "+",
        }
    # default unicode
    return {
        "H": "─", "V": "│",
        "TL": "┌", "TM": "┬", "TR": "┐",
        "ML": "├", "MM": "┼", "MR": "┤",
        "BL": "└", "BM": "┴", "BR": "┘",
    }

def _compute_widths(headers, rows, max_widths=None):
    """
    headers: list[str]
    rows: list[list[str]] (already sanitized strings)
    max_widths: None|int|list[int] -> truncation width per column
    """
    n = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(n):
            widths[i] = max(widths[i], len(row[i]))
    if max_widths is not None:
        if isinstance(max_widths, int):
            widths = [min(w, max_widths) for w in widths]
        elif isinstance(max_widths, (list, tuple)):
            widths = [min(w, max_widths[i]) for i, w in enumerate(widths)]
    return widths

def _truncate(s, width):
    """Truncate string to width with ellipsis if needed."""
    if len(s) <= width:
        return s
    if width <= 1:
        return s[:width]
    return s[:width-1] + "…"

def _build_rule(widths, chars, padding, kind="top"):
    """
    kind: 'top'|'mid'|'bottom'
    """
    if kind == "top":
        left, mid, right = chars["TL"], chars["TM"], chars["TR"]
    elif kind == "mid":
        left, mid, right = chars["ML"], chars["MM"], chars["MR"]
    else:
        left, mid, right = chars["BL"], chars["BM"], chars["BR"]

    segments = [chars["H"] * (w + 2 * padding) for w in widths]
    return left + mid.join(segments) + right

def _build_row(cols, widths, chars, padding):
    cells = []
    for col, w in zip(cols, widths):
        cells.append(" " * padding + col.ljust(w) + " " * padding)
    return chars["V"] + chars["V"].join(cells) + chars["V"]

def render_table(headers, rows, title=None, style="unicode", padding=1, max_widths=None):
    """
    headers: list[str]
    rows: list[list[Any]]
    title: str|None -> centered decorative box above table
    style: 'unicode'|'ascii'
    padding: spaces around each cell
    max_widths: None|int|list[int] -> truncation width per column
    """
    # sanitize rows (unescape HTML, normalize)
    sanitized_rows = [[_unescape_and_sanitize(c) for c in r] for r in rows]
    chars = _chars(style)

    # compute column widths and then truncate data to those widths
    widths = _compute_widths(headers, sanitized_rows, max_widths=max_widths)
    truncated_rows = [[_truncate(c, w) for c, w in zip(r, widths)] for r in sanitized_rows]
    truncated_headers = [_truncate(h, w) for h, w in zip(headers, widths)]

    # full line width of rule lines for title box
    # segments length + separators: there are (len(widths)-1) mids and 2 corners
    rule_line_len = len(_build_rule(widths, chars, padding, kind="top"))
    deco_inner = rule_line_len - 2  # exclude corners for content width

    lines = []

    # Optional title box
    if title:
        t = _unescape_and_sanitize(title)
        if len(t) <= deco_inner:
            # center the title
            left_pad = (deco_inner - len(t)) // 2
            right_pad = deco_inner - len(t) - left_pad
            lines.append(chars["TL"] + (chars["H"] * deco_inner) + chars["TR"])
            lines.append(chars["V"] + (" " * left_pad) + t + (" " * right_pad) + chars["V"])
            lines.append(chars["BL"] + (chars["H"] * deco_inner) + chars["BR"])
        else:
            # truncate the title to fit
            t = _truncate(t, deco_inner)
            lines.append(chars["TL"] + (chars["H"] * deco_inner) + chars["TR"])
            lines.append(chars["V"] + t + chars["V"])
            lines.append(chars["BL"] + (chars["H"] * deco_inner) + chars["BR"])

    # Table header
    lines.append(_build_rule(widths, chars, padding, kind="top"))
    lines.append(_build_row(truncated_headers, widths, chars, padding))
    lines.append(_build_rule(widths, chars, padding, kind="mid"))

    # Data rows
    if truncated_rows:
        for r in truncated_rows:
            lines.append(_build_row(r, widths, chars, padding))
    else:
        # No data: show a centered message spanning all columns
        msg = "— No Artifacts —"
        span_width = sum(widths) + 2 * padding * len(widths) + (len(widths) - 1)  # account for verticals later
        # Build a single-cell fake row that fills the inner width between the outer verticals
        # Inner width between outer verticals equals rule_line_len - 2
        inner_width = rule_line_len - 2
        msg_trunc = _truncate(msg, inner_width)
        # Center message inside the inner width
        pad_left = (inner_width - len(msg_trunc)) // 2
        pad_right = inner_width - len(msg_trunc) - pad_left
        lines.append(chars["V"] + (" " * pad_left) + msg_trunc + (" " * pad_right) + chars["V"])

    # Table bottom
    lines.append(_build_rule(widths, chars, padding, kind="bottom"))

    return "\n".join(lines)