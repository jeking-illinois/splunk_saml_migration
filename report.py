#!/usr/bin/env python3
"""
Shared Excel reporting. Every sync script produces the same shape of workbook:

    sheet 1   one row per item, colour-coded by Result, frozen header, autofilter
    Summary   metric/value pairs, bold on section headers
    extras    zero or more additional sheets

    from report import Sheet, write_workbook
    write_workbook(path,
        Sheet("User Sync", COLUMNS, rows, colour_by="Result"),
        summary=[("Mode", "APPLY"), ("", ""), ("Results:", ""), ...],
        extras=[Sheet("Roles Absent On Target", [("Role", 40), ...], more_rows)])

Result values that get a colour: success, error, in_sync, dry-run, skipped,
none, restored, deleted, already-ok.
"""

import os

EXCEL_CELL_LIMIT = 32000  # real limit is 32767; leave room for the truncation note

HEADER_BG = "1F3864"
RESULT_FILLS = {
    "success": "C6EFCE",
    "restored": "C6EFCE",
    "deleted": "C6EFCE",
    "create": "C6EFCE",
    "error": "FFC7CE",
    "in_sync": "DDEBF7",
    "none": "DDEBF7",
    "dry-run": "FFF2CC",
    # Planned-but-not-done, from rollback_users.py --verify.
    "would-restore": "FFF2CC",
    "would-delete": "FFF2CC",
    "skipped": "E7E6E6",
    "already-ok": "E7E6E6",
    "non_saml_skipped": "E7E6E6",
    "excluded": "E7E6E6",
    "no_source_roles": "E7E6E6",
    # Wanted something, but every role it wanted is absent on the target.
    "nothing_grantable": "FCE4D6",
}


def cell(value):
    """Excel-safe value: join collections, clamp to the per-cell character limit.

    The clamp is not cosmetic - one real user had 369 roles, and openpyxl raises
    on anything past 32767 characters, which would lose the whole report at the
    very last step.
    """
    if isinstance(value, (list, tuple, set)):
        items = sorted(value) if isinstance(value, set) else list(value)
        text = ", ".join(str(i) for i in items)
        if len(text) > EXCEL_CELL_LIMIT:
            kept, total = [], 0
            for i, item in enumerate(items):
                if total + len(str(item)) + 2 > EXCEL_CELL_LIMIT:
                    return ", ".join(kept) + f" ...({len(items) - i} more)"
                kept.append(str(item))
                total += len(str(item)) + 2
        return text
    if value is None:
        return ""
    text = str(value)
    if len(text) > EXCEL_CELL_LIMIT:
        return text[:EXCEL_CELL_LIMIT - 20] + "... (truncated)"
    return value


class Sheet:
    """One worksheet. `columns` is a list of (header, width) pairs; `rows` is a
    list of dicts keyed by header."""

    def __init__(self, title, columns, rows, colour_by=None, freeze="B2"):
        self.title = title[:31]  # Excel caps sheet names at 31 chars
        self.columns = columns
        self.rows = rows
        self.colour_by = colour_by
        self.freeze = freeze


def write_workbook(path, main, summary=None, extras=()):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    header_fill = PatternFill("solid", fgColor=HEADER_BG)
    header_font = Font(bold=True, color="FFFFFF")
    fills = {k: PatternFill("solid", fgColor=v) for k, v in RESULT_FILLS.items()}

    wb = Workbook()

    def build(ws, sheet):
        headers = [c[0] for c in sheet.columns]
        ws.append(headers)
        for i, (name, width) in enumerate(sheet.columns, 1):
            c = ws.cell(row=1, column=i)
            c.fill, c.font = header_fill, header_font
            c.alignment = Alignment(vertical="center", wrap_text=True)
            ws.column_dimensions[get_column_letter(i)].width = width

        colour_col = headers.index(sheet.colour_by) + 1 if sheet.colour_by in headers else None
        for row in sheet.rows:
            ws.append([cell(row.get(name, "")) for name in headers])
            if colour_col:
                fill = fills.get(row.get(sheet.colour_by))
                if fill:
                    ws.cell(row=ws.max_row, column=colour_col).fill = fill
        if sheet.freeze:
            ws.freeze_panes = sheet.freeze
        if ws.max_row >= 1:
            ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{ws.max_row}"

    ws = wb.active
    ws.title = main.title
    build(ws, main)

    if summary is not None:
        s = wb.create_sheet("Summary")
        s.column_dimensions["A"].width = 54
        s.column_dimensions["B"].width = 66
        s.append(["Metric", "Value"])
        for c in s[1]:
            c.fill, c.font = header_fill, header_font
        for k, v in summary:
            s.append([k, cell(v)])
            # Section headers ("Results:") and spacers get bolded.
            if str(k).endswith(":") or v == "":
                s.cell(row=s.max_row, column=1).font = Font(bold=True)

    for extra in extras:
        build(wb.create_sheet(extra.title), extra)

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    wb.save(path)
    return path


def banner(title, cfg, mode, extra_lines=()):
    """The identical header every script prints, so runs are easy to tell apart."""
    line = "=" * 74
    print(f"\n{line}")
    print(f"{title}")
    print(f"  {cfg.source.label}  ->  {cfg.target.label}")
    print(f"  Mode: {mode}")
    print(line)
    for text in extra_lines:
        print(f"  {text}")


def token_warning(client, label):
    """Print an expiry warning for a token that is about to die or already has."""
    from clients import token_expiry
    when, expired = token_expiry(client.token)
    if not when:
        return
    from datetime import datetime
    days = (when - datetime.now(when.tzinfo)).days
    note = "*** EXPIRED ***" if expired else f"{days}d left"
    print(f"  {label} token expires {when.strftime('%Y-%m-%d')} ({note})")
    if expired or days <= 3:
        print(f"  WARNING: refresh this credential before a long run")
