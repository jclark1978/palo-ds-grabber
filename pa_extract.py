#!/usr/bin/env python3
"""Extract the raw spec tables from Palo Alto Networks PA-Series datasheets.

Palo Alto datasheets number their tables ("Table 1. PA-400 Series Performance
and Capacities", "Table 3. ... Hardware Specifications (continued)"), so tables
are found by caption and read by word position (PyMuPDF spans):

Performance table (one column per model)
  * the first line under the caption holds the model columns; long names can
    wrap ("PA-520-" / "5G");
  * every line with values starts a row; label fragments (labels wrap onto
    1-3 lines, above, beside or below the values) go to the nearest row by y;
  * footnote markers are small superscripts (*, †, ‡, §, ||, #, **, ††) or
    glued to the end of a label or value;
  * footnotes and the "Note: Results were measured on PAN-OS x" line follow
    the table and hold the test conditions for each value.

Hardware table (label + scoped lines)
  * row labels are bold; value lines below them are plain text;
  * a value line may be scoped to models: "PA-440, PA-450/PA-460: 1G RJ45 (8)";
    a bare model list ("PA-5540, PA-5550:") scopes the lines that follow;
    unscoped lines apply to every model in the datasheet;
  * some rows embed a small sub-table (PA-400 power: model / avg / max).

Product summary spec sheet
  * stacked "Performance and Capacities" blocks with merged cells; only the
    performance rows are read (used to cross-check the series datasheets).

Output is lossless: labels and values as printed, markers, footnotes, page.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pymupdf

SUPERSCRIPT_MAX = 6.0
SAME_LINE_TOL = 2.0
FOOTER_Y = 745.0
CAPTION_RE = re.compile(r"^Table (\d+)\.\s*(.*)$")
MODEL_TOKEN = r"PA-\d{2,4}[A-Z]?(?:-[A-Z0-9]+)*"
HEADER_CELL_RE = re.compile(rf"^(Single\s+)?{MODEL_TOKEN}|^PA-$|^PA-\d+[A-Z]?-$")
# Marker symbols as printed: order matters (longest first).
MARK_RE = re.compile(r"(\*\*|\*|††|†|‡|§|\|\||#)+$")
FOOT_START_RE = re.compile(r"^(\*\*|\*|††|†|‡|§|\|\||#)\s*(.*)$")
MARK_ONLY = re.compile(r"^(\*\*|\*|††|†|‡|§|\|\||#)+$")
NOTE_RE = re.compile(r"^Notes?:\s*(.*)$", re.I)


class Span:
    __slots__ = ("x0", "x1", "y", "size", "text", "bold")

    def __init__(self, s=None, **kw):
        if s is not None:
            self.x0, y0, self.x1, _ = s["bbox"]
            self.y = round(y0, 1)
            self.size = s["size"]
            self.text = re.sub(r"[\x00-\x1f\u00ad]", "", s["text"]).strip()
            self.bold = "Bold" in s["font"] or bool(s["flags"] & 16)
        for k, v in kw.items():
            setattr(self, k, v)

    @property
    def cx(self):
        return (self.x0 + self.x1) / 2

    @property
    def sup(self):
        return self.size <= SUPERSCRIPT_MAX

    def __repr__(self):
        return f"<{self.x0:.0f},{self.y:.0f} {self.text!r}>"


def page_spans(page) -> list[Span]:
    out = []
    for b in page.get_text("dict")["blocks"]:
        for l in b.get("lines", []):
            for s in l["spans"]:
                sp = Span(s)
                if sp.text and sp.y < FOOTER_Y:
                    out.append(sp)
    return out


def group_lines(spans: list[Span]) -> list[list[Span]]:
    """Group spans into lines. Superscripts sit a little lower, so tolerate it."""
    lines: list[list[Span]] = []
    for s in sorted(spans, key=lambda s: (s.y, s.x0)):
        if lines and abs(lines[-1][0].y - s.y) <= (SAME_LINE_TOL + (1.0 if s.sup else 0)):
            lines[-1].append(s)
        else:
            lines.append([s])
    return [sorted(l, key=lambda s: s.x0) for l in lines]


def split_marks(text: str) -> tuple[str, list[str]]:
    """'IPsec VPN throughput‡' -> ('IPsec VPN throughput', ['‡'])."""
    text = text.strip()
    m = MARK_RE.search(text)
    if not m or m.start() == 0:
        return text, []
    marks = re.findall(r"\*\*|\*|††|†|‡|§|\|\||#", m.group(0))
    return text[:m.start()].rstrip(), marks


def merge_groups(spans: list[Span], gap: float = 4.0) -> list[dict]:
    groups: list[dict] = []
    for s in sorted(spans, key=lambda s: s.x0):
        if groups and s.x0 - groups[-1]["x1"] <= gap:
            groups[-1]["text"] += ("" if s.sup else " ") + s.text
            groups[-1]["x1"] = s.x1
        else:
            groups.append({"x0": s.x0, "x1": s.x1, "text": s.text})
    for g in groups:
        g["cx"] = (g["x0"] + g["x1"]) / 2
        g["text"] = " ".join(g["text"].split())
    return groups


def assign_columns(groups: list[dict], centers: list[float]) -> list[tuple[int, int, str]]:
    """Map value groups to contiguous column ranges (a merged cell spans
    several columns and is centered across them). DP over partitions."""
    groups = [dict(g) for g in groups]
    n = len(centers)
    while len(groups) > n:
        i = min(range(len(groups) - 1), key=lambda i: groups[i + 1]["x0"] - groups[i]["x1"])
        a, b = groups[i], groups.pop(i + 1)
        a["text"] += " " + b["text"]
        a["x1"] = b["x1"]
        a["cx"] = (a["x0"] + a["x1"]) / 2
    k = len(groups)
    INF = float("inf")
    best = [[INF] * (n + 1) for _ in range(k + 1)]
    back = [[0] * (n + 1) for _ in range(k + 1)]
    best[0][0] = 0
    for i in range(1, k + 1):
        for j in range(i, n + 1):
            for s in range(i - 1, j):
                c = best[i - 1][s]
                if c == INF:
                    continue
                cost = c + abs(groups[i - 1]["cx"] - (centers[s] + centers[j - 1]) / 2)
                if cost < best[i][j]:
                    best[i][j], back[i][j] = cost, s
    out, j = [], n
    for i in range(k, 0, -1):
        s = back[i][j]
        out.append((s, j - 1, groups[i - 1]["text"]))
        j = s
    return out[::-1]


# --------------------------------------------------------------------------
# Locate captioned tables
# --------------------------------------------------------------------------
def find_tables(doc) -> list[dict]:
    """Return [{num, title, kind, parts:[(page_no, spans_in_region)]}]."""
    tables: dict[int, dict] = {}
    for pno, page in enumerate(doc):
        spans = page_spans(page)
        caps = [s for s in spans if CAPTION_RE.match(s.text) and s.size >= 8.5]
        caps.sort(key=lambda s: s.y)
        for i, cap in enumerate(caps):
            num, title = CAPTION_RE.match(cap.text).groups()
            num = int(num)
            y_end = caps[i + 1].y - 1 if i + 1 < len(caps) else FOOTER_Y
            region = [s for s in spans if cap.y + 2 < s.y < y_end and s is not cap]
            # Stop at the back-page address block.
            stop = min((s.y for s in region if s.text.startswith("3000 Tannery Way")), default=None)
            if stop is not None and stop > cap.y:
                region = [s for s in region if s.y < stop - 1]
            base = re.sub(r"\s*\(continued\)\s*$", "", title, flags=re.I).strip()
            low = base.lower()
            kind = ("performance" if "performance" in low else
                    "hardware" if "hardware" in low else
                    "networking" if "networking" in low else "other")
            t = tables.setdefault(num, {"num": num, "title": base, "kind": kind, "parts": []})
            t["parts"].append((pno + 1, region))
    return [tables[k] for k in sorted(tables)]


# --------------------------------------------------------------------------
# Performance tables
# --------------------------------------------------------------------------
def header_columns(spans: list[Span]) -> tuple[float, list[dict]] | None:
    """Model header: spans near the top of the region, right of the label
    column. Names can wrap onto a second line ('PA-520-' / '5G') and sit
    higher than single-line names, so cluster by x overlap, not by line."""
    first = min((s for s in spans if not s.sup and re.match(r"^(Single\s+)?PA-", s.text)),
                key=lambda s: s.y, default=None)
    if first is None:
        return None
    cand = [s for s in spans if not s.sup and abs(s.y - first.y) <= 12 and s.x0 > 100]
    body_label = [s for s in spans if s.x0 < 100 and not s.sup and s.y > first.y - 6]
    if body_label:  # header sits above the first label line
        top_label = min(s.y for s in body_label)
        cand = [s for s in cand if s.y < top_label - 1]
    cols: list[dict] = []
    for s in sorted(cand, key=lambda s: (s.y, s.x0)):
        hit = next((c for c in cols if s.x0 < c["x1"] + 2 and s.x1 > c["x0"] - 2), None)
        if hit:
            hit["text"] += ("" if hit["text"].endswith("-") else " ") + s.text
            hit["x0"], hit["x1"] = min(hit["x0"], s.x0), max(hit["x1"], s.x1)
            hit["ymax"] = max(hit["ymax"], s.y)
        else:
            cols.append({"x0": s.x0, "x1": s.x1, "text": s.text, "ymax": s.y})
    cols.sort(key=lambda c: c["x0"])
    if not any(re.match(r"^(Single\s+)?PA-", c["text"]) for c in cols):
        return None
    for c in cols:
        c["cx"] = (c["x0"] + c["x1"]) / 2
        c["text"], c["marks"] = split_marks(c["text"])
    for s in spans:  # superscript markers on a column header
        if s.sup and s.x0 > 100 and abs(s.y - first.y) <= 12 and MARK_ONLY.match(s.text):
            c = min(cols, key=lambda c: abs(c["x1"] - s.x0))
            c["marks"] += re.findall(r"\*\*|\*|††|†|‡|§|\|\||#", s.text)
    return max(c["ymax"] for c in cols), cols


def parse_footnotes(lines: list[list[Span]]) -> dict[str, str]:
    """Footnote lines: '<marker> text' (marker may be a small span), 'Note: ...',
    plus wrapped continuation lines."""
    notes: dict[str, str] = {}
    cur = None
    for line in lines:
        text = ""
        for s in line:
            text += s.text if (s.sup or not text) else " " + s.text
        text = " ".join(text.split())
        if not text or re.match(r"^\d+$", text) or text.startswith("Strata by Palo Alto"):
            continue
        m = NOTE_RE.match(text)
        if m:
            cur = "note"
            notes["note"] = (notes.get("note", "") + " " + m.group(1)).strip()
            continue
        m = FOOT_START_RE.match(text)
        if m and m.group(2):
            cur = m.group(1)
            notes[cur] = (notes.get(cur, "") + " " + m.group(2)).strip()
        elif cur:
            notes[cur] += " " + text
    return notes


def extract_performance(parts) -> dict | None:
    """parts: [(page, spans)]; performance tables fit on one page."""
    page, spans = parts[0]
    hdr = header_columns(spans)
    if not hdr:
        return None
    hy, cols = hdr
    centers = [c["cx"] for c in cols]
    spacing = min((b - a for a, b in zip(centers, centers[1:])), default=150)
    value_left = max(centers[0] - spacing * 0.55, 100)
    body = group_lines([s for s in spans if s.y > hy + 1.5])

    # Split body into table lines and footnote lines (first footnote/Note line
    # that has no values ends the table).
    tbl, foot = [], []
    for line in body:
        normal = [s for s in line if not s.sup]
        has_val = any(s.x0 >= value_left for s in normal)
        first = line[0]
        txt = " ".join(s.text for s in line)
        is_foot = (not has_val and (NOTE_RE.match(txt) or FOOT_START_RE.match(txt) and first.x0 < value_left
                                    or (first.sup and first.x0 < 45) or (normal and normal[0].size < 7.6
                                                                          and normal[0].size < cols_size(cols, spans) - 0.6)))
        if foot or is_foot:
            foot.append(line)
        else:
            tbl.append(line)

    # Rows: one per line that has values.
    rows = []
    label_frags = []
    for line in tbl:
        normal = [s for s in line if not s.sup]
        vals = [s for s in line if s.x0 >= value_left]
        labs = [s for s in line if s.x0 < value_left]
        if any(not s.sup and not MARK_ONLY.match(s.text) for s in vals):
            rows.append({"y": line[0].y, "vals": vals, "label": [], "marks": []})
        if labs:
            label_frags.append(labs)
        elif vals and all(s.sup for s in vals) and rows:
            rows[-1]["vals"] += vals
    if not rows:
        return None

    # Two value lines very close together with no label between them = wrapped values.
    merged = [rows[0]]
    for r in rows[1:]:
        prev = merged[-1]
        lab_between = any(prev["y"] + 1 < f[0].y < r["y"] + 1 for f in label_frags)
        if r["y"] - prev["y"] < 10.5 and not lab_between:
            prev["vals"] += r["vals"]
            prev["wrapped"] = True
        else:
            merged.append(r)
    rows = merged

    for frag in label_frags:
        y = frag[0].y
        r = min(rows, key=lambda r: (abs(r["y"] - y), -r["y"]))
        r["label"].append(frag)

    out_rows = []
    for r in rows:
        frags = sorted(r["label"], key=lambda f: f[0].y)
        label, marks = "", []
        for f in frags:
            for s in f:
                if s.sup or MARK_ONLY.match(s.text):
                    marks += re.findall(r"\*\*|\*|††|†|‡|§|\|\||#", s.text)
                else:
                    label += " " + s.text
        label, m2 = split_marks(" ".join(label.split()))
        marks += m2
        values: dict[str, dict] = {}
        lines_v = group_lines(r["vals"])
        for li, vl in enumerate(lines_v):
            groups = merge_groups([s for s in vl])
            for a, b, txt in assign_columns(groups, centers):
                v, vm = split_marks(txt)
                for c in cols[a:b + 1]:
                    e = values.setdefault(c["text"], {"raw": "", "marks": []})
                    e["raw"] = (e["raw"] + " " + v).strip()
                    e["marks"] += vm
        out_rows.append({"label": label, "marks": sorted(set(marks), key=marks.index), "values": values})

    footnotes = parse_footnotes(foot)
    return {"page": page, "models": [c["text"] for c in cols], "model_marks": {c["text"]: c["marks"] for c in cols if c["marks"]}, "rows": out_rows, "footnotes": footnotes}


def cols_size(cols, spans) -> float:
    sizes = [s.size for s in spans if not s.sup and s.x0 >= cols[0]["x0"] - 10]
    return max(set(sizes), key=sizes.count) if sizes else 8.0


# --------------------------------------------------------------------------
# Hardware tables
# --------------------------------------------------------------------------
_MT = rf"{MODEL_TOKEN}[*†‡§#]*"
SCOPE_RE = re.compile(rf"^((?:{_MT})(?:\s*(?:,|/|\bor\b|\band\b)\s*(?:{_MT}))*),?\s*(?:(?:\s*:\s*|\s+)(.*))?$")


def scope_models(text: str) -> tuple[list[str] | None, str]:
    """'PA-440, PA-450/PA-460: 1G RJ45 (8)' -> (['PA-440','PA-450','PA-460'], '1G RJ45 (8)')."""
    m = SCOPE_RE.match(text)
    if not m:
        return None, text
    models = re.findall(MODEL_TOKEN, m.group(1))
    value = (m.group(2) or "").strip()
    value = re.sub(r"^(\d+(?:\.\d+)?):\s", r"\1 ", value)  # 'PA-410R-5G 105: mm H' typo
    return models, value


def extract_hardware(parts) -> dict:
    """Rows of {label, lines[]} or {label, subtable{columns, rows[{model, cells}]}}."""
    all_spans = [sp for _, spans in parts for sp in spans if not sp.sup]
    sizes = [round(sp.size, 1) for sp in all_spans]
    body_size = max(set(sizes), key=sizes.count) if sizes else 8.0

    def is_label(line):
        normal = [s for s in line if not s.sup]
        if not normal or normal[0].size < 7.5:
            return False
        models, value = scope_models(line_text(line))
        if models and not value:  # bold scope line: 'PA-5540, PA-5550:'
            return False
        return all(s.bold or s.size >= body_size + 0.7 for s in normal)

    # 1) Blocks: consecutive label lines (gap < 11pt) form one label block;
    #    value lines up to the next label block are its body.
    blocks = []
    stopped = False
    for page, spans in parts:
        prev_label_y = None
        if stopped:
            break
        for line in group_lines(spans):
            txt = " ".join(s.text for s in line)
            if "Ordering Information" in txt:
                stopped = True
                break
            if txt.startswith("Strata by Palo Alto") or re.fullmatch(r"\d+", txt):
                continue
            if is_label(line):
                if blocks and prev_label_y is not None and not blocks[-1]["body"] \
                        and line[0].y - prev_label_y < 11 and blocks[-1]["page"] == page:
                    blocks[-1]["label_spans"] += [s for s in line if not s.sup]
                else:
                    blocks.append({"page": page, "label_spans": [s for s in line if not s.sup], "body": []})
                prev_label_y = line[0].y
            elif blocks:
                blocks[-1]["body"].append(line)
                prev_label_y = None

    rows = []
    pending = None  # label with an empty body, waiting for a sub-table header
    for b in blocks:
        cols = []
        for sp in sorted(b["label_spans"], key=lambda s: (s.y, s.x0)):
            hit = next((c for c in cols if sp.x0 < c["x1"] + 4 and sp.x1 > c["x0"] - 4), None)
            if hit:
                hit["text"] += " " + sp.text
                hit["x0"], hit["x1"] = min(hit["x0"], sp.x0), max(hit["x1"], sp.x1)
            else:
                cols.append({"x0": sp.x0, "x1": sp.x1, "text": sp.text})
        cols.sort(key=lambda c: c["x0"])
        for c in cols:
            c["cx"] = (c["x0"] + c["x1"]) / 2
            c["text"] = " ".join(c["text"].split())
        if len(cols) == 1:
            row = {"label": cols[0]["text"], "page": b["page"], "lines": hw_lines(b["body"])}
            if not b["body"]:
                pending = row
            else:
                pending = None
            rows.append(row)
            continue
        vcols = [c for c in cols if c["x0"] >= 120]
        label = pending["label"] if pending else " / ".join(c["text"] for c in vcols)
        if pending:
            rows.remove(pending)
            pending = None
        rows.append({"label": label, "page": b["page"], "lines": [],
                     "subtable": hw_subtable(b["body"], vcols, body_size)})
    return {"pages": sorted({p for p, _ in parts}), "rows": rows}


def line_text(line) -> str:
    text = ""
    for s in line:
        text += s.text if (s.sup or not text) else " " + s.text
    return " ".join(text.split())


def hw_lines(body) -> list[str]:
    """Join wrapped lines (wrap gap ~8.5pt vs line gap ~12pt)."""
    out, prev_y = [], None
    for line in body:
        text = line_text(line)
        if out and prev_y is not None and line[0].y - prev_y < 10.0 and not scope_models(text)[0]:
            out[-1] += " " + text
        else:
            out.append(text)
        prev_y = line[0].y
    return out


def hw_subtable(body, vcols, body_size) -> dict:
    """Grid rows: lines closer than 8pt chain into one row (cells wrap inside
    a row). Left spans (x0 < 120) name the model(s); others go to the nearest
    column. Small-text lines are footnotes."""
    groups, notes = [], []
    for line in body:
        normal = [s for s in line if not s.sup]
        if normal and normal[0].size < body_size - 0.4:
            notes.append(line_text(line))
            continue
        if groups and line[0].y - groups[-1][-1][0].y < 8.0:
            groups[-1].append(line)
        else:
            groups.append([line])
    rows = []
    for g in groups:
        left, cells = [], {}
        for line in g:
            left += [s for s in line if s.x0 < 120]
            rest = [s for s in line if s.x0 >= 120]
            for grp in merge_groups(rest):
                c = min(vcols, key=lambda c: abs(c["cx"] - grp["cx"]))
                cells[c["text"]] = (cells.get(c["text"], "") + " " + grp["text"]).strip()
        model = line_text(sorted(left, key=lambda s: (s.y, s.x0)))
        rows.append({"model": model, "cells": cells})
    out = {"columns": [c["text"] for c in vcols], "rows": rows}
    if notes:
        out["notes"] = notes
    return out


# --------------------------------------------------------------------------
# Product summary (cross-check)
# --------------------------------------------------------------------------
def extract_summary(doc) -> dict:
    out = {"pan_os": None, "blocks": []}
    m = re.search(r"PAN-OS®?\s*(\d+(?:\.\d+)*)", doc[0].get_text())
    out["pan_os"] = m.group(1) if m else None
    for pno, page in enumerate(doc):
        spans = page_spans(page)
        lines = group_lines(spans)
        starts = [i for i, l in enumerate(lines) if l[0].text.startswith(("Performance and Capacities",
                                                                          "Hardware Specifications"))]
        for k, i in enumerate(starts):
            if not lines[i][0].text.startswith("Performance"):
                continue
            end = starts[k + 1] if k + 1 < len(starts) else len(lines)
            hdr = [s for s in lines[i][1:] if s.size > 4.5]
            centers = [s.cx for s in hdr]
            models = [split_marks(s.text)[0] for s in hdr]
            left = hdr[0].x0 - 15
            rows = []
            for line in lines[i + 1:end]:
                labs = [s for s in line if s.x1 < left and s.size > 4.5]
                vals = [s for s in line if s.x0 >= left]
                if labs and vals:
                    label = split_marks(" ".join(s.text for s in labs))[0]
                    values = {}
                    for a, b, txt in assign_columns(merge_groups(vals), centers):
                        for mdl in models[a:b + 1]:
                            values[mdl] = re.sub(r"(?<=[\dMKk])[A-E]$", "", txt)  # letter footnote keys
                    rows.append({"label": label, "values": values})
                elif vals and rows and not labs:
                    for a, b, txt in assign_columns(merge_groups(vals), centers):
                        for mdl in models[a:b + 1]:
                            rows[-1]["values"][mdl] = (rows[-1]["values"].get(mdl, "") + " " + txt).strip()
            out["blocks"].append({"page": pno + 1, "models": models, "rows": rows})
    return out


# --------------------------------------------------------------------------
def extract(pdf_path: str | Path) -> dict:
    doc = pymupdf.open(str(pdf_path))
    res = {"file": Path(pdf_path).name, "performance": None, "hardware": None, "tables": []}
    for t in find_tables(doc):
        res["tables"].append({"num": t["num"], "title": t["title"], "kind": t["kind"],
                              "pages": [p for p, _ in t["parts"]]})
        if t["kind"] == "performance" and res["performance"] is None:
            res["performance"] = extract_performance(t["parts"])
            if res["performance"]:
                res["performance"]["title"] = t["title"]
        elif t["kind"] == "hardware" and res["hardware"] is None:
            res["hardware"] = extract_hardware(t["parts"])
            res["hardware"]["title"] = t["title"]
    return res


if __name__ == "__main__":
    for f in sys.argv[1:]:
        d = pymupdf.open(f)
        if "product-summary" in f:
            print(json.dumps(extract_summary(d), indent=1, ensure_ascii=False))
        else:
            print(json.dumps(extract(f), indent=1, ensure_ascii=False))
