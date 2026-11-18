#!/usr/bin/env python3
"""Turn downloaded Palo Alto datasheets into normalized JSON (+ CSV).

    python pa_normalize.py            # reads datasheets/ + manifest.json
    python pa_normalize.py --check    # also print the per-datasheet report

Outputs (same layout as jclark1978/ds-grabber):
    data/models.json             one record per model
    data/models/<id>.json        one small file per model
    data/index.json              model ids, codes, file paths, spec URLs
    data/models.csv              flat table of the main comparison fields
    reports/extraction.txt       per-datasheet counts and problems
    reports/unmapped_labels.txt  labels not in labels.yaml
    reports/crosscheck.txt       series datasheets vs the product summary

Every performance value carries the PAN-OS version it was measured on and
the footnote text (test conditions) that applies to it. Palo Alto numbers
are not directly comparable to other vendors' numbers; keep the conditions.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import re
import sys
import unicodedata
from pathlib import Path

import pymupdf
import yaml

from pa_extract import MODEL_TOKEN, extract, extract_summary, scope_models

ROOT = Path(__file__).parent
SCHEMA_VERSION = "1.0"
VENDOR = "Palo Alto Networks"
NONE_VALUES = {"", "—", "-", "–", "n/a", "na", "none", "tbd", "tba"}
MARKS = r"\*\*|\*|††|†|‡|§|\|\||#"


# --------------------------------------------------------------------------
# Value parsing
# --------------------------------------------------------------------------
def clean(raw: str) -> str:
    raw = unicodedata.normalize("NFKC", raw or "")
    return " ".join(re.sub(r"[\x00-\x1f]", "", raw).split())


def is_none(raw: str) -> bool:
    return clean(raw).strip("* ").lower() in NONE_VALUES


def num(s: str) -> float:
    n = float(s.replace(",", ""))
    return int(n) if n == int(n) else n


def to_mbps(raw: str) -> tuple[float | None, str | None]:
    """Returns (Mbps, assumed_unit)."""
    s = clean(raw)
    m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(Tbps|Gbps|Mbps|Kbps)?", s, re.I)
    if not m:
        return None, None
    n = float(m.group(1).replace(",", ""))
    unit = (m.group(2) or "").lower()
    assumed = None
    if not unit:
        unit, assumed = "gbps", "Gbps"
    v = round(n * {"tbps": 1_000_000, "gbps": 1000, "mbps": 1, "kbps": 0.001}[unit], 3)
    return (int(v) if v == int(v) else v), assumed


def to_count(raw: str) -> float | None:
    s = clean(raw)
    m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(M|K|million|thousand)?\b", s, re.I)
    if not m:
        return None
    n = float(m.group(1).replace(",", ""))
    mult = (m.group(2) or "").lower()
    n *= 1_000_000 if mult in ("m", "million") else 1000 if mult in ("k", "thousand") else 1
    return int(round(n))


def split_http_appmix(label: str, raw: str) -> tuple[str, str | None]:
    """'(HTTP/appmix)' rows print 'HTTP/appmix' values ('545/535 Mbps',
    '1.0/1.2 Gbps'). -> (appmix raw, HTTP raw); unit copied to both."""
    if not re.search(r"HTTP\s*/\s*appmix", label, re.I):
        return raw, None
    m = re.match(r"^\s*([\d.,]+)\s*(\w*bps)?\s*/\s*([\d.,]+)\s*(\w*bps)?\s*$", clean(raw), re.I)
    if not m:
        return raw, None
    unit = m.group(4) or m.group(2) or ""
    return f"{m.group(3)} {m.group(4) or unit}".strip(), f"{m.group(1)} {m.group(2) or unit}".strip()


def parse_perf(kind: str, raw: str):
    if is_none(raw):
        return {None: None}, None
    if kind == "mbps":
        v, assumed = to_mbps(raw)
        return {None: v}, assumed
    if kind == "count":
        return {None: to_count(raw)}, None
    if kind == "pair":
        parts = [p for p in re.split(r"\s*/\s*", clean(raw))][:2]
        return {i: (None if is_none(p) else to_count(p)) for i, p in enumerate(parts)}, None
    return {None: clean(raw)}, None


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
class Config:
    def __init__(self, path: Path):
        cfg = yaml.safe_load(path.read_text())
        self.perf = [(re.compile(p, re.I), name, spec)
                     for name, spec in cfg["performance"].items() for p in spec["patterns"]]
        self.hw = [(re.compile(p, re.I), name) for name, pats in cfg["hardware"].items() for p in pats]
        self.aliases = cfg.get("model_aliases") or {}
        self.card_re = re.compile(cfg.get("card_column_re", r"$^"))
        self.exclude = cfg.get("exclude_files") or []
        self.label_fixes = {clean(k): v for k, v in (cfg.get("hardware_label_fixes") or {}).items()}

    def perf_field(self, label):
        return next(((n, s) for rx, n, s in self.perf if rx.search(label)), None)

    def hw_field(self, label):
        return next((n for rx, n in self.hw if rx.search(label)), None)

    def fix_label(self, label: str) -> str:
        return self.label_fixes.get(clean(label), clean(label))

    def canon(self, model: str) -> str:
        m = clean(model).upper()
        return self.aliases.get(m, m)

    def excluded(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, p) for p in self.exclude)


# --------------------------------------------------------------------------
# Hardware helpers
# --------------------------------------------------------------------------
def models_in(text: str) -> list[str]:
    return re.findall(MODEL_TOKEN, text)


def inline_per_model(line: str, known: set, cfg: Config) -> dict[str, str] | None:
    """Lines that scope values to models mid-line:
      'Maximum: PA-820: 120 W; PA-850: 240 W Average: PA-820: 41 W; PA-850: 64 W'
      'HSCI: PA-1510-POE: 10G SFP+ (1), PA-1520-POE, PA-1530-POE: 25G SFP28 (1)'
    -> {'PA-820': 'Maximum: 120 W; Average: 41 W', ...}. A line that starts with
    the model list ('PA-820: ...') is a normal scoped line and returns None."""
    mt = rf"{MODEL_TOKEN}[*†‡§#]*"
    groups = list(re.finditer(rf"((?:{mt}\s*(?:,|\band\b|\bor\b)\s*)*{mt})\s*:\s*", line))
    if not groups or groups[0].start() == 0:
        return None
    if len({cfg.canon(m) for g in groups for m in models_in(g.group(1))} & known) < 2:
        return None
    out: dict[str, list[str]] = {}
    for i, g in enumerate(groups):
        end = groups[i + 1].start() if i + 1 < len(groups) else len(line)
        seg = line[g.end():end]
        seg = re.sub(r"\s[A-Z][A-Za-z]+:\s*$", "", seg)  # next context word ('Average:')
        ctx = None
        for c in re.finditer(r"(?:^|\s)([A-Z][A-Za-z]+):\s", line[:g.start()]):
            ctx = c.group(1)
        if not seg.strip(" ;,"):
            continue
        text = f"{ctx + ': ' if ctx else ''}{seg.strip(' ;,')}"
        for m in models_in(g.group(1)):
            mid = cfg.canon(m)
            if mid in known:
                out.setdefault(mid, []).append(text)
    return {k: "; ".join(v) for k, v in out.items()} if out else None


def hardware_by_model(hw: dict, models: list[str], cfg: Config, problems: list[str]) -> dict[str, dict]:
    """-> {model: {label: text}} using the scoping rules in pa_extract."""
    known = set(models)
    out: dict[str, dict] = {m: {} for m in models}

    def add(targets, label, text):
        for m in targets:
            d = out[m]
            d[label] = f"{d[label]}; {text}" if label in d else text

    def resolve(tokens):
        ms = [cfg.canon(t) for t in tokens]
        hit = [m for m in ms if m in known]
        miss = [m for m in ms if m not in known]
        return hit, miss

    for row in (hw or {}).get("rows", []):
        label = cfg.fix_label(row["label"])
        if row.get("subtable") and row["subtable"].get("transposed"):
            # rows are attributes, columns are systems (PA-7000)
            st = row["subtable"]
            colmap = {}
            for col in st["columns"]:
                hit, _ = resolve(models_in(col))
                if len(hit) == 1:
                    colmap[col] = hit[0]
            for r in st["rows"]:
                rlabel = cfg.fix_label(r["model"])
                for col, val in r["cells"].items():
                    if col in colmap and not is_none(val):
                        add([colmap[col]], rlabel, clean(val))
            continue
        if row.get("subtable"):
            st = row["subtable"]
            for r in st["rows"]:
                hit, miss = resolve(models_in(r["model"]))
                if miss and hit:
                    problems.append(f"hardware '{label}': unknown model(s) {miss}")
                targets = hit or models
                for col, val in r["cells"].items():
                    add(targets, f"{label} | {clean(col)}" if " / " not in label else clean(col), clean(val))
            continue
        scope = None
        for line in row["lines"]:
            line = clean(line)
            per = inline_per_model(line, known, cfg)
            if per:
                for m, text in per.items():
                    add([m], label, text)
                continue
            toks, value = scope_models(line)
            if toks:
                hit, miss = resolve(toks)
                if miss:
                    problems.append(f"hardware '{label}': unknown model(s) {miss}")
                if hit and not value:
                    scope = hit
                    continue
                if hit:
                    add(hit, label, value)
                    continue
            # 'Passive cooling: PA-501, PA-505, and PA-555-POE'
            m = re.match(rf"^(.+?):\s*((?:{MODEL_TOKEN})(?:\s*(?:,|and|or|/)\s*(?:{MODEL_TOKEN}))*)\.?$", line)
            if m:
                hit, _ = resolve(models_in(m.group(2)))
                if hit:
                    add(hit, label, m.group(1))
                    continue
            add(scope or models, label, line)
    return out


def joined(items: list[tuple[str, str]]) -> str:
    return "; ".join(t for _, t in items)


W_NUM = r"(\d[\d,]*(?:\.\d+)?)"


def parse_power(label: str, text: str) -> tuple[float | None, float | None]:
    """-> (avg_w, max_w). Ignores PSU ratings and PoE budgets in the text."""
    low = label.lower()
    if re.search(r"avg\s*/\s*max", low):
        # 'PSU rating (avg/max)': '250W (150/200)', 'Redundant 400W AC (175W/200W)', '180 W (40 W / 75 W)'
        m = re.search(rf"\(\s*{W_NUM}\s*(?:W\b)?\s*/\s*{W_NUM}\s*(?:W\b)?\s*\)", text, re.I)
        if m:
            return float(m.group(1).replace(",", "")), float(m.group(2).replace(",", ""))
    t = re.sub(r"\(with [^)]*\)|with \d[\d,]*\s*W PoE\)?|\d[\d,]*\s*W PoE( output)?", " ", text, flags=re.I)
    t = re.sub(r"\d[\d,]*\s*-?\s*(?:W|watts?)\b\s*(?:/\s*)?(?:AC\s*|DC\s*)?power supply", " ", t, flags=re.I)
    t = re.sub(r"\d+-watt", " ", t, flags=re.I)
    t = re.sub(r"(AC|DC)\s+\d[\d,]*\s*W\b", " ", t)
    mult = lambda u: 1000 if (u or "").lower() == "kw" else 1
    vals = []
    m = re.search(rf"{W_NUM}\s*(KW|W)?\s*/\s*{W_NUM}\s*(KW|W)?(?:\s*/\s*{W_NUM}\s*(KW|W))?", t, re.I)
    if m and (m.group(2) or m.group(4) or m.group(6)):
        unit = m.group(6) or m.group(4) or m.group(2)
        for g, u in ((1, 2), (3, 4), (5, 6)):
            if m.group(g):
                vals.append(float(m.group(g).replace(",", "")) * mult(m.group(u) or unit))
    else:
        vals = [float(n.replace(",", "")) * mult(u) for n, u in re.findall(rf"{W_NUM}\s*(KW|W)\b", t, re.I)]
    mx_m = re.search(rf"Max(?:imum)?:\s*{W_NUM}\s*(KW|W)\b", t, re.I)
    av_m = re.search(rf"Av(?:era)?g(?:e)?:\s*{W_NUM}\s*(KW|W)\b", t, re.I)
    if mx_m or av_m:
        f = lambda m: float(m.group(1).replace(",", "")) * mult(m.group(2)) if m else None
        return f(av_m), f(mx_m)
    if not vals and re.search(r"avg\s*/\s*max", low):
        m = re.search(rf"\(\s*{W_NUM}\s*/\s*{W_NUM}\s*\)", t)  # 'Redundant 650-watt AC or DC (195/240)'
        if m:
            return float(m.group(1).replace(",", "")), float(m.group(2).replace(",", ""))
    if not vals:
        return None, None
    if "idle/typical/max" in low and len(vals) >= 3:
        return vals[1], vals[2]
    if re.search(r"max\s*/\s*av", low):
        return (vals[1] if len(vals) > 1 else None), vals[0]
    if re.search(r"avg\s*/\s*max|average\s*/\s*max", low) and len(vals) >= 2:
        return vals[0], vals[1]
    if re.search(r"\(max", t, re.I):
        mm = re.search(rf"{W_NUM}\s*W\s*\(max", t, re.I)
        return None, float(mm.group(1).replace(",", "")) if mm else vals[0]
    if "average" in low and "max" not in low:
        return vals[0], None
    if "max" in low or "max power" in t.lower():
        return None, vals[0]
    return None, None


def derive_hardware(raw_by_field: dict[str, list[tuple[str, str]]], cells: dict[str, str]) -> dict:
    """raw_by_field: {field: [(label, text), ...]}."""
    hw: dict = {}
    # Power: per (label, text), most specific label first.
    pw_items = [(l, t) for l, t in raw_by_field.get("power_consumption", [])]
    pw_items += [(k, v) for k, v in cells.items() if "power consumption" in k.lower()]
    pw_items.sort(key=lambda lt: 0 if "consumption" in lt[0].lower() else 1)
    avg = mx = None
    for label, text in pw_items:
        a2, m2 = parse_power(label, text)
        if avg is None and a2 is not None:
            avg = a2
        if mx is None and m2 is not None:
            mx = m2
    if avg is not None:
        hw["power_avg_w"] = avg
    if mx is not None:
        hw["power_max_w"] = mx
    # BTU
    if "heat_btu_h" in raw_by_field:
        t = joined(raw_by_field["heat_btu_h"])
        m = (re.search(r"(\d[\d,]*(?:\.\d+)?)\s*BTU", t, re.I) or re.search(r"BTU\w*\s+(\d[\d,]*(?:\.\d+)?)", t, re.I)
             or re.search(r"(?:^|;\s*)(\d[\d,]*(?:\.\d+)?)\s*(?:;|$|\()", t))
        if m:
            hw["heat_btu_h"] = num(m.group(1))
    # Dimensions / rack units
    if "dimensions" in raw_by_field:
        t = joined(raw_by_field["dimensions"])
        m = re.search(r"(\d+)\s*-?\s*RU\b|\b(\d+)U\b", t)
        hw["rack_units"] = int(m.group(1) or m.group(2)) if m else None
        hw["desktop"] = hw["rack_units"] is None and not re.search(r"rack", t, re.I)
        dims = {}
        mm = "mm" in t
        for n, axis in re.findall(r"(\d+(?:\.\d+)?)\s*(?:mm|\"|”|in)?\s*(H|W|D)\b", t):
            dims.setdefault(axis.lower(), float(n) if mm else round(float(n) * 25.4, 1))
        if len(dims) == 3:
            hw["dimensions_mm"] = {"h": dims["h"], "w": dims["w"], "d": dims["d"]}
    # Weight (standalone)
    if "weight" in raw_by_field:
        t = joined(raw_by_field["weight"])
        m = re.search(r"(\d+(?:\.\d+)?)\s*(?:/[\d.]+\s*)?(lbs?|kg)", t, re.I)
        if m:
            w = float(m.group(1))
            hw["weight_kg"] = round(w if m.group(2).lower() == "kg" else w * 0.45359, 2)
    # Operating temperature
    if "environment" in raw_by_field:
        env = joined(raw_by_field["environment"])
        seg = re.search(r"(?<!non-)(?<!non)Operating temperature\s*[:–-]?\s*(.*?)(?:;|Non-?operating|$)", env, re.I)
        if seg:  # '32°F to 104°F, 0°C to 40°C' / '0° to 40° C' / '-40°C to 70°C' / '0 to 50 C'
            m = re.search(r"(-?\d+)\s*°?\s*(?:C\s*)?(?:to|–|-)\s*(-?\d+)\s*°?\s*C\b", seg.group(1))
            if m:
                hw["operating_temp_c"] = {"min": int(m.group(1)), "max": int(m.group(2))}
    # Interfaces
    ifs = []
    if "interfaces" in raw_by_field:
        t = joined(raw_by_field["interfaces"])
        for part in re.split(r",\s*(?![^()]*\))|;\s*", t):
            m = re.match(r"^\s*(?:and\s+)?(.+?)\s*\((\d+)\)\s*(/\s*PoE)?\s*(.*)$", part)
            m2 = re.match(r"^\s*(?:and\s+)?\((\d+)\)\s*(.+?)\s*$", part)  # 2013-2018: '(12) 10/100/1000'
            if m2:
                ifs.append({"type": clean(m2.group(2)), "count": int(m2.group(1))})
            elif m:
                ifs.append({"type": clean(m.group(1) + (" PoE" if m.group(3) else "") +
                                          (" " + m.group(4) if m.group(4) and len(m.group(4)) < 40 else "")),
                            "count": int(m.group(2))})
    for k, v in cells.items():
        m = re.match(r"^(\d+)\s*x\s*(.+)$", v)
        if m:
            ifs.append({"type": f"{k} {m.group(2)}", "count": int(m.group(1))})
    if ifs:
        hw["interfaces"] = ifs
    for f in ("storage", "mtbf", "power_supplies"):
        if f in raw_by_field:
            hw[f] = joined(raw_by_field[f])
    return hw


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
def series_name(title: str) -> str:
    m = re.search(r"(PA-\w+(?:\s+Series)?)", title)
    return m.group(1) if m else title


def system_name(col: str) -> str:
    return re.sub(r"\s+Configured System$", "", clean(col))


def build(ds_dir: Path, manifest: dict, cfg: Config):
    models: dict[str, dict] = {}
    unmapped: dict[str, set] = {}
    report: list[str] = []

    for pdf in sorted(ds_dir.glob("*.pdf"), key=lambda p: p.name.lower()):
        if cfg.excluded(pdf.name):
            report.append(f"SKIP   {pdf.name} (excluded in labels.yaml)")
            continue
        meta = manifest.get(pdf.name, {})
        problems: list[str] = []
        try:
            ext = extract(pdf)
        except Exception as e:  # keep going, report it
            report.append(f"ERROR  {pdf.name}: {e.__class__.__name__}: {e}")
            continue
        perf = ext["performance"]
        if not perf:
            report.append(f"CHECK  {pdf.name}: no performance table found")
            continue
        foot = {k: clean(v) for k, v in perf["footnotes"].items()}
        note = foot.get("note", "")
        m = re.search(r"PAN-OS\s*(\d+(?:\.\d+)*)", note)
        if not m:  # 2013-2015 specsheets: '1 Performance and capacities are measured ... using PAN-OS 5.0.'
            for k, v in foot.items():
                m = re.search(r"PAN-OS\s*(\d+(?:\.\d+)*)", v)
                if m:
                    note = v
                    break
        pan_os = m.group(1) if m else None
        legacy = bool(meta.get("legacy"))
        table_conds = [note] if perf.get("legacy_layout") and note else []
        if not pan_os:
            problems.append("PAN-OS version not found")
        series = series_name(perf.get("title", ""))
        if perf.get("legacy_layout"):  # no caption: name the series from the file ('specsheet-pa-3000' -> 'PA-3000 Series')
            fm = re.search(r"pa-(\d+)", pdf.stem)
            series = f"PA-{fm.group(1)}" + (" Series" if len(perf["models"]) > 1 else "") if fm else pdf.stem
        url = meta.get("url")

        cols = perf["models"]
        card_cols = [c for c in cols if cfg.card_re.search(c)]
        sys_cols = [c for c in cols if c not in card_cols]
        sys_ids = {c: cfg.canon(system_name(c)) for c in sys_cols}
        for c, mid in sys_ids.items():
            if mid in models:
                problems.append(f"{mid} also in {models[mid]['source']['file']}; first kept")
                continue
            models[mid] = {
                "model": mid,
                "model_id": mid,
                "vendor": VENDOR,
                "family": "PA-Series",
                "series": series,
                "form_factor": "appliance",
                "legacy": legacy,
                "source": {
                    "title": f"{series} Datasheet",
                    "url": url,
                    "page_url": meta.get("page_url"),
                    "spec_url": f"{url}#page={perf['page']}" if url else None,
                    "file": pdf.name,
                    "library_last_updated": meta.get("last_updated"),
                    "sha256": meta.get("sha256"),
                },
                "test_conditions": {"pan_os": pan_os, "note": note or None},
                "specs": {},
                "hardware": {},
                "vm": None,
                "footnotes": {k: v for k, v in foot.items() if k != "note"},
                "other": {},
            }
            if clean(c).upper() != mid:
                models[mid]["printed_as"] = clean(c)
            colm = perf.get("model_marks", {}).get(c, [])
            if colm:
                models[mid]["test_conditions"]["column_notes"] = [foot[k] for k in colm if k in foot]

        n_rows, mapped = len(perf["rows"]), 0
        for row in perf["rows"]:
            label = clean(row["label"])
            hit = cfg.perf_field(label)
            if hit:
                mapped += 1
            else:
                unmapped.setdefault(label, set()).add(pdf.name)
            for col, cell in row["values"].items():
                raw = clean(cell["raw"])
                marks = row["marks"] + cell["marks"] + perf.get("model_marks", {}).get(col, [])
                marks = sorted(set(marks), key=marks.index)
                is_card = col in card_cols
                targets = [sys_ids[c] for c in sys_cols] if is_card else [sys_ids[col]]
                for mid in targets:
                    rec = models.get(mid)
                    if rec is None or rec["source"]["file"] != pdf.name:
                        continue
                    if is_card:
                        cname = clean(re.sub(r"^Single\s+", "", col))
                        cards = rec.setdefault("per_card", [])
                        pc = next((c for c in cards if c["card"] == cname), None)
                        if pc is None:
                            pc = {"card": cname, "specs": {}}
                            cards.append(pc)
                        store = pc["specs"]
                    else:
                        store = rec["specs"]
                    if not hit:
                        (rec["other"] if not is_card else store)[label] = raw
                        continue
                    field, spec = hit
                    val_raw, http_raw = (split_http_appmix(label, raw) if spec["parse"] == "mbps"
                                         else (raw, None))
                    parsed, assumed = parse_perf(spec["parse"], val_raw)
                    names = spec.get("fields") or [field]
                    for key, val in parsed.items():
                        fname = names[0] if key is None else (names[key] if key < len(names) else None)
                        if not fname:
                            continue
                        e = {"value": val, "raw": raw, "label": label}
                        if marks:
                            e["notes"] = marks
                        conds = [foot[k] for k in marks if k in foot] + table_conds
                        if conds:
                            e["test_conditions"] = list(dict.fromkeys(conds))
                        if assumed and val is not None:
                            e["unit_assumed"] = assumed
                        if http_raw:
                            e["http_value"], _ = to_mbps(http_raw)
                            e["note"] = "Datasheet prints HTTP/appmix; value is the appmix number."
                        e["pan_os"] = pan_os
                        store[fname] = e

        # Hardware
        file_models = [m for m in sys_ids.values() if models[m]["source"]["file"] == pdf.name]
        hw_raw = hardware_by_model(ext["hardware"], file_models, cfg, problems)
        hw_unmapped = set()
        sub_cols = {clean(c) for r in (ext["hardware"] or {}).get("rows", []) if r.get("subtable")
                    for c in r["subtable"]["columns"]}
        for mid in file_models:
            raw = hw_raw.get(mid, {})
            by_field, cells = {}, {}
            for label, text in raw.items():
                base = label.split(" | ")[0]
                f = cfg.hw_field(base) or cfg.hw_field(label)
                if " | " in label or label in sub_cols:
                    cells[label.split(" | ")[-1]] = text
                if f:
                    by_field.setdefault(f, []).append((label, text))
                else:
                    hw_unmapped.add(label)
            hw = derive_hardware(by_field, cells)
            hw["raw"] = raw
            models[mid]["hardware"] = hw
        for lab in hw_unmapped:
            if not any(cfg.hw_field(p) for p in lab.split(" | ")):
                unmapped.setdefault(f"[hardware] {lab}", set()).add(pdf.name)
        if not ext["hardware"]:
            problems.append("no hardware table found")

        pct = f"{100 * mapped // n_rows}%" if n_rows else "-"
        report.append(f"{'OK   ' if not problems else 'CHECK'}  {pdf.name:30} perf_page={perf['page']:<2} "
                      f"rows={n_rows} mapped={pct:>4} models={len(file_models)} PAN-OS={pan_os}"
                      + (f"  cards={card_cols}" if card_cols else "") + ("  legacy" if legacy else ""))
        for p in sorted(set(problems)):
            report.append(f"         - {p}")
    return models, unmapped, report


# --------------------------------------------------------------------------
# Cross-check against the product summary
# --------------------------------------------------------------------------
def crosscheck(summary_pdf: Path, models: dict, cfg: Config) -> list[str]:
    if not summary_pdf.exists():
        return ["product-summary-specsheet.pdf not found; skipped."]
    summ = extract_summary(pymupdf.open(str(summary_pdf)))
    lines = [f"Product summary (PAN-OS {summ['pan_os']}) vs series datasheets.",
             "Differences usually mean the two documents were measured on different",
             "PAN-OS releases or one was updated before the other. The series datasheet",
             "is the source used in data/.", ""]
    diffs = same = 0
    missing = set()
    for block in summ["blocks"]:
        for row in block["rows"]:
            hit = cfg.perf_field(clean(row["label"]))
            if not hit:
                continue
            field, spec = hit
            for mdl, raw in row["values"].items():
                mid = cfg.canon(re.sub(r"[A-E]$", "", mdl) if re.match(r"^PA-\d+[A-E]$", mdl)
                                and cfg.canon(mdl) not in models else mdl)
                rec = models.get(mid)
                if not rec:
                    missing.add(mid)
                    continue
                parsed, _ = parse_perf(spec["parse"], raw)
                names = spec.get("fields") or [field]
                for key, val in parsed.items():
                    fname = names[0] if key is None else names[key]
                    mine = (rec["specs"].get(fname) or {}).get("value")
                    if mine is None and val is None:
                        continue
                    if mine == val:
                        same += 1
                    else:
                        diffs += 1
                        lines.append(f"DIFF  {mid:16} {fname:34} datasheet={mine!s:>10} "
                                     f"(PAN-OS {rec['test_conditions']['pan_os']})  summary={val!s:>10}  "
                                     f"[summary raw: {clean(raw)}]")
    lines.insert(5, f"{same} values match, {diffs} differ.")
    lines.insert(6, "")
    if missing:
        lines += ["", "In the summary but not in any series datasheet: " + ", ".join(sorted(missing))]
    in_ds = sorted({m for m, r in models.items() if not r.get("legacy")}
                   - {cfg.canon(m) for b in summ["blocks"] for m in b["models"]})
    if in_ds:
        lines += ["In a series datasheet but not in the summary: " + ", ".join(in_ds)]
    return lines


# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------
CSV_FIELDS = ["fw_throughput_appmix_mbps", "fw_throughput_appid_mbps", "threat_prevention_throughput_mbps", "ipsec_throughput_mbps",
              "concurrent_sessions", "new_sessions_per_sec", "vsys_base", "vsys_max"]


def natural_key(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def model_slug(mid: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", mid).strip("_")


def model_codes(mid: str) -> list[str]:
    """'PA-415-5G' -> ['415-5G', '4155G']."""
    code = mid[3:] if mid.startswith("PA-") else mid
    out = [code, code.replace("-", "")]
    return sorted(set(out), key=out.index)


def write_if_changed(path: Path, body: str) -> None:
    if not path.exists() or path.read_text() != body:
        path.write_text(body)


def write_outputs(models, unmapped, report, cross, out_root: Path) -> None:
    data, reports = out_root / "data", out_root / "reports"
    (data / "models").mkdir(parents=True, exist_ok=True)
    reports.mkdir(exist_ok=True)
    recs = sorted(models.values(), key=lambda r: natural_key(r["model_id"]))
    doc = {"schema_version": SCHEMA_VERSION, "vendor": VENDOR,
           "units": {"throughput": "Mbps", "power": "watts", "weight": "kg", "dimensions": "mm"},
           "note": "Performance values are as published, measured on the PAN-OS release in each "
                   "value's pan_os field, under the conditions in test_conditions. They are not "
                   "like-for-like with other vendors' published numbers.",
           "count": len(recs), "models": recs}
    write_if_changed(data / "models.json", json.dumps(doc, indent=2, ensure_ascii=False) + "\n")

    keep, index = set(), []
    for r in recs:
        slug = model_slug(r["model_id"])
        keep.add(f"{slug}.json")
        write_if_changed(data / "models" / f"{slug}.json", json.dumps(r, indent=2, ensure_ascii=False) + "\n")
        index.append({"model_id": r["model_id"], "model": r["model"], "form_factor": r["form_factor"],
                      "file": f"data/models/{slug}.json", "family": r["family"], "series": r["series"],
                      "codes": model_codes(r["model_id"]), "pan_os": r["test_conditions"]["pan_os"],
                      "legacy": r["legacy"],
                      "spec_url": r["source"]["spec_url"]})
    for f in (data / "models").glob("*.json"):
        if f.name not in keep:
            f.unlink()
    write_if_changed(data / "index.json", json.dumps({
        "schema_version": SCHEMA_VERSION, "vendor": VENDOR, "count": len(index),
        "match_rule": "Uppercase the user's text, strip 'PALO ALTO', 'NETWORKS', a leading 'PA', spaces "
                      "and a leading dash, then compare to 'codes' (with and without dashes).",
        "legacy_rule": "legacy: true = end-of-sale model, found only through Palo Alto's Hardware End-of-Life "
                       "Dates page. Its datasheet may be years old and measured on an old PAN-OS release; "
                       "skip legacy models when picking a current competitor match.",
        "models": index}, indent=1, ensure_ascii=False) + "\n")

    with open(data / "models.csv", "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["model_id", "series", "legacy", "pan_os", "rack_units", "power_max_w"] + CSV_FIELDS + ["spec_url"])
        for r in recs:
            hw = r["hardware"] or {}
            w.writerow([r["model_id"], r["series"], r["legacy"], r["test_conditions"]["pan_os"], hw.get("rack_units"),
                        hw.get("power_max_w")] + [(r["specs"].get(k) or {}).get("value") for k in CSV_FIELDS]
                       + [r["source"]["spec_url"]])

    lines = [f"{len(unmapped)} labels not mapped in labels.yaml.", ""]
    for label, files in sorted(unmapped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"{len(files):3}  {label}    [{', '.join(sorted(files)[:3])}{', ...' if len(files) > 3 else ''}]")
    write_if_changed(reports / "unmapped_labels.txt", "\n".join(lines).rstrip() + "\n")
    write_if_changed(reports / "extraction.txt", "\n".join(report) + "\n")
    write_if_changed(reports / "crosscheck.txt", "\n".join(cross) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasheets", default=str(ROOT / "datasheets"))
    ap.add_argument("--manifest", default=str(ROOT / "manifest.json"))
    ap.add_argument("--labels", default=str(ROOT / "labels.yaml"))
    ap.add_argument("--out", default=str(ROOT))
    ap.add_argument("--check", action="store_true", help="print the per-datasheet report")
    args = ap.parse_args()

    manifest = {}
    if Path(args.manifest).exists():
        manifest = json.loads(Path(args.manifest).read_text()).get("datasheets", {})
    cfg = Config(Path(args.labels))
    models, unmapped, report = build(Path(args.datasheets), manifest, cfg)
    cross = crosscheck(Path(args.datasheets) / "product-summary-specsheet.pdf", models, cfg)
    write_outputs(models, unmapped, report, cross, Path(args.out))
    if args.check:
        print("\n".join(report))
        print("\n".join(cross[:6]))
    print(f"models.json: {len(models)} models; {len(unmapped)} unmapped labels (see reports/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
