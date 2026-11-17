#!/usr/bin/env python3
"""pa-grabber: keep a local, current library of Palo Alto Networks firewall datasheets.

Finds datasheet pages (/resources/datasheets/<slug>) linked from the pages in
sources.yaml, reads each page's published date, downloads new or changed PDFs,
and records everything in manifest.json.

Usage:
    python pa_grabber.py --list-only     # show what would be downloaded
    python pa_grabber.py                 # download new/changed datasheets
    python pa_grabber.py --force         # re-download everything
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import yaml

BASE = "https://www.paloaltonetworks.com"
DETAIL = BASE + "/resources/datasheets/{slug}"
HANDLER = BASE + "/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/datasheets/{slug}"
DAM_PDF = BASE + "/content/dam/pan/en_US/assets/pdf/datasheets/{slug}/{slug}.pdf"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
SLUG_RE = re.compile(r"/resources/datasheets/([a-z0-9][a-z0-9\-]*)", re.I)
DATE_RE = re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? (\d{1,2}), (\d{4})\b")
TITLE_RE = re.compile(r"<title>\s*([^<|]+?)\s*(?:\||</title>)", re.I)
DAM_RE = re.compile(r"/content/dam/pan/en_US/assets/pdf/datasheets/[^\"'\s]+?\.pdf", re.I)


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"})
    return s


def load_sources(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def wanted(slug: str, cfg: dict) -> bool:
    inc = [re.compile(p, re.I) for p in cfg.get("include", [])]
    exc = [re.compile(p, re.I) for p in cfg.get("exclude", [])]
    return any(p.search(slug) for p in inc) and not any(p.search(slug) for p in exc)


def discover(s: requests.Session, cfg: dict) -> list[str]:
    slugs: list[str] = []
    for url in cfg.get("crawl_pages", []):
        try:
            r = s.get(url, timeout=30)
        except requests.RequestException as e:
            print(f"  warning: {url}: {e.__class__.__name__}", flush=True)
            continue
        if r.status_code != 200:
            print(f"  warning: {url}: HTTP {r.status_code}", flush=True)
            continue
        found = [m.group(1).lower() for m in SLUG_RE.finditer(r.text)]
        found = [f for f in found if wanted(f, cfg)]
        print(f"  {url}: {len(set(found))} datasheet links", flush=True)
        slugs += found
    slugs += [x.lower() for x in cfg.get("extra_slugs", [])]
    out = []
    for x in slugs:  # keep order, drop duplicates
        if x not in out:
            out.append(x)
    return out


def page_info(s: requests.Session, slug: str) -> dict:
    """Title, published date and any direct PDF path from the datasheet page."""
    info = {"slug": slug, "page_url": DETAIL.format(slug=slug), "title": None, "last_updated": None, "dam_pdf": None}
    try:
        r = s.get(info["page_url"], timeout=30)
    except requests.RequestException as e:
        info["error"] = e.__class__.__name__
        return info
    if r.status_code != 200:
        info["error"] = f"HTTP {r.status_code}"
        return info
    html = r.text
    m = TITLE_RE.search(html)
    if m:
        info["title"] = " ".join(m.group(1).split())
    m = DATE_RE.search(html)
    if m:
        try:
            info["last_updated"] = datetime.strptime(f"{m.group(1)[:3]} {m.group(2)} {m.group(3)}", "%b %d %Y").date().isoformat()
        except ValueError:
            pass
    m = DAM_RE.search(html)
    if m:
        info["dam_pdf"] = urljoin(BASE, m.group(0))
    return info


def fetch_pdf(s: requests.Session, info: dict) -> tuple[bytes, str]:
    """Try the download handler, then the DAM path from the page, then the inferred DAM path."""
    slug = info["slug"]
    tries = [HANDLER.format(slug=slug)]
    if info.get("dam_pdf"):
        tries.append(info["dam_pdf"])
    tries.append(DAM_PDF.format(slug=slug))
    last = "no attempt"
    for url in dict.fromkeys(tries):
        try:
            r = s.get(url, timeout=60, allow_redirects=True)
        except requests.RequestException as e:
            last = f"{url}: {e.__class__.__name__}"
            continue
        if r.status_code == 200 and r.content.startswith(b"%PDF"):
            return r.content, r.url
        last = f"{url}: HTTP {r.status_code}" + ("" if r.status_code != 200 else " (not a PDF)")
    raise RuntimeError(last)


def load_manifest(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"generated": None, "source": BASE + "/resources/datasheets", "datasheets": {}}


def sync(s, infos, out_dir: Path, manifest_path: Path, force=False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / "_archive"
    manifest = load_manifest(manifest_path)
    entries = manifest["datasheets"]
    stats = {"new": [], "updated": [], "unchanged": [], "failed": []}

    for info in infos:
        name = f"{info['slug']}.pdf"
        prev, dest = entries.get(name), out_dir / name
        if info.get("error"):
            print(f"  FAILED  {name}: page {info['error']}", file=sys.stderr)
            stats["failed"].append(name)
            continue
        if (not force and prev and dest.exists() and info["last_updated"]
                and prev.get("last_updated") == info["last_updated"]):
            stats["unchanged"].append(name)
            continue
        try:
            data, pdf_url = fetch_pdf(s, info)
        except RuntimeError as e:
            print(f"  FAILED  {name}: {e}", file=sys.stderr)
            stats["failed"].append(name)
            continue
        digest = hashlib.sha256(data).hexdigest()
        if prev and prev.get("sha256") == digest and dest.exists():
            prev["last_updated"] = info["last_updated"]
            stats["unchanged"].append(name)
            continue
        if prev and dest.exists():
            archive.mkdir(exist_ok=True)
            stamp = prev.get("last_updated") or (prev.get("downloaded") or "old")[:10]
            dest.rename(archive / f"{dest.stem}_{stamp}{dest.suffix}")
            stats["updated"].append(name)
            print(f"  UPDATED {name}")
        else:
            stats["new"].append(name)
            print(f"  NEW     {name}")
        dest.write_bytes(data)
        entries[name] = {
            "title": info["title"] or info["slug"],
            "page_url": info["page_url"],
            "url": pdf_url,
            "last_updated": info["last_updated"],
            "downloaded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sha256": digest,
            "bytes": len(data),
        }
        time.sleep(0.5)  # be polite

    if stats["new"] or stats["updated"] or not manifest.get("generated"):
        manifest["generated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    write_index(entries, out_dir / "INDEX.md")
    return stats


def write_index(entries: dict, path: Path) -> None:
    rows = sorted(entries.items(), key=lambda kv: kv[0])
    lines = ["# Datasheet index", "", f"{len(rows)} datasheets from {BASE}/resources/datasheets.", "",
             "| Datasheet | Published (Palo Alto) | File |", "|---|---|---|"]
    for name, e in rows:
        lines.append(f"| [{e['title']}]({e['page_url']}) | {e.get('last_updated') or 'n/a'} | [{name}]({name}) |")
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", default="sources.yaml")
    ap.add_argument("--out", default="datasheets")
    ap.add_argument("--manifest", default="manifest.json")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    cfg = load_sources(Path(a.sources))
    s = session()
    print("Discovering datasheet pages ...", flush=True)
    slugs = discover(s, cfg)
    print(f"{len(slugs)} datasheet pages: {', '.join(slugs)}", flush=True)
    if not slugs:
        print("ERROR: no datasheet pages found; the source pages may have changed.", file=sys.stderr)
        return 2

    infos = [page_info(s, slug) for slug in slugs]
    if a.list_only:
        for i in infos:
            print(f"  {i.get('last_updated') or '----------'}  {i['slug']:40} {i.get('title') or ''} {('ERROR ' + i['error']) if i.get('error') else ''}")
        return 0

    stats = sync(s, infos, Path(a.out), Path(a.manifest), force=a.force)
    print(f"Done: {len(stats['new'])} new, {len(stats['updated'])} updated, "
          f"{len(stats['unchanged'])} unchanged, {len(stats['failed'])} failed")
    ok = stats["new"] or stats["updated"] or stats["unchanged"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
