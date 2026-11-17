# palo-ds-grabber

Keeps a current local library of Palo Alto Networks firewall datasheets (PA-Series hardware, VM-Series and the Product Summary Specsheet), pulled from Palo Alto's public resources at <https://www.paloaltonetworks.com/resources/datasheets>.

The full library has over 500 datasheets across every Palo Alto product, so instead of paging through it, pa-grabber reads the pages listed in `sources.yaml` (the PA-Series hardware architecture page and the firewall product pages), collects their links to datasheet pages, and keeps only firewall datasheets.

## What you get

```
datasheets/
  pa-400-series.pdf
  pa-1400-series.pdf
  ...
  INDEX.md        # title, Palo Alto's published date, file link
  _archive/       # previous versions, renamed with their old date
manifest.json     # page URL, PDF URL, published date, sha256, size, download time
```

## Run it locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python pa_grabber.py --list-only    # preview
python pa_grabber.py                # download
```

## How it works

1. **Discover:** collect `/resources/datasheets/<slug>` links from the pages in `sources.yaml`, filtered by its include/exclude rules, plus any `extra_slugs`.
2. **Check:** read each datasheet page's title and published date. If the date hasn't changed and the PDF is present, skip it.
3. **Download:** try Palo Alto's download handler, then the PDF's asset path. A changed PDF replaces the old one, which moves to `datasheets/_archive/`.

To add a datasheet the crawl misses, put its slug (the last part of its `/resources/datasheets/...` URL) under `extra_slugs` in `sources.yaml`.

## GitHub Actions

`.github/workflows/grab.yml` runs every Monday and commits any changes. Run it by hand from the **Actions** tab, optionally forcing a full re-download.
