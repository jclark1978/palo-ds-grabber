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

**Legacy models.** End-of-sale models aren't linked from the current product pages, so the grabber also reads Palo Alto's [Hardware End-of-Life Dates](https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates) page. Its Resources column links each model's datasheet page (PA-220, PA-3200, PA-5200, PA-7000, ...) or, for the oldest models, a PDF file directly (PA-500, PA-2000, PA-4000). The few old specsheets no page links to any more (PA-200, PA-3000, PA-5000) are listed under `extra_pdfs` in `sources.yaml`. Direct PDFs have no published date; they're downloaded once and marked `"legacy": true` in `manifest.json` (`--force` re-checks them).

To add a datasheet the crawl misses, put its slug (the last part of its `/resources/datasheets/...` URL) under `extra_slugs` in `sources.yaml`.

## JSON specs

`pa_normalize.py` reads the downloaded datasheets and writes the spec tables as JSON, in the same layout as [ds-grabber](https://github.com/jclark1978/ds-grabber):

```
data/
  models.json          every model, one file
  models/PA-1410.json  one small file per model
  index.json           model ids, codes to match user input, file paths, PAN-OS, spec URLs
  models.csv           main comparison fields, one row per model
reports/
  extraction.txt       per-datasheet counts and problems
  unmapped_labels.txt  labels labels.yaml doesn't map yet
  crosscheck.txt       series datasheets vs the Product Summary Specsheet
```

```bash
python pa_normalize.py --check
```

Each record has `specs` (throughput in Mbps, sessions, connections per second, virtual systems), `hardware` (interfaces, power, BTU, rack units, dimensions in mm, weight in kg, plus every hardware row as printed under `hardware.raw`), `test_conditions` and `source` (PDF URL with `#page=N` for the spec table).

**Test conditions travel with every value.** Palo Alto numbers depend on the PAN-OS release and the test traffic, so each spec carries `pan_os` and `test_conditions` (the datasheet footnotes that apply to it). Chassis models (PA-5450, PA-7500, PA-7050/7080) also keep single-card numbers under `per_card`, a list of `{card, specs}`. These figures are not like-for-like with other vendors' datasheets.

Notes:

- **Primary source:** the per-series datasheets. The Product Summary Specsheet is only used for `reports/crosscheck.txt`, which lists where the two documents disagree (usually different PAN-OS releases or a stale summary).
- **Legacy models:** records have `legacy: true` (also in `index.json` and `models.csv`) when the datasheet came only from the EOL page. Those datasheets can be years old, so check `test_conditions.pan_os`:
  - 2022-2024 datasheets (PA-220, PA-220R, PA-800, PA-3200, PA-5200, PA-7000) use the current appmix tests. PA-220/220R/800 print "HTTP/appmix" pairs; the appmix number is the value and the HTTP number is kept as `http_value`.
  - 2013-2018 specsheets (PA-200, PA-500, PA-2000/3000/4000/5000) measure "App-ID enabled" firewall throughput under "ideal testing conditions" on PAN-OS 5.0/6.0. That goes in `fw_throughput_appid_mbps`, never in the appmix field. They also publish capacities the new sheets don't (`firewall_policies`, `ipsec_tunnels`, `ssl_vpn_users`, `ssl_decrypt_sessions`, `virtual_routers`, `security_zones`). The PA-500 sheet states no PAN-OS release.
  - Skip legacy models when picking a current competitor match; use them when someone names one (a refresh).
- **VM-Series:** the VM-Series datasheet has no spec tables (Palo Alto publishes VM numbers in a web tool), so there are no VM records.
- **Name fixes:** `labels.yaml` `model_aliases` maps alternate spellings to one model id (for example the PA-50R performance table prints `PA-54R-POE-5G` where every other table says `PA-54R-POE`). Records keep `printed_as` when the name was changed.
- **New wording:** a label that `labels.yaml` doesn't recognize is kept and listed in `reports/unmapped_labels.txt`, so nothing is dropped silently.

## GitHub Actions

`.github/workflows/grab.yml` runs every Monday, downloads changed datasheets, rebuilds the JSON, and commits any changes. Run it by hand from the **Actions** tab, optionally forcing a full re-download.
