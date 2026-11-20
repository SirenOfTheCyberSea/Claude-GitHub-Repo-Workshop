# 🛡️ Siren ThreatWatch

**A defensive Cyber Threat Intelligence (CTI) platform.** It collects public threat intelligence,
normalises and de-duplicates it, prioritises it with explainable scoring, and lets you search, track
and report on it in a local Streamlit dashboard.

No paid services. No API key needed to get started.

![Overview](docs/screenshots/overview.png)

> **Status: Phase 1 (vertical slice).** CISA KEV collection, the full data model, scoring,
> watchlists, alerts, reports and all nine dashboard pages are working. NVD, MITRE ATT&CK, abuse.ch,
> OTX and RSS connectors are **planned, not yet implemented**. They appear as "Planned" in Settings.
> See [Roadmap](#roadmap).

---

## What it does

- **Collects** the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog from CISA's official feed. If that is unreachable it falls back to CISA's official GitHub
  mirror, [`cisagov/kev-data`](https://github.com/cisagov/kev-data).
- **Normalises** every record: source URL, publication, observation and ingestion times, external ID,
  confidence, TLP when supplied, and a reference to the raw payload.
- **De-duplicates** CVEs, indicators and actors **without discarding attribution**. Each source's
  statement is kept as an *observation*, with sightings and change history.
- **Prioritises** with transparent, additive factors: KEV status, ransomware use, CVSS, recency, due
  dates, source confidence and your own keywords or watchlist. Missing data is shown explicitly. A
  score is always labelled *"computed priority — not evidence of exploitation"*.
- **Analyst workflow**: status (New → Investigating → Monitoring → Mitigated → Closed), analyst
  priority, tags, notes and watchlists.
- **Alerts** on new high-priority records, CVEs newly added to KEV and material changes to watched
  items. Alerts are de-duplicated, and the first import doesn't flood you.
- **Exports** executive and technical Markdown summaries, JSON, CSV (formula-injection safe) and STIX
  2.1 bundles.
- **Validates IOCs** (IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256/SHA-512), accepts defanged input and
  always displays indicators defanged.

## Quick start (Windows, macOS, Linux)

You need **Python 3.12 or newer** ([download](https://www.python.org/downloads/); on Windows tick
*"Add python.exe to PATH"*) and **git**.

### 1. Get the code

```bash
git clone https://github.com/SirenOfTheCyberSea/Claude-GitHub-Repo-Workshop.git
```

```bash
cd Claude-GitHub-Repo-Workshop
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it. On **macOS / Linux**:

```bash
source .venv/bin/activate
```

On **Windows (PowerShell)**:

```powershell
.venv\Scripts\Activate.ps1
```

(If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
On Windows `cmd.exe`, use `.venv\Scripts\activate.bat` instead.)

### 3. Install

```bash
pip install -e .
```

### 4. (Optional) Configure

Settings come from environment variables or a `.env` file. The defaults work without one. To
customise, copy the example on macOS / Linux:

```bash
cp .env.example .env
```

On Windows:

```powershell
copy .env.example .env
```

### 5. Collect CISA KEV

```bash
siren ingest --source cisa_kev
```

You should see something like:

```
[ SUCCESS] cisa_kev: fetched=1786 new=1786 updated=0 unchanged=0 rejected=0 alerts=1  via https://www.cisa.gov/...
```

### 6. Open the dashboard

```bash
siren dashboard
```

Then browse to **<http://127.0.0.1:8501>**. Use the **CVE Explorer** to search and filter, open a CVE
to see its cited sources and priority explanation, and use **Reports** to download a summary.

> No internet access, or behind a strict proxy? Download the KEV JSON in a browser from
> `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, then import
> it with `siren ingest --source cisa_kev --from-file known_exploited_vulnerabilities.json`.

### Want sample data to explore?

```bash
siren seed-demo
```

This loads a small **synthetic** dataset: fictional actors, campaigns, malware, indicators in
documentation IP ranges, and CVE IDs in the non-existent year 2099. Every synthetic record is labelled
**SYNTHETIC DEMO** throughout the UI and reports. Remove it with:

```bash
siren purge-demo
```

## CLI reference

| Command | Purpose |
|---|---|
| `siren init` | Create or migrate the database |
| `siren ingest [--source cisa_kev\|synthetic_demo\|all] [--from-file PATH]` | Collect intelligence |
| `siren sources` | Configured sources, credential status (set/not set only) and health |
| `siren score [--explain CVE-ID] [--top N]` | Recompute priorities; show a factor-by-factor explanation |
| `siren alerts [--all] [--ack ID ...]` | List or acknowledge alerts |
| `siren export --format md-executive\|md-technical\|json\|csv\|stix [--days N] [--kev-only] [--exclude-synthetic] [--out PATH\|-]` | Export a report |
| `siren schedule` | Run recurring ingestion (interval from `SIREN_SCHEDULE_INTERVAL_MINUTES`) |
| `siren seed-demo` / `siren purge-demo` | Load or remove synthetic demo data |
| `siren dashboard [--port 8501]` | Launch the dashboard on 127.0.0.1 |

`python -m siren_threatwatch <command>` works too.

## Dashboard pages

| Page | What you get |
|---|---|
| **Overview** | Key metrics, highest computed priorities, newest KEV additions, actor/campaign highlights, ingestion health |
| **Threat Feed** | Searchable, filterable cards, each with its source citation, timestamps, confidence and TLP |
| **CVE Explorer** | Filters (KEV, ransomware, band, vendor, status, date); detail tabs for exploitation signals, remediation references, priority explanation, provenance, history and analyst workflow |
| **IOC Explorer** | Defanged indicators, sightings, confidence, relationships, plus an offline indicator validator |
| **Threat Actors & Campaigns** | Evidence-backed profiles, aliases, ATT&CK mappings and source-cited relationships |
| **Trends & Analytics** | KEV additions over time (by ransomware use), observations by source, vendor and priority distributions |
| **Watchlist & Alerts** | Watch CVEs, indicators or vendor/product keywords; review and acknowledge alerts |
| **Reports** | Configure, preview, download or save exports |
| **Settings** | Sources and status, credential status, ingest now, schedule, sync history, security posture |

Dark (navy, burgundy and teal) is the default theme. A light theme is available from the ⋮ menu →
Settings.

## How prioritisation works

Each CVE's score is the sum of named factors, capped at 100:

| Factor | Points | Evidence type |
|---|---|---|
| Listed in CISA KEV | 35 | source-reported |
| CISA: known ransomware use | 15 | source-reported |
| CVSS base score (scaled) | 0–30 | computed (missing until NVD enrichment) |
| EPSS (scaled) | 0–10 | computed (missing: integration planned) |
| Published or added ≤30 days / ≤90 days | 10 / 5 | computed |
| CISA due date within 14 days or passed | 5 | source-reported |
| Matches your keywords or watchlist | 15 | analyst |
| Source confidence (scaled) | 0–5 | computed |

Bands: **Critical ≥80**, **High ≥60**, **Medium ≥40**, **Low ≥15**, otherwise Informational. Run
`siren score --explain CVE-…` or open the *Priority explanation* tab to see the breakdown. Until
NVD enrichment arrives (Phase 2), real KEV entries have no CVSS input. Their scores top out around 70,
and "CVSS severity" is listed as missing.

## Configuration

See [`.env.example`](.env.example). The most useful settings:

| Variable | Default | Meaning |
|---|---|---|
| `SIREN_DATABASE_URL` | `sqlite:///data/siren.db` | SQLite by default. PostgreSQL: `postgresql+psycopg://user:pass@host/db` (run `pip install -e ".[postgres]"`) |
| `SIREN_ORG_RELEVANT_KEYWORDS` | *(empty)* | Comma-separated vendors/products that matter to you |
| `SIREN_ALERT_MIN_SCORE` | `60` | Threshold for "new high-priority" alerts |
| `SIREN_SCHEDULE_INTERVAL_MINUTES` | `360` | `siren schedule` interval |
| `SIREN_HTTP_*` | see file | Timeouts, retries, response size, concurrency |
| `NVD_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY` | *(empty)* | For future connectors; never logged or displayed |

## Security

This is a **passive, defensive** tool. It never runs exploits, downloads malware, scans hosts, or
visits or resolves reported indicators. Highlights:

- Outbound requests are limited to allowlisted HTTPS hosts, with every redirect re-validated, plus
  timeouts, retries with backoff, size limits, bounded concurrency and caching.
- Feed content is treated as untrusted. It is validated by Pydantic and HTML/Markdown-escaped when
  displayed, and indicators are defanged.
- CSV exports are protected against formula injection. Data files get owner-only permissions.
- Secrets come only from environment variables or `.env`, and are redacted from logs.

### Network exposure

The dashboard listens on **127.0.0.1 only** and **has no built-in authentication**. If you need
remote access, don't simply bind it to `0.0.0.0`. Instead, put it behind a reverse proxy that
provides **TLS** and **authentication** (for example Caddy or nginx with oauth2-proxy / SSO), and
restrict access to trusted networks or a VPN. Full details are in [SECURITY.md](SECURITY.md).

## Development

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

```bash
ruff check src tests
```

```bash
ruff format --check src tests
```

```bash
mypy
```

- All external APIs are **mocked** in tests (`respx`). The suite makes no network calls.
- GitHub Actions (`.github/workflows/ci.yml`) runs lint, type checks and tests on Linux, Windows and
  macOS with Python 3.12 and 3.13.
- Architecture notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Sample outputs (synthetic data):
  [docs/sample_reports/](docs/sample_reports/). Screenshot guide: [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md).

## Project layout

```
src/siren_threatwatch/
  config.py · logging_config.py · cli.py · queries.py
  connectors/      safe HTTP client, CISA KEV, synthetic demo, source catalogue
  normalization/   Pydantic schema, KEV mapping
  iocs/            IOC validation / refang / defang
  ingestion/       pipeline + scheduler
  db/              models, repository (dedup/merge), migrations runner
  migrations/      Alembic scripts
  prioritization/  explainable scoring
  alerts/          alert rules + dedup
  reporting/       Markdown / JSON / CSV / STIX exporters
  dashboard/       Streamlit app, theme, safe components, views/
  demo/            synthetic_dataset.json
tests/unit · tests/integration · tests/fixtures
```

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffold, config, DB and migrations, CISA KEV, normalisation, scoring, alerts, reports, dashboard, tests, CI | ✅ Done |
| 2 | NVD CVE API 2.0 (CVSS, CPE, rate limits, optional key), MITRE ATT&CK STIX, entity relationships | Planned |
| 3 | abuse.ch URLhaus / ThreatFox (Auth-Key), AlienVault OTX (API key), curated RSS allowlist | Planned |
| 4 | EPSS (official FIRST API), richer correlation, notification channels, UI enhancements | Planned |
| 5 | Hardening review, authentication guidance and examples, release packaging | Planned |

Each new integration will be implemented against its official documentation. Integrations that need
credentials stay disabled until those are configured.

## Data sources & licensing

- CISA KEV is published under CC0 1.0 ([license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)).
  Its presence in KEV means *CISA* reports exploitation; this tool repeats that claim only with
  attribution.
- The demo dataset is entirely fictional and marked synthetic.
- Code license: MIT (see `pyproject.toml`).
