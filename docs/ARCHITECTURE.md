# Architecture

```
            ┌──────────────── connectors/ ────────────────┐
 Sources →  │ SafeHttpClient (allowlist, retries, limits) │  → untrusted payload
            │ CisaKev · Nvd · MitreAttack · SyntheticDemo │
            └──────────────────────┬──────────────────────┘
                                   ▼
           normalization/ (Pydantic v2: NormalizedRecord, KEV mapper, IOC validation)
                                   ▼
           db/repository.Persister ──► raw_records    (verbatim payload, by content hash)
                                   ──► observations   (per-source statement + citation + timestamps)
                                   ──► vulnerabilities / indicators / intel_objects (canonical, de-duplicated)
                                   ──► relationships  (source-evidenced only)
                                   ──► change_events  (field-level history)
                                   ▼
           prioritization/ (explainable factors) ──► priority_scores
                                   ▼
           alerts/ (dedup keys, baseline suppression, watchlist) ──► alerts
                                   ▼
           queries.py ──► dashboard/ (Streamlit) · reporting/ (MD/JSON/CSV/STIX) · cli.py
```

## Packages

| Package | Responsibility |
|---|---|
| `config.py`, `logging_config.py` | Environment-based settings, secret handling, structured logging with redaction |
| `connectors/` | `BaseConnector`, the safe HTTP client, the CISA KEV and demo connectors, and the source catalogue |
| `normalization/` | The canonical record schema, text and URL sanitisation, and the KEV mapping |
| `iocs/` | IOC type detection, validation, canonicalisation, refang and defang |
| `ingestion/` | The pipeline (fetch → persist → score → alert → run health) and the APScheduler job |
| `db/` | ORM models, engine and permissions, Alembic migrations, persistence and de-duplication |
| `prioritization/` | Pure scoring functions and the service that persists scores |
| `alerts/` | Pure alert-candidate logic and deduplicated persistence |
| `reporting/` | Exporters and the report builder |
| `dashboard/` | The Streamlit app, theme, safe rendering components and nine views |

Correlation is limited to explicit, source-stated relationships (`relationships` table). This covers
ATT&CK `uses`, `attributed-to` and `subtechnique-of`, plus CVE IDs named in ATT&CK descriptions,
recorded as `mentions`. Phase 3 adds abuse.ch, OTX and RSS connectors into the same pipeline. Each
connector only needs to produce `NormalizedRecord` objects.

## Merging and provenance

- `Vulnerability.field_sources` records which source set each field. `FIELD_PRECEDENCE` in
  `db/repository.py` decides who may overwrite what (NVD owns CVSS/CPE/description; CISA owns KEV
  fields and vendor/product naming).
- Intel objects from a different source merge into an existing object when a name or alias matches
  exactly one existing object. Objects from the same source are never merged.
- ATT&CK techniques are keyed by ATT&CK ID (`attack-pattern:t1566-001`), because technique names are
  not unique.
- `sync_state` stores per-source cursors: the ATT&CK release version per domain and the last
  successful sync.

## Source verification notes

| Source | How the integration was verified |
|---|---|
| CISA KEV | Field layout checked against the live feed and `cisagov/kev-data` |
| NVD | NIST's published response schema plus live API responses. Server-confirmed limits: 2000 results per page, 120-day date windows, start+end dates required together, `hasKev`/`noRejected` flags, errors as HTTP 404 with a `message` header. The documented rate limits and the `apiKey` header name could not be re-read from the build environment, so request pacing is conservative and configurable. |
| MITRE ATT&CK | Official `attack-stix-data` README, `index.json` and the Enterprise v20.1 bundle |

## Data model keys

Entities are referenced as `(entity_kind, entity_key)`:

- `("vulnerability", "CVE-2024-1234")`
- `("indicator", "domain:example.com")`, `("indicator", "url:http://example.com/a")`
- `("intel", "threat-actor:demo-tidecaller")`, `("intel", "attack-pattern:t1566")`

## Migrations

Alembic scripts live in `src/siren_threatwatch/migrations/`. `siren init` applies them
programmatically. To change the schema, edit `db/models.py`, then run:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

`tests/integration/test_migrations_and_cli.py` fails if models and migrations diverge.
