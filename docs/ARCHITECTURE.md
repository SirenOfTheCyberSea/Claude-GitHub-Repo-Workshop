# Architecture

```
            ┌──────────────── connectors/ ────────────────┐
 Sources →  │ SafeHttpClient (allowlist, retries, limits) │  → untrusted payload
            │ CisaKevConnector · SyntheticDemoConnector   │
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

Correlation in Phase 1 is limited to explicit, source-stated relationships (`relationships` table).
Later phases add NVD (CVSS, CPE), MITRE ATT&CK, abuse.ch, OTX and RSS connectors into the same
pipeline. Each connector only needs to produce `NormalizedRecord` objects.

## Data model keys

Entities are referenced as `(entity_kind, entity_key)`:

- `("vulnerability", "CVE-2024-1234")`
- `("indicator", "domain:example.com")`, `("indicator", "url:http://example.com/a")`
- `("intel", "threat-actor:demo-tidecaller")`, `("intel", "attack-pattern:phishing")`

## Migrations

Alembic scripts live in `src/siren_threatwatch/migrations/`. `siren init` applies them
programmatically. To change the schema, edit `db/models.py`, then run:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

`tests/integration/test_migrations_and_cli.py` fails if models and migrations diverge.
