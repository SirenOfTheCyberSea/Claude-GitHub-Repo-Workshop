# Security Policy & Design

Siren ThreatWatch is a **defensive, passive** intelligence tool. This document describes its security
controls, their limits and how to report a vulnerability.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Advisories → "Report a vulnerability")
rather than a public issue. Don't include live credentials or real victim data in reports.

## Scope of behaviour

| The tool does | The tool never does |
|---|---|
| Downloads published feeds from allowlisted HTTPS hosts | Execute exploits or attack automation |
| Parses and stores feed content as untrusted data | Download malware samples |
| Validates and defangs indicators | Visit, resolve, ping or scan reported indicators or URLs |
| Correlates entities only where a source states the link | Infer attribution from shared infrastructure |

## Controls

**Outbound requests (SSRF and abuse)** — `src/siren_threatwatch/connectors/http.py`
- HTTPS only, with an explicit per-connector host allowlist: `www.cisa.gov` and
  `raw.githubusercontent.com` (KEV mirror, ATT&CK), and `services.nvd.nist.gov`. URLs found inside
  feed data, such as ATT&CK's release index, are checked against the same allowlist before they are
  requested. IP-literal hosts, URL user-info and
  non-443 ports are refused.
- Redirects are followed manually. Each hop is re-validated against the allowlist and the number of
  hops is bounded.
- Timeouts, a maximum response size (streamed and aborted early), bounded concurrency and a per-run
  request budget.
- Retries with exponential backoff and jitter for transport errors, HTTP 429 and 5xx. `Retry-After` is
  honoured, capped at 120 s.
- ETag / Last-Modified caching to avoid needless load on providers. ATT&CK downloads are skipped when
  the release version is unchanged. NVD requests are paced (6 s apart without a key) and capped per
  run.
- Feed URLs set in `.env` are validated against the allowlist at startup.

**Untrusted content**
- Pydantic models are the trust boundary: control characters are stripped, lengths are capped, URLs
  must be http(s), and identifiers are canonicalised. Invalid records are rejected and counted, not
  silently stored.
- The dashboard HTML-escapes every dynamic value, and Markdown output escapes link, image and HTML
  syntax. Without this, injected `![](url)` would make browsers fetch attacker-chosen URLs.
- Only validated http(s) reference URLs become links, with `rel="noopener noreferrer nofollow"`.
  Indicators are always shown **defanged** and never linked.
- CSV exports prefix cells starting with `= + - @ | %`, tab or CR with `'` (CWE-1236).

**Secrets**
- The NVD API key is sent only in a request header, never in the URL, so it can't leak into logs or
  error messages that include URLs.
- Secrets are read only from environment variables or `.env`, which is git-ignored, and held as
  `SecretStr`. The UI and CLI show only *whether* a credential is set.
- A logging filter redacts configured secret values and `key=value`-style tokens. httpx request
  logging is reduced to WARNING.

**Local storage**
- The data directory is created `0700`; the database, cache and export files are `0600` (best effort
  on Windows, where NTFS ACLs apply).

**Dashboard exposure**
- Binds to `127.0.0.1` by default (`.streamlit/config.toml`, `siren dashboard`). `siren dashboard`
  refuses non-localhost hosts unless `--i-understand-the-risk` is given.
- XSRF protection is enabled; usage statistics are disabled.
- **The dashboard has no authentication.** Before exposing it beyond localhost, put it behind a
  reverse proxy (nginx, Caddy or Traefik) that terminates **TLS** and enforces **authentication**
  (OIDC/SSO via e.g. oauth2-proxy, or at minimum HTTP basic auth over TLS). Restrict it to trusted
  networks or a VPN.

## Known limitations

- Feed providers are trusted for availability, not for content correctness. A compromised feed could
  inject false records; provenance is kept so they can be traced and purged.
- Synthetic demo records can never modify real records. Real data replaces synthetic placeholders.
- Priority scores are heuristics, labelled everywhere as "computed priority — not evidence of
  exploitation".
