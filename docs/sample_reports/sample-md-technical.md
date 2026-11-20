# Siren ThreatWatch Report — Technical Summary

_Generated 2026-11-20 01:42 UTC by Siren ThreatWatch 0.1.0. Reporting window: all time._

> **⚠ Contains SYNTHETIC DEMO DATA.** Records marked synthetic are fabricated and must not be used for decisions.

> Priority scores are a *computed priority — a triage aid, not evidence of exploitation*. Exploitation claims are only made where a cited source (e.g. CISA KEV) states them.

## Vulnerabilities

### CVE-2099-0003: DemoCorp VPN Concentrator command injection — SYNTHETIC

- **Vendor / product:** DemoCorp / VPN Concentrator
- **CVSS:** 8.8
- **CISA KEV:** listed 2026-10-26; due 2026-11-16; ransomware use: Known
- **Required action (CISA):** Apply vendor mitigations (synthetic).
- **Computed priority:** 95/100 (Critical)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Command injection via crafted request parameters.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0003`

### CVE-2099-0001: DemoCorp Edge Gateway authentication bypass — SYNTHETIC

- **Vendor / product:** DemoCorp / Edge Gateway
- **CVSS:** 9.8
- **CISA KEV:** listed 2026-11-17; due 2026-12-08; ransomware use: Known
- **Required action (CISA):** Apply vendor mitigations (synthetic).
- **Computed priority:** 93/100 (Critical)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Authentication bypass in the management interface allows remote unauthenticated access.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0001`

### CVE-2099-0002: ExampleSoft FileShare Pro path traversal — SYNTHETIC

- **Vendor / product:** ExampleSoft / FileShare Pro
- **CVSS:** 7.5
- **CISA KEV:** listed 2026-11-08; due 2026-11-29; ransomware use: Unknown
- **Required action (CISA):** Apply vendor mitigations (synthetic).
- **Computed priority:** 76/100 (High)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Path traversal permits reading arbitrary files.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0002`

### CVE-2099-0005: ExampleSoft Office Suite memory corruption — SYNTHETIC

- **Vendor / product:** ExampleSoft / Office Suite
- **CVSS:** 7.8
- **CISA KEV:** listed 2026-10-03; due 2026-10-24; ransomware use: Unknown
- **Required action (CISA):** Apply vendor mitigations (synthetic).
- **Computed priority:** 72/100 (High)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Memory corruption when opening crafted documents.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0005`

### CVE-2099-0004: Placeholder Mail Relay SSRF — SYNTHETIC

- **Vendor / product:** Placeholder Systems / Mail Relay
- **CVSS:** 6.5
- **Computed priority:** 33/100 (Low)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Server-side request forgery in webhook handler.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0004`

### CVE-2099-0008: Fictional Cloud Identity Portal XSS — SYNTHETIC

- **Vendor / product:** Fictional Cloud / Identity Portal
- **CVSS:** 5.4
- **Computed priority:** 30/100 (Low)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Stored cross-site scripting in profile fields.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0008`

### CVE-2099-0007: DemoCorp Endpoint Agent privilege escalation — SYNTHETIC

- **Vendor / product:** DemoCorp / Endpoint Agent
- **CVSS:** 7.0
- **Computed priority:** 30/100 (Low)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Local privilege escalation through insecure service permissions.
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0007`

### CVE-2099-0006: Sample Networks Router OS hard-coded credentials — SYNTHETIC

- **Vendor / product:** Sample Networks / Router OS
- **CVSS:** unavailable
- **Computed priority:** 14/100 (Informational)
- **Analyst status:** New
- **Description:** \[SYNTHETIC DEMO DATA — not real intelligence\] Hard-coded maintenance credentials (CVSS not yet published).
- **References (not visited by this tool):**
  - `https://example.com/advisories/cve-2099-0006`

## Indicators of compromise (defanged)

| Type | Indicator | Confidence | Last seen | Synthetic |
|---|---|---|---|---|
| domain | `update-check[.]example[.]com` | 75 | 2026-11-19T01:42:11.380322+00:00 | yes |
| url | `hxxp[://]update-check[.]example[.]com/payload/stage2` | 80 | 2026-11-19T01:42:11.380322+00:00 | yes |
| ipv4 | `192[.]0[.]2[.]15` | 80 | 2026-11-18T01:42:11.380322+00:00 | yes |
| sha256 | `491d109a65eba57028cc44bf96524b9d81d2d10695d17f5fb1bf25b160a0faac` | 85 | 2026-11-18T01:42:11.380322+00:00 | yes |
| domain | `login-portal[.]example[.]net` | 70 | 2026-11-17T01:42:11.380322+00:00 | yes |
| url | `hxxps[://]login-portal[.]example[.]net/owa/auth?id=demo` | 70 | 2026-11-17T01:42:11.380322+00:00 | yes |
| ipv6 | `2001[:]db8[:][:]bad[:]1` | 55 | 2026-11-16T01:42:11.380322+00:00 | yes |
| ipv4 | `198[.]51[.]100[.]23` | 65 | 2026-11-15T01:42:11.380322+00:00 | yes |
| sha256 | `3166440dfe96eca68e1844f06409ec52f1698730bc2ea8d55483abee19f88e57` | 60 | 2026-11-12T01:42:11.380322+00:00 | yes |
| ipv4 | `203[.]0[.]113[.]77` | 50 | 2026-11-11T01:42:11.380322+00:00 | yes |
| domain | `cdn-sync[.]example[.]org` | 45 | 2026-11-06T01:42:11.380322+00:00 | yes |
| url | `hxxps[://]cdn-sync[.]example[.]org/js/lib.js` | 45 | 2026-11-06T01:42:11.380322+00:00 | yes |
| ipv4 | `10[.]20[.]30[.]40` | 30 | 2026-10-31T01:42:11.380322+00:00 | yes |
| domain | `files[.]invalid-demo[.]test` | 40 | 2026-10-21T01:42:11.380322+00:00 | yes |
| sha1 | `dbffe20992f99d10be623e52ebdd3b869eb230d7` | 40 | 2026-10-11T01:42:11.380322+00:00 | yes |
| md5 | `6d80c69464fd0abc56321b89cf5ec2af` | 35 | 2026-09-21T01:42:11.380322+00:00 | yes |
