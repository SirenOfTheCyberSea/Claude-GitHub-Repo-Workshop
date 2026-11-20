"""Report exports: JSON, CSV (formula-injection safe), Markdown executive/technical summaries and a
STIX 2.1 bundle.

Markdown output escapes source text so untrusted feed content cannot inject links, images or HTML into
rendered reports, and indicators are always defanged.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from siren_threatwatch import __version__
from siren_threatwatch.db.base import secure_file, secure_mkdir
from siren_threatwatch.iocs.validation import IocType, defang
from siren_threatwatch.prioritization.scoring import SCORE_LABEL

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "|", "%")
# Characters that can create links/images/HTML/emphasis/tables/LaTeX in (Streamlit) Markdown.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]#!|<>~$:])")
STIX_NAMESPACE = uuid.UUID("6f1a7d6e-2b8f-4f53-9c1e-5a1c2d3e4f50")  # project-specific, for deterministic IDs
# Official STIX 2.1 TLP v1 marking-definition IDs (TLP:CLEAR maps to TLP:WHITE).
STIX_TLP_MARKINGS = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (CWE-1236) by prefixing risky cells with a quote."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def md_escape(value: Any) -> str:
    """Escape Markdown/HTML control characters in untrusted text."""
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", text)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, float) and pd.isna(value):
        return None
    if value is pd.NaT:
        return None
    return value


def records_from_df(df: pd.DataFrame) -> list[dict[str, Any]]:
    return [{k: _jsonable(v) for k, v in row.items()} for row in df.to_dict(orient="records")]


def to_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=_jsonable, ensure_ascii=False)


def to_csv(rows: Iterable[Mapping[str, Any]]) -> str:
    rows = list(rows)
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=list(rows[0].keys()), extrasaction="ignore", quoting=csv.QUOTE_MINIMAL
    )
    writer.writeheader()
    for row in rows:
        out = {}
        for k, v in row.items():
            if isinstance(v, (list, tuple)):
                v = "; ".join(str(x) for x in v)
            out[k] = sanitize_csv_cell(_jsonable(v))
        writer.writerow(out)
    return buf.getvalue()


@dataclass
class ReportData:
    title: str
    generated_at: datetime
    metrics: dict[str, Any]
    vulnerabilities: pd.DataFrame
    indicators: pd.DataFrame
    health: pd.DataFrame
    alerts: pd.DataFrame
    period_days: int = 30
    notes: list[str] = field(default_factory=list)
    intel: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_synthetic(self) -> bool:
        def any_syn(df: pd.DataFrame) -> bool:
            return bool(not df.empty and "is_synthetic" in df and df["is_synthetic"].any())

        return any_syn(self.vulnerabilities) or any_syn(self.indicators)


def _header(data: ReportData, kind: str) -> list[str]:
    lines = [
        f"# {md_escape(data.title)} — {kind}",
        "",
        f"_Generated {data.generated_at:%Y-%m-%d %H:%M} UTC by Siren ThreatWatch {__version__}. "
        f"Reporting window: {f'last {data.period_days} days' if data.period_days else 'all time'}._",
        "",
    ]
    if data.has_synthetic:
        lines += [
            "> **⚠ Contains SYNTHETIC DEMO DATA.** Records marked synthetic are fabricated and must not "
            "be used for decisions.",
            "",
        ]
    lines += [
        f"> Priority scores are a *{SCORE_LABEL.lower()}*. Exploitation claims are only made where a "
        "cited source (e.g. CISA KEV) states them.",
        "",
    ]
    return lines


def markdown_executive(data: ReportData, top_n: int = 10) -> str:
    m = data.metrics
    v = data.vulnerabilities
    lines = _header(data, "Executive Summary")
    lines += [
        "## Key figures",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Vulnerabilities tracked | {m.get('vulnerabilities', 0)} |",
        f"| In CISA KEV (known exploited, per CISA) | {m.get('kev', 0)} |",
        f"| Added to KEV in last 7 days | {m.get('kev_last_7d', 0)} |",
        f"| KEV entries with known ransomware use (per CISA) | {m.get('ransomware', 0)} |",
        f"| Records in Critical/High computed priority | {m.get('high_priority', 0)} |",
        f"| Open alerts | {m.get('open_alerts', 0)} |",
        "",
    ]
    lines += ["## Top priorities", ""]
    if v.empty:
        lines += ["_No vulnerabilities in scope._", ""]
    else:
        lines += ["| CVE | Vendor / Product | Priority | Why |", "|---|---|---|---|"]
        for row in v.head(top_n).to_dict(orient="records"):
            why = []
            if row.get("kev_listed"):
                why.append("CISA KEV")
            if row.get("kev_ransomware_use") == "Known":
                why.append("ransomware use (CISA)")
            if row.get("cvss_score") is not None and not pd.isna(row.get("cvss_score")):
                why.append(f"CVSS {row['cvss_score']:.1f}")
            syn = " (synthetic)" if row.get("is_synthetic") else ""
            score = row.get("priority_score")
            score_txt = (
                f"{score:.0f} {row.get('priority_band') or ''}"
                if score is not None and not pd.isna(score)
                else "n/a"
            )
            lines.append(
                f"| {md_escape(row['cve_id'])}{syn} | {md_escape(row.get('vendor'))} / "
                f"{md_escape(row.get('product'))} | {score_txt} | {md_escape(', '.join(why))} |"
            )
        lines.append("")
    lines += ["## Collection health", ""]
    if data.health.empty:
        lines += ["_No ingestion runs recorded._", ""]
    else:
        for h in data.health.to_dict(orient="records"):
            last_ok = _jsonable(h.get("last_success")) or "never"
            lines.append(
                f"- **{md_escape(h['source'])}**: last status `{h['last_status']}`, last success {last_ok}"
            )
        lines.append("")
    lines += [
        "## Recommended actions",
        "",
        "1. Confirm exposure of products listed under *Top priorities* and apply vendor remediation.",
        "2. Treat CISA KEV entries as exploited per CISA; follow the listed required action and due dates.",
        "3. Review open alerts and assign owners in the Watchlist & Alerts page.",
        "",
    ]
    lines += [f"- {md_escape(n)}" for n in data.notes]
    return "\n".join(lines).rstrip() + "\n"


def markdown_technical(data: ReportData, max_rows: int = 100) -> str:
    lines = _header(data, "Technical Summary")
    v = data.vulnerabilities
    lines += ["## Vulnerabilities", ""]
    if v.empty:
        lines += ["_None in scope._", ""]
    for row in v.head(max_rows).to_dict(orient="records"):
        syn = " — SYNTHETIC" if row.get("is_synthetic") else ""
        lines += [f"### {md_escape(row['cve_id'])}: {md_escape(row.get('title'))}{syn}", ""]
        lines.append(
            f"- **Vendor / product:** {md_escape(row.get('vendor'))} / {md_escape(row.get('product'))}"
        )
        cvss = row.get("cvss_score")
        if cvss is not None and not pd.isna(cvss):
            lines.append(
                f"- **CVSS {md_escape(row.get('cvss_version') or '')}:** {cvss} "
                f"{md_escape(row.get('cvss_severity') or '')} `{str(row.get('cvss_vector') or '').replace('`', '')}`"
            )
        else:
            lines.append("- **CVSS:** unavailable")
        if row.get("nvd_status"):
            lines.append(f"- **NVD status:** {md_escape(row['nvd_status'])}")
        products = row.get("affected_products") or []
        if products:
            more = f" (+{len(products) - 5} more)" if len(products) > 5 else ""
            lines.append(
                "- **Affected products (NVD CPE):** " + "; ".join(md_escape(p) for p in products[:5]) + more
            )
        if row.get("kev_listed"):
            lines.append(
                f"- **CISA KEV:** listed {_jsonable(row.get('kev_date_added'))}; due "
                f"{_jsonable(row.get('kev_due_date'))}; ransomware use: "
                f"{md_escape(row.get('kev_ransomware_use') or 'n/a')}"
            )
            if row.get("kev_required_action"):
                lines.append(f"- **Required action (CISA):** {md_escape(row['kev_required_action'])}")
        score = row.get("priority_score")
        if score is not None and not pd.isna(score):
            lines.append(f"- **Computed priority:** {score:.0f}/100 ({row.get('priority_band')})")
        lines.append(f"- **Analyst status:** {md_escape(row.get('status'))}")
        if row.get("description"):
            lines.append(f"- **Description:** {md_escape(row['description'])}")
        refs = row.get("references") or []
        if refs:
            lines.append("- **References (not visited by this tool):**")
            lines += [f"  - `{str(r).replace('`', '')}`" for r in refs[:10]]
        lines.append("")
    ind = data.indicators
    lines += ["## Indicators of compromise (defanged)", ""]
    if ind.empty:
        lines += ["_None in scope._", ""]
    else:
        lines += ["| Type | Indicator | Confidence | Last seen | Synthetic |", "|---|---|---|---|---|"]
        for row in ind.head(max_rows).to_dict(orient="records"):
            ioc = defang(row["value"], row["ioc_type"]).replace("|", "\\|").replace("`", "")
            lines.append(
                f"| {row['ioc_type']} | `{ioc}` | {row.get('confidence') or 'n/a'} | "
                f"{_jsonable(row.get('last_seen_at'))} | {'yes' if row.get('is_synthetic') else 'no'} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, f'{kind}:{key}')}"


def _stix_ts(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day, tzinfo=UTC)
    else:
        dt = datetime.now(UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    esc = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        IocType.IPV4.value: f"[ipv4-addr:value = '{esc}']",
        IocType.IPV6.value: f"[ipv6-addr:value = '{esc}']",
        IocType.DOMAIN.value: f"[domain-name:value = '{esc}']",
        IocType.URL.value: f"[url:value = '{esc}']",
        IocType.MD5.value: f"[file:hashes.MD5 = '{esc}']",
        IocType.SHA1.value: f"[file:hashes.'SHA-1' = '{esc}']",
        IocType.SHA256.value: f"[file:hashes.'SHA-256' = '{esc}']",
        IocType.SHA512.value: f"[file:hashes.'SHA-512' = '{esc}']",
    }.get(ioc_type)


STIX_INTEL_TYPES = {
    "threat-actor": "intrusion-set",
    "campaign": "campaign",
    "malware": "malware",
    "tool": "tool",
    "attack-pattern": "attack-pattern",
}


def to_stix_bundle(
    vulns: pd.DataFrame,
    indicators: pd.DataFrame,
    intel: list[dict[str, Any]] | None = None,
    relationships: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle with deterministic IDs: vulnerability and indicator SDOs, plus (optionally)
    intrusion-set / campaign / malware / tool / attack-pattern SDOs and relationship SROs between
    exported objects."""
    now = _stix_ts(datetime.now(UTC))
    identity_id = _stix_id("identity", "siren-threatwatch")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "Siren ThreatWatch (export)",
            "identity_class": "system",
        }
    ]
    for row in records_from_df(vulns) if not vulns.empty else []:
        refs = [{"source_name": "cve", "external_id": row["cve_id"]}]
        refs += [{"source_name": "reference", "url": u} for u in (row.get("references") or [])[:20]]
        labels = ["cisa-kev"] if row.get("kev_listed") else []
        if row.get("is_synthetic"):
            labels.append("synthetic-demo")
        obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": _stix_id("vulnerability", row["cve_id"]),
            "created": _stix_ts(row.get("first_seen_at")),
            "modified": now,
            "created_by_ref": identity_id,
            "name": row["cve_id"],
            "description": row.get("description") or row.get("title") or "",
            "external_references": refs,
        }
        if labels:
            obj["labels"] = labels
        objects.append(obj)
    for row in records_from_df(indicators) if not indicators.empty else []:
        pattern = _stix_pattern(row["ioc_type"], row["value"])
        if pattern is None:
            continue
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator", row["entity_key"]),
            "created": _stix_ts(row.get("first_seen_at")),
            "modified": now,
            "created_by_ref": identity_id,
            "name": f"{row['ioc_type']} indicator",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _stix_ts(row.get("first_seen_at")),
        }
        if row.get("description"):
            obj["description"] = row["description"]
        if row.get("confidence") is not None:
            obj["confidence"] = int(row["confidence"])
        if row.get("tlp") in STIX_TLP_MARKINGS:
            obj["object_marking_refs"] = [STIX_TLP_MARKINGS[row["tlp"]]]
        if row.get("is_synthetic"):
            obj["labels"] = ["synthetic-demo"]
        objects.append(obj)
    ids: dict[tuple[str, str], str] = {}
    for o in objects:
        if o["type"] == "vulnerability":
            ids[("vulnerability", o["name"])] = o["id"]
    for row in records_from_df(indicators) if not indicators.empty else []:
        ids[("indicator", row["entity_key"])] = _stix_id("indicator", row["entity_key"])
    for item in intel or []:
        stix_type = STIX_INTEL_TYPES.get(item["kind"])
        if stix_type is None:
            continue
        key = f"{item['kind']}:{item['key']}"
        obj = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": _stix_id(stix_type, key),
            "created": _stix_ts(item.get("first_seen_at")),
            "modified": now,
            "created_by_ref": identity_id,
            "name": item["name"],
        }
        if item.get("description"):
            obj["description"] = item["description"]
        if item.get("aliases") and stix_type in ("intrusion-set", "campaign", "malware", "tool"):
            obj["aliases"] = list(item["aliases"])
        if stix_type == "malware":
            obj["is_family"] = True
        url = (item.get("attributes") or {}).get("url")
        if item.get("external_id"):
            ref = {"source_name": "mitre-attack", "external_id": item["external_id"]}
            if url:
                ref["url"] = url
            obj["external_references"] = [ref]
        if item.get("is_synthetic"):
            obj["labels"] = ["synthetic-demo"]
        objects.append(obj)
        ids[("intel", key)] = obj["id"]
    for rel in relationships or []:
        src = ids.get((rel["src_kind"], rel["src_key"]))
        dst = ids.get((rel["dst_kind"], rel["dst_key"]))
        if not src or not dst:
            continue
        sro = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id(
                "relationship", f"{rel['src_key']}|{rel['rel_type']}|{rel['dst_key']}|{rel['source']}"
            ),
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "relationship_type": rel["rel_type"],
            "source_ref": src,
            "target_ref": dst,
        }
        if rel.get("description"):
            sro["description"] = rel["description"]
        if rel.get("evidence_url"):
            sro["external_references"] = [{"source_name": rel["source"], "url": rel["evidence_url"]}]
        objects.append(sro)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def write_export(content: str, path: Path) -> Path:
    """Write an export file with owner-only permissions."""
    secure_mkdir(path.parent)
    path.write_text(content, encoding="utf-8")
    secure_file(path)
    return path
