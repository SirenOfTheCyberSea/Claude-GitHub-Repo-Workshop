"""Normalise NVD CVE API 2.0 records.

Field paths follow NIST's published response schema
(https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema) and were checked against live responses:

* ``metrics.cvssMetricV40/V31/V30/V2[]`` each have ``source``, ``type`` (Primary/Secondary) and ``cvssData``
  (``baseScore``, ``vectorString``, ``version``; ``baseSeverity`` is inside ``cvssData`` for v3.x/v4.0 but at
  the metric level for v2). Other metric families (e.g. ``ssvcV203``) may lack ``type`` and are ignored here.
* ``weaknesses[].description[].value`` holds CWE IDs; ``configurations[].nodes[].cpeMatch[]`` holds
  ``criteria`` / ``vulnerable`` / version-range fields.
* ``published`` / ``lastModified`` carry no timezone. NVD's own response ``timestamp`` matches current UTC,
  so these are interpreted as UTC.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from siren_threatwatch.normalization.schema import (
    CvssMetric,
    EntityKind,
    NormalizedRecord,
    VulnerabilityData,
)

NVD_SOURCE = "nvd"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
NVD_CONFIDENCE = 85
# Preference when choosing the single "headline" CVSS score used for prioritisation.
METRIC_FAMILIES: tuple[tuple[str, str], ...] = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)
_CPE_SPLIT = re.compile(r"(?<!\\):")
_CWE = re.compile(r"^(CWE-\d+|NVD-CWE-[A-Za-z]+)$")


def parse_nvd_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def extract_metrics(cve: dict[str, Any]) -> list[CvssMetric]:
    raw_metrics = cve.get("metrics")
    metrics: dict[str, Any] = raw_metrics if isinstance(raw_metrics, dict) else {}
    out: list[CvssMetric] = []
    for family, default_version in METRIC_FAMILIES:
        for m in metrics.get(family) or []:
            if not isinstance(m, dict) or not isinstance(m.get("cvssData"), dict):
                continue
            data = m["cvssData"]
            score = data.get("baseScore")
            if not isinstance(score, (int, float)):
                continue
            out.append(
                CvssMetric(
                    version=str(data.get("version") or default_version),
                    source=m.get("source"),
                    type=m.get("type"),
                    base_score=float(score),
                    base_severity=data.get("baseSeverity") or m.get("baseSeverity"),  # v2: metric level
                    vector=data.get("vectorString"),
                )
            )
    return out


def headline_metric(metrics: list[CvssMetric]) -> CvssMetric | None:
    """Prefer newer v3.x, then v4.0, then v2; within a version prefer NVD's Primary assessment."""
    if not metrics:
        return None
    order = {v: i for i, (_, v) in enumerate(METRIC_FAMILIES)}

    def key(m: CvssMetric) -> tuple[int, int, int]:
        return (
            order.get(m.version, 99),
            0 if m.type == "Primary" else 1,
            0 if m.source == "nvd@nist.gov" else 1,
        )

    return sorted(metrics, key=key)[0]


def parse_cpe(criteria: str) -> dict[str, str] | None:
    """Split a CPE 2.3 formatted string (``cpe:2.3:part:vendor:product:version:...``)."""
    parts = _CPE_SPLIT.split(criteria)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    unescape = lambda v: v.replace("\\", "")  # noqa: E731
    return {
        "part": parts[2],
        "vendor": unescape(parts[3]),
        "product": unescape(parts[4]),
        "version": unescape(parts[5]),
    }


def _range_text(match: dict[str, Any]) -> str:
    bounds = []
    for key, op in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        if match.get(key):
            bounds.append(f"{op}{match[key]}")
    return " ".join(bounds)


def affected_products(cve: dict[str, Any], limit: int = 200) -> list[str]:
    """Human-readable 'vendor product version-range' strings for CPE matches NVD marks vulnerable."""
    out: list[str] = []
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable") or not match.get("criteria"):
                    continue
                cpe = parse_cpe(str(match["criteria"]))
                if cpe is None:
                    continue
                version = cpe["version"] if cpe["version"] not in ("*", "-", "") else ""
                text = " ".join(x for x in (cpe["vendor"], cpe["product"], version, _range_text(match)) if x)
                if text not in out:
                    out.append(text)
                if len(out) >= limit:
                    return out
    return out


def _first_vendor_product(cve: dict[str, Any]) -> tuple[str | None, str | None]:
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("vulnerable") and match.get("criteria"):
                    cpe = parse_cpe(str(match["criteria"]))
                    if cpe:
                        return cpe["vendor"].replace("_", " "), cpe["product"].replace("_", " ")
    return None, None


def english_description(cve: dict[str, Any]) -> str | None:
    descs = [d for d in cve.get("descriptions") or [] if isinstance(d, dict)]
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            return str(d["value"])
    return str(descs[0]["value"]) if descs and descs[0].get("value") else None


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    out = set()
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            value = str((d or {}).get("value", "")).strip()
            if _CWE.match(value):
                out.add(value)
    return sorted(out)


def normalize_nvd_item(item: dict[str, Any]) -> NormalizedRecord:
    """Convert one ``vulnerabilities[]`` element (``{"cve": {...}}``). Raises ``ValueError`` if invalid."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        raise ValueError("NVD item has no cve.id")
    metrics = extract_metrics(cve)
    head = headline_metric(metrics)
    vendor, product = _first_vendor_product(cve)
    published = parse_nvd_datetime(cve.get("published"))
    modified = parse_nvd_datetime(cve.get("lastModified"))
    description = english_description(cve)
    refs = [str(r["url"]) for r in cve.get("references") or [] if isinstance(r, dict) and r.get("url")]
    cve_id = cve["id"].strip().upper()
    vuln = VulnerabilityData(
        cve_id=cve_id,
        description=description,
        vendor=vendor,
        product=product,
        cwes=extract_cwes(cve),
        cvss_score=head.base_score if head else None,
        cvss_vector=head.vector if head else None,
        cvss_version=head.version if head else None,
        cvss_severity=(head.base_severity or None) if head else None,
        cvss_metrics=metrics,
        affected_products=affected_products(cve),
        nvd_status=cve.get("vulnStatus"),
        nvd_last_modified=modified,
        references=refs,
    )
    return NormalizedRecord(
        source=NVD_SOURCE,
        entity_kind=EntityKind.VULNERABILITY,
        external_id=cve_id,
        title=f"{cve_id} ({cve.get('vulnStatus') or 'NVD'})",
        description=description,
        source_url=NVD_DETAIL_URL.format(cve=cve_id),
        published_at=published,
        observed_at=modified,
        confidence=NVD_CONFIDENCE,
        tlp=None,  # NVD does not supply TLP markings
        raw_payload=item,
        vulnerability=vuln,
    )
