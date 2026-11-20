"""Normalise CISA KEV catalogue entries.

Schema verified against the official feed / cisagov/kev-data (fields: cveID, vendorProject, product,
vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
notes, cwes; newer catalogues add fields such as forensicTriage, which are kept in the raw payload).
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from siren_threatwatch.normalization.schema import (
    EntityKind,
    NormalizedRecord,
    VulnerabilityData,
)

KEV_SOURCE = "cisa_kev"
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
KEV_CONFIDENCE = 90  # CISA requires reliable evidence of active exploitation before listing.
_URL_IN_TEXT = re.compile(r"https?://[^\s;,<>\"']+")


class KevCatalog(BaseModel):
    """Envelope of the KEV JSON feed. Individual entries stay as dicts and are validated one by one."""

    model_config = ConfigDict(extra="allow")
    title: str | None = None
    catalogVersion: str | None = None
    dateReleased: datetime | None = None
    count: int | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)


def _parse_date(value: Any) -> date | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _as_datetime(value: date | None) -> datetime | None:
    return datetime.combine(value, time.min, tzinfo=UTC) if value else None


def extract_urls(text: str | None) -> list[str]:
    if not text:
        return []
    return [u.rstrip(".)") for u in _URL_IN_TEXT.findall(text)]


def normalize_kev_entry(item: dict[str, Any], catalog_released: datetime | None = None) -> NormalizedRecord:
    """Convert one KEV entry into a :class:`NormalizedRecord`. Raises ``ValueError`` if invalid."""
    if not isinstance(item, dict):
        raise ValueError("KEV entry is not an object")
    cve = item.get("cveID")
    if not isinstance(cve, str):
        raise ValueError("KEV entry has no cveID")
    date_added = _parse_date(item.get("dateAdded"))
    ransomware = item.get("knownRansomwareCampaignUse")
    ransomware = ransomware if ransomware in ("Known", "Unknown") else None
    notes = item.get("notes") if isinstance(item.get("notes"), str) else None
    raw_cwes = item.get("cwes")
    cwes: list[Any] = raw_cwes if isinstance(raw_cwes, list) else []
    references = extract_urls(notes)
    cve_upper = cve.strip().upper()
    references.append(f"https://nvd.nist.gov/vuln/detail/{cve_upper}")

    vuln = VulnerabilityData(
        cve_id=cve,
        title=item.get("vulnerabilityName"),
        description=item.get("shortDescription"),
        vendor=item.get("vendorProject"),
        product=item.get("product"),
        cwes=[c for c in cwes if isinstance(c, str)],
        kev_listed=True,
        kev_date_added=date_added,
        kev_due_date=_parse_date(item.get("dueDate")),
        kev_required_action=item.get("requiredAction"),
        kev_ransomware_use=ransomware,
        kev_notes=notes,
        references=references,
    )
    return NormalizedRecord(
        source=KEV_SOURCE,
        entity_kind=EntityKind.VULNERABILITY,
        external_id=vuln.cve_id,
        title=item.get("vulnerabilityName") or vuln.cve_id,
        description=item.get("shortDescription"),
        source_url=KEV_CATALOG_URL,
        published_at=_as_datetime(date_added),
        observed_at=catalog_released,
        confidence=KEV_CONFIDENCE,
        tlp=None,  # KEV does not supply a TLP marking (it is public, CC0-licensed data).
        raw_payload=item,
        vulnerability=vuln,
    )
