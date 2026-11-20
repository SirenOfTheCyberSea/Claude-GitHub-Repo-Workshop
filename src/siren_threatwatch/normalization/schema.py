"""Pydantic v2 schema for normalised intelligence records.

Every connector converts its untrusted source payload into :class:`NormalizedRecord` objects.
Validation here is the trust boundary: text is cleaned of control characters and length-capped,
URLs must be http(s), identifiers are canonicalised.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from siren_threatwatch.iocs.validation import IocType, validate_indicator

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TEXT = 20_000
MAX_TITLE = 500


class EntityKind(StrEnum):
    VULNERABILITY = "vulnerability"
    INDICATOR = "indicator"
    INTEL = "intel"


class TLP(StrEnum):
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


_TLP_ALIASES = {
    "WHITE": TLP.CLEAR,
    "CLEAR": TLP.CLEAR,
    "GREEN": TLP.GREEN,
    "AMBER": TLP.AMBER,
    "AMBER+STRICT": TLP.AMBER_STRICT,
    "RED": TLP.RED,
}


def parse_tlp(value: str | None) -> TLP | None:
    if not value:
        return None
    key = value.strip().upper().removeprefix("TLP:").removeprefix("TLP ").strip()
    return _TLP_ALIASES.get(key)


def clean_text(value: Any, limit: int = MAX_TEXT) -> str | None:
    """Strip control characters, collapse surrounding whitespace and cap length. Not HTML-escaped:
    escaping happens at render time so stored evidence stays faithful."""
    if value is None:
        return None
    text = _CTRL.sub("", str(value)).strip()
    if not text:
        return None
    return text[:limit]


def safe_http_url(value: str | None) -> str | None:
    """Return the URL if it is a syntactically valid http(s) URL, else ``None``."""
    if not value:
        return None
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or any(c in value for c in "\r\n\t <>\"'"):
        return None
    return value[:2048]


_TRACKING_PARAMS = re.compile(r"^(utm_.*|fbclid|gclid|mc_cid|mc_eid|ref|ref_src)$", re.I)


def canonical_article_url(url: str) -> str:
    """Canonicalise an article URL for de-duplication (lower-case host, drop fragment/tracking)."""
    parts = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not _TRACKING_PARAMS.match(k)])
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), (parts.hostname or "").lower(), path, query, ""))


def canonical_cve(value: str) -> str:
    cve = value.strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"invalid CVE identifier: {value!r}")
    return cve


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")[:200]


def content_hash(data: Any) -> str:
    """Stable SHA-256 of JSON-serialisable data (keys sorted)."""
    blob = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class VulnerabilityData(_Strict):
    cve_id: str
    title: str | None = None
    description: str | None = None
    vendor: str | None = None
    product: str | None = None
    cwes: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cvss_severity: str | None = None
    kev_listed: bool | None = None
    kev_date_added: date | None = None
    kev_due_date: date | None = None
    kev_required_action: str | None = None
    kev_ransomware_use: Literal["Known", "Unknown"] | None = None
    kev_notes: str | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def _cve(cls, v: str) -> str:
        return canonical_cve(v)

    @field_validator("title", "vendor", "product", "cvss_vector", "cvss_severity")
    @classmethod
    def _short(cls, v: str | None) -> str | None:
        return clean_text(v, 500)

    @field_validator("description", "kev_required_action", "kev_notes")
    @classmethod
    def _long(cls, v: str | None) -> str | None:
        return clean_text(v)

    @field_validator("cwes")
    @classmethod
    def _cwes(cls, v: list[str]) -> list[str]:
        return sorted({c.strip().upper() for c in v if re.match(r"^\s*(CWE-\d+|NVD-CWE-[A-Za-z]+)\s*$", c)})

    @field_validator("references")
    @classmethod
    def _refs(cls, v: list[str]) -> list[str]:
        seen: list[str] = []
        for ref in v:
            url = safe_http_url(ref)
            if url and url not in seen:
                seen.append(url)
        return seen[:100]


class IndicatorData(_Strict):
    ioc_type: IocType
    value: str
    original_value: str
    is_routable: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate(cls, data: Any) -> Any:
        if isinstance(data, dict) and "value" in data:
            validated = validate_indicator(data.get("original_value") or data["value"], data.get("ioc_type"))
            return {
                "ioc_type": validated.ioc_type,
                "value": validated.value,
                "original_value": validated.original,
                "is_routable": validated.is_routable,
            }
        return data

    @property
    def entity_key(self) -> str:
        return f"{self.ioc_type.value}:{self.value}"


IntelKind = Literal["threat-actor", "campaign", "malware", "attack-pattern"]


class IntelObjectData(_Strict):
    kind: IntelKind
    name: str
    aliases: list[str] = Field(default_factory=list)
    external_id: str | None = None
    description: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        cleaned = clean_text(v, 300)
        if not cleaned:
            raise ValueError("name is required")
        return cleaned

    @field_validator("aliases")
    @classmethod
    def _aliases(cls, v: list[str]) -> list[str]:
        return sorted({a for a in (clean_text(x, 300) for x in v) if a})

    @field_validator("description")
    @classmethod
    def _desc(cls, v: str | None) -> str | None:
        return clean_text(v)

    @property
    def key(self) -> str:
        return slugify(self.name)

    @property
    def entity_key(self) -> str:
        return f"{self.kind}:{self.key}"


class RelationshipData(_Strict):
    rel_type: str  # e.g. "exploits", "uses", "attributed-to", "indicates", "related-to"
    dst_kind: EntityKind
    dst_key: str
    description: str | None = None
    evidence_url: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)

    @field_validator("evidence_url")
    @classmethod
    def _evidence_url(cls, v: str | None) -> str | None:
        return safe_http_url(v)


class NormalizedRecord(_Strict):
    """One source observation about one entity."""

    source: str
    entity_kind: EntityKind
    external_id: str
    title: str
    description: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    observed_at: datetime | None = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    confidence: int | None = Field(default=None, ge=0, le=100)
    tlp: TLP | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict, repr=False)
    is_synthetic: bool = False

    vulnerability: VulnerabilityData | None = None
    indicator: IndicatorData | None = None
    intel: IntelObjectData | None = None
    relationships: list[RelationshipData] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        return clean_text(v, MAX_TITLE) or "(untitled)"

    @field_validator("description")
    @classmethod
    def _desc(cls, v: str | None) -> str | None:
        return clean_text(v)

    @field_validator("external_id")
    @classmethod
    def _ext(cls, v: str) -> str:
        cleaned = clean_text(v, 512)
        if not cleaned:
            raise ValueError("external_id is required")
        return cleaned

    @field_validator("source_url")
    @classmethod
    def _source_url(cls, v: str | None) -> str | None:
        return safe_http_url(v)

    @field_validator("published_at", "observed_at", "ingested_at")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v)

    @field_validator("tlp", mode="before")
    @classmethod
    def _tlp(cls, v: Any) -> Any:
        return parse_tlp(v) if isinstance(v, str) else v

    @model_validator(mode="after")
    def _payload_matches_kind(self) -> NormalizedRecord:
        expected = {
            EntityKind.VULNERABILITY: self.vulnerability,
            EntityKind.INDICATOR: self.indicator,
            EntityKind.INTEL: self.intel,
        }[self.entity_kind]
        if expected is None:
            raise ValueError(f"{self.entity_kind.value} record requires its matching data block")
        return self

    @property
    def entity_key(self) -> str:
        if self.vulnerability:
            return self.vulnerability.cve_id
        if self.indicator:
            return self.indicator.entity_key
        assert self.intel is not None
        return self.intel.entity_key

    @property
    def raw_hash(self) -> str:
        return content_hash(self.raw_payload)

    def observation_hash(self) -> str:
        """Hash of the normalised content (ignores ingestion time) — changes mean the source changed."""
        return content_hash(
            self.model_dump(mode="json", exclude={"ingested_at", "raw_payload", "is_synthetic"})
        )
