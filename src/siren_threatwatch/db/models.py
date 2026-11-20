"""SQLAlchemy ORM models.

Design notes
------------
* **Provenance is stored separately from canonical entities.** ``RawRecord`` keeps the untouched
  source payload; ``Observation`` keeps each source's normalised statement about an entity
  (with source URL, publication/observation/ingestion times, confidence and TLP); canonical
  tables (``Vulnerability``, ``Indicator``, ``IntelObject``) hold the de-duplicated merged view.
* Entities are referenced polymorphically by ``(entity_kind, entity_key)`` — e.g.
  ``("vulnerability", "CVE-2024-1234")`` or ``("indicator", "domain:example.com")``.
* All timestamps are timezone-aware UTC (works on SQLite and PostgreSQL).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores datetimes as UTC and always returns timezone-aware values."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: UTCDateTime, dict[str, Any]: JSON, list[Any]: JSON}


# Entity kinds
VULNERABILITY = "vulnerability"
INDICATOR = "indicator"
INTEL = "intel"
ENTITY_KINDS = (VULNERABILITY, INDICATOR, INTEL)

ANALYST_STATUSES = ("New", "Investigating", "Monitoring", "Mitigated", "Closed")


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    # running | success | not_modified | partial | failed | skipped
    status: Mapped[str] = mapped_column(String(20), default="running")
    fetched_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    http_status: Mapped[int | None] = mapped_column(Integer, default=None)
    records_fetched: Mapped[int] = mapped_column(Integer, default=0)
    records_new: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    records_unchanged: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)


class RawRecord(Base):
    """Untouched source payload (untrusted). De-duplicated by content hash per source."""

    __tablename__ = "raw_records"
    __table_args__ = (UniqueConstraint("source", "content_hash", name="uq_raw_source_hash"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    external_id: Mapped[str] = mapped_column(String(512), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column()
    source_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    first_fetched_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_fetched_at: Mapped[datetime] = mapped_column(default=utcnow)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_runs.id"), default=None)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str | None] = mapped_column(String(500), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    vendor: Mapped[str | None] = mapped_column(String(200), default=None, index=True)
    product: Mapped[str | None] = mapped_column(String(300), default=None)
    cwes: Mapped[list[Any]] = mapped_column(default=list)
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), default=None)
    cvss_version: Mapped[str | None] = mapped_column(String(10), default=None)
    cvss_severity: Mapped[str | None] = mapped_column(String(20), default=None)
    epss_score: Mapped[float | None] = mapped_column(Float, default=None)
    epss_percentile: Mapped[float | None] = mapped_column(Float, default=None)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, default=None, index=True)
    kev_due_date: Mapped[date | None] = mapped_column(Date, default=None)
    kev_required_action: Mapped[str | None] = mapped_column(Text, default=None)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(20), default=None)
    kev_notes: Mapped[str | None] = mapped_column(Text, default=None)
    references: Mapped[list[Any]] = mapped_column(default=list)
    # NVD enrichment (Phase 2)
    cvss_metrics: Mapped[list[Any]] = mapped_column(
        default=list
    )  # every CVSS metric NVD lists, all versions/sources
    affected_products: Mapped[list[Any]] = mapped_column(
        default=list
    )  # vulnerable CPE match criteria (+ ranges)
    nvd_status: Mapped[str | None] = mapped_column(String(40), default=None)
    nvd_last_modified: Mapped[datetime | None] = mapped_column(default=None)
    # Which source supplied each canonical field ({"cvss_score": "nvd", "vendor": "cisa_kev", ...})
    field_sources: Mapped[dict[str, Any]] = mapped_column(default=dict)
    published_at: Mapped[datetime | None] = mapped_column(default=None)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("ioc_type", "value", name="uq_indicator_type_value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(20), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    original_value: Mapped[str] = mapped_column(String(2048))
    is_routable: Mapped[bool | None] = mapped_column(Boolean, default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    confidence: Mapped[int | None] = mapped_column(Integer, default=None)
    tlp: Mapped[str | None] = mapped_column(String(20), default=None)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def entity_key(self) -> str:
        return f"{self.ioc_type}:{self.value}"


class IntelObject(Base):
    """Threat actors, campaigns, malware families, ATT&CK techniques."""

    __tablename__ = "intel_objects"
    __table_args__ = (UniqueConstraint("kind", "key", name="uq_intel_kind_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    # threat-actor | campaign | malware | tool | attack-pattern
    kind: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(300))
    aliases: Mapped[list[Any]] = mapped_column(default=list)
    external_id: Mapped[str | None] = mapped_column(String(64), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    # Source-specific structured facts, e.g. ATT&CK tactics/platforms/domains, reference URL
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def entity_key(self) -> str:
        return f"{self.kind}:{self.key}"


class SyncState(Base):
    """Per-source cursors (e.g. NVD last successful sync time, ATT&CK release version)."""

    __tablename__ = "sync_state"
    __table_args__ = (UniqueConstraint("source", "key", name="uq_sync_state"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str | None] = mapped_column(Text, default=None)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class Observation(Base):
    """A source's (normalised) statement about an entity — the historical sighting record."""

    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("source", "entity_kind", "entity_key", "content_hash", name="uq_observation"),
        Index("ix_observation_entity", "entity_kind", "entity_key"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    entity_kind: Mapped[str] = mapped_column(String(20))
    entity_key: Mapped[str] = mapped_column(String(2100))
    external_id: Mapped[str] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    source_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    published_at: Mapped[datetime | None] = mapped_column(default=None, index=True)
    observed_at: Mapped[datetime | None] = mapped_column(default=None)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1)
    confidence: Mapped[int | None] = mapped_column(Integer, default=None)
    tlp: Mapped[str | None] = mapped_column(String(20), default=None)
    content_hash: Mapped[str] = mapped_column(String(64))
    raw_record_id: Mapped[int | None] = mapped_column(ForeignKey("raw_records.id"), default=None)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_runs.id"), default=None)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class Relationship(Base):
    """An explicit, source-evidenced link between two entities."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "src_kind", "src_key", "rel_type", "dst_kind", "dst_key", "source", name="uq_relationship"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    src_kind: Mapped[str] = mapped_column(String(20))
    src_key: Mapped[str] = mapped_column(String(2100), index=True)
    rel_type: Mapped[str] = mapped_column(String(50))
    dst_kind: Mapped[str] = mapped_column(String(20))
    dst_key: Mapped[str] = mapped_column(String(2100), index=True)
    source: Mapped[str] = mapped_column(String(64))
    evidence_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    confidence: Mapped[int | None] = mapped_column(Integer, default=None)
    raw_record_id: Mapped[int | None] = mapped_column(ForeignKey("raw_records.id"), default=None)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class ChangeEvent(Base):
    __tablename__ = "change_events"
    __table_args__ = (Index("ix_change_entity", "entity_kind", "entity_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(20))
    entity_key: Mapped[str] = mapped_column(String(2100))
    field: Mapped[str] = mapped_column(String(64))
    old_value: Mapped[str | None] = mapped_column(Text, default=None)
    new_value: Mapped[str | None] = mapped_column(Text, default=None)
    source: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_runs.id"), default=None)
    changed_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class AnalystState(Base):
    __tablename__ = "analyst_states"
    __table_args__ = (UniqueConstraint("entity_kind", "entity_key", name="uq_analyst_entity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(20))
    entity_key: Mapped[str] = mapped_column(String(2100))
    status: Mapped[str] = mapped_column(String(20), default="New")
    priority_override: Mapped[str | None] = mapped_column(String(20), default=None)
    tags: Mapped[list[Any]] = mapped_column(default=list)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class WatchlistEntry(Base):
    __tablename__ = "watchlist"
    __table_args__ = (UniqueConstraint("entity_kind", "value", name="uq_watchlist"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    # vulnerability | indicator | intel | keyword
    entity_kind: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(2100))
    label: Mapped[str | None] = mapped_column(String(200), default=None)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(300), unique=True)
    alert_type: Mapped[str] = mapped_column(String(40), index=True)
    entity_kind: Mapped[str] = mapped_column(String(20))
    entity_key: Mapped[str] = mapped_column(String(2100))
    title: Mapped[str] = mapped_column(String(500))
    detail: Mapped[str | None] = mapped_column(Text, default=None)
    severity: Mapped[str] = mapped_column(String(20), default="Medium")
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(default=None)


class PriorityScore(Base):
    __tablename__ = "priority_scores"
    __table_args__ = (UniqueConstraint("entity_kind", "entity_key", name="uq_priority_entity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(20))
    entity_key: Mapped[str] = mapped_column(String(2100))
    score: Mapped[float] = mapped_column(Float, index=True)
    band: Mapped[str] = mapped_column(String(20))
    factors: Mapped[list[Any]] = mapped_column(default=list)
    missing: Mapped[list[Any]] = mapped_column(default=list)
    computed_at: Mapped[datetime] = mapped_column(default=utcnow)
