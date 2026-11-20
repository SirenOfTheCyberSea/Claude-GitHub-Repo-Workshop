"""Read-side query helpers shared by the dashboard, CLI and report generators."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd
from sqlalchemy import ColumnElement, and_, delete, desc, func, or_, select
from sqlalchemy.orm import Session

from siren_threatwatch.db.models import (
    INDICATOR,
    INTEL,
    VULNERABILITY,
    Alert,
    AnalystState,
    ChangeEvent,
    Indicator,
    IngestionRun,
    IntelObject,
    Observation,
    PriorityScore,
    RawRecord,
    Relationship,
    Source,
    Vulnerability,
    WatchlistEntry,
)


@dataclass
class VulnFilter:
    text: str | None = None
    kev_only: bool = False
    ransomware_only: bool = False
    bands: list[str] | None = None
    vendors: list[str] | None = None
    statuses: list[str] | None = None
    added_within_days: int | None = None
    include_synthetic: bool = True
    limit: int = 5000


def vulnerabilities_df(session: Session, flt: VulnFilter | None = None) -> pd.DataFrame:
    flt = flt or VulnFilter()
    stmt = (
        select(Vulnerability, PriorityScore.score, PriorityScore.band, AnalystState.status, AnalystState.tags)
        .outerjoin(
            PriorityScore,
            and_(
                PriorityScore.entity_kind == VULNERABILITY, PriorityScore.entity_key == Vulnerability.cve_id
            ),
        )
        .outerjoin(
            AnalystState,
            and_(AnalystState.entity_kind == VULNERABILITY, AnalystState.entity_key == Vulnerability.cve_id),
        )
    )
    if flt.text:
        like = f"%{flt.text.strip()}%"
        stmt = stmt.where(
            or_(
                Vulnerability.cve_id.ilike(like),
                Vulnerability.title.ilike(like),
                Vulnerability.vendor.ilike(like),
                Vulnerability.product.ilike(like),
                Vulnerability.description.ilike(like),
            )
        )
    if flt.kev_only:
        stmt = stmt.where(Vulnerability.kev_listed.is_(True))
    if flt.ransomware_only:
        stmt = stmt.where(Vulnerability.kev_ransomware_use == "Known")
    if flt.bands:
        stmt = stmt.where(PriorityScore.band.in_(flt.bands))
    if flt.vendors:
        stmt = stmt.where(Vulnerability.vendor.in_(flt.vendors))
    if flt.statuses:
        cond: ColumnElement[bool] = AnalystState.status.in_(flt.statuses)
        if "New" in flt.statuses:
            cond = or_(cond, AnalystState.status.is_(None))
        stmt = stmt.where(cond)
    if flt.added_within_days:
        cutoff = (datetime.now(UTC) - timedelta(days=flt.added_within_days)).date()
        stmt = stmt.where(
            or_(
                Vulnerability.kev_date_added >= cutoff,
                Vulnerability.first_seen_at >= datetime.now(UTC) - timedelta(days=flt.added_within_days),
            )
        )
    if not flt.include_synthetic:
        stmt = stmt.where(Vulnerability.is_synthetic.is_(False))
    stmt = stmt.order_by(desc(PriorityScore.score), desc(Vulnerability.kev_date_added)).limit(flt.limit)
    rows = []
    for v, score, band, status, tags in session.execute(stmt):
        rows.append(
            {
                "cve_id": v.cve_id,
                "title": v.title,
                "vendor": v.vendor,
                "product": v.product,
                "description": v.description,
                "cvss_score": v.cvss_score,
                "cvss_severity": v.cvss_severity,
                "kev_listed": v.kev_listed,
                "kev_date_added": v.kev_date_added,
                "kev_due_date": v.kev_due_date,
                "kev_ransomware_use": v.kev_ransomware_use,
                "kev_required_action": v.kev_required_action,
                "cwes": ", ".join(v.cwes or []),
                "references": v.references or [],
                "priority_score": score,
                "priority_band": band,
                "status": status or "New",
                "tags": tags or [],
                "first_seen_at": v.first_seen_at,
                "is_synthetic": v.is_synthetic,
                "cvss_version": v.cvss_version,
                "cvss_vector": v.cvss_vector,
                "cvss_metrics": v.cvss_metrics or [],
                "affected_products": v.affected_products or [],
                "nvd_status": v.nvd_status,
                "nvd_last_modified": v.nvd_last_modified,
                "published_at": v.published_at,
                "field_sources": v.field_sources or {},
            }
        )
    return pd.DataFrame(rows)


def indicators_df(
    session: Session,
    text: str | None = None,
    types: list[str] | None = None,
    min_confidence: int = 0,
    include_synthetic: bool = True,
) -> pd.DataFrame:
    stmt = select(Indicator, PriorityScore.score, PriorityScore.band).outerjoin(
        PriorityScore,
        and_(
            PriorityScore.entity_kind == INDICATOR,
            PriorityScore.entity_key == Indicator.ioc_type + ":" + Indicator.value,
        ),
    )
    if text:
        like = f"%{text.strip()}%"
        stmt = stmt.where(
            or_(
                Indicator.value.ilike(like),
                Indicator.original_value.ilike(like),
                Indicator.description.ilike(like),
            )
        )
    if types:
        stmt = stmt.where(Indicator.ioc_type.in_(types))
    if min_confidence:
        stmt = stmt.where(func.coalesce(Indicator.confidence, 0) >= min_confidence)
    if not include_synthetic:
        stmt = stmt.where(Indicator.is_synthetic.is_(False))
    sightings = dict(
        session.execute(
            select(Observation.entity_key, func.sum(Observation.sighting_count))
            .where(Observation.entity_kind == INDICATOR)
            .group_by(Observation.entity_key)
        ).all()
    )
    rows = []
    for i, score, band in session.execute(stmt.order_by(desc(Indicator.last_seen_at))):
        rows.append(
            {
                "entity_key": i.entity_key,
                "ioc_type": i.ioc_type,
                "value": i.value,
                "original_value": i.original_value,
                "confidence": i.confidence,
                "tlp": i.tlp,
                "is_routable": i.is_routable,
                "description": i.description,
                "first_seen_at": i.first_seen_at,
                "last_seen_at": i.last_seen_at,
                "sightings": int(sightings.get(i.entity_key, 0) or 0),
                "priority_score": score,
                "priority_band": band,
                "is_synthetic": i.is_synthetic,
            }
        )
    return pd.DataFrame(rows)


def intel_objects(session: Session, kind: str | None = None) -> list[IntelObject]:
    stmt = select(IntelObject).order_by(IntelObject.kind, IntelObject.name)
    if kind:
        stmt = stmt.where(IntelObject.kind == kind)
    return list(session.scalars(stmt))


def relationships_for(session: Session, kind: str, key: str) -> list[Relationship]:
    stmt = (
        select(Relationship)
        .where(
            or_(
                and_(Relationship.src_kind == kind, Relationship.src_key == key),
                and_(Relationship.dst_kind == kind, Relationship.dst_key == key),
            )
        )
        .order_by(Relationship.rel_type)
    )
    return list(session.scalars(stmt))


def observations_for(session: Session, kind: str, key: str) -> list[Observation]:
    stmt = select(Observation).where(Observation.entity_kind == kind, Observation.entity_key == key)
    return list(session.scalars(stmt.order_by(desc(Observation.ingested_at))))


def changes_for(session: Session, kind: str, key: str) -> list[ChangeEvent]:
    stmt = select(ChangeEvent).where(ChangeEvent.entity_kind == kind, ChangeEvent.entity_key == key)
    return list(session.scalars(stmt.order_by(desc(ChangeEvent.changed_at))))


def priority_for(session: Session, kind: str, key: str) -> PriorityScore | None:
    return session.scalar(
        select(PriorityScore).where(PriorityScore.entity_kind == kind, PriorityScore.entity_key == key)
    )


def analyst_state(session: Session, kind: str, key: str) -> AnalystState | None:
    return session.scalar(
        select(AnalystState).where(AnalystState.entity_kind == kind, AnalystState.entity_key == key)
    )


def save_analyst_state(
    session: Session,
    kind: str,
    key: str,
    *,
    status: str,
    tags: list[str],
    notes: str | None,
    priority_override: str | None,
) -> AnalystState:
    row = analyst_state(session, kind, key)
    if row is None:
        row = AnalystState(entity_kind=kind, entity_key=key)
        session.add(row)
    row.status = status
    row.tags = sorted({t.strip()[:50] for t in tags if t.strip()})[:30]
    row.notes = (notes or "")[:10_000] or None
    row.priority_override = priority_override
    row.updated_at = datetime.now(UTC)
    session.flush()
    return row


def feed_df(
    session: Session,
    text: str | None = None,
    sources: list[str] | None = None,
    kinds: list[str] | None = None,
    days: int | None = None,
    limit: int = 300,
) -> pd.DataFrame:
    stmt = select(Observation)
    if text:
        like = f"%{text.strip()}%"
        stmt = stmt.where(
            or_(
                Observation.title.ilike(like),
                Observation.description.ilike(like),
                Observation.entity_key.ilike(like),
            )
        )
    if sources:
        stmt = stmt.where(Observation.source.in_(sources))
    if kinds:
        stmt = stmt.where(Observation.entity_kind.in_(kinds))
    if days:
        stmt = stmt.where(
            func.coalesce(Observation.published_at, Observation.ingested_at)
            >= datetime.now(UTC) - timedelta(days=days)
        )
    stmt = stmt.order_by(desc(func.coalesce(Observation.published_at, Observation.ingested_at))).limit(limit)
    rows = [
        {
            "source": o.source,
            "entity_kind": o.entity_kind,
            "entity_key": o.entity_key,
            "title": o.title,
            "description": o.description,
            "source_url": o.source_url,
            "published_at": o.published_at,
            "observed_at": o.observed_at,
            "ingested_at": o.ingested_at,
            "confidence": o.confidence,
            "tlp": o.tlp,
            "sighting_count": o.sighting_count,
            "is_synthetic": o.is_synthetic,
        }
        for o in session.scalars(stmt)
    ]
    return pd.DataFrame(rows)


def observations_timeseries(session: Session, days: int = 90) -> pd.DataFrame:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    stmt = select(
        Observation.source, Observation.entity_kind, Observation.published_at, Observation.ingested_at
    )
    rows = [
        {"source": s, "entity_kind": k, "date": (p or i)}
        for s, k, p, i in session.execute(stmt)
        if (p or i) and (p or i) >= cutoff
    ]
    df = pd.DataFrame(rows, columns=["source", "entity_kind", "date"])
    if not df.empty:
        df["date"] = pd.to_datetime(df["date"], utc=True).dt.tz_convert(None).dt.normalize()
    return df


def kev_additions_timeseries(session: Session, days: int = 365) -> pd.DataFrame:
    cutoff = (datetime.now(UTC) - timedelta(days=days)).date()
    stmt = select(Vulnerability.kev_date_added, Vulnerability.kev_ransomware_use).where(
        Vulnerability.kev_date_added.is_not(None), Vulnerability.kev_date_added >= cutoff
    )
    df = pd.DataFrame(session.execute(stmt).all(), columns=["date", "ransomware"])
    if not df.empty:
        df["date"] = pd.to_datetime(df["date"])
    return df


def source_health(session: Session) -> pd.DataFrame:
    rows = []
    names = [s.name for s in session.scalars(select(Source).order_by(Source.name))]
    for name in names:
        runs = list(
            session.scalars(
                select(IngestionRun)
                .where(IngestionRun.source == name)
                .order_by(desc(IngestionRun.started_at))
                .limit(20)
            )
        )
        if not runs:
            continue
        last = runs[0]
        last_ok = next((r for r in runs if r.status in ("success", "partial")), None)
        consecutive_failures = 0
        for r in runs:
            if r.status != "failed":
                break
            consecutive_failures += 1
        rows.append(
            {
                "source": name,
                "last_status": last.status,
                "last_run": last.started_at,
                "last_success": last_ok.finished_at if last_ok else None,
                "consecutive_failures": consecutive_failures,
                "records_fetched": last.records_fetched,
                "new": last.records_new,
                "updated": last.records_updated,
                "rejected": last.records_rejected,
                "last_error": last.error,
                "endpoint": last.fetched_url,
            }
        )
    return pd.DataFrame(rows)


def ingestion_runs_df(session: Session, limit: int = 100) -> pd.DataFrame:
    runs = session.scalars(select(IngestionRun).order_by(desc(IngestionRun.started_at)).limit(limit))
    return pd.DataFrame(
        [
            {
                "id": r.id,
                "source": r.source,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "fetched": r.records_fetched,
                "new": r.records_new,
                "updated": r.records_updated,
                "unchanged": r.records_unchanged,
                "rejected": r.records_rejected,
                "alerts": r.alerts_created,
                "endpoint": r.fetched_url,
                "http_status": r.http_status,
                "error": r.error,
            }
            for r in runs
        ]
    )


def alerts_df(session: Session, include_acknowledged: bool = False, limit: int = 500) -> pd.DataFrame:
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if not include_acknowledged:
        stmt = stmt.where(Alert.acknowledged.is_(False))
    return pd.DataFrame(
        [
            {
                "id": a.id,
                "created_at": a.created_at,
                "severity": a.severity,
                "alert_type": a.alert_type,
                "title": a.title,
                "detail": a.detail,
                "entity_kind": a.entity_kind,
                "entity_key": a.entity_key,
                "acknowledged": a.acknowledged,
            }
            for a in session.scalars(stmt)
        ]
    )


def acknowledge_alerts(session: Session, ids: list[int]) -> int:
    count = 0
    for alert in session.scalars(select(Alert).where(Alert.id.in_(ids))):
        if not alert.acknowledged:
            alert.acknowledged, alert.acknowledged_at = True, datetime.now(UTC)
            count += 1
    return count


def watchlist(session: Session) -> list[WatchlistEntry]:
    return list(session.scalars(select(WatchlistEntry).order_by(WatchlistEntry.created_at.desc())))


def add_watch(session: Session, kind: str, value: str, label: str | None = None) -> WatchlistEntry:
    value = value.strip()
    if kind == VULNERABILITY:
        value = value.upper()
    elif kind == "keyword":
        value = value.lower()
    if not value or len(value) > 500:
        raise ValueError("watch value must be 1-500 characters")
    existing = session.scalar(
        select(WatchlistEntry).where(WatchlistEntry.entity_kind == kind, WatchlistEntry.value == value)
    )
    if existing:
        existing.active = True
        return existing
    row = WatchlistEntry(entity_kind=kind, value=value, label=(label or "").strip()[:200] or None)
    session.add(row)
    session.flush()
    return row


def remove_watch(session: Session, watch_id: int) -> None:
    row = session.get(WatchlistEntry, watch_id)
    if row:
        session.delete(row)


def overview_metrics(session: Session) -> dict[str, Any]:
    now = datetime.now(UTC)
    week = (now - timedelta(days=7)).date()

    def count(stmt: Any) -> int:
        return int(session.scalar(stmt) or 0)

    return {
        "vulnerabilities": count(select(func.count(Vulnerability.id))),
        "kev": count(select(func.count(Vulnerability.id)).where(Vulnerability.kev_listed.is_(True))),
        "kev_last_7d": count(
            select(func.count(Vulnerability.id)).where(Vulnerability.kev_date_added >= week)
        ),
        "ransomware": count(
            select(func.count(Vulnerability.id)).where(Vulnerability.kev_ransomware_use == "Known")
        ),
        "indicators": count(select(func.count(Indicator.id))),
        "intel": count(select(func.count(IntelObject.id))),
        "high_priority": count(
            select(func.count(PriorityScore.id)).where(PriorityScore.band.in_(("Critical", "High")))
        ),
        "open_alerts": count(select(func.count(Alert.id)).where(Alert.acknowledged.is_(False))),
        "synthetic_records": count(
            select(func.count(Observation.id)).where(Observation.is_synthetic.is_(True))
        ),
    }


def purge_synthetic(session: Session) -> int:
    """Remove all synthetic demo data."""
    total = 0
    demo_ind = [
        i.entity_key for i in session.scalars(select(Indicator).where(Indicator.is_synthetic.is_(True)))
    ]
    demo_vuln = list(
        session.scalars(select(Vulnerability.cve_id).where(Vulnerability.is_synthetic.is_(True)))
    )
    demo_intel = [
        o.entity_key for o in session.scalars(select(IntelObject).where(IntelObject.is_synthetic.is_(True)))
    ]
    for kind, keys in ((INDICATOR, demo_ind), (VULNERABILITY, demo_vuln), (INTEL, demo_intel)):
        for i in range(0, len(keys), 500):
            chunk = keys[i : i + 500]
            for state_model in (PriorityScore, AnalystState, Alert, ChangeEvent):
                session.execute(
                    delete(state_model).where(
                        state_model.entity_kind == kind, state_model.entity_key.in_(chunk)
                    )
                )
    for model in (Observation, Relationship, Vulnerability, Indicator, IntelObject):
        result: Any = session.execute(delete(model).where(model.is_synthetic.is_(True)))
        total += result.rowcount or 0

    session.execute(delete(Alert).where(Alert.dedup_key == "baseline:synthetic_demo"))
    session.execute(delete(RawRecord).where(RawRecord.source == "synthetic_demo"))
    return total
