"""Assemble report data from the database and render it in the requested format."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from siren_threatwatch import queries
from siren_threatwatch.db.models import Relationship
from siren_threatwatch.reporting.exporters import (
    ReportData,
    markdown_executive,
    markdown_technical,
    records_from_df,
    to_csv,
    to_json,
    to_stix_bundle,
)

ReportFormat = Literal["md-executive", "md-technical", "json", "csv", "stix"]
FORMATS: dict[str, str] = {
    "md-executive": ".md",
    "md-technical": ".md",
    "json": ".json",
    "csv": ".csv",
    "stix": ".stix.json",
}


def gather(
    session: Session,
    *,
    period_days: int = 30,
    kev_only: bool = False,
    bands: list[str] | None = None,
    include_synthetic: bool = True,
    include_indicators: bool = True,
    include_intel: bool = False,
    title: str = "Siren ThreatWatch Report",
) -> ReportData:
    flt = queries.VulnFilter(
        kev_only=kev_only,
        bands=bands or None,
        include_synthetic=include_synthetic,
        added_within_days=period_days or None,
    )
    intel: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []
    if include_intel:
        intel = [
            {
                "kind": o.kind,
                "key": o.key,
                "name": o.name,
                "aliases": o.aliases,
                "external_id": o.external_id,
                "description": o.description,
                "attributes": o.attributes,
                "first_seen_at": o.first_seen_at,
                "is_synthetic": o.is_synthetic,
            }
            for o in queries.intel_objects(session)
            if include_synthetic or not o.is_synthetic
        ]
        rels = [
            {
                "src_kind": r.src_kind,
                "src_key": r.src_key,
                "rel_type": r.rel_type,
                "dst_kind": r.dst_kind,
                "dst_key": r.dst_key,
                "source": r.source,
                "description": r.description,
                "evidence_url": r.evidence_url,
            }
            for r in session.scalars(select(Relationship))
            if include_synthetic or not r.is_synthetic
        ]
    return ReportData(
        title=title,
        intel=intel,
        relationships=rels,
        generated_at=datetime.now(UTC),
        metrics=queries.overview_metrics(session),
        vulnerabilities=queries.vulnerabilities_df(session, flt),
        indicators=queries.indicators_df(session, include_synthetic=include_synthetic)
        if include_indicators
        else queries.indicators_df(session).iloc[0:0],
        health=queries.source_health(session),
        alerts=queries.alerts_df(session),
        period_days=period_days,
    )


def render(data: ReportData, fmt: str) -> str:
    if fmt == "md-executive":
        return markdown_executive(data)
    if fmt == "md-technical":
        return markdown_technical(data)
    if fmt == "json":
        return to_json(
            {
                "generated_at": data.generated_at.isoformat(),
                "title": data.title,
                "period_days": data.period_days,
                "contains_synthetic_data": data.has_synthetic,
                "metrics": data.metrics,
                "priority_note": "priority_score is a computed triage aid, not evidence of exploitation",
                "vulnerabilities": records_from_df(data.vulnerabilities),
                "indicators": records_from_df(data.indicators),
                "intel_objects": data.intel,
                "relationships": data.relationships,
            }
        )
    if fmt == "csv":
        return to_csv(records_from_df(data.vulnerabilities))
    if fmt == "stix":
        return to_json(to_stix_bundle(data.vulnerabilities, data.indicators, data.intel, data.relationships))
    raise ValueError(f"unknown format {fmt!r}; choose from {sorted(FORMATS)}")
