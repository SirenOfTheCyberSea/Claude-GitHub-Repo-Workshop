"""Assemble report data from the database and render it in the requested format."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.orm import Session

from siren_threatwatch import queries
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
    title: str = "Siren ThreatWatch Report",
) -> ReportData:
    flt = queries.VulnFilter(
        kev_only=kev_only,
        bands=bands or None,
        include_synthetic=include_synthetic,
        added_within_days=period_days or None,
    )
    return ReportData(
        title=title,
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
            }
        )
    if fmt == "csv":
        return to_csv(records_from_df(data.vulnerabilities))
    if fmt == "stix":
        return to_json(to_stix_bundle(data.vulnerabilities, data.indicators))
    raise ValueError(f"unknown format {fmt!r}; choose from {sorted(FORMATS)}")
