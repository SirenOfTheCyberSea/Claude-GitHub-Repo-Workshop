"""Database bootstrap and cached data access for the dashboard."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.config import get_settings
from siren_threatwatch.db.base import secure_mkdir, session_scope
from siren_threatwatch.db.migrate import upgrade_database
from siren_threatwatch.logging_config import configure_logging


@st.cache_resource(show_spinner="Preparing database…")
def bootstrap() -> bool:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json, settings.secret_values())
    secure_mkdir(settings.data_dir)
    upgrade_database(settings.database_url)
    return True


def invalidate() -> None:
    st.cache_data.clear()


@st.cache_data(ttl=60, show_spinner=False)
def metrics() -> dict[str, Any]:
    with session_scope() as s:
        return queries.overview_metrics(s)


@st.cache_data(ttl=60, show_spinner=False)
def vulns(
    text: str | None = None,
    kev_only: bool = False,
    ransomware_only: bool = False,
    bands: tuple[str, ...] = (),
    vendors: tuple[str, ...] = (),
    statuses: tuple[str, ...] = (),
    added_within_days: int | None = None,
    include_synthetic: bool = True,
    limit: int = 5000,
) -> pd.DataFrame:
    flt = queries.VulnFilter(
        text=text or None,
        kev_only=kev_only,
        ransomware_only=ransomware_only,
        bands=list(bands) or None,
        vendors=list(vendors) or None,
        statuses=list(statuses) or None,
        added_within_days=added_within_days,
        include_synthetic=include_synthetic,
        limit=limit,
    )
    with session_scope() as s:
        return queries.vulnerabilities_df(s, flt)


@st.cache_data(ttl=60, show_spinner=False)
def indicators(
    text: str | None = None,
    types: tuple[str, ...] = (),
    min_confidence: int = 0,
    include_synthetic: bool = True,
) -> pd.DataFrame:
    with session_scope() as s:
        return queries.indicators_df(s, text, list(types) or None, min_confidence, include_synthetic)


@st.cache_data(ttl=60, show_spinner=False)
def feed(
    text: str | None, sources: tuple[str, ...], kinds: tuple[str, ...], days: int | None, limit: int
) -> pd.DataFrame:
    with session_scope() as s:
        return queries.feed_df(s, text, list(sources) or None, list(kinds) or None, days, limit)


@st.cache_data(ttl=60, show_spinner=False)
def health() -> pd.DataFrame:
    with session_scope() as s:
        return queries.source_health(s)


@st.cache_data(ttl=60, show_spinner=False)
def runs(limit: int = 100) -> pd.DataFrame:
    with session_scope() as s:
        return queries.ingestion_runs_df(s, limit)


@st.cache_data(ttl=60, show_spinner=False)
def obs_timeseries(days: int) -> pd.DataFrame:
    with session_scope() as s:
        return queries.observations_timeseries(s, days)


@st.cache_data(ttl=60, show_spinner=False)
def kev_timeseries(days: int) -> pd.DataFrame:
    with session_scope() as s:
        return queries.kev_additions_timeseries(s, days)


@st.cache_data(ttl=30, show_spinner=False)
def alerts(include_acknowledged: bool = False) -> pd.DataFrame:
    with session_scope() as s:
        return queries.alerts_df(s, include_acknowledged)


def entity_detail(kind: str, key: str) -> dict[str, Any]:
    """Uncached: provenance, relationships, change history, score and analyst state for one entity."""
    with session_scope() as s:
        score = queries.priority_for(s, kind, key)
        state = queries.analyst_state(s, kind, key)
        return {
            "observations": [
                {
                    "source": o.source,
                    "title": o.title,
                    "description": o.description,
                    "source_url": o.source_url,
                    "published_at": o.published_at,
                    "observed_at": o.observed_at,
                    "ingested_at": o.ingested_at,
                    "last_seen_at": o.last_seen_at,
                    "sighting_count": o.sighting_count,
                    "confidence": o.confidence,
                    "tlp": o.tlp,
                    "is_synthetic": o.is_synthetic,
                }
                for o in queries.observations_for(s, kind, key)
            ],
            "relationships": [
                {
                    "src": f"{r.src_kind}:{r.src_key}",
                    "rel_type": r.rel_type,
                    "dst": f"{r.dst_kind}:{r.dst_key}",
                    "source": r.source,
                    "evidence_url": r.evidence_url,
                    "description": r.description,
                    "confidence": r.confidence,
                    "is_synthetic": r.is_synthetic,
                }
                for r in queries.relationships_for(s, kind, key)
            ],
            "changes": [
                {
                    "changed_at": c.changed_at,
                    "field": c.field,
                    "old": c.old_value,
                    "new": c.new_value,
                    "source": c.source,
                }
                for c in queries.changes_for(s, kind, key)
            ],
            "score": None
            if score is None
            else {
                "score": score.score,
                "band": score.band,
                "factors": score.factors,
                "missing": score.missing,
                "computed_at": score.computed_at,
            },
            "state": None
            if state is None
            else {
                "status": state.status,
                "tags": state.tags,
                "notes": state.notes,
                "priority_override": state.priority_override,
            },
            "watched": any(w.entity_kind == kind and w.value == key for w in queries.watchlist(s)),
        }
