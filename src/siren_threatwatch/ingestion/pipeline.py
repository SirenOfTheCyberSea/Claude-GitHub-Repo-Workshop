"""Ingestion orchestration: fetch → validate/normalise → persist (raw + canonical + observations)
→ rescore → alerts → record run health."""

from __future__ import annotations

import asyncio
import logging
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from siren_threatwatch.alerts.engine import evaluate_and_store
from siren_threatwatch.config import Settings, get_settings
from siren_threatwatch.connectors import (
    CONNECTORS,
    BaseConnector,
    CisaKevConnector,
    FetchResult,
    MitreAttackConnector,
    NvdConnector,
)
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.db.models import VULNERABILITY, IngestionRun, Vulnerability, WatchlistEntry
from siren_threatwatch.db.repository import Persister, ensure_source, get_sync_state, set_sync_state
from siren_threatwatch.prioritization.service import rescore_all

log = logging.getLogger(__name__)


@dataclass
class RunSummary:
    source: str
    status: str
    run_id: int | None
    fetched: int = 0
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    rejected: int = 0
    alerts: int = 0
    error: str | None = None
    fetched_url: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _notes(result: FetchResult) -> list[str]:
    d = result.details
    notes = [f"release unchanged, download skipped: {x}" for x in d.get("unchanged_domains", [])]
    notes += [f"step failed: {e}" for e in d.get("step_errors", [])[:5]]
    notes += [f"page cap reached (SIREN_NVD_MAX_PAGES): {s}" for s in d.get("truncated_steps", [])]
    if d.get("not_found"):
        notes.append("not found in NVD: " + ", ".join(d["not_found"][:10]))
    return notes


def _is_baseline(session: Session, source: str) -> bool:
    prior = session.scalar(
        select(func.count(IngestionRun.id)).where(
            IngestionRun.source == source, IngestionRun.status.in_(("success", "partial"))
        )
    )
    return not prior


def _tracked_cves_needing_nvd(session: Session, limit: int) -> list[str]:
    """Watched CVEs first, then other real (non-synthetic, non-KEV) CVEs that NVD has not enriched yet."""
    if limit <= 0:
        return []
    watched = list(
        session.scalars(
            select(WatchlistEntry.value).where(
                WatchlistEntry.entity_kind == VULNERABILITY, WatchlistEntry.active.is_(True)
            )
        )
    )
    others = list(
        session.scalars(
            select(Vulnerability.cve_id)
            .where(
                Vulnerability.nvd_status.is_(None),
                Vulnerability.is_synthetic.is_(False),
                Vulnerability.kev_listed.is_(False),
            )
            .limit(limit)
        )
    )
    return list(dict.fromkeys([*watched, *others]))[:limit]


def build_connector(
    name: str,
    settings: Settings,
    local_file: Path | None = None,
    *,
    cve_ids: list[str] | None = None,
    recent_days: int | None = None,
    force: bool = False,
) -> BaseConnector:
    if name not in CONNECTORS:
        raise KeyError(f"unknown or not-yet-implemented source: {name!r} (available: {sorted(CONNECTORS)})")
    if name == CisaKevConnector.name:
        return CisaKevConnector(settings, local_file=local_file)
    if name == NvdConnector.name:
        with session_scope() as session:
            tracked = [] if cve_ids else _tracked_cves_needing_nvd(session, settings.nvd_lookup_limit)
        return NvdConnector(settings, cve_ids=cve_ids, recent_days=recent_days, tracked_cves=tracked)
    if name == MitreAttackConnector.name:
        with session_scope() as session:
            known = {
                d: v
                for d in settings.mitre_domains
                if (v := get_sync_state(session, MitreAttackConnector.name, f"version:{d}"))
            }
        return MitreAttackConnector(settings, local_file=local_file, known_versions=known, force=force)
    return CONNECTORS[name](settings)


async def _fetch(connector: BaseConnector) -> FetchResult:
    async with connector.make_client() as client:
        return await connector.fetch(client)


def ingest_source(
    name: str,
    settings: Settings | None = None,
    *,
    local_file: Path | None = None,
    connector: BaseConnector | None = None,
    cve_ids: list[str] | None = None,
    recent_days: int | None = None,
    force: bool = False,
) -> RunSummary:
    """Run one source end-to-end. Never raises for source failures — they are recorded on the run."""
    settings = settings or get_settings()
    connector = connector or build_connector(
        name, settings, local_file, cve_ids=cve_ids, recent_days=recent_days, force=force
    )
    ready, reason = connector.configuration_status()

    with session_scope() as session:
        ensure_source(session, connector.name, connector.display_name)
        run = IngestionRun(source=connector.name, started_at=datetime.now(UTC))
        session.add(run)
        session.flush()
        run_id = run.id
        if not ready:
            run.status, run.error, run.finished_at = "skipped", reason, datetime.now(UTC)
            log.info("source skipped", extra={"source": connector.name, "reason": reason})
            return RunSummary(connector.name, "skipped", run_id, error=reason)

    log.info("ingestion started", extra={"source": connector.name, "run_id": run_id})
    try:
        result = asyncio.run(_fetch(connector))
    except Exception as exc:  # recorded, not raised: one bad source must not stop others
        message = f"{type(exc).__name__}: {exc}"
        log.error("ingestion failed", extra={"source": connector.name, "run_id": run_id, "error": message})
        log.debug(traceback.format_exc())
        with session_scope() as session:
            run_row = session.get(IngestionRun, run_id)
            assert run_row is not None
            run_row.status, run_row.error, run_row.finished_at = "failed", message[:2000], datetime.now(UTC)
            run_row.fetched_url = getattr(exc, "url", None)
            run_row.http_status = getattr(exc, "status", None)
        return RunSummary(connector.name, "failed", run_id, error=message)

    with session_scope() as session:
        run_row = session.get(IngestionRun, run_id)
        assert run_row is not None
        baseline = _is_baseline(session, connector.name)
        stats = Persister(session, run_row).persist(result.records)
        scores = rescore_all(session, settings)
        alerts = evaluate_and_store(
            session,
            stats.changes,
            scores,
            min_score=settings.alert_min_score,
            baseline=baseline,
            source=connector.name,
            run_id=run_id,
        )
        status = "partial" if result.rejected or result.details.get("partial") else "success"
        for domain, version in (result.details.get("versions") or {}).items():
            set_sync_state(session, connector.name, f"version:{domain}", version)
        set_sync_state(session, connector.name, "last_success", datetime.now(UTC).isoformat())
        run_row.status = status
        run_row.finished_at = datetime.now(UTC)
        run_row.fetched_url = result.fetched_url
        run_row.http_status = result.http_status
        run_row.records_fetched = len(result.records) + result.rejected
        run_row.records_new, run_row.records_updated = stats.new, stats.updated
        run_row.records_unchanged, run_row.records_rejected = stats.unchanged, result.rejected
        run_row.alerts_created = alerts
        run_row.details = {
            **result.details,
            "from_cache": result.from_cache,
            "baseline": baseline,
            "rejection_samples": result.rejection_samples,
        }
        summary = RunSummary(
            connector.name,
            status,
            run_id,
            fetched=run_row.records_fetched,
            new=stats.new,
            updated=stats.updated,
            unchanged=stats.unchanged,
            rejected=result.rejected,
            alerts=alerts,
            fetched_url=result.fetched_url,
            notes=_notes(result),
        )
    log.info("ingestion finished", extra=summary.as_dict())
    return summary


def ingest_all(settings: Settings | None = None, include_demo: bool = False) -> list[RunSummary]:
    settings = settings or get_settings()
    names = [n for n in CONNECTORS if include_demo or n != "synthetic_demo"]
    return [ingest_source(n, settings) for n in names]
