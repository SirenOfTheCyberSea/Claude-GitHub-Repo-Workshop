"""Optional recurring ingestion using APScheduler."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.blocking import BlockingScheduler

from siren_threatwatch.config import Settings
from siren_threatwatch.ingestion.pipeline import ingest_all

log = logging.getLogger(__name__)


def run_scheduler(settings: Settings, run_immediately: bool = True) -> None:
    """Block forever, ingesting all enabled sources every ``schedule_interval_minutes``."""
    scheduler = BlockingScheduler(timezone="UTC")

    def job() -> None:
        for summary in ingest_all(settings):
            log.info("scheduled run", extra=summary.as_dict())

    scheduler.add_job(
        job,
        "interval",
        minutes=settings.schedule_interval_minutes,
        id="ingest_all",
        max_instances=1,  # never overlap runs
        coalesce=True,  # collapse missed runs into one
        misfire_grace_time=300,
        next_run_time=datetime.now(UTC) if run_immediately else None,
    )
    log.info("scheduler started", extra={"interval_minutes": settings.schedule_interval_minutes})
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("scheduler stopped")
