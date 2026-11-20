from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from siren_threatwatch.config import Settings
from siren_threatwatch.db.base import create_db_engine, set_engine
from siren_threatwatch.db.models import Base, IngestionRun
from siren_threatwatch.normalization.schema import EntityKind, NormalizedRecord

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path,
        http_max_retries=2,
        http_timeout_seconds=5,
    )


@pytest.fixture
def engine(settings: Settings):  # type: ignore[no-untyped-def]
    eng = create_db_engine(settings.database_url, settings)
    Base.metadata.create_all(eng)
    set_engine(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine) -> Iterator[Session]:  # type: ignore[no-untyped-def]
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def run(session: Session) -> IngestionRun:
    r = IngestionRun(source="test")
    session.add(r)
    session.flush()
    return r


@pytest.fixture
def kev_payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "kev_sample.json").read_text("utf-8"))
    return data


def vuln_record(cve: str = "CVE-2024-0001", source: str = "test", **vuln: Any) -> NormalizedRecord:
    payload = {"cve_id": cve, "title": f"{cve} title", **vuln}
    return NormalizedRecord(
        source=source,
        entity_kind=EntityKind.VULNERABILITY,
        external_id=cve,
        title=payload["title"],
        source_url="https://example.com/advisory",
        published_at=datetime(2024, 1, 1, tzinfo=UTC),
        confidence=80,
        raw_payload={"src": source, **{k: str(v) for k, v in payload.items()}},
        vulnerability=payload,
    )


def ioc_record(value: str, ioc_type: str | None = None, source: str = "test", **kw: Any) -> NormalizedRecord:
    return NormalizedRecord(
        source=source,
        entity_kind=EntityKind.INDICATOR,
        external_id=f"ioc-{value}",
        title="indicator",
        raw_payload={"value": value, "src": source},
        indicator={"value": value, "ioc_type": ioc_type},
        **kw,
    )
