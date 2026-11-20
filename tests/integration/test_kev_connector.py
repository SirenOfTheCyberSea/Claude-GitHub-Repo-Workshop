"""Mocked integration tests for the CISA KEV connector and the end-to-end ingestion pipeline."""

import json

import httpx
import pytest
import respx
from sqlalchemy import func, select

from siren_threatwatch.connectors.base import ConnectorError
from siren_threatwatch.connectors.cisa_kev import CisaKevConnector
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.db.models import Alert, IngestionRun, PriorityScore, Vulnerability, WatchlistEntry
from siren_threatwatch.ingestion.pipeline import ingest_source


async def _fetch(settings, **kw):
    conn = CisaKevConnector(settings, **kw)
    async with conn.make_client(sleep=_nosleep, use_cache=False) as client:
        return await conn.fetch(client)


async def _nosleep(_):
    return None


@respx.mock
async def test_primary_feed(settings, kev_payload):
    respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(200, json=kev_payload))
    result = await _fetch(settings)
    assert len(result.records) == 3 and result.rejected == 2
    assert result.details["endpoint"] == "primary"


@respx.mock
async def test_falls_back_to_official_mirror(settings, kev_payload):
    respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(500))
    respx.get(settings.kev_mirror_url).mock(return_value=httpx.Response(200, json=kev_payload))
    result = await _fetch(settings)
    assert result.details["endpoint"] == "mirror"
    assert result.fetched_url == settings.kev_mirror_url
    assert "primary" in result.details["endpoint_errors"][0]


@respx.mock
async def test_all_endpoints_fail(settings):
    respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
    respx.get(settings.kev_mirror_url).mock(side_effect=httpx.ConnectTimeout("t"))
    with pytest.raises(ConnectorError, match="all KEV endpoints failed"):
        await _fetch(settings)


@respx.mock
async def test_malformed_json(settings):
    respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(200, content=b"<html>not json"))
    with pytest.raises(ConnectorError, match="not valid JSON"):
        await _fetch(settings)


async def test_offline_file(settings, tmp_path, kev_payload):
    f = tmp_path / "kev.json"
    f.write_text(json.dumps(kev_payload))
    result = await _fetch(settings, local_file=f)
    assert len(result.records) == 3 and result.details["offline_import"]


def test_disabled_connector_is_skipped(settings, engine):
    settings.kev_enabled = False
    summary = ingest_source("cisa_kev", settings)
    assert summary.status == "skipped"


@respx.mock
def test_pipeline_end_to_end_success_then_change(settings, engine, kev_payload):
    route = respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(200, json=kev_payload))
    first = ingest_source("cisa_kev", settings)
    assert (first.status, first.new, first.rejected) == ("partial", 3, 2)

    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 3
        assert s.scalar(select(func.count()).select_from(PriorityScore)) == 3
        alert_types = list(s.scalars(select(Alert.alert_type)))
        assert alert_types == ["baseline"]  # no flood on first ingestion
        s.add(WatchlistEntry(entity_kind="vulnerability", value="CVE-2026-40217"))

    changed = json.loads(json.dumps(kev_payload))
    changed["vulnerabilities"][1]["knownRansomwareCampaignUse"] = "Known"
    changed["vulnerabilities"].append(
        {
            **changed["vulnerabilities"][2],
            "cveID": "CVE-2026-99999",
            "knownRansomwareCampaignUse": "Known",
            "dateAdded": "2026-11-19",
            "dueDate": "2026-11-21",
        }
    )
    route.mock(return_value=httpx.Response(200, json=changed))
    second = ingest_source("cisa_kev", settings)
    assert second.new == 1 and second.updated == 1

    with session_scope() as s:
        types = sorted(s.scalars(select(Alert.alert_type)))
        assert "watch_change" in types
        runs = list(s.scalars(select(IngestionRun.status)))
        assert runs == ["partial", "partial"]

    third = ingest_source("cisa_kev", settings)  # identical feed: nothing new, no duplicate alerts
    assert (third.new, third.updated, third.alerts) == (0, 0, 0)


@respx.mock
def test_pipeline_records_failure_without_raising(settings, engine):
    settings.http_max_retries = 0
    respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(503))
    respx.get(settings.kev_mirror_url).mock(return_value=httpx.Response(503))
    summary = ingest_source("cisa_kev", settings)
    assert summary.status == "failed" and "503" in summary.error
    with session_scope() as s:
        run = s.scalar(select(IngestionRun))
        assert run.status == "failed" and run.finished_at is not None
