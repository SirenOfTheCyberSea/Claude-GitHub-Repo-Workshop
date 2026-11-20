"""Mocked integration tests for the NVD and MITRE ATT&CK connectors and their pipeline behaviour."""

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from pydantic import SecretStr
from sqlalchemy import func, select

from siren_threatwatch.connectors.base import ConnectorError
from siren_threatwatch.connectors.mitre_attack import MitreAttackConnector, latest_release
from siren_threatwatch.connectors.nvd import NvdConnector
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.db.models import (
    Alert,
    ChangeEvent,
    IntelObject,
    PriorityScore,
    Relationship,
    SyncState,
    Vulnerability,
    WatchlistEntry,
)
from siren_threatwatch.db.repository import Persister
from siren_threatwatch.ingestion.pipeline import ingest_source
from siren_threatwatch.normalization.schema import EntityKind, NormalizedRecord
from tests.conftest import FIXTURES

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
BUNDLE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json"


class Sleeper:
    def __init__(self):
        self.calls = []

    async def __call__(self, s):
        self.calls.append(s)


@pytest.fixture
def nvd_payload():
    return json.loads((FIXTURES / "nvd_sample.json").read_text("utf-8"))


@pytest.fixture
def attack_bundle():
    return json.loads((FIXTURES / "attack_sample.json").read_text("utf-8"))


@pytest.fixture
def attack_index():
    return {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {"version": "19.0", "url": BUNDLE_URL.replace("20.1", "19.0")},
                    {"version": "20.1", "url": BUNDLE_URL},
                ],
            }
        ]
    }


def _page(payload, items, start, total):
    return {
        **payload,
        "vulnerabilities": items,
        "startIndex": start,
        "resultsPerPage": len(items),
        "totalResults": total,
    }


def _params(request):
    return parse_qs(urlsplit(str(request.url)).query, keep_blank_values=True)


async def _run(conn, sleeper=None):
    async with conn.make_client(sleep=sleeper or Sleeper()) as client:
        return await conn.fetch(client)


# ------------------------------------------------------------------ NVD
@respx.mock
async def test_nvd_haskev_paginates_and_paces(settings, nvd_payload):
    items = nvd_payload["vulnerabilities"]
    route = respx.get(NVD).mock(
        side_effect=[
            httpx.Response(200, json=_page(nvd_payload, items[:2], 0, 3)),
            httpx.Response(200, json=_page(nvd_payload, items[2:], 2, 3)),
        ]
    )
    settings.nvd_request_interval_seconds = 6.0
    sleeper = Sleeper()
    result = await _run(NvdConnector(settings), sleeper)
    assert [r.external_id for r in result.records] == ["CVE-2021-44228", "CVE-2025-61932", "CVE-2024-10441"]
    first, second = (_params(c.request) for c in route.calls)
    assert "hasKev" in first and "noRejected" in first
    assert (
        first["resultsPerPage"] == ["2000"] and first["startIndex"] == ["0"] and second["startIndex"] == ["2"]
    )
    assert "apiKey" not in route.calls[0].request.headers  # no key configured
    assert sleeper.calls and sleeper.calls[0] > 5  # second request waited for the pacing interval


@respx.mock
async def test_nvd_api_key_sent_as_header_and_faster(settings, nvd_payload):
    settings.nvd_api_key = SecretStr("test-key-123")
    route = respx.get(NVD).mock(return_value=httpx.Response(200, json=_page(nvd_payload, [], 0, 0)))
    await _run(NvdConnector(settings))
    assert route.calls[0].request.headers["apiKey"] == "test-key-123"
    assert "test-key-123" not in str(route.calls[0].request.url)
    assert settings.nvd_interval < 1


@respx.mock
async def test_nvd_error_message_header_and_partial_success(settings, nvd_payload):
    settings.nvd_recent_days = 5
    respx.get(NVD).mock(
        side_effect=lambda req: (
            httpx.Response(200, json=_page(nvd_payload, nvd_payload["vulnerabilities"][:1], 0, 1))
            if "hasKev" in _params(req)
            else httpx.Response(404, headers={"message": "Date range cannot exceed 120 days."})
        )
    )
    result = await _run(NvdConnector(settings))
    assert len(result.records) == 1 and result.details["partial"]
    assert "Date range cannot exceed 120 days." in result.details["step_errors"][0]


@respx.mock
async def test_nvd_all_failed_raises(settings):
    settings.http_max_retries = 1
    respx.get(NVD).mock(return_value=httpx.Response(503))
    with pytest.raises(ConnectorError, match="all NVD requests failed"):
        await _run(NvdConnector(settings))


@respx.mock
async def test_nvd_403_is_retried(settings, nvd_payload):
    route = respx.get(NVD).mock(
        side_effect=[httpx.Response(403), httpx.Response(200, json=_page(nvd_payload, [], 0, 0))]
    )
    await _run(NvdConnector(settings))
    assert route.call_count == 2


@respx.mock
async def test_nvd_cve_lookup_and_not_found(settings, nvd_payload):
    def responder(req):
        cve = _params(req)["cveId"][0]
        items = [v for v in nvd_payload["vulnerabilities"] if v["cve"]["id"] == cve]
        return httpx.Response(200, json=_page(nvd_payload, items, 0, len(items)))

    route = respx.get(NVD).mock(side_effect=responder)
    result = await _run(NvdConnector(settings, cve_ids=["cve-2021-44228", "CVE-2099-0001"]))
    assert [r.external_id for r in result.records] == ["CVE-2021-44228"]
    assert result.details["not_found"] == ["CVE-2099-0001"]
    assert all("hasKev" not in _params(c.request) for c in route.calls)  # lookups only


@respx.mock
async def test_nvd_recent_window_parameters(settings, nvd_payload):
    route = respx.get(NVD).mock(return_value=httpx.Response(200, json=_page(nvd_payload, [], 0, 0)))
    await _run(NvdConnector(settings, recent_days=10))
    window = next(_params(c.request) for c in route.calls if "lastModStartDate" in _params(c.request))
    assert window["lastModStartDate"][0].endswith("Z") and "lastModEndDate" in window


def test_kev_then_nvd_pipeline_precedence_and_rescoring(settings, engine, kev_payload, nvd_payload):
    settings.nvd_request_interval_seconds = 0.1
    with respx.mock:
        respx.get(settings.kev_feed_url).mock(return_value=httpx.Response(200, json=kev_payload))
        assert ingest_source("cisa_kev", settings).new == 3
    with session_scope() as s:
        before = s.scalar(select(PriorityScore.score).where(PriorityScore.entity_key == "CVE-2024-10441"))
        s.add(WatchlistEntry(entity_kind="vulnerability", value="CVE-2024-10441"))

    with respx.mock:
        respx.get(NVD).mock(return_value=httpx.Response(200, json=nvd_payload))
        summary = ingest_source("nvd", settings)
    assert summary.status == "success" and summary.updated == 1 and summary.new == 2

    with session_scope() as s:
        v = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2024-10441"))
        assert v.vendor == "Synology"  # CISA's naming kept over NVD's CPE vendor
        assert v.cvss_score is not None and v.field_sources["cvss_score"] == "nvd"
        assert v.field_sources["vendor"] == "cisa_kev" and v.kev_listed
        assert v.cvss_metrics and v.affected_products
        after = s.scalar(select(PriorityScore.score).where(PriorityScore.entity_key == "CVE-2024-10441"))
        assert after > before  # CVSS now contributes
        assert s.scalar(
            select(func.count()).select_from(ChangeEvent).where(ChangeEvent.field == "cvss_score")
        )
        assert "watch_change" in set(s.scalars(select(Alert.alert_type)))  # watched CVE gained CVSS
        assert s.scalar(
            select(SyncState.value).where(SyncState.source == "nvd", SyncState.key == "last_success")
        )

    with respx.mock:
        respx.get(NVD).mock(return_value=httpx.Response(200, json=nvd_payload))
        again = ingest_source("nvd", settings)
    assert (again.new, again.updated, again.alerts) == (0, 0, 0)


# ------------------------------------------------------------------ ATT&CK
def test_latest_release_selection(attack_index):
    assert latest_release(attack_index, "enterprise-attack") == ("20.1", BUNDLE_URL)
    with pytest.raises(ConnectorError):
        latest_release({"collections": []}, "enterprise-attack")
    with pytest.raises(ConnectorError):
        latest_release([], "enterprise-attack")


@respx.mock
async def test_attack_fetch_and_skip_unchanged(settings, attack_index, attack_bundle):
    respx.get(INDEX).mock(return_value=httpx.Response(200, json=attack_index))
    bundle_route = respx.get(BUNDLE_URL).mock(return_value=httpx.Response(200, json=attack_bundle))
    result = await _run(MitreAttackConnector(settings))
    assert len(result.records) == 17 and result.details["versions"] == {"enterprise-attack": "20.1"}
    skipped = await _run(MitreAttackConnector(settings, known_versions={"enterprise-attack": "20.1"}))
    assert skipped.records == [] and skipped.details["unchanged_domains"] == ["enterprise-attack v20.1"]
    forced = await _run(
        MitreAttackConnector(settings, known_versions={"enterprise-attack": "20.1"}, force=True)
    )
    assert forced.records and bundle_route.call_count == 2


@respx.mock
async def test_attack_index_pointing_off_allowlist_is_refused(settings, attack_bundle):
    evil = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [{"version": "99.0", "url": "https://evil.example.com/bundle.json"}],
            }
        ]
    }
    respx.get(INDEX).mock(return_value=httpx.Response(200, json=evil))
    with pytest.raises(ConnectorError, match="not on the connector allowlist"):
        await _run(MitreAttackConnector(settings))


@respx.mock
async def test_attack_bad_bundle(settings, attack_index):
    respx.get(INDEX).mock(return_value=httpx.Response(200, json=attack_index))
    respx.get(BUNDLE_URL).mock(return_value=httpx.Response(200, json={"type": "nope"}))
    with pytest.raises(ConnectorError, match="not a STIX bundle"):
        await _run(MitreAttackConnector(settings))


async def test_attack_local_file(settings, tmp_path, attack_bundle):
    f = tmp_path / "enterprise.json"
    f.write_text(json.dumps(attack_bundle))
    result = await _run(MitreAttackConnector(settings, local_file=f))
    assert len(result.records) == 17


def test_attack_pipeline_persists_graph_and_versions(settings, engine, attack_index, attack_bundle):
    with respx.mock:
        respx.get(INDEX).mock(return_value=httpx.Response(200, json=attack_index))
        respx.get(BUNDLE_URL).mock(return_value=httpx.Response(200, json=attack_bundle))
        first = ingest_source("mitre_attack", settings)
        second = ingest_source("mitre_attack", settings)
    assert first.new == 17 and second.fetched == 0 and second.notes
    with session_scope() as s:
        assert s.scalar(select(SyncState.value).where(SyncState.key == "version:enterprise-attack")) == "20.1"
        kinds = dict(s.execute(select(IntelObject.kind, func.count()).group_by(IntelObject.kind)).all())
        assert kinds["threat-actor"] == 2 and kinds["campaign"] == 2 and kinds["attack-pattern"] == 12
        assert s.scalar(select(func.count()).select_from(Relationship)) == 18  # 14 explicit + 4 CVE mentions
        lazarus = s.scalar(select(IntelObject).where(IntelObject.key == "lazarus-group"))
        assert "HIDDEN COBRA" in lazarus.aliases and lazarus.external_id == "G0032"


def _other_source_actor(name, aliases, source="other_feed"):
    return NormalizedRecord(
        source=source,
        entity_kind=EntityKind.INTEL,
        external_id=f"{source}-{name}",
        title=name,
        raw_payload={"n": name, "s": source},
        intel={"kind": "threat-actor", "name": name, "aliases": aliases},
        relationships=[{"rel_type": "uses", "dst_kind": "intel", "dst_key": "malware:x"}],
    )


def test_cross_source_alias_merge(session, run, attack_bundle):
    from siren_threatwatch.normalization.attack import parse_bundle

    Persister(session, run).persist(parse_bundle(attack_bundle).records)
    # Another source calls the group "Bluenoroff" — an ATT&CK alias of APT38 — so it merges.
    stats = Persister(session, run).persist([_other_source_actor("Bluenoroff", ["BlueNoroff Group"])])
    assert stats.new == 0
    apt38 = session.scalar(select(IntelObject).where(IntelObject.key == "apt38"))
    assert "BlueNoroff Group" in apt38.aliases
    assert apt38.description and "APT38" in apt38.description  # ATT&CK text not overwritten
    rel = session.scalar(select(Relationship).where(Relationship.source == "other_feed"))
    assert rel.src_key == "threat-actor:apt38"  # observation/relationships attached to canonical object


def test_ambiguous_alias_does_not_merge(session, run):
    Persister(session, run).persist(
        [
            _other_source_actor("Group One", ["Shared Name"], source="feed_a"),
            _other_source_actor("Group Two", ["Shared Name"], source="feed_a"),
        ]
    )
    stats = Persister(session, run).persist([_other_source_actor("Shared Name", [], source="feed_b")])
    assert stats.new == 1  # matches two objects -> kept separate rather than guessing


def _demo_technique(external_id="T1486"):
    return NormalizedRecord(
        source="synthetic_demo",
        entity_kind=EntityKind.INTEL,
        external_id=external_id,
        title="t",
        description="[SYNTHETIC DEMO DATA] fake",
        raw_payload={"x": external_id},
        is_synthetic=True,
        intel={
            "kind": "attack-pattern",
            "name": "Data Encrypted for Impact",
            "external_id": external_id,
            "description": "[SYNTHETIC DEMO DATA] fake mapping",
        },
    )


def test_synthetic_data_never_overwrites_real_entities(session, run, attack_bundle):
    from siren_threatwatch.normalization.attack import parse_bundle

    Persister(session, run).persist(parse_bundle(attack_bundle).records)
    stats = Persister(session, run).persist([_demo_technique()])
    assert stats.updated == 0 and stats.new == 0
    t = session.scalar(select(IntelObject).where(IntelObject.key == "t1486"))
    assert not t.is_synthetic and "SYNTHETIC" not in (t.description or "")


def test_real_data_replaces_synthetic_placeholder(session, run, attack_bundle):
    from siren_threatwatch.normalization.attack import parse_bundle

    Persister(session, run).persist([_demo_technique()])
    Persister(session, run).persist(parse_bundle(attack_bundle).records)
    t = session.scalar(select(IntelObject).where(IntelObject.key == "t1486"))
    assert not t.is_synthetic and "SYNTHETIC" not in (t.description or "")
