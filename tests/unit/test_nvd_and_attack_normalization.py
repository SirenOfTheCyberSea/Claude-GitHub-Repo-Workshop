import json
from datetime import UTC, datetime, timedelta

import pytest

from siren_threatwatch.connectors.nvd import date_windows
from siren_threatwatch.db.repository import may_overwrite, source_rank
from siren_threatwatch.normalization.attack import clean_attack_text, parse_bundle
from siren_threatwatch.normalization.nvd import (
    affected_products,
    extract_metrics,
    headline_metric,
    normalize_nvd_item,
    parse_cpe,
    parse_nvd_datetime,
)
from tests.conftest import FIXTURES


@pytest.fixture
def nvd_items():
    return json.loads((FIXTURES / "nvd_sample.json").read_text("utf-8"))["vulnerabilities"]


@pytest.fixture
def attack_bundle():
    return json.loads((FIXTURES / "attack_sample.json").read_text("utf-8"))


# ---------------------------------------------------------------- NVD
def test_log4j_normalisation(nvd_items):
    rec = normalize_nvd_item(nvd_items[0])
    v = rec.vulnerability
    assert rec.source == "nvd" and v.cve_id == "CVE-2021-44228"
    assert (v.cvss_score, v.cvss_version, v.cvss_severity) == (10.0, "3.1", "CRITICAL")
    assert v.cvss_vector.startswith("CVSS:3.1/")
    assert v.nvd_status == "Analyzed"
    assert "CWE-917" in v.cwes and "CWE-502" in v.cwes
    assert rec.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert rec.published_at == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC)
    assert rec.observed_at == v.nvd_last_modified and rec.observed_at.tzinfo is not None
    assert v.affected_products and all(isinstance(p, str) for p in v.affected_products)
    assert rec.raw_payload == nvd_items[0]  # raw provenance kept verbatim
    assert v.kev_listed is None  # NVD restates KEV data, but KEV fields are owned by the CISA connector


def test_v2_severity_read_from_metric_level(nvd_items):
    metrics = extract_metrics(nvd_items[0]["cve"])
    v2 = [m for m in metrics if m.version == "2.0"]
    assert v2 and v2[0].base_severity == "HIGH" and v2[0].base_score == 9.3


def test_headline_prefers_v31_primary_then_v40(nvd_items):
    assert headline_metric(extract_metrics(nvd_items[0]["cve"])).type == "Primary"
    both = normalize_nvd_item(nvd_items[1]).vulnerability  # has v3.0 and v4.0
    assert both.cvss_version == "3.0" and {m.version for m in both.cvss_metrics} >= {"3.0", "4.0"}
    item = json.loads(json.dumps(nvd_items[1]))
    item["cve"]["metrics"].pop("cvssMetricV30")
    v40_only = normalize_nvd_item(item).vulnerability
    assert v40_only.cvss_version == "4.0" and v40_only.cvss_score is not None


def test_metrics_without_type_or_score_are_ignored():
    cve = {
        "metrics": {
            "ssvcV203": [{"source": "x", "ssvcData": {}}],
            "cvssMetricV31": [{"source": "x", "cvssData": {"version": "3.1"}}],
        }
    }
    assert extract_metrics(cve) == []


def test_parse_cpe_handles_escaped_colons():
    cpe = parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert cpe == {"part": "a", "vendor": "vendor", "product": "prod:uct", "version": "1.0"}
    assert parse_cpe("not-a-cpe") is None


def test_affected_products_include_ranges_and_only_vulnerable():
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.0.1",
                                "versionEndExcluding": "2.3.1",
                                "matchCriteriaId": "x",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:linux:kernel:-:*:*:*:*:*:*:*",
                                "matchCriteriaId": "y",
                            },
                        ],
                    }
                ]
            }
        ]
    }
    assert affected_products(cve) == ["apache log4j >=2.0.1 <2.3.1"]


def test_nvd_datetime_is_utc():
    assert parse_nvd_datetime("2021-12-10T10:15:09.143") == datetime(
        2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC
    )
    assert parse_nvd_datetime("garbage") is None


def test_invalid_nvd_item_rejected():
    with pytest.raises(ValueError):
        normalize_nvd_item({"cve": {}})


def test_date_windows_respect_120_day_limit():
    end = datetime(2026, 11, 20, tzinfo=UTC)
    windows = date_windows(end - timedelta(days=250), end)
    assert len(windows) == 3
    assert all((b - a).days <= 120 for a, b in windows)
    assert windows[0][0] == end - timedelta(days=250) and windows[-1][1] == end


def test_field_precedence_rules():
    assert may_overwrite("cvss_score", "cisa_kev", "nvd")
    assert not may_overwrite("vendor", "cisa_kev", "nvd")
    assert may_overwrite("description", "cisa_kev", "nvd")
    assert not may_overwrite("kev_listed", "cisa_kev", "nvd")
    assert not may_overwrite("vendor", None, "nvd")  # unknown provenance: only the top-ranked source
    assert may_overwrite("vendor", None, "cisa_kev")
    assert source_rank("vendor", "some_other_feed") == 2


# ---------------------------------------------------------------- ATT&CK
def test_attack_bundle_parsing(attack_bundle):
    result = parse_bundle(attack_bundle)
    keys = {r.entity_key for r in result.records}
    assert result.attack_version == "20.1"
    assert result.skipped_inactive == 2  # revoked technique + deprecated malware
    assert {"threat-actor:apt38", "threat-actor:lazarus-group", "campaign:operation-dream-job"} <= keys
    assert "attack-pattern:t1036-005" in keys  # techniques keyed by ATT&CK ID, not ambiguous names
    apt38 = next(r for r in result.records if r.entity_key == "threat-actor:apt38")
    assert apt38.intel.external_id == "G0082"
    assert "Bluenoroff" in apt38.intel.aliases and "APT38" not in apt38.intel.aliases
    assert apt38.source_url == "https://attack.mitre.org/groups/G0082"
    assert "(Citation:" not in (apt38.intel.description or "")
    assert apt38.confidence == 80 and apt38.tlp is None


def test_attack_relationships_explicit_only(attack_bundle):
    result = parse_bundle(attack_bundle)
    rels = {(r.entity_key, rel.rel_type, rel.dst_key) for r in result.records for rel in r.relationships}
    assert ("campaign:operation-dream-job", "attributed-to", "threat-actor:lazarus-group") in rels
    assert ("attack-pattern:t1036-005", "subtechnique-of", "attack-pattern:t1036") in rels
    assert any(t == "uses" for _, t, _ in rels)
    mentions = [r for r in rels if r[1] == "mentions"]
    assert ("campaign:sharepoint-toolshell-exploitation", "mentions", "CVE-2025-53770") in mentions
    sub = next(r for r in result.records if r.entity_key == "campaign:sharepoint-toolshell-exploitation")
    mention = next(rel for rel in sub.relationships if rel.rel_type == "mentions")
    assert "not a verified exploitation claim" in mention.description


def test_attack_technique_attributes(attack_bundle):
    result = parse_bundle(attack_bundle)
    t = next(r for r in result.records if r.entity_key == "attack-pattern:t1036-005")
    assert t.intel.attributes["tactics"] == ["defense-evasion"] or t.intel.attributes["tactics"]
    assert t.intel.attributes["is_subtechnique"] is True


def test_attack_dedup_across_domains(attack_bundle):
    seen: set[str] = set()
    first = parse_bundle(attack_bundle, seen)
    second = parse_bundle(attack_bundle, seen)
    assert first.records and not second.records


def test_attack_rejects_non_bundle():
    with pytest.raises(ValueError):
        parse_bundle({"type": "not-a-bundle"})


def test_clean_attack_text():
    text = "[APT38](https://attack.mitre.org/groups/G0082) is a group.(Citation: FireEye APT38 Oct 2018)"
    assert clean_attack_text(text) == "APT38 is a group."
