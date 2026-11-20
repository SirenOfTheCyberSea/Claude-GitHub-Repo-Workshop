from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from siren_threatwatch.connectors.base import ConnectorError, FetchResult
from siren_threatwatch.connectors.cisa_kev import parse_catalog
from siren_threatwatch.connectors.demo import build_demo_records
from siren_threatwatch.normalization.kev import KEV_CATALOG_URL, normalize_kev_entry
from siren_threatwatch.normalization.schema import (
    TLP,
    EntityKind,
    NormalizedRecord,
    canonical_article_url,
    canonical_cve,
    clean_text,
    parse_tlp,
    safe_http_url,
)


def test_normalize_kev_entry_maps_all_fields(kev_payload):
    item = kev_payload["vulnerabilities"][0]
    rec = normalize_kev_entry(item, datetime(2026, 11, 18, tzinfo=UTC))
    v = rec.vulnerability
    assert rec.source == "cisa_kev" and rec.entity_kind == EntityKind.VULNERABILITY
    assert rec.external_id == v.cve_id == item["cveID"]
    assert v.vendor == item["vendorProject"] and v.product == item["product"]
    assert v.kev_listed is True
    assert v.kev_date_added == date.fromisoformat(item["dateAdded"])
    assert v.kev_due_date == date.fromisoformat(item["dueDate"])
    assert v.kev_ransomware_use == item["knownRansomwareCampaignUse"]
    assert v.cwes == sorted(item["cwes"])
    assert rec.published_at == datetime.fromisoformat(item["dateAdded"]).replace(tzinfo=UTC)
    assert rec.observed_at == datetime(2026, 11, 18, tzinfo=UTC)
    assert rec.source_url == KEV_CATALOG_URL
    assert rec.tlp is None  # KEV does not supply TLP; we never invent one
    assert rec.raw_payload == item  # raw provenance kept verbatim (incl. unknown fields)
    assert f"https://nvd.nist.gov/vuln/detail/{v.cve_id}" in v.references
    assert all(r.startswith(("http://", "https://")) for r in v.references)


def test_parse_catalog_rejects_bad_entries_and_dedupes(kev_payload):
    result = parse_catalog(kev_payload, FetchResult())
    ids = [r.external_id for r in result.records]
    assert ids == ["CVE-2024-10441", "CVE-2026-40217", "CVE-2026-59310"]  # duplicate collapsed
    assert result.rejected == 2
    assert any("NOT-A-CVE" in s for s in result.rejection_samples)
    assert result.details["catalog_version"] == "2026.11.18"


@pytest.mark.parametrize("payload", [[], {"vulnerabilities": "nope"}, {"foo": 1}, None])
def test_parse_catalog_schema_errors(payload):
    with pytest.raises(ConnectorError):
        parse_catalog(payload, FetchResult())


def test_kev_entry_tolerates_odd_values():
    rec = normalize_kev_entry(
        {
            "cveID": " cve-2023-1234 ",
            "dateAdded": "garbage",
            "knownRansomwareCampaignUse": "x",
            "cwes": "not-a-list",
            "notes": "see https://vendor.example/a; and javascript:x",
        }
    )
    assert rec.vulnerability.cve_id == "CVE-2023-1234"
    assert rec.vulnerability.kev_date_added is None
    assert rec.vulnerability.kev_ransomware_use is None
    assert "https://vendor.example/a" in rec.vulnerability.references
    assert not any("javascript" in r for r in rec.vulnerability.references)


def test_clean_text_strips_control_chars_and_caps():
    assert clean_text("a\x00b\x1bc  ") == "abc"
    assert clean_text("") is None
    assert len(clean_text("x" * 50_000)) == 20_000
    assert clean_text("<script>alert(1)</script>") == "<script>alert(1)</script>"  # escaped at render time


def test_safe_http_url():
    assert safe_http_url("https://example.com/a") == "https://example.com/a"
    for bad in (
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://",
        'https://a.com/"onmouseover=x',
        None,
    ):
        assert safe_http_url(bad) is None


def test_tlp_parsing():
    assert parse_tlp("white") == TLP.CLEAR
    assert parse_tlp("TLP:AMBER+STRICT") == TLP.AMBER_STRICT
    assert parse_tlp("tlp:red") == TLP.RED
    assert parse_tlp("purple") is None


def test_canonical_helpers():
    assert canonical_cve("cve-2021-44228") == "CVE-2021-44228"
    with pytest.raises(ValueError):
        canonical_cve("CVE-21-1")
    assert canonical_article_url(
        "HTTPS://Blog.Example.com/post/?utm_source=x&id=2#top"
    ) == canonical_article_url("https://blog.example.com/post?id=2")


def test_record_requires_matching_block():
    with pytest.raises(ValidationError):
        NormalizedRecord(
            source="t",
            entity_kind=EntityKind.INDICATOR,
            external_id="x",
            title="t",
            vulnerability={"cve_id": "CVE-2024-0001"},
        )


def test_record_rejects_bad_confidence_and_strips_unsafe_url():
    with pytest.raises(ValidationError):
        NormalizedRecord(
            source="t",
            entity_kind=EntityKind.VULNERABILITY,
            external_id="x",
            title="t",
            confidence=150,
            vulnerability={"cve_id": "CVE-2024-0001"},
        )
    rec = NormalizedRecord(
        source="t",
        entity_kind=EntityKind.VULNERABILITY,
        external_id="x",
        title="t",
        source_url="javascript:alert(1)",
        vulnerability={"cve_id": "CVE-2024-0001"},
    )
    assert rec.source_url is None


def test_observation_hash_ignores_ingestion_time():
    kw = dict(
        source="t",
        entity_kind=EntityKind.VULNERABILITY,
        external_id="x",
        title="t",
        vulnerability={"cve_id": "CVE-2024-0001"},
    )
    a = NormalizedRecord(ingested_at=datetime(2024, 1, 1, tzinfo=UTC), **kw)
    b = NormalizedRecord(ingested_at=datetime(2025, 1, 1, tzinfo=UTC), **kw)
    assert a.observation_hash() == b.observation_hash()
    c = NormalizedRecord(description="changed", **kw)
    assert c.observation_hash() != a.observation_hash()


def test_demo_dataset_is_valid_and_labelled():
    result = build_demo_records()
    assert result.rejected == 0, result.rejection_samples
    assert len(result.records) >= 30
    assert all(r.is_synthetic for r in result.records)
    assert all("SYNTHETIC" in (r.description or "") for r in result.records)
    for r in result.records:
        if r.indicator and r.indicator.ioc_type.value in ("ipv4", "ipv6"):
            assert r.indicator.is_routable is False  # documentation / private ranges only
        if r.vulnerability:
            assert r.vulnerability.cve_id.startswith("CVE-2099-")
