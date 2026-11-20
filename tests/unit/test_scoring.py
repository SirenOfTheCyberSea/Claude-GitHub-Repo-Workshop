from datetime import UTC, date, datetime, timedelta

from siren_threatwatch.prioritization.scoring import (
    SCORE_LABEL,
    ScoringWeights,
    band_for,
    score_indicator,
    score_vulnerability,
)

NOW = datetime(2026, 11, 20, tzinfo=UTC)


def _factor(result, name):
    return next(f for f in result.factors if f.name == name)


def test_kev_ransomware_recent_scores_high_and_is_explained():
    r = score_vulnerability(
        cve_id="CVE-1",
        kev_listed=True,
        kev_ransomware_use="Known",
        kev_date_added=date(2026, 11, 15),
        kev_due_date=date(2026, 11, 25),
        cvss_score=9.8,
        source_confidence=90,
        now=NOW,
    )
    assert r.band == "Critical" and r.score >= 80
    assert _factor(r, "CISA KEV").evidence == "source-reported"
    assert _factor(r, "CVSS severity").evidence == "computed"
    assert r.label == SCORE_LABEL and "not evidence of exploitation" in r.label
    assert "EPSS" in r.missing
    assert round(sum(f.points for f in r.factors), 1) >= r.score  # capped at 100


def test_missing_data_is_explicit_and_contributes_zero():
    r = score_vulnerability(cve_id="CVE-2", kev_listed=False, now=NOW)
    assert set(r.missing) >= {"Ransomware use", "CVSS severity", "EPSS", "Recency", "Source confidence"}
    for name in r.missing:
        assert _factor(r, name).points == 0
    assert r.score == 0 and r.band == "Informational"
    assert r.completeness < 0.5
    assert "Absence does not prove" in _factor(r, "CISA KEV").detail


def test_score_is_bounded_and_deterministic():
    kw = dict(
        cve_id="CVE-3",
        kev_listed=True,
        kev_ransomware_use="Known",
        kev_date_added=NOW.date(),
        kev_due_date=NOW.date(),
        cvss_score=10.0,
        epss_score=1.0,
        source_confidence=100,
        watched=True,
        now=NOW,
    )
    a, b = score_vulnerability(**kw), score_vulnerability(**kw)
    assert a.score == b.score == 100.0


def test_org_relevance_keyword_match():
    base = dict(
        cve_id="CVE-4", kev_listed=False, cvss_score=5.0, vendor="Fortinet", product="FortiOS", now=NOW
    )
    without = score_vulnerability(**base)
    with_kw = score_vulnerability(**base, relevant_keywords=["fortinet"])
    assert with_kw.score - without.score == ScoringWeights().org_relevance
    assert _factor(with_kw, "Organisational relevance").evidence == "analyst"


def test_recency_tiers():
    def rec(days):
        return _factor(
            score_vulnerability(
                cve_id="C", kev_listed=True, kev_date_added=(NOW - timedelta(days=days)).date(), now=NOW
            ),
            "Recency",
        ).points

    assert rec(5) == 10 and rec(60) == 5 and rec(400) == 0


def test_custom_weights():
    r = score_vulnerability(cve_id="C", kev_listed=True, now=NOW, weights=ScoringWeights(kev_listed=50))
    assert _factor(r, "CISA KEV").points == 50


def test_bands():
    assert [band_for(x) for x in (95, 65, 45, 20, 5)] == [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ]


def test_indicator_scoring():
    fresh = score_indicator(
        ioc_type="domain", confidence=90, last_seen_at=NOW - timedelta(days=1), linked_threats=2, now=NOW
    )
    stale = score_indicator(ioc_type="domain", confidence=90, last_seen_at=NOW - timedelta(days=200), now=NOW)
    private = score_indicator(ioc_type="ipv4", confidence=90, last_seen_at=NOW, is_routable=False, now=NOW)
    assert fresh.score > stale.score
    assert any(f.name == "Non-routable address" and f.points < 0 for f in private.factors)
    assert score_indicator(ioc_type="md5", confidence=None, last_seen_at=None, now=NOW).missing


def test_explain_text():
    text = score_vulnerability(cve_id="CVE-5", kev_listed=True, now=NOW).explain()
    assert "CISA KEV" in text and "[source-reported]" in text and "/100" in text
