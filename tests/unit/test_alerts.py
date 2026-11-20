from sqlalchemy import func, select

from siren_threatwatch.alerts.engine import AlertCandidate, WatchItem, build_candidates, persist_alerts
from siren_threatwatch.db.models import Alert
from siren_threatwatch.db.repository import EntityChange
from siren_threatwatch.prioritization.scoring import PriorityResult

HIGH = PriorityResult(score=85, band="Critical")
LOW = PriorityResult(score=20, band="Low")
V = "vulnerability"


def _build(changes, scores, watches=(), baseline=False, texts=None):
    return build_candidates(changes, scores, list(watches), texts or {}, min_score=60, baseline=baseline)


def test_new_high_priority_alert():
    out = _build([EntityChange(V, "CVE-1", True)], {(V, "CVE-1"): HIGH})
    assert [c.alert_type for c in out] == ["new_high_priority"]
    assert out[0].dedup_key == "new-high:vulnerability:CVE-1"
    assert out[0].severity == "Critical"


def test_low_priority_does_not_alert():
    assert _build([EntityChange(V, "CVE-1", True)], {(V, "CVE-1"): LOW}) == []


def test_baseline_suppresses_new_high_but_not_watch_matches():
    watches = [WatchItem(1, "keyword", "fortinet")]
    texts = {(V, "CVE-1"): "CVE-1 Fortinet FortiOS"}
    out = _build([EntityChange(V, "CVE-1", True)], {(V, "CVE-1"): HIGH}, watches, baseline=True, texts=texts)
    assert [c.alert_type for c in out] == ["watch_match"]


def test_kev_added_alert_for_existing_cve():
    ch = EntityChange(V, "CVE-1", False, {"kev_listed": (False, True)})
    out = _build([ch], {(V, "CVE-1"): HIGH})
    assert any(c.alert_type == "kev_added" and c.dedup_key == "kev-added:CVE-1" for c in out)


def test_watch_change_only_for_material_fields():
    watches = [WatchItem(7, V, "CVE-1")]
    immaterial = EntityChange(V, "CVE-1", False, {"title": ("a", "b")})
    material = EntityChange(V, "CVE-1", False, {"kev_ransomware_use": ("Unknown", "Known")})
    assert _build([immaterial], {}, watches) == []
    out = _build([material], {}, watches)
    assert len(out) == 1 and out[0].alert_type == "watch_change"
    assert "Unknown → Known" in out[0].detail


def test_same_change_produces_same_dedup_key_different_change_differs():
    watches = [WatchItem(7, V, "CVE-1")]
    a = _build([EntityChange(V, "CVE-1", False, {"cvss_score": (5.0, 9.0)})], {}, watches)[0]
    b = _build([EntityChange(V, "CVE-1", False, {"cvss_score": (5.0, 9.0)})], {}, watches)[0]
    c = _build([EntityChange(V, "CVE-1", False, {"cvss_score": (9.0, 7.0)})], {}, watches)[0]
    assert a.dedup_key == b.dedup_key != c.dedup_key


def test_unwatched_change_does_not_alert():
    ch = EntityChange(V, "CVE-9", False, {"cvss_score": (5.0, 9.0)})
    assert _build([ch], {}, [WatchItem(1, V, "CVE-1")]) == []


def test_persist_alerts_deduplicates(session):
    cand = AlertCandidate("k1", "new_high_priority", V, "CVE-1", "t", "d", "High")
    assert persist_alerts(session, [cand, cand]) == 1
    assert persist_alerts(session, [cand]) == 0  # never notify twice
    assert session.scalar(select(func.count()).select_from(Alert)) == 1


def test_synthetic_marked_in_title():
    out = _build([EntityChange(V, "CVE-2099-0001", True, is_synthetic=True)], {(V, "CVE-2099-0001"): HIGH})
    assert "[SYNTHETIC]" in out[0].title
