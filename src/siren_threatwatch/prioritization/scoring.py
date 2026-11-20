"""Explainable, additive prioritisation.

Every score is the sum of named factors, each with points, a human-readable explanation and an
``evidence`` class:

* ``source-reported`` — a fact stated by a cited source (e.g. "CISA KEV lists this CVE").
* ``computed`` — derived by this tool (e.g. age, scaled CVSS). **Not evidence of exploitation.**
* ``analyst`` — organisational relevance or watchlist membership configured by you.
* ``missing`` — the input was unavailable; contributes 0 points and is listed explicitly.

The overall result is always labelled as a *computed priority*, never as verified exploitation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from typing import Any, Literal

Evidence = Literal["source-reported", "computed", "analyst", "missing"]
SCORE_LABEL = "Computed priority — a triage aid, not evidence of exploitation"


@dataclass(frozen=True)
class ScoringWeights:
    kev_listed: float = 35
    ransomware_known: float = 15
    cvss_max: float = 30
    epss_max: float = 10
    recent_30d: float = 10
    recent_90d: float = 5
    due_date_near: float = 5
    org_relevance: float = 15
    source_confidence_max: float = 5
    threat_association: float = 5
    # indicators
    ioc_confidence_max: float = 40
    ioc_recent_7d: float = 20
    ioc_recent_30d: float = 10
    ioc_linked_threat: float = 20


BANDS: tuple[tuple[float, str], ...] = ((80, "Critical"), (60, "High"), (40, "Medium"), (15, "Low"))


def band_for(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "Informational"


@dataclass
class ScoreFactor:
    name: str
    points: float
    detail: str
    evidence: Evidence


@dataclass
class PriorityResult:
    score: float
    band: str
    factors: list[ScoreFactor] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    label: str = SCORE_LABEL

    @property
    def completeness(self) -> float:
        """Share of factors for which input data was available (0-1)."""
        total = len(self.factors)
        return 0.0 if not total else 1 - len(self.missing) / total

    def factors_as_dicts(self) -> list[dict[str, Any]]:
        return [asdict(f) for f in self.factors]

    def explain(self) -> str:
        lines = [f"{self.score:.0f}/100 ({self.band}) — {self.label}"]
        for f in self.factors:
            sign = "+" if f.points >= 0 else ""
            lines.append(f"  {sign}{f.points:.1f}  [{f.evidence}] {f.name}: {f.detail}")
        return "\n".join(lines)


def _finish(factors: list[ScoreFactor]) -> PriorityResult:
    total = max(0.0, min(100.0, sum(f.points for f in factors)))
    total = round(total, 1)
    missing = [f.name for f in factors if f.evidence == "missing"]
    return PriorityResult(score=total, band=band_for(total), factors=factors, missing=missing)


def _age_days(when: date | datetime | None, now: datetime) -> int | None:
    if when is None:
        return None
    if isinstance(when, datetime):
        when_dt = when if when.tzinfo else when.replace(tzinfo=UTC)
        return max(0, (now - when_dt).days)
    return max(0, (now.date() - when).days)


def matches_keywords(text_fields: list[str | None], keywords: list[str]) -> str | None:
    haystack = " ".join(t.lower() for t in text_fields if t)
    for kw in keywords:
        if kw and kw.lower() in haystack:
            return kw
    return None


def score_vulnerability(
    *,
    cve_id: str,
    kev_listed: bool,
    kev_ransomware_use: str | None = None,
    kev_date_added: date | None = None,
    kev_due_date: date | None = None,
    cvss_score: float | None = None,
    cvss_severity: str | None = None,
    epss_score: float | None = None,
    published_at: datetime | None = None,
    vendor: str | None = None,
    product: str | None = None,
    source_confidence: int | None = None,
    watched: bool = False,
    relevant_keywords: list[str] | None = None,
    threat_references: int = 0,
    now: datetime | None = None,
    weights: ScoringWeights | None = None,
) -> PriorityResult:
    w = weights or ScoringWeights()
    now = now or datetime.now(UTC)
    f: list[ScoreFactor] = []

    if kev_listed:
        when = f" (added {kev_date_added.isoformat()})" if kev_date_added else ""
        f.append(
            ScoreFactor(
                "CISA KEV",
                w.kev_listed,
                f"CISA's KEV catalog lists {cve_id} as exploited in the wild{when}.",
                "source-reported",
            )
        )
    else:
        f.append(
            ScoreFactor(
                "CISA KEV",
                0,
                "Not in the CISA KEV catalog. Absence does not prove it is unexploited.",
                "computed",
            )
        )

    if kev_ransomware_use == "Known":
        f.append(
            ScoreFactor(
                "Ransomware use",
                w.ransomware_known,
                "CISA reports known use in ransomware campaigns.",
                "source-reported",
            )
        )
    elif kev_ransomware_use == "Unknown":
        f.append(
            ScoreFactor("Ransomware use", 0, "CISA reports ransomware use as 'Unknown'.", "source-reported")
        )
    else:
        f.append(ScoreFactor("Ransomware use", 0, "No ransomware-use information available.", "missing"))

    if cvss_score is not None:
        pts = round(cvss_score / 10 * w.cvss_max, 1)
        sev = f" ({cvss_severity})" if cvss_severity else ""
        f.append(
            ScoreFactor(
                "CVSS severity", pts, f"CVSS base score {cvss_score:.1f}{sev} scaled to {pts}.", "computed"
            )
        )
    else:
        f.append(
            ScoreFactor(
                "CVSS severity", 0, "CVSS base score unavailable (e.g. not yet enriched from NVD).", "missing"
            )
        )

    if epss_score is not None:
        pts = round(epss_score * w.epss_max, 1)
        f.append(ScoreFactor("EPSS", pts, f"EPSS probability {epss_score:.3f} scaled to {pts}.", "computed"))
    else:
        f.append(ScoreFactor("EPSS", 0, "EPSS not available (no EPSS integration configured).", "missing"))

    age = _age_days(kev_date_added or published_at, now)
    if age is None:
        f.append(ScoreFactor("Recency", 0, "No publication / KEV date available.", "missing"))
    elif age <= 30:
        f.append(
            ScoreFactor("Recency", w.recent_30d, f"Published or added {age} day(s) ago (≤30).", "computed")
        )
    elif age <= 90:
        f.append(
            ScoreFactor("Recency", w.recent_90d, f"Published or added {age} day(s) ago (≤90).", "computed")
        )
    else:
        f.append(ScoreFactor("Recency", 0, f"Published or added {age} day(s) ago.", "computed"))

    if kev_due_date is not None:
        days_left = (kev_due_date - now.date()).days
        if days_left <= 14:
            state = "passed" if days_left < 0 else f"in {days_left} day(s)"
            f.append(
                ScoreFactor(
                    "Remediation due date",
                    w.due_date_near,
                    f"CISA federal remediation due date {kev_due_date.isoformat()} ({state}).",
                    "source-reported",
                )
            )
        else:
            f.append(
                ScoreFactor(
                    "Remediation due date", 0, f"CISA due date {kev_due_date.isoformat()}.", "source-reported"
                )
            )

    kw = matches_keywords([vendor, product], relevant_keywords or [])
    if watched or kw:
        why = "on your watchlist" if watched else f"matches organisational keyword '{kw}'"
        f.append(
            ScoreFactor("Organisational relevance", w.org_relevance, f"Affected product {why}.", "analyst")
        )
    else:
        f.append(
            ScoreFactor(
                "Organisational relevance", 0, "No match to configured keywords or watchlist.", "analyst"
            )
        )

    if threat_references:
        f.append(
            ScoreFactor(
                "Threat activity references",
                w.threat_association,
                f"Referenced by {threat_references} actor/campaign/software entr"
                f"{'y' if threat_references == 1 else 'ies'} (e.g. MITRE ATT&CK). Source text only — not proof "
                "of attribution or of exploitation against you.",
                "source-reported",
            )
        )

    if source_confidence is not None:
        pts = round(source_confidence / 100 * w.source_confidence_max, 1)
        f.append(
            ScoreFactor(
                "Source confidence", pts, f"Highest source confidence {source_confidence}/100.", "computed"
            )
        )
    else:
        f.append(ScoreFactor("Source confidence", 0, "No source confidence supplied.", "missing"))
    return _finish(f)


def score_indicator(
    *,
    ioc_type: str,
    confidence: int | None,
    last_seen_at: datetime | None,
    is_routable: bool | None = None,
    linked_threats: int = 0,
    watched: bool = False,
    now: datetime | None = None,
    weights: ScoringWeights | None = None,
) -> PriorityResult:
    w = weights or ScoringWeights()
    now = now or datetime.now(UTC)
    f: list[ScoreFactor] = []
    if confidence is not None:
        pts = round(confidence / 100 * w.ioc_confidence_max, 1)
        f.append(ScoreFactor("Source confidence", pts, f"Source confidence {confidence}/100.", "computed"))
    else:
        f.append(ScoreFactor("Source confidence", 0, "No source confidence supplied.", "missing"))

    age = _age_days(last_seen_at, now)
    if age is None:
        f.append(ScoreFactor("Recency", 0, "No sighting date available.", "missing"))
    elif age <= 7:
        f.append(ScoreFactor("Recency", w.ioc_recent_7d, f"Last reported {age} day(s) ago.", "computed"))
    elif age <= 30:
        f.append(ScoreFactor("Recency", w.ioc_recent_30d, f"Last reported {age} day(s) ago.", "computed"))
    else:
        f.append(ScoreFactor("Recency", 0, f"Last reported {age} day(s) ago — may be stale.", "computed"))

    if linked_threats:
        f.append(
            ScoreFactor(
                "Linked threats",
                w.ioc_linked_threat,
                f"{linked_threats} source-evidenced relationship(s) to malware/campaigns/actors.",
                "source-reported",
            )
        )
    else:
        f.append(ScoreFactor("Linked threats", 0, "No source-evidenced relationships.", "computed"))

    if watched:
        f.append(ScoreFactor("Organisational relevance", w.org_relevance, "On your watchlist.", "analyst"))

    if is_routable is False:
        f.append(
            ScoreFactor(
                "Non-routable address",
                -10,
                "Private/reserved/documentation range — limited external relevance.",
                "computed",
            )
        )
    return _finish(f)
