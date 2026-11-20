"""Applies scoring to stored entities and persists results."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from siren_threatwatch.config import Settings
from siren_threatwatch.db.models import (
    INDICATOR,
    INTEL,
    VULNERABILITY,
    Indicator,
    Observation,
    PriorityScore,
    Relationship,
    Vulnerability,
    WatchlistEntry,
)
from siren_threatwatch.prioritization.scoring import PriorityResult, score_indicator, score_vulnerability


def _watch_sets(session: Session) -> tuple[set[tuple[str, str]], list[str]]:
    exact: set[tuple[str, str]] = set()
    keywords: list[str] = []
    for w in session.scalars(select(WatchlistEntry).where(WatchlistEntry.active.is_(True))):
        if w.entity_kind == "keyword":
            keywords.append(w.value.lower())
        else:
            exact.add((w.entity_kind, w.value))
    return exact, keywords


def rescore_all(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[tuple[str, str], PriorityResult]:
    """Recompute every priority score (age-based factors change daily, so we rescore all)."""
    now = now or datetime.now(UTC)
    exact, watch_keywords = _watch_sets(session)
    keywords = list(dict.fromkeys([*settings.org_relevant_keywords, *watch_keywords]))

    max_conf = dict(
        session.execute(
            select(Observation.entity_key, func.max(Observation.confidence))
            .where(Observation.entity_kind == VULNERABILITY)
            .group_by(Observation.entity_key)
        ).all()
    )
    threat_refs: dict[str, int] = {}
    for dst_key, n in session.execute(
        select(Relationship.dst_key, func.count(func.distinct(Relationship.src_key)))
        .where(
            Relationship.src_kind == INTEL,
            Relationship.dst_kind == VULNERABILITY,
            # ATT&CK technique pages cite CVEs as generic examples; only actor/campaign/software count.
            Relationship.src_key.not_like("attack-pattern:%"),
        )
        .group_by(Relationship.dst_key)
    ).all():
        threat_refs[dst_key] = int(n)
    results: dict[tuple[str, str], PriorityResult] = {}
    for v in session.scalars(select(Vulnerability)):
        results[(VULNERABILITY, v.cve_id)] = score_vulnerability(
            cve_id=v.cve_id,
            kev_listed=v.kev_listed,
            kev_ransomware_use=v.kev_ransomware_use,
            kev_date_added=v.kev_date_added,
            kev_due_date=v.kev_due_date,
            cvss_score=v.cvss_score,
            cvss_severity=v.cvss_severity,
            epss_score=v.epss_score,
            published_at=v.published_at,
            vendor=v.vendor,
            product=v.product,
            source_confidence=max_conf.get(v.cve_id),
            watched=(VULNERABILITY, v.cve_id) in exact,
            relevant_keywords=keywords,
            threat_references=threat_refs.get(v.cve_id, 0),
            now=now,
        )

    threat_links: dict[str, int] = {}
    for src_key, dst_kind in session.execute(
        select(Relationship.src_key, Relationship.dst_kind).where(Relationship.src_kind == INDICATOR)
    ):
        if dst_kind == INTEL:
            threat_links[src_key] = threat_links.get(src_key, 0) + 1
    for i in session.scalars(select(Indicator)):
        results[(INDICATOR, i.entity_key)] = score_indicator(
            ioc_type=i.ioc_type,
            confidence=i.confidence,
            last_seen_at=i.last_seen_at,
            is_routable=i.is_routable,
            linked_threats=threat_links.get(i.entity_key, 0),
            watched=(INDICATOR, i.entity_key) in exact,
            now=now,
        )

    existing = {(p.entity_kind, p.entity_key): p for p in session.scalars(select(PriorityScore))}
    for (kind, key), res in results.items():
        row = existing.get((kind, key))
        if row is None:
            row = PriorityScore(entity_kind=kind, entity_key=key, score=0, band="")
            session.add(row)
        row.score = res.score
        row.band = res.band
        row.factors = res.factors_as_dicts()
        row.missing = res.missing
        row.computed_at = now
    session.flush()
    return results
