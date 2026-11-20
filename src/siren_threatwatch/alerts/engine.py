"""Alert generation with de-duplication.

Alert types
-----------
* ``new_high_priority`` — a newly ingested record whose computed priority ≥ ``alert_min_score``.
  Suppressed during a source's *baseline* (first successful) ingestion, which instead raises a single
  ``baseline`` summary alert, to avoid flooding analysts with thousands of alerts on day one.
* ``kev_added`` — an already-known CVE newly appears in CISA KEV.
* ``watch_match`` — a new record matches a watchlist entry.
* ``watch_change`` — a material change to a watched record. Keyed by a signature of the change so the
  same change never alerts twice.

Every alert has a unique ``dedup_key``; inserting an existing key is a no-op.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from siren_threatwatch.db.models import VULNERABILITY, Alert, Indicator, Vulnerability, WatchlistEntry
from siren_threatwatch.db.repository import MATERIAL_VULN_FIELDS, EntityChange
from siren_threatwatch.prioritization.scoring import PriorityResult

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class AlertCandidate:
    dedup_key: str
    alert_type: str
    entity_kind: str
    entity_key: str
    title: str
    detail: str
    severity: str


@dataclass(frozen=True)
class WatchItem:
    id: int
    entity_kind: str  # vulnerability | indicator | intel | keyword
    value: str
    label: str | None = None


def _severity(result: PriorityResult | None, default: str = "Medium") -> str:
    if result is None:
        return default
    return result.band if result.band in ("Critical", "High", "Medium", "Low") else "Low"


def watch_matches(
    change: EntityChange, searchable_text: str, watches: Sequence[WatchItem]
) -> list[WatchItem]:
    hits = []
    text = searchable_text.lower()
    for w in watches:
        if w.entity_kind == "keyword":
            if w.value.lower() in text:
                hits.append(w)
        elif w.entity_kind == change.kind and w.value == change.key:
            hits.append(w)
    return hits


def build_candidates(
    changes: Iterable[EntityChange],
    scores: dict[tuple[str, str], PriorityResult],
    watches: Sequence[WatchItem],
    texts: dict[tuple[str, str], str],
    *,
    min_score: float,
    baseline: bool,
) -> list[AlertCandidate]:
    """Pure function: decide which alerts a batch of entity changes should raise."""
    out: list[AlertCandidate] = []
    for ch in changes:
        ref = (ch.kind, ch.key)
        res = scores.get(ref)
        hits = watch_matches(ch, texts.get(ref, ch.key), watches)
        synthetic = " [SYNTHETIC]" if ch.is_synthetic else ""
        if ch.is_new:
            if res is not None and res.score >= min_score and not baseline:
                out.append(
                    AlertCandidate(
                        f"new-high:{ch.kind}:{ch.key}",
                        "new_high_priority",
                        ch.kind,
                        ch.key,
                        f"New {res.band.lower()}-priority {ch.kind}: {ch.key}{synthetic}",
                        f"Computed priority {res.score:.0f}/100 ({res.label}).",
                        _severity(res),
                    )
                )
            for w in hits:
                out.append(
                    AlertCandidate(
                        f"watch:{w.id}:{ch.kind}:{ch.key}:new",
                        "watch_match",
                        ch.kind,
                        ch.key,
                        f"Watchlist match '{w.label or w.value}': {ch.key}{synthetic}",
                        "A newly ingested record matches your watchlist.",
                        _severity(res, "High"),
                    )
                )
            continue

        if ch.kind == VULNERABILITY and "kev_listed" in ch.changed_fields:
            old, new = ch.changed_fields["kev_listed"]
            if new and not old:
                out.append(
                    AlertCandidate(
                        f"kev-added:{ch.key}",
                        "kev_added",
                        ch.kind,
                        ch.key,
                        f"{ch.key} added to CISA KEV{synthetic}",
                        "CISA now lists this CVE as known exploited.",
                        "High",
                    )
                )
        material = {
            k: v
            for k, v in ch.changed_fields.items()
            if ch.kind != VULNERABILITY or k in MATERIAL_VULN_FIELDS
        }
        if material and hits:
            summary = "; ".join(f"{k}: {a!s} → {b!s}" for k, (a, b) in sorted(material.items()))[:1000]
            signature = EntityChange(ch.kind, ch.key, False, material).change_signature[:16]
            for w in hits:
                out.append(
                    AlertCandidate(
                        f"watch-change:{w.id}:{ch.kind}:{ch.key}:{signature}",
                        "watch_change",
                        ch.kind,
                        ch.key,
                        f"Watched {ch.kind} changed: {ch.key}{synthetic}",
                        summary,
                        _severity(res, "Medium"),
                    )
                )
    return out


def load_watches(session: Session) -> list[WatchItem]:
    return [
        WatchItem(w.id, w.entity_kind, w.value, w.label)
        for w in session.scalars(select(WatchlistEntry).where(WatchlistEntry.active.is_(True)))
    ]


def searchable_texts(session: Session, changes: Sequence[EntityChange]) -> dict[tuple[str, str], str]:
    texts: dict[tuple[str, str], str] = {}
    cves = [c.key for c in changes if c.kind == VULNERABILITY]
    for i in range(0, len(cves), 500):
        for v in session.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(cves[i : i + 500]))):
            texts[(VULNERABILITY, v.cve_id)] = " ".join(
                x for x in (v.cve_id, v.vendor, v.product, v.title) if x
            )
    for c in changes:
        if c.kind != VULNERABILITY:
            texts.setdefault((c.kind, c.key), c.key)
    return texts


def persist_alerts(
    session: Session, candidates: Sequence[AlertCandidate], now: datetime | None = None
) -> int:
    """Insert candidates whose dedup_key is not already present. Returns number created."""
    if not candidates:
        return 0
    now = now or datetime.now(UTC)
    keys = list({c.dedup_key for c in candidates})
    existing: set[str] = set()
    for i in range(0, len(keys), 500):
        existing |= set(
            session.scalars(select(Alert.dedup_key).where(Alert.dedup_key.in_(keys[i : i + 500])))
        )
    created = 0
    for c in candidates:
        if c.dedup_key in existing:
            continue
        existing.add(c.dedup_key)
        session.add(
            Alert(
                dedup_key=c.dedup_key,
                alert_type=c.alert_type,
                entity_kind=c.entity_kind,
                entity_key=c.entity_key,
                title=c.title[:500],
                detail=c.detail,
                severity=c.severity,
                created_at=now,
            )
        )
        created += 1
        log.info("alert created", extra={"alert_type": c.alert_type, "entity": c.entity_key})
    session.flush()
    return created


def evaluate_and_store(
    session: Session,
    changes: Sequence[EntityChange],
    scores: dict[tuple[str, str], PriorityResult],
    *,
    min_score: float,
    baseline: bool,
    source: str,
    run_id: int,
) -> int:
    watches = load_watches(session)
    candidates = build_candidates(
        changes, scores, watches, searchable_texts(session, changes), min_score=min_score, baseline=baseline
    )
    if baseline and changes:
        new_count = sum(1 for c in changes if c.is_new)
        candidates.append(
            AlertCandidate(
                f"baseline:{source}",
                "baseline",
                "source",
                source,
                f"Baseline ingestion from {source}: {new_count} records",
                "Per-record 'new high-priority' alerts are suppressed on a source's first ingestion. "
                "Use the Overview and CVE Explorer to triage.",
                "Low",
            )
        )
    return persist_alerts(session, candidates)


def ioc_text(ind: Indicator) -> str:
    return f"{ind.ioc_type}:{ind.value} {ind.original_value}"
