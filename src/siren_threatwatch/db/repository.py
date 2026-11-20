"""Persistence, de-duplication and merge logic.

De-duplication rules
--------------------
* Vulnerabilities: one canonical row per CVE ID (upper-cased).
* Indicators: one row per ``(type, canonical value)`` — e.g. ``hxxp://Evil[.]com`` == ``http://evil.com/``.
* Intel objects: one row per ``(kind, slug(name))``; aliases are merged.
* Observations: one row per ``(source, entity, normalised-content hash)``. Re-seeing identical content
  increments ``sighting_count``/``last_seen_at``; changed content creates a *new* observation, so the
  history of what each source said, and when, is preserved. Attribution is never discarded.
* Raw payloads: one row per ``(source, payload hash)``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from siren_threatwatch.db.models import (
    INDICATOR,
    INTEL,
    VULNERABILITY,
    ChangeEvent,
    Indicator,
    IngestionRun,
    IntelObject,
    Observation,
    RawRecord,
    Relationship,
    Source,
    Vulnerability,
)
from siren_threatwatch.normalization.schema import NormalizedRecord, content_hash

CHUNK = 500
# Fields on Vulnerability that a source may set; tracked for change detection.
VULN_FIELDS = (
    "title",
    "description",
    "vendor",
    "product",
    "cwes",
    "cvss_score",
    "cvss_vector",
    "cvss_version",
    "cvss_severity",
    "kev_listed",
    "kev_date_added",
    "kev_due_date",
    "kev_required_action",
    "kev_ransomware_use",
    "kev_notes",
)
# Changes to these fields are "material" for watchlist alerts.
MATERIAL_VULN_FIELDS = frozenset(
    {"kev_listed", "kev_ransomware_use", "kev_due_date", "cvss_score", "kev_required_action"}
)


@dataclass
class EntityChange:
    kind: str
    key: str
    is_new: bool
    changed_fields: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    is_synthetic: bool = False

    @property
    def change_signature(self) -> str:
        return content_hash({k: [str(a), str(b)] for k, (a, b) in sorted(self.changed_fields.items())})


@dataclass
class PersistStats:
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    changes: list[EntityChange] = field(default_factory=list)


def _chunks(items: Sequence[Any], size: int = CHUNK) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _str(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def ensure_source(session: Session, name: str, display_name: str) -> Source:
    src = session.scalar(select(Source).where(Source.name == name))
    if src is None:
        src = Source(name=name, display_name=display_name)
        session.add(src)
        session.flush()
    return src


class Persister:
    """Writes a batch of normalised records from one ingestion run."""

    def __init__(self, session: Session, run: IngestionRun, now: datetime | None = None) -> None:
        self.s = session
        self.run = run
        self.now = now or datetime.now(UTC)
        self.stats = PersistStats()

    # -- public ---------------------------------------------------------
    def persist(self, records: Sequence[NormalizedRecord]) -> PersistStats:
        raw_ids = self._persist_raw(records)
        vulns = self._prefetch_vulns([r for r in records if r.vulnerability])
        iocs = self._prefetch_indicators([r for r in records if r.indicator])
        intel = self._prefetch_intel([r for r in records if r.intel])
        obs = self._prefetch_observations(records)

        for rec in records:
            if rec.vulnerability:
                change = self._upsert_vuln(rec, vulns)
            elif rec.indicator:
                change = self._upsert_indicator(rec, iocs)
            else:
                change = self._upsert_intel(rec, intel)
            self._upsert_observation(rec, raw_ids.get(rec.raw_hash), obs)
            for rel in rec.relationships:
                self._upsert_relationship(rec, rel, raw_ids.get(rec.raw_hash))

            if change.is_new:
                self.stats.new += 1
            elif change.changed_fields:
                self.stats.updated += 1
                for fname, (old, new) in change.changed_fields.items():
                    self.s.add(
                        ChangeEvent(
                            entity_kind=change.kind,
                            entity_key=change.key,
                            field=fname,
                            old_value=_str(old),
                            new_value=_str(new),
                            source=rec.source,
                            run_id=self.run.id,
                            changed_at=self.now,
                        )
                    )
            else:
                self.stats.unchanged += 1
            if change.is_new or change.changed_fields:
                self.stats.changes.append(change)
        self.s.flush()
        return self.stats

    # -- raw provenance ---------------------------------------------------
    def _persist_raw(self, records: Sequence[NormalizedRecord]) -> dict[str, int]:
        by_hash = {r.raw_hash: r for r in records}
        existing: dict[str, RawRecord] = {}
        hashes = list(by_hash)
        source = records[0].source if records else ""
        for chunk in _chunks(hashes):
            for row in self.s.scalars(
                select(RawRecord).where(RawRecord.source == source, RawRecord.content_hash.in_(chunk))
            ):
                existing[row.content_hash] = row
        for h, rec in by_hash.items():
            found = existing.get(h)
            if found is None:
                row = RawRecord(
                    source=rec.source,
                    external_id=rec.external_id,
                    content_hash=h,
                    payload=rec.raw_payload,
                    source_url=rec.source_url,
                    first_fetched_at=self.now,
                    last_fetched_at=self.now,
                    run_id=self.run.id,
                )
                self.s.add(row)
                existing[h] = row
            else:
                found.last_fetched_at = self.now
        self.s.flush()
        return {h: row.id for h, row in existing.items()}

    # -- prefetch -------------------------------------------------------
    def _prefetch_vulns(self, records: list[NormalizedRecord]) -> dict[str, Vulnerability]:
        keys = list({r.entity_key for r in records})
        out: dict[str, Vulnerability] = {}
        for chunk in _chunks(keys):
            for v in self.s.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(chunk))):
                out[v.cve_id] = v
        return out

    def _prefetch_indicators(self, records: list[NormalizedRecord]) -> dict[str, Indicator]:
        pairs = list({(r.indicator.ioc_type.value, r.indicator.value) for r in records if r.indicator})
        out: dict[str, Indicator] = {}
        for chunk in _chunks(pairs):
            stmt = select(Indicator).where(tuple_(Indicator.ioc_type, Indicator.value).in_(chunk))
            for i in self.s.scalars(stmt):
                out[i.entity_key] = i
        return out

    def _prefetch_intel(self, records: list[NormalizedRecord]) -> dict[str, IntelObject]:
        pairs = list({(r.intel.kind, r.intel.key) for r in records if r.intel})
        out: dict[str, IntelObject] = {}
        for chunk in _chunks(pairs):
            for o in self.s.scalars(
                select(IntelObject).where(tuple_(IntelObject.kind, IntelObject.key).in_(chunk))
            ):
                out[o.entity_key] = o
        return out

    def _prefetch_observations(
        self, records: Sequence[NormalizedRecord]
    ) -> dict[tuple[str, str, str], Observation]:
        out: dict[tuple[str, str, str], Observation] = {}
        if not records:
            return out
        source = records[0].source
        keys = list({r.entity_key for r in records})
        for chunk in _chunks(keys):
            stmt = select(Observation).where(Observation.source == source, Observation.entity_key.in_(chunk))
            for o in self.s.scalars(stmt):
                out[(o.entity_kind, o.entity_key, o.content_hash)] = o
        return out

    # -- canonical upserts ------------------------------------------------
    def _upsert_vuln(self, rec: NormalizedRecord, cache: dict[str, Vulnerability]) -> EntityChange:
        data = rec.vulnerability
        assert data is not None
        key = data.cve_id
        row = cache.get(key)
        values = data.model_dump(exclude={"cve_id", "references"}, exclude_none=True)
        if row is None:
            row = Vulnerability(
                cve_id=key,
                references=list(data.references),
                published_at=rec.published_at,
                first_seen_at=self.now,
                last_seen_at=self.now,
                is_synthetic=rec.is_synthetic,
                **values,
            )
            row.content_hash = self._vuln_hash(row)
            self.s.add(row)
            cache[key] = row
            return EntityChange(VULNERABILITY, key, True, is_synthetic=rec.is_synthetic)

        changed: dict[str, tuple[Any, Any]] = {}
        for fname, new in values.items():
            old = getattr(row, fname)
            if fname == "cwes":
                new = sorted(set(old or []) | set(new))
            if old != new:
                changed[fname] = (old, new)
                setattr(row, fname, new)
        merged_refs = list(dict.fromkeys([*(row.references or []), *data.references]))
        if merged_refs != row.references:
            row.references = merged_refs
        if row.published_at is None and rec.published_at:
            row.published_at = rec.published_at
        row.last_seen_at = self.now
        row.content_hash = self._vuln_hash(row)
        return EntityChange(VULNERABILITY, key, False, changed, rec.is_synthetic)

    @staticmethod
    def _vuln_hash(row: Vulnerability) -> str:
        return content_hash({f: _str(getattr(row, f)) for f in VULN_FIELDS})

    def _upsert_indicator(self, rec: NormalizedRecord, cache: dict[str, Indicator]) -> EntityChange:
        data = rec.indicator
        assert data is not None
        key = data.entity_key
        seen = rec.observed_at or rec.published_at or self.now
        row = cache.get(key)
        if row is None:
            row = Indicator(
                ioc_type=data.ioc_type.value,
                value=data.value,
                original_value=data.original_value,
                is_routable=data.is_routable,
                description=rec.description,
                confidence=rec.confidence,
                tlp=rec.tlp.value if rec.tlp else None,
                first_seen_at=min(seen, self.now),
                last_seen_at=seen,
                is_synthetic=rec.is_synthetic,
            )
            self.s.add(row)
            cache[key] = row
            return EntityChange(INDICATOR, key, True, is_synthetic=rec.is_synthetic)
        changed: dict[str, tuple[Any, Any]] = {}
        for fname, new in (
            ("confidence", rec.confidence),
            ("description", rec.description),
            ("tlp", rec.tlp.value if rec.tlp else None),
        ):
            if new is not None and getattr(row, fname) != new:
                changed[fname] = (getattr(row, fname), new)
                setattr(row, fname, new)
        row.first_seen_at = min(row.first_seen_at, seen)
        row.last_seen_at = max(row.last_seen_at, seen)
        return EntityChange(INDICATOR, key, False, changed, rec.is_synthetic)

    def _upsert_intel(self, rec: NormalizedRecord, cache: dict[str, IntelObject]) -> EntityChange:
        data = rec.intel
        assert data is not None
        key = data.entity_key
        row = cache.get(key)
        if row is None:
            row = IntelObject(
                kind=data.kind,
                key=data.key,
                name=data.name,
                aliases=data.aliases,
                external_id=data.external_id,
                description=data.description,
                first_seen_at=self.now,
                last_seen_at=self.now,
                is_synthetic=rec.is_synthetic,
            )
            self.s.add(row)
            cache[key] = row
            return EntityChange(INTEL, key, True, is_synthetic=rec.is_synthetic)
        changed: dict[str, tuple[Any, Any]] = {}
        aliases = sorted(set(row.aliases or []) | set(data.aliases))
        if aliases != sorted(row.aliases or []):
            changed["aliases"] = (row.aliases, aliases)
            row.aliases = aliases
        for fname in ("external_id", "description"):
            new = getattr(data, fname)
            if new and getattr(row, fname) != new:
                changed[fname] = (getattr(row, fname), new)
                setattr(row, fname, new)
        row.last_seen_at = self.now
        return EntityChange(INTEL, key, False, changed, rec.is_synthetic)

    # -- provenance ---------------------------------------------------------
    def _upsert_observation(
        self, rec: NormalizedRecord, raw_id: int | None, cache: dict[tuple[str, str, str], Observation]
    ) -> None:
        obs_hash = rec.observation_hash()
        ck = (rec.entity_kind.value, rec.entity_key, obs_hash)
        row = cache.get(ck)
        if row is not None:
            row.sighting_count += 1
            row.last_seen_at = self.now
            return
        row = Observation(
            source=rec.source,
            entity_kind=rec.entity_kind.value,
            entity_key=rec.entity_key,
            external_id=rec.external_id,
            title=rec.title,
            description=rec.description,
            source_url=rec.source_url,
            published_at=rec.published_at,
            observed_at=rec.observed_at,
            ingested_at=rec.ingested_at,
            last_seen_at=self.now,
            sighting_count=1,
            confidence=rec.confidence,
            tlp=rec.tlp.value if rec.tlp else None,
            content_hash=obs_hash,
            raw_record_id=raw_id,
            run_id=self.run.id,
            is_synthetic=rec.is_synthetic,
        )
        self.s.add(row)
        cache[ck] = row

    def _upsert_relationship(self, rec: NormalizedRecord, rel: Any, raw_id: int | None) -> None:
        src_kind, src_key = rec.entity_kind.value, rec.entity_key
        row = self.s.scalar(
            select(Relationship).where(
                Relationship.src_kind == src_kind,
                Relationship.src_key == src_key,
                Relationship.rel_type == rel.rel_type,
                Relationship.dst_kind == rel.dst_kind.value,
                Relationship.dst_key == rel.dst_key,
                Relationship.source == rec.source,
            )
        )
        if row is None:
            self.s.add(
                Relationship(
                    src_kind=src_kind,
                    src_key=src_key,
                    rel_type=rel.rel_type,
                    dst_kind=rel.dst_kind.value,
                    dst_key=rel.dst_key,
                    source=rec.source,
                    evidence_url=rel.evidence_url or rec.source_url,
                    description=rel.description,
                    confidence=rel.confidence,
                    raw_record_id=raw_id,
                    first_seen_at=self.now,
                    last_seen_at=self.now,
                    is_synthetic=rec.is_synthetic,
                )
            )
            self.s.flush()
        else:
            row.last_seen_at = self.now
