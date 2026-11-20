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

Merge rules
-----------
* Vulnerability fields follow :data:`FIELD_PRECEDENCE`: a source may overwrite a field only if it ranks at
  least as high as the source that last set it (e.g. NVD owns CVSS, CISA owns KEV fields and keeps its
  vendor/product names over NVD's CPE-derived ones). ``field_sources`` records who supplied each field.
* Intel objects from a *different* source are merged into an existing object when the incoming name or
  an alias matches exactly one existing object's name/alias (case-insensitive). Objects from the same
  source are never merged with each other — the source evidently considers them distinct.
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
    SyncState,
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
    "cvss_metrics",
    "affected_products",
    "nvd_status",
)

# Lower index = higher precedence. Sources not listed rank below every listed source.
_KEV_FIRST = ("cisa_kev", "nvd")
_NVD_FIRST = ("nvd", "cisa_kev")
FIELD_PRECEDENCE: dict[str, tuple[str, ...]] = {
    "title": _KEV_FIRST,
    "vendor": _KEV_FIRST,
    "product": _KEV_FIRST,
    "description": _NVD_FIRST,
    "published_at": _NVD_FIRST,
    "cvss_score": _NVD_FIRST,
    "cvss_vector": _NVD_FIRST,
    "cvss_version": _NVD_FIRST,
    "cvss_severity": _NVD_FIRST,
    "cvss_metrics": _NVD_FIRST,
    "affected_products": _NVD_FIRST,
    "nvd_status": ("nvd",),
    "nvd_last_modified": ("nvd",),
    "kev_listed": ("cisa_kev",),
    "kev_date_added": ("cisa_kev",),
    "kev_due_date": ("cisa_kev",),
    "kev_required_action": ("cisa_kev",),
    "kev_ransomware_use": ("cisa_kev",),
    "kev_notes": ("cisa_kev",),
}
_MERGEABLE_INTEL = frozenset({"threat-actor", "campaign", "malware", "tool"})


def source_rank(field: str, source: str | None) -> int:
    order = FIELD_PRECEDENCE.get(field, ())
    return order.index(source) if source in order else len(order)


def may_overwrite(field: str, current_source: str | None, new_source: str) -> bool:
    """Whether ``new_source`` may replace a non-empty value last set by ``current_source``.

    If provenance is unknown (e.g. rows created before provenance was tracked), only the field's
    top-ranked source may overwrite it."""
    if current_source is None:
        return source_rank(field, new_source) == 0
    return source_rank(field, new_source) <= source_rank(field, current_source)


def _is_unset(field: str, value: Any, sources: dict[str, Any]) -> bool:
    """True if the field is empty, or still holds its column default and no source ever set it."""
    if value is None or value == []:
        return True
    return field not in sources and field == "kev_listed" and value is False


def get_sync_state(session: Session, source: str, key: str) -> str | None:
    row = session.scalar(select(SyncState).where(SyncState.source == source, SyncState.key == key))
    return row.value if row else None


def set_sync_state(session: Session, source: str, key: str, value: str | None) -> None:
    row = session.scalar(select(SyncState).where(SyncState.source == source, SyncState.key == key))
    if row is None:
        row = SyncState(source=source, key=key)
        session.add(row)
    row.value = value
    row.updated_at = datetime.now(UTC)


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
        self._intel_redirects: dict[str, str] = {}  # incoming intel entity key -> canonical key

    # -- public ---------------------------------------------------------
    def persist(self, records: Sequence[NormalizedRecord]) -> PersistStats:
        raw_ids = self._persist_raw(records)
        vulns = self._prefetch_vulns([r for r in records if r.vulnerability])
        iocs = self._prefetch_indicators([r for r in records if r.indicator])
        intel = self._prefetch_intel([r for r in records if r.intel])
        obs = self._prefetch_observations(records)
        alias_index, same_source_keys = self._intel_alias_index(records)

        changes: list[tuple[NormalizedRecord, EntityChange]] = []
        for rec in records:
            if rec.vulnerability:
                change = self._upsert_vuln(rec, vulns)
            elif rec.indicator:
                change = self._upsert_indicator(rec, iocs)
            else:
                change = self._upsert_intel(rec, intel, alias_index, same_source_keys)
            self._upsert_observation(rec, raw_ids.get(rec.raw_hash), obs, change.key)
            changes.append((rec, change))

        # Relationships after all entities exist, so destination keys can be resolved through alias merges.
        rels = self._prefetch_relationships(records)
        for rec, change in changes:
            for rel in rec.relationships:
                self._upsert_relationship(rec, change.key, rel, raw_ids.get(rec.raw_hash), rels)

        for rec, change in changes:
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

    @staticmethod
    def _synthetic_guard(rec: NormalizedRecord, row: Any, key: str) -> EntityChange | None:
        """Synthetic demo data never modifies a real entity; real data takes over a synthetic placeholder."""
        kind = rec.entity_kind.value
        if rec.is_synthetic and not row.is_synthetic:
            return EntityChange(kind, key, False, {}, is_synthetic=True)
        if not rec.is_synthetic and row.is_synthetic:
            row.is_synthetic = False
        return None

    def _intel_alias_index(
        self, records: Sequence[NormalizedRecord]
    ) -> tuple[dict[tuple[str, str], list[IntelObject]], set[str]]:
        """Map (kind, lower-cased name/alias) -> existing objects, and the keys this source already owns."""
        kinds = {r.intel.kind for r in records if r.intel} & _MERGEABLE_INTEL
        index: dict[tuple[str, str], list[IntelObject]] = {}
        if not kinds:
            return index, set()
        for obj in self.s.scalars(select(IntelObject).where(IntelObject.kind.in_(kinds))):
            for label in {obj.name, *(obj.aliases or [])}:
                index.setdefault((obj.kind, label.casefold()), []).append(obj)
        source = records[0].source
        owned = set(
            self.s.scalars(
                select(Observation.entity_key).where(
                    Observation.source == source, Observation.entity_kind == INTEL
                )
            )
        )
        return index, owned

    def _prefetch_relationships(
        self, records: Sequence[NormalizedRecord]
    ) -> dict[tuple[str, ...], Relationship]:
        out: dict[tuple[str, ...], Relationship] = {}
        if not any(r.relationships for r in records):
            return out
        source = records[0].source
        for row in self.s.scalars(select(Relationship).where(Relationship.source == source)):
            out[(row.src_kind, row.src_key, row.rel_type, row.dst_kind, row.dst_key)] = row
        return out

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
        for empty in ("cvss_metrics", "affected_products"):  # empty list = "source had nothing to say"
            if not values.get(empty):
                values.pop(empty, None)
        if rec.published_at is not None:
            values["published_at"] = rec.published_at
        if row is None:
            row = Vulnerability(
                cve_id=key,
                references=list(data.references),
                first_seen_at=self.now,
                last_seen_at=self.now,
                is_synthetic=rec.is_synthetic,
                field_sources=dict.fromkeys(values, rec.source),
                **values,
            )
            row.content_hash = self._vuln_hash(row)
            self.s.add(row)
            cache[key] = row
            return EntityChange(VULNERABILITY, key, True, is_synthetic=rec.is_synthetic)

        if (guard := self._synthetic_guard(rec, row, key)) is not None:
            return guard
        changed: dict[str, tuple[Any, Any]] = {}
        sources = dict(row.field_sources or {})
        for fname, new in values.items():
            old = getattr(row, fname)
            if fname == "cwes":
                new = sorted(set(old or []) | set(new))
            elif not _is_unset(fname, old, sources) and not may_overwrite(
                fname, sources.get(fname), rec.source
            ):
                continue  # a higher-precedence source owns this field
            if old != new:
                if fname not in ("nvd_last_modified", "published_at"):  # bookkeeping, not analyst-relevant
                    changed[fname] = (old, new)
                setattr(row, fname, new)
            if fname == "cwes":
                sources.setdefault(fname, rec.source)  # union of all sources; remember the first
            else:
                sources[fname] = rec.source
        if sources != row.field_sources:
            row.field_sources = sources
        merged_refs = list(dict.fromkeys([*(row.references or []), *data.references]))[:300]
        if merged_refs != row.references:
            row.references = merged_refs
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
        if (guard := self._synthetic_guard(rec, row, key)) is not None:
            return guard
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

    def _upsert_intel(
        self,
        rec: NormalizedRecord,
        cache: dict[str, IntelObject],
        alias_index: dict[tuple[str, str], list[IntelObject]] | None = None,
        owned: set[str] | None = None,
    ) -> EntityChange:
        data = rec.intel
        assert data is not None
        key = data.entity_key
        row = cache.get(key)
        if row is None and alias_index is not None and data.kind in _MERGEABLE_INTEL and not rec.is_synthetic:
            candidates = {
                o.entity_key: o
                for label in {data.name, *data.aliases}
                for o in alias_index.get((data.kind, label.casefold()), [])
                if o.entity_key not in (owned or set())  # never merge objects the same source keeps apart
            }
            if len(candidates) == 1:
                row = next(iter(candidates.values()))
                self._intel_redirects[key] = row.entity_key
                key = row.entity_key
                cache[data.entity_key] = row
        if row is None:
            row = IntelObject(
                kind=data.kind,
                key=data.key,
                name=data.name,
                aliases=data.aliases,
                external_id=data.external_id,
                description=data.description,
                attributes=data.attributes,
                first_seen_at=self.now,
                last_seen_at=self.now,
                is_synthetic=rec.is_synthetic,
            )
            self.s.add(row)
            cache[key] = row
            if alias_index is not None:
                for label in {data.name, *data.aliases}:
                    alias_index.setdefault((data.kind, label.casefold()), []).append(row)
                (owned if owned is not None else set()).add(key)
            return EntityChange(INTEL, key, True, is_synthetic=rec.is_synthetic)
        if (guard := self._synthetic_guard(rec, row, key)) is not None:
            return guard
        changed: dict[str, tuple[Any, Any]] = {}
        extra = {data.name} if data.name.casefold() != row.name.casefold() else set()
        aliases = sorted(set(row.aliases or []) | set(data.aliases) | extra)
        if aliases != sorted(row.aliases or []):
            changed["aliases"] = (row.aliases, aliases)
            row.aliases = aliases
        if data.attributes and key == data.entity_key and row.attributes != data.attributes:
            changed["attributes"] = (row.attributes, data.attributes)
            row.attributes = data.attributes
        for fname in ("external_id", "description"):
            new = getattr(data, fname)
            if new and getattr(row, fname) is not None and key != data.entity_key:
                continue  # merged from another source by alias: keep the original source's text
            if new and getattr(row, fname) != new:
                changed[fname] = (getattr(row, fname), new)
                setattr(row, fname, new)
        row.last_seen_at = self.now
        return EntityChange(INTEL, key, False, changed, rec.is_synthetic)

    # -- provenance ---------------------------------------------------------
    def _upsert_observation(
        self,
        rec: NormalizedRecord,
        raw_id: int | None,
        cache: dict[tuple[str, str, str], Observation],
        entity_key: str | None = None,
    ) -> None:
        obs_hash = rec.observation_hash()
        entity_key = entity_key or rec.entity_key
        ck = (rec.entity_kind.value, entity_key, obs_hash)
        row = cache.get(ck)
        if row is not None:
            row.sighting_count += 1
            row.last_seen_at = self.now
            return
        row = Observation(
            source=rec.source,
            entity_kind=rec.entity_kind.value,
            entity_key=entity_key,
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

    def _resolve_dst(self, dst_kind: str, dst_key: str) -> str:
        if dst_kind == INTEL:
            return self._intel_redirects.get(dst_key, dst_key)
        return dst_key

    def _upsert_relationship(
        self,
        rec: NormalizedRecord,
        src_key: str,
        rel: Any,
        raw_id: int | None,
        cache: dict[tuple[str, ...], Relationship],
    ) -> None:
        src_kind = rec.entity_kind.value
        dst_kind = rel.dst_kind.value
        dst_key = self._resolve_dst(dst_kind, rel.dst_key)
        ck = (src_kind, src_key, rel.rel_type, dst_kind, dst_key)
        row = cache.get(ck)
        if row is None:
            row = Relationship(
                src_kind=src_kind,
                src_key=src_key,
                rel_type=rel.rel_type,
                dst_kind=dst_kind,
                dst_key=dst_key,
                source=rec.source,
                evidence_url=rel.evidence_url or rec.source_url,
                description=rel.description,
                confidence=rel.confidence,
                raw_record_id=raw_id,
                first_seen_at=self.now,
                last_seen_at=self.now,
                is_synthetic=rec.is_synthetic,
            )
            self.s.add(row)
            cache[ck] = row
        else:
            row.last_seen_at = self.now
            if rel.description and row.description != rel.description:
                row.description = rel.description
