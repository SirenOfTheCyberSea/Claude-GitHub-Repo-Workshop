from datetime import date

from sqlalchemy import func, select

from siren_threatwatch.db.models import (
    ChangeEvent,
    Indicator,
    IngestionRun,
    IntelObject,
    Observation,
    RawRecord,
    Relationship,
    Vulnerability,
)
from siren_threatwatch.db.repository import Persister
from siren_threatwatch.normalization.schema import EntityKind, NormalizedRecord
from tests.conftest import ioc_record, vuln_record


def _count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def _new_run(session, source="test"):
    r = IngestionRun(source=source)
    session.add(r)
    session.flush()
    return r


def test_cve_case_variants_merge_into_one_entity(session, run):
    stats = Persister(session, run).persist([vuln_record("CVE-2024-0001"), vuln_record("cve-2024-0001")])
    assert stats.new == 1
    assert _count(session, Vulnerability) == 1
    # The source's own identifiers differed, so both statements are kept as provenance.
    assert set(session.scalars(select(Observation.entity_key))) == {"CVE-2024-0001"}


def test_identical_records_in_batch_are_one_observation(session, run):
    Persister(session, run).persist([vuln_record(), vuln_record()])
    assert _count(session, Observation) == 1
    assert session.scalar(select(Observation.sighting_count)) == 2


def test_reingest_identical_increments_sightings_not_rows(session, run):
    Persister(session, run).persist([vuln_record()])
    stats = Persister(session, _new_run(session)).persist([vuln_record()])
    assert (stats.new, stats.updated, stats.unchanged) == (0, 0, 1)
    assert _count(session, Observation) == 1
    assert _count(session, RawRecord) == 1
    assert session.scalar(select(Observation.sighting_count)) == 2


def test_changed_content_preserves_history(session, run):
    Persister(session, run).persist([vuln_record(kev_listed=True, kev_ransomware_use="Unknown")])
    stats = Persister(session, _new_run(session)).persist(
        [vuln_record(kev_listed=True, kev_ransomware_use="Known", kev_due_date=date(2025, 1, 1))]
    )
    assert stats.updated == 1
    change = stats.changes[0]
    assert change.changed_fields["kev_ransomware_use"] == ("Unknown", "Known")
    assert _count(session, Observation) == 2  # both versions of the source statement retained
    assert _count(session, RawRecord) == 2
    fields = set(session.scalars(select(ChangeEvent.field)))
    assert {"kev_ransomware_use", "kev_due_date"} <= fields
    assert session.scalar(select(Vulnerability.kev_ransomware_use)) == "Known"


def test_multiple_sources_keep_attribution(session, run):
    Persister(session, run).persist([vuln_record(source="source_a", cvss_score=7.5)])
    Persister(session, _new_run(session, "source_b")).persist(
        [vuln_record(source="source_b", kev_listed=True, references=["https://b.example/x"])]
    )
    assert _count(session, Vulnerability) == 1
    assert set(session.scalars(select(Observation.source))) == {"source_a", "source_b"}
    v = session.scalar(select(Vulnerability))
    assert v.cvss_score == 7.5 and v.kev_listed is True  # merged, not overwritten with None
    assert "https://b.example/x" in v.references


def test_indicator_dedup_across_defanged_forms(session, run):
    stats = Persister(session, run).persist(
        [
            ioc_record("hxxp://evil.example[.]com/a"),
            ioc_record("http://EVIL.example.com/a", source="test"),
        ]
    )
    assert stats.new == 1
    assert _count(session, Indicator) == 1
    ind = session.scalar(select(Indicator))
    assert ind.value == "http://evil.example.com/a"
    assert ind.original_value == "hxxp://evil.example[.]com/a"  # first-seen original evidence preserved


def test_intel_alias_merge_and_relationships(session, run):
    def actor(aliases, rels=()):
        return NormalizedRecord(
            source="test",
            entity_kind=EntityKind.INTEL,
            external_id="a1",
            title="Actor",
            raw_payload={"aliases": aliases},
            intel={"kind": "threat-actor", "name": "Demo Actor", "aliases": aliases},
            relationships=list(rels),
        )

    rel = {
        "rel_type": "uses",
        "dst_kind": "intel",
        "dst_key": "malware:demo",
        "evidence_url": "https://e.example/r",
    }
    Persister(session, run).persist([actor(["A"], [rel])])
    Persister(session, _new_run(session)).persist([actor(["B"], [rel])])
    obj = session.scalar(select(IntelObject))
    assert obj.aliases == ["A", "B"]
    assert _count(session, IntelObject) == 1
    assert _count(session, Relationship) == 1
