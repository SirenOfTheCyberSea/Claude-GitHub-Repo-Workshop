"""Normalise MITRE ATT&CK STIX 2.1 bundles (github.com/mitre-attack/attack-stix-data).

Structure verified against the official Enterprise bundle: objects of type ``intrusion-set``, ``campaign``,
``malware``, ``tool`` and ``attack-pattern`` carry a ``mitre-attack`` external reference (ATT&CK ID + URL);
aliases are in ``aliases`` (groups, campaigns) or ``x_mitre_aliases`` (software); ``relationship`` objects
link them (``uses``, ``attributed-to``, ``subtechnique-of``, ...). Objects with ``revoked`` or
``x_mitre_deprecated`` set are skipped.

Only relationships that ATT&CK states explicitly are recorded. CVE IDs that appear in an object's
description are recorded as ``mentions`` — a textual reference, not a verified exploitation claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from siren_threatwatch.normalization.schema import (
    EntityKind,
    IntelObjectData,
    NormalizedRecord,
    RelationshipData,
)

ATTACK_SOURCE = "mitre_attack"
ATTACK_CONFIDENCE = 80  # curated public knowledge base; ATT&CK itself does not publish per-object confidence
STIX_TO_KIND = {
    "intrusion-set": "threat-actor",
    "campaign": "campaign",
    "malware": "malware",
    "tool": "tool",
    "attack-pattern": "attack-pattern",
}
KEPT_RELATIONSHIPS = frozenset({"uses", "attributed-to", "subtechnique-of"})
_MITRE_SOURCES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)\s]+)\)")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
MAX_RELATIONSHIP_TEXT = 1500


def clean_attack_text(text: Any, limit: int | None = None) -> str | None:
    """Strip ATT&CK citation markers and Markdown links (keeping the link text)."""
    if not isinstance(text, str):
        return None
    out = _MD_LINK.sub(r"\1", _CITATION.sub("", text)).strip()
    return (out[:limit] if limit else out) or None


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def mitre_reference(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") in _MITRE_SOURCES:
            return ref.get("external_id"), ref.get("url")
    return None, None


def _first_url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            return ref["url"]
    return None


def is_active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


@dataclass
class AttackParseResult:
    records: list[NormalizedRecord] = field(default_factory=list)
    skipped_inactive: int = 0
    rejected: list[str] = field(default_factory=list)
    relationships: int = 0
    cve_mentions: int = 0
    attack_version: str | None = None


def _intel_data(obj: dict[str, Any], kind: str) -> IntelObjectData:
    ext_id, url = mitre_reference(obj)
    name = obj.get("name")
    aliases = obj.get("aliases") or obj.get("x_mitre_aliases") or []
    attrs: dict[str, Any] = {"stix_id": obj.get("id")}
    if url:
        attrs["url"] = url
    if obj.get("x_mitre_domains"):
        attrs["domains"] = list(obj["x_mitre_domains"])[:5]
    if obj.get("x_mitre_platforms"):
        attrs["platforms"] = list(obj["x_mitre_platforms"])[:20]
    if kind == "attack-pattern":
        attrs["tactics"] = sorted(
            {
                p.get("phase_name")
                for p in obj.get("kill_chain_phases") or []
                if isinstance(p, dict) and p.get("phase_name")
            }
        )
        attrs["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
    if kind == "campaign":
        for k in ("first_seen", "last_seen"):
            if obj.get(k):
                attrs[k] = obj[k]
    return IntelObjectData(
        kind=kind,
        name=name,
        aliases=[a for a in aliases if isinstance(a, str) and a != name],
        external_id=ext_id,
        description=clean_attack_text(obj.get("description")),
        attributes=attrs,
    )


def parse_bundle(bundle: Any, seen_ids: set[str] | None = None) -> AttackParseResult:
    """Convert an ATT&CK STIX bundle into normalised intel records with relationships."""
    if (
        not isinstance(bundle, dict)
        or bundle.get("type") != "bundle"
        or not isinstance(bundle.get("objects"), list)
    ):
        raise ValueError("not a STIX bundle")
    result = AttackParseResult()
    seen_ids = seen_ids if seen_ids is not None else set()
    objects: list[dict[str, Any]] = [o for o in bundle["objects"] if isinstance(o, dict)]
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            result.attack_version = o.get("x_mitre_version")

    data_by_id: dict[str, IntelObjectData] = {}
    raw_by_id: dict[str, dict[str, Any]] = {}
    for o in objects:
        kind = STIX_TO_KIND.get(str(o.get("type")))
        if kind is None or not isinstance(o.get("id"), str):
            continue
        if not is_active(o):
            result.skipped_inactive += 1
            continue
        if o["id"] in seen_ids:  # shared across ATT&CK domains: keep the first copy
            continue
        try:
            data_by_id[o["id"]] = _intel_data(o, kind)
            raw_by_id[o["id"]] = o
        except (ValueError, ValidationError) as exc:
            result.rejected.append(f"{o.get('id')}: {str(exc).splitlines()[0]}")
    seen_ids.update(data_by_id)

    rels: dict[str, list[RelationshipData]] = {}
    for r in objects:
        if r.get("type") != "relationship" or r.get("relationship_type") not in KEPT_RELATIONSHIPS:
            continue
        if not is_active(r):
            continue
        src, dst = data_by_id.get(r.get("source_ref", "")), data_by_id.get(r.get("target_ref", ""))
        if src is None or dst is None:
            continue
        rels.setdefault(r["source_ref"], []).append(
            RelationshipData(
                rel_type=r["relationship_type"],
                dst_kind=EntityKind.INTEL,
                dst_key=dst.entity_key,
                description=clean_attack_text(r.get("description"), MAX_RELATIONSHIP_TEXT),
                evidence_url=_first_url(r) or src.attributes.get("url"),
            )
        )
        result.relationships += 1

    for stix_id, data in data_by_id.items():
        raw = raw_by_id[stix_id]
        rel_list = rels.get(stix_id, [])
        for cve in sorted(set(_CVE.findall(raw.get("description") or "")))[:50]:
            rel_list.append(
                RelationshipData(
                    rel_type="mentions",
                    dst_kind=EntityKind.VULNERABILITY,
                    dst_key=cve,
                    description=f"The ATT&CK entry for {data.name} mentions {cve} in its description. "
                    "This is a textual reference, not a verified exploitation claim.",
                    evidence_url=data.attributes.get("url"),
                )
            )
            result.cve_mentions += 1
        result.records.append(
            NormalizedRecord(
                source=ATTACK_SOURCE,
                entity_kind=EntityKind.INTEL,
                external_id=data.external_id or stix_id,
                title=f"{data.external_id + ' ' if data.external_id else ''}{data.name}",
                description=data.description,
                source_url=data.attributes.get("url"),
                published_at=_parse_ts(raw.get("created")),
                observed_at=_parse_ts(raw.get("modified")),
                confidence=ATTACK_CONFIDENCE,
                tlp=None,
                raw_payload=raw,
                intel=data,
                relationships=rel_list,
            )
        )
    return result
