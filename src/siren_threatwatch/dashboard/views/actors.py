from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.dashboard import state, widgets
from siren_threatwatch.dashboard.components import empty_state, md
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.db.models import INTEL

KIND_LABELS = {
    "threat-actor": "Threat actors",
    "campaign": "Campaigns",
    "malware": "Malware families",
    "attack-pattern": "ATT&CK techniques",
}


def render() -> None:
    st.title("Threat Actors & Campaigns")
    st.caption(
        "Profiles show only what sources state, with citations. Attribution claims are the source's, "
        "with the source's confidence — shared infrastructure is never treated as proof of attribution."
    )
    with session_scope() as s:
        objs: list[dict[str, Any]] = [
            {
                "kind": o.kind,
                "name": o.name,
                "key": o.entity_key,
                "aliases": o.aliases,
                "external_id": o.external_id,
                "description": o.description,
                "synthetic": o.is_synthetic,
            }
            for o in queries.intel_objects(s)
        ]
    if not objs:
        empty_state(
            "No actors, campaigns, malware or techniques yet. MITRE ATT&CK ingestion arrives in Phase 2; "
            "run `siren seed-demo` to explore synthetic examples."
        )
        return
    kind = st.radio("Show", list(KIND_LABELS), format_func=KIND_LABELS.__getitem__, horizontal=True)
    items = [o for o in objs if o["kind"] == kind]
    if not items:
        empty_state(f"No {KIND_LABELS[kind].lower()} recorded.")
        return
    names: dict[str, dict[str, Any]] = {o["key"]: o for o in items}
    sel = st.selectbox(
        "Profile",
        list(names),
        format_func=lambda k: str(names[k]["name"]) + (" (synthetic)" if names[k]["synthetic"] else ""),
    )
    o = names[sel]
    st.subheader(o["name"])
    if o["synthetic"]:
        st.warning("SYNTHETIC DEMO PROFILE — fictional.")
    if o["aliases"]:
        st.markdown("**Known aliases (as reported):** " + ", ".join(md(a) for a in o["aliases"]))
    if o["external_id"]:
        st.markdown(f"**External ID:** {md(o['external_id'])}")
    st.write(o["description"] or "No description.")

    detail = state.entity_detail(INTEL, o["key"])
    techniques = [r for r in detail["relationships"] if r["dst"].startswith("intel:attack-pattern:")]
    if techniques:
        st.markdown("**ATT&CK mappings (source-stated)**")
        by_key = {x["key"]: x for x in objs}
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "technique": by_key.get(r["dst"].removeprefix("intel:"), {}).get("external_id"),
                        "name": by_key.get(r["dst"].removeprefix("intel:"), {}).get("name"),
                        "source": r["source"],
                        "confidence": r["confidence"],
                    }
                    for r in techniques
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    widgets.relationships(detail)
    with st.expander("Provenance"):
        widgets.provenance(detail)
