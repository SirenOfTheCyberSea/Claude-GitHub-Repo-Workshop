"""Composite widgets reused across views (provenance, relationships, analyst workflow)."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.dashboard import state
from siren_threatwatch.dashboard.components import badge, card, esc, fmt_dt, link, score_breakdown
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.db.models import ANALYST_STATUSES
from siren_threatwatch.prioritization.scoring import SCORE_LABEL


def provenance(detail: dict[str, Any]) -> None:
    obs = detail["observations"]
    st.markdown(
        f"**Source observations** ({len(obs)}) — every source statement is preserved with its citation."
    )
    for o in obs:
        meta = [
            f"Source: <b>{esc(o['source'])}</b>",
            f"Published {esc(fmt_dt(o['published_at']))}",
            f"Observed {esc(fmt_dt(o['observed_at']))}",
            f"Ingested {esc(fmt_dt(o['ingested_at']))}",
            f"Seen {esc(o['sighting_count'])}×",
            f"Confidence {esc(o['confidence']) if o['confidence'] is not None else 'n/a'}",
            f"TLP {esc(o['tlp'] or 'not supplied')}",
            link(o["source_url"], "Source citation") if o["source_url"] else "No source URL",
        ]
        card(o["title"], o["description"], meta, synthetic=o["is_synthetic"])


def relationships(detail: dict[str, Any]) -> None:
    rels = detail["relationships"]
    st.markdown(f"**Source-evidenced relationships** ({len(rels)})")
    st.caption(
        "Relationships are only recorded when a source explicitly states them. Shared infrastructure "
        "or co-occurrence does not prove attribution."
    )
    if not rels:
        st.write("None recorded.")
        return
    for r in rels:
        meta = [
            f"Source: <b>{esc(r['source'])}</b>",
            f"Confidence {esc(r['confidence']) if r['confidence'] is not None else 'n/a'}",
            link(r["evidence_url"], "Evidence") if r["evidence_url"] else "No evidence URL",
        ]
        card(
            f"{r['src']}  —{r['rel_type']}→  {r['dst']}", r["description"], meta, synthetic=r["is_synthetic"]
        )


def history(detail: dict[str, Any]) -> None:
    changes = detail["changes"]
    st.markdown(f"**Change history** ({len(changes)})")
    if changes:
        st.dataframe(pd.DataFrame(changes), hide_index=True, width="stretch")
    else:
        st.write("No changes recorded since first ingestion.")


def score(detail: dict[str, Any]) -> None:
    sc = detail["score"]
    if sc is None:
        st.info("Not scored yet.")
        return
    st.markdown(f"**Computed priority: {sc['score']:.0f}/100 — {esc(sc['band'])}**")
    if sc["missing"]:
        st.caption("Missing inputs (0 points, shown explicitly): " + ", ".join(sc["missing"]))
    score_breakdown(sc["factors"], SCORE_LABEL)


def analyst_panel(kind: str, key: str, detail: dict[str, Any]) -> None:
    current = detail["state"] or {}
    with st.form(f"analyst-{kind}-{key}"):
        st.markdown("**Analyst workflow**")
        c1, c2 = st.columns(2)
        status = c1.selectbox(
            "Status", ANALYST_STATUSES, index=ANALYST_STATUSES.index(current.get("status", "New"))
        )
        overrides = ["(computed)", "Critical", "High", "Medium", "Low"]
        po = current.get("priority_override") or "(computed)"
        override = c2.selectbox(
            "Analyst priority", overrides, index=overrides.index(po) if po in overrides else 0
        )
        tags = st.text_input("Tags (comma-separated)", ", ".join(current.get("tags") or []), max_chars=500)
        notes = st.text_area("Notes", current.get("notes") or "", max_chars=10_000)
        if st.form_submit_button("Save", type="primary"):
            with session_scope() as s:
                queries.save_analyst_state(
                    s,
                    kind,
                    key,
                    status=status,
                    tags=tags.split(","),
                    notes=notes,
                    priority_override=None if override == "(computed)" else override,
                )
            state.invalidate()
            st.success("Saved.")
    if detail["watched"]:
        st.markdown(badge("On watchlist", "#0E7C73"), unsafe_allow_html=True)
    elif st.button("Add to watchlist", key=f"watch-{kind}-{key}"):
        with session_scope() as s:
            queries.add_watch(s, kind, key)
        state.invalidate()
        st.rerun()
