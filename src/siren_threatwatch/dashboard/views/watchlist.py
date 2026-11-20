from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.config import Settings
from siren_threatwatch.dashboard import state
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.iocs.validation import IocValidationError, validate_indicator
from siren_threatwatch.normalization.schema import canonical_cve
from siren_threatwatch.prioritization.service import rescore_all

KINDS = {"keyword": "Vendor / product keyword", "vulnerability": "CVE ID", "indicator": "Indicator"}


def render() -> None:
    st.title("Watchlist & Alerts")
    tab_alerts, tab_watch = st.tabs(["Alerts", "Watchlist"])
    with tab_watch:
        _watchlist()
    with tab_alerts:
        _alerts()


def _watchlist() -> None:
    st.caption(
        "Watched items raise alerts when new matching records arrive or when a watched record changes "
        "materially (e.g. added to KEV, ransomware use, due date, CVSS). Keywords also raise priority."
    )
    with st.form("add-watch", clear_on_submit=True):
        c1, c2, c3 = st.columns([2, 3, 2])
        kind = c1.selectbox("Type", list(KINDS), format_func=KINDS.__getitem__)
        value = c2.text_input(
            "Value", max_chars=500, placeholder="e.g. fortinet · CVE-2024-3400 · 198.51.100.7"
        )
        label = c3.text_input("Label (optional)", max_chars=200)
        if st.form_submit_button("Add", type="primary") and value.strip():
            try:
                if kind == "vulnerability":
                    value = canonical_cve(value)
                elif kind == "indicator":
                    value = validate_indicator(value).entity_key
                with session_scope() as s:
                    queries.add_watch(s, kind, value, label)
                    rescore_all(s, _settings())
                state.invalidate()
                st.success(f"Watching {value}")
            except (ValueError, IocValidationError) as exc:
                st.error(str(exc))
    with session_scope() as s:
        items: list[dict[str, Any]] = [
            {
                "id": w.id,
                "type": KINDS.get(w.entity_kind, w.entity_kind),
                "value": w.value,
                "label": w.label,
                "added": w.created_at,
            }
            for w in queries.watchlist(s)
        ]
    if not items:
        st.info("Your watchlist is empty.")
        return
    st.dataframe(pd.DataFrame(items).drop(columns=["id"]), hide_index=True, width="stretch")
    remove = st.multiselect(
        "Remove",
        [i["id"] for i in items],
        format_func=lambda i: next(f"{x['value']} ({x['type']})" for x in items if x["id"] == i),
    )
    if remove and st.button("Remove selected"):
        with session_scope() as s:
            for wid in remove:
                queries.remove_watch(s, int(wid))
            s.flush()
            rescore_all(s, _settings())
        state.invalidate()
        st.rerun()


def _alerts() -> None:
    show_ack = st.toggle("Include acknowledged")
    df = state.alerts(show_ack)
    if df.empty:
        st.info("No alerts. New high-priority records and changes to watched items will appear here.")
        return
    st.dataframe(
        df.drop(columns=["entity_kind"]),
        hide_index=True,
        width="stretch",
        column_config={"acknowledged": st.column_config.CheckboxColumn("Ack")},
    )
    open_ids = df.loc[~df["acknowledged"], "id"].tolist()
    if open_ids:
        ack = st.multiselect(
            "Acknowledge",
            open_ids,
            format_func=lambda i: f"#{i} " + str(df.loc[df["id"] == i, "title"].iloc[0])[:80],
        )
        c1, c2 = st.columns(2)
        if c1.button("Acknowledge selected", disabled=not ack):
            _ack(ack)
        if c2.button(f"Acknowledge all {len(open_ids)} open"):
            _ack(open_ids)


def _ack(ids: list[int]) -> None:
    with session_scope() as s:
        queries.acknowledge_alerts(s, [int(i) for i in ids])
    state.invalidate()
    st.rerun()


def _settings() -> Settings:
    from siren_threatwatch.config import get_settings

    return get_settings()
