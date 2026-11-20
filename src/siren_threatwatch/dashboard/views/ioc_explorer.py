from __future__ import annotations

import streamlit as st

from siren_threatwatch.dashboard import state, widgets
from siren_threatwatch.dashboard.components import band_badge, empty_state, md
from siren_threatwatch.db.models import INDICATOR
from siren_threatwatch.iocs.validation import IocType, IocValidationError, defang, validate_indicator


def render() -> None:
    st.title("IOC Explorer")
    st.caption(
        "Indicators are displayed **defanged** and are never resolved, fetched or linked by this tool."
    )
    c1, c2, c3, c4 = st.columns([3, 2, 1, 1])
    text = c1.text_input("Search indicator / description", max_chars=300)
    types = c2.multiselect("Type", [t.value for t in IocType])
    min_conf = c3.slider("Min confidence", 0, 100, 0, 5)
    include_syn = c4.toggle("Include synthetic", value=True)

    df = state.indicators(text or None, tuple(types), min_conf, include_syn)
    if df.empty:
        empty_state(
            "No indicators yet. IOC feeds (abuse.ch, OTX) arrive in Phase 3; run `siren seed-demo` to "
            "explore with synthetic indicators."
        )
    else:
        view = df.assign(indicator=[defang(v, t) for v, t in zip(df["value"], df["ioc_type"], strict=True)])
        view = view[
            [
                "indicator",
                "ioc_type",
                "confidence",
                "sightings",
                "priority_score",
                "priority_band",
                "tlp",
                "is_routable",
                "last_seen_at",
                "is_synthetic",
                "entity_key",
            ]
        ]
        event = st.dataframe(
            view.drop(columns=["entity_key"]),
            hide_index=True,
            width="stretch",
            height=360,
            on_select="rerun",
            selection_mode="single-row",
            column_config={
                "indicator": "Indicator (defanged)",
                "ioc_type": "Type",
                "priority_score": st.column_config.ProgressColumn(
                    "Priority", min_value=0, max_value=100, format="%.0f"
                ),
                "is_routable": st.column_config.CheckboxColumn("Routable"),
                "is_synthetic": st.column_config.CheckboxColumn("Synthetic"),
            },
        )
        rows = event.selection.rows if event and event.selection else []
        if rows:
            _detail(df.iloc[rows[0]].to_dict())

    st.divider()
    st.subheader("Validate an indicator (offline)")
    st.caption(
        "Parses and normalises locally — accepts defanged input such as hxxp://example[.]com. "
        "Nothing is looked up or contacted."
    )
    raw = st.text_input("Indicator", max_chars=2048, key="ioc-validate")
    if raw:
        try:
            v = validate_indicator(raw)
            st.success(f"Valid **{v.ioc_type.value}**")
            st.code(
                f"canonical: {defang(v.value, v.ioc_type)}\noriginal:  {v.original}"
                + (f"\nroutable:  {v.is_routable}" if v.is_routable is not None else ""),
                language=None,
            )
        except IocValidationError as exc:
            st.error(f"Invalid: {exc}")


def _detail(row: dict) -> None:
    st.divider()
    shown = defang(row["value"], row["ioc_type"])
    st.markdown(
        f"### {md(row['ioc_type'])} indicator {band_badge(row['priority_band'], row['priority_score'])}",
        unsafe_allow_html=True,
    )
    if row["is_synthetic"]:
        st.warning("SYNTHETIC DEMO RECORD — fabricated, documentation-range value.")
    st.code(
        f"defanged:  {shown}\noriginal (as reported, may be defanged): {row['original_value']}", language=None
    )
    if row["is_routable"] is False:
        st.info("Private / reserved / documentation address — limited external relevance.")
    detail = state.entity_detail(INDICATOR, row["entity_key"])
    t1, t2, t3, t4 = st.tabs(["Context & relationships", "Sightings / provenance", "Priority", "Analyst"])
    with t1:
        st.write(row["description"] or "No description.")
        widgets.relationships(detail)
    with t2:
        widgets.provenance(detail)
        widgets.history(detail)
    with t3:
        widgets.score(detail)
    with t4:
        widgets.analyst_panel(INDICATOR, row["entity_key"], detail)
