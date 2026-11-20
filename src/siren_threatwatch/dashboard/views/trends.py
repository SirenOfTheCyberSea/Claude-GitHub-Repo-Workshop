from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from siren_threatwatch.dashboard import state
from siren_threatwatch.dashboard.components import empty_state


def render() -> None:
    st.title("Trends & Analytics")
    c1, c2 = st.columns(2)
    days = c1.selectbox("Window", [30, 90, 180, 365, 730], index=3, format_func=lambda d: f"Last {d} days")
    grain = c2.radio("Granularity", ["Daily", "Weekly"], horizontal=True, index=1)
    freq = "D" if grain == "Daily" else "W-MON"

    kev = state.kev_timeseries(days)
    st.subheader("CISA KEV additions")
    if kev.empty:
        empty_state("No KEV additions in this window.")
    else:
        kev["ransomware"] = (
            kev["ransomware"]
            .fillna("n/a")
            .map({"Known": "Known ransomware use", "Unknown": "Unknown", "n/a": "n/a"})
        )
        grouped = (
            kev.groupby([pd.Grouper(key="date", freq=freq), "ransomware"]).size().reset_index(name="count")
        )
        st.plotly_chart(
            px.bar(
                grouped,
                x="date",
                y="count",
                color="ransomware",
                labels={"date": "", "count": "CVEs added", "ransomware": "Ransomware (CISA)"},
            ),
            width="stretch",
        )

    obs = state.obs_timeseries(days)
    st.subheader("Observations by source")
    if obs.empty:
        empty_state("No observations in this window.")
    else:
        g = obs.groupby([pd.Grouper(key="date", freq=freq), "source"]).size().reset_index(name="count")
        st.plotly_chart(
            px.line(
                g,
                x="date",
                y="count",
                color="source",
                markers=True,
                labels={"date": "", "count": "Observations"},
            ),
            width="stretch",
        )
        a, b = st.columns(2)
        a.plotly_chart(px.pie(obs, names="source", title="Source distribution", hole=0.45), width="stretch")
        b.plotly_chart(
            px.pie(obs, names="entity_kind", title="Category distribution", hole=0.45), width="stretch"
        )

    v = state.vulns(limit=100_000)
    if not v.empty:
        a, b = st.columns(2)
        top = v["vendor"].value_counts().head(15).reset_index()
        top.columns = ["vendor", "count"]
        a.plotly_chart(
            px.bar(
                top, x="count", y="vendor", orientation="h", title="Top vendors (tracked CVEs)"
            ).update_yaxes(autorange="reversed"),
            width="stretch",
        )
        bands = (
            v["priority_band"]
            .fillna("Unscored")
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low", "Informational", "Unscored"])
            .dropna()
            .reset_index()
        )
        bands.columns = ["band", "count"]
        b.plotly_chart(
            px.bar(
                bands,
                x="band",
                y="count",
                title="Computed priority distribution",
                color="band",
                color_discrete_map={
                    "Critical": "#B3263E",
                    "High": "#D9534F",
                    "Medium": "#E0A030",
                    "Low": "#2EC4B6",
                },
            ),
            width="stretch",
        )
