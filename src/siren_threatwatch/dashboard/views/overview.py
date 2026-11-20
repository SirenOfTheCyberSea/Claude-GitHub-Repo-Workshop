from __future__ import annotations

import plotly.express as px
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.dashboard import state
from siren_threatwatch.dashboard.components import (
    band_badge,
    card,
    empty_state,
    esc,
    fmt_dt,
    synthetic_notice,
)
from siren_threatwatch.db.base import session_scope


def render() -> None:
    st.title("Overview")
    m = state.metrics()
    synthetic_notice(m["synthetic_records"])
    if not m["vulnerabilities"] and not m["indicators"]:
        empty_state(
            "No intelligence yet. Go to **Settings → Ingest now** (CISA KEV needs no API key), "
            "or run `siren ingest --source cisa_kev`. To explore with fake data, run `siren seed-demo`."
        )
        return

    c = st.columns(4)
    c[0].metric("CVEs in CISA KEV", f"{m['kev']:,}", help="Listed by CISA as known exploited")
    c[1].metric("Added to KEV (7 days)", m["kev_last_7d"])
    c[2].metric("KEV: known ransomware use", f"{m['ransomware']:,}", help="As reported by CISA")
    c[3].metric("Critical / High priority", f"{m['high_priority']:,}", help="Computed triage priority")
    c = st.columns(4)
    c[0].metric("Vulnerabilities tracked", f"{m['vulnerabilities']:,}")
    c[1].metric("Indicators", f"{m['indicators']:,}")
    c[2].metric("Actors / campaigns / malware / techniques", m["intel"])
    c[3].metric("Open alerts", m["open_alerts"])

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Highest computed priority")
        top = state.vulns(limit=8)
        for row in top.to_dict(orient="records"):
            meta = [
                f"{esc(row['vendor'])} / {esc(row['product'])}",
                f"KEV added {esc(fmt_dt(row['kev_date_added']))}" if row["kev_listed"] else "Not in KEV",
                f"Ransomware (CISA): {esc(row['kev_ransomware_use'] or 'n/a')}",
            ]
            card(
                f"{row['cve_id']} — {row['title'] or ''}",
                None,
                meta,
                band_badge(row["priority_band"], row["priority_score"]),
                synthetic=row["is_synthetic"],
            )
    with right:
        st.subheader("Newest KEV additions")
        newest = state.vulns(kev_only=True, limit=5000)
        if not newest.empty:
            newest = newest.sort_values("kev_date_added", ascending=False).head(8)
            for row in newest.to_dict(orient="records"):
                card(
                    row["cve_id"],
                    row["title"],
                    [
                        f"Added {esc(fmt_dt(row['kev_date_added']))}",
                        f"Due {esc(fmt_dt(row['kev_due_date']))}",
                    ],
                    synthetic=row["is_synthetic"],
                )

    st.subheader("KEV additions — last 90 days")
    ts = state.kev_timeseries(90)
    if ts.empty:
        st.caption("No KEV additions in this window.")
    else:
        daily = ts.groupby("date").size().reset_index(name="count")
        fig = px.bar(daily, x="date", y="count", labels={"date": "Date added", "count": "CVEs added"})
        st.plotly_chart(fig, width="stretch")

    a, b = st.columns(2)
    with a:
        st.subheader("Actor & campaign highlights")
        with session_scope() as s:
            items = [
                (o.kind, o.name, o.is_synthetic)
                for o in queries.intel_objects(s)
                if o.kind in ("threat-actor", "campaign")
            ]
        if not items:
            st.caption("No actors or campaigns yet (MITRE ATT&CK / OTX connectors arrive in later phases).")
        for kind, name, syn in items[:8]:
            card(name, None, [esc(kind)], synthetic=syn)
    with b:
        st.subheader("Ingestion health")
        h = state.health()
        if h.empty:
            st.caption("No ingestion runs yet.")
        else:
            st.dataframe(
                h[
                    [
                        "source",
                        "last_status",
                        "last_run",
                        "last_success",
                        "consecutive_failures",
                        "records_fetched",
                    ]
                ],
                hide_index=True,
                width="stretch",
            )
