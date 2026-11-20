from __future__ import annotations

import pandas as pd
import streamlit as st

from siren_threatwatch.dashboard import state, widgets
from siren_threatwatch.dashboard.components import band_badge, empty_state, esc, fmt_dt, link, md
from siren_threatwatch.db.models import ANALYST_STATUSES, VULNERABILITY


def render() -> None:
    st.title("CVE Explorer")
    with st.expander("Filters", expanded=True):
        c1, c2, c3 = st.columns([3, 2, 2])
        text = c1.text_input("Search CVE / vendor / product / text", max_chars=200)
        bands = c2.multiselect("Priority band", ["Critical", "High", "Medium", "Low", "Informational"])
        statuses = c3.multiselect("Analyst status", list(ANALYST_STATUSES))
        c4, c5, c6, c7 = st.columns(4)
        kev_only = c4.toggle("CISA KEV only")
        ransomware = c5.toggle("Known ransomware use")
        window = c6.selectbox(
            "Added / first seen",
            [0, 7, 30, 90, 365],
            format_func=lambda d: "Any time" if d == 0 else f"Last {d} days",
        )
        include_syn = c7.toggle("Include synthetic", value=True)
        all_vendors = state.vulns(limit=100_000)
        vendor_opts = (
            sorted(v for v in all_vendors["vendor"].dropna().unique()) if not all_vendors.empty else []
        )
        vendors = st.multiselect("Vendor", vendor_opts)

    df = state.vulns(
        text or None,
        kev_only,
        ransomware,
        tuple(bands),
        tuple(vendors),
        tuple(statuses),
        window or None,
        include_syn,
    )
    if df.empty:
        empty_state("No CVEs match. If the database is empty, ingest CISA KEV from Settings.")
        return
    st.caption(f"{len(df):,} CVEs · sorted by computed priority. Select a row for details.")
    view = df[
        [
            "cve_id",
            "priority_score",
            "priority_band",
            "vendor",
            "product",
            "cvss_score",
            "kev_listed",
            "kev_date_added",
            "kev_due_date",
            "kev_ransomware_use",
            "status",
            "is_synthetic",
        ]
    ]
    event = st.dataframe(
        view,
        hide_index=True,
        width="stretch",
        height=380,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "cve_id": "CVE",
            "priority_score": st.column_config.ProgressColumn(
                "Priority", min_value=0, max_value=100, format="%.0f", help="Computed triage aid"
            ),
            "priority_band": "Band",
            "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "kev_listed": st.column_config.CheckboxColumn("KEV"),
            "kev_date_added": "KEV added",
            "kev_due_date": "KEV due",
            "kev_ransomware_use": "Ransomware (CISA)",
            "status": "Status",
            "is_synthetic": st.column_config.CheckboxColumn("Synthetic"),
        },
    )
    rows = event.selection.rows if event and event.selection else []
    manual = st.text_input("…or look up a CVE ID", placeholder="CVE-2024-12345", max_chars=30)
    cve = manual.strip().upper() if manual.strip() else (view.iloc[rows[0]]["cve_id"] if rows else None)
    if not cve:
        return
    match = df[df["cve_id"] == cve]
    if match.empty:
        match = state.vulns(text=cve, include_synthetic=True)
        if not match.empty:
            match = match[match["cve_id"] == cve]
    if match.empty:
        st.warning(f"{cve} is not in the local database.")
        if st.button(f"Look up {cve} in NVD", type="primary"):
            _nvd_lookup(cve)
        return
    _detail(match.iloc[0].to_dict())


def _detail(row: dict) -> None:
    cve = row["cve_id"]
    st.divider()
    st.markdown(
        f"## {md(cve)} {band_badge(row['priority_band'], row['priority_score'])}", unsafe_allow_html=True
    )
    if row["is_synthetic"]:
        st.warning("SYNTHETIC DEMO RECORD — fabricated, not real intelligence.")
    st.markdown(f"**{md(row['title'])}**")
    st.write(row["description"] or "No description.")
    detail = state.entity_detail(VULNERABILITY, cve)
    t1, t2, t3, t4, t5 = st.tabs(
        [
            "Exploitation & remediation",
            "Priority explanation",
            "Provenance",
            "Relationships & history",
            "Analyst",
        ]
    )
    with t1:
        c1, c2, c3, c4 = st.columns(4)
        cvss = row["cvss_score"]
        has_cvss = cvss is not None and not pd.isna(cvss)
        c1.metric(
            " · ".join(x for x in (f"CVSS {row['cvss_version'] or ''}".strip(), row["cvss_severity"]) if x),
            f"{cvss:.1f}" if has_cvss else "Unavailable",
            help="Headline score: NVD's v3.1 > v3.0 > v4.0 > v2, preferring NVD's Primary assessment",
        )
        c2.metric("CISA KEV", "Listed" if row["kev_listed"] else "Not listed")
        c3.metric("Ransomware use (CISA)", row["kev_ransomware_use"] or "n/a")
        c4.metric("NVD status", row["nvd_status"] or "Not enriched")
        if not row["is_synthetic"] and st.button("Refresh from NVD", key=f"nvd-{cve}"):
            _nvd_lookup(cve)
        st.markdown(
            f"**Affected (as named by {md(row['field_sources'].get('vendor', 'source'))}):** "
            f"{md(row['vendor'])} — {md(row['product'])}"
        )
        if row["cvss_metrics"]:
            st.markdown("**All CVSS assessments listed by NVD**")
            st.dataframe(pd.DataFrame(row["cvss_metrics"]), hide_index=True, width="stretch")
        if row["affected_products"]:
            with st.expander(
                f"Affected products — {len(row['affected_products'])} vulnerable CPE match(es) (NVD)"
            ):
                st.dataframe(
                    pd.DataFrame({"product / version range": row["affected_products"]}),
                    hide_index=True,
                    width="stretch",
                )
        if row["cwes"]:
            st.markdown(f"**CWE:** {md(row['cwes'])}")
        if row["kev_listed"]:
            st.markdown(
                f"**KEV date added:** {fmt_dt(row['kev_date_added'])} · **Federal due date:** "
                f"{fmt_dt(row['kev_due_date'])}"
            )
            st.markdown("**Required action (CISA):**")
            st.write(row["kev_required_action"] or "—")
        st.markdown("**Remediation references** (opened only if you click; never fetched by this tool):")
        refs = row["references"] or []
        st.markdown("<br>".join(link(r) for r in refs) or "None", unsafe_allow_html=True)
        st.caption(
            f"Signals shown are as reported by cited sources. {esc('EPSS: not configured (planned).')}"
        )
    with t2:
        widgets.score(detail)
    with t3:
        if row["field_sources"]:
            st.markdown("**Which source supplied each field**")
            st.dataframe(
                pd.DataFrame(sorted(row["field_sources"].items()), columns=["field", "source"]),
                hide_index=True,
                width="stretch",
            )
        widgets.provenance(detail)
    with t4:
        widgets.relationships(detail)
        widgets.history(detail)
    with t5:
        widgets.analyst_panel(VULNERABILITY, cve, detail)


def _nvd_lookup(cve: str) -> None:
    """On-demand single-CVE fetch from the NVD API (passive, rate-paced)."""
    from siren_threatwatch.config import get_settings
    from siren_threatwatch.ingestion.pipeline import ingest_source

    with st.spinner(f"Querying NVD for {cve}…"):
        summary = ingest_source("nvd", get_settings(), cve_ids=[cve])
    state.invalidate()
    if summary.status == "failed":
        st.error(f"NVD lookup failed: {summary.error}")
    elif summary.fetched == 0:
        st.warning(f"NVD has no record of {cve}.")
    else:
        st.success(f"Updated from NVD ({summary.new} new, {summary.updated} updated).")
        st.rerun()
