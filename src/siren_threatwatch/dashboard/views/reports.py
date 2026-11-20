from __future__ import annotations

from datetime import UTC, datetime

import streamlit as st

from siren_threatwatch.config import get_settings
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.reporting.builder import FORMATS, gather
from siren_threatwatch.reporting.builder import render as render_report
from siren_threatwatch.reporting.exporters import write_export

LABELS = {
    "md-executive": "Executive summary (Markdown)",
    "md-technical": "Analyst technical summary (Markdown)",
    "json": "Full data (JSON)",
    "csv": "CVE table (CSV, formula-injection safe)",
    "stix": "STIX 2.1 bundle (JSON)",
}
MIME = {
    ".md": "text/markdown",
    ".json": "application/json",
    ".csv": "text/csv",
    ".stix.json": "application/json",
}


def render() -> None:
    st.title("Reports")
    c1, c2 = st.columns(2)
    fmt = c1.selectbox("Report type", list(LABELS), format_func=LABELS.__getitem__)
    days = c2.selectbox(
        "Window (by KEV date added / first seen)",
        [7, 30, 90, 365, 0],
        index=1,
        format_func=lambda d: "All time" if d == 0 else f"Last {d} days",
    )
    c3, c4, c5 = st.columns(3)
    kev_only = c3.toggle("CISA KEV only")
    bands = c4.multiselect("Priority bands", ["Critical", "High", "Medium", "Low", "Informational"])
    excl_syn = c5.toggle("Exclude synthetic data", value=True)
    incl_intel = st.toggle(
        "Include actors / campaigns / software / techniques and relationships (JSON & STIX)",
        help="A full ATT&CK import adds ~1,800 objects and ~19,000 relationships.",
    )
    title = st.text_input("Report title", "Siren ThreatWatch Report", max_chars=120)

    with session_scope() as s:
        data = gather(
            s,
            period_days=days,
            kev_only=kev_only,
            bands=bands,
            include_synthetic=not excl_syn,
            include_intel=incl_intel,
            title=title,
        )
        content = render_report(data, fmt)
    ext = FORMATS[fmt]
    filename = f"siren-{fmt}-{datetime.now(UTC):%Y%m%d-%H%M}{ext}"
    st.caption(f"{len(data.vulnerabilities):,} CVEs and {len(data.indicators):,} indicators in scope.")
    a, b = st.columns(2)
    a.download_button("Download", content.encode("utf-8"), file_name=filename, mime=MIME[ext], type="primary")
    if b.button("Save to data/exports"):
        path = write_export(content, get_settings().export_dir / filename)
        st.success(f"Saved {path}")
    st.subheader("Preview")
    preview = content if len(content) < 60_000 else content[:60_000] + "\n… (truncated preview)"
    if ext == ".md":
        st.markdown(preview)  # report text is Markdown-escaped at generation time
    else:
        st.code(preview, language="json" if "json" in ext else None)
