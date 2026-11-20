from __future__ import annotations

import streamlit as st

from siren_threatwatch.dashboard import state
from siren_threatwatch.dashboard.components import badge, card, empty_state, esc, fmt_dt, link
from siren_threatwatch.iocs.validation import defang


def render() -> None:
    st.title("Threat Feed")
    st.caption(
        "Every card is one source observation, with its citation and timestamps. Content is untrusted "
        "source text, displayed as plain text; indicators are defanged."
    )
    health = state.health()
    sources = sorted(health["source"].tolist()) if not health.empty else []
    c1, c2, c3, c4 = st.columns([3, 2, 2, 1])
    text = c1.text_input("Search", placeholder="CVE, vendor, keyword…", max_chars=200)
    pick_sources = c2.multiselect("Sources", sources)
    kinds = c3.multiselect("Type", ["vulnerability", "indicator", "intel"])
    days = c4.selectbox(
        "Window", [7, 30, 90, 365, 0], index=1, format_func=lambda d: "All" if d == 0 else f"{d}d"
    )
    df = state.feed(text or None, tuple(pick_sources), tuple(kinds), days or None, 300)
    if df.empty:
        empty_state("No observations match these filters.")
        return
    page_size = 25
    pages = max(1, (len(df) + page_size - 1) // page_size)
    page = st.number_input(f"Page (1–{pages}) · {len(df)} results", 1, pages, 1)
    for row in df.iloc[(page - 1) * page_size : page * page_size].to_dict(orient="records"):
        key = row["entity_key"]
        if row["entity_kind"] == "indicator":
            ioc_type, _, value = key.partition(":")
            key = f"{ioc_type}:{defang(value, ioc_type)}"
        meta = [
            f"Source: <b>{esc(row['source'])}</b>",
            f"Published {esc(fmt_dt(row['published_at']))}",
            f"Ingested {esc(fmt_dt(row['ingested_at']))}",
            f"Confidence {esc(row['confidence']) if row['confidence'] is not None else 'n/a'}",
            f"TLP {esc(row['tlp'] or 'not supplied')}",
            link(row["source_url"], "Source citation") if row["source_url"] else "No source URL",
        ]
        card(
            f"{row['title']}",
            row["description"],
            meta,
            badge(row["entity_kind"]) + badge(key, "#34476B"),
            synthetic=row["is_synthetic"],
        )
