"""Streamlit entry point. Launch with ``siren dashboard`` (binds to 127.0.0.1)."""

from __future__ import annotations

import streamlit as st

from siren_threatwatch import __version__
from siren_threatwatch.dashboard import state
from siren_threatwatch.dashboard.theme import apply_theme
from siren_threatwatch.dashboard.views import (
    actors,
    cve_explorer,
    ioc_explorer,
    overview,
    reports,
    settings,
    threat_feed,
    trends,
    watchlist,
)

st.set_page_config(
    page_title="Siren ThreatWatch", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded"
)
apply_theme()
state.bootstrap()

pages = {
    "Intelligence": [
        st.Page(overview.render, title="Overview", icon="🧭", default=True),
        st.Page(threat_feed.render, title="Threat Feed", icon="📰", url_path="feed"),
        st.Page(cve_explorer.render, title="CVE Explorer", icon="🐞", url_path="cves"),
        st.Page(ioc_explorer.render, title="IOC Explorer", icon="🔎", url_path="iocs"),
        st.Page(actors.render, title="Threat Actors & Campaigns", icon="🎭", url_path="actors"),
        st.Page(trends.render, title="Trends & Analytics", icon="📈", url_path="trends"),
    ],
    "Workflow": [
        st.Page(watchlist.render, title="Watchlist & Alerts", icon="🔔", url_path="alerts"),
        st.Page(reports.render, title="Reports", icon="📄", url_path="reports"),
        st.Page(settings.render, title="Settings", icon="⚙️", url_path="settings"),
    ],
}

with st.sidebar:
    st.markdown("### 🛡️ Siren ThreatWatch")
    st.caption(f"Defensive CTI · v{__version__}")

nav = st.navigation(pages)
with st.sidebar:
    st.divider()
    open_alerts = state.metrics()["open_alerts"]
    if open_alerts:
        st.markdown(f"🔔 **{open_alerts}** open alert(s)")
    st.caption(
        "Theme: ⋮ menu → Settings → light/dark.\nPassive collection only. Scores are triage aids, "
        "not exploitation evidence."
    )
nav.run()
