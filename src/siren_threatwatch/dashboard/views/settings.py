from __future__ import annotations

import pandas as pd
import streamlit as st

from siren_threatwatch import queries
from siren_threatwatch.config import get_settings
from siren_threatwatch.connectors import CONNECTORS, SOURCE_CATALOG
from siren_threatwatch.dashboard import state
from siren_threatwatch.db.base import session_scope
from siren_threatwatch.ingestion.pipeline import ingest_source


def render() -> None:
    st.title("Settings")
    settings = get_settings()
    creds = settings.credential_status()

    st.subheader("Sources")
    rows = []
    for spec in SOURCE_CATALOG:
        if spec.implemented and spec.name in CONNECTORS:
            ready, reason = CONNECTORS[spec.name](settings).configuration_status()
            status = "Ready" if ready else "Disabled"
        else:
            status, reason = "Planned", f"Phase {spec.phase} — not implemented yet"
        cred = "Not required"
        if spec.requires_credential:
            env = spec.requires_credential.split()[0]
            cred = f"{env}: {'configured' if creds.get(env) else 'not set'}"
        rows.append(
            {
                "source": spec.display_name,
                "id": spec.name,
                "status": status,
                "detail": reason,
                "credential": cred,
                "notes": spec.notes,
                "docs": spec.docs_url or None,
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        column_config={"docs": st.column_config.LinkColumn("Documentation")},
    )
    st.caption(
        "Credentials are read from environment variables / `.env` and are never displayed or logged — "
        "only whether they are set."
    )

    st.subheader("Synchronise")
    c1, c2, c3 = st.columns(3)
    if c1.button("Ingest CISA KEV now", type="primary"):
        with st.spinner("Fetching CISA KEV…"):
            summary = ingest_source("cisa_kev", settings)
        state.invalidate()
        (st.success if summary.status in ("success", "partial") else st.error)(
            f"{summary.status}: new={summary.new} updated={summary.updated} unchanged={summary.unchanged} "
            f"rejected={summary.rejected} alerts={summary.alerts}"
            + (f" — {summary.error}" if summary.error else "")
        )
    if c2.button("Load synthetic demo data"):
        summary = ingest_source("synthetic_demo", settings)
        state.invalidate()
        st.success(f"Demo data loaded ({summary.new} new). It is clearly labelled SYNTHETIC.")
    if c3.button("Remove synthetic demo data"):
        with session_scope() as s:
            removed = queries.purge_synthetic(s)
        state.invalidate()
        st.success(f"Removed {removed} synthetic rows.")

    st.subheader("Schedule")
    st.markdown(
        f"Recurring ingestion interval: **{settings.schedule_interval_minutes} minutes** "
        "(`SIREN_SCHEDULE_INTERVAL_MINUTES`). Run `siren schedule` in a separate terminal to enable it."
    )

    st.subheader("Synchronisation history")
    r = state.runs()
    if r.empty:
        st.info("No runs yet.")
    else:
        st.dataframe(r, hide_index=True, width="stretch")

    st.subheader("Security posture")
    st.markdown(
        "- Passive collection only from allowlisted HTTPS hosts; redirects re-validated; no indicator is ever "
        "visited, resolved or scanned.\n"
        "- Dashboard bound to `127.0.0.1` by default. **It has no authentication** — see README before exposing it.\n"
        "- Source content is treated as untrusted and rendered escaped; CSV exports neutralise formulas.\n"
        f"- Database: `{settings.database_url.split('@')[-1]}` · data directory permissions restricted to owner."
    )
