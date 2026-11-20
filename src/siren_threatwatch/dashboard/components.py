"""Safe rendering helpers.

All source content is untrusted. Rules:
* HTML is only produced by these helpers, and every dynamic value is ``html.escape``-d.
* Plain-text Markdown uses :func:`md` which escapes Markdown syntax (prevents injected links/images,
  which would otherwise make the browser fetch attacker-chosen URLs).
* Indicators are always shown defanged and never as links.
* Only syntactically valid http(s) reference URLs become links, with ``rel="noopener noreferrer nofollow"``.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from datetime import date, datetime
from typing import Any

import pandas as pd
import streamlit as st

from siren_threatwatch.normalization.schema import safe_http_url
from siren_threatwatch.reporting.exporters import md_escape

BAND_COLORS = {
    "Critical": "#B3263E",
    "High": "#D9534F",
    "Medium": "#E0A030",
    "Low": "#2EC4B6",
    "Informational": "#6C7A96",
}


def esc(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return html.escape(str(value), quote=True)


def md(value: Any) -> str:
    return md_escape(value)


def fmt_dt(value: Any) -> str:
    if value is None or value is pd.NaT or (isinstance(value, float) and pd.isna(value)):
        return "—"
    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def badge(text: str, color: str | None = None) -> str:
    style = f' style="background:{esc(color)}"' if color else ""
    return f'<span class="stw-badge"{style}>{esc(text)}</span>'


def band_badge(band: str | None, score: float | None = None) -> str:
    if not band:
        return badge("Unscored", BAND_COLORS["Informational"])
    label = f"{band} {score:.0f}" if score is not None and not pd.isna(score) else band
    return badge(label, BAND_COLORS.get(band, BAND_COLORS["Informational"]))


def link(url: str | None, label: str | None = None) -> str:
    """Return an anchor for a validated http(s) URL, otherwise escaped plain text."""
    safe = safe_http_url(url)
    if not safe:
        return esc(label or url or "")
    return (
        f'<a href="{esc(safe)}" target="_blank" rel="noopener noreferrer nofollow">{esc(label or safe)}</a>'
    )


def card(
    title: str,
    body: str | None = None,
    meta: Iterable[str] = (),
    badges_html: str = "",
    synthetic: bool = False,
) -> None:
    """Render an intelligence card. ``title``/``body``/``meta`` are escaped here; ``badges_html`` must be
    produced by :func:`badge`/:func:`band_badge`/:func:`link` (already escaped)."""
    syn = badge("SYNTHETIC DEMO", "#7A3B69") if synthetic else ""
    body_html = f'<div class="stw-body">{esc(body)}</div>' if body else ""
    meta_html = " · ".join(meta)
    st.markdown(
        f'<div class="stw-card"><div class="stw-title">{esc(title)} {badges_html} {syn}</div>'
        f'{body_html}<div class="stw-meta">{meta_html}</div></div>',
        unsafe_allow_html=True,
    )


def score_breakdown(factors: list[dict[str, Any]], label: str) -> None:
    st.caption(label)
    if not factors:
        st.info("No score computed yet.")
        return
    df = pd.DataFrame(factors)[["name", "points", "evidence", "detail"]]
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        column_config={
            "name": "Factor",
            "points": st.column_config.NumberColumn("Points", format="%.1f"),
            "evidence": st.column_config.TextColumn(
                "Evidence type", help="source-reported · computed · analyst · missing"
            ),
            "detail": "Explanation",
        },
    )


def synthetic_notice(count: int) -> None:
    if count:
        st.warning(
            f"This database contains {count} SYNTHETIC demo observations (labelled “SYNTHETIC DEMO”). "
            "They are fabricated for demonstration only. Remove them in Settings or with `siren purge-demo`.",
            icon="⚠️",
        )


def empty_state(message: str) -> None:
    st.info(message, icon="ℹ️")
