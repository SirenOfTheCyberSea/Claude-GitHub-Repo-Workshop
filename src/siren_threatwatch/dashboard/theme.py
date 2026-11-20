"""Navy / burgundy / teal styling. Base colours come from `.streamlit/config.toml` ([theme.dark] and
[theme.light]); this module adds card styles and a matching Plotly template."""

from __future__ import annotations

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

NAVY = "#0B1426"
NAVY_2 = "#13213D"
BURGUNDY = "#8C1C3A"
TEAL = "#2EC4B6"
PALETTE = [TEAL, "#C2456A", "#5B8DEF", "#E0A030", "#9B6FD1", "#4FB477", "#E06C3C", "#7A8BA8"]


def is_light() -> bool:
    try:
        return st.context.theme.type == "light"
    except Exception:  # older Streamlit / no context
        return False


def apply_theme() -> None:
    light = is_light()
    card_bg = "#FFFFFF" if light else NAVY_2
    border = "#C9D1E0" if light else "#2A3A5C"
    muted = "#4A5875" if light else "#A9B6CF"
    st.markdown(
        f"""
<style>
.stw-card {{ background:{card_bg}; border:1px solid {border}; border-left:4px solid {BURGUNDY};
  border-radius:8px; padding:0.8rem 1rem; margin-bottom:0.7rem; }}
.stw-title {{ font-weight:600; font-size:1.02rem; line-height:1.4; }}
.stw-body {{ margin:0.35rem 0; font-size:0.93rem; line-height:1.5; overflow-wrap:anywhere; }}
.stw-meta {{ color:{muted}; font-size:0.82rem; overflow-wrap:anywhere; }}
.stw-meta a {{ color:{TEAL if not light else "#0B6E66"}; }}
.stw-badge {{ display:inline-block; padding:0.08rem 0.5rem; margin-left:0.3rem; border-radius:999px;
  font-size:0.74rem; font-weight:600; color:#fff; background:{BURGUNDY}; vertical-align:middle; }}
div[data-testid="stMetric"] {{ background:{card_bg}; border:1px solid {border}; border-radius:8px;
  padding:0.6rem 0.8rem; }}
</style>""",
        unsafe_allow_html=True,
    )
    _register_plotly(light)


def _register_plotly(light: bool) -> None:
    text = "#14213D" if light else "#E8EDF5"
    grid = "#D5DBE7" if light else "#22314F"
    pio.templates["siren"] = go.layout.Template(
        layout=go.Layout(
            colorway=PALETTE,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": text, "family": "sans-serif"},
            xaxis={"gridcolor": grid, "zerolinecolor": grid},
            yaxis={"gridcolor": grid, "zerolinecolor": grid},
            margin={"l": 40, "r": 20, "t": 50, "b": 40},
            legend={"orientation": "h", "y": -0.2},
        )
    )
    pio.templates.default = "siren"
