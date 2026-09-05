"""Shared color palette and chart helpers for all dashboard pages."""
from typing import Tuple


# ── Semantic colors ───────────────────────────────────────────────────────────
C_HEALTHY  = "#1a7f37"
C_WARNING  = "#9a6700"
C_CRITICAL = "#cf222e"
C_BLUE     = "#0969da"
C_PURPLE   = "#8250df"
C_ORANGE   = "#bc4c00"

# ── Layout colors ─────────────────────────────────────────────────────────────
BG_PAGE  = "#f6f8fa"
BG_CARD  = "#ffffff"
BG_CHART = "#f6f8fa"
BORDER   = "#d0d7de"
TEXT_DIM  = "#57606a"
TEXT_MAIN = "#24292f"

# ── Per-metric palette ────────────────────────────────────────────────────────
METRIC_COLORS = {
    "availability_score":  C_BLUE,
    "response_time_score": C_HEALTHY,
    "link_score":          C_PURPLE,
    "security_score":      C_ORANGE,
}

# ── RGB tuples for rgba() conversion ─────────────────────────────────────────
_RGB: dict[str, Tuple[int, int, int]] = {
    C_HEALTHY:  (26,  127, 55),
    C_WARNING:  (154, 103, 0),
    C_CRITICAL: (207, 34,  46),
    C_BLUE:     (9,   105, 218),
    C_PURPLE:   (130, 80,  223),
    C_ORANGE:   (188, 76,  0),
}


def rgba(hex_color: str, alpha: float = 0.12) -> str:
    """Convert a known hex color to rgba() string safe for Plotly fillcolor."""
    r, g, b = _RGB.get(hex_color, (128, 128, 128))
    return f"rgba({r},{g},{b},{alpha})"


# ── Shared Plotly layout defaults ─────────────────────────────────────────────
def chart_layout(**overrides) -> dict:
    base = dict(
        paper_bgcolor=BG_CARD,
        plot_bgcolor=BG_CHART,
        font=dict(color=TEXT_MAIN, size=12),
        xaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM)),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM)),
        legend=dict(
            bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1,
            font=dict(color=TEXT_MAIN), orientation="h", yanchor="bottom", y=1.02,
        ),
        margin=dict(t=60, b=40, l=55, r=20),
    )
    base.update(overrides)
    return base


def risk_info(score: float) -> Tuple[str, str, str]:
    """Returns (label, hex_color, bg_rgba)."""
    if score >= 80:
        return "正常", C_HEALTHY, rgba(C_HEALTHY, 0.08)
    if score >= 60:
        return "警告", C_WARNING, f"rgba(154,103,0,0.08)"
    return "异常", C_CRITICAL, rgba(C_CRITICAL, 0.08)


def bar_color(v: float) -> str:
    return C_HEALTHY if v >= 80 else (C_WARNING if v >= 60 else C_CRITICAL)