# Shared visual constants and helpers for all pages.

# ── Palette ───────────────────────────────────────────────────────────────────
C_HEALTHY  = "#1a7f37"
C_WARNING  = "#9a6700"
C_CRITICAL = "#cf222e"
C_BLUE     = "#0969da"
C_PURPLE   = "#8250df"
C_ORANGE   = "#bc4c00"
C_TEAL     = "#0e7490"
C_INDIGO   = "#3730a3"

BG_PAGE    = "#f0f4f8"
BG_CARD    = "#ffffff"
BG_CHART   = "#f8fafc"
BG_HEADER  = "linear-gradient(135deg,#0969da 0%,#8250df 100%)"
BORDER     = "#e2e8f0"
BORDER_MED = "#cbd5e1"
TEXT_DIM   = "#64748b"
TEXT_MAIN  = "#1e293b"
TEXT_LIGHT = "#94a3b8"

_RGB = {
    C_HEALTHY:  (26,  127, 55),
    C_WARNING:  (154, 103, 0),
    C_CRITICAL: (207, 34,  46),
    C_BLUE:     (9,   105, 218),
    C_PURPLE:   (130, 80,  223),
    C_ORANGE:   (188, 76,  0),
    C_TEAL:     (14,  116, 144),
    C_INDIGO:   (55,  48,  163),
}

CHART_PALETTE = [C_BLUE, C_HEALTHY, C_PURPLE, C_ORANGE, C_TEAL, C_CRITICAL, C_INDIGO]


def rgba(hex_color: str, alpha: float = 0.12) -> str:
    r, g, b = _RGB.get(hex_color, (128, 128, 128))
    return f"rgba({r},{g},{b},{alpha})"


def risk_info(score: float):
    if score >= 80: return "正常", C_HEALTHY, rgba(C_HEALTHY, 0.08)
    if score >= 60: return "警告", C_WARNING, rgba(C_WARNING, 0.08)
    return "异常", C_CRITICAL, rgba(C_CRITICAL, 0.08)


def score_color(score: float) -> str:
    if score >= 80: return C_HEALTHY
    if score >= 60: return C_WARNING
    return C_CRITICAL


def chart_layout(**overrides) -> dict:
    base = dict(
        paper_bgcolor=BG_CARD,
        plot_bgcolor=BG_CHART,
        font=dict(color=TEXT_MAIN, family="'Inter','PingFang SC','Microsoft YaHei',sans-serif", size=12),
        xaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED, tickfont=dict(color=TEXT_DIM), zeroline=False),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED, tickfont=dict(color=TEXT_DIM), zeroline=False),
        legend=dict(
            bgcolor="rgba(255,255,255,0.9)", bordercolor=BORDER, borderwidth=1,
            font=dict(color=TEXT_MAIN, size=11), orientation="h",
            yanchor="bottom", y=1.02, xanchor="left", x=0,
        ),
        margin=dict(t=60, b=44, l=58, r=24),
        hoverlabel=dict(bgcolor=BG_CARD, bordercolor=BORDER, font=dict(color=TEXT_MAIN, size=12)),
    )
    base.update(overrides)
    return base


# ── Global CSS injected once in main.py ───────────────────────────────────────
GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* ── Base ── */
[data-testid="stAppViewContainer"] {
    background: #f0f4f8;
    font-family: 'Inter','PingFang SC','Microsoft YaHei',sans-serif;
}
[data-testid="stMainBlockContainer"] { padding-top: 1.2rem; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#0f2044 0%,#1a3a6b 60%,#0d2137 100%) !important;
    border-right: 1px solid #1e4080;
}
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
[data-testid="stSidebar"] hr { border-color: #1e4080 !important; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color: #94a3b8 !important; }
[data-testid="stSidebar"] label { color: #cbd5e1 !important; }
[data-testid="stRadio"] label {
    padding: 8px 12px; border-radius: 8px; cursor: pointer;
    transition: background 0.15s;
}
[data-testid="stRadio"] label:hover { background: rgba(255,255,255,0.10) !important; }
[data-testid="stRadio"] [aria-checked="true"] label {
    background: linear-gradient(90deg,rgba(9,105,218,0.40),rgba(130,80,223,0.25)) !important;
    color: #93c5fd !important;
    border-left: 3px solid #60a5fa;
}

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 18px 22px;
    box-shadow: 0 1px 4px rgba(15,23,42,0.06), 0 4px 16px rgba(15,23,42,0.04);
    transition: box-shadow 0.2s;
}
[data-testid="metric-container"]:hover {
    box-shadow: 0 4px 12px rgba(15,23,42,0.10), 0 8px 24px rgba(15,23,42,0.06);
}
[data-testid="stMetricValue"] { color: #0969da !important; font-size: 1.85rem !important; font-weight: 700 !important; }
[data-testid="stMetricLabel"] { color: #64748b !important; font-size: 0.82rem !important; font-weight: 500 !important; }
[data-testid="stMetricDelta"] { font-size: 0.78rem !important; }

/* ── Tabs ── */
[data-testid="stTabs"] { border-bottom: 2px solid #e2e8f0; }
[data-testid="stTabs"] button {
    color: #64748b; border-radius: 8px 8px 0 0;
    font-weight: 500; padding: 8px 18px;
    transition: color 0.15s;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    color: #0969da !important;
    border-bottom: 2px solid #0969da;
    background: rgba(9,105,218,0.05);
    font-weight: 600;
}

/* ── DataFrame ── */
[data-testid="stDataFrame"] {
    border: 1px solid #e2e8f0; border-radius: 12px;
    background: #ffffff; overflow: hidden;
    box-shadow: 0 1px 4px rgba(15,23,42,0.05);
}

/* ── Buttons ── */
[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg,#0969da,#0550ae) !important;
    border: none !important; color: #fff !important;
    border-radius: 8px !important; font-weight: 600 !important;
    box-shadow: 0 2px 8px rgba(9,105,218,0.30) !important;
    transition: box-shadow 0.2s !important;
}
[data-testid="baseButton-primary"]:hover {
    box-shadow: 0 4px 16px rgba(9,105,218,0.45) !important;
}
[data-testid="baseButton-secondary"] {
    background: #ffffff !important; border: 1px solid #e2e8f0 !important;
    color: #1e293b !important; border-radius: 8px !important;
    font-weight: 500 !important;
}

/* ── Expander ── */
[data-testid="stExpander"] {
    background: #ffffff; border: 1px solid #e2e8f0;
    border-radius: 12px; overflow: hidden;
    box-shadow: 0 1px 3px rgba(15,23,42,0.05);
}

/* ── Slider ── */
[data-testid="stSlider"] [data-baseweb="slider"] div[role="slider"] {
    background: #0969da !important;
    box-shadow: 0 0 0 4px rgba(9,105,218,0.20) !important;
}

/* ── Info / Success / Warning boxes ── */
[data-testid="stAlert"] { border-radius: 10px !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #f1f5f9; }
::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

/* ── Headings ── */
h1 { color: #1e293b !important; font-weight: 700 !important; letter-spacing: -0.5px; }
h2, h3 { color: #1e293b !important; font-weight: 600 !important; }
h4 { color: #334155 !important; font-weight: 600 !important; }

/* ── Page header banner ── */
.page-header {
    background: linear-gradient(135deg,#0969da 0%,#8250df 100%);
    border-radius: 16px; padding: 24px 32px; margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(9,105,218,0.25);
    color: #ffffff;
}
.page-header h2 { color: #ffffff !important; margin: 0; font-size: 1.4rem; }
.page-header p  { color: rgba(255,255,255,0.80); margin: 6px 0 0 0; font-size: 0.88rem; }

/* ── Stat badge ── */
.stat-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 20px;
    font-size: 0.75rem; font-weight: 600;
}

/* ── Section divider ── */
.section-title {
    font-size: 1rem; font-weight: 700; color: #1e293b;
    border-left: 4px solid #0969da; padding-left: 10px;
    margin: 20px 0 12px 0;
}
</style>
"""


# ── HTML component helpers ─────────────────────────────────────────────────────

def page_header(title: str, subtitle: str, icon: str = "") -> str:
    return (
        f'<div class="page-header">'
        f'<h2>{icon} {title}</h2>'
        f'<p>{subtitle}</p>'
        f'</div>'
    )


def section_title(text: str) -> str:
    return f'<div class="section-title">{text}</div>'


def kpi_card(label: str, value: str, sub: str = "", color: str = C_BLUE,
             icon: str = "", trend: str = "") -> str:
    trend_html = ""
    if trend == "up":
        trend_html = f'<span style="color:{C_CRITICAL};font-size:0.75rem;">▲</span>'
    elif trend == "down":
        trend_html = f'<span style="color:{C_HEALTHY};font-size:0.75rem;">▼</span>'

    return (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:14px;'
        f'padding:18px 20px;box-shadow:0 1px 4px rgba(15,23,42,0.06),'
        f'0 4px 16px rgba(15,23,42,0.04);border-top:3px solid {color};">'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM};font-weight:500;margin-bottom:6px;">'
        f'{icon} {label}</div>'
        f'<div style="font-size:1.8rem;font-weight:700;color:{color};line-height:1.1;">'
        f'{value} {trend_html}</div>'
        f'{"" if not sub else "<div style=" + chr(34) + "font-size:0.75rem;color:" + TEXT_LIGHT + ";margin-top:4px;" + chr(34) + ">" + sub + "</div>"}'
        f'</div>'
    )


def status_badge(label: str, color: str) -> str:
    return (
        f'<span style="background:{rgba(color,0.12)};border:1px solid {rgba(color,0.3)};'
        f'color:{color};font-size:0.72rem;font-weight:600;'
        f'padding:3px 10px;border-radius:20px;">{label}</span>'
    )


def metric_bar(label: str, value: float, color: str) -> str:
    pct = max(0.0, min(100.0, value))
    return (
        f'<div style="margin-bottom:8px;">'
        f'<div style="display:flex;justify-content:space-between;'
        f'font-size:0.75rem;color:{TEXT_DIM};margin-bottom:4px;">'
        f'<span>{label}</span>'
        f'<span style="color:{color};font-weight:600;">{pct:.1f}</span></div>'
        f'<div style="background:#e2e8f0;border-radius:6px;height:7px;overflow:hidden;">'
        f'<div style="width:{pct}%;height:100%;background:linear-gradient(90deg,{color},{rgba(color,0.7)});'
        f'border-radius:6px;transition:width 0.4s ease;"></div>'
        f'</div></div>'
    )


def alert_badge(count: int) -> str:
    if count == 0:
        return ""
    return (
        f'<span style="background:rgba(207,34,46,0.10);border:1px solid rgba(207,34,46,0.30);'
        f'color:{C_CRITICAL};font-size:0.68rem;font-weight:600;'
        f'padding:2px 8px;border-radius:10px;margin-left:8px;">'
        f'🔔 {count} 条告警</span>'
    )