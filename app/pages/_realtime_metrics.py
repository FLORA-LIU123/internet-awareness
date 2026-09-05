"""实时监测与指标展示 — 国家级竞赛标准重写版"""
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE, C_TEAL,
    BG_CARD, BG_CHART, BORDER, BORDER_MED, TEXT_DIM, TEXT_MAIN, TEXT_LIGHT,
    CHART_PALETTE, rgba, risk_info, score_color, chart_layout,
    page_header, section_title, kpi_card, status_badge, metric_bar,
)
from src.storage import db
from src.utils.config_loader import Config

_METRIC_META = {
    "http":             {"label": "HTTP 可用性",   "unit": "score", "color": C_BLUE,     "invert": False, "icon": "🌐"},
    "response_time_ms": {"label": "HTTP 响应时延", "unit": "ms",    "color": C_HEALTHY,  "invert": True,  "icon": "⚡"},
    "icmp_latency":     {"label": "ICMP 时延",     "unit": "ms",    "color": C_PURPLE,   "invert": True,  "icon": "📡"},
    "icmp_loss":        {"label": "ICMP 丢包率",   "unit": "%",     "color": C_CRITICAL, "invert": True,  "icon": "📉"},
    "threat_score":     {"label": "威胁情报评分",  "unit": "score", "color": C_ORANGE,   "invert": True,  "icon": "🛡️"},
    "tls_security":     {"label": "TLS/HTTPS 安全","unit": "score", "color": C_TEAL,     "invert": False, "icon": "🔒"},
}

_THRESHOLDS = {
    "http":             {"warn": 80,  "crit": 60},
    "response_time_ms": {"warn": 300, "crit": 800},
    "icmp_latency":     {"warn": 100, "crit": 300},
    "icmp_loss":        {"warn": 5,   "crit": 20},
    "threat_score":     {"warn": 3,   "crit": 6},
    "tls_security":     {"warn": 70,  "crit": 50},
}


def _load_raw(db_path: str, target: str, metric: str, hours: int) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT collected_at, value FROM raw_metrics "
        "WHERE target_name=? AND metric_type=? AND collected_at>=? ORDER BY collected_at",
        (target, metric, since),
    )
    if df.empty:
        return df
    df["collected_at"] = pd.to_datetime(df["collected_at"], utc=True)
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    return df.dropna(subset=["value"])


def _latest_raw(db_path: str, target: str) -> dict:
    result = {}
    for metric in _METRIC_META:
        df = db.query_df(
            db_path,
            "SELECT value, collected_at FROM raw_metrics "
            "WHERE target_name=? AND metric_type=? ORDER BY collected_at DESC LIMIT 1",
            (target, metric),
        )
        if not df.empty:
            raw_val = df.iloc[0]["value"]
            if raw_val is None or (isinstance(raw_val, float) and __import__("math").isnan(raw_val)):
                continue
            result[metric] = {
                "value": float(raw_val),
                "ts": str(df.iloc[0]["collected_at"])[:19],
            }
    return result


def _anomaly_points(df: pd.DataFrame, col: str, metric: str) -> pd.DataFrame:
    """Return rows where value crosses critical threshold."""
    th = _THRESHOLDS.get(metric, {})
    crit = th.get("crit")
    if crit is None or df.empty:
        return pd.DataFrame()
    meta = _METRIC_META[metric]
    if meta["invert"]:
        return df[df[col] >= crit]
    else:
        return df[df[col] <= crit]


def _metric_status_card(metric: str, info: dict | None) -> str:
    meta = _METRIC_META[metric]
    val = info["value"] if info else None
    ts  = info["ts"]    if info else "—"
    val_str = f"{val:.1f}" if val is not None else "—"

    if val is not None:
        th = _THRESHOLDS.get(metric, {})
        warn, crit = th.get("warn"), th.get("crit")
        if meta["invert"]:
            color = C_CRITICAL if (crit and val >= crit) else (C_WARNING if (warn and val >= warn) else C_HEALTHY)
        else:
            color = C_CRITICAL if (crit and val <= crit) else (C_WARNING if (warn and val <= warn) else C_HEALTHY)
    else:
        color = TEXT_DIM

    return (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
        f'border-top:3px solid {color};border-radius:12px;padding:16px 18px;'
        f'box-shadow:0 1px 4px rgba(15,23,42,0.06),0 4px 16px rgba(15,23,42,0.04);">'
        f'<div style="font-size:0.75rem;color:{TEXT_DIM};font-weight:500;margin-bottom:6px;">'
        f'{meta["icon"]} {meta["label"]}</div>'
        f'<div style="font-size:1.6rem;font-weight:700;color:{color};line-height:1.1;">'
        f'{val_str}'
        f'<span style="font-size:0.75rem;font-weight:400;color:{TEXT_DIM};margin-left:4px;">{meta["unit"]}</span>'
        f'</div>'
        f'<div style="font-size:0.68rem;color:{TEXT_LIGHT};margin-top:6px;">采集：{ts}</div>'
        f'</div>'
    )


def _multi_service_comparison(db_path: str, targets: list, metric: str, hours: int) -> go.Figure:
    """Multi-service overlay chart for a single metric."""
    meta = _METRIC_META[metric]
    fig = go.Figure()
    for i, tname in enumerate(targets):
        df = _load_raw(db_path, tname, metric, hours)
        if df.empty:
            continue
        color = CHART_PALETTE[i % len(CHART_PALETTE)]
        fig.add_trace(go.Scatter(
            x=df["collected_at"], y=df["value"],
            mode="lines+markers", name=tname,
            line=dict(color=color, width=2),
            marker=dict(size=4),
        ))
        # Anomaly markers
        anom = _anomaly_points(df, "value", metric)
        if not anom.empty:
            fig.add_trace(go.Scatter(
                x=anom["collected_at"], y=anom["value"],
                mode="markers", name=f"{tname} 异常",
                marker=dict(color=C_CRITICAL, size=9, symbol="x",
                            line=dict(color=C_CRITICAL, width=2)),
                showlegend=False,
            ))

    th = _THRESHOLDS.get(metric, {})
    if th.get("warn"):
        fig.add_hline(y=th["warn"], line_dash="dot", line_color=C_WARNING, line_width=1.5,
                      annotation_text=f"警告 {th['warn']}", annotation_font_color=C_WARNING,
                      annotation_font_size=10)
    if th.get("crit"):
        fig.add_hline(y=th["crit"], line_dash="dot", line_color=C_CRITICAL, line_width=1.5,
                      annotation_text=f"严重 {th['crit']}", annotation_font_color=C_CRITICAL,
                      annotation_font_size=10)

    fig.update_layout(**chart_layout(
        height=320,
        title=dict(text=f"多服务对比 · {meta['label']} ({meta['unit']})",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="时间",
        yaxis_title=f"{meta['label']} ({meta['unit']})",
    ))
    return fig


def _http_icmp_combined(db_path: str, target: str, hours: int) -> go.Figure:
    """HTTP availability + response time on dual-axis, with anomaly markers."""
    http_df = _load_raw(db_path, target, "http", hours)
    rt_df   = _load_raw(db_path, target, "response_time_ms", hours)

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    if not http_df.empty:
        fig.add_trace(go.Scatter(
            x=http_df["collected_at"], y=http_df["value"],
            mode="lines+markers", name="可用性得分",
            line=dict(color=C_BLUE, width=2.5),
            marker=dict(size=5, color=C_BLUE),
            fill="tozeroy", fillcolor=rgba(C_BLUE, 0.08),
        ), secondary_y=False)
        anom_h = _anomaly_points(http_df, "value", "http")
        if not anom_h.empty:
            fig.add_trace(go.Scatter(
                x=anom_h["collected_at"], y=anom_h["value"],
                mode="markers", name="可用性异常",
                marker=dict(color=C_CRITICAL, size=10, symbol="x",
                            line=dict(color=C_CRITICAL, width=2)),
            ), secondary_y=False)

    if not rt_df.empty:
        fig.add_trace(go.Scatter(
            x=rt_df["collected_at"], y=rt_df["value"],
            mode="lines+markers", name="响应时延 (ms)",
            line=dict(color=C_HEALTHY, width=2, dash="dot"),
            marker=dict(size=4, color=C_HEALTHY),
        ), secondary_y=True)
        anom_rt = _anomaly_points(rt_df, "value", "response_time_ms")
        if not anom_rt.empty:
            fig.add_trace(go.Scatter(
                x=anom_rt["collected_at"], y=anom_rt["value"],
                mode="markers", name="时延异常",
                marker=dict(color=C_ORANGE, size=10, symbol="triangle-up",
                            line=dict(color=C_ORANGE, width=2)),
            ), secondary_y=True)

    fig.update_yaxes(title_text="可用性得分", secondary_y=False,
                     gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM), range=[0, 110])
    fig.update_yaxes(title_text="响应时延 (ms)", secondary_y=True,
                     gridcolor="rgba(0,0,0,0)", linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM))
    fig.update_layout(**chart_layout(
        height=340,
        title=dict(text="HTTP 可用性 & 响应时延（双轴）",
                   font=dict(size=13, color=TEXT_MAIN)),
        margin=dict(t=60, b=44, l=58, r=58),
    ))
    return fig


def _icmp_combined(db_path: str, target: str, hours: int) -> go.Figure:
    """ICMP latency + packet loss on dual-axis."""
    lat_df  = _load_raw(db_path, target, "icmp_latency", hours)
    loss_df = _load_raw(db_path, target, "icmp_loss", hours)

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    if not lat_df.empty:
        fig.add_trace(go.Scatter(
            x=lat_df["collected_at"], y=lat_df["value"],
            mode="lines+markers", name="ICMP 时延 (ms)",
            line=dict(color=C_PURPLE, width=2.5),
            marker=dict(size=5, color=C_PURPLE),
            fill="tozeroy", fillcolor=rgba(C_PURPLE, 0.08),
        ), secondary_y=False)
        anom_lat = _anomaly_points(lat_df, "value", "icmp_latency")
        if not anom_lat.empty:
            fig.add_trace(go.Scatter(
                x=anom_lat["collected_at"], y=anom_lat["value"],
                mode="markers", name="时延异常",
                marker=dict(color=C_CRITICAL, size=10, symbol="x",
                            line=dict(color=C_CRITICAL, width=2)),
            ), secondary_y=False)

    if not loss_df.empty:
        fig.add_trace(go.Bar(
            x=loss_df["collected_at"], y=loss_df["value"],
            name="丢包率 (%)",
            marker_color=[
                rgba(C_CRITICAL, 0.75) if v >= 20 else
                (rgba(C_WARNING, 0.65) if v >= 5 else rgba(C_BLUE, 0.45))
                for v in loss_df["value"]
            ],
        ), secondary_y=True)

    fig.update_yaxes(title_text="ICMP 时延 (ms)", secondary_y=False,
                     gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM))
    fig.update_yaxes(title_text="丢包率 (%)", secondary_y=True,
                     range=[0, 105], gridcolor="rgba(0,0,0,0)",
                     linecolor=BORDER_MED, tickfont=dict(color=TEXT_DIM))
    fig.update_layout(**chart_layout(
        height=300,
        title=dict(text="ICMP 链路质量（时延 & 丢包率）",
                   font=dict(size=13, color=TEXT_MAIN)),
        bargap=0.25,
        margin=dict(t=60, b=44, l=58, r=58),
    ))
    return fig


def _threat_chart(db_path: str, target: str, hours: int) -> go.Figure:
    df = _load_raw(db_path, target, "threat_score", hours)
    if df.empty:
        return None

    colors = [
        C_CRITICAL if v >= 6 else (C_WARNING if v >= 3 else C_HEALTHY)
        for v in df["value"]
    ]
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=df["collected_at"], y=df["value"],
        name="威胁评分", marker_color=colors,
        text=[f"{v:.1f}" for v in df["value"]],
        textposition="outside",
        hovertemplate="时间：%{x}<br>威胁评分：%{y:.2f}<br><extra></extra>",
    ))
    # Reference band: 0 = 无威胁记录（绿色安全区）
    fig.add_hrect(y0=0, y1=3, fillcolor=rgba(C_HEALTHY, 0.06),
                  line_width=0, annotation_text="安全区 (0–3)",
                  annotation_font_color=C_HEALTHY, annotation_font_size=10)
    fig.add_hrect(y0=3, y1=6, fillcolor=rgba(C_WARNING, 0.06),
                  line_width=0, annotation_text="警告区 (3–6)",
                  annotation_font_color=C_WARNING, annotation_font_size=10)
    fig.add_hrect(y0=6, y1=10.5, fillcolor=rgba(C_CRITICAL, 0.06),
                  line_width=0, annotation_text="危险区 (6–10)",
                  annotation_font_color=C_CRITICAL, annotation_font_size=10)
    fig.update_layout(**chart_layout(
        height=280,
        title=dict(text="威胁情报评分（AlienVault OTX · 0=无威胁记录，10=高危）",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="时间", yaxis_title="威胁评分 (0–10)",
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM), range=[0, 11]),
    ))
    return fig


def _load_health_raw(db_path: str, target: str, hours: int) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT scored_at AS collected_at, score AS value FROM health_scores "
        "WHERE target_name=? AND scored_at>=? ORDER BY scored_at",
        (target, since),
    )
    if df.empty:
        return df
    df["collected_at"] = pd.to_datetime(df["collected_at"], utc=True)
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    return df.dropna(subset=["value"])


def _subplot_domain_center(row: int, col: int, rows: int = 4, cols: int = 2,
                           v_spacing: float = 0.09, h_spacing: float = 0.08) -> tuple[float, float]:
    """
    Compute the paper-space (x, y) centre of a subplot cell.
    Used so '暂无数据' annotations land in the middle of their respective cell.
    """
    cell_h = (1.0 - v_spacing * (rows - 1)) / rows
    cell_w = (1.0 - h_spacing * (cols - 1)) / cols

    # Plotly lays out rows top-to-bottom: row 1 is at the top
    y_bottom = 1.0 - row * cell_h - (row - 1) * v_spacing
    y_center = y_bottom + cell_h / 2.0

    x_left   = (col - 1) * (cell_w + h_spacing)
    x_center = x_left + cell_w / 2.0

    return round(x_center, 4), round(y_center, 4)


def _all_metrics_grid(db_path: str, target: str, hours: int) -> go.Figure:
    metrics = list(_METRIC_META.keys())  # 6 raw metrics (including tls_security)
    # Layout: 6 metrics fill (1,1)→(3,2), health score at (4,2), (4,1) is empty spacer
    # subplot_titles are assigned left-to-right row by row, so (4,1) needs a blank placeholder
    titles = [_METRIC_META[m]["label"] for m in metrics] + ["", "综合健康度"]
    V_SP, H_SP = 0.09, 0.08
    fig = make_subplots(
        rows=4, cols=2,
        subplot_titles=titles,
        vertical_spacing=V_SP, horizontal_spacing=H_SP,
    )
    positions = [(1,1),(1,2),(2,1),(2,2),(3,1),(3,2)]
    for metric, (row, col) in zip(metrics, positions):
        meta = _METRIC_META[metric]
        df = _load_raw(db_path, target, metric, hours)
        if df.empty:
            px, py = _subplot_domain_center(row, col, v_spacing=V_SP, h_spacing=H_SP)
            fig.add_annotation(
                text="暂无数据", xref="paper", yref="paper",
                x=px, y=py, showarrow=False,
                font=dict(size=11, color=TEXT_LIGHT),
                xanchor="center", yanchor="middle",
            )
            # invisible dummy trace so the subplot grid box still renders
            fig.add_trace(go.Scatter(
                x=[0], y=[0], mode="markers", showlegend=False,
                marker=dict(opacity=0),
            ), row=row, col=col)
            continue
        fig.add_trace(go.Scatter(
            x=df["collected_at"], y=df["value"],
            mode="lines+markers", name=meta["label"],
            line=dict(color=meta["color"], width=1.8),
            marker=dict(size=3),
            fill="tozeroy", fillcolor=rgba(meta["color"], 0.09),
            showlegend=False,
        ), row=row, col=col)
        anom = _anomaly_points(df, "value", metric)
        if not anom.empty:
            fig.add_trace(go.Scatter(
                x=anom["collected_at"], y=anom["value"],
                mode="markers", name="异常",
                marker=dict(color=C_CRITICAL, size=7, symbol="x"),
                showlegend=False,
            ), row=row, col=col)

    # (4,1) is intentionally blank — add invisible trace so axis renders
    fig.add_trace(go.Scatter(x=[], y=[], showlegend=False, opacity=0), row=4, col=1)

    # Panel 7: health score at (4,2)
    hs_df = _load_health_raw(db_path, target, hours)
    if hs_df.empty:
        px, py = _subplot_domain_center(4, 2, v_spacing=V_SP, h_spacing=H_SP)
        fig.add_annotation(
            text="暂无数据", xref="paper", yref="paper",
            x=px, y=py, showarrow=False,
            font=dict(size=11, color=TEXT_LIGHT),
            xanchor="center", yanchor="middle",
        )
        fig.add_trace(go.Scatter(
            x=[0], y=[0], mode="markers", showlegend=False,
            marker=dict(opacity=0),
        ), row=4, col=2)
    else:
        fig.add_trace(go.Scatter(
            x=hs_df["collected_at"], y=hs_df["value"],
            mode="lines+markers", name="综合健康度",
            line=dict(color=C_HEALTHY, width=1.8),
            marker=dict(size=3),
            fill="tozeroy", fillcolor=rgba(C_HEALTHY, 0.09),
            showlegend=False,
        ), row=4, col=2)
        fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1, row=4, col=2)
        fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING,  line_width=1, row=4, col=2)

    fig.update_layout(
        height=740, paper_bgcolor=BG_CARD, plot_bgcolor=BG_CHART,
        font=dict(color=TEXT_MAIN, size=11,
                  family="'Inter','PingFang SC','Microsoft YaHei',sans-serif"),
        margin=dict(t=50, b=30, l=45, r=20),
    )
    # subplot_titles are added as annotations; reset their colour
    for ann in fig.layout.annotations:
        if not ann.text.startswith("暂"):  # don't override the "暂无数据" colour
            ann.font.color = TEXT_DIM
            ann.font.size = 11
    fig.update_xaxes(gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM, size=9))
    fig.update_yaxes(gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM, size=9))
    return fig


def _tls_chart(db_path: str, target: str, hours: int) -> go.Figure | None:
    """TLS/HTTPS security score trend chart with warn/crit reference lines."""
    df = _load_raw(db_path, target, "tls_security", hours)
    if df.empty:
        return None

    # Colour each point by threshold
    point_colors = [
        C_CRITICAL if v <= 50 else (C_WARNING if v <= 70 else C_TEAL)
        for v in df["value"]
    ]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["collected_at"], y=df["value"],
        mode="lines+markers",
        name="TLS/HTTPS 安全评分",
        line=dict(color=C_TEAL, width=2.5),
        marker=dict(size=6, color=point_colors,
                    line=dict(color=C_TEAL, width=1)),
        fill="tozeroy",
        fillcolor=rgba(C_TEAL, 0.08),
        hovertemplate="时间：%{x}<br>安全评分：%{y:.1f}<extra></extra>",
    ))

    # Anomaly markers (score drops below critical threshold)
    anom = df[df["value"] <= 50]
    if not anom.empty:
        fig.add_trace(go.Scatter(
            x=anom["collected_at"], y=anom["value"],
            mode="markers", name="安全异常",
            marker=dict(color=C_CRITICAL, size=10, symbol="x",
                        line=dict(color=C_CRITICAL, width=2)),
            showlegend=False,
        ))

    # Reference lines
    fig.add_hline(
        y=70, line_dash="dot", line_color=C_WARNING, line_width=1.5,
        annotation_text="警告 70", annotation_font_color=C_WARNING,
        annotation_font_size=10,
    )
    fig.add_hline(
        y=50, line_dash="dot", line_color=C_CRITICAL, line_width=1.5,
        annotation_text="严重 50", annotation_font_color=C_CRITICAL,
        annotation_font_size=10,
    )

    fig.update_layout(**chart_layout(
        height=280,
        title=dict(
            text="TLS/HTTPS 安全评分（证书有效性 · 协议版本 · 安全响应头 · HTTPS 重定向 · SCT）",
            font=dict(size=13, color=TEXT_MAIN),
        ),
        xaxis_title="时间",
        yaxis=dict(
            title_text="安全评分 (0–100)",
            gridcolor=BORDER, linecolor=BORDER_MED,
            tickfont=dict(color=TEXT_DIM),
            range=[0, 110],
        ),
    ))
    return fig


def _render_content_integrity(db_path: str, target: str, hours: int) -> None:
    """展示网页内容完整性检测结果：最新快照状态 + 变化历史。"""
    from src.collection.content_monitor import get_latest_snapshots, get_change_history
    from src.storage import db as storage_db

    # 最新快照
    snapshots = get_latest_snapshots(db_path)
    snap = next((s for s in snapshots if s["target_name"] == target), None)

    if snap is None:
        st.info("暂无内容快照数据，等待首次采集完成。")
        return

    changed    = bool(snap.get("changed"))
    summary    = snap.get("change_summary") or "—"
    ts         = str(snap.get("collected_at", ""))[:19]
    hash_short = str(snap.get("content_hash", ""))[:16]
    length     = snap.get("content_length", 0)

    status_color = C_CRITICAL if changed else C_HEALTHY
    status_icon  = "🚨" if changed else "✅"
    status_text  = "检测到内容变化" if changed else "内容与上次一致"

    # 状态卡片
    st.markdown(
        f'<div style="background:{rgba(status_color, 0.06)};'
        f'border:1px solid {rgba(status_color, 0.30)};'
        f'border-left:4px solid {status_color};border-radius:10px;'
        f'padding:14px 18px;margin-bottom:12px;">'
        f'<div style="display:flex;align-items:center;gap:10px;">'
        f'<span style="font-size:1.4rem;">{status_icon}</span>'
        f'<div>'
        f'<div style="font-size:0.95rem;font-weight:700;color:{status_color};">{status_text}</div>'
        f'<div style="font-size:0.8rem;color:{TEXT_DIM};margin-top:3px;">{summary}</div>'
        f'</div></div>'
        f'<div style="margin-top:10px;font-size:0.75rem;color:{TEXT_LIGHT};'
        f'display:flex;gap:20px;flex-wrap:wrap;">'
        f'<span>🕐 最后检测：{ts}</span>'
        f'<span>🔑 内容哈希：<code>{hash_short}…</code></span>'
        f'<span>📄 文本长度：{length:,} 字符</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    # 变化历史
    history = get_change_history(db_path, target, hours)
    if history:
        st.markdown(
            f'<div style="font-size:0.82rem;font-weight:600;color:{C_WARNING};'
            f'margin:10px 0 6px 0;">⚠ 本时间窗口内共发生 {len(history)} 次内容变化</div>',
            unsafe_allow_html=True,
        )
        for rec in history[:5]:  # 最多展示5条
            rec_ts      = str(rec.get("collected_at", ""))[:19]
            rec_summary = rec.get("change_summary") or "内容发生变化"
            st.markdown(
                f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
                f'border-left:3px solid {C_WARNING};border-radius:6px;'
                f'padding:8px 14px;margin-bottom:6px;font-size:0.8rem;">'
                f'<span style="color:{TEXT_DIM};">{rec_ts}</span> &nbsp;·&nbsp; '
                f'<span style="color:{TEXT_MAIN};">{rec_summary}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption(f"最近 {hours} 小时内未检测到内容变化")


def render() -> None:
    cfg = Config.get()
    db_path = cfg.db_path
    auto_refresh = cfg.get_setting("ui", "auto_refresh_seconds", default=30)

    st.markdown(page_header(
        "实时监测与指标展示",
        "多维度外部观测指标实时采集 · 异常点自动标注 · 多服务横向对比",
        "📡",
    ), unsafe_allow_html=True)

    targets = [t["name"] for t in cfg.targets]
    if not targets:
        st.warning("未配置监测目标，请前往「配置管理」添加。")
        return

    # ── Controls ──────────────────────────────────────────────────────────────
    ctrl1, ctrl2, ctrl3 = st.columns([2, 1, 1])
    with ctrl1:
        target = st.selectbox("监测目标", targets, label_visibility="collapsed",
                              placeholder="选择服务...")
    with ctrl2:
        hours = st.selectbox("时间窗口", [1, 3, 6, 12, 24, 48, 72],
                             index=2, format_func=lambda h: f"最近 {h} 小时")
    with ctrl3:
        compare_mode = st.toggle("多服务对比", value=False)

    st.markdown("---")

    latest = _latest_raw(db_path, target)

    if not latest:
        st.info("暂无采集数据，等待首次采集完成...")
        return

    # ── KPI cards ─────────────────────────────────────────────────────────────
    st.markdown(section_title("最新采集值"), unsafe_allow_html=True)
    cols = st.columns(len(_METRIC_META))
    for i, (metric, meta) in enumerate(_METRIC_META.items()):
        with cols[i]:
            st.markdown(_metric_status_card(metric, latest.get(metric)),
                        unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Multi-service comparison mode ─────────────────────────────────────────
    if compare_mode:
        st.markdown(section_title("多服务横向对比"), unsafe_allow_html=True)
        cmp_metric = st.selectbox(
            "对比指标",
            list(_METRIC_META.keys()),
            format_func=lambda k: _METRIC_META[k]["label"],
        )
        st.plotly_chart(
            _multi_service_comparison(db_path, targets, cmp_metric, hours),
            use_container_width=True,
        )
        st.markdown("---")

    # ── HTTP section ──────────────────────────────────────────────────────────
    st.markdown(section_title("HTTP 可用性与响应时延"), unsafe_allow_html=True)
    http_df = _load_raw(db_path, target, "http", hours)
    rt_df   = _load_raw(db_path, target, "response_time_ms", hours)
    if not http_df.empty or not rt_df.empty:
        st.plotly_chart(_http_icmp_combined(db_path, target, hours),
                        use_container_width=True)
        # Stats row
        if not rt_df.empty:
            avg_rt = rt_df["value"].mean()
            p95_rt = rt_df["value"].quantile(0.95)
            max_rt = rt_df["value"].max()
            m1, m2, m3 = st.columns(3)
            m1.metric("响应时延均值", f"{avg_rt:.0f} ms")
            m2.metric("P95 时延", f"{p95_rt:.0f} ms")
            m3.metric("最大时延", f"{max_rt:.0f} ms")
    else:
        st.info("暂无 HTTP 数据。")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── ICMP section ──────────────────────────────────────────────────────────
    st.markdown(section_title("ICMP 链路质量"), unsafe_allow_html=True)
    icmp_lat  = _load_raw(db_path, target, "icmp_latency", hours)
    icmp_loss = _load_raw(db_path, target, "icmp_loss", hours)
    if not icmp_lat.empty or not icmp_loss.empty:
        st.plotly_chart(_icmp_combined(db_path, target, hours),
                        use_container_width=True)
        if not icmp_lat.empty:
            avg_lat  = icmp_lat["value"].mean()
            p95_lat  = icmp_lat["value"].quantile(0.95)
            avg_loss = icmp_loss["value"].mean() if not icmp_loss.empty else 0.0
            m1, m2, m3 = st.columns(3)
            m1.metric("ICMP 时延均值", f"{avg_lat:.1f} ms")
            m2.metric("P95 时延", f"{p95_lat:.1f} ms")
            m3.metric("平均丢包率", f"{avg_loss:.1f} %")
    else:
        st.info("该服务未配置 ICMP 探测，或暂无 ICMP 数据。")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Threat intel section ───────────────────────────────────────────────────
    st.markdown(section_title("威胁情报评分（AlienVault OTX）"), unsafe_allow_html=True)
    threat_fig = _threat_chart(db_path, target, hours)
    if threat_fig:
        st.plotly_chart(threat_fig, use_container_width=True)
    else:
        otx_key = cfg.get_setting("threat_intel", "otx_api_key", default="")
        if not otx_key:
            st.info("暂无威胁情报数据（需配置 OTX API Key）。")
        else:
            st.info("暂无威胁情报数据（OTX 查询可能超时或尚未完成首次采集）。")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── TLS / HTTPS security section ───────────────────────────────────────────
    st.markdown(section_title("TLS/HTTPS 安全检测"), unsafe_allow_html=True)
    tls_fig = _tls_chart(db_path, target, hours)
    if tls_fig:
        st.plotly_chart(tls_fig, use_container_width=True)
        # Show latest TLS score stats
        tls_df_raw = _load_raw(db_path, target, "tls_security", hours)
        if not tls_df_raw.empty:
            latest_tls = tls_df_raw["value"].iloc[-1]
            avg_tls    = tls_df_raw["value"].mean()
            min_tls    = tls_df_raw["value"].min()
            m1, m2, m3 = st.columns(3)
            m1.metric("最新安全评分", f"{latest_tls:.1f}")
            m2.metric("时间窗口均值", f"{avg_tls:.1f}")
            m3.metric("时间窗口最低", f"{min_tls:.1f}")
    else:
        st.info("暂无 TLS/HTTPS 安全数据，等待首次采集完成。")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── 网页内容完整性检测 ─────────────────────────────────────────────────────
    st.markdown(section_title("网页内容完整性"), unsafe_allow_html=True)
    _render_content_integrity(db_path, target, hours)

    # ── Full grid expander ────────────────────────────────────────────────────
    with st.expander("📊 全指标总览（七宫格）", expanded=True):
        grid_hours = st.select_slider(
            "七宫格时间跨度",
            options=[6, 12, 24, 48, 72, 168],
            value=48,
            format_func=lambda h: f"最近 {h} 小时" if h < 168 else "最近 7 天",
            label_visibility="collapsed",
        )
        st.plotly_chart(_all_metrics_grid(db_path, target, grid_hours),
                        use_container_width=True)

    st.markdown(
        f'<div style="text-align:center;padding:16px;color:{TEXT_DIM};font-size:0.74rem;">'
        f'页面每 {auto_refresh} 秒自动刷新 · 探测数据每小时更新 · 红色 ✕ 标记为异常采集点</div>',
        unsafe_allow_html=True,
    )