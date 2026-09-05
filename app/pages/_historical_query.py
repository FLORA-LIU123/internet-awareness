"""历史数据查询与回溯 — 国家级竞赛标准重写版"""
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE, C_TEAL,
    BG_CARD, BG_CHART, BORDER, BORDER_MED, TEXT_DIM, TEXT_MAIN, TEXT_LIGHT,
    CHART_PALETTE, rgba, risk_info, score_color, chart_layout,
    page_header, section_title, kpi_card, status_badge,
)
from src.storage import db
from src.utils.config_loader import Config

_TABLES = {
    "原始采集数据 (raw_metrics)":  "raw_metrics",
    "融合指标 (fused_metrics)":    "fused_metrics",
    "健康度评分 (health_scores)":  "health_scores",
    "告警记录 (alerts)":           "alerts",
}
_TIME_COL = {
    "raw_metrics":   "collected_at",
    "fused_metrics": "fused_at",
    "health_scores": "scored_at",
    "alerts":        "created_at",
}
_AGG_OPTIONS = {"原始数据": "raw", "每小时均值": "1h", "每日均值": "1D"}

_FUSED_COLS = {
    "availability_score":  ("可用性得分",     C_BLUE),
    "response_time_score": ("响应时延得分",   C_HEALTHY),
    "link_score":          ("链路连通性得分", C_PURPLE),
    "security_score":      ("安全风险得分",   C_ORANGE),
}


def _load_table(db_path: str, table: str, target: str | None,
                hours: int, agg: str) -> pd.DataFrame:
    time_col = _TIME_COL[table]
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    where = f"WHERE {time_col} >= ?"
    params: tuple = (since,)
    if target:
        where += " AND target_name = ?"
        params = (since, target)

    df = db.query_df(
        db_path,
        f"SELECT * FROM {table} {where} ORDER BY {time_col} DESC",
        params,
    )
    if not df.empty:
        df[time_col] = (
            pd.to_datetime(df[time_col], utc=True, errors="coerce")
            .dt.tz_convert("Asia/Shanghai")
            .dt.tz_localize(None)
        )

    if df.empty or agg == "raw":
        return df

    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    if numeric_cols and "target_name" in df.columns:
        df = (
            df.set_index(time_col)
            .groupby("target_name")[numeric_cols]
            .resample(agg)
            .mean()
            .reset_index()
        )
    return df


def _health_score_chart(df: pd.DataFrame, time_col: str) -> go.Figure:
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    fig = go.Figure()
    for idx, (tname, grp) in enumerate(df.groupby("target_name")):
        color = CHART_PALETTE[idx % len(CHART_PALETTE)]
        grp = grp.sort_values(time_col)
        fig.add_trace(go.Scatter(
            x=grp[time_col], y=grp["score"],
            mode="lines+markers", name=str(tname),
            line=dict(color=color, width=2),
            marker=dict(size=4),
            fill="tozeroy", fillcolor=rgba(color, 0.07),
        ))
    fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1.5,
                  annotation_text="警戒 60", annotation_font_color=C_CRITICAL,
                  annotation_font_size=11)
    fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING, line_width=1.5,
                  annotation_text="良好 80", annotation_font_color=C_WARNING,
                  annotation_font_size=11)
    fig.update_layout(**chart_layout(
        height=360,
        title=dict(text="健康度评分趋势（多服务对比）",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="时间",
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM), range=[0, 105],
                   title="健康度评分"),
    ))
    return fig


def _fused_metrics_chart(df: pd.DataFrame, time_col: str, target: str | None) -> go.Figure:
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    targets = df["target_name"].unique() if "target_name" in df.columns else []
    if target:
        targets = [target]

    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=[v[0] for v in _FUSED_COLS.values()],
        vertical_spacing=0.14, horizontal_spacing=0.08,
    )
    positions = [(1,1),(1,2),(2,1),(2,2)]
    for (col, (label, color)), (row, c) in zip(_FUSED_COLS.items(), positions):
        if col not in df.columns:
            continue
        for i, tname in enumerate(targets):
            sub = df[df["target_name"] == tname].sort_values(time_col) if "target_name" in df.columns else df.sort_values(time_col)
            if sub.empty:
                continue
            tc = CHART_PALETTE[i % len(CHART_PALETTE)] if len(targets) > 1 else color
            fig.add_trace(go.Scatter(
                x=sub[time_col], y=sub[col],
                mode="lines", name=f"{tname} · {label}" if len(targets) > 1 else label,
                line=dict(color=tc, width=1.8),
                fill="tozeroy", fillcolor=rgba(tc, 0.07),
                showlegend=(row == 1 and c == 1),
            ), row=row, col=c)
        fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1,
                      row=row, col=c)
        fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING, line_width=1,
                      row=row, col=c)

    fig.update_layout(
        height=440, paper_bgcolor=BG_CARD, plot_bgcolor=BG_CHART,
        font=dict(color=TEXT_MAIN, size=11,
                  family="'Inter','PingFang SC','Microsoft YaHei',sans-serif"),
        margin=dict(t=50, b=30, l=40, r=20),
    )
    for ann in fig.layout.annotations:
        ann.font.color = TEXT_DIM
        ann.font.size = 11
    fig.update_xaxes(gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM, size=9))
    fig.update_yaxes(gridcolor=BORDER, linecolor=BORDER_MED,
                     tickfont=dict(color=TEXT_DIM, size=9), range=[0, 105])
    return fig


def _raw_metrics_chart(df: pd.DataFrame, time_col: str) -> go.Figure | None:
    if "metric_type" not in df.columns or "value" not in df.columns:
        return None
    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    metric_types = df["metric_type"].unique()[:6]

    fig = go.Figure()
    for i, mtype in enumerate(metric_types):
        sub = df[df["metric_type"] == mtype].sort_values(time_col)
        if sub.empty:
            continue
        color = CHART_PALETTE[i % len(CHART_PALETTE)]
        fig.add_trace(go.Scatter(
            x=sub[time_col], y=sub["value"],
            mode="lines+markers", name=mtype,
            line=dict(color=color, width=1.8),
            marker=dict(size=3),
        ))
    fig.update_layout(**chart_layout(
        height=320,
        title=dict(text="原始指标时序（按指标类型）",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="时间", yaxis_title="值",
    ))
    return fig


def _stat_summary(df: pd.DataFrame, table: str) -> dict:
    summary = {}
    if table == "health_scores" and "score" in df.columns:
        s = pd.to_numeric(df["score"], errors="coerce").dropna()
        if not s.empty:
            summary = {
                "均值": f"{s.mean():.1f}",
                "中位数": f"{s.median():.1f}",
                "最小值": f"{s.min():.1f}",
                "最大值": f"{s.max():.1f}",
                "标准差": f"{s.std():.1f}",
            }
    elif table == "raw_metrics" and "value" in df.columns:
        s = pd.to_numeric(df["value"], errors="coerce").dropna()
        if not s.empty:
            summary = {
                "均值": f"{s.mean():.2f}",
                "中位数": f"{s.median():.2f}",
                "最小值": f"{s.min():.2f}",
                "最大值": f"{s.max():.2f}",
                "标准差": f"{s.std():.2f}",
            }
    return summary


def _render_target_block(sub: pd.DataFrame, tname: str, table: str,
                          time_col: str, hours: int) -> None:
    """Render stats + table + export for a single target's data slice."""
    st.caption(f"共 {len(sub)} 条记录")

    # Per-target stat summary
    stat = _stat_summary(sub, table)
    if stat:
        stat_cols = st.columns(len(stat))
        for i, (k, v) in enumerate(stat.items()):
            stat_cols[i].metric(k, v)

    st.dataframe(sub, use_container_width=True, hide_index=True)

    csv = sub.to_csv(index=False)
    safe_name = tname.replace(" ", "_").replace("/", "_")
    st.download_button(
        f"⬇️ 导出 {tname} CSV",
        data=csv,
        file_name=f"{table}_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        key=f"dl_{table}_{tname}_{hours}",
    )


def render() -> None:
    cfg = Config.get()
    db_path = cfg.db_path

    st.markdown(page_header(
        "历史数据查询与回溯",
        "多表查询 · 聚合分析 · 统计摘要 · 可视化回溯 · CSV 导出",
        "🗄️",
    ), unsafe_allow_html=True)

    # ── Query controls ─────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        table_label = st.selectbox("数据表", list(_TABLES.keys()))
        table = _TABLES[table_label]
    with col2:
        targets = ["全部"] + [t["name"] for t in cfg.targets]
        target_filter = st.selectbox("服务名称", targets)
    with col3:
        hours = st.slider("时间范围（小时）", 1, 720, 24)

    agg_label = st.selectbox("聚合方式", list(_AGG_OPTIONS.keys()))
    agg = _AGG_OPTIONS[agg_label]

    target_arg = None if target_filter == "全部" else target_filter
    df = _load_table(db_path, table, target_arg, hours, agg)

    if df.empty:
        st.markdown(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;'
            f'padding:40px;text-align:center;margin:16px 0;">'
            f'<div style="font-size:2.5rem;margin-bottom:10px;">📭</div>'
            f'<div style="font-size:1rem;color:{TEXT_DIM};">该条件下暂无数据</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Summary metrics ────────────────────────────────────────────────────────
    time_col = _TIME_COL[table]
    s1, s2, s3 = st.columns(3)
    s1.metric("查询结果", f"{len(df)} 条")
    s2.metric("时间范围", f"最近 {hours} 小时")
    s3.metric("聚合方式", agg_label)

    stat = _stat_summary(df, table)
    if stat:
        st.markdown(section_title("统计摘要"), unsafe_allow_html=True)
        stat_cols = st.columns(len(stat))
        for i, (k, v) in enumerate(stat.items()):
            stat_cols[i].metric(k, v)

    st.markdown("---")

    # ── Visualization ──────────────────────────────────────────────────────────
    if table == "health_scores" and "score" in df.columns:
        st.markdown(section_title("健康度趋势图"), unsafe_allow_html=True)
        st.plotly_chart(_health_score_chart(df, time_col), use_container_width=True)

    elif table == "fused_metrics":
        st.markdown(section_title("融合指标趋势图"), unsafe_allow_html=True)
        st.plotly_chart(
            _fused_metrics_chart(df, time_col, target_arg),
            use_container_width=True,
        )

    elif table == "raw_metrics":
        raw_fig = _raw_metrics_chart(df, time_col)
        if raw_fig:
            st.markdown(section_title("原始指标时序图"), unsafe_allow_html=True)
            st.plotly_chart(raw_fig, use_container_width=True)

    # ── Per-target categorized data tables ────────────────────────────────────
    st.markdown(section_title("分监测目标数据明细"), unsafe_allow_html=True)

    if "target_name" in df.columns and target_arg is None:
        # Show one tab per target
        target_names = sorted(df["target_name"].dropna().unique())
        if len(target_names) > 1:
            tabs = st.tabs([f"📌 {t}" for t in target_names])
            for tab, tname in zip(tabs, target_names):
                with tab:
                    sub = df[df["target_name"] == tname].copy()
                    _render_target_block(sub, tname, table, time_col, hours)
        else:
            # Only one target in result
            _render_target_block(df, target_names[0] if target_names else "全部", table, time_col, hours)
    else:
        # Single target selected or no target_name column
        _render_target_block(df, target_arg or "全部", table, time_col, hours)