"""异常预警管理 — 国家级竞赛标准重写版"""
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE, C_TEAL,
    BG_CARD, BG_CHART, BORDER, BORDER_MED, TEXT_DIM, TEXT_MAIN, TEXT_LIGHT,
    CHART_PALETTE, rgba, risk_info, score_color, chart_layout,
    page_header, section_title, kpi_card, status_badge, alert_badge,
)
from src.rules.alert_manager import acknowledge, get_all_alerts, get_active_alerts
from src.utils.config_loader import Config

_SEVERITY_META = {
    "critical": {"icon": "🔴", "color": C_CRITICAL, "label": "严重"},
    "warning":  {"icon": "🟡", "color": C_WARNING,  "label": "警告"},
    "info":     {"icon": "🔵", "color": C_BLUE,     "label": "提示"},
}

_RULE_LABELS = {
    "health_threshold": "健康度阈值告警",
    "metric_deviation": "指标偏差告警",
    "tls_degradation":  "🔒 TLS/HTTPS 安全劣化",
    "threat_spike":     "🛡️ 威胁情报异常",
    "content_change":   "🔍 网页内容变化",
    "new_asset_discovered": "🕸️ 新增暴露资产",
}


def _severity_badge(severity: str) -> str:
    meta = _SEVERITY_META.get(severity, _SEVERITY_META["warning"])
    return (
        f'<span style="background:{rgba(meta["color"],0.10)};'
        f'border:1px solid {rgba(meta["color"],0.35)};'
        f'color:{meta["color"]};font-size:0.72rem;font-weight:600;'
        f'padding:2px 10px;border-radius:12px;">'
        f'{meta["icon"]} {meta["label"]}</span>'
    )


def _alert_card(row: pd.Series) -> str:
    severity = row.get("severity", "warning")
    meta = _SEVERITY_META.get(severity, _SEVERITY_META["warning"])
    rule_label = _RULE_LABELS.get(row.get("rule_type", ""), row.get("rule_type", ""))
    ts = str(row.get("created_at", ""))[:19]
    return (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
        f'border-left:4px solid {meta["color"]};border-radius:10px;'
        f'padding:14px 18px;margin-bottom:10px;'
        f'box-shadow:0 1px 4px rgba(15,23,42,0.05);">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
        f'<div style="font-size:0.9rem;font-weight:600;color:{TEXT_MAIN};">'
        f'{meta["icon"]} {row["target_name"]}</div>'
        f'<div style="font-size:0.72rem;color:{TEXT_DIM};">{ts}</div>'
        f'</div>'
        f'<div style="font-size:0.82rem;color:{TEXT_DIM};margin:6px 0 4px 0;">'
        f'{row["message"]}</div>'
        f'<div style="display:flex;gap:8px;align-items:center;">'
        f'{_severity_badge(severity)}'
        f'<span style="font-size:0.72rem;color:{TEXT_LIGHT};">{rule_label}</span>'
        f'</div>'
        f'</div>'
    )


def _render_detail(rule_type: str, detail: str, color: str) -> str:
    """将告警 detail 文本渲染成结构化 HTML，安全专项规则额外解析步骤列表。"""
    if not detail:
        return ""

    is_security_rule = rule_type in ("tls_degradation", "threat_spike")

    if is_security_rule:
        # 将中文序号（①②③...）识别为列表项并渲染成带图标的列表
        import re
        # 把步骤拆成段落
        steps = re.split(r'(?=①|②|③|④|⑤|⑥|⑦|⑧|⑨)', detail)
        items_html = ""
        for step in steps:
            step = step.strip()
            if not step:
                continue
            # 第一段是前缀说明（不以序号开头），单独展示
            if not re.match(r'^[①-⑨]', step):
                items_html += (
                    f'<div style="font-size:0.84rem;color:{TEXT_DIM};'
                    f'margin-bottom:8px;line-height:1.6;">{step}</div>'
                )
            else:
                icon = step[0]
                content = step[1:].strip()
                items_html += (
                    f'<div style="display:flex;gap:8px;margin-bottom:7px;align-items:flex-start;">'
                    f'<span style="font-size:0.9rem;color:{color};flex-shrink:0;'
                    f'font-weight:600;margin-top:1px;">{icon}</span>'
                    f'<span style="font-size:0.83rem;color:{TEXT_MAIN};line-height:1.65;">{content}</span>'
                    f'</div>'
                )
        return (
            f'<div style="background:{rgba(color, 0.04)};border:1px solid {rgba(color, 0.20)};'
            f'border-left:3px solid {color};border-radius:8px;'
            f'padding:12px 16px;margin-top:10px;">'
            f'<div style="font-size:0.78rem;font-weight:700;color:{color};'
            f'margin-bottom:10px;letter-spacing:0.3px;">▎ 处置步骤</div>'
            f'{items_html}'
            f'</div>'
        )
    else:
        # 普通告警，原样展示
        return (
            f'<div style="background:#f8fafc;border:1px solid {BORDER};'
            f'border-left:3px solid {C_BLUE};border-radius:8px;'
            f'padding:12px 16px;margin-top:10px;font-size:0.85rem;color:{TEXT_DIM};">'
            f'💡 <strong>根因分析：</strong>{detail}</div>'
        )


def _alert_frequency_chart(hist_df: pd.DataFrame) -> go.Figure | None:
    df = hist_df.copy()
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True, errors="coerce")
    df = df.dropna(subset=["created_at"])
    if df.empty:
        return None

    df["hour_bucket"] = df["created_at"].dt.floor("h")
    counts = df.groupby(["hour_bucket", "severity"]).size().reset_index(name="count")

    fig = go.Figure()
    for sev, meta in _SEVERITY_META.items():
        sub = counts[counts["severity"] == sev]
        if sub.empty:
            continue
        fig.add_trace(go.Bar(
            x=sub["hour_bucket"], y=sub["count"],
            name=meta["label"],
            marker_color=rgba(meta["color"], 0.75),
            marker_line_color=meta["color"],
            marker_line_width=1,
        ))

    fig.update_layout(**chart_layout(
        height=260,
        title=dict(text="告警频率分布（按小时）",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="时间",
        yaxis_title="告警数量",
        barmode="stack",
        bargap=0.2,
    ))
    return fig


def _mttr_stats(hist_df: pd.DataFrame) -> dict:
    """Compute basic MTTR and acknowledgement rate."""
    if hist_df.empty:
        return {}
    total = len(hist_df)
    acked = int(hist_df["acknowledged"].sum())
    rate  = acked / total * 100 if total else 0
    return {"total": total, "acked": acked, "unacked": total - acked, "ack_rate": rate}


def _target_alert_bar(hist_df: pd.DataFrame) -> go.Figure | None:
    if hist_df.empty:
        return None
    counts = hist_df.groupby("target_name").size().sort_values(ascending=True)
    colors = [
        C_CRITICAL if v >= 10 else (C_WARNING if v >= 5 else C_BLUE)
        for v in counts.values
    ]
    fig = go.Figure(go.Bar(
        x=counts.values, y=counts.index,
        orientation="h",
        marker_color=colors,
        text=counts.values,
        textposition="outside",
    ))
    fig.update_layout(**chart_layout(
        height=max(180, len(counts) * 50 + 80),
        title=dict(text="各服务告警次数",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis_title="告警次数",
        margin=dict(t=60, b=44, l=140, r=40),
    ))
    return fig


def _rule_pie(hist_df: pd.DataFrame) -> go.Figure | None:
    if hist_df.empty:
        return None
    counts = hist_df["rule_type"].map(_RULE_LABELS).fillna(hist_df["rule_type"]).value_counts()
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        hole=0.5,
        marker_colors=[C_BLUE, C_ORANGE, C_PURPLE, C_TEAL],
        textinfo="label+percent",
        textfont=dict(size=11, color=TEXT_MAIN),
    ))
    fig.update_layout(
        height=260,
        paper_bgcolor=BG_CARD,
        font=dict(color=TEXT_MAIN, family="'Inter','PingFang SC','Microsoft YaHei',sans-serif"),
        margin=dict(t=40, b=20, l=20, r=20),
        showlegend=False,
        title=dict(text="告警规则分布", font=dict(size=13, color=TEXT_MAIN)),
    )
    return fig


def render() -> None:
    cfg = Config.get()
    db_path = cfg.db_path

    st.markdown(page_header(
        "异常预警管理",
        "实时告警处置 · MTTR 统计 · 告警频率分析 · 根因关联",
        "🔔",
    ), unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🚨  当前活跃告警", "📋  历史告警记录", "📊  告警统计分析"])

    # ── Tab 1: Active alerts ───────────────────────────────────────────────────
    with tab1:
        _target_opts1 = ["全部"] + [t["name"] for t in cfg.targets]
        _filter1 = st.selectbox("筛选服务", _target_opts1, key="alert_filter_tab1")
        active_df = get_active_alerts(db_path)
        if _filter1 != "全部" and not active_df.empty:
            active_df = active_df[active_df["target_name"] == _filter1]

        if active_df.empty:
            st.markdown(
                f'<div style="background:#f0fff4;border:1px solid {C_HEALTHY}40;'
                f'border-left:4px solid {C_HEALTHY};border-radius:12px;'
                f'padding:32px;margin:16px 0;text-align:center;">'
                f'<div style="font-size:2.5rem;margin-bottom:10px;">✅</div>'
                f'<div style="font-size:1.1rem;font-weight:700;color:{C_HEALTHY};">当前无活跃告警</div>'
                f'<div style="font-size:0.85rem;color:{TEXT_DIM};margin-top:6px;">所有监测服务运行正常</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            critical_cnt = int((active_df["severity"] == "critical").sum())
            warning_cnt  = int((active_df["severity"] == "warning").sum())
            info_cnt     = int((active_df["severity"] == "info").sum())

            # Summary banner
            st.markdown(
                f'<div style="background:linear-gradient(135deg,{rgba(C_CRITICAL,0.08)},{rgba(C_WARNING,0.06)});'
                f'border:1px solid {rgba(C_CRITICAL,0.25)};border-radius:12px;'
                f'padding:16px 24px;margin-bottom:20px;display:flex;align-items:center;gap:16px;">'
                f'<span style="font-size:1.8rem;">🚨</span>'
                f'<div>'
                f'<div style="font-size:1rem;font-weight:700;color:{C_CRITICAL};">'
                f'共 {len(active_df)} 条未处理告警</div>'
                f'<div style="font-size:0.82rem;color:{TEXT_DIM};margin-top:2px;">'
                f'严重 {critical_cnt} 条 &nbsp;·&nbsp; 警告 {warning_cnt} 条 &nbsp;·&nbsp; 提示 {info_cnt} 条'
                f'</div></div></div>',
                unsafe_allow_html=True,
            )

            for _, row in active_df.iterrows():
                severity   = row.get("severity", "warning")
                meta       = _SEVERITY_META.get(severity, _SEVERITY_META["warning"])
                rule_label = _RULE_LABELS.get(row.get("rule_type", ""), row.get("rule_type", ""))
                with st.expander(
                    f"{meta['icon']} [{rule_label}]  {row['target_name']}  —  {row['message']}"
                ):
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**服务名称**\n\n{row['target_name']}")
                    c2.markdown(f"**规则类型**\n\n{rule_label}")
                    c3.markdown(f"**告警时间**\n\n{str(row.get('created_at', ''))[:19]}")
                    st.markdown(
                        f"**严重程度** &nbsp; {_severity_badge(severity)}",
                        unsafe_allow_html=True,
                    )
                    if row.get("detail"):
                        st.markdown(
                            _render_detail(
                                row.get("rule_type", ""),
                                row["detail"],
                                meta["color"],
                            ),
                            unsafe_allow_html=True,
                        )
                    if st.button("✔ 确认处理", key=f"ack_{row['id']}", type="primary"):
                        acknowledge(db_path, int(row["id"]))
                        st.success("已确认处理")
                        st.rerun()

    # ── Tab 2: History ─────────────────────────────────────────────────────────
    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            hours = st.slider("查询时间范围（小时）", 1, 168, 72)
        with col2:
            targets = ["全部"] + [t["name"] for t in cfg.targets]
            target_filter = st.selectbox("筛选服务", targets)

        target_arg = None if target_filter == "全部" else target_filter
        hist_df = get_all_alerts(db_path, target=target_arg, hours=hours)

        if hist_df.empty:
            st.info("该时间范围内无告警记录。")
        else:
            stats = _mttr_stats(hist_df)
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("告警总数", stats["total"])
            s2.metric("已处理",   stats["acked"])
            s3.metric("未处理",   stats["unacked"])
            s4.metric("处理率",   f"{stats['ack_rate']:.0f}%")

            st.markdown("---")

            hist_df["规则类型"] = hist_df["rule_type"].map(_RULE_LABELS).fillna(hist_df["rule_type"])
            hist_df["严重程度"] = hist_df["severity"].map(
                lambda s: _SEVERITY_META.get(s, {}).get("icon", "") + " " +
                          _SEVERITY_META.get(s, {}).get("label", s)
            )
            hist_df["状态"] = hist_df["acknowledged"].map(
                lambda v: "✅ 已处理" if v else "⏳ 未处理"
            )
            display = hist_df[[
                "created_at", "target_name", "规则类型", "严重程度", "message", "状态"
            ]].rename(columns={
                "created_at": "告警时间", "target_name": "服务名称", "message": "告警信息",
            })
            st.dataframe(display, use_container_width=True, hide_index=True)
            st.caption(f"共 {stats['total']} 条记录 · 最近 {hours} 小时")

    # ── Tab 3: Analytics ───────────────────────────────────────────────────────
    with tab3:
        col_h, col_f = st.columns(2)
        with col_h:
            hours_a = st.slider("分析时间范围（小时）", 1, 168, 72, key="analytics_hours")
        with col_f:
            _target_opts3 = ["全部"] + [t["name"] for t in cfg.targets]
            _filter3 = st.selectbox("筛选服务", _target_opts3, key="alert_filter_tab3")
        _target_arg3 = None if _filter3 == "全部" else _filter3
        all_df = get_all_alerts(db_path, target=_target_arg3, hours=hours_a)

        if all_df.empty:
            st.info("该时间范围内无告警数据可分析。")
        else:
            stats = _mttr_stats(all_df)
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("告警总数", stats["total"])
            s2.metric("已处理",   stats["acked"])
            s3.metric("处理率",   f"{stats['ack_rate']:.0f}%")
            critical_pct = int((all_df["severity"] == "critical").sum() / len(all_df) * 100)
            s4.metric("严重告警占比", f"{critical_pct}%")

            st.markdown("<br>", unsafe_allow_html=True)

            # Frequency chart
            freq_fig = _alert_frequency_chart(all_df)
            if freq_fig:
                st.plotly_chart(freq_fig, use_container_width=True)

            # Two-column: target bar + rule pie
            col_a, col_b = st.columns(2)
            with col_a:
                bar_fig = _target_alert_bar(all_df)
                if bar_fig:
                    st.plotly_chart(bar_fig, use_container_width=True)
            with col_b:
                pie_fig = _rule_pie(all_df)
                if pie_fig:
                    st.plotly_chart(pie_fig, use_container_width=True)