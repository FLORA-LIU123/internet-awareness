"""
高级安全分析页面 — 5大创新功能可视化
1. 威胁情报关联分析（跨目标同步检测、IoC 趋势追踪）
2. 内容完整性精细检测（语义区域哈希、关键词注入检测）
3. 攻击路径推断（多阶段攻击链可视化）
4. 基线自适应告警（时段基线热力图、偏差可视化）
5. 等保合规自查（自动化证据收集、合规仪表盘）
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE, C_TEAL,
    BG_CARD, BG_CHART, BORDER, TEXT_DIM, TEXT_MAIN,
    rgba, chart_layout, page_header, section_title,
)
from src.storage import db
from src.utils.config_loader import Config
from src.collection import threat_correlation
from src.rules import adaptive_baseline
from src.analysis import root_cause, compliance


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _load_tls_detail(db_path: str, target_name: str) -> dict:
    """从 raw_metrics 读取最新一次采集的 TLS 子项数据。"""
    result = {}
    metrics = [
        "tls_security", "tls_cert_days", "tls_version_score", "tls_header_score",
        "tls_https_redirect", "tls_sct",
        "tls_hdr_hsts", "tls_hdr_csp", "tls_hdr_x_frame_options",
        "tls_hdr_x_content_type_options", "tls_hdr_referrer_policy",
        "tls_hdr_permissions_policy",
    ]
    for m in metrics:
        row = db.query_df(
            db_path,
            "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type=? "
            "ORDER BY collected_at DESC LIMIT 1",
            (target_name, m),
        )
        if not row.empty and row.iloc[0]["value"] is not None:
            result[m] = float(row.iloc[0]["value"])
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Feature 1: 威胁情报关联分析
# ══════════════════════════════════════════════════════════════════════════════

def _render_threat_correlation(db_path: str) -> None:
    st.markdown(section_title("1. 威胁情报关联分析"), unsafe_allow_html=True)
    st.caption("跨目标同步威胁检测 · IoC 趋势追踪 · 关联攻击事件识别")

    correlations = threat_correlation.get_latest(db_path, hours=72)

    if not correlations:
        st.info("⏳ 暂无关联威胁事件（需至少 2 个目标威胁分数同时 ≥ 3.0 才会触发）")
    else:
        # 关联事件时间轴
        df = pd.DataFrame(correlations)
        df["computed_at"] = pd.to_datetime(df["computed_at"], utc=True, errors="coerce")

        # 跨目标关联热力图
        st.markdown("**▎ 跨目标威胁关联矩阵**")
        targets = df["target_name"].unique().tolist()
        matrix_data = []
        for t1 in targets:
            row = []
            for t2 in targets:
                if t1 == t2:
                    row.append(0)
                else:
                    count = len(df[(df["target_name"] == t1) &
                                   (df["correlated_with"].str.contains(t2, na=False))])
                    row.append(count)
            matrix_data.append(row)

        fig = go.Figure(data=go.Heatmap(
            z=matrix_data,
            x=targets, y=targets,
            colorscale=[[0, rgba(C_BLUE, 0.1)], [1, C_CRITICAL]],
            showscale=True,
            text=matrix_data,
            texttemplate="%{text}",
            hovertemplate="<b>%{x}</b> ↔ <b>%{y}</b><br>关联次数: %{z}<extra></extra>",
        ))
        fig.update_layout(
            height=300, margin=dict(t=20, b=60, l=80, r=20),
            paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
            font=dict(color=TEXT_MAIN),
        )
        st.plotly_chart(fig, use_container_width=True, key="threat_corr_matrix")

    # 各目标威胁分数趋势
    cfg = Config.get()
    st.markdown("**▎ 各目标威胁分数趋势（近 7 天）**")
    fig_trend = go.Figure()
    for target in cfg.targets:
        name = target.get("name", "")
        series = threat_correlation.get_trend_series(db_path, name, hours=168)
        if series:
            df_s = pd.DataFrame(series)
            df_s["collected_at"] = pd.to_datetime(df_s["collected_at"], utc=True, errors="coerce")
            fig_trend.add_trace(go.Scatter(
                x=df_s["collected_at"], y=df_s["threat_score"],
                mode="lines+markers", name=name,
                line=dict(width=2), marker=dict(size=5),
            ))
    fig_trend.add_hline(y=3.0, line=dict(color=C_WARNING, dash="dot"),
                        annotation_text="警戒线 3.0", annotation_position="right")
    fig_trend.add_hline(y=6.0, line=dict(color=C_CRITICAL, dash="dot"),
                        annotation_text="危险线 6.0", annotation_position="right")
    fig_trend.update_layout(
        height=280, margin=dict(t=20, b=40, l=50, r=20),
        paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
        font=dict(color=TEXT_MAIN),
        xaxis_title="时间", yaxis_title="威胁分数",
    )
    st.plotly_chart(fig_trend, use_container_width=True, key="threat_trend")


# ══════════════════════════════════════════════════════════════════════════════
# Feature 2: 内容完整性精细检测
# ══════════════════════════════════════════════════════════════════════════════

def _render_content_integrity(db_path: str) -> None:
    st.markdown(section_title("2. 内容完整性精细检测"), unsafe_allow_html=True)
    st.caption("语义区域哈希 · 关键词注入检测 · 篡改评分趋势")

    cfg = Config.get()

    # 内容完整性检查记录
    df_integrity = db.query_df(
        db_path,
        """SELECT target_name, target_url, region_hashes, injected_kws,
                  tamper_score, checked_at
           FROM content_integrity_checks
           ORDER BY checked_at DESC LIMIT 100"""
    )

    if df_integrity.empty:
        st.info("⏳ 暂无精细检测结果（将在下一轮采集后生成）")
        return

    df_integrity["checked_at"] = pd.to_datetime(df_integrity["checked_at"], utc=True, errors="coerce")

    # 篡改评分趋势
    st.markdown("**▎ 各目标篡改评分趋势**")
    fig_tamper = go.Figure()
    for name in df_integrity["target_name"].unique():
        sub = df_integrity[df_integrity["target_name"] == name].sort_values("checked_at")
        fig_tamper.add_trace(go.Scatter(
            x=sub["checked_at"], y=sub["tamper_score"],
            mode="lines+markers", name=name,
            line=dict(width=2), marker=dict(size=5),
            fill="tozeroy", fillcolor=rgba(C_CRITICAL, 0.1),
        ))
    fig_tamper.add_hline(y=30, line=dict(color=C_WARNING, dash="dot"),
                         annotation_text="警告阈值", annotation_position="right")
    fig_tamper.add_hline(y=60, line=dict(color=C_CRITICAL, dash="dot"),
                         annotation_text="危险阈值", annotation_position="right")
    fig_tamper.update_layout(
        height=280, margin=dict(t=20, b=40, l=50, r=20),
        paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
        font=dict(color=TEXT_MAIN),
        xaxis_title="时间", yaxis_title="篡改评分",
    )
    st.plotly_chart(fig_tamper, use_container_width=True, key="tamper_trend")

    # 关键词注入检测
    st.markdown("**▎ 关键词注入检测记录**")
    kw_records = df_integrity[df_integrity["injected_kws"].notna() &
                               (df_integrity["injected_kws"] != "[]")].copy()
    if kw_records.empty:
        st.success("✅ 未检测到关键词注入")
    else:
        for _, row in kw_records.head(10).iterrows():
            kws = row["injected_kws"]
            color = C_CRITICAL if row["tamper_score"] >= 60 else C_WARNING
            st.markdown(
                f'<div style="background:{rgba(color, 0.08)};border:1px solid {rgba(color, 0.3)};'
                f'border-left:4px solid {color};border-radius:8px;padding:12px 16px;margin-bottom:8px;">'
                f'<span style="font-weight:700;color:{color};">{row["target_name"]}</span>'
                f'<span style="color:{TEXT_DIM};font-size:0.8rem;margin-left:12px;">'
                f'{row["checked_at"].strftime("%m-%d %H:%M")}</span>'
                f'<div style="margin-top:6px;font-size:0.85rem;color:{TEXT_MAIN};">'
                f'检测到注入关键词：<span style="color:{C_CRITICAL};font-weight:600;">{kws}</span>'
                f'</div></div>',
                unsafe_allow_html=True,
            )


# ══════════════════════════════════════════════════════════════════════════════
# Feature 3: 攻击路径推断
# ══════════════════════════════════════════════════════════════════════════════

def _render_attack_chains(db_path: str) -> None:
    st.markdown(section_title("3. 攻击路径推断"), unsafe_allow_html=True)
    st.caption("多阶段攻击链可视化 · 侦察 → 弱点暴露 → 异常行为 → 疑似失陷")

    cfg = Config.get()

    # 攻击链记录
    df_chains = db.query_df(
        db_path,
        """SELECT target_name, chain_type, stage_sequence, confidence,
                  first_event_at, last_event_at, detail, computed_at
           FROM attack_chains
           ORDER BY computed_at DESC LIMIT 50"""
    )

    if df_chains.empty:
        st.info("⏳ 暂无攻击链记录（需检测到多阶段关联事件才会生成）")
        # 展示现有告警的攻击链时间轴（复用 root_cause 的逻辑）
        st.markdown("**▎ 当前告警时间轴**")
        for target in cfg.targets:
            name = target.get("name", "")
            chain = root_cause.build_attack_chain(db_path, name, hours=48)
            if chain["events"]:
                st.markdown(f"**{name}**")
                events = chain["events"]
                for ev in events[:10]:
                    color = C_CRITICAL if ev["severity"] == "critical" else C_WARNING
                    st.markdown(
                        f'<div style="display:flex;align-items:center;gap:8px;'
                        f'padding:6px 12px;border-left:3px solid {color};margin-bottom:4px;">'
                        f'<span style="font-size:1.1rem;">{ev["icon"]}</span>'
                        f'<span style="font-size:0.8rem;color:{TEXT_DIM};min-width:80px;">'
                        f'{ev["time"].strftime("%m-%d %H:%M") if hasattr(ev["time"], "strftime") else str(ev["time"])[:16]}</span>'
                        f'<span style="font-size:0.85rem;color:{TEXT_MAIN};">{ev["title"]}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
        return

    # 攻击链可视化
    df_chains["first_event_at"] = pd.to_datetime(df_chains["first_event_at"], utc=True, errors="coerce")
    df_chains["last_event_at"] = pd.to_datetime(df_chains["last_event_at"], utc=True, errors="coerce")

    st.markdown("**▎ 检测到的攻击链**")
    for _, row in df_chains.head(5).iterrows():
        stages = row["stage_sequence"].split(" → ")
        confidence = row["confidence"]
        color = C_CRITICAL if confidence >= 0.7 else (C_WARNING if confidence >= 0.4 else C_BLUE)

        # 阶段进度条
        stages_html = ""
        for i, stage in enumerate(stages):
            stages_html += (
                f'<div style="flex:1;text-align:center;padding:8px 4px;'
                f'background:{rgba(color, 0.1 + i * 0.15)};border-radius:6px;'
                f'font-size:0.75rem;font-weight:600;color:{color};">{stage}</div>'
            )
            if i < len(stages) - 1:
                stages_html += '<div style="font-size:1rem;color:{TEXT_DIM};">→</div>'

        st.markdown(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:10px;'
            f'padding:14px 18px;margin-bottom:12px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
            f'<span style="font-weight:700;font-size:0.95rem;color:{TEXT_MAIN};">{row["target_name"]}</span>'
            f'<span style="font-size:0.8rem;color:{color};font-weight:600;">'
            f'置信度 {confidence:.0%}</span>'
            f'</div>'
            f'<div style="display:flex;gap:4px;align-items:center;">{stages_html}</div>'
            f'<div style="margin-top:8px;font-size:0.78rem;color:{TEXT_DIM};">'
            f'{row["first_event_at"].strftime("%m-%d %H:%M")} → {row["last_event_at"].strftime("%m-%d %H:%M")}'
            f' · {row["chain_type"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Feature 4: 基线自适应告警
# ══════════════════════════════════════════════════════════════════════════════

def _render_adaptive_baseline(db_path: str) -> None:
    st.markdown(section_title("4. 基线自适应告警"), unsafe_allow_html=True)
    st.caption("时段-星期二维基线 · 动态偏差检测 · 误报率大幅降低")

    cfg = Config.get()

    # 基线热力图
    st.markdown("**▎ 时段基线热力图（响应时延）**")

    heatmap_data = []
    hours = list(range(24))
    days = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]

    for target in cfg.targets:
        name = target.get("name", "")
        baseline = adaptive_baseline.get_baseline_data(db_path, name, "response_time_ms")
        if baseline:
            # 构建 24x7 矩阵
            matrix = np.zeros((7, 24))
            for b in baseline:
                h = b["hour_of_day"]
                d = b["day_of_week"]
                matrix[d][h] = b["baseline_mean"]
            heatmap_data.append((name, matrix))

    if not heatmap_data:
        st.info("⏳ 暂无基线数据（需至少 5 个样本点才能建立有效基线）")
        return

    # 选择目标
    target_names = [h[0] for h in heatmap_data]
    selected = st.selectbox("选择目标", target_names, key="baseline_target")
    matrix = next(h[1] for h in heatmap_data if h[0] == selected)

    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=hours,
        y=days,
        colorscale=[[0, C_HEALTHY], [0.5, C_WARNING], [1, C_CRITICAL]],
        showscale=True,
        text=matrix,
        texttemplate="%{text:.0f}ms",
        hovertemplate="<b>%{y} %{x}:00</b><br>基线均值: %{z:.0f}ms<extra></extra>",
    ))
    fig.update_layout(
        height=300, margin=dict(t=20, b=40, l=60, r=20),
        paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
        font=dict(color=TEXT_MAIN),
        xaxis_title="小时", yaxis_title="",
    )
    st.plotly_chart(fig, use_container_width=True, key="baseline_heatmap")

    # 基线偏离统计
    st.markdown("**▎ 基线偏离统计**")
    df_baselines = db.query_df(
        db_path,
        """SELECT target_name, metric, baseline_mean, baseline_std,
                  sample_count, hour_of_day, day_of_week, updated_at
           FROM time_baselines
           ORDER BY updated_at DESC LIMIT 100"""
    )

    if not df_baselines.empty:
        df_baselines["updated_at"] = pd.to_datetime(df_baselines["updated_at"], utc=True, errors="coerce")

        # 各指标基线样本数
        st.markdown("**▎ 各指标基线样本数**")
        fig_samples = px.bar(
            df_baselines.groupby("metric")["sample_count"].sum().reset_index(),
            x="metric", y="sample_count",
            color="metric",
            color_discrete_sequence=[C_BLUE, C_HEALTHY, C_ORANGE, C_PURPLE, C_TEAL],
        )
        fig_samples.update_layout(
            height=250, margin=dict(t=20, b=40, l=50, r=20),
            paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
            font=dict(color=TEXT_MAIN),
            showlegend=False,
        )
        st.plotly_chart(fig_samples, use_container_width=True, key="baseline_samples")


# ══════════════════════════════════════════════════════════════════════════════
# Feature 5: 等保合规自查
# ══════════════════════════════════════════════════════════════════════════════

def _render_compliance(db_path: str) -> None:
    st.markdown(section_title("5. 等保合规自查"), unsafe_allow_html=True)
    st.caption("自动化证据收集 · 合规仪表盘 · 整改追踪")

    cfg = Config.get()

    # 各目标合规评分
    st.markdown("**▎ 各目标合规评分**")
    compliance_scores = []
    for target in cfg.targets:
        name = target.get("name", "")
        tls_detail = _load_tls_detail(db_path, name)
        if tls_detail:
            result = compliance.evaluate(tls_detail)
            compliance_scores.append({
                "target_name": name,
                "score": result["score"],
                "level": result["level"],
                "pass_count": result["pass_count"],
                "warn_count": result["warn_count"],
                "fail_count": result["fail_count"],
            })

    if not compliance_scores:
        st.info("⏳ 暂无合规数据")
        return

    df_compliance = pd.DataFrame(compliance_scores)

    # 合规评分柱状图
    fig_score = go.Figure()
    fig_score.add_trace(go.Bar(
        x=df_compliance["target_name"],
        y=df_compliance["score"],
        marker=dict(
            color=[C_HEALTHY if s >= 75 else (C_WARNING if s >= 60 else C_CRITICAL)
                   for s in df_compliance["score"]],
        ),
        text=[f"{s:.1f}" for s in df_compliance["score"]],
        textposition="outside",
    ))
    fig_score.add_hline(y=75, line=dict(color=C_HEALTHY, dash="dot"),
                        annotation_text="良好线 75", annotation_position="right")
    fig_score.add_hline(y=60, line=dict(color=C_WARNING, dash="dot"),
                        annotation_text="合格线 60", annotation_position="right")
    fig_score.update_layout(
        height=280, margin=dict(t=20, b=60, l=50, r=20),
        paper_bgcolor=BG_CARD, plot_bgcolor=BG_CARD,
        font=dict(color=TEXT_MAIN),
        yaxis_title="合规评分",
    )
    st.plotly_chart(fig_score, use_container_width=True, key="compliance_score")

    # 合规状态分布
    st.markdown("**▎ 合规状态分布**")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("达标条款", int(df_compliance["pass_count"].sum()))
    with col2:
        st.metric("警告条款", int(df_compliance["warn_count"].sum()))
    with col3:
        st.metric("不达标条款", int(df_compliance["fail_count"].sum()))

    # 详细条款检查
    st.markdown("**▎ 详细条款检查**")
    selected_target = st.selectbox("选择目标", df_compliance["target_name"].tolist(),
                                   key="compliance_target")
    tls_detail = _load_tls_detail(db_path, selected_target)
    result = compliance.evaluate(tls_detail)

    for category, clauses in result["categories"].items():
        with st.expander(f"{category}（{len(clauses)} 条）"):
            for clause in clauses:
                status = clause["status"]
                icon = "✅" if status == "pass" else ("⚠️" if status == "warn" else "❌")
                color = C_HEALTHY if status == "pass" else (C_WARNING if status == "warn" else C_CRITICAL)

                st.markdown(
                    f'<div style="border-left:3px solid {color};padding:8px 12px;margin-bottom:8px;">'
                    f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                    f'<span style="font-weight:600;font-size:0.9rem;">{icon} {clause["id"]} {clause["name"]}</span>'
                    f'<span style="font-size:0.78rem;color:{color};font-weight:600;">{clause["detail"]}</span>'
                    f'</div>'
                    f'<div style="font-size:0.78rem;color:{TEXT_DIM};margin-top:4px;">{clause["desc"]}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


# ══════════════════════════════════════════════════════════════════════════════
# 主渲染入口
# ══════════════════════════════════════════════════════════════════════════════

def render() -> None:
    cfg = Config.get()
    db_path = cfg.db_path

    st.markdown(page_header(
        "高级安全分析",
        "3 大创新功能 · 威胁关联 · 内容完整性 · 自适应基线",
        "🔬",
    ), unsafe_allow_html=True)

    # 功能选择
    tab1, tab2, tab3 = st.tabs([
        "🛰️ 威胁关联",
        "🔍 内容完整性",
        "📊 自适应基线",
    ])

    with tab1:
        _render_threat_correlation(db_path)

    with tab2:
        _render_content_integrity(db_path)

    with tab3:
        _render_adaptive_baseline(db_path)