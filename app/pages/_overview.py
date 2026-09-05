"""
服务态势总览页面 — 国家级竞赛标准实现
"""
from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.styles import (
    BG_CARD, BG_CHART, BORDER, BORDER_MED,
    C_BLUE, C_CRITICAL, C_HEALTHY, C_ORANGE, C_PURPLE, C_TEAL, C_WARNING,
    CHART_PALETTE, TEXT_DIM, TEXT_LIGHT, TEXT_MAIN,
    alert_badge, chart_layout, kpi_card, metric_bar,
    page_header, rgba, risk_info, score_color, section_title, status_badge,
)
from src.prediction import risk_forecast
from src.storage import db
from src.utils.config_loader import Config

# ── 风险等级颜色映射 ───────────────────────────────────────────────────────────
_RISK_LEVEL_COLOR = {
    "严重预警": C_CRITICAL,
    "高风险":   C_ORANGE,
    "中风险":   C_WARNING,
    "低风险":   C_HEALTHY,
}

# ── 分项指标标签映射 ───────────────────────────────────────────────────────────
_METRIC_LABELS = {
    "availability_score":  ("可用性",     C_BLUE),
    "response_time_score": ("响应时延",   C_HEALTHY),
    "link_score":          ("链路连通性", C_PURPLE),
    "security_score":      ("安全风险",   C_ORANGE),
}


# ══════════════════════════════════════════════════════════════════════════════
# 数据加载函数
# ══════════════════════════════════════════════════════════════════════════════

def _load_latest_scores(db_path: str) -> pd.DataFrame:
    """每个服务最新一条健康度记录。"""
    return db.query_df(
        db_path,
        """
        SELECT h.target_name, h.score, h.scored_at
        FROM health_scores h
        INNER JOIN (
            SELECT target_name, MAX(scored_at) AS latest
            FROM health_scores
            GROUP BY target_name
        ) m ON h.target_name = m.target_name AND h.scored_at = m.latest
        ORDER BY h.score DESC
        """,
    )


def _load_avg_score_24h_ago(db_path: str) -> float:
    """24 小时前的平均健康度（用于趋势对比）。"""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    df = db.query_df(
        db_path,
        """
        SELECT AVG(score) AS avg_score
        FROM (
            SELECT h.target_name, h.score
            FROM health_scores h
            INNER JOIN (
                SELECT target_name, MAX(scored_at) AS latest
                FROM health_scores
                WHERE scored_at <= ?
                GROUP BY target_name
            ) m ON h.target_name = m.target_name AND h.scored_at = m.latest
        )
        """,
        (cutoff,),
    )
    if df.empty or pd.isna(df.iloc[0]["avg_score"]):
        return 0.0
    return float(df.iloc[0]["avg_score"])


def _load_active_alerts(db_path: str) -> pd.DataFrame:
    """所有未确认告警。"""
    return db.query_df(
        db_path,
        "SELECT target_name, severity, rule_type, message, created_at FROM alerts WHERE acknowledged=0 ORDER BY created_at DESC",
    )


def _load_today_alert_count(db_path: str) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    df = db.query_df(
        db_path,
        "SELECT COUNT(*) AS cnt FROM alerts WHERE created_at >= ?",
        (today + " 00:00:00",),
    )
    return 0 if df.empty else int(df.iloc[0]["cnt"])


def _load_yesterday_alert_count(db_path: str) -> int:
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    df = db.query_df(
        db_path,
        "SELECT COUNT(*) AS cnt FROM alerts WHERE created_at >= ? AND created_at < ?",
        (yesterday + " 00:00:00", today + " 00:00:00"),
    )
    return 0 if df.empty else int(df.iloc[0]["cnt"])


def _load_today_collection_count(db_path: str) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    df = db.query_df(
        db_path,
        "SELECT COUNT(*) AS cnt FROM health_scores WHERE scored_at >= ?",
        (today + " 00:00:00",),
    )
    return 0 if df.empty else int(df.iloc[0]["cnt"])


def _load_today_avg_score(db_path: str) -> float:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    df = db.query_df(
        db_path,
        "SELECT AVG(score) AS avg_score FROM health_scores WHERE scored_at >= ?",
        (today + " 00:00:00",),
    )
    if df.empty or pd.isna(df.iloc[0]["avg_score"]):
        return 0.0
    return float(df.iloc[0]["avg_score"])


def _load_yesterday_avg_score(db_path: str) -> float:
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    df = db.query_df(
        db_path,
        "SELECT AVG(score) AS avg_score FROM health_scores WHERE scored_at >= ? AND scored_at < ?",
        (yesterday + " 00:00:00", today + " 00:00:00"),
    )
    if df.empty or pd.isna(df.iloc[0]["avg_score"]):
        return 0.0
    return float(df.iloc[0]["avg_score"])


def _load_recent_scores(db_path: str, target: str, n: int = 20) -> list:
    """近 n 条健康度，时间正序。"""
    df = db.query_df(
        db_path,
        "SELECT score FROM health_scores WHERE target_name=? ORDER BY scored_at DESC LIMIT ?",
        (target, n),
    )
    return [] if df.empty else df["score"].tolist()[::-1]


def _load_fused_latest(db_path: str, target: str) -> dict:
    """最新一条融合指标。"""
    df = db.query_df(
        db_path,
        """
        SELECT f.*
        FROM fused_metrics f
        INNER JOIN (
            SELECT target_name, MAX(fused_at) AS latest
            FROM fused_metrics
            WHERE target_name=?
        ) m ON f.target_name = m.target_name AND f.fused_at = m.latest
        """,
        (target,),
    )
    return {} if df.empty else df.iloc[0].to_dict()


def _active_alert_count(db_path: str, target: str) -> int:
    df = db.query_df(
        db_path,
        "SELECT COUNT(*) AS cnt FROM alerts WHERE target_name=? AND acknowledged=0",
        (target,),
    )
    return 0 if df.empty else int(df.iloc[0]["cnt"])


# ══════════════════════════════════════════════════════════════════════════════
# 图表构建函数
# ══════════════════════════════════════════════════════════════════════════════

def _build_gauge(score: float) -> go.Figure:
    """渐变色仪表盘。"""
    _, color, _ = risk_info(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={
            "axis": {
                "range": [0, 100],
                "tickvals": [0, 20, 40, 60, 80, 100],
                "tickfont": {"color": TEXT_DIM, "size": 9},
                "tickcolor": BORDER_MED,
            },
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": BG_CHART,
            "bordercolor": BORDER,
            "borderwidth": 1,
            "steps": [
                {"range": [0,  60],  "color": rgba(C_CRITICAL, 0.10)},
                {"range": [60, 80],  "color": rgba(C_WARNING,  0.10)},
                {"range": [80, 100], "color": rgba(C_HEALTHY,  0.10)},
            ],
            "threshold": {
                "line": {"color": C_CRITICAL, "width": 2},
                "thickness": 0.75,
                "value": 60,
            },
        },
        number={
            "font": {"size": 30, "color": color, "family": "Inter,sans-serif"},
            "suffix": "",
        },
    ))
    fig.update_layout(
        height=190,
        margin=dict(t=20, b=10, l=20, r=20),
        paper_bgcolor=BG_CARD,
        plot_bgcolor=BG_CARD,
        font={"color": TEXT_MAIN, "family": "Inter,'PingFang SC','Microsoft YaHei',sans-serif"},
    )
    return fig


def _build_sparkline(scores: list, color: str) -> go.Figure:
    """带填充的迷你趋势折线图。"""
    fig = go.Figure(go.Scatter(
        y=scores,
        mode="lines",
        line=dict(color=color, width=2),
        fill="tozeroy",
        fillcolor=rgba(color, 0.15),
        hovertemplate="%{y:.1f}<extra></extra>",
    ))
    fig.update_layout(
        height=70,
        margin=dict(t=4, b=4, l=4, r=4),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False, range=[0, 105]),
        showlegend=False,
    )
    return fig


def _build_bar_chart(df: pd.DataFrame) -> go.Figure:
    """所有服务健康度对比柱状图，带警戒线。"""
    colors = [score_color(s) for s in df["score"]]
    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=df["target_name"],
        y=df["score"],
        marker=dict(
            color=colors,
            line=dict(width=0),
            opacity=0.88,
        ),
        text=[f"{s:.1f}" for s in df["score"]],
        textposition="outside",
        textfont=dict(size=11, color=TEXT_MAIN),
        hovertemplate="<b>%{x}</b><br>健康度: %{y:.1f}<extra></extra>",
        name="健康度",
    ))

    # 警戒线 60
    fig.add_hline(
        y=60,
        line=dict(color=C_CRITICAL, width=1.5, dash="dot"),
        annotation_text="异常阈值 60",
        annotation_position="right",
        annotation_font=dict(color=C_CRITICAL, size=10),
    )
    # 警戒线 80
    fig.add_hline(
        y=80,
        line=dict(color=C_HEALTHY, width=1.5, dash="dot"),
        annotation_text="健康阈值 80",
        annotation_position="right",
        annotation_font=dict(color=C_HEALTHY, size=10),
    )

    layout = chart_layout(
        title=dict(text="各服务健康度对比", font=dict(size=14, color=TEXT_MAIN), x=0),
        yaxis=dict(range=[0, 115], title="健康度评分"),
        xaxis=dict(title=""),
        showlegend=False,
        height=320,
        margin=dict(t=50, b=60, l=55, r=80),
    )
    fig.update_layout(**layout)
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 子组件渲染函数
# ══════════════════════════════════════════════════════════════════════════════

def _render_kpi_bar(df: pd.DataFrame, db_path: str) -> None:
    """顶部 5 列 KPI 栏。"""
    avg_score = df["score"].mean()
    avg_24h   = _load_avg_score_24h_ago(db_path)
    total     = len(df)
    online    = int((df["score"] > 0).sum())
    sla_count = int((df["score"] >= 80).sum())
    active_alerts = _load_today_alert_count(db_path)
    collections   = _load_today_collection_count(db_path)

    # 趋势方向
    if avg_24h > 0:
        delta = avg_score - avg_24h
        trend = "up" if delta > 0 else ("down" if delta < 0 else "")
        trend_sub = f"较24h前 {'▲' if delta > 0 else '▼'} {abs(delta):.1f} 分"
    else:
        trend = ""
        trend_sub = "暂无历史对比"

    avg_color = score_color(avg_score)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(
            kpi_card("平均健康度", f"{avg_score:.1f}", trend_sub, avg_color, "📊", trend),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            kpi_card("在线 / 总服务", f"{online} / {total}", "个监测目标", C_BLUE, "🖥️"),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            kpi_card("SLA 达成率", f"{sla_count} / {total}", "健康度 ≥ 80 的服务数", C_HEALTHY, "✅"),
            unsafe_allow_html=True,
        )
    with c4:
        alert_color = C_CRITICAL if active_alerts > 0 else C_HEALTHY
        st.markdown(
            kpi_card("活跃告警数", str(active_alerts), "今日未确认告警", alert_color, "🔔"),
            unsafe_allow_html=True,
        )
    with c5:
        st.markdown(
            kpi_card("今日采集次数", str(collections), "health_scores 记录数", C_PURPLE, "📡"),
            unsafe_allow_html=True,
        )


def _render_risk_warning_bar(db_path: str) -> None:
    """未来风险预警指数横幅：区别于健康度（反映当前状态），此处预测未来1-2天风险。"""
    risk_df = risk_forecast.get_latest(db_path)

    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">'
        f'<span style="font-size:1rem;">🔮</span>'
        f'<span style="font-size:0.95rem;font-weight:700;color:{TEXT_MAIN};">未来风险预警指数</span>'
        f'<span style="font-size:0.72rem;color:{TEXT_DIM};">'
        f'（融合健康度预测趋势 · 威胁情报走势 · 内容篡改频率，预测未来1-2天风险，而非当前状态）</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if risk_df.empty:
        st.info("⏳ 风险预警指数正在计算中，请等待下一轮采集周期完成。")
        return

    high_risk = risk_df[risk_df["risk_score"] >= 40]

    cards_html = '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px;">'
    for _, row in risk_df.iterrows():
        color = _RISK_LEVEL_COLOR.get(row["risk_level"], C_BLUE)
        cards_html += (
            f'<div style="flex:1;min-width:160px;background:{BG_CARD};border:1px solid {BORDER};'
            f'border-top:3px solid {color};border-radius:12px;padding:12px 16px;'
            f'box-shadow:0 1px 4px rgba(15,23,42,0.06);">'
            f'<div style="font-size:0.78rem;color:{TEXT_DIM};font-weight:500;'
            f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{row["target_name"]}</div>'
            f'<div style="display:flex;align-items:baseline;gap:6px;margin-top:4px;">'
            f'<span style="font-size:1.5rem;font-weight:700;color:{color};">{row["risk_score"]:.0f}</span>'
            f'<span style="font-size:0.72rem;color:{color};font-weight:600;">{row["risk_level"]}</span>'
            f'</div></div>'
        )
    cards_html += "</div>"
    st.markdown(cards_html, unsafe_allow_html=True)

    if not high_risk.empty:
        names = "、".join(high_risk["target_name"].tolist())
        st.warning(f"⚠️ 以下目标未来1-2天风险指数偏高，建议提前关注：**{names}**（详情见「时序预测与趋势」页面）")
    else:
        st.success("✅ 当前所有目标未来风险指数均处于低位")


def _render_comparison_bar(db_path: str) -> None:
    """今日 vs 昨日对比横向卡片。"""
    today_score = _load_today_avg_score(db_path)
    yest_score  = _load_yesterday_avg_score(db_path)
    today_alerts = _load_today_alert_count(db_path)
    yest_alerts  = _load_yesterday_alert_count(db_path)

    def _pct_change(cur: float, prev: float) -> str:
        if prev == 0:
            return "—"
        delta = (cur - prev) / prev * 100
        arrow = "▲" if delta > 0 else "▼"
        color = C_CRITICAL if delta > 0 else C_HEALTHY  # 健康度上升是好事，告警上升是坏事
        return f'<span style="color:{color};font-weight:700;">{arrow} {abs(delta):.1f}%</span>'

    score_change  = _pct_change(today_score, yest_score)
    # 告警：上升是坏事，颜色逻辑反转
    if yest_alerts == 0:
        alert_change_html = "—"
    else:
        delta_a = today_alerts - yest_alerts
        arrow_a = "▲" if delta_a > 0 else "▼"
        color_a = C_CRITICAL if delta_a > 0 else C_HEALTHY
        alert_change_html = f'<span style="color:{color_a};font-weight:700;">{arrow_a} {abs(delta_a)}</span>'

    html = (
        f'<div style="display:flex;gap:16px;margin-bottom:20px;">'

        # 健康度对比
        f'<div style="flex:1;background:{BG_CARD};border:1px solid {BORDER};border-radius:14px;'
        f'padding:16px 22px;box-shadow:0 1px 4px rgba(15,23,42,0.06);">'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM};font-weight:500;margin-bottom:10px;">📈 平均健康度对比</div>'
        f'<div style="display:flex;align-items:center;gap:24px;">'
        f'<div><div style="font-size:0.7rem;color:{TEXT_LIGHT};">今日</div>'
        f'<div style="font-size:1.5rem;font-weight:700;color:{score_color(today_score) if today_score else C_BLUE};">'
        f'{today_score:.1f}</div></div>'
        f'<div style="font-size:1.2rem;color:{TEXT_DIM};">vs</div>'
        f'<div><div style="font-size:0.7rem;color:{TEXT_LIGHT};">昨日</div>'
        f'<div style="font-size:1.5rem;font-weight:700;color:{TEXT_DIM};">{yest_score:.1f}</div></div>'
        f'<div style="margin-left:auto;font-size:1rem;">{score_change}</div>'
        f'</div></div>'

        # 告警对比
        f'<div style="flex:1;background:{BG_CARD};border:1px solid {BORDER};border-radius:14px;'
        f'padding:16px 22px;box-shadow:0 1px 4px rgba(15,23,42,0.06);">'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM};font-weight:500;margin-bottom:10px;">🔔 告警数量对比</div>'
        f'<div style="display:flex;align-items:center;gap:24px;">'
        f'<div><div style="font-size:0.7rem;color:{TEXT_LIGHT};">今日</div>'
        f'<div style="font-size:1.5rem;font-weight:700;color:{C_CRITICAL if today_alerts > 0 else C_HEALTHY};">'
        f'{today_alerts}</div></div>'
        f'<div style="font-size:1.2rem;color:{TEXT_DIM};">vs</div>'
        f'<div><div style="font-size:0.7rem;color:{TEXT_LIGHT};">昨日</div>'
        f'<div style="font-size:1.5rem;font-weight:700;color:{TEXT_DIM};">{yest_alerts}</div></div>'
        f'<div style="margin-left:auto;font-size:1rem;">{alert_change_html}</div>'
        f'</div></div>'

        f'</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def _render_service_card(col, target_name: str, score: float, scored_at: str,
                         db_path: str) -> None:
    """单张服务健康度卡片。"""
    label, color, bg = risk_info(score)
    recent_scores = _load_recent_scores(db_path, target_name)
    fused         = _load_fused_latest(db_path, target_name)
    alert_cnt     = _active_alert_count(db_path, target_name)

    with col:
        # ── 卡片外壳 ──────────────────────────────────────────────────────────
        st.markdown(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
            f'border-left:4px solid {color};border-radius:14px;'
            f'padding:16px 18px 12px 18px;margin-bottom:16px;'
            f'box-shadow:0 2px 8px rgba(15,23,42,0.07),0 1px 3px rgba(15,23,42,0.04);'
            f'transition:box-shadow 0.2s;">'

            # 顶部：服务名 + 状态徽章 + 告警徽章
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap;">'
            f'<span style="font-size:0.98rem;font-weight:700;color:{TEXT_MAIN};flex:1;min-width:0;'
            f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{target_name}</span>'
            + status_badge(label, color)
            + alert_badge(alert_cnt) +
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # ── 仪表盘 + 趋势图 ───────────────────────────────────────────────────
        g_col, s_col = st.columns([5, 4])
        with g_col:
            st.plotly_chart(
                _build_gauge(score),
                use_container_width=True,
                key=f"gauge_{target_name}",
            )
        with s_col:
            st.markdown(
                f'<div style="font-size:0.7rem;color:{TEXT_DIM};font-weight:600;'
                f'margin-top:8px;margin-bottom:2px;">近期趋势</div>',
                unsafe_allow_html=True,
            )
            if recent_scores:
                st.plotly_chart(
                    _build_sparkline(recent_scores, color),
                    use_container_width=True,
                    key=f"spark_{target_name}",
                )
            else:
                st.markdown(
                    f'<div style="height:70px;display:flex;align-items:center;'
                    f'justify-content:center;color:{TEXT_LIGHT};font-size:0.72rem;">暂无数据</div>',
                    unsafe_allow_html=True,
                )

            # ── 分项指标进度条 ─────────────────────────────────────────────
            if fused:
                bars_html = ""
                for key, (lbl, bar_c) in _METRIC_LABELS.items():
                    val = float(fused.get(key) or 0)
                    if key == "security_score":
                        # 安全维度：特殊标注，突出显示
                        sec_color = score_color(val)
                        sec_icon = "🔒" if val >= 70 else ("⚠️" if val >= 50 else "🚨")
                        bars_html += metric_bar(f"{sec_icon} 安全风险", val, sec_color)
                    else:
                        bars_html += metric_bar(lbl, val, score_color(val))
                # 安全评分单独补充一行文字说明
                sec_val = float(fused.get("security_score") or 0)
                if sec_val < 70:
                    sec_tip_color = C_CRITICAL if sec_val < 50 else C_WARNING
                    sec_tip = "TLS/威胁情报异常，建议前往「数据启示」查看安全建议" if sec_val < 50 else "安全评分偏低，建议检查TLS配置"
                    bars_html += (
                        f'<div style="font-size:0.67rem;color:{sec_tip_color};'
                        f'background:{rgba(sec_tip_color, 0.08)};border-radius:4px;'
                        f'padding:3px 7px;margin-top:3px;">'
                        f'🔐 {sec_tip}</div>'
                    )
                st.markdown(
                    f'<div style="margin-top:6px;">{bars_html}</div>',
                    unsafe_allow_html=True,
                )

        # ── 底部：最后评估时间 ────────────────────────────────────────────────
        st.markdown(
            f'<div style="font-size:0.7rem;color:{TEXT_LIGHT};'
            f'padding:4px 0 8px 0;border-top:1px solid {BORDER};margin-top:4px;">'
            f'🕐 最后评估：<span style="color:{C_BLUE};">{scored_at[:19]}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_summary_table(df: pd.DataFrame) -> None:
    """健康度汇总表格，带颜色标记。"""
    display = df.copy()
    display["风险等级"]  = display["score"].apply(
        lambda s: "✅ 正常" if s >= 80 else ("⚠️ 警告" if s >= 60 else "🔴 异常")
    )
    display["健康度评分"] = display["score"].apply(lambda s: f"{s:.1f}")
    display = display.rename(columns={
        "target_name": "服务名称",
        "scored_at":   "评估时间",
    })[["服务名称", "健康度评分", "风险等级", "评估时间"]]
    st.dataframe(display, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# 主渲染入口
# ══════════════════════════════════════════════════════════════════════════════

def render() -> None:
    cfg     = Config.get()
    db_path = cfg.db_path
    auto_refresh = cfg.get_setting("ui", "auto_refresh_seconds", default=30)

    # ── 1. Banner ─────────────────────────────────────────────────────────────
    now_str = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S CST")
    st.markdown(
        page_header(
            "服务态势总览",
            f"实时掌握全网服务运行状态与健康度评分 · 最后更新：{now_str}",
            "📡",
        ),
        unsafe_allow_html=True,
    )

    # ── 2. 加载核心数据 ───────────────────────────────────────────────────────
    df = _load_latest_scores(db_path)

    if df.empty:
        st.info("⏳ 等待首次采集完成（约 1 分钟），请稍候…")
        return

    # ── 3. KPI 栏 ─────────────────────────────────────────────────────────────
    st.markdown(section_title("核心指标"), unsafe_allow_html=True)
    _render_kpi_bar(df, db_path)

    # ── 3.5 未来风险预警指数 ───────────────────────────────────────────────────
    st.markdown(section_title("未来风险预警"), unsafe_allow_html=True)
    _render_risk_warning_bar(db_path)

    # ── 4. 今日 vs 昨日对比 ───────────────────────────────────────────────────
    st.markdown(section_title("今日 vs 昨日对比"), unsafe_allow_html=True)
    _render_comparison_bar(db_path)

    # ── 5. 服务健康度卡片网格 ─────────────────────────────────────────────────
    st.markdown(section_title("服务健康度详情"), unsafe_allow_html=True)

    records = list(df.iterrows())
    for row_start in range(0, len(records), 2):
        pair = records[row_start : row_start + 2]
        cols = st.columns(2)
        for col_idx, (_, row) in enumerate(pair):
            _render_service_card(
                cols[col_idx],
                target_name=str(row["target_name"]),
                score=float(row["score"]),
                scored_at=str(row["scored_at"]),
                db_path=db_path,
            )

    # ── 6. 底部汇总区 ─────────────────────────────────────────────────────────
    st.markdown(section_title("汇总分析"), unsafe_allow_html=True)

    chart_col, table_col = st.columns([3, 2])
    with chart_col:
        st.plotly_chart(
            _build_bar_chart(df),
            use_container_width=True,
            key="overview_bar_chart",
        )
    with table_col:
        st.markdown(
            f'<div style="font-size:0.82rem;font-weight:600;color:{TEXT_MAIN};'
            f'margin-bottom:8px;">健康度汇总表</div>',
            unsafe_allow_html=True,
        )
        _render_summary_table(df)

    # ── 页脚 ──────────────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="text-align:center;padding:16px 0 8px 0;'
        f'color:{TEXT_LIGHT};font-size:0.72rem;">'
        f'数据每 {auto_refresh} 秒自动刷新 · 服务态势总览 v2.0'
        f'</div>',
        unsafe_allow_html=True,
    )