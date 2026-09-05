"""时序预测与趋势分析 — 国家级竞赛标准重写版"""
from datetime import datetime, timedelta, timezone

import numpy as np
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
from src.prediction import prophet_model, risk_forecast
from src.storage import db
from src.utils.config_loader import Config

_RISK_LEVEL_COLOR = {
    "严重预警": C_CRITICAL,
    "高风险":   C_ORANGE,
    "中风险":   C_WARNING,
    "低风险":   C_HEALTHY,
}

_METRIC_LABELS = {
    "availability_score":  ("可用性得分",     C_BLUE),
    "response_time_score": ("响应时延得分",   C_HEALTHY),
    "link_score":          ("链路连通性得分", C_PURPLE),
    "security_score":      ("安全风险得分",   C_ORANGE),
}


def _load_fused(db_path: str, target: str, col: str, hours: int) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        f"SELECT fused_at, {col} FROM fused_metrics "
        f"WHERE target_name=? AND fused_at>=? ORDER BY fused_at",
        (target, since),
    )
    if df.empty:
        return df
    df["fused_at"] = pd.to_datetime(df["fused_at"], utc=True)
    df[col] = pd.to_numeric(df[col], errors="coerce")
    return df.dropna(subset=[col])


def _load_health(db_path: str, target: str, hours: int) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT scored_at, score FROM health_scores "
        "WHERE target_name=? AND scored_at>=? ORDER BY scored_at",
        (target, since),
    )
    if df.empty:
        return df
    df["scored_at"] = pd.to_datetime(df["scored_at"], utc=True)
    df["score"] = pd.to_numeric(df["score"], errors="coerce")
    return df.dropna(subset=["score"])


def _trend_direction(series: pd.Series) -> tuple[str, str]:
    """Return (label, color) for trend direction using linear regression slope."""
    if len(series) < 3:
        return "数据不足", TEXT_DIM
    x = np.arange(len(series))
    slope = np.polyfit(x, series.values, 1)[0]
    if slope > 0.5:
        return "↑ 上升趋势", C_CRITICAL
    if slope < -0.5:
        return "↓ 下降趋势", C_HEALTHY
    return "→ 平稳", C_BLUE


def _volatility_label(series: pd.Series) -> tuple[str, str]:
    if len(series) < 3:
        return "—", TEXT_DIM
    cv = series.std() / (series.mean() + 1e-9) * 100
    if cv > 20:
        return f"高波动 ({cv:.0f}%)", C_CRITICAL
    if cv > 10:
        return f"中波动 ({cv:.0f}%)", C_WARNING
    return f"低波动 ({cv:.0f}%)", C_HEALTHY


def _forecast_health(db_path: str, target: str, forecast_days: int,
                     min_pts: int, refit: int):
    """Forecast health score directly from health_scores table, resampled to daily."""
    hs = _load_health(db_path, target, 720)
    if hs.empty or len(hs) < min_pts:
        return None

    # Resample to daily — same treatment as prophet_model._load_series
    tmp = hs.rename(columns={"scored_at": "ds", "score": "y"}).copy()
    tmp["ds"] = pd.to_datetime(tmp["ds"]).dt.tz_convert(None)
    tmp = tmp.set_index("ds").resample("D")["y"].mean().dropna().reset_index()

    if len(tmp) < min_pts:
        return None

    try:
        from src.prediction.prophet_model import _fit_and_predict, _linear_forecast
        if len(tmp) >= 10:
            return _fit_and_predict(tmp, forecast_days)
        return _linear_forecast(tmp, forecast_days)
    except Exception as exc:
        from src.utils.logger import get_logger
        get_logger(__name__).error("Health forecast error: %s", exc)
        try:
            from src.prediction.prophet_model import _linear_forecast
            return _linear_forecast(tmp, forecast_days)
        except Exception:
            return None


def _six_metrics_grid(db_path: str, target: str, hours: int) -> go.Figure:
    """6-panel grid: 4 fused metrics + health score + composite radar placeholder."""
    hs_df = _load_health(db_path, target, hours)
    titles = [v[0] for v in _METRIC_LABELS.values()] + ["综合健康度", "指标雷达图"]
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=titles,
        vertical_spacing=0.11, horizontal_spacing=0.08,
        specs=[
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "xy"}, {"type": "polar"}],
        ],
    )
    positions = [(1,1),(1,2),(2,1),(2,2)]
    for (col, (label, color)), (row, c) in zip(_METRIC_LABELS.items(), positions):
        df = _load_fused(db_path, target, col, hours)
        if df.empty:
            continue
        fig.add_trace(go.Scatter(
            x=df["fused_at"], y=df[col],
            mode="lines", name=label,
            line=dict(color=color, width=2),
            fill="tozeroy", fillcolor=rgba(color, 0.09),
            showlegend=False,
        ), row=row, col=c)
        fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1,
                      row=row, col=c)
        fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING, line_width=1,
                      row=row, col=c)

    # Panel 5: health score trend
    if not hs_df.empty:
        fig.add_trace(go.Scatter(
            x=hs_df["scored_at"], y=hs_df["score"],
            mode="lines", name="综合健康度",
            line=dict(color=C_HEALTHY, width=2),
            fill="tozeroy", fillcolor=rgba(C_HEALTHY, 0.09),
            showlegend=False,
        ), row=3, col=1)
        fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1, row=3, col=1)
        fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING,  line_width=1, row=3, col=1)

    # Panel 6: radar of latest values
    latest_vals = []
    radar_labels = []
    for col, (label, _) in _METRIC_LABELS.items():
        df = _load_fused(db_path, target, col, hours)
        if not df.empty:
            latest_vals.append(float(df[col].iloc[-1]))
            radar_labels.append(label)
    if latest_vals:
        radar_labels_closed = radar_labels + [radar_labels[0]]
        latest_vals_closed  = latest_vals  + [latest_vals[0]]
        fig.add_trace(go.Scatterpolar(
            r=latest_vals_closed, theta=radar_labels_closed,
            fill="toself", fillcolor=rgba(C_BLUE, 0.18),
            line=dict(color=C_BLUE, width=2),
            name="最新指标", showlegend=False,
        ), row=3, col=2)

    fig.update_layout(
        height=620, paper_bgcolor=BG_CARD, plot_bgcolor=BG_CHART,
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


def _to_utc_aware(ds_series: pd.Series) -> pd.Series:
    """Convert a ds column (naive or aware) to UTC-aware for Plotly alignment."""
    s = pd.to_datetime(ds_series)
    if s.dt.tz is None:
        return s.dt.tz_localize("UTC")
    return s.dt.tz_convert("UTC")


def _forecast_chart(
    hist_df: pd.DataFrame, fc_df: pd.DataFrame | None,
    col: str, label: str, color: str,
) -> go.Figure:
    fig = go.Figure()

    # Historical data: resample to daily for consistent x-axis scale
    hist = hist_df.copy()
    hist["fused_at"] = pd.to_datetime(hist["fused_at"])
    daily_hist = hist.set_index("fused_at").resample("D")[col].mean().dropna().reset_index()
    daily_hist.columns = ["date", "val"]

    fig.add_trace(go.Scatter(
        x=daily_hist["date"], y=daily_hist["val"],
        mode="lines+markers",
        name=f"历史{label}（日均值）",
        line=dict(color=color, width=2.5),
        marker=dict(size=5, color=color),
        fill="tozeroy", fillcolor=rgba(color, 0.08),
        hovertemplate="日期：%{x|%m-%d}<br>得分：%{y:.1f}<extra>历史</extra>",
    ))

    # Forecast: confidence band + prediction line
    if fc_df is not None and not fc_df.empty:
        fc = fc_df.copy()
        fc["ds"] = _to_utc_aware(fc["ds"])
        now_utc = datetime.now(timezone.utc)
        future = fc[fc["ds"] > now_utc].copy()

        if not future.empty:
            # Vertical separator
            sep_x = future["ds"].iloc[0]
            fig.add_shape(type="line",
                x0=sep_x, x1=sep_x, y0=0, y1=1, xref="x", yref="paper",
                line=dict(color="#555555", width=1.5, dash="dash"))
            fig.add_annotation(x=sep_x, y=105, xref="x", yref="y",
                text="← 历史 | 预测 →", showarrow=False,
                font=dict(size=11, color="#555555"))

            # Confidence band
            band_x = pd.concat([future["ds"], future["ds"].iloc[::-1]], ignore_index=True)
            band_y = pd.concat([future["yhat_upper"], future["yhat_lower"].iloc[::-1]], ignore_index=True)
            fig.add_trace(go.Scatter(
                x=band_x, y=band_y,
                fill="toself",
                fillcolor="rgba(99,179,237,0.30)",
                line=dict(color="rgba(66,153,225,0.5)", width=1),
                name="80%置信区间（预测不确定性范围）",
                hoverinfo="skip",
                showlegend=True,
            ))

            # Prediction line
            fig.add_trace(go.Scatter(
                x=future["ds"], y=future["yhat"],
                mode="lines+markers",
                name=f"预测{label}（未来7天）",
                line=dict(color="#E07B00", width=2.5, dash="dash"),
                marker=dict(size=7, color="#E07B00", symbol="diamond"),
                hovertemplate="日期：%{x|%m-%d}<br>预测值：%{y:.1f}<extra>预测</extra>",
            ))

            # Value labels on prediction points
            for _, row in future.iterrows():
                fig.add_annotation(
                    x=row["ds"], y=row["yhat"],
                    text=f"{row['yhat']:.0f}",
                    showarrow=False, yshift=12,
                    font=dict(size=9, color="#E07B00"),
                )

    # Threshold reference lines
    fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1.5,
                  annotation_text="警戒线 60 分", annotation_font_color=C_CRITICAL,
                  annotation_font_size=10, annotation_position="top left")
    fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING, line_width=1.5,
                  annotation_text="良好线 80 分", annotation_font_color=C_WARNING,
                  annotation_font_size=10, annotation_position="top left")

    fig.update_layout(**chart_layout(
        height=460,
        title=dict(
            text=f"时序预测 · {label}（未来一周）<br>"
                 f"<sup style='color:#666;font-weight:normal;'>"
                 f"实线=历史日均值 | 橙色虚线=预测值 | 蓝色区域=80%置信区间</sup>",
            font=dict(size=14, color=TEXT_MAIN)),
        xaxis=dict(
            title="日期",
            tickformat="%m-%d",
            dtick=86400000,
            gridcolor=BORDER, linecolor=BORDER_MED,
            tickfont=dict(color=TEXT_DIM)),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM), range=[0, 107],
                   title="得分 (0–100)"),
        legend=dict(orientation="h", yanchor="top", y=-0.15, xanchor="center", x=0.5,
                    bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1,
                    font=dict(size=11)),
    ))
    return fig


def _health_trend_chart(hs_df: pd.DataFrame, fc_df: pd.DataFrame | None) -> go.Figure:
    fig = go.Figure()

    # Resample historical data to daily for consistent x-axis scale
    hist = hs_df.copy()
    hist["scored_at"] = pd.to_datetime(hist["scored_at"])
    daily_hist = hist.set_index("scored_at").resample("D")["score"].mean().dropna().reset_index()
    daily_hist.columns = ["date", "score"]

    # Historical data: green solid line
    fig.add_trace(go.Scatter(
        x=daily_hist["date"], y=daily_hist["score"],
        mode="lines+markers",
        name="历史健康度（日均值）",
        line=dict(color=C_HEALTHY, width=2.5),
        marker=dict(size=5, color=C_HEALTHY),
        fill="tozeroy", fillcolor=rgba(C_HEALTHY, 0.08),
        hovertemplate="日期：%{x|%m-%d}<br>健康度：%{y:.1f}<extra>历史</extra>",
    ))

    if fc_df is not None and not fc_df.empty:
        fc = fc_df.copy()
        fc["ds"] = _to_utc_aware(fc["ds"])
        now_utc = datetime.now(timezone.utc)
        future = fc[fc["ds"] > now_utc].copy()

        if not future.empty:
            # Vertical separator line
            sep_x = future["ds"].iloc[0]
            fig.add_shape(type="line",
                x0=sep_x, x1=sep_x, y0=0, y1=1, xref="x", yref="paper",
                line=dict(color="#555555", width=1.5, dash="dash"))
            fig.add_annotation(x=sep_x, y=105, xref="x", yref="y",
                text="← 历史 | 预测 →", showarrow=False,
                font=dict(size=11, color="#555555"))

            # Confidence band: light blue shaded area
            band_x = pd.concat([future["ds"], future["ds"].iloc[::-1]], ignore_index=True)
            band_y = pd.concat([future["yhat_upper"], future["yhat_lower"].iloc[::-1]], ignore_index=True)
            fig.add_trace(go.Scatter(
                x=band_x, y=band_y,
                fill="toself",
                fillcolor="rgba(99,179,237,0.30)",
                line=dict(color="rgba(66,153,225,0.5)", width=1),
                name="80%置信区间（预测不确定性范围）",
                hoverinfo="skip",
                showlegend=True,
            ))

            # Prediction line: orange dashed
            fig.add_trace(go.Scatter(
                x=future["ds"], y=future["yhat"],
                mode="lines+markers",
                name="预测健康度（未来7天）",
                line=dict(color="#E07B00", width=2.5, dash="dash"),
                marker=dict(size=7, color="#E07B00", symbol="diamond"),
                hovertemplate="日期：%{x|%m-%d}<br>预测值：%{y:.1f}<extra>预测</extra>",
            ))

            # Show prediction values as text annotations on the line
            for i, row in future.iterrows():
                fig.add_annotation(
                    x=row["ds"], y=row["yhat"],
                    text=f"{row['yhat']:.0f}",
                    showarrow=False, yshift=12,
                    font=dict(size=9, color="#E07B00"),
                )

    # Threshold lines
    fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1.5,
                  annotation_text="警戒线 60 分", annotation_font_color=C_CRITICAL,
                  annotation_font_size=10, annotation_position="top left")
    fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING, line_width=1.5,
                  annotation_text="良好线 80 分", annotation_font_color=C_WARNING,
                  annotation_font_size=10, annotation_position="top left")

    fig.update_layout(**chart_layout(
        height=440,
        title=dict(
            text="综合健康度趋势与预测（未来一周）<br>"
                 "<sup style='color:#666;font-weight:normal;'>"
                 "绿色实线=历史日均值 | 橙色虚线=预测值 | 蓝色区域=80%置信区间</sup>",
            font=dict(size=14, color=TEXT_MAIN)),
        xaxis=dict(
            title="日期",
            tickformat="%m-%d",
            dtick=86400000,  # one day in ms
            gridcolor=BORDER, linecolor=BORDER_MED,
            tickfont=dict(color=TEXT_DIM)),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM), range=[0, 107],
                   title="健康度评分 (0–100)"),
        legend=dict(orientation="h", yanchor="top", y=-0.15, xanchor="center", x=0.5,
                    bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1,
                    font=dict(size=11)),
    ))
    return fig


def _periodicity_heatmap(hs_df: pd.DataFrame) -> go.Figure | None:
    """Hour-of-day × day-of-week average health score heatmap."""
    if len(hs_df) < 12:
        return None
    df = hs_df.copy()
    df["hour"] = df["scored_at"].dt.hour
    df["dow"]  = df["scored_at"].dt.dayofweek
    pivot = df.pivot_table(values="score", index="hour", columns="dow", aggfunc="mean")
    dow_labels = ["周一","周二","周三","周四","周五","周六","周日"]
    cols = [dow_labels[c] for c in pivot.columns]

    fig = go.Figure(go.Heatmap(
        z=pivot.values,
        x=cols,
        y=[f"{h:02d}:00" for h in pivot.index],
        colorscale=[
            [0.0, rgba(C_CRITICAL, 1.0)],
            [0.5, rgba(C_WARNING, 1.0)],
            [1.0, rgba(C_HEALTHY, 1.0)],
        ],
        zmin=0, zmax=100,
        colorbar=dict(title="健康度", tickfont=dict(color=TEXT_DIM)),
        hovertemplate="时间：%{y}<br>%{x}<br>健康度：%{z:.1f}<extra></extra>",
    ))
    fig.update_layout(**chart_layout(
        height=320,
        title=dict(text="健康度周期性热力图（时段 × 星期）",
                   font=dict(size=13, color=TEXT_MAIN)),
        xaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM)),
        yaxis=dict(gridcolor=BORDER, linecolor=BORDER_MED,
                   tickfont=dict(color=TEXT_DIM), autorange="reversed"),
        margin=dict(t=60, b=44, l=70, r=24),
    ))
    return fig


def _risk_history_chart(risk_hist: pd.DataFrame) -> go.Figure:
    """未来风险预警指数历史趋势 + 三个分量堆叠面积图。"""
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=risk_hist["computed_at"], y=risk_hist["risk_score"],
        mode="lines+markers", name="综合风险指数",
        line=dict(color=C_CRITICAL, width=2.5),
        marker=dict(size=5, color=C_CRITICAL),
        hovertemplate="时间：%{x}<br>风险指数：%{y:.1f}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=risk_hist["computed_at"], y=risk_hist["health_trend_risk"],
        mode="lines", name="健康度预测风险",
        line=dict(color=C_BLUE, width=1.5, dash="dot"),
    ))
    fig.add_trace(go.Scatter(
        x=risk_hist["computed_at"], y=risk_hist["threat_trend_risk"],
        mode="lines", name="威胁情报趋势风险",
        line=dict(color=C_PURPLE, width=1.5, dash="dot"),
    ))
    fig.add_trace(go.Scatter(
        x=risk_hist["computed_at"], y=risk_hist["content_tamper_risk"],
        mode="lines", name="内容篡改频率风险",
        line=dict(color=C_ORANGE, width=1.5, dash="dot"),
    ))
    fig.add_hrect(y0=40, y1=100, fillcolor=rgba(C_CRITICAL, 0.05), line_width=0)
    fig.update_layout(**chart_layout(
        height=340,
        title=dict(text="未来风险预警指数历史趋势",
                   font=dict(size=13, color=TEXT_MAIN)),
        yaxis=dict(range=[0, 105], title="风险指数 (0–100)",
                   gridcolor=BORDER, linecolor=BORDER_MED, tickfont=dict(color=TEXT_DIM)),
        xaxis=dict(title="时间"),
        legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5,
                    bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1, font=dict(size=10)),
    ))
    return fig


def _render_risk_section(db_path: str, target: str, hours: int) -> None:
    st.markdown(section_title("未来风险预警指数"), unsafe_allow_html=True)
    st.caption("融合健康度预测趋势、威胁情报走势、内容篡改频率，预测未来1-2天风险等级，区别于当前状态告警")

    risk = risk_forecast.compute(db_path, target)
    color = _RISK_LEVEL_COLOR.get(risk["risk_level"], C_BLUE)

    top_html = (
        f'<div style="display:flex;gap:16px;align-items:center;background:{BG_CARD};'
        f'border:1px solid {BORDER};border-left:5px solid {color};border-radius:12px;'
        f'padding:16px 22px;margin-bottom:14px;">'
        f'<div style="font-size:2.2rem;font-weight:700;color:{color};">{risk["risk_score"]:.0f}</div>'
        f'<div>'
        f'<div style="font-size:0.95rem;font-weight:700;color:{color};">{risk["risk_level"]}</div>'
        f'<div style="font-size:0.75rem;color:{TEXT_DIM};">未来风险预警指数（0-100，越高越危险）</div>'
        f'</div></div>'
    )
    st.markdown(top_html, unsafe_allow_html=True)

    comps = risk["components"]
    c1, c2, c3 = st.columns(3)
    for col, key, label in (
        (c1, "health_trend_risk",   "📈 健康度预测风险"),
        (c2, "threat_trend_risk",   "🛡️ 威胁情报趋势风险"),
        (c3, "content_tamper_risk", "📄 内容篡改频率风险"),
    ):
        comp = comps[key]
        with col:
            st.markdown(
                f'<div style="background:{BG_CHART};border:1px solid {BORDER};border-radius:10px;'
                f'padding:12px 14px;height:100%;">'
                f'<div style="font-size:0.8rem;font-weight:600;color:{TEXT_MAIN};margin-bottom:4px;">{label}</div>'
                f'<div style="font-size:1.3rem;font-weight:700;color:{score_color(100 - comp["risk"])};">'
                f'{comp["risk"]:.0f}</div>'
                f'<div style="font-size:0.72rem;color:{TEXT_DIM};margin-top:4px;line-height:1.5;">{comp["detail"]}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    risk_hist = risk_forecast.get_history(db_path, target, hours=max(hours, 168))
    if not risk_hist.empty and len(risk_hist) >= 2:
        st.plotly_chart(_risk_history_chart(risk_hist), use_container_width=True)
    else:
        st.info("风险指数历史数据积累中，多轮采集后将显示趋势图。")


def render() -> None:
    cfg = Config.get()
    db_path = cfg.db_path

    st.markdown(page_header(
        "时序预测与趋势分析",
        "NeuralProphet 模型短期预测 · 趋势方向判断 · 周期性热力图 · 波动率分析",
        "📈",
    ), unsafe_allow_html=True)

    targets = [t["name"] for t in cfg.targets]
    if not targets:
        st.warning("未配置监测目标，请前往「配置管理」添加。")
        return

    # ── Controls ──────────────────────────────────────────────────────────────
    ctrl1, ctrl2, ctrl3 = st.columns([2, 2, 1])
    with ctrl1:
        target = st.selectbox("监测目标", targets)
    with ctrl2:
        metric_col = st.selectbox(
            "预测指标",
            list(_METRIC_LABELS.keys()),
            format_func=lambda k: _METRIC_LABELS[k][0],
        )
    with ctrl3:
        hours = st.selectbox("历史窗口", [24, 48, 72, 168],
                             format_func=lambda h: f"{h}h")

    label, color = _METRIC_LABELS[metric_col]

    # ── Four-metric overview ───────────────────────────────────────────────────
    with st.expander("📊 六维指标总览", expanded=False):
        st.plotly_chart(_six_metrics_grid(db_path, target, hours),
                        use_container_width=True)

    st.markdown("---")

    # Load up to 30 days of history for better model training
    hist_df = _load_fused(db_path, target, metric_col, 720)
    hs_df   = _load_health(db_path, target, 720)

    # For chart display, also get the user-selected window subset
    display_df = _load_fused(db_path, target, metric_col, hours)

    if hist_df.empty:
        st.info("暂无历史数据，等待采集积累中...")
        return

    # ── Trend stats row ────────────────────────────────────────────────────────
    st.markdown(section_title(f"{label} — 统计摘要"), unsafe_allow_html=True)
    # Use display_df for stats (user-selected window)
    stat_df = display_df if not display_df.empty else hist_df
    trend_label, trend_color = _trend_direction(stat_df[metric_col])
    vol_label, vol_color     = _volatility_label(stat_df[metric_col])
    avg_val  = stat_df[metric_col].mean()
    min_val  = stat_df[metric_col].min()
    max_val  = stat_df[metric_col].max()

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("均值", f"{avg_val:.1f}")
    c2.metric("最小值", f"{min_val:.1f}")
    c3.metric("最大值", f"{max_val:.1f}")
    c4.markdown(
        f'<div style="padding:8px 0;">'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM};">趋势方向</div>'
        f'<div style="font-size:1.1rem;font-weight:700;color:{trend_color};">{trend_label}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    c5.markdown(
        f'<div style="padding:8px 0;">'
        f'<div style="font-size:0.78rem;color:{TEXT_DIM};">波动率</div>'
        f'<div style="font-size:1.1rem;font-weight:700;color:{vol_color};">{vol_label}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Forecast ──────────────────────────────────────────────────────────────
    st.markdown(section_title("时序预测（未来一周）"), unsafe_allow_html=True)

    forecast_days = 7
    refit = cfg.get_setting("prediction", "refit_interval_minutes", default=30)
    actual_pts = len(hist_df)

    fc_df = prophet_model.forecast(
        db_path, target, metric_col,
        forecast_days=forecast_days,
        min_points=2,
        refit_interval_minutes=refit,
    )

    # ── 数据积累进度与模型状态卡片 ────────────────────────────────────────────
    # 阶段：<2点=无法预测, 2-4点=线性外推, >=5点=NeuralProphet（降级到Holt-Winters）
    _STAGES = [
        (2,  "线性趋势外推",    "数据极少，仅能做线性趋势推断，误差范围较大",        C_CRITICAL),
        (5,  "NeuralProphet / Holt-Winters", "数据充足，启用神经网络预测（自动降级到统计平滑）", C_HEALTHY),
    ]
    stage_threshold = [s[0] for s in _STAGES]
    current_stage = 0
    for i, thresh in enumerate(stage_threshold):
        if actual_pts >= thresh:
            current_stage = i

    stage_name, stage_desc, stage_color = _STAGES[current_stage][1], _STAGES[current_stage][2], _STAGES[current_stage][3]
    next_thresh = stage_threshold[current_stage + 1] if current_stage + 1 < len(stage_threshold) else None
    progress_pct = min(actual_pts / stage_threshold[-1] * 100, 100)

    # 积累进度条
    progress_html = (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
        f'border-left:4px solid {stage_color};border-radius:12px;'
        f'padding:16px 20px;margin-bottom:16px;">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
        f'<div>'
        f'<span style="font-size:0.88rem;font-weight:700;color:{stage_color};">📊 当前预测模型：{stage_name}</span>'
        f'<span style="font-size:0.78rem;color:{TEXT_DIM};margin-left:10px;">{stage_desc}</span>'
        f'</div>'
        f'<span style="font-size:0.82rem;font-weight:600;color:{TEXT_MAIN};">'
        f'已积累 <span style="color:{stage_color};">{actual_pts}</span> 个日数据点'
        + (f'，再积累 <span style="color:{C_BLUE};">{next_thresh - actual_pts}</span> 个解锁下一级模型' if next_thresh and actual_pts < next_thresh else '（已达最优模型）')
        + f'</span>'
        f'</div>'
        f'<div style="background:#e2e8f0;border-radius:6px;height:8px;">'
        f'<div style="width:{progress_pct:.1f}%;height:100%;'
        f'background:linear-gradient(90deg,{stage_color},{rgba(stage_color,0.6)});'
        f'border-radius:6px;transition:width 0.4s;"></div>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;'
        f'font-size:0.72rem;color:{TEXT_LIGHT};margin-top:4px;">'
        f'<span>0</span>'
        f'<span style="color:{C_CRITICAL};">线性外推 (2+)</span>'
        f'<span style="color:{C_HEALTHY};">NeuralProphet (5+)</span>'
        f'</div>'
        f'</div>'
    )
    st.markdown(progress_html, unsafe_allow_html=True)

    if fc_df is not None and not fc_df.empty:
        fc_ds_utc = _to_utc_aware(fc_df["ds"])
        future_pts = int((fc_ds_utc > datetime.now(timezone.utc)).sum())
        method = fc_df.attrs.get("method", stage_name)
        train_days = fc_df.attrs.get("train_days", actual_pts)
        st.info(
            f"📊 预测模型：**{method}** · 训练数据 **{train_days}** 天 · "
            f"预测未来 **{future_pts}** 天"
        )
    else:
        st.warning(f"当前数据点数不足（{actual_pts} 个日均值），至少需要 2 个点才能生成预测。请等待采集积累。")

    # Chart uses display_df for the historical portion so zoom level matches selection
    chart_hist = display_df if not display_df.empty else hist_df
    st.plotly_chart(
        _forecast_chart(chart_hist, fc_df, metric_col, label, color),
        use_container_width=True,
    )

    # ── Health score trend + forecast ─────────────────────────────────────────
    if not hs_df.empty:
        st.markdown(section_title("综合健康度趋势与预测"), unsafe_allow_html=True)

        hs_fc = _forecast_health(db_path, target, forecast_days, 3, refit)

        # Display window for health chart matches user selection
        hs_display = _load_health(db_path, target, hours)
        st.plotly_chart(_health_trend_chart(
            hs_display if not hs_display.empty else hs_df, hs_fc),
            use_container_width=True)

    # ── Periodicity heatmap ────────────────────────────────────────────────────
    if not hs_df.empty:
        heatmap_fig = _periodicity_heatmap(hs_df)
        if heatmap_fig:
            st.markdown(section_title("周期性分析"), unsafe_allow_html=True)
            st.plotly_chart(heatmap_fig, use_container_width=True)
            st.caption("颜色越绿表示该时段健康度越高，越红表示越差。可识别高风险时段。")

    # ── 未来风险预警指数 ───────────────────────────────────────────────────────
    st.markdown("---")
    _render_risk_section(db_path, target, hours)