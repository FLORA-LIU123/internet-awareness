"""配置管理 — 国家级竞赛标准重写版（含交互式 AHP 判断矩阵）"""
from copy import deepcopy

import numpy as np
import yaml
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE,
    BG_CARD, BORDER, TEXT_DIM, TEXT_MAIN, TEXT_LIGHT,
    rgba, page_header, section_title,
)
from src.utils.config_loader import Config


# ── AHP 工具函数 ──────────────────────────────────────────────────────────────

_DIMS      = ["availability", "response_time", "link_connectivity", "security_risk"]
_DIM_NAMES = ["可用性", "响应时延", "链路连通性", "安全风险"]
_DIM_COLORS = [C_BLUE, C_HEALTHY, C_PURPLE, C_ORANGE]

# 随机一致性指标（Saaty）
_RI = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32}

# Saaty 标度描述
_SAATY_LABELS = {
    1: "同等重要",
    2: "稍偏重要",
    3: "稍微重要",
    4: "较为重要",
    5: "明显重要",
    6: "偏强重要",
    7: "强烈重要",
    8: "很强重要",
    9: "极端重要",
}


def _ahp_from_matrix(matrix: np.ndarray) -> tuple:
    """
    从 n×n 正互反判断矩阵计算权重向量和一致性比率。
    返回 (weights_dict, cr, lambda_max)。
    weights_dict: {dim_key: weight}
    cr: 一致性比率（<0.1 为可接受）
    """
    n = len(matrix)
    col_sums = matrix.sum(axis=0)
    normalised = matrix / col_sums
    priority = normalised.mean(axis=1)

    w = np.array([priority[i] for i in range(n)])
    lambda_max = float((matrix @ w / w).mean())
    ci = (lambda_max - n) / (n - 1)
    ri = _RI.get(n, 1.12)
    cr = ci / ri if ri > 0 else 0.0

    weights = {dim: round(float(priority[i]), 4) for i, dim in enumerate(_DIMS)}
    return weights, round(cr, 4), round(lambda_max, 4)


def _matrix_from_upper(upper_vals: list) -> np.ndarray:
    """从上三角 6 个值重建 4×4 正互反矩阵。"""
    n = 4
    mat = np.ones((n, n), dtype=float)
    idx = 0
    for i in range(n):
        for j in range(i + 1, n):
            v = upper_vals[idx]
            mat[i][j] = v
            mat[j][i] = 1.0 / v
            idx += 1
    return mat


def _load_raw_yaml(rel_path: str) -> dict:
    path = Config.get().base_path / rel_path
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── AHP 矩阵区块 ──────────────────────────────────────────────────────────────

def _render_ahp_section(settings: dict) -> dict:
    """
    渲染交互式 AHP 判断矩阵，返回用户确认后的 weights dict。
    上三角共 C(4,2)=6 个两两比较值。
    """
    st.markdown(section_title("AHP 权重决策矩阵"), unsafe_allow_html=True)
    st.caption(
        "通过两两比较确定各指标权重（Saaty 标度法）。填写每对指标的相对重要程度，"
        "系统自动推导权重并验证一致性（CR < 0.10 为合格）。"
    )

    # 读取 settings.yaml 里保存的判断矩阵值，没有则用默认值
    saved_matrix = settings.get("scoring", {}).get("ahp_matrix", {})

    # 默认判断矩阵（来自 ahp_weights.py 的原始值）
    _DEFAULT_UPPER = {
        "avail_resp": 2.0,   # 可用性 vs 响应时延
        "avail_link": 3.0,   # 可用性 vs 链路连通性
        "avail_sec":  5.0,   # 可用性 vs 安全风险
        "resp_link":  2.0,   # 响应时延 vs 链路连通性
        "resp_sec":   3.0,   # 响应时延 vs 安全风险
        "link_sec":   2.0,   # 链路连通性 vs 安全风险
    }
    keys = list(_DEFAULT_UPPER.keys())
    pairs = [
        ("可用性",     "响应时延"),
        ("可用性",     "链路连通性"),
        ("可用性",     "安全风险"),
        ("响应时延",   "链路连通性"),
        ("响应时延",   "安全风险"),
        ("链路连通性", "安全风险"),
    ]

    # Saaty 标度 selectbox
    saaty_options = list(range(1, 10))
    saaty_format  = lambda v: f"{v} — {_SAATY_LABELS[v]}"

    st.markdown(
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;'
        f'padding:18px 22px;margin-bottom:16px;">'
        f'<div style="font-size:0.8rem;font-weight:700;color:{TEXT_DIM};margin-bottom:12px;">'
        f'▎ 两两重要性比较（行指标 相对于 列指标 的重要程度）</div>',
        unsafe_allow_html=True,
    )

    upper_vals = []
    for i, (key, (left, right)) in enumerate(zip(keys, pairs)):
        saved_v = saved_matrix.get(key, _DEFAULT_UPPER[key])
        saved_i = saaty_options.index(int(round(saved_v))) if int(round(saved_v)) in saaty_options else 0
        col_l, col_mid, col_r = st.columns([3, 4, 3])
        with col_l:
            st.markdown(
                f'<div style="text-align:right;font-size:0.85rem;font-weight:600;'
                f'color:{TEXT_MAIN};padding-top:8px;">{left}</div>',
                unsafe_allow_html=True,
            )
        with col_mid:
            val = st.selectbox(
                f"比较 {i+1}",
                options=saaty_options,
                index=saved_i,
                format_func=saaty_format,
                key=f"ahp_{key}",
                label_visibility="collapsed",
            )
        with col_r:
            st.markdown(
                f'<div style="text-align:left;font-size:0.85rem;color:{TEXT_DIM};padding-top:8px;">'
                f'vs {right}</div>',
                unsafe_allow_html=True,
            )
        upper_vals.append(float(val))

    st.markdown('</div>', unsafe_allow_html=True)

    # 实时计算权重和 CR
    matrix = _matrix_from_upper(upper_vals)
    weights, cr, lambda_max = _ahp_from_matrix(matrix)

    # CR 状态
    if cr < 0.10:
        cr_color = C_HEALTHY
        cr_icon  = "✅"
        cr_label = f"CR = {cr:.4f}（一致性良好，可接受）"
    elif cr < 0.20:
        cr_color = C_WARNING
        cr_icon  = "⚠️"
        cr_label = f"CR = {cr:.4f}（一致性勉强，建议调整判断矩阵）"
    else:
        cr_color = C_CRITICAL
        cr_icon  = "❌"
        cr_label = f"CR = {cr:.4f}（一致性不足，判断矩阵需要修正）"

    # 权重可视化
    bars_html = ""
    for dim_key, name, color in zip(_DIMS, _DIM_NAMES, _DIM_COLORS):
        w_val = weights[dim_key]
        bars_html += (
            f'<div style="margin-bottom:8px;">'
            f'<div style="display:flex;justify-content:space-between;'
            f'font-size:0.78rem;color:{TEXT_DIM};margin-bottom:3px;">'
            f'<span style="font-weight:600;">{name}</span>'
            f'<span style="color:{color};font-weight:700;">{w_val:.4f} '
            f'<span style="color:{TEXT_LIGHT};font-weight:400;">({w_val*100:.1f}%)</span></span>'
            f'</div>'
            f'<div style="background:#e2e8f0;border-radius:5px;height:10px;">'
            f'<div style="width:{w_val*100:.1f}%;height:100%;'
            f'background:linear-gradient(90deg,{color},{rgba(color,0.6)});'
            f'border-radius:5px;transition:width 0.3s;"></div>'
            f'</div></div>'
        )

    st.markdown(
        f'<div style="display:flex;gap:16px;margin-bottom:8px;">'
        # 权重结果卡片
        f'<div style="flex:3;background:{BG_CARD};border:1px solid {BORDER};'
        f'border-radius:12px;padding:16px 20px;">'
        f'<div style="font-size:0.8rem;font-weight:700;color:{TEXT_DIM};margin-bottom:12px;">'
        f'▎ AHP 推导权重（归一化优先级向量）</div>'
        f'{bars_html}'
        f'</div>'
        # 一致性指标卡片
        f'<div style="flex:2;background:{BG_CARD};border:1px solid {BORDER};'
        f'border:2px solid {cr_color};border-radius:12px;padding:16px 20px;">'
        f'<div style="font-size:0.8rem;font-weight:700;color:{TEXT_DIM};margin-bottom:14px;">'
        f'▎ 一致性验证</div>'
        f'<div style="font-size:1.5rem;text-align:center;margin-bottom:8px;">{cr_icon}</div>'
        f'<div style="font-size:0.82rem;font-weight:600;color:{cr_color};'
        f'text-align:center;margin-bottom:12px;">{cr_label}</div>'
        f'<div style="font-size:0.75rem;color:{TEXT_DIM};line-height:1.8;">'
        f'λmax = {lambda_max:.4f}<br>'
        f'n = 4（指标数）<br>'
        f'RI = 0.90（Saaty 随机指标）<br>'
        f'CR = CI / RI，阈值 0.10</div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    return weights, upper_vals, keys, cr


# ── 主渲染函数 ────────────────────────────────────────────────────────────────

def render() -> None:
    cfg = Config.get()

    st.markdown(page_header(
        "配置管理与场景切换",
        "修改监测目标、采集时段、预警阈值和 AHP 权重参数（修改后立即生效）",
        "⚙️",
    ), unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔧  全局设置", "🎯  监测目标管理"])

    with tab1:
        settings = _load_raw_yaml("config/settings.yaml")

        # ── 采集时段 ───────────────────────────────────────────────────────────
        st.markdown(section_title("采集时段"), unsafe_allow_html=True)
        schedule_times = settings.get("collection", {}).get("schedule_times", ["08:00", "12:00", "20:00"])
        st.info(f"当前采集时段：**{' / '.join(schedule_times)}**（每日定时采集）")

        col1, col2 = st.columns(2)
        with col1:
            http_timeout = st.number_input(
                "HTTP 超时时间（秒）", min_value=1, max_value=60,
                value=settings.get("collection", {}).get("http_timeout_seconds", 10),
            )
        with col2:
            icmp_count = st.number_input(
                "ICMP 探测次数", min_value=1, max_value=20,
                value=settings.get("collection", {}).get("icmp_count", 4),
            )

        st.markdown("---")

        # ── 预警阈值 ───────────────────────────────────────────────────────────
        st.markdown(section_title("预警阈值"), unsafe_allow_html=True)
        col3, col4, col5 = st.columns(3)
        with col3:
            health_threshold = st.slider(
                "健康度警戒阈值", 0, 100,
                int(settings.get("rules", {}).get("health_score_threshold", 60)),
            )
        with col4:
            deviation_mult = st.number_input(
                "偏差倍数阈值", min_value=0.5, max_value=10.0, step=0.1,
                value=float(settings.get("rules", {}).get("deviation_multiplier", 2.0)),
            )
        with col5:
            cooldown = st.number_input(
                "告警冷却时间（分钟）", min_value=1, max_value=120,
                value=int(settings.get("rules", {}).get("alert_cooldown_minutes", 10)),
            )

        st.markdown("---")

        # ── AHP 判断矩阵（核心改进） ───────────────────────────────────────────
        weights, upper_vals, upper_keys, cr = _render_ahp_section(settings)

        st.markdown("---")

        # ── 威胁情报 ───────────────────────────────────────────────────────────
        st.markdown(section_title("威胁情报"), unsafe_allow_html=True)
        otx_key = st.text_input(
            "AlienVault OTX API Key",
            value=settings.get("threat_intel", {}).get("otx_api_key", ""),
            type="password",
        )

        st.markdown("---")

        # ── 预测参数 ───────────────────────────────────────────────────────────
        st.markdown(section_title("预测参数"), unsafe_allow_html=True)
        pred = settings.get("prediction", {})
        pc1, pc2, pc3 = st.columns(3)
        with pc1:
            forecast_h = st.number_input(
                "预测时域（小时）", min_value=1, max_value=48,
                value=int(pred.get("forecast_horizon_hours", 6)),
            )
        with pc2:
            min_train = st.number_input(
                "最少训练点数", min_value=2, max_value=200,
                value=int(pred.get("min_training_points", 3)),
            )
        with pc3:
            refit_min = st.number_input(
                "重训间隔（分钟）", min_value=5, max_value=180,
                value=int(pred.get("refit_interval_minutes", 30)),
            )

        st.markdown("---")

        if cr >= 0.10:
            st.error(
                f"⚠️ 当前判断矩阵一致性比率 CR = {cr:.4f} ≥ 0.10，"
                "建议先调整判断矩阵使 CR < 0.10，再保存设置。"
            )

        if st.button("💾  保存全局设置", type="primary", disabled=(cr >= 0.20)):
            new_settings = deepcopy(settings)
            new_settings.setdefault("collection", {})
            new_settings["collection"]["schedule_times"]       = schedule_times
            new_settings["collection"]["http_timeout_seconds"] = http_timeout
            new_settings["collection"]["icmp_count"]           = icmp_count
            new_settings.setdefault("rules", {})
            new_settings["rules"]["health_score_threshold"] = health_threshold
            new_settings["rules"]["deviation_multiplier"]   = deviation_mult
            new_settings["rules"]["alert_cooldown_minutes"] = cooldown
            # 保存 AHP 推导权重（归一化后）
            new_settings.setdefault("scoring", {})["weights"] = weights
            # 同时持久化判断矩阵原始值，下次打开页面可回显
            new_settings["scoring"]["ahp_matrix"] = {
                k: v for k, v in zip(upper_keys, upper_vals)
            }
            new_settings.setdefault("threat_intel", {})["otx_api_key"] = otx_key
            new_settings.setdefault("prediction", {})
            new_settings["prediction"]["forecast_horizon_hours"]  = forecast_h
            new_settings["prediction"]["min_training_points"]     = min_train
            new_settings["prediction"]["refit_interval_minutes"]  = refit_min
            cfg.save_settings(new_settings)
            Config._instance = None
            st.success(
                f"✅ 设置已保存。AHP 权重：可用性 {weights['availability']:.4f}，"
                f"响应时延 {weights['response_time']:.4f}，"
                f"链路连通性 {weights['link_connectivity']:.4f}，"
                f"安全风险 {weights['security_risk']:.4f}（CR = {cr:.4f}）"
            )
            st.rerun()

    with tab2:
        targets_data = _load_raw_yaml("config/targets.yaml")
        targets = targets_data.get("targets", [])

        st.markdown(section_title(f"当前监测目标（共 {len(targets)} 个）"), unsafe_allow_html=True)
        for i, t in enumerate(targets):
            enabled = t.get("enabled", True)
            with st.expander(f"{'✅' if enabled else '❌'}  {t['name']}  ·  {t.get('url', '')}"):
                col1, col2 = st.columns(2)
                with col1:
                    targets[i]["name"] = st.text_input("服务名称", t["name"], key=f"name_{i}")
                    targets[i]["url"]  = st.text_input("URL",      t.get("url", ""), key=f"url_{i}")
                with col2:
                    targets[i]["ip"]   = st.text_input("IP 地址",  t.get("ip", ""), key=f"ip_{i}")
                    targets[i]["type"] = st.selectbox(
                        "探测类型", ["both", "http", "icmp"],
                        index=["both", "http", "icmp"].index(t.get("type", "both")),
                        key=f"type_{i}",
                    )
                targets[i]["enabled"] = st.checkbox("启用此目标", t.get("enabled", True), key=f"en_{i}")
                tags = t.get("tags", [])
                if tags:
                    tag_html = "".join(
                        f'<span style="background:#ddf4ff;border:1px solid #54aeff40;'
                        f'color:{C_BLUE};font-size:0.72rem;padding:2px 8px;'
                        f'border-radius:10px;margin-right:4px;">{tag}</span>'
                        for tag in tags
                    )
                    st.markdown(f'<div style="margin-top:4px;">{tag_html}</div>',
                                unsafe_allow_html=True)

                st.markdown("---")
                if st.button("🗑️ 删除此目标", key=f"del_{i}", type="secondary"):
                    del_name = t["name"]
                    targets.pop(i)
                    cfg.save_targets(targets)
                    # 同步清除数据库中该目标的所有历史记录
                    from src.storage import db as _db
                    for tbl in ("health_scores", "fused_metrics", "alerts",
                                "raw_metrics", "content_snapshots", "risk_forecasts"):
                        try:
                            _db.execute(cfg.db_path,
                                        f"DELETE FROM {tbl} WHERE target_name=?",
                                        (del_name,))
                        except Exception:
                            pass
                    Config._instance = None
                    st.success(f"✅ 已删除「{del_name}」及其全部历史数据")
                    st.rerun()

        # ── 孤立目标清理（数据库有但 targets.yaml 没有的） ─────────────────────
        from src.storage import db as _db
        db_names_df = _db.query_df(cfg.db_path,
                                   "SELECT DISTINCT target_name FROM health_scores")
        if not db_names_df.empty:
            yaml_names = {t["name"] for t in targets}
            orphans = [n for n in db_names_df["target_name"].tolist() if n not in yaml_names]
            if orphans:
                st.markdown("---")
                st.markdown(section_title("清理孤立目标"), unsafe_allow_html=True)
                st.caption("以下目标在数据库中有历史记录，但已不在 targets.yaml 里，会导致首页出现多余卡片。")
                with st.form("del_orphans_form"):
                    to_del = st.multiselect("选择要清除的孤立目标", orphans, default=orphans)
                    del_submitted = st.form_submit_button("🗑️ 清除所选孤立目标", type="primary")
                if del_submitted and to_del:
                    for name in to_del:
                        for tbl in ("health_scores", "fused_metrics", "alerts",
                                    "raw_metrics", "content_snapshots", "risk_forecasts"):
                            try:
                                _db.execute(cfg.db_path,
                                            f"DELETE FROM {tbl} WHERE target_name=?",
                                            (name,))
                            except Exception:
                                pass
                    st.success(f"✅ 已清除：{'、'.join(to_del)}")
                    st.rerun()

        st.markdown("---")
        st.markdown(section_title("添加新监测目标"), unsafe_allow_html=True)
        with st.form("add_target"):
            nc1, nc2 = st.columns(2)
            with nc1:
                new_name = st.text_input("服务名称 *")
                new_url  = st.text_input("URL")
            with nc2:
                new_ip   = st.text_input("IP 地址")
                new_type = st.selectbox("探测类型", ["both", "http", "icmp"])
            new_tags = st.text_input("标签（逗号分隔，可选）", placeholder="例：government, portal")
            submitted = st.form_submit_button("➕  添加目标", type="primary")
            if submitted and new_name:
                tag_list = [tg.strip() for tg in new_tags.split(",") if tg.strip()] if new_tags else []
                targets.append({
                    "name": new_name, "url": new_url, "ip": new_ip,
                    "type": new_type, "enabled": True, "tags": tag_list,
                })
                cfg.save_targets(targets)
                Config._instance = None
                st.success(f"✅ 已添加目标：{new_name}")
                st.rerun()

        if st.button("💾  保存目标配置", type="primary"):
            cfg.save_targets(targets)
            Config._instance = None
            st.success("✅ 目标配置已保存。")