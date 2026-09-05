"""URL 搜索与即时探测页面"""
import ssl
import socket
import time
import requests
from datetime import datetime
from urllib.parse import urlparse

import plotly.graph_objects as go
import streamlit as st

from app.styles import (
    BG_CARD, BORDER, BORDER_MED, TEXT_DIM, TEXT_MAIN, TEXT_LIGHT,
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_TEAL, C_ORANGE,
    rgba, page_header, section_title, chart_layout,
)
from src.utils.config_loader import Config


# ── 探测核心 ──────────────────────────────────────────────────────────────────

def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if raw and not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def _probe_dns(hostname: str, timeout: int = 5) -> float | None:
    try:
        start = time.perf_counter()
        socket.getaddrinfo(hostname, None, socket.AF_INET)
        return (time.perf_counter() - start) * 1000
    except Exception:
        return None


def _probe_ssl(hostname: str, port: int = 443, timeout: int = 5) -> int | None:
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((hostname, port), timeout=timeout)
        with ctx.wrap_socket(conn, server_hostname=hostname) as s:
            cert = s.getpeercert()
        not_after = cert.get("notAfter", "")
        if not_after:
            expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return max(0, (expire_dt - datetime.utcnow()).days)
    except Exception:
        return None


def _probe(url: str, timeout: int) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    result = {
        "url": url,
        "ts": datetime.now(),
        "ok": False,
        "error": None,
        "status_code": None,
        "latency_ms": None,
        "dns_ms": _probe_dns(hostname, timeout),
        "ssl_days": _probe_ssl(hostname, port, timeout) if parsed.scheme == "https" else None,
        "size_kb": None,
        "redirect_url": None,
    }

    try:
        start = time.perf_counter()
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (NetAwarenessPlatform/1.0)"},
            verify=True,
        )
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        result["status_code"] = resp.status_code
        result["size_kb"] = round(len(resp.content) / 1024, 2)
        result["ok"] = resp.status_code < 400
        if resp.url != url:
            result["redirect_url"] = resp.url
        # 尝试从 <title> 标签提取页面名称
        try:
            import re
            ct = resp.headers.get("content-type", "")
            if "html" in ct:
                m = re.search(r"<title[^>]*>([^<]{1,80})</title>", resp.text, re.IGNORECASE)
                result["page_title"] = m.group(1).strip() if m else None
            else:
                result["page_title"] = None
        except Exception:
            result["page_title"] = None
    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL 错误: {e}"
    except requests.exceptions.ConnectionError:
        result["error"] = "连接失败（主机不可达或拒绝连接）"
    except requests.exceptions.Timeout:
        result["error"] = f"请求超时（>{timeout}s）"
    except Exception as e:
        result["error"] = f"未知错误: {e}"

    return result


# ── 辅助渲染 ──────────────────────────────────────────────────────────────────

def _color(val, kind: str) -> str:
    if val is None:
        return TEXT_LIGHT
    if kind == "latency":
        return C_CRITICAL if val > 2000 else (C_WARNING if val > 1000 else C_HEALTHY)
    if kind == "dns":
        return C_CRITICAL if val > 500 else (C_WARNING if val > 200 else C_HEALTHY)
    if kind == "ssl":
        return C_CRITICAL if val < 7 else (C_WARNING if val < 30 else C_HEALTHY)
    if kind == "status":
        return C_CRITICAL if val >= 500 else (C_WARNING if val >= 400 else C_HEALTHY)
    return C_BLUE


def _kpi(label: str, value: str, color: str) -> str:
    return (
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
        f'border-top:3px solid {color};border-radius:12px;padding:16px 18px;">'
        f'<div style="font-size:0.75rem;color:{TEXT_DIM};font-weight:500;margin-bottom:6px;">{label}</div>'
        f'<div style="font-size:1.5rem;font-weight:700;color:{color};line-height:1.1;">{value}</div>'
        f'</div>'
    )


def _render_result(r: dict) -> None:
    st.markdown(section_title("探测结果"), unsafe_allow_html=True)

    url_display = r["url"]
    if r.get("redirect_url"):
        url_display += f' <span style="font-size:0.8rem;color:{TEXT_DIM};">→ {r["redirect_url"]}</span>'
    st.markdown(
        f'<div style="font-size:0.85rem;color:{TEXT_LIGHT};margin-bottom:12px;">'
        f'🔗 {url_display} &nbsp;·&nbsp; 探测时间：{r["ts"].strftime("%Y-%m-%d %H:%M:%S")}'
        f'</div>',
        unsafe_allow_html=True,
    )

    if r["error"] and not r["ok"]:
        dns_line = ""
        if r["dns_ms"] is not None:
            dns_line = f'<div style="color:{TEXT_LIGHT};font-size:0.8rem;margin-top:4px;">DNS 解析耗时：{r["dns_ms"]:.1f} ms</div>'
        st.markdown(
            f'<div style="background:{rgba(C_CRITICAL, 0.08)};border:1px solid {rgba(C_CRITICAL, 0.3)};'
            f'border-left:4px solid {C_CRITICAL};border-radius:8px;padding:14px 18px;">'
            f'<span style="color:{C_CRITICAL};font-weight:600;">❌ 探测失败</span>'
            f'<div style="color:{TEXT_DIM};font-size:0.85rem;margin-top:6px;">{r["error"]}</div>'
            f'{dns_line}'
            f'</div>',
            unsafe_allow_html=True,
        )
        return

    # ── 雷达图：5 维健康评分 ──────────────────────────────────────────────────
    lat   = r["latency_ms"]
    dns   = r["dns_ms"]
    ssl   = r["ssl_days"]
    code  = r["status_code"]

    # 将各维度转换为 0–100 健康分
    def _avail_score() -> float:
        return 100.0 if r["ok"] else 0.0

    def _latency_score() -> float:
        if lat is None:
            return 0.0
        if lat <= 300:
            return 100.0
        if lat <= 1000:
            return round(100 - (lat - 300) / 700 * 40, 1)   # 100→60
        if lat <= 3000:
            return round(60 - (lat - 1000) / 2000 * 50, 1)  # 60→10
        return 10.0

    def _dns_score() -> float:
        if dns is None:
            return 50.0   # 无数据（HTTP）给中性分
        if dns <= 50:
            return 100.0
        if dns <= 200:
            return round(100 - (dns - 50) / 150 * 30, 1)    # 100→70
        if dns <= 500:
            return round(70 - (dns - 200) / 300 * 40, 1)    # 70→30
        return 20.0

    def _ssl_score() -> float:
        if ssl is None:
            return 50.0   # 非 HTTPS 给中性分
        if ssl >= 90:
            return 100.0
        if ssl >= 30:
            return round(60 + (ssl - 30) / 60 * 40, 1)      # 60→100
        if ssl >= 7:
            return round(30 + (ssl - 7) / 23 * 30, 1)       # 30→60
        return max(0.0, round(ssl / 7 * 30, 1))

    def _status_score() -> float:
        if code is None:
            return 0.0
        if code < 400:
            return 100.0
        if code < 500:
            return 40.0
        return 10.0

    scores = [_avail_score(), _latency_score(), _dns_score(), _ssl_score(), _status_score()]
    dims   = ["可用性", "响应延迟", "DNS解析", "SSL安全", "HTTP状态"]

    # 颜色：取5维均值决定整体色
    avg_score = sum(scores) / len(scores)
    radar_color = C_HEALTHY if avg_score >= 80 else (C_WARNING if avg_score >= 50 else C_CRITICAL)

    theta = dims + [dims[0]]   # 闭合多边形
    r_val = scores + [scores[0]]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=r_val, theta=theta,
        fill="toself",
        fillcolor=rgba(radar_color, 0.15),
        line=dict(color=radar_color, width=2),
        marker=dict(size=6, color=radar_color),
        hovertemplate="%{theta}: <b>%{r:.0f}</b><extra></extra>",
    ))
    # 各维度实际值标注
    labels_text = [
        f"{scores[0]:.0f}分<br>{'可达' if r['ok'] else '不可达'}",
        f"{scores[1]:.0f}分<br>{f'{lat:.0f}ms' if lat else '—'}",
        f"{scores[2]:.0f}分<br>{f'{dns:.0f}ms' if dns else 'N/A'}",
        f"{scores[3]:.0f}分<br>{f'{ssl}天' if ssl is not None else 'N/A'}",
        f"{scores[4]:.0f}分<br>{code if code else '—'}",
    ]
    fig.add_trace(go.Scatterpolar(
        r=scores, theta=dims,
        mode="text",
        text=labels_text,
        textfont=dict(size=11, color=TEXT_MAIN),
        hoverinfo="skip",
        showlegend=False,
    ))

    layout = chart_layout(
        title=dict(text=f"综合健康雷达  ·  均分 {avg_score:.0f}", font=dict(size=14)),
        polar=dict(
            bgcolor=BG_CARD,
            radialaxis=dict(
                range=[0, 100], tickfont=dict(size=9), gridcolor=BORDER,
                linecolor=BORDER, ticksuffix="",
            ),
            angularaxis=dict(tickfont=dict(size=12), gridcolor=BORDER, linecolor=BORDER),
        ),
        height=380,
        margin=dict(t=60, b=30, l=60, r=60),
        showlegend=False,
    )
    fig.layout.update(layout)

    col_radar, col_meta = st.columns([3, 2])
    with col_radar:
        st.plotly_chart(fig, use_container_width=True, key="probe_radar")
    with col_meta:
        st.markdown("<br>", unsafe_allow_html=True)
        rows = [
            ("可用性",   f"{'✅ 可达' if r['ok'] else '❌ 不可达'}",        _color(None if not r["ok"] else 1, "status") if not r["ok"] else C_HEALTHY),
            ("响应延迟", f"{lat:.0f} ms" if lat is not None else "—",       _color(lat, "latency")),
            ("DNS 解析", f"{dns:.1f} ms" if dns is not None else "N/A",     _color(dns, "dns")),
            ("SSL 剩余", f"{ssl} 天" if ssl is not None else "N/A",         _color(ssl, "ssl")),
            ("HTTP 状态", str(code) if code is not None else "—",           _color(code, "status")),
        ]
        if r["size_kb"] is not None:
            rows.append(("响应大小", f"{r['size_kb']} KB", TEXT_DIM))
        for label, val, color in rows:
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;align-items:center;'
                f'padding:7px 12px;border-bottom:1px solid {BORDER};">'
                f'<span style="font-size:0.83rem;color:{TEXT_DIM};">{label}</span>'
                f'<span style="font-size:0.9rem;font-weight:700;color:{color};">{val}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # 健康小结
    issues = []
    if lat and lat > 2000:
        issues.append(f"响应延迟过高（{lat:.0f} ms）")
    elif lat and lat > 1000:
        issues.append(f"响应延迟偏高（{lat:.0f} ms）")
    if dns and dns > 500:
        issues.append(f"DNS 解析缓慢（{dns:.1f} ms）")
    if ssl is not None and ssl < 7:
        issues.append(f"SSL 证书即将过期（仅剩 {ssl} 天）")
    elif ssl is not None and ssl < 30:
        issues.append(f"SSL 证书将在 {ssl} 天后到期")
    if code and code >= 500:
        issues.append(f"服务端错误（HTTP {code}）")
    elif code and code >= 400:
        issues.append(f"客户端错误（HTTP {code}）")

    st.markdown("<br>", unsafe_allow_html=True)
    if issues:
        body = "".join(f'<div style="margin-top:4px;">· {i}</div>' for i in issues)
        st.markdown(
            f'<div style="background:{rgba(C_WARNING, 0.08)};border:1px solid {rgba(C_WARNING, 0.3)};'
            f'border-left:4px solid {C_WARNING};border-radius:8px;padding:14px 18px;">'
            f'<span style="color:{C_WARNING};font-weight:600;">⚠ 存在问题</span>'
            f'<div style="color:{TEXT_DIM};font-size:0.85rem;margin-top:6px;">{body}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div style="background:{rgba(C_HEALTHY, 0.08)};border:1px solid {rgba(C_HEALTHY, 0.3)};'
            f'border-left:4px solid {C_HEALTHY};border-radius:8px;padding:12px 18px;">'
            f'<span style="color:{C_HEALTHY};font-weight:600;">✅ 各项指标正常</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # 加入监测
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(section_title("加入监测列表"), unsafe_allow_html=True)
    _render_add_target(r)


def _default_name(r: dict) -> str:
    """生成默认目标名称：优先用 page_title，其次用去掉 www. 的主域名。"""
    title = r.get("page_title")
    if title:
        return title
    parsed = urlparse(r["url"])
    host = parsed.hostname or r["url"]
    return host.removeprefix("www.")


def _save_targets(cfg: "Config", new_targets: list) -> None:
    import yaml
    targets_path = cfg.base_path / "config" / "targets.yaml"
    with open(targets_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data["targets"] = new_targets
    with open(targets_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
    Config._instance = None


def _render_add_target(r: dict) -> None:
    parsed = urlparse(r["url"])
    cfg = Config.get()
    all_targets = cfg._targets  # 含 disabled 的完整列表
    existing_names = {t["name"] for t in all_targets}

    # ── 添加 ──
    with st.form("add_target_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            name = st.text_input("目标名称", value=_default_name(r))
        with c2:
            proto = st.selectbox("类型", ["https", "http"],
                                 index=0 if parsed.scheme != "http" else 1)
        submitted = st.form_submit_button("➕ 添加到监测目标", type="primary")

    if submitted:
        if not name.strip():
            st.error("请填写目标名称")
        elif name.strip() in existing_names:
            st.warning(f"已存在同名目标「{name.strip()}」，请修改名称")
        else:
            all_targets.append({
                "name": name.strip(),
                "url": r["url"],
                "protocol": proto,
                "enabled": True,
            })
            _save_targets(cfg, all_targets)
            st.success(f"✅ 已将「{name.strip()}」添加到监测目标，重启采集器后生效。")
            st.rerun()

    # ── 删除 ──
    if all_targets:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(section_title("删除监测目标"), unsafe_allow_html=True)
        target_names = [t["name"] for t in all_targets]
        with st.form("del_target_form", clear_on_submit=True):
            to_del = st.selectbox("选择要删除的目标", options=target_names)
            del_submitted = st.form_submit_button("🗑️ 删除", type="secondary")
        if del_submitted:
            new_targets = [t for t in all_targets if t["name"] != to_del]
            _save_targets(cfg, new_targets)
            st.success(f"✅ 已删除「{to_del}」")
            st.rerun()


def _render_history() -> None:
    history = st.session_state.get("search_history", [])
    if len(history) <= 1:
        return
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(section_title("本次会话探测历史"), unsafe_allow_html=True)
    rows = []
    for r in history:
        code = r.get("status_code")
        rows.append({
            "URL": r["url"],
            "状态码": str(code) if code else "—",
            "延迟(ms)": f"{r['latency_ms']:.0f}" if r["latency_ms"] is not None else "—",
            "DNS(ms)": f"{r['dns_ms']:.1f}" if r["dns_ms"] is not None else "—",
            "SSL剩余天": str(r["ssl_days"]) if r["ssl_days"] is not None else "—",
            "结果": "✅ 正常" if r["ok"] else "❌ 失败",
            "探测时间": r["ts"].strftime("%H:%M:%S"),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ── 页面入口 ──────────────────────────────────────────────────────────────────

def render() -> None:
    st.markdown(page_header(
        "URL 搜索与即时探测",
        "输入任意网址，立即发起真实探测 · 可用性 · 延迟 · DNS · SSL · 威胁情报",
        "🔍",
    ), unsafe_allow_html=True)

    if "search_history" not in st.session_state:
        st.session_state.search_history = []

    # 输入区
    c_input, c_btn = st.columns([5, 1])
    with c_input:
        raw = st.text_input(
            "目标网址",
            placeholder="例：www.baidu.com 或 https://api.example.com/health",
            label_visibility="collapsed",
        )
    with c_btn:
        go = st.button("🚀 探测", use_container_width=True, type="primary")

    timeout = st.slider("请求超时（秒）", 3, 30, 10, step=1)

    if go and not raw:
        st.warning("请先输入目标网址")
    elif go and raw:
        url = _normalize_url(raw)
        with st.spinner(f"正在探测 {url} …"):
            result = _probe(url, timeout)
        st.session_state.search_history.insert(0, result)
        if len(st.session_state.search_history) > 20:
            st.session_state.search_history = st.session_state.search_history[:20]

    if st.session_state.search_history:
        _render_result(st.session_state.search_history[0])

    _render_history()