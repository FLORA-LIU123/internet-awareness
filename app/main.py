"""
Streamlit entry point.
Run with: streamlit run app/main.py

"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Import torch first so its DLL search path is registered before any
# downstream library (neuralprophet → pytorch_lightning) tries to load
# c10.dll on Windows. Without this, WinError 1114 occurs because the
# DLL directories are not yet in the loader's search list.
try:
    import torch as _torch  # noqa: F401
    if hasattr(_torch, "_load_dll_libraries"):
        _torch._load_dll_libraries()
except Exception:
    pass

import os

import streamlit as st

from app.styles import GLOBAL_CSS
from scheduler.collector_job import start_scheduler
from src.storage import db
from src.utils.config_loader import Config
from src.utils.logger import setup_logging

st.set_page_config(
    page_title="网络安全态势感知与风险预警平台",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

# ── Simple password gate ────────────────────────────────────────────────────
# 部署到公网服务器时用环境变量 APP_PASSWORD 设置访问密码；未设置则不做校验（本机开发场景）。
_APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
if _APP_PASSWORD and not st.session_state.get("authenticated"):
    st.markdown("### 🔒 请输入访问密码")
    pwd = st.text_input("密码", type="password", label_visibility="collapsed")
    if st.button("登录"):
        if pwd == _APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("密码错误")
    st.stop()


@st.cache_resource
def _init():
    cfg = Config.get()
    setup_logging(
        level=cfg.get_setting("logging", "level", default="INFO"),
        log_file=cfg.get_setting("logging", "file", default="logs/app.log"),
    )
    db.init_db(cfg.db_path)
    start_scheduler()
    return True

_init()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:16px 0 8px 0;">
        <div style="font-size:2.4rem;">🛡️</div>
        <div style="font-size:1.05rem;font-weight:700;color:#60a5fa;letter-spacing:0.5px;">
            网络安全态势感知与风险预警平台
        </div>
        <div style="font-size:0.72rem;color:#8b9dc3;margin-top:4px;line-height:1.5;">
            TLS · 威胁情报 · 流量链路 · 等保合规
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    PAGES = {
        "📊  服务态势总览":   "overview",
        "📡  实时监测与指标": "realtime_metrics",
        "📈  时序预测与趋势": "metrics_trends",
        "🔔  异常预警管理":   "alert_management",
        "💡  数据启示与建议": "insights",
        "📄  安全评估报告":   "security_report",
        "🔍  URL 搜索探测":   "url_search",
        "🔬  高级安全分析":   "advanced_analysis",
        "⚙️  配置管理":       "config_management",
        "🗄️  历史数据查询":   "historical_query",
    }

    selection = st.radio("导航", list(PAGES.keys()), label_visibility="collapsed")
    st.markdown("---")

    cfg = Config.get()
    enabled = [t for t in cfg.targets if t.get("enabled", True)]
    interval = cfg.get_setting("collection", "interval_minutes", default=60)
    st.markdown(
        f'<div style="font-size:0.8rem;color:#57606a;line-height:2.2;">'
        f'<div>📡 监测目标：<span style="color:#60a5fa;font-weight:600;">{len(enabled)} 个</span></div>'
        f'<div>🔄 巡检间隔：<span style="color:#60a5fa;font-weight:600;">每 {interval} 分钟</span></div>'
        f'<div>🕐 页面刷新：<span style="color:#60a5fa;font-weight:600;">30 秒</span></div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    # 安全维度说明
    st.markdown(
        '<div style="font-size:0.72rem;color:#8b9dc3;line-height:1.8;padding:0 4px;">'
        '<div style="font-weight:600;color:#60a5fa;margin-bottom:4px;">🔐 安全监测能力</div>'
        '<div>🔒 TLS/HTTPS 协议安全评估</div>'
        '<div>🛡️ AlienVault OTX 威胁情报</div>'
        '<div>📋 等保合规自查建议</div>'
        '<div>🚨 安全劣化实时告警</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")
    st.caption("数据每分钟自动更新")

    # 仅在总览和实时监测页启用自动刷新，其他页面用户手动操作
    _AUTO_REFRESH_PAGES = {"overview", "realtime_metrics"}
    if PAGES.get(selection) in _AUTO_REFRESH_PAGES:
        auto_refresh = cfg.get_setting("ui", "auto_refresh_seconds", default=30)
        import time
        if "last_refresh" not in st.session_state:
            st.session_state.last_refresh = time.time()
        elapsed = time.time() - st.session_state.last_refresh
        if elapsed >= auto_refresh:
            st.session_state.last_refresh = time.time()
            st.rerun()

# ── Page routing — exec file directly, bypasses sys.modules cache entirely ────
_PAGES_DIR = Path(__file__).resolve().parent / "pages"
_page_file = _PAGES_DIR / f"_{PAGES[selection]}.py"

_page_ns = {"__file__": str(_page_file)}
with open(_page_file, encoding="utf-8") as _f:
    exec(compile(_f.read(), str(_page_file), "exec"), _page_ns)
_page_ns["render"]()