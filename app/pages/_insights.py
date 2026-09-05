from datetime import datetime, timedelta, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.styles import (
    C_HEALTHY, C_WARNING, C_CRITICAL, C_BLUE, C_PURPLE, C_ORANGE, C_TEAL,
    BG_CARD, BG_CHART, BORDER, TEXT_DIM, TEXT_MAIN,
    rgba, chart_layout,
)
from src.storage import db
from src.utils.config_loader import Config
from src.analysis import root_cause, compliance, asset_graph

# 攻击链阶段颜色（与 root_cause.STAGE_ORDER 对应）
_STAGE_COLOR = {
    "侦察特征": C_BLUE,
    "弱点暴露": C_ORANGE,
    "异常行为": C_WARNING,
    "疑似失陷": C_CRITICAL,
    "其他事件": TEXT_DIM,
}
_SEVERITY_MARKER = {"critical": 14, "warning": 10, "info": 8}


# TLS 安全响应头中文名映射
_HDR_LABELS = {
    "hsts":                  ("Strict-Transport-Security (HSTS)",  "防止 SSL Stripping 降级攻击，浏览器强制使用 HTTPS"),
    "csp":                   ("Content-Security-Policy (CSP)",      "限制页面可加载的资源来源，防止 XSS 跨站脚本攻击"),
    "x_frame_options":       ("X-Frame-Options",                    "禁止页面被嵌入 iframe，防止点击劫持攻击"),
    "x_content_type_options":("X-Content-Type-Options",             "禁止浏览器 MIME 类型嗅探，防止内容类型混淆攻击"),
    "referrer_policy":       ("Referrer-Policy",                    "控制 HTTP Referer 信息泄露范围"),
    "permissions_policy":    ("Permissions-Policy",                  "限制页面可使用的浏览器 API（摄像头/麦克风等）"),
}


def _load_tls_detail(db_path: str, target_name: str) -> dict:
    """从 raw_metrics 读取最新一次采集的 TLS 子项数据，返回结构化字典。"""
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


def _load_health_history(db_path, hours):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(db_path,
        "SELECT target_name, score, scored_at FROM health_scores WHERE scored_at >= ? ORDER BY scored_at ASC",
        (since,))
    if not df.empty:
        df["scored_at"] = pd.to_datetime(df["scored_at"], utc=True, errors="coerce")
    return df

def _load_fused_history(db_path, hours):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(db_path,
        "SELECT target_name, availability_score, response_time_score, link_score, security_score, fused_at FROM fused_metrics WHERE fused_at >= ? ORDER BY fused_at ASC",
        (since,))
    if not df.empty:
        df["fused_at"] = pd.to_datetime(df["fused_at"], utc=True, errors="coerce")
    return df

def _load_alerts_history(db_path, hours):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    return db.query_df(db_path,
        "SELECT target_name, severity, rule_type, created_at FROM alerts WHERE created_at >= ? ORDER BY created_at ASC",
        (since,))


def _insight_card(icon, title, problem, solutions, color=C_BLUE):
    sol_html = "".join(
        f'<li style="margin-bottom:7px;line-height:1.7;">{s}</li>' for s in solutions
    )
    st.markdown(
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};'
        f'border-left:5px solid {color};border-radius:12px;'
        f'padding:18px 22px 14px 22px;margin-bottom:14px;'
        f'box-shadow:0 2px 6px rgba(31,35,40,0.07);">'
        # 标题行
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">'
        f'<span style="font-size:1.1rem;">{icon}</span>'
        f'<span style="font-size:0.97rem;font-weight:700;color:{TEXT_MAIN};">{title}</span>'
        f'</div>'
        # 问题描述
        f'<div style="font-size:0.84rem;color:{TEXT_DIM};line-height:1.7;'
        f'padding:8px 12px;background:{rgba(color,0.06)};border-radius:6px;margin-bottom:12px;">'
        f'<span style="font-weight:600;color:{color};">现状：</span>{problem}</div>'
        # 解决方案
        f'<div style="background:{BG_CHART};border:1px solid {BORDER};border-radius:8px;padding:12px 16px;">'
        f'<div style="font-size:0.8rem;font-weight:700;color:{color};margin-bottom:8px;'
        f'letter-spacing:0.3px;">▎ 运维建议</div>'
        f'<ol style="margin:0;padding-left:20px;font-size:0.83rem;color:{TEXT_MAIN};line-height:1.8;">'
        f'{sol_html}'
        f'</ol></div></div>',
        unsafe_allow_html=True,
    )


# ── Org-type metadata ─────────────────────────────────────────────────────────
_ORG_TYPE_MAP = {
    "university":  {"icon": "🎓", "label": "高校门户"},
    "government":  {"icon": "🏛️", "label": "政府门户"},
    "enterprise":  {"icon": "🏢", "label": "企业官网"},
    "finance":     {"icon": "🏦", "label": "金融机构"},
    "healthcare":  {"icon": "🏥", "label": "医疗卫生"},
    "isp":         {"icon": "📡", "label": "互联网服务商"},
}

# Priority order when a target carries multiple type tags
_TYPE_TAG_PRIORITY = ["university", "government", "finance", "healthcare", "isp", "enterprise"]

# Per-org-type sensible defaults when context field is absent
_ORG_DEFAULTS = {
    "university": {
        "peak": "工作日 8:00–9:00、14:00–15:00（上课高峰）及 19:00–22:00（晚自习）",
        "admin": "校园网络信息中心",
        "compliance": "教育部等保 2.0 三级要求",
        "users": "全校师生",
        "risk_note": "高校 IP 段常被扫描，需重点防范 Web 漏洞和 DDoS",
    },
    "government": {
        "peak": "工作日 9:00–11:30、14:00–17:00（政务办理高峰）",
        "admin": "政务信息化主管部门",
        "compliance": "等保 2.0 三级及以上、政务外网安全规范",
        "users": "公众及政务人员",
        "risk_note": "政府网站是高价值攻击目标，需严格防范篡改、钓鱼和数据泄露",
    },
    "enterprise": {
        "peak": "全天候，流量分布较均匀，节假日可能有波动",
        "admin": "企业 SRE / 运维团队",
        "compliance": "企业内部 SLA 标准（通常 99.9% 以上可用性）",
        "users": "全球访客及合作伙伴",
        "risk_note": "企业官网代表品牌形象，可用性和安全性直接影响商业信誉",
    },
    "finance": {
        "peak": "工作日 9:00–11:00、14:00–16:00（交易高峰），月末结算日流量激增",
        "admin": "金融科技 / 运维合规团队",
        "compliance": "PCI-DSS、等保 2.0 三级、央行科技风险管理办法",
        "users": "金融消费者及机构客户",
        "risk_note": "金融系统是高价值攻击目标，须重点防范资金欺诈、数据泄露和系统中断",
    },
    "healthcare": {
        "peak": "工作日 8:00–12:00（挂号高峰）、节假日前后流量骤增",
        "admin": "医院信息化部门 / 卫生健康委",
        "compliance": "等保 2.0 三级、医疗数据安全管理规范、个人信息保护法",
        "users": "患者、医疗人员及医保部门",
        "risk_note": "医疗数据高度敏感，须防范勒索软件攻击和患者隐私泄露",
    },
    "isp": {
        "peak": "20:00–23:00（晚间消费高峰），重大赛事/直播期间流量突发",
        "admin": "网络运维中心（NOC）",
        "compliance": "工信部互联网信息服务安全规范、等保 2.0",
        "users": "宽带/移动互联网用户（百万量级）",
        "risk_note": "基础设施目标，需重点防范 DDoS 攻击和 BGP 路由劫持",
    },
}


def _resolve_target_context(target_name: str) -> dict:
    """
    Dynamically resolve display context for a target by reading Config.get().targets.

    Returns a dict with keys: type, icon, label, peak, admin, compliance, users, risk_note.
    """
    targets = Config.get().targets
    target_cfg = next((t for t in targets if t.get("name") == target_name), None)

    # Determine org_type from tags using priority ordering
    org_type = "enterprise"
    if target_cfg:
        tags = target_cfg.get("tags") or []
        for candidate in _TYPE_TAG_PRIORITY:
            if candidate in tags:
                org_type = candidate
                break

    type_meta = _ORG_TYPE_MAP.get(org_type, _ORG_TYPE_MAP["enterprise"])
    defaults = _ORG_DEFAULTS.get(org_type, _ORG_DEFAULTS["enterprise"])

    # Merge with any per-target context overrides from yaml
    context_override = {}
    if target_cfg:
        context_override = target_cfg.get("context") or {}

    return {
        "type": org_type,
        "icon": type_meta["icon"],
        "label": type_meta["label"],
        "peak": context_override.get("peak", defaults["peak"]),
        "admin": context_override.get("admin", defaults["admin"]),
        "compliance": context_override.get("compliance", defaults["compliance"]),
        "users": context_override.get("users", defaults["users"]),
        "risk_note": context_override.get("risk_note", defaults["risk_note"]),
    }


def _render_target_overview() -> None:
    """Render an info card listing every enabled target with its tags and inferred org type."""
    targets = Config.get().targets
    if not targets:
        return

    rows_html = ""
    for t in targets:
        tags = t.get("tags") or []
        org_type = "enterprise"
        for candidate in _TYPE_TAG_PRIORITY:
            if candidate in tags:
                org_type = candidate
                break
        type_meta = _ORG_TYPE_MAP.get(org_type, _ORG_TYPE_MAP["enterprise"])
        tags_html = "".join(
            f'<span style="background:{rgba(C_BLUE, 0.10)};border:1px solid {rgba(C_BLUE, 0.25)};'
            f'color:{C_BLUE};font-size:0.7rem;font-weight:600;padding:2px 8px;border-radius:12px;'
            f'margin-right:4px;">{tag}</span>'
            for tag in tags
        )
        rows_html += (
            f'<div style="display:flex;align-items:center;gap:12px;padding:10px 14px;'
            f'border-bottom:1px solid {BORDER};flex-wrap:wrap;">'
            f'<span style="font-size:1.2rem;">{type_meta["icon"]}</span>'
            f'<span style="font-size:0.9rem;font-weight:600;color:{TEXT_MAIN};min-width:160px;">'
            f'{t.get("name","")}</span>'
            f'<span style="font-size:0.78rem;color:{TEXT_DIM};min-width:90px;">'
            f'{type_meta["label"]}</span>'
            f'<div>{tags_html}</div>'
            f'</div>'
        )

    st.markdown(
        f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;'
        f'overflow:hidden;box-shadow:0 2px 6px rgba(31,35,40,0.06);margin-bottom:20px;">'
        f'<div style="padding:12px 16px;background:{rgba(C_BLUE,0.06)};border-bottom:1px solid {BORDER};">'
        f'<span style="font-size:0.85rem;font-weight:700;color:{C_BLUE};">🎯 当前监测目标概况</span>'
        f'<span style="font-size:0.75rem;color:{TEXT_DIM};margin-left:10px;">'
        f'系统动态识别机构类型，自动生成针对性运维建议</span>'
        f'</div>'
        f'{rows_html}'
        f'</div>',
        unsafe_allow_html=True,
    )


def _generate_insights(health_df, fused_df, alerts_df):
    insights = []
    if health_df.empty:
        return insights

    latest = health_df.sort_values("scored_at").groupby("target_name").last().reset_index()

    # 按每个监测目标单独生成针对性建议
    for _, row in latest.iterrows():
        name  = row["target_name"]
        score = float(row["score"])

        # 获取融合指标
        fused_row = {}
        if not fused_df.empty:
            sub = fused_df[fused_df["target_name"] == name]
            if not sub.empty:
                fused_row = sub.sort_values("fused_at").iloc[-1].to_dict()

        avail = float(fused_row.get("availability_score") or 0)
        resp  = float(fused_row.get("response_time_score") or 0)
        link  = float(fused_row.get("link_score") or 0)
        sec   = float(fused_row.get("security_score") or 0)

        # 动态从 Config 读取目标上下文，无需硬编码字典
        ctx = _resolve_target_context(name)
        org_type = ctx["type"]

        # 确定状态描述和卡片颜色
        if score >= 80:
            status_desc = f"运行健康（{score:.1f} 分）"
            color = C_HEALTHY
            icon  = "✅"
        elif score >= 60:
            status_desc = f"性能预警（{score:.1f} 分）"
            color = C_WARNING
            icon  = "⚠️"
        else:
            status_desc = f"严重异常（{score:.1f} 分）"
            color = C_CRITICAL
            icon  = "🔴"

        # 识别薄弱项
        weak = []
        if avail < 60: weak.append("可用性")
        if resp  < 60: weak.append("响应时延")
        if link  < 70: weak.append("链路连通性")
        if sec   < 70: weak.append("安全风险")

        # 构建 problem 描述
        if weak:
            weak_str = "、".join(weak)
            problem = (
                f"当前健康度 {score:.1f} 分，薄弱项：{weak_str}。"
                f"峰值时段为{ctx['peak']}，{ctx['risk_note']}。"
            )
        else:
            problem = (
                f"当前健康度 {score:.1f} 分，各项指标基本正常。"
                f"峰值时段为{ctx['peak']}，建议持续关注并做好预防性维护。"
            )

        # 按机构类型生成深度运维建议
        solutions = []

        if org_type == "university":
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】服务可用性严重不足</strong><br>"
                    f"① 立即联系<strong>{ctx['admin']}</strong>启动应急响应，确认 Web 服务进程（Nginx/Tomcat）是否存活；<br>"
                    "② 检查服务器 CPU/内存/磁盘 I/O 是否达到瓶颈（<code>top</code>、<code>iostat -x 1</code>）；<br>"
                    "③ 排查是否因选课系统、教务系统等并发请求激增导致连接池耗尽；<br>"
                    "④ 若为硬件故障，立即切换至灾备服务器，同时通知师生通过备用域名访问"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】可用性存在下滑趋势</strong><br>"
                    f"① 联系<strong>{ctx['admin']}</strong>获取近期网络变更记录，排查是否因配置调整引入问题；<br>"
                    "② 在下一个寒暑假低峰期安排全链路压力测试（建议使用 JMeter 模拟 5000+ 并发）；<br>"
                    "③ 评估当前服务器集群是否满足开学季峰值需求，提前规划扩容方案"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】响应时延严重超标</strong><br>"
                    "① 使用 <code>curl -o /dev/null -w '%{time_total}' URL</code> 定位延迟瓶颈（DNS/TCP/TTFB/传输）；<br>"
                    "② 分析是否在上课高峰期（8:00–9:00、14:00–15:00）出现规律性延迟，绘制 24h 延迟热力图；<br>"
                    "③ 检查数据库慢查询（<code>SHOW PROCESSLIST</code>），优化高频 SQL 并添加索引；<br>"
                    "④ 部署校内 CDN 缓存节点（如 Nginx 反向代理 + 静态资源缓存），减少 CERNET 出口压力；<br>"
                    "⑤ 启用 HTTP/2 和 Gzip/Brotli 压缩，减少页面传输体积"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】响应时延波动需关注</strong><br>"
                    "① 建立 24h 响应时延基线，重点监控上课高峰期（8–9点、14–15点）的 P95/P99 延迟；<br>"
                    "② 评估校内 CDN 缓存节点部署方案，将静态资源（JS/CSS/图片）缓存至校内节点；<br>"
                    "③ 检查 DNS 解析时间，考虑将校内 DNS 缓存 TTL 适当延长以减少解析开销"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全加固】威胁情报显示风险偏高</strong><br>"
                    f"① 按<strong>{ctx['compliance']}</strong>开展安全自查，重点检查 Web 应用漏洞（SQL 注入、XSS、文件上传）；<br>"
                    "② 联系 CERNET 安全应急响应中心（CCERT）报告异常 IP 活动；<br>"
                    "③ 审计学生/教师账号系统，强制弱密码用户修改密码，启用登录失败锁定策略；<br>"
                    "④ 部署 Web 应用防火墙（WAF），配置 OWASP Top 10 防护规则集；<br>"
                    "⑤ 检查 SSL/TLS 配置（<code>ssllabs.com</code> 评级应达到 A 级），禁用 TLS 1.0/1.1"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络诊断】链路连通性不稳定</strong><br>"
                    "① 执行持续 MTR 测试（<code>mtr -rwc 100 目标IP</code>），定位丢包发生的具体跳数；<br>"
                    "② 向校园网管理部门提交工单，附上 MTR 报告，请求排查 CERNET 出口路由；<br>"
                    "③ 检查是否存在 P2P 下载或大流量应用占用出口带宽（可通过 NetFlow 分析）；<br>"
                    "④ 评估是否需要申请 CERNET 带宽扩容或增加商业 ISP 出口作为备份链路"
                )
            solutions.append(
                "<strong>【长期规划】持续改进建议</strong><br>"
                "① 建立门户网站 SLA 目标（建议可用性 ≥ 99.5%、响应时间 P95 ≤ 2s）；<br>"
                "② 在寒暑假低峰期集中进行系统升级、安全补丁更新和架构优化；<br>"
                "③ 将教务系统、图书馆系统、一卡通系统等关键内部服务纳入统一监测体系；<br>"
                "④ 制定《校园网站应急响应预案》，明确故障分级、响应时限和责任人；<br>"
                "⑤ 每学期初开展一次全链路演练，验证灾备切换和应急通知流程的有效性"
            )

        elif org_type == "government":
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】政务服务可用性严重不足</strong><br>"
                    f"① 立即上报<strong>{ctx['admin']}</strong>，按《政务网站应急预案》启动 II 级响应；<br>"
                    "② 确认政务云平台资源状态，检查虚拟机/容器是否正常运行；<br>"
                    "③ 若主站不可用，立即启用备用站点并通过政务微信公众号发布临时访问通知；<br>"
                    "④ 同步通知省政务服务中心，评估对网上办事大厅、政务 APP 的影响范围"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】可用性存在下滑风险</strong><br>"
                    f"① 向<strong>{ctx['admin']}</strong>报告监测异常，请求排查政务云平台资源利用率；<br>"
                    "② 在政务办理高峰期（9:00–11:30、14:00–17:00）前完成容量评估；<br>"
                    "③ 检查近期是否有政策发布、公示公告等可能引发流量激增的事件，提前做好扩容准备"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】响应时延影响政务办理效率</strong><br>"
                    "① 分析政务应用后端接口响应时间，定位慢接口（建议使用 APM 工具如 SkyWalking）；<br>"
                    "② 优化政务数据库查询：检查是否存在全表扫描、缺失索引或锁等待问题；<br>"
                    "③ 评估政务云弹性扩容方案，在办事高峰期自动扩展计算资源；<br>"
                    "④ 对静态页面（政策文件、公告）启用页面缓存，减少动态渲染开销；<br>"
                    "⑤ 检查政务外网带宽是否满足当前访问量，必要时申请带宽升级"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】响应时延需持续关注</strong><br>"
                    "① 建立政务网站性能基线，重点监控办事高峰期的 P95 响应时间；<br>"
                    "② 分析页面加载瀑布图，优化首屏渲染关键路径（减少阻塞资源、启用预加载）；<br>"
                    "③ 评估是否需要将高频访问的政策文件、办事指南等内容迁移至 CDN 加速"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全合规】安全评分不满足等保要求</strong><br>"
                    f"① 按<strong>{ctx['compliance']}</strong>立即开展安全自查，重点检查身份认证和访问控制；<br>"
                    "② 向省网信办报告威胁情报异常，配合开展安全排查；<br>"
                    "③ 检查网页完整性监测系统是否正常运行，防范网页篡改和暗链植入；<br>"
                    "④ 审计管理员账号权限，实施最小权限原则，启用双因素认证（2FA）；<br>"
                    "⑤ 开展渗透测试，重点关注政务数据接口是否存在未授权访问风险；<br>"
                    "⑥ 检查数据传输加密（全站 HTTPS）和敏感数据存储加密是否符合《数据安全法》要求"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络保障】政务外网链路质量不达标</strong><br>"
                    "① 联系政务外网运营商提交链路质量报告，要求 48h 内给出排查结论；<br>"
                    "② 评估是否需要双运营商接入（电信 + 联通/移动），实现链路冗余；<br>"
                    "③ 检查政务外网防火墙策略是否过于严格导致正常流量被误拦截；<br>"
                    "④ 若为跨省访问延迟，评估是否需要在省内部署就近接入节点"
                )
            solutions.append(
                "<strong>【长期规划】合规与持续改进</strong><br>"
                f"① 每年至少开展一次等保测评（{ctx['compliance']}），确保持续合规；<br>"
                "② 制定并演练《政务网站网络安全事件应急预案》，明确 I/II/III 级响应流程；<br>"
                "③ 建立 7×24h 值班监控机制，确保重大政务活动期间（两会、国庆等）零故障；<br>"
                "④ 定期开展政务网站无障碍访问测试，确保符合《信息无障碍》国家标准；<br>"
                "⑤ 建立政务网站性能月报制度，向主管领导汇报运行态势和改进计划"
            )

        elif org_type == "finance":
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】金融服务可用性严重中断</strong><br>"
                    f"① 立即启动<strong>{ctx['admin']}</strong>金融科技应急响应流程，上报监管机构（若要求）；<br>"
                    "② 确认核心交易系统（支付/清算/账务）是否受影响，优先保障交易连续性；<br>"
                    "③ 启用灾备数据中心或同城双活节点，执行 RTO ≤ 4h 的恢复目标；<br>"
                    "④ 通知客服团队准备用户公告，避免引发客户恐慌或舆情危机"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】可用性存在下滑风险</strong><br>"
                    f"① 向<strong>{ctx['admin']}</strong>报告监测异常，评估是否触发内部重大事件升级条件；<br>"
                    f"② 在{ctx['peak']}前完成容量评估，避免交易高峰期出现拥堵；<br>"
                    "③ 检查限流熔断策略是否配置合理，防止单点故障级联扩散"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】交易响应时延超标</strong><br>"
                    "① 检查核心交易链路（接入层→业务层→数据层）各节点响应时间分布；<br>"
                    "② 分析数据库连接池使用率和锁等待情况，优化热点账户读写路径；<br>"
                    "③ 对查询类接口（余额查询/历史账单）启用 Redis 缓存，降低 DB 压力；<br>"
                    "④ 评估分布式事务链路是否引入额外延迟，考虑引入 Saga/TCC 模式优化；<br>"
                    "⑤ 检查 TLS 握手时间，确认证书链完整、OCSP Stapling 已启用"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】响应时延波动需关注</strong><br>"
                    "① 建立交易响应时延 SLA 基线（P99 ≤ 500ms），设置自动告警；<br>"
                    "② 分析月末结算日流量模式，提前预置弹性扩容策略；<br>"
                    "③ 审查消息队列积压情况，防止异步链路延迟累积影响用户体验"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全合规】安全评分不满足金融监管要求</strong><br>"
                    f"① 按<strong>{ctx['compliance']}</strong>立即开展安全自查，重点审查支付接口和身份认证模块；<br>"
                    "② 检查反欺诈系统规则是否覆盖最新攻击手法（账户接管/羊毛党/深伪欺诈）；<br>"
                    "③ 审计 API 鉴权机制，确认所有资金相关接口均强制双因素认证；<br>"
                    "④ 检查敏感数据（卡号/账号/姓名）是否全链路加密存储和传输；<br>"
                    "⑤ 联系专业安全机构开展渗透测试，重点覆盖 OWASP Top 10 金融专项场景"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络保障】金融专线链路质量异常</strong><br>"
                    "① 立即联系金融专线运营商，提交 SLA 违规工单，要求 4h 内响应；<br>"
                    "② 检查跨行清算专线（人民银行大小额系统）是否正常；<br>"
                    "③ 评估是否需要增加备用专线或 SD-WAN 智能选路方案，降低单链路依赖风险；<br>"
                    "④ 检查防火墙 QoS 策略，确保交易报文优先级高于普通流量"
                )
            solutions.append(
                "<strong>【长期规划】金融科技韧性建设</strong><br>"
                f"① 每年按<strong>{ctx['compliance']}</strong>完成合规审计，并提交监管报告；<br>"
                "② 建立同城双活 + 异地灾备的三中心架构，确保 RPO ≤ 15min、RTO ≤ 4h；<br>"
                "③ 实施金融级 CI/CD 流程（含自动化回归、灰度发布、一键回滚）；<br>"
                "④ 定期开展红蓝对抗演练（攻防演练），验证安全防护体系的实战有效性；<br>"
                "⑤ 建立用户行为基线模型，实时检测异常登录和资金异动"
            )

        elif org_type == "healthcare":
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】医疗信息系统可用性中断</strong><br>"
                    f"① 立即通知<strong>{ctx['admin']}</strong>启动医疗 IT 应急响应，评估对挂号、HIS、EMR 系统的影响；<br>"
                    "② 启用离线应急预案（纸质挂号/手工医嘱），确保诊疗活动不中断；<br>"
                    "③ 检查服务器机房 UPS 电源和网络设备运行状态；<br>"
                    "④ 若为勒索软件攻击，立即隔离受感染主机，启动备份恢复流程"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】可用性存在下滑风险</strong><br>"
                    f"① 向<strong>{ctx['admin']}</strong>报告异常，在{ctx['peak']}前完成系统健康检查；<br>"
                    "② 检查 HIS/EMR 数据库连接数和磁盘使用率，提前扩容避免满载；<br>"
                    "③ 验证灾备系统数据同步状态，确保备份数据不超过 4h 时效"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】医疗系统响应迟缓影响诊疗效率</strong><br>"
                    "① 分析 HIS/EMR 慢查询（影像调取/电子病历检索），优化数据库索引；<br>"
                    "② 对影像系统（PACS）部署本地缓存节点，减少远程调取延迟；<br>"
                    "③ 检查内网核心交换机带宽利用率，识别是否存在广播风暴或环路；<br>"
                    "④ 评估挂号/取药高峰期的并发承载能力，部署应用层负载均衡；<br>"
                    "⑤ 检查 VPN/专线到医保结算平台的链路质量，保障实时结算不超时"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】响应时延波动需关注</strong><br>"
                    "① 建立诊疗关键链路（挂号→就诊→取药）端到端延迟监测；<br>"
                    "② 在挂号高峰期（8:00–10:00）重点关注预约系统并发指标；<br>"
                    "③ 审查医疗设备联网（IoMT）是否占用过多内网带宽"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全合规】医疗数据安全风险需立即处置</strong><br>"
                    f"① 按<strong>{ctx['compliance']}</strong>立即开展全面安全自查，重点保护患者隐私数据（PHI）；<br>"
                    "② 检查医疗信息系统是否存在未打补丁的已知漏洞（重点：RDP、VPN 设备）；<br>"
                    "③ 加强内网横向移动防护，部署微分段（Micro-Segmentation）隔离医疗设备网络；<br>"
                    "④ 启用医疗数据全生命周期审计，监控 PHI 访问行为异常；<br>"
                    "⑤ 定期开展医护人员网络安全意识培训，防范钓鱼邮件和社会工程学攻击"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络保障】医疗专网链路质量异常</strong><br>"
                    "① 检查医院内网核心层、汇聚层交换机端口状态，排查物理链路故障；<br>"
                    "② 确认到卫健委/医保局的专线连通性，提交运营商排障工单；<br>"
                    "③ 评估 Wi-Fi 覆盖质量（移动查房终端/护士站 PDA 使用场景）；<br>"
                    "④ 对关键系统（手术室/ICU/急诊）部署独立专用网络，与普通业务网隔离"
                )
            solutions.append(
                "<strong>【长期规划】医疗信息化韧性提升</strong><br>"
                f"① 按<strong>{ctx['compliance']}</strong>每年开展等保测评和医疗数据安全评估；<br>"
                "② 建立医疗数据三级备份机制（本地热备 + 同城冷备 + 异地灾备）；<br>"
                "③ 推进医院网络安全态势感知平台建设，实现威胁的统一检测和响应；<br>"
                "④ 制定《医疗信息系统网络安全事件应急预案》，每年至少演练一次；<br>"
                "⑤ 对接国家卫健委医疗数据安全管理平台，确保合规上报"
            )

        elif org_type == "isp":
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】互联网服务可用性严重中断</strong><br>"
                    f"① 立即启动<strong>{ctx['admin']}</strong>NOC 应急响应流程，评估影响用户规模；<br>"
                    "② 检查骨干路由器/核心交换机运行状态，确认是否存在硬件故障；<br>"
                    "③ 分析是否遭受大规模 DDoS 攻击（流量异常 > 正常基线 5 倍），启动清洗预案；<br>"
                    "④ 若为 BGP 路由异常，立即联系上游运营商和 CNNIC/CERNET 协同处置"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】服务可用性存在下滑风险</strong><br>"
                    f"① 向<strong>{ctx['admin']}</strong>报告异常，启动设备健康评估；<br>"
                    f"② 提前为{ctx['peak']}备足带宽和计算资源，评估 CDN 节点扩容计划；<br>"
                    "③ 检查近期网络变更（路由策略/防火墙规则）是否引入问题"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】网络服务延迟严重超标</strong><br>"
                    "① 使用 NetFlow/sFlow 分析流量分布，定位高延迟路径和拥塞节点；<br>"
                    "② 优化 BGP 路由策略（AS Path Prepend/MED），将流量导向低延迟出口；<br>"
                    "③ 检查 DNS 解析集群性能，DNS 响应时间应 < 50ms；<br>"
                    "④ 评估 CDN 节点命中率，将热点内容下沉至边缘节点，减少回源压力；<br>"
                    "⑤ 对视频/直播流量实施 QoS 优先级保障，减少缓冲卡顿"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】网络延迟波动需关注</strong><br>"
                    "① 部署覆盖全网 PoP 节点的主动拨测（Synthetic Monitoring）；<br>"
                    "② 分析是否存在特定 AS 路径延迟偏高，优化对等互联（Peering）策略；<br>"
                    "③ 检查 CDN 缓存节点磁盘 I/O 和内存使用率，优化缓存淘汰策略"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全防护】基础设施安全威胁需立即响应</strong><br>"
                    f"① 按<strong>{ctx['compliance']}</strong>立即开展安全自查，重点检查 BGP 路由安全（RPKI 部署）；<br>"
                    "② 检查 DDoS 清洗设施防护阈值，确保能应对 Tbps 级攻击；<br>"
                    "③ 审计 DNS 安全配置（DNSSEC/DNS-over-HTTPS），防范 DNS 劫持和缓存投毒；<br>"
                    "④ 检查网管系统（NMS/OSS/BSS）安全加固，防止内部横向渗透；<br>"
                    "⑤ 向 CNCERT 报告重大网络安全威胁，配合行业协同防护"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络诊断】骨干链路质量劣化</strong><br>"
                    "① 执行 MPLS TE 路径追踪，定位物理链路故障或光缆衰减问题；<br>"
                    "② 向上游互联运营商提交链路质量报告（附 TWAMP/Y.1731 测量结果）；<br>"
                    "③ 检查城域网汇聚层设备端口错误计数（CRC/输入错误），排查物理层异常；<br>"
                    "④ 评估是否需要新建或升级骨干链路（10G→100G），满足流量增长需求"
                )
            solutions.append(
                "<strong>【长期规划】网络基础设施韧性提升</strong><br>"
                f"① 持续推进 IPv6 规模化部署，确保双栈能力符合{ctx['compliance']}要求；<br>"
                "② 建立全网流量大数据分析平台，预测带宽需求并提前扩容；<br>"
                "③ 推进 RPKI 路由源验证部署，提升 BGP 路由安全性；<br>"
                "④ 开展红队演练，验证 DDoS 防护、BGP 劫持应急响应能力；<br>"
                "⑤ 建立全网视角的端到端质量监测体系，支撑 SLA 对外承诺"
            )

        else:  # enterprise
            if avail < 60:
                solutions.append(
                    "<strong>【紧急处置】官网可用性严重异常</strong><br>"
                    "① 立即触发 SRE On-Call 响应流程，拉起 War Room 协同排障；<br>"
                    "② 检查负载均衡（LB）健康检查状态，确认后端 Real Server 存活数量；<br>"
                    "③ 评估是否需要执行流量切换（DNS Failover 或 GSLB 切换至备用集群）；<br>"
                    "④ 检查最近一次部署变更（Rollback 窗口内），评估是否需要紧急回滚；<br>"
                    "⑤ 同步通知 PR/品牌团队，准备对外沟通口径（官网代表企业形象）"
                )
            elif avail < 80:
                solutions.append(
                    "<strong>【预防性维护】可用性存在下滑趋势</strong><br>"
                    "① 检查负载均衡后端节点健康状态，确认是否有节点被摘除；<br>"
                    f"② 评估当前 SLA 达标情况（目标：{ctx['compliance']}），计算本月 Error Budget 剩余；<br>"
                    "③ 审查最近 24h 的部署变更记录，排查是否引入了性能回退"
                )
            if resp < 60:
                solutions.append(
                    "<strong>【性能优化】响应时延严重影响用户体验</strong><br>"
                    "① 分析 CDN 节点覆盖和缓存命中率（目标 Hit Rate ≥ 95%），排查回源异常；<br>"
                    "② 检查全球加速（GA/DCDN）配置，确认各地域 PoP 节点是否正常服务；<br>"
                    "③ 使用 Lighthouse/WebPageTest 分析首屏加载性能，优化 LCP/FID/CLS 指标；<br>"
                    "④ 检查后端 API 响应时间（P99），定位慢接口并优化（缓存/异步/降级）；<br>"
                    "⑤ 评估是否需要启用边缘计算（Edge Function）将动态逻辑下沉至 CDN 节点"
                )
            elif resp < 80:
                solutions.append(
                    "<strong>【性能监控】响应时延波动需关注</strong><br>"
                    "① 检查 CDN 缓存命中率趋势，排查是否有缓存穿透或缓存雪崩；<br>"
                    "② 分析是否存在特定地区或运营商的访问延迟异常（通过 RUM 数据定位）；<br>"
                    "③ 优化 Core Web Vitals 指标，确保 LCP < 2.5s、FID < 100ms、CLS < 0.1"
                )
            if sec < 70:
                solutions.append(
                    "<strong>【安全响应】威胁情报显示风险偏高</strong><br>"
                    "① 启动安全应急响应（SIRT）流程，评估威胁等级和影响范围；<br>"
                    "② 检查 WAF/Anti-DDoS 规则是否覆盖最新攻击特征（OWASP Top 10 2021）；<br>"
                    "③ 分析近期流量模式，排查是否遭受 CC 攻击、大规模爬虫或凭证填充攻击；<br>"
                    "④ 审计 API 接口暴露面，确认是否有未授权端点泄露敏感信息；<br>"
                    "⑤ 检查 HTTPS 证书链完整性和 HSTS 配置，防范中间人攻击和 SSL Stripping"
                )
            if link < 70:
                solutions.append(
                    "<strong>【网络架构】链路冗余度不足</strong><br>"
                    "① 检查多 ISP 接入配置，确认 BGP 路由通告和 AS Path 是否正常；<br>"
                    "② 评估 BGP Anycast 方案，将流量就近引导至最优 PoP 节点；<br>"
                    "③ 检查 DNS 解析策略（GeoDNS/Latency-based），确保用户被路由至最近节点；<br>"
                    "④ 审查网络监控（SmokePing/ThousandEyes），定位丢包发生的具体链路段"
                )
            solutions.append(
                "<strong>【长期规划】SRE 最佳实践</strong><br>"
                "① 定期进行混沌工程测试（Chaos Engineering），验证故障注入后的自动恢复能力；<br>"
                f"② 完善 SLA 监控体系，建立 Error Budget 消耗告警（目标：{ctx['compliance']}）；<br>"
                "③ 实施金丝雀发布（Canary Release），将变更风险控制在 1%–5% 流量范围内；<br>"
                "④ 建立 Post-Mortem 文化，每次故障后产出 RCA 报告并跟踪改进项落地；<br>"
                "⑤ 持续优化 MTTR（平均恢复时间），目标 P1 故障 < 15min 恢复"
            )

        insights.append({
            "icon": icon,
            "color": color,
            "title": f"{ctx['icon']} {name}（{ctx['label']}）— {status_desc}",
            "problem": problem,
            "solutions": solutions,
        })

        # 安全专项卡片：每个监测目标单独输出，基于实测 TLS 子项数据
        cfg = Config.get()
        tls_detail = _load_tls_detail(cfg.db_path, name)
        sec_solutions = _build_security_card(name, org_type, sec, ctx, tls_detail)
        if sec_solutions:
            insights.append({
                "icon": "🔐",
                "color": C_TEAL,
                "title": f"🔐 {name} — 网络安全专项检查清单",
                "problem": _build_security_problem(name, org_type, sec, tls_detail),
                "solutions": sec_solutions,
            })

    return insights


def _build_security_problem(name: str, org_type: str, sec_score: float,
                             tls_detail: dict | None = None) -> str:
    """根据实测安全评分和 TLS 子项数据生成安全专项问题描述。"""
    level = "良好" if sec_score >= 80 else ("需关注" if sec_score >= 60 else "存在明显风险")
    org_labels = {
        "university": "高校门户",
        "government": "政务网站",
        "enterprise": "企业官网",
        "finance": "金融平台",
        "healthcare": "医疗系统",
        "isp": "互联网基础设施",
    }
    label = org_labels.get(org_type, "网站")

    # 从实测数据提炼关键问题
    issues = []
    if tls_detail:
        days = tls_detail.get("tls_cert_days")
        if days is not None:
            if days < 0:
                issues.append(f"证书已过期 {abs(int(days))} 天")
            elif days < 14:
                issues.append(f"证书仅剩 {int(days)} 天到期（紧急）")
            elif days < 30:
                issues.append(f"证书剩余 {int(days)} 天（需尽快续期）")

        missing_hdrs = [
            _HDR_LABELS[k][0].split(" (")[0]
            for k in ("hsts", "csp", "x_frame_options",
                      "x_content_type_options", "referrer_policy", "permissions_policy")
            if tls_detail.get(f"tls_hdr_{k}", 1.0) == 0.0
        ]
        if missing_hdrs:
            issues.append(f"缺少 {len(missing_hdrs)} 项安全响应头（{', '.join(missing_hdrs[:3])}{'等' if len(missing_hdrs) > 3 else ''}）")

        if tls_detail.get("tls_https_redirect", 1.0) == 0.0:
            issues.append("HTTP 未强制跳转 HTTPS")

        ver_score = tls_detail.get("tls_version_score", 100.0)
        if ver_score < 80:
            issues.append("TLS 协议版本不安全（仍使用 TLS 1.0/1.1）")

    if issues:
        issue_str = "；".join(issues)
        return (
            f"当前安全综合评分 {sec_score:.1f} 分（{level}）。"
            f"实测发现以下问题：{issue_str}。"
            f"以下为针对 {name} 作为{label}的具体修复操作。"
        )

    has_data = bool(tls_detail)
    data_note = "以下为针对该站点的安全加固建议。" if has_data else "TLS 数据尚未采集，以下为常规安全加固建议（下次采集后将显示实测问题）。"
    return (
        f"当前安全综合评分 {sec_score:.1f} 分（{level}）。{data_note}"
    )


def _build_security_card(name: str, org_type: str, sec_score: float,
                          ctx: dict, tls_detail: dict | None = None) -> list:
    """生成网络安全专项建议，TLS 部分完全基于实测数据，内容具体可操作。"""
    solutions = []

    # ── 1. TLS 实测问题清单（基于本次采集数据，精确到每一项） ──────────────────
    if tls_detail:
        tls_problems = []   # 实测发现的具体问题
        tls_fixes    = []   # 对应的修复操作

        # 证书有效期
        days = tls_detail.get("tls_cert_days")
        if days is not None:
            if days < 0:
                tls_problems.append(f"<span style='color:#cf222e;'>❌ 证书已过期 {abs(int(days))} 天</span>——浏览器正在向用户显示「不安全」警告")
                tls_fixes.append(
                    f"<strong>证书过期（最高优先级）：</strong>立即执行 <code>certbot renew --force-renewal</code>（Let's Encrypt），"
                    f"或登录 CA 控制台重新签发；部署后执行 <code>nginx -s reload</code> 并用 "
                    f"<code>openssl s_client -connect {name}:443 &lt;&lt;&lt; '' 2&gt;&amp;1 | grep notAfter</code> 验证"
                )
            elif days < 14:
                tls_problems.append(f"<span style='color:#cf222e;'>⚠ 证书仅剩 {int(days)} 天到期</span>——到期后服务将立即中断")
                tls_fixes.append(
                    f"<strong>证书即将到期：</strong>本周内完成续期，执行 <code>certbot renew</code> 并检查 crontab 中是否已有自动续期任务 "
                    f"（<code>crontab -l | grep certbot</code>）"
                )
            elif days < 30:
                tls_problems.append(f"<span style='color:#9a6700;'>⚠ 证书剩余 {int(days)} 天</span>——建议本月内完成续期")
                tls_fixes.append(f"<strong>证书续期：</strong>执行 <code>certbot renew --dry-run</code> 测试续期流程是否正常，确认无误后正式续期")

        # TLS 协议版本
        ver_score = tls_detail.get("tls_version_score", 100.0)
        if ver_score < 80:
            tls_problems.append("<span style='color:#cf222e;'>❌ 使用了不安全的 TLS 协议版本</span>（TLS 1.0 或 TLS 1.1，已于 2021 年被 RFC 8996 正式废弃）")
            tls_fixes.append(
                "<strong>升级 TLS 版本：</strong>修改 Nginx 配置 <code>ssl_protocols TLSv1.2 TLSv1.3;</code>，"
                "Apache 修改 <code>SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1</code>，改完执行 <code>nginx -t && nginx -s reload</code>"
            )

        # 各安全响应头
        missing_hdr_details = []
        for hdr_key in ("hsts", "csp", "x_frame_options",
                         "x_content_type_options", "referrer_policy", "permissions_policy"):
            if tls_detail.get(f"tls_hdr_{hdr_key}", 1.0) == 0.0:
                full_name, attack_desc = _HDR_LABELS[hdr_key]
                missing_hdr_details.append((full_name, attack_desc))

        if missing_hdr_details:
            hdr_list = "".join(
                f"<li><code>{h}</code>——{d}</li>"
                for h, d in missing_hdr_details
            )
            tls_problems.append(
                f"<span style='color:#9a6700;'>⚠ 缺少 {len(missing_hdr_details)} 项 HTTP 安全响应头：</span>"
                f"<ul style='margin:4px 0 0 16px;'>{hdr_list}</ul>"
            )
            # 针对最重要的缺失头给出具体配置
            fix_lines = []
            for hdr_key, (full_name, _) in zip(
                ("hsts", "csp", "x_frame_options", "x_content_type_options"),
                [_HDR_LABELS[k] for k in ("hsts", "csp", "x_frame_options", "x_content_type_options")]
            ):
                if tls_detail.get(f"tls_hdr_{hdr_key}", 1.0) == 0.0:
                    if hdr_key == "hsts":
                        fix_lines.append('<code>add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;</code>')
                    elif hdr_key == "csp":
                        fix_lines.append("<code>add_header Content-Security-Policy \"default-src 'self'\" always;</code>（再根据实际资源来源细化）")
                    elif hdr_key == "x_frame_options":
                        fix_lines.append('<code>add_header X-Frame-Options "SAMEORIGIN" always;</code>')
                    elif hdr_key == "x_content_type_options":
                        fix_lines.append('<code>add_header X-Content-Type-Options "nosniff" always;</code>')
            if fix_lines:
                tls_fixes.append(
                    "<strong>添加安全响应头（Nginx server 块中加入）：</strong><br>"
                    + "<br>".join(fix_lines)
                    + "<br>改完执行 <code>nginx -t && nginx -s reload</code>"
                )

        # HTTPS 重定向
        if tls_detail.get("tls_https_redirect", 1.0) == 0.0:
            tls_problems.append("<span style='color:#9a6700;'>⚠ HTTP 未强制跳转 HTTPS</span>——用户通过 http:// 访问时不会自动升级到加密连接")
            tls_fixes.append(
                "<strong>强制 HTTPS 重定向：</strong>在 Nginx 的 80 端口 server 块中添加 "
                "<code>return 301 https://$host$request_uri;</code>"
            )

        # SCT 证书透明度
        if tls_detail.get("tls_sct", 1.0) == 0.0:
            tls_problems.append("<span style='color:#57606a;'>ℹ 未检测到证书透明度（CT/SCT）扩展</span>——部分浏览器可能对此发出警告")
            tls_fixes.append(
                "<strong>证书透明度：</strong>重新从支持 CT 的 CA 签发证书（Let's Encrypt 默认支持），"
                "或联系当前 CA 补签 SCT"
            )

        if tls_problems:
            problems_html = "".join(f"<li style='margin-bottom:6px;'>{p}</li>" for p in tls_problems)
            fixes_html = "".join(f"<li style='margin-bottom:8px;'>{f}</li>" for f in tls_fixes)
            solutions.append(
                f"<strong>【TLS/HTTPS 实测问题】本次采集发现 {len(tls_problems)} 项问题</strong><br>"
                f"<div style='margin:6px 0 8px 0;'>"
                f"<strong style='font-size:0.85em;'>▎ 发现的问题：</strong>"
                f"<ul style='margin:4px 0 0 16px;'>{problems_html}</ul>"
                f"</div>"
                f"<div>"
                f"<strong style='font-size:0.85em;'>▎ 修复操作：</strong>"
                f"<ol style='margin:4px 0 0 16px;'>{fixes_html}</ol>"
                f"</div>"
            )
        else:
            tls_score = tls_detail.get("tls_security", 0)
            solutions.append(
                f"<strong>【TLS/HTTPS 配置】实测评分 {tls_score:.0f} 分，当前未发现明显问题</strong><br>"
                "① 证书有效期正常、TLS 版本安全、主要安全响应头已配置；<br>"
                "② 建议每季度通过 <a href='https://www.ssllabs.com/ssltest/' target='_blank'>ssllabs.com</a> 做一次完整评级，目标保持 A 级；<br>"
                "③ 设置证书到期前 30 天的监控告警（本平台已接管此监测，如有异常将自动触发 tls_degradation 告警）"
            )
    else:
        # 无实测数据时给出通用操作指引
        solutions.append(
            "<strong>【TLS/HTTPS 加固】等待首次采集数据后显示实测问题</strong><br>"
            "① 当前 TLS 子项数据尚未采集，以下为通用加固建议；<br>"
            f"② 执行 <code>curl -I https://目标域名 2&gt;&amp;1 | grep -i -E 'strict|content-security|x-frame|x-content'</code> 手动检查安全头；<br>"
            "③ 禁用 TLS 1.0/1.1，Nginx 配置：<code>ssl_protocols TLSv1.2 TLSv1.3;</code>；<br>"
            "④ 下次采集完成后，本卡片将显示基于实测数据的精确问题清单"
        )

    # ── 2. Web 应用安全（按机构类型给出具体扫描工具和关注点）────────────────
    if org_type == "university":
        solutions.append(
            "<strong>【Web 应用安全】高校门户常见漏洞防护</strong><br>"
            "① 对教务系统、图书馆、一卡通等子系统使用 <a href='https://github.com/urbanadventurer/WhatWeb' target='_blank'>WhatWeb</a> 识别技术栈，针对性补丁更新；<br>"
            "② 重点测试文件上传接口（毕业论文提交、作业上传）是否有文件类型白名单校验，防止 WebShell 上传；<br>"
            "③ 检查学生信息管理系统登录接口是否存在 SQL 注入（可用 <code>sqlmap -u \"登录URL\" --forms --dbs</code> 测试授权范围内的接口）；<br>"
            "④ 确认后台管理入口（/admin、/manage 等）是否对校内 IP 段访问控制，不对公网开放；<br>"
            "⑤ 联系 CERNET CCERT（cert@cernet.edu.cn）订阅高校安全漏洞通报，及时获取针对教育网的定向攻击预警"
        )
    elif org_type == "government":
        solutions.append(
            "<strong>【Web 应用安全】政务网站安全防护重点</strong><br>"
            "① 部署网页完整性监测，每 5 分钟对首页和关键页面内容做哈希比对，检测暗链植入和页面篡改（推荐工具：网宿/知道创宇等国产 WAF）；<br>"
            "② 对政务表单（在线申报、信访提交）进行 CSRF Token 校验，防止跨站请求伪造；<br>"
            "③ 检查政务网站是否存在 HTTP 响应中的目录遍历（访问 /.. 路径）和敏感文件暴露（.git、.env、backup.zip）；<br>"
            "④ 对管理后台启用双因素认证（推荐使用国密 SM2 证书），符合《电子政务外网安全保障规范》要求；<br>"
            "⑤ 每半年委托具备 CISP-PTE 资质的机构开展渗透测试，测试报告归档备查"
        )
    else:
        solutions.append(
            "<strong>【Web 应用安全】企业官网攻击面收敛</strong><br>"
            "① 使用 <code>nmap -sV --script=http-headers 目标IP</code> 确认对外暴露的端口和服务是否最小化；<br>"
            "② 检查官网是否意外暴露 /.git/、/backup/、/phpinfo.php 等敏感路径；<br>"
            "③ 对联系表单、搜索框等用户输入点进行 XSS 测试，确认输出做了 HTML 转义；<br>"
            "④ 配置 WAF 规则拦截 OWASP Top 10 攻击向量，重点覆盖 SQL 注入和 XSS；<br>"
            "⑤ 定期扫描依赖库漏洞（如使用 npm audit、pip audit），及时升级已知 CVE 影响的组件"
        )

    # ── 3. 威胁情报研判（基于 OTX 数据给出实际操作指引）────────────────────
    solutions.append(
        "<strong>【威胁情报研判】AlienVault OTX 数据解读与响应</strong><br>"
        f"① 访问 <a href='https://otx.alienvault.com' target='_blank'>otx.alienvault.com</a> 搜索目标 IP，"
        f"查看「Pulse」数量和标签（如 Malware、Phishing、Scanning 等），判断威胁类型；<br>"
        "② 若 Pulse 数量 ≥ 3，说明该 IP 已被多个安全研究者关注，需重点核查近期 Web 访问日志中的异常来源请求；<br>"
        "③ 威胁情报评分突增时（本平台「威胁情报」图表柱体变为橙/红色），优先检查：<br>"
        "　　· Linux：<code>last -F</code>（最近登录记录）、<code>crontab -l</code>（可疑定时任务）；<br>"
        "　　· Windows：事件查看器 → 安全日志 → 筛选登录失败（事件ID 4625）；<br>"
        "④ 如需进一步溯源，可向 CNCERT（www.cert.org.cn）报告可疑 IP，申请协同处置；<br>"
        f"⑤ 对于{ctx['compliance']}要求的机构，威胁情报数据可作为等保测评「安全监测」能力的佐证材料"
    )

    # ── 4. 合规自查清单（按机构类型对应具体标准条款）────────────────────────
    compliance_tips = {
        "university": (
            "① 对照《教育部等级保护 2.0 三级要求》，确认已完成：网络架构安全（边界防护、访问控制）、主机安全（最小化安装、补丁更新）、数据备份（每日增量+每周全量）；<br>"
            "② 联系湖南省教育厅信息化处，了解当年度等保测评安排，提前准备测评证据材料；<br>"
            "③ 检查是否建立《网络安全事件应急响应预案》，明确分级响应流程（一级/二级/三级）和责任人联系方式；<br>"
            "④ 确认《网络安全法》第 21 条要求的「网络安全等级保护制度」落地情况，系统定级备案是否有效；<br>"
            "⑤ 参考 CERNET 发布的《高校网络安全自查指南》（每年更新），逐条核对自查结果"
        ),
        "government": (
            "① 对照《等保 2.0 三级技术要求》（GB/T 22239-2019）逐控制点自查，重点核查身份鉴别、访问控制、安全审计三个类别；<br>"
            "② 检查政务系统是否已完成《数据安全法》要求的「重要数据」识别和分类分级工作；<br>"
            "③ 《个人信息保护法》合规检查：公民在政务平台填写的个人信息是否最小化收集、是否有隐私政策、是否可删除；<br>"
            "④ 检查政务网站是否在工业和信息化部 ICP 备案，备案信息是否与实际运营主体一致；<br>"
            "⑤ 按《政府网站管理办法》要求，确认页面底部标注网站责任单位、联系方式和互联网举报渠道"
        ),
        "enterprise": (
            "① 检查企业官网是否有完善的隐私政策页面，符合《个人信息保护法》最小化收集原则；<br>"
            "② 如官网涉及用户注册/登录，确认密码存储使用加盐哈希（bcrypt/Argon2），不以明文或 MD5 存储；<br>"
            "③ 检查第三方 SDK 引入情况（统计、广告、分享组件），确认未违规收集用户设备信息；<br>"
            "④ 大型互联网企业（如字节跳动、腾讯）需关注《数据安全法》第 21 条「重要数据目录」管理要求；<br>"
            "⑤ 确认企业有效期内的 ICP 许可证/备案，以及网络安全等级保护定级备案"
        ),
    }
    default_compliance = (
        "① 确认系统已完成网络安全等级保护定级备案；<br>"
        "② 检查是否建立网络安全事件应急响应预案；<br>"
        "③ 核查《数据安全法》和《个人信息保护法》合规落地情况；<br>"
        "④ 检查 ICP 备案信息是否与实际运营主体一致；<br>"
        "⑤ 每年至少开展一次安全自查，形成书面报告存档"
    )
    solutions.append(
        f"<strong>【合规自查】{ctx['compliance']} 核对清单</strong><br>"
        + compliance_tips.get(org_type, default_compliance)
    )

    return solutions


def _build_asset_graph_figure(graph: dict, target_name: str) -> go.Figure:
    """把 asset_graph.build_graph() 的结果渲染成 Plotly 力导向图。"""
    pos = graph["pos"]

    edge_x, edge_y = [], []
    for src, dst in graph["edges"]:
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(color=BORDER, width=1.2),
        hoverinfo="skip", showlegend=False,
    ))

    for node in graph["nodes"]:
        x, y = pos[node["id"]]
        fig.add_trace(go.Scatter(
            x=[x], y=[y], mode="markers+text",
            marker=dict(size=node["size"], color=node["color"],
                       line=dict(color="#ffffff", width=2)),
            text=[node["label"] if node["type"] == "root" else ""],
            textposition="top center",
            textfont=dict(size=11, color=TEXT_MAIN),
            hovertext=[node["hover"]], hoverinfo="text",
            showlegend=False,
        ))

    fig.update_layout(**chart_layout(
        height=460,
        title=dict(text=f"{target_name} — 攻击面资产关系图",
                   font=dict(size=14, color=TEXT_MAIN)),
        xaxis=dict(visible=False, showgrid=False, zeroline=False),
        yaxis=dict(visible=False, showgrid=False, zeroline=False),
        margin=dict(t=50, b=20, l=20, r=20),
        hovermode="closest",
    ))
    return fig


def _render_asset_coverage(db_path: str, targets: list) -> None:
    """渲染攻击面/资产覆盖区块：资产关系图 + 被动发现子域名 + 站内多页面监测覆盖。"""
    from src.collection import subdomain_discovery, content_monitor

    st.markdown("### 🕸️ 攻击面测绘与覆盖范围")
    st.caption(
        "被动侦察：通过证书透明度日志（crt.sh）发现该域名下的对外暴露子系统，"
        "并对站内多个公开页面持续做内容完整性监测，而非只盯配置中的单一入口。"
        "下图以关系图形式呈现暴露面全貌：橙色=24小时内新发现子域名，红色=内容被篡改的页面。"
    )

    for target_name in targets:
        assets = subdomain_discovery.get_assets(db_path, target_name)
        sub_pages = content_monitor.get_latest_subpage_snapshots(db_path, target_name)

        if not assets and not sub_pages:
            continue

        with st.expander(f"🌐 {target_name} — 子域名 {len(assets)} 个 · 站内监测页面 {len(sub_pages)} 个"):
            graph = asset_graph.build_graph(db_path, target_name)
            if not graph["empty"]:
                st.plotly_chart(_build_asset_graph_figure(graph, target_name),
                               use_container_width=True, key=f"asset_graph_{target_name}")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**被动发现的子域名**")
                if assets:
                    for a in assets:
                        st.markdown(f"- `{a['subdomain']}`")
                else:
                    st.caption("尚未发现额外子域名（或该域名证书记录较少）")
            with col2:
                st.markdown("**站内多页面监测覆盖**")
                if sub_pages:
                    for p in sub_pages:
                        icon = "🚨" if p.get("changed") else "✅"
                        st.markdown(f"- {icon} `{p['page_path']}`")
                else:
                    st.caption("尚未从首页发现可监测的站内子页面")


def _build_attack_chain_figure(chain: dict) -> go.Figure:
    """把 root_cause.build_attack_chain() 的事件列表渲染成分阶段时间轴散点图。"""
    events = chain["events"]
    stage_y = {s: i for i, s in enumerate(root_cause.STAGE_ORDER)}

    fig = go.Figure()
    for stage in root_cause.STAGE_ORDER:
        stage_events = [e for e in events if e["stage"] == stage]
        if not stage_events:
            continue
        color = _STAGE_COLOR.get(stage, TEXT_DIM)
        fig.add_trace(go.Scatter(
            x=[e["time"] for e in stage_events],
            y=[stage_y[stage]] * len(stage_events),
            mode="markers",
            marker=dict(
                size=[_SEVERITY_MARKER.get(e["severity"], 9) for e in stage_events],
                color=color, line=dict(color="#ffffff", width=1.5),
            ),
            name=stage,
            hovertext=[f"{e['icon']} {e['title']}<br>{e['time'].strftime('%Y-%m-%d %H:%M')}"
                      for e in stage_events],
            hoverinfo="text",
        ))

    # 阶段之间的推进箭头（按时间最早的事件连线，突出"从侦察到失陷"的演化路径）
    stage_first_time = {}
    for e in events:
        if e["stage"] not in stage_first_time:
            stage_first_time[e["stage"]] = e["time"]
    ordered_stages = [s for s in root_cause.STAGE_ORDER if s in stage_first_time]
    for i in range(len(ordered_stages) - 1):
        s0, s1 = ordered_stages[i], ordered_stages[i + 1]
        fig.add_shape(
            type="line",
            x0=stage_first_time[s0], x1=stage_first_time[s1],
            y0=stage_y[s0], y1=stage_y[s1],
            line=dict(color=TEXT_DIM, width=1, dash="dot"),
        )

    fig.update_layout(**chart_layout(
        height=280,
        title=dict(text="攻击链复盘时间轴", font=dict(size=14, color=TEXT_MAIN)),
        yaxis=dict(
            tickmode="array", tickvals=list(stage_y.values()), ticktext=list(stage_y.keys()),
            range=[-0.6, len(root_cause.STAGE_ORDER) - 0.4],
            gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM),
        ),
        xaxis=dict(title="时间", gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM)),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
                   bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1, font=dict(size=10)),
    ))
    return fig


def _render_attack_chain(db_path: str, targets: list, hours: int) -> None:
    """渲染攻击链复盘区块：把告警和骤降事件按 侦察特征→弱点暴露→异常行为→疑似失陷 归类，画时间轴。"""
    st.markdown("### ⛓️ 攻击链复盘")
    st.caption(
        "把窗口内的安全事件按简化版 Cyber Kill Chain 归类排序："
        "侦察特征（新资产/威胁情报） → 弱点暴露（TLS劣化） → 异常行为（可用性/时延/健康度骤降） → 疑似失陷（内容篡改），"
        "呈现攻击从早期迹象到最终影响的演化路径，而非孤立罗列告警。"
    )

    has_any = False
    for target_name in targets:
        chain = root_cause.build_attack_chain(db_path, target_name, hours=hours)
        if not chain["events"]:
            continue
        has_any = True

        counts = chain["stage_counts"]
        badges = "".join(
            f'<span style="background:{rgba(_STAGE_COLOR.get(s, TEXT_DIM),0.10)};'
            f'border:1px solid {rgba(_STAGE_COLOR.get(s, TEXT_DIM),0.3)};'
            f'color:{_STAGE_COLOR.get(s, TEXT_DIM)};font-size:0.72rem;font-weight:600;'
            f'padding:2px 10px;border-radius:12px;margin-right:6px;">{s} × {counts[s]}</span>'
            for s in root_cause.STAGE_ORDER if s in counts
        )
        st.markdown(
            f'<div style="margin-bottom:6px;">'
            f'<span style="font-size:0.9rem;font-weight:700;color:{TEXT_MAIN};">{target_name}</span>'
            f'<span style="margin-left:10px;">{badges}</span></div>',
            unsafe_allow_html=True,
        )

        with st.expander(f"查看 {target_name} 的攻击链时间轴（{len(chain['events'])} 个事件）", expanded=False):
            st.plotly_chart(_build_attack_chain_figure(chain), use_container_width=True,
                           key=f"attack_chain_{target_name}")

            for e in chain["events"]:
                color = _STAGE_COLOR.get(e["stage"], TEXT_DIM)
                st.markdown(
                    f'<div style="display:flex;gap:10px;padding:6px 10px;border-left:3px solid {color};'
                    f'margin-bottom:4px;background:{rgba(color,0.04)};border-radius:0 6px 6px 0;">'
                    f'<span>{e["icon"]}</span>'
                    f'<span style="font-size:0.72rem;color:{TEXT_DIM};min-width:110px;">'
                    f'{e["time"].strftime("%Y-%m-%d %H:%M")}</span>'
                    f'<span style="font-size:0.72rem;color:{color};font-weight:600;min-width:64px;">{e["stage"]}</span>'
                    f'<span style="font-size:0.82rem;color:{TEXT_MAIN};">{e["title"]}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    if not has_any:
        st.success(f"过去 {hours} 小时内未检测到可归类的安全事件，暂无攻击链可复盘")


def _chart_compliance_category(result: dict) -> go.Figure:
    """等保各类别达标率水平条形图。"""
    categories = list(result["categories"].keys())
    pass_counts  = [sum(1 for c in result["categories"][cat] if c["status"] == "pass")  for cat in categories]
    warn_counts  = [sum(1 for c in result["categories"][cat] if c["status"] == "warn")  for cat in categories]
    fail_counts  = [sum(1 for c in result["categories"][cat] if c["status"] == "fail")  for cat in categories]
    unk_counts   = [sum(1 for c in result["categories"][cat] if c["status"] == "unknown") for cat in categories]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="✅ 达标", x=pass_counts, y=categories, orientation="h",
        marker_color=C_HEALTHY, text=pass_counts, textposition="inside",
    ))
    fig.add_trace(go.Bar(
        name="⚠️ 需关注", x=warn_counts, y=categories, orientation="h",
        marker_color=C_WARNING, text=warn_counts, textposition="inside",
    ))
    fig.add_trace(go.Bar(
        name="❌ 不达标", x=fail_counts, y=categories, orientation="h",
        marker_color=C_CRITICAL, text=fail_counts, textposition="inside",
    ))
    fig.add_trace(go.Bar(
        name="❓ 待检测", x=unk_counts, y=categories, orientation="h",
        marker_color=TEXT_DIM, text=unk_counts, textposition="inside",
    ))
    fig.update_layout(**chart_layout(
        height=max(200, len(categories) * 52 + 80),
        barmode="stack",
        title=dict(text="等保2.0各类别达标分布", font=dict(size=13, color=TEXT_MAIN)),
        xaxis=dict(title="条款数", gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM)),
        margin=dict(t=50, b=40, l=90, r=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
                    bgcolor=BG_CARD, bordercolor=BORDER, borderwidth=1, font=dict(size=10)),
    ))
    return fig


def _chart_tls_headers(tls_detail: dict, target_name: str) -> go.Figure:
    """TLS 6项安全响应头配置状态水平条形图（已配置=1，未配置=0）。"""
    _HDR_KEYS = [
        ("tls_hdr_hsts",                  "HSTS"),
        ("tls_hdr_csp",                   "CSP"),
        ("tls_hdr_x_frame_options",       "X-Frame-Options"),
        ("tls_hdr_x_content_type_options","X-Content-Type-Options"),
        ("tls_hdr_referrer_policy",       "Referrer-Policy"),
        ("tls_hdr_permissions_policy",    "Permissions-Policy"),
    ]
    labels = [label for _, label in _HDR_KEYS]
    values = [int(tls_detail.get(key, 0)) for key, _ in _HDR_KEYS]
    colors = [C_HEALTHY if v else C_CRITICAL for v in values]
    texts  = ["已配置" if v else "未配置" for v in values]

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker_color=colors,
        text=texts, textposition="outside",
        textfont=dict(color=TEXT_MAIN, size=11),
        hovertemplate="%{y}：%{text}<extra></extra>",
    ))
    fig.update_layout(**chart_layout(
        height=280,
        title=dict(text=f"{target_name} — HTTP 安全响应头配置状态", font=dict(size=13, color=TEXT_MAIN)),
        xaxis=dict(range=[0, 1.6], visible=False),
        margin=dict(t=50, b=20, l=160, r=80),
        showlegend=False,
    ))
    return fig


def _chart_root_cause_summary(ev: dict, ev_key: str) -> go.Figure:
    """根因分析事件三类异常计数条形图。"""
    categories = ["指标异常", "TLS/安全层变化", "关联告警"]
    counts = [
        len(ev.get("metric_anomalies", [])),
        len(ev.get("tls_changes", [])),
        len(ev.get("alerts", [])),
    ]
    colors = [C_ORANGE, C_TEAL, C_CRITICAL]

    fig = go.Figure(go.Bar(
        x=categories, y=counts,
        marker_color=colors,
        text=counts, textposition="outside",
        hovertemplate="%{x}：%{y} 项<extra></extra>",
    ))
    fig.update_layout(**chart_layout(
        height=200,
        title=dict(text="根因关联项数量", font=dict(size=12, color=TEXT_MAIN)),
        yaxis=dict(title="数量", range=[0, max(counts) + 2 if any(counts) else 3],
                   gridcolor=BORDER, tickfont=dict(color=TEXT_DIM)),
        showlegend=False,
        margin=dict(t=40, b=30, l=40, r=20),
    ))
    return fig


def _render_root_cause(db_path: str, targets: list, hours: int) -> None:
    """渲染根因关联分析区块。"""
    st.markdown("### 🔍 评分骤降根因分析")
    st.caption("自动检测过去时间窗口内的评分骤降事件，关联同时段的TLS变化、指标异常和告警")

    has_any = False
    for target_name in targets:
        events = root_cause.analyze(db_path, target_name, hours=hours)
        if not events:
            continue
        has_any = True
        st.markdown(f"**{target_name}** — 发现 {len(events)} 个骤降事件")
        for ev in events:
            t_str = ev["time"].strftime("%Y-%m-%d %H:%M") if hasattr(ev["time"], "strftime") else str(ev["time"])
            drop_color = C_CRITICAL if ev["drop"] >= 10 else C_WARNING
            with st.expander(
                f"⬇ {t_str}  |  {ev['from_score']:.1f} → {ev['to_score']:.1f}  （下降 {ev['drop']:.1f} 分）",
                expanded=ev["drop"] >= 10,
            ):
                st.markdown(
                    f'<div style="background:{rgba(drop_color,0.08)};border-left:4px solid {drop_color};'
                    f'border-radius:6px;padding:10px 14px;margin-bottom:10px;font-size:0.88rem;color:{TEXT_MAIN};">'
                    f'<strong>根因摘要：</strong>{ev["summary"]}</div>',
                    unsafe_allow_html=True,
                )
                # 根因关联项数量图
                ev_key = f"rc_{target_name}_{t_str}"
                st.plotly_chart(
                    _chart_root_cause_summary(ev, ev_key),
                    use_container_width=True,
                    key=ev_key,
                )
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.markdown("**指标异常**")
                    if ev["metric_anomalies"]:
                        for a in ev["metric_anomalies"]:
                            st.markdown(f"- {a}")
                    else:
                        st.caption("无明显指标异常")
                with col2:
                    st.markdown("**TLS/安全层变化**")
                    if ev["tls_changes"]:
                        for c in ev["tls_changes"]:
                            st.markdown(f"- {c}")
                    else:
                        st.caption("无TLS变化")
                with col3:
                    st.markdown("**同期触发告警**")
                    if ev["alerts"]:
                        for a in ev["alerts"]:
                            st.markdown(f"- {a}")
                    else:
                        st.caption("无关联告警")

    if not has_any:
        st.success(f"过去 {hours} 小时内未检测到评分骤降事件（阈值：单次下降 ≥5分）")


def _render_compliance(db_path: str, targets: list) -> None:
    """渲染等保2.0合规自查区块。"""
    st.markdown("### 📋 等保2.0合规自查评分")
    st.caption("基于实测TLS/HTTPS数据自动映射GB/T 22239-2019（等保2.0）三级技术要求条款，给出达标状态和合规得分")

    st.markdown(
        f'<div style="background:{rgba(C_ORANGE,0.07)};border:1px solid {rgba(C_ORANGE,0.25)};'
        f'border-radius:8px;padding:10px 16px;margin-bottom:16px;font-size:0.82rem;color:{TEXT_DIM};">'
        f'<strong style="color:{C_ORANGE};">📌 说明：</strong>'
        f'评分反映的是<strong>被监测网站</strong>当前的安全头配置实际状态，低分意味着该网站存在需要整改的安全配置项。'
        f'例如湖南省政府网站未配置HSTS、缺少CSP等安全响应头，这是真实存在的安全风险，与本平台无关。'
        f'各条款下方均附有具体修复建议，可直接提供给目标网站管理员参考。'
        f'</div>',
        unsafe_allow_html=True,
    )

    _STATUS_ICON  = {"pass": "✅", "warn": "⚠️", "fail": "❌", "unknown": "❓"}
    _STATUS_COLOR = {"pass": C_HEALTHY, "warn": C_WARNING, "fail": C_CRITICAL, "unknown": TEXT_DIM}
    _STATUS_LABEL = {"pass": "达标", "warn": "需关注", "fail": "不达标", "unknown": "待检测"}

    for target_name in targets:
        # 读取TLS详情
        tls_detail = _load_tls_detail(db_path, target_name)
        result = compliance.evaluate(tls_detail)

        score = result["score"]
        level = result["level"]
        score_color = C_HEALTHY if score >= 90 else (C_WARNING if score >= 60 else C_CRITICAL)

        # 顶部评分卡
        st.markdown(
            f'<div style="background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;'
            f'padding:16px 20px;margin-bottom:12px;">'
            f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">'
            f'<div>'
            f'<div style="font-size:0.95rem;font-weight:700;color:{TEXT_MAIN};">🏛️ {target_name}</div>'
            f'<div style="font-size:0.78rem;color:{TEXT_DIM};margin-top:3px;">等保2.0三级技术要求 · GB/T 22239-2019</div>'
            f'</div>'
            f'<div style="text-align:center;">'
            f'<div style="font-size:2rem;font-weight:800;color:{score_color};">{score:.0f}</div>'
            f'<div style="font-size:0.75rem;color:{TEXT_DIM};">合规得分</div>'
            f'</div>'
            f'<div style="text-align:center;">'
            f'<div style="font-size:1.2rem;font-weight:700;color:{score_color};">{level}</div>'
            f'<div style="font-size:0.75rem;color:{TEXT_DIM};">综合评级</div>'
            f'</div>'
            f'<div style="display:flex;gap:16px;font-size:0.82rem;">'
            f'<span style="color:{C_HEALTHY};">✅ 达标 {result["pass_count"]}</span>'
            f'<span style="color:{C_WARNING};">⚠️ 需关注 {result["warn_count"]}</span>'
            f'<span style="color:{C_CRITICAL};">❌ 不达标 {result["fail_count"]}</span>'
            f'</div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # 等保各类别达标率图 + TLS响应头图
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.plotly_chart(
                _chart_compliance_category(result),
                use_container_width=True,
                key=f"compliance_cat_{target_name}",
            )
        with chart_col2:
            st.plotly_chart(
                _chart_tls_headers(tls_detail, target_name),
                use_container_width=True,
                key=f"tls_hdr_{target_name}",
            )

        # 按类别展示条款
        for cat_name, clauses in result["categories"].items():
            cat_pass  = sum(1 for c in clauses if c["status"] == "pass")
            cat_total = len(clauses)
            cat_color = C_HEALTHY if cat_pass == cat_total else (C_WARNING if cat_pass >= cat_total // 2 else C_CRITICAL)
            with st.expander(f"{cat_name}  —  {cat_pass}/{cat_total} 项达标", expanded=(cat_pass < cat_total)):
                for clause in clauses:
                    s = clause["status"]
                    icon  = _STATUS_ICON[s]
                    color = _STATUS_COLOR[s]
                    label = _STATUS_LABEL[s]
                    st.markdown(
                        f'<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;'
                        f'border-bottom:1px solid {BORDER};">'
                        f'<span style="font-size:1rem;min-width:20px;">{icon}</span>'
                        f'<div style="flex:1;">'
                        f'<div style="font-size:0.85rem;font-weight:600;color:{TEXT_MAIN};">'
                        f'<span style="color:{TEXT_DIM};font-size:0.75rem;">{clause["id"]} </span>'
                        f'{clause["name"]}'
                        f'<span style="margin-left:8px;font-size:0.72rem;font-weight:400;'
                        f'color:{color};background:{rgba(color,0.1)};padding:1px 7px;border-radius:10px;">{label}</span>'
                        f'</div>'
                        f'<div style="font-size:0.78rem;color:{TEXT_DIM};margin-top:2px;">{clause["desc"]}</div>'
                        f'<div style="font-size:0.78rem;color:{color};margin-top:3px;">检测结果：{clause["detail"]}</div>'
                        + (
                            f'<div style="font-size:0.76rem;color:{TEXT_DIM};margin-top:3px;'
                            f'background:{rgba(C_ORANGE,0.07)};padding:4px 8px;border-radius:4px;">'
                            f'🔧 修复建议：{clause["fix"]}</div>'
                            if s in ("fail", "warn") else ""
                        )
                        + f'</div></div>',
                        unsafe_allow_html=True,
                    )

        st.markdown("<br>", unsafe_allow_html=True)


def _chart_score_distribution(health_df):
    latest = health_df.sort_values("scored_at").groupby("target_name").last().reset_index()
    colors = [C_HEALTHY if s >= 80 else (C_WARNING if s >= 60 else C_CRITICAL) for s in latest["score"]]
    fig = go.Figure(go.Bar(
        x=latest["target_name"], y=latest["score"],
        marker_color=colors,
        text=[f"{s:.1f}" for s in latest["score"]],
        textposition="outside",
    ))
    fig.add_hline(y=80, line_dash="dot", line_color=C_WARNING,  line_width=1.5, annotation_text="良好 80", annotation_font_color=C_WARNING)
    fig.add_hline(y=60, line_dash="dot", line_color=C_CRITICAL, line_width=1.5, annotation_text="警戒 60", annotation_font_color=C_CRITICAL)
    fig.update_layout(**chart_layout(
        height=300, title="各服务当前健康度",
        yaxis=dict(range=[0, 115], gridcolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM)),
    ))
    return fig


def _chart_metric_radar(fused_df, target):
    grp = fused_df[fused_df["target_name"] == target]
    if grp.empty:
        return go.Figure()
    latest = grp.sort_values("fused_at").iloc[-1]
    categories = ["可用性", "响应时延", "链路连通性", "安全风险"]
    values = [
        float(latest.get("availability_score") or 0),
        float(latest.get("response_time_score") or 0),
        float(latest.get("link_score") or 0),
        float(latest.get("security_score") or 0),
    ]
    v = values + [values[0]]
    c = categories + [categories[0]]
    fig = go.Figure(go.Scatterpolar(
        r=v, theta=c, fill="toself",
        fillcolor=rgba(C_BLUE, 0.15),
        line=dict(color=C_BLUE, width=2),
        marker=dict(color=C_BLUE, size=6),
    ))
    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(color=TEXT_DIM, size=10), gridcolor=BORDER),
            angularaxis=dict(tickfont=dict(color=TEXT_MAIN, size=11)),
            bgcolor=BG_CHART,
        ),
        paper_bgcolor=BG_CARD, height=300,
        margin=dict(t=40, b=20, l=40, r=40),
        showlegend=False,
        title=dict(text=f"{target} — 分项指标雷达图", font=dict(color=TEXT_MAIN, size=13)),
    )
    return fig


def _chart_alert_timeline(alerts_df):
    df = alerts_df.copy()
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True, errors="coerce")
    df["hour"] = df["created_at"].dt.floor("h")
    grouped = df.groupby(["hour", "severity"]).size().reset_index(name="cnt")
    fig = go.Figure()
    for sev, color in [("critical", C_CRITICAL), ("warning", C_WARNING), ("info", C_BLUE)]:
        sub = grouped[grouped["severity"] == sev]
        if sub.empty:
            continue
        fig.add_trace(go.Bar(x=sub["hour"], y=sub["cnt"], name=sev, marker_color=color))
    fig.update_layout(**chart_layout(height=260, barmode="stack", title="告警时间分布（按小时）", xaxis_title="时间", yaxis_title="告警次数"))
    return fig


def render():
    cfg = Config.get()
    db_path = cfg.db_path

    st.markdown("## 💡 数据启示与运维建议")
    st.caption("基于实时采集数据，针对每个问题给出具体可操作的解决方案")
    st.markdown("---")

    # ── 顶部目标筛选器 ────────────────────────────────────────────────────────
    all_config_targets = [t["name"] for t in cfg.targets if t.get("enabled", True)]
    _ALL_LABEL = "📊 全部目标（汇总视图）"
    filter_options = [_ALL_LABEL] + all_config_targets
    selected_filter = st.selectbox(
        "🎯 筛选监测目标",
        filter_options,
        key="insights_target_filter",
        help="选择单个目标可查看该目标专属的所有分析与图表；选择「全部」显示汇总视图",
    )
    single_target = None if selected_filter == _ALL_LABEL else selected_filter
    st.markdown("---")

    if single_target is None:
        _render_target_overview()

    hours = st.slider("分析时间窗口（小时）", 1, 168, 24, key="insights_hours")

    health_df = _load_health_history(db_path, hours)
    fused_df  = _load_fused_history(db_path, hours)
    alerts_df = _load_alerts_history(db_path, hours)

    # 按筛选器过滤数据帧
    if single_target:
        health_df = health_df[health_df["target_name"] == single_target]
        fused_df  = fused_df[fused_df["target_name"] == single_target]   if not fused_df.empty  else fused_df
        alerts_df = alerts_df[alerts_df["target_name"] == single_target] if not alerts_df.empty else alerts_df

    if health_df.empty:
        st.info("暂无数据，等待首次采集完成（约 1 分钟）...")
        return

    latest_scores = health_df.sort_values("scored_at").groupby("target_name")["score"].last()
    avg_score    = latest_scores.mean()
    critical_cnt = int((latest_scores < 60).sum())
    warning_cnt  = int(((latest_scores >= 60) & (latest_scores < 80)).sum())
    alert_total  = len(alerts_df)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("平均健康度",  f"{avg_score:.1f} 分")
    m2.metric("异常服务数",  f"{critical_cnt} 个", delta=f"-{critical_cnt}" if critical_cnt else None, delta_color="inverse")
    m3.metric("警告服务数",  f"{warning_cnt} 个")
    m4.metric("告警总次数",  f"{alert_total} 次", delta=f"+{alert_total}" if alert_total else None, delta_color="inverse")

    st.markdown("---")
    st.markdown("### 🛠️ 运维建议")
    st.caption("以下建议按监测对象分别给出，结合各机构实际情况可直接参照执行")

    insights = _generate_insights(health_df, fused_df, alerts_df)
    if not insights:
        st.success("当前时间窗口内数据量不足，请扩大时间范围后重试。")
    else:
        for item in insights:
            _insight_card(item["icon"], item["title"], item["problem"], item["solutions"], item["color"])

    st.markdown("---")
    st.markdown("### 📊 可视化分析")

    st.plotly_chart(_chart_score_distribution(health_df), use_container_width=True)

    if not fused_df.empty:
        radar_targets = fused_df["target_name"].unique().tolist()
        if single_target:
            radar_sel = single_target
        else:
            radar_sel = st.selectbox("选择服务查看分项雷达图", radar_targets, key="insights_radar_target")
        st.plotly_chart(_chart_metric_radar(fused_df, radar_sel), use_container_width=True)

    # ── 攻击面/资产覆盖 ────────────────────────────────────────────────────────
    st.markdown("---")
    all_targets = health_df["target_name"].unique().tolist()
    _render_asset_coverage(db_path, all_targets)

    # ── 攻击链复盘 ────────────────────────────────────────────────────────────
    st.markdown("---")
    _render_attack_chain(db_path, all_targets, hours)

    # ── 根因关联分析 ──────────────────────────────────────────────────────────
    st.markdown("---")
    _render_root_cause(db_path, all_targets, hours)

    # ── 等保2.0合规自查 ────────────────────────────────────────────────────────
    st.markdown("---")
    _render_compliance(db_path, all_targets)

    if not fused_df.empty:
        st.markdown("---")
        st.markdown("### 📋 分项指标均值汇总")
        summary = (
            fused_df.groupby("target_name")[["availability_score", "response_time_score", "link_score", "security_score"]]
            .mean().reset_index()
            .rename(columns={
                "target_name": "服务名称",
                "availability_score": "可用性",
                "response_time_score": "响应时延",
                "link_score": "链路连通性",
                "security_score": "安全风险",
            })
        )
        for col in ["可用性", "响应时延", "链路连通性", "安全风险"]:
            summary[col] = summary[col].apply(lambda v: f"{v:.1f}")
        st.dataframe(summary, use_container_width=True, hide_index=True)