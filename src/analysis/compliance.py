"""
等保2.0合规自查模块
基于实测TLS数据自动映射到等保2.0具体条款，给出达标/不达标清单和合规得分。
"""
from typing import Dict, List, Tuple


# 等保2.0三级技术要求条款映射
# 格式：(条款编号, 条款名称, 检测方法, 评分权重)
_CLAUSES = [
    # ── 通信传输 ──────────────────────────────────────────────────────────────
    {
        "id": "8.1.4.1",
        "category": "通信传输",
        "name": "数据传输加密",
        "desc": "应采用密码技术保证通信过程中数据的保密性",
        "check": "tls_https_redirect",
        "check_type": "binary",       # 1=达标 0=不达标
        "pass_threshold": 1.0,
        "weight": 3,
        "fix": "在Nginx 80端口 server 块中添加 return 301 https://$host$request_uri;",
    },
    {
        "id": "8.1.4.2",
        "category": "通信传输",
        "name": "TLS协议版本安全",
        "desc": "应使用经国家密码主管部门认可的密码算法，禁用已知不安全的协议版本",
        "check": "tls_version_score",
        "check_type": "score",
        "pass_threshold": 80.0,
        "weight": 3,
        "fix": "Nginx配置 ssl_protocols TLSv1.2 TLSv1.3; 禁用TLS 1.0/1.1",
    },
    {
        "id": "8.1.4.3",
        "category": "通信传输",
        "name": "证书有效性管理",
        "desc": "应保证数字证书在有效期内，确保加密通信可信",
        "check": "tls_cert_days",
        "check_type": "cert_days",    # 特殊处理：>30天达标，14-30天警告，<14天不达标
        "pass_threshold": 30,
        "weight": 3,
        "fix": "执行 certbot renew 续期证书，并配置 crontab 自动续期",
    },
    {
        "id": "8.1.4.4",
        "category": "通信传输",
        "name": "证书透明度(CT)",
        "desc": "证书应提交至公开的证书透明度日志，防止伪造证书",
        "check": "tls_sct",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 1,
        "fix": "从支持CT的CA重新签发证书（Let's Encrypt默认支持CT）",
    },
    # ── 入侵防范 ──────────────────────────────────────────────────────────────
    {
        "id": "8.1.5.1",
        "category": "入侵防范",
        "name": "防点击劫持（X-Frame-Options）",
        "desc": "应防止页面被嵌入恶意 iframe，避免点击劫持攻击",
        "check": "tls_hdr_x_frame_options",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 2,
        "fix": 'Nginx添加 add_header X-Frame-Options "SAMEORIGIN" always;',
    },
    {
        "id": "8.1.5.2",
        "category": "入侵防范",
        "name": "防XSS攻击（Content-Security-Policy）",
        "desc": "应配置内容安全策略，限制可加载资源来源，防止跨站脚本攻击",
        "check": "tls_hdr_csp",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 2,
        "fix": "Nginx添加 add_header Content-Security-Policy \"default-src 'self'\" always;",
    },
    {
        "id": "8.1.5.3",
        "category": "入侵防范",
        "name": "防MIME嗅探（X-Content-Type-Options）",
        "desc": "应禁止浏览器MIME类型嗅探，防止内容类型混淆攻击",
        "check": "tls_hdr_x_content_type_options",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 1,
        "fix": 'Nginx添加 add_header X-Content-Type-Options "nosniff" always;',
    },
    # ── 安全审计 ──────────────────────────────────────────────────────────────
    {
        "id": "8.1.6.1",
        "category": "安全审计",
        "name": "HTTPS强制传输（HSTS）",
        "desc": "应配置HTTP严格传输安全头，防止SSL降级攻击，确保全程加密访问",
        "check": "tls_hdr_hsts",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 3,
        "fix": 'Nginx添加 add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    },
    {
        "id": "8.1.6.2",
        "category": "安全审计",
        "name": "信息泄露控制（Referrer-Policy）",
        "desc": "应控制HTTP Referer信息传递范围，防止敏感URL信息泄露",
        "check": "tls_hdr_referrer_policy",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 1,
        "fix": 'Nginx添加 add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    },
    {
        "id": "8.1.6.3",
        "category": "安全审计",
        "name": "浏览器权限控制（Permissions-Policy）",
        "desc": "应限制页面可使用的浏览器敏感API（摄像头、麦克风、地理位置等）",
        "check": "tls_hdr_permissions_policy",
        "check_type": "binary",
        "pass_threshold": 1.0,
        "weight": 1,
        "fix": 'Nginx添加 add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    },
    # ── 综合安全 ──────────────────────────────────────────────────────────────
    {
        "id": "8.1.7.1",
        "category": "综合安全",
        "name": "TLS综合安全评分",
        "desc": "TLS/HTTPS整体配置应达到行业基准安全水平（≥70分）",
        "check": "tls_security",
        "check_type": "score",
        "pass_threshold": 70.0,
        "weight": 2,
        "fix": "综合修复上述各项TLS/HTTPS配置问题后，综合评分将自动提升",
    },
]


def _evaluate_clause(clause: dict, tls_detail: dict) -> Tuple[str, float, str]:
    """
    评估单条条款的达标状态。
    返回 (status, score_contrib, detail)
    status: 'pass' | 'warn' | 'fail' | 'unknown'
    """
    key   = clause["check"]
    ctype = clause["check_type"]
    value = tls_detail.get(key)

    if value is None:
        return "unknown", 0.0, "尚无实测数据"

    value = float(value)

    if ctype == "binary":
        if value >= clause["pass_threshold"]:
            return "pass", float(clause["weight"]), "已配置"
        else:
            return "fail", 0.0, "未检测到"

    elif ctype == "score":
        if value >= clause["pass_threshold"]:
            return "pass", float(clause["weight"]), f"评分 {value:.1f}（≥{clause['pass_threshold']}）"
        elif value >= clause["pass_threshold"] * 0.7:
            return "warn", float(clause["weight"]) * 0.5, f"评分 {value:.1f}，偏低（基准 {clause['pass_threshold']}）"
        else:
            return "fail", 0.0, f"评分 {value:.1f}，不达标（基准 {clause['pass_threshold']}）"

    elif ctype == "cert_days":
        days = int(value)
        if days >= 30:
            return "pass", float(clause["weight"]), f"证书剩余 {days} 天"
        elif days >= 14:
            return "warn", float(clause["weight"]) * 0.5, f"证书剩余 {days} 天，请尽快续期"
        elif days >= 0:
            return "fail", 0.0, f"证书仅剩 {days} 天（紧急）"
        else:
            return "fail", 0.0, f"证书已过期 {abs(days)} 天"

    return "unknown", 0.0, "检测类型未知"


def evaluate(tls_detail: dict) -> dict:
    """
    对照等保2.0条款评估TLS实测数据，返回结构化结果。

    Returns:
        {
            score: float,           # 合规得分 0-100
            level: str,             # 达标等级 优秀/良好/需整改/不达标
            total_weight: int,
            earned_weight: float,
            clauses: List[dict],    # 每条条款的评估结果
            pass_count: int,
            warn_count: int,
            fail_count: int,
            unknown_count: int,
            categories: dict,       # 按类别分组的结果
        }
    """
    total_weight  = sum(c["weight"] for c in _CLAUSES)
    earned_weight = 0.0
    results = []
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for clause in _CLAUSES:
        status, contrib, detail = _evaluate_clause(clause, tls_detail)
        earned_weight += contrib
        counts[status] += 1
        results.append({
            **clause,
            "status": status,
            "contrib": contrib,
            "detail": detail,
        })

    score = round(earned_weight / total_weight * 100, 1) if total_weight > 0 else 0.0

    if score >= 90:
        level = "优秀"
    elif score >= 75:
        level = "良好"
    elif score >= 60:
        level = "需整改"
    else:
        level = "不达标"

    # 按类别分组
    categories: Dict[str, List] = {}
    for r in results:
        cat = r["category"]
        categories.setdefault(cat, []).append(r)

    return {
        "score": score,
        "level": level,
        "total_weight": total_weight,
        "earned_weight": earned_weight,
        "clauses": results,
        "pass_count":    counts["pass"],
        "warn_count":    counts["warn"],
        "fail_count":    counts["fail"],
        "unknown_count": counts["unknown"],
        "categories": categories,
    }