"""
主动 TLS / HTTP 安全检测模块。

检测项及权重：
  证书有效性（含剩余天数）   25 %
  TLS 协议版本               20 %
  HTTP 安全响应头（6项）     35 %
  HTTPS 强制重定向           10 %
  证书透明度（SCT）          10 %

所有错误均被吞掉并记入 issues，保证 probe() 永远返回合法结构。
"""

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3

from src.utils.logger import get_logger

logger = get_logger(__name__)

# 关闭 verify=False 时的 InsecureRequestWarning，避免日志污染
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 权重 ──────────────────────────────────────────────────────────────────────
_W_CERT     = 0.25
_W_TLS_VER  = 0.20
_W_HEADERS  = 0.35
_W_REDIRECT = 0.10
_W_SCT      = 0.10

# TLS 版本得分表
_TLS_VERSION_SCORES: Dict[str, float] = {
    "TLSv1.3": 100.0,
    "TLSv1.2": 80.0,
    "TLSv1.1": 30.0,
    "TLSv1.0": 10.0,
    "SSLv3":    0.0,
    "SSLv2":    0.0,
}

# 安全响应头：头名（小写）→ 归一化权重（合计 1.0）
_SECURITY_HEADERS: Dict[str, float] = {
    "strict-transport-security": 0.25,
    "content-security-policy":   0.25,
    "x-frame-options":           0.20,
    "x-content-type-options":    0.15,
    "referrer-policy":           0.10,
    "permissions-policy":        0.05,
}

_HEADER_LABELS: Dict[str, str] = {
    "strict-transport-security": "HSTS",
    "content-security-policy":   "Content-Security-Policy",
    "x-frame-options":           "X-Frame-Options",
    "x-content-type-options":    "X-Content-Type-Options",
    "referrer-policy":           "Referrer-Policy",
    "permissions-policy":        "Permissions-Policy",
}


# ── 证书分析 ──────────────────────────────────────────────────────────────────

def _cert_score(cert_dict: Optional[Dict[str, Any]]) -> tuple:
    """返回 (score 0-100, days_remaining, issues)。"""
    if cert_dict is None:
        return 0.0, None, ["无法获取 TLS 证书信息"]

    issues: List[str] = []
    days_remaining: Optional[int] = None

    not_after = cert_dict.get("notAfter")
    if not_after:
        try:
            exp_ts = ssl.cert_time_to_seconds(not_after)
            days_remaining = int((exp_ts - time.time()) / 86400)
            if days_remaining < 0:
                issues.append(f"证书已过期（{abs(days_remaining)} 天前）")
                return 0.0, days_remaining, issues
            elif days_remaining < 7:
                issues.append(f"证书即将过期（仅剩 {days_remaining} 天）")
                score = 10.0
            elif days_remaining < 30:
                issues.append(f"证书有效期较短（剩余 {days_remaining} 天）")
                score = 50.0
            elif days_remaining < 90:
                score = 80.0
            else:
                score = 100.0
        except Exception:
            issues.append("证书有效期解析失败")
            score = 50.0
    else:
        issues.append("未找到证书有效期字段")
        score = 40.0

    return score, days_remaining, issues


def _check_sct(der_bytes: bytes) -> bool:
    """检测 DER 证书是否含 SCT 扩展（OID 1.3.6.1.4.1.11129.2.4.2）。"""
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der_bytes)
        SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
        cert.extensions.get_extension_for_oid(SCT_OID)
        return True
    except Exception:
        return False


def _get_cert_and_tls(hostname: str, port: int, timeout: int) -> tuple:
    """返回 (cert_dict, tls_version, has_sct, issues)。"""
    issues: List[str] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
                cert_dict   = ssock.getpeercert()
                tls_version = ssock.version()
                has_sct = False
                try:
                    has_sct = _check_sct(ssock.getpeercert(binary_form=True))
                except Exception:
                    pass
                return cert_dict, tls_version, has_sct, issues
    except ssl.SSLCertVerificationError as e:
        issues.append(f"证书验证失败：{e.reason}")
    except ssl.SSLError as e:
        issues.append(f"TLS 握手错误：{e}")
    except (socket.timeout, TimeoutError):
        issues.append("TLS 连接超时")
    except ConnectionRefusedError:
        issues.append("目标拒绝 TLS 连接（端口不可达）")
    except Exception as e:
        issues.append(f"TLS 探测异常：{type(e).__name__}: {e}")
    return None, None, False, issues


# ── HTTP 安全头 ───────────────────────────────────────────────────────────────

def _header_score(headers: Dict[str, str]) -> tuple:
    """返回 (score 0-100, flags {header: bool}, issues)。"""
    lower = {k.lower(): v for k, v in headers.items()}
    issues: List[str] = []
    flags: Dict[str, bool] = {}
    weighted_sum = 0.0

    for header, weight in _SECURITY_HEADERS.items():
        present = header in lower
        flags[header] = present
        if present:
            weighted_sum += weight
        else:
            issues.append(f"缺少安全响应头：{_HEADER_LABELS.get(header, header)}")

    return round(weighted_sum * 100.0, 2), flags, issues


# ── HTTPS 重定向 ──────────────────────────────────────────────────────────────

def _check_https_redirect(url: str, timeout: int) -> tuple:
    """返回 (redirects_to_https: bool, issues)。"""
    issues: List[str] = []
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
    if parsed.query:
        http_url += f"?{parsed.query}"
    try:
        resp = requests.get(
            http_url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "SituationalAwareness-TLSProbe/1.0"},
            verify=False,
        )
        if resp.url.startswith("https://"):
            return True, issues
        issues.append("HTTP 未强制跳转至 HTTPS")
        return False, issues
    except requests.exceptions.SSLError:
        return True, issues  # 有跳转，但证书问题，视为重定向存在
    except Exception as e:
        issues.append(f"HTTPS 重定向检测失败：{e}")
        return False, issues


# ── 公共 API ──────────────────────────────────────────────────────────────────

def probe(target: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
    """
    对目标 URL 执行 TLS / HTTP 安全全面检测。
    返回结构与其他 probe 函数一致，value 为 0–100 综合安全分。
    detail 字段含各子项得分和问题清单，供 UI 展示。
    """
    url  = target.get("url", "")
    name = target.get("name", url)
    ts   = datetime.now(timezone.utc).isoformat()

    base: Dict[str, Any] = {
        "target_name":  name,
        "target_url":   url,
        "target_ip":    target.get("ip", ""),
        "metric_type":  "tls_security",
        "unit":         "score",
        "status_code":  None,
        "collected_at": ts,
        "value":        0.0,
        "detail":       {},
    }

    if not url:
        base["detail"] = {"issues": ["目标未配置 URL"]}
        return base

    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"

    all_issues: List[str] = []

    # ── 1. TLS 握手：证书 + 协议版本 + SCT ────────────────────────────────────
    if is_https:
        cert_dict, tls_version, has_sct, tls_issues = _get_cert_and_tls(
            hostname, port=443, timeout=timeout
        )
        all_issues.extend(tls_issues)
    else:
        cert_dict, tls_version, has_sct = None, None, False
        all_issues.append("目标使用明文 HTTP，无 TLS 加密")

    cert_score_val, days_remaining, cert_issues = _cert_score(cert_dict)
    all_issues.extend(cert_issues)

    tls_ver_score = 0.0
    if tls_version:
        tls_ver_score = _TLS_VERSION_SCORES.get(tls_version, 40.0)
        if tls_version in ("TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"):
            all_issues.append(f"使用不安全的 TLS 版本：{tls_version}（建议升级至 TLSv1.2+）")
    elif is_https:
        all_issues.append("无法确定 TLS 协议版本")

    sct_score = 100.0 if has_sct else 60.0
    if not has_sct and is_https:
        all_issues.append("未检测到证书透明度（CT/SCT）扩展")

    # ── 2. HTTP 安全响应头 ─────────────────────────────────────────────────────
    header_score_val = 0.0
    header_flags: Dict[str, bool] = {h: False for h in _SECURITY_HEADERS}
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "SituationalAwareness-TLSProbe/1.0"},
            verify=False,
        )
        header_score_val, header_flags, head_issues = _header_score(dict(resp.headers))
        all_issues.extend(head_issues)
    except Exception as e:
        all_issues.append(f"HTTP 头部检测失败：{e}")

    # ── 3. HTTPS 强制重定向 ────────────────────────────────────────────────────
    https_redirect, redir_issues = _check_https_redirect(url, timeout=timeout)
    all_issues.extend(redir_issues)
    redirect_score = 100.0 if https_redirect else 0.0

    # ── 综合评分 ───────────────────────────────────────────────────────────────
    final_score = round(
        cert_score_val   * _W_CERT
        + tls_ver_score  * _W_TLS_VER
        + header_score_val * _W_HEADERS
        + redirect_score * _W_REDIRECT
        + sct_score      * _W_SCT,
        2,
    )

    detail: Dict[str, Any] = {
        "cert_valid":             cert_dict is not None,
        "cert_days_remaining":    days_remaining,
        "tls_version":            tls_version,
        "tls_version_score":      tls_ver_score,
        "hsts":                   header_flags.get("strict-transport-security", False),
        "csp":                    header_flags.get("content-security-policy", False),
        "x_frame_options":        header_flags.get("x-frame-options", False),
        "x_content_type_options": header_flags.get("x-content-type-options", False),
        "referrer_policy":        header_flags.get("referrer-policy", False),
        "permissions_policy":     header_flags.get("permissions-policy", False),
        "https_redirect":         https_redirect,
        "has_sct":                has_sct,
        "header_score":           header_score_val,
        "cert_score":             cert_score_val,
        "final_score":            final_score,
        "issues":                 all_issues,
    }

    base["value"]  = final_score
    base["detail"] = detail

    logger.info(
        "TLS probe %s: score=%.1f tls=%s cert_days=%s headers=%.0f redirect=%s sct=%s issues=%d",
        name, final_score, tls_version, days_remaining,
        header_score_val, https_redirect, has_sct, len(all_issues),
    )
    return base