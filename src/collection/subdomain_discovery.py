"""
被动子域名/资产发现模块。

数据来源：crt.sh 证书透明度日志公开查询接口（https://crt.sh/?q=...&output=json）。
证书透明度（Certificate Transparency）要求所有公开签发的 HTTPS 证书必须记录进
公开日志，crt.sh 提供该日志的检索服务。查询过程只读取第三方已公开的历史证书
记录，不会向被监测目标发出任何请求，属于纯被动侦察，不需要目标授权。

发现的子域名写入 discovered_assets 表，供采集主流程自动纳入 HTTP/TLS/内容
完整性监测，从而把"只监测配置文件里手动填写的一个入口"扩展为
"自动发现并持续监测该域名下的所有对外暴露子系统"。
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)

_CRTSH_URL = "https://crt.sh/"
_TIMEOUT = 20

# 通配符 / 无意义前缀，发现结果中过滤掉
_SKIP_PREFIXES = ("*.", "_dmarc.", "_domainkey.")


def _extract_root_domain(url: str) -> str:
    """从 URL 提取注册域名（简单启发式：取最后两段，不处理特殊后缀如 .edu.cn）。"""
    hostname = urlparse(url).hostname or ""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # 常见国内多段后缀（.edu.cn / .gov.cn / .com.cn 等）保留三段
    if parts[-2] in ("edu", "gov", "com", "org", "net") and parts[-1] == "cn":
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname
    return ".".join(parts[-2:])


def _query_crtsh(root_domain: str) -> List[Dict[str, Any]]:
    """查询 crt.sh JSON 接口，返回原始证书记录列表。"""
    try:
        resp = requests.get(
            _CRTSH_URL,
            params={"q": f"%.{root_domain}", "output": "json"},
            timeout=_TIMEOUT,
            headers={"User-Agent": "SituationalAwareness-PassiveRecon/1.0"},
        )
        if resp.status_code != 200:
            logger.warning("crt.sh returned %d for domain %s", resp.status_code, root_domain)
            return []
        return resp.json()
    except requests.exceptions.Timeout:
        logger.warning("crt.sh query timeout for domain %s", root_domain)
    except Exception as exc:
        logger.error("crt.sh query error for %s: %s", root_domain, exc)
    return []


def _parse_subdomains(records: List[Dict[str, Any]], root_domain: str) -> Set[str]:
    """从证书记录的 name_value 字段中提取合法子域名，去重、去通配符。"""
    found: Set[str] = set()
    name_pattern = re.compile(r"^[a-z0-9.\-]+$")

    for rec in records:
        raw = rec.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower()
            if not name or not name.endswith(root_domain):
                continue
            if any(name.startswith(p) for p in _SKIP_PREFIXES):
                continue
            if not name_pattern.match(name):
                continue
            found.add(name)

    return found


def discover(target: Dict[str, Any]) -> List[str]:
    """
    对单个 target 执行被动子域名发现，返回新发现的子域名列表（含主域名本身）。
    不写数据库，纯查询 + 解析。
    """
    url = target.get("url", "")
    root_domain = _extract_root_domain(url)
    if not root_domain:
        return []

    records = _query_crtsh(root_domain)
    subdomains = _parse_subdomains(records, root_domain)

    logger.info("被动子域名发现 %s (%s): 共 %d 个子域名", target.get("name"), root_domain, len(subdomains))
    return sorted(subdomains)


def sync_assets(target: Dict[str, Any], db_path: str, max_new: int = 15) -> List[str]:
    """
    发现子域名并写入/更新 discovered_assets 表。
    为避免单个域名下证书记录过多（大机构常见），限制单次同步新增数量。
    返回本次新增（此前未记录过）的子域名列表。
    """
    from src.storage import db as storage_db

    target_name = target.get("name", "")
    url = target.get("url", "")
    root_domain = _extract_root_domain(url)
    if not root_domain:
        return []

    subdomains = discover(target)
    if not subdomains:
        return []

    ts = datetime.now(timezone.utc).isoformat()
    new_subs: List[str] = []

    for sub in subdomains:
        existing = storage_db.query_df(
            db_path,
            "SELECT subdomain FROM discovered_assets WHERE target_name=? AND subdomain=?",
            (target_name, sub),
        )
        if existing.empty:
            if len(new_subs) >= max_new:
                continue
            new_subs.append(sub)
            storage_db.execute(
                db_path,
                """INSERT INTO discovered_assets
                   (target_name, root_domain, subdomain, source, first_seen, last_seen)
                   VALUES (?, ?, ?, 'crt.sh', ?, ?)""",
                (target_name, root_domain, sub, ts, ts),
            )
        else:
            storage_db.execute(
                db_path,
                "UPDATE discovered_assets SET last_seen=? WHERE target_name=? AND subdomain=?",
                (ts, target_name, sub),
            )

    if new_subs:
        logger.info("目标 %s 新增被动发现资产 %d 个：%s", target_name, len(new_subs), new_subs)

    return new_subs


def get_assets(db_path: str, target_name: str) -> List[Dict[str, Any]]:
    """返回某目标当前已发现的所有子域名资产，供 UI 展示。"""
    from src.storage import db as storage_db
    df = storage_db.query_df(
        db_path,
        "SELECT subdomain, root_domain, source, first_seen, last_seen "
        "FROM discovered_assets WHERE target_name=? ORDER BY subdomain",
        (target_name,),
    )
    return df.to_dict("records") if not df.empty else []