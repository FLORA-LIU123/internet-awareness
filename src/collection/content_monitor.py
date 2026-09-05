"""
网页内容完整性检测模块。

每次采集时抓取目标页面 HTML，计算 SHA-256 哈希，与数据库中
上一次快照比对。内容变化时返回变化摘要，供 engine 触发告警。

检测逻辑：
  1. 抓取页面正文（去掉动态时间戳、CSRF token 等噪声）
  2. 计算 SHA-256 哈希
  3. 与上次哈希比对
  4. 变化时提取差异摘要（新增/消失的关键词）

站内多页面覆盖：probe() 默认只检测首页。crawl_and_monitor() 额外从首页
解析同域名下的公开链接（<a href>），对发现的若干个子页面同样做哈希比对，
把"只盯首页"扩展为"覆盖站内多个公开页面"。抓取行为等价于一次正常的
浏览器点击浏览，纯被动只读，不需要额外授权。
"""

import hashlib
import html as html_module
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)

# 抓取超时
_TIMEOUT = 15

# 过滤掉页面中会频繁变化但不代表内容篡改的噪声模式
# 例如：动态时间戳、CSRF token 隐藏字段、访问计数器
_NOISE_PATTERNS = [
    re.compile(r'<input[^>]+name=["\']csrf[^>]+>', re.I),
    re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'),  # 时间戳
    re.compile(r'访问量[:：]\s*[\d,]+', re.I),
    re.compile(r'访问次数[:：]\s*[\d,]+', re.I),
    re.compile(r'var\s+\w+\s*=\s*["\']?[\w-]{20,}["\']?\s*;'),  # JS token
]

# 用于提取页面关键文本的标签（去掉脚本、样式、注释）
_STRIP_TAGS = re.compile(r'<(script|style)[^>]*>.*?</\1>', re.S | re.I)
_STRIP_HTML  = re.compile(r'<[^>]+>')
_COLLAPSE    = re.compile(r'\s+')

# 高风险关键词：出现在页面上可能代表被篡改
_RISK_KEYWORDS = [
    "黑客", "hack", "hacked", "pwned", "deface",
    "赌博", "博彩", "色情", "成人", "贷款", "刷单",
    "比特币", "虚拟货币", "暗网",
    "病毒", "木马", "勒索",
]


def _clean_html(html: str) -> str:
    """去除脚本/样式/注释，剥离 HTML 标签，折叠空白，过滤噪声。"""
    text = _STRIP_TAGS.sub(" ", html)
    # 去注释
    text = re.sub(r'<!--.*?-->', ' ', text, flags=re.S)
    # 过滤噪声
    for pat in _NOISE_PATTERNS:
        text = pat.sub(" ", text)
    text = _STRIP_HTML.sub(" ", text)
    text = _COLLAPSE.sub(" ", text).strip()
    return text


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _extract_risk_keywords(text: str) -> list:
    """返回页面中出现的高风险关键词列表。"""
    found = []
    text_lower = text.lower()
    for kw in _RISK_KEYWORDS:
        if kw.lower() in text_lower:
            found.append(kw)
    return found


def _build_change_summary(old_text: str, new_text: str, new_html: str) -> str:
    """生成内容变化摘要：内容长度变化 + 高风险关键词 + 简要差异。"""
    parts = []

    old_len = len(old_text)
    new_len = len(new_text)
    diff = new_len - old_len
    if abs(diff) > 50:
        direction = "增加" if diff > 0 else "减少"
        parts.append(f"页面文本{direction}约 {abs(diff)} 字符")

    risk_kws = _extract_risk_keywords(new_text)
    if risk_kws:
        parts.append(f"检测到高风险关键词：{'、'.join(risk_kws)}")

    # 标题变化
    title_match = re.search(r'<title[^>]*>(.*?)</title>', new_html, re.I | re.S)
    if title_match:
        new_title = title_match.group(1).strip()
        old_title_match = re.search(r'<title[^>]*>(.*?)</title>',
                                     old_text[:2000] if len(old_text) > 2000 else old_text,
                                     re.I | re.S)
        # old_text 是已清洗的文本，无法提取标题；仅报告新标题供参考
        if new_title:
                new_title = html_module.unescape(new_title)
                parts.append(f"当前页面标题：「{new_title[:60]}」")

    if not parts:
        parts.append("页面内容发生变化（具体差异需人工核实）")

    return "；".join(parts)


def _fetch_page(url: str, timeout: int) -> Optional[Any]:
    resp = requests.get(
        url, timeout=timeout,
        headers={"User-Agent": "SituationalAwareness-ContentMonitor/1.0"},
        allow_redirects=True,
        verify=False,
    )
    if resp.encoding and resp.encoding.lower() == "iso-8859-1":
        resp.encoding = resp.apparent_encoding or "utf-8"
    return resp


def _extract_links(html: str, base_url: str, max_links: int = 8) -> List[str]:
    """从首页 HTML 中解析同域名下的公开链接，去重、去锚点/资源文件，最多返回 max_links 个。"""
    base_host = urlparse(base_url).hostname or ""
    hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I)

    seen: Dict[str, None] = {}
    for href in hrefs:
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.hostname != base_host:
            continue
        if re.search(r'\.(jpg|jpeg|png|gif|css|js|pdf|zip|rar|doc|docx|xls|xlsx|ico|svg)$',
                     parsed.path, re.I):
            continue
        if full == base_url:
            continue
        if full not in seen:
            seen[full] = None
        if len(seen) >= max_links:
            break

    return list(seen.keys())


def probe(target: Dict[str, Any], db_path: str, timeout: int = _TIMEOUT) -> Dict[str, Any]:
    """
    抓取目标首页，计算哈希，与上次快照比对。
    将本次快照写入 content_snapshots 表，并返回结构化结果。
    """
    from src.storage import db as storage_db

    url  = target.get("url", "")
    name = target.get("name", url)
    ts   = datetime.now(timezone.utc).isoformat()

    base: Dict[str, Any] = {
        "target_name":  name,
        "target_url":   url,
        "page_path":    "",  # 空字符串代表首页
        "content_hash": "",
        "content_length": 0,
        "status_code":  None,
        "changed":      False,
        "prev_hash":    None,
        "change_summary": None,
        "collected_at": ts,
    }

    if not url:
        return base

    # ── 抓取页面 ──────────────────────────────────────────────────────────────
    try:
        resp = _fetch_page(url, timeout)
        status_code = resp.status_code
        html = resp.text
    except Exception as exc:
        logger.warning("Content monitor fetch error for %s: %s", name, exc)
        _store_snapshot(storage_db, db_path, {**base, "change_summary": f"抓取失败：{exc}"})
        return base

    base["status_code"] = status_code

    # ── 清洗 & 哈希 ───────────────────────────────────────────────────────────
    clean_text  = _clean_html(html)
    current_hash = _sha256(clean_text)
    base["content_hash"]   = current_hash
    base["content_length"] = len(clean_text)

    # ── 读取上次快照 ──────────────────────────────────────────────────────────
    prev = _get_last_snapshot(storage_db, db_path, name, "")

    if prev is None:
        # 首次采集，建立基线快照
        base["changed"] = False
        base["change_summary"] = "首次采集，已建立内容基线"
        logger.info("Content baseline established for %s (hash=%s)", name, current_hash[:12])
    elif prev["content_hash"] == current_hash:
        base["changed"] = False
        base["prev_hash"] = prev["content_hash"]
        logger.info("Content unchanged for %s", name)
    else:
        # 内容发生变化
        summary = _build_change_summary(
            prev.get("_clean_text", ""), clean_text, html
        )
        base["changed"]        = True
        base["prev_hash"]      = prev["content_hash"]
        base["change_summary"] = summary
        logger.warning("Content CHANGED for %s: %s", name, summary)

    _store_snapshot(storage_db, db_path, base)

    # ── 精细完整性检测（语义区域哈希 + 关键词注入检测） ─────────────────────
    try:
        _store_integrity_check(storage_db, db_path, name, url, html, clean_text, ts)
    except Exception as exc:
        logger.warning("Integrity check error for %s: %s", name, exc)

    # ── 站内多页面覆盖 ─────────────────────────────────────────────────────────
    try:
        base["sub_pages"] = crawl_subpages(target, db_path, html, timeout)
    except Exception as exc:
        logger.warning("Sub-page crawl error for %s: %s", name, exc)
        base["sub_pages"] = []

    return base


def crawl_subpages(target: Dict[str, Any], db_path: str, home_html: str,
                    timeout: int = _TIMEOUT, max_links: int = 8) -> List[Dict[str, Any]]:
    """
    从首页 HTML 解析同域名下的公开链接，对每个子页面同样做哈希比对。
    与 probe() 分离，便于独立调用/测试；被 probe() 在检测完首页后自动触发。
    """
    from src.storage import db as storage_db

    url  = target.get("url", "")
    name = target.get("name", url)
    if not url:
        return []

    links = _extract_links(home_html, url, max_links=max_links)
    results: List[Dict[str, Any]] = []

    for link in links:
        path = urlparse(link).path or "/"
        ts = datetime.now(timezone.utc).isoformat()
        entry: Dict[str, Any] = {
            "target_name":  name,
            "target_url":   link,
            "page_path":    path,
            "content_hash": "",
            "content_length": 0,
            "status_code":  None,
            "changed":      False,
            "prev_hash":    None,
            "change_summary": None,
            "collected_at": ts,
        }
        try:
            resp = _fetch_page(link, timeout)
            entry["status_code"] = resp.status_code
            clean_text = _clean_html(resp.text)
            current_hash = _sha256(clean_text)
            entry["content_hash"]   = current_hash
            entry["content_length"] = len(clean_text)

            prev = _get_last_snapshot(storage_db, db_path, name, path)
            if prev is None:
                entry["change_summary"] = "首次采集，已建立内容基线"
            elif prev["content_hash"] == current_hash:
                entry["prev_hash"] = prev["content_hash"]
            else:
                entry["changed"] = True
                entry["prev_hash"] = prev["content_hash"]
                entry["change_summary"] = _build_change_summary("", clean_text, resp.text)
                logger.warning("Content CHANGED for %s%s: %s", name, path, entry["change_summary"])
        except Exception as exc:
            entry["change_summary"] = f"抓取失败：{exc}"
            logger.warning("Sub-page fetch error for %s (%s): %s", name, link, exc)

        _store_snapshot(storage_db, db_path, entry)
        results.append(entry)

    return results


def _get_last_snapshot(storage_db, db_path: str, target_name: str,
                        page_path: str = "") -> Optional[Dict[str, Any]]:
    """取指定页面（首页或子页面）上一次成功的快照记录。"""
    df = storage_db.query_df(
        db_path,
        "SELECT content_hash, content_length, collected_at FROM content_snapshots "
        "WHERE target_name=? AND page_path=? AND content_hash != '' "
        "ORDER BY collected_at DESC LIMIT 1",
        (target_name, page_path),
    )
    if df.empty:
        return None
    row = df.iloc[0]
    return {
        "content_hash":   row["content_hash"],
        "content_length": row["content_length"],
        "collected_at":   row["collected_at"],
        "_clean_text":    "",  # 历史文本不存储，仅用哈希比对
    }


def _store_snapshot(storage_db, db_path: str, data: Dict[str, Any]) -> None:
    """将本次快照写入数据库。"""
    try:
        storage_db.execute(
            db_path,
            """INSERT INTO content_snapshots
               (target_name, target_url, page_path, content_hash, content_length,
                status_code, changed, prev_hash, change_summary, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["target_name"],
                data["target_url"],
                data.get("page_path", ""),
                data["content_hash"],
                data.get("content_length", 0),
                data.get("status_code"),
                1 if data.get("changed") else 0,
                data.get("prev_hash"),
                data.get("change_summary"),
                data["collected_at"],
            ),
        )
    except Exception as exc:
        logger.error("Failed to store content snapshot for %s: %s", data["target_name"], exc)


def _store_integrity_check(storage_db, db_path: str, target_name: str,
                           target_url: str, html: str, clean_text: str,
                           checked_at: str) -> None:
    """
    精细完整性检测：语义区域哈希 + 关键词注入检测。
    将页面分为 header/nav、main content、footer 三个区域分别哈希，
    检测高风险关键词注入，计算篡改评分，写入 content_integrity_checks 表。
    """
    import json

    # 语义区域划分（简化版：按 HTML 结构特征分割）
    regions = {}

    # Header/Nav 区域
    header_match = re.search(
        r'<(header|nav|div[^>]*class=["\']?(?:header|nav|top))[^>]*>.*?</\1>',
        html, re.S | re.I
    )
    if header_match:
        regions["header"] = _sha256(_clean_html(header_match.group(0)))

    # Main content 区域
    main_match = re.search(
        r'<(main|article|div[^>]*class=["\']?(?:content|main|body))[^>]*>.*?</\1>',
        html, re.S | re.I
    )
    if main_match:
        regions["main"] = _sha256(_clean_html(main_match.group(0)))

    # Footer 区域
    footer_match = re.search(
        r'<(footer|div[^>]*class=["\']?(?:footer|bottom))[^>]*>.*?</\1>',
        html, re.S | re.I
    )
    if footer_match:
        regions["footer"] = _sha256(_clean_html(footer_match.group(0)))

    # 如果没有找到明确的区域标记，用整体内容
    if not regions:
        regions["full"] = _sha256(clean_text)

    # 关键词注入检测
    injected_kws = _extract_risk_keywords(clean_text)

    # 篡改评分计算
    tamper_score = 0.0
    if injected_kws:
        # 高风险关键词注入：每个关键词 +20 分
        tamper_score += len(injected_kws) * 20.0

    # 检查是否有异常的外部链接注入
    external_links = re.findall(
        r'<a[^>]+href=["\']?(https?://[^"\'<>\s]+)',
        html, re.I
    )
    suspicious_domains = ["bit.ly", "tinyurl", "goo.gl", "is.gd"]
    for link in external_links:
        for domain in suspicious_domains:
            if domain in link.lower():
                tamper_score += 10.0
                break

    # 检查是否有异常的 iframe 或 script 注入
    iframes = re.findall(r'<iframe[^>]*>', html, re.I)
    if len(iframes) > 3:
        tamper_score += 15.0

    tamper_score = min(tamper_score, 100.0)

    try:
        storage_db.execute(
            db_path,
            """INSERT INTO content_integrity_checks
               (target_name, target_url, region_hashes, injected_kws,
                tamper_score, checked_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                target_name,
                target_url,
                json.dumps(regions, ensure_ascii=False),
                json.dumps(injected_kws, ensure_ascii=False),
                tamper_score,
                checked_at,
            ),
        )
    except Exception as exc:
        logger.error("Failed to store integrity check for %s: %s", target_name, exc)


def get_latest_snapshots(db_path: str) -> list:
    """返回每个目标首页最新一次快照，供 UI 总览展示用。"""
    from src.storage import db as storage_db
    df = storage_db.query_df(
        db_path,
        """SELECT s.target_name, s.content_hash, s.content_length,
                  s.status_code, s.changed, s.change_summary, s.collected_at
           FROM content_snapshots s
           INNER JOIN (
               SELECT target_name, MAX(collected_at) AS latest
               FROM content_snapshots
               WHERE page_path = ''
               GROUP BY target_name
           ) m ON s.target_name = m.target_name AND s.collected_at = m.latest
           WHERE s.page_path = ''
           ORDER BY s.target_name""",
    )
    return df.to_dict("records") if not df.empty else []


def get_latest_subpage_snapshots(db_path: str, target_name: str) -> list:
    """返回某目标下所有已监测子页面的最新快照，供 UI 展示站内覆盖情况。"""
    from src.storage import db as storage_db
    df = storage_db.query_df(
        db_path,
        """SELECT s.target_url, s.page_path, s.content_hash, s.content_length,
                  s.status_code, s.changed, s.change_summary, s.collected_at
           FROM content_snapshots s
           INNER JOIN (
               SELECT page_path, MAX(collected_at) AS latest
               FROM content_snapshots
               WHERE target_name = ? AND page_path != ''
               GROUP BY page_path
           ) m ON s.page_path = m.page_path AND s.collected_at = m.latest
           WHERE s.target_name = ? AND s.page_path != ''
           ORDER BY s.page_path""",
        (target_name, target_name),
    )
    return df.to_dict("records") if not df.empty else []


def get_change_history(db_path: str, target_name: str, hours: int = 168) -> list:
    """返回某目标最近 N 小时内发生变化的快照记录（含首页与子页面）。"""
    from datetime import timedelta
    from src.storage import db as storage_db
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = storage_db.query_df(
        db_path,
        "SELECT target_name, page_path, content_hash, content_length, changed, "
        "change_summary, collected_at FROM content_snapshots "
        "WHERE target_name=? AND collected_at>=? AND changed=1 "
        "ORDER BY collected_at DESC",
        (target_name, since),
    )
    return df.to_dict("records") if not df.empty else []