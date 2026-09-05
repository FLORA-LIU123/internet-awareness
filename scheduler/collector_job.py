"""
Background collection scheduler.

Run standalone:
    python -m scheduler.collector_job

Or import and call start_scheduler() to run as a background thread
inside the Streamlit process.

Collects data three times daily (default: 08:00, 12:00, 20:00).
Also runs once immediately on startup to ensure data is available.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from src.collection import (
    http_probe, icmp_probe, speed_test, threat_intel, tls_probe,
    content_monitor, subdomain_discovery, threat_correlation,
)
from src.processing import cleaner, fusion, normalizer
from src.prediction import risk_forecast
from src.rules import engine, adaptive_baseline
from src.scoring import health_score
from src.storage import db
from src.utils.config_loader import Config
from src.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)

_scheduler_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _store_raw(records: List[Dict[str, Any]], db_path: str) -> None:
    for r in records:
        if not isinstance(r, dict):
            continue
        db.execute(
            db_path,
            """INSERT INTO raw_metrics
               (target_name, target_url, target_ip, metric_type, value, unit,
                status_code, collected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                r.get("target_name", ""),
                r.get("target_url", ""),
                r.get("target_ip", ""),
                r.get("metric_type", ""),
                r.get("value"),
                r.get("unit", ""),
                r.get("status_code"),
                r.get("collected_at", datetime.now(timezone.utc).isoformat()),
            ),
        )


def run_collection_cycle() -> None:
    cfg = Config.get()
    db_path = cfg.db_path
    targets = cfg.targets
    otx_key = cfg.get_setting("threat_intel", "otx_api_key", default="")
    timeout = cfg.get_setting("collection", "http_timeout_seconds", default=10)
    icmp_count = cfg.get_setting("collection", "icmp_count", default=4)
    weight_overrides = cfg.weights

    raw_records: List[Dict[str, Any]] = []

    for target in targets:
        probe_type = target.get("type", "both")

        if probe_type in ("http", "both"):
            http_result = http_probe.probe(target, timeout=timeout)
            # Convert HTTP result to raw_metrics format
            http_raw = {
                "target_name": http_result["target_name"],
                "target_url": http_result["target_url"],
                "target_ip": http_result["target_ip"],
                "metric_type": "response_time_ms",
                "value": http_result["value"],
                "unit": "ms",
                "status_code": http_result["status_code"],
                "collected_at": http_result["collected_at"],
            }
            avail_raw = {
                **http_raw,
                "metric_type": "http",
                "value": 100.0 if http_result.get("available") else 0.0,
                "unit": "score",
            }
            raw_records.extend([http_raw, avail_raw])

            # TLS / HTTP security probe — runs immediately after HTTP probe
            tls_result = tls_probe.probe(target, timeout=timeout)
            tls_base = {
                "target_name":  tls_result["target_name"],
                "target_url":   tls_result["target_url"],
                "target_ip":    tls_result["target_ip"],
                "status_code":  None,
                "collected_at": tls_result["collected_at"],
            }
            # 综合安全分
            raw_records.append({**tls_base, "metric_type": "tls_security",
                                 "value": tls_result["value"], "unit": "score"})

            # 拆存 TLS 子项，供 insights 页面读取实测数据生成具体建议
            detail = tls_result.get("detail", {})
            if detail:
                # 证书剩余天数（负数 = 已过期）
                days = detail.get("cert_days_remaining")
                if days is not None:
                    raw_records.append({**tls_base, "metric_type": "tls_cert_days",
                                        "value": float(days), "unit": "days"})
                # TLS 协议版本分
                raw_records.append({**tls_base, "metric_type": "tls_version_score",
                                     "value": float(detail.get("tls_version_score") or 0),
                                     "unit": "score"})
                # HTTP 安全响应头综合分
                raw_records.append({**tls_base, "metric_type": "tls_header_score",
                                     "value": float(detail.get("header_score") or 0),
                                     "unit": "score"})
                # 各安全响应头是否存在（1=有，0=无）
                for hdr in ("hsts", "csp", "x_frame_options",
                            "x_content_type_options", "referrer_policy", "permissions_policy"):
                    raw_records.append({**tls_base,
                                        "metric_type": f"tls_hdr_{hdr}",
                                        "value": 1.0 if detail.get(hdr) else 0.0,
                                        "unit": "bool"})
                # HTTPS 强制重定向
                raw_records.append({**tls_base, "metric_type": "tls_https_redirect",
                                     "value": 1.0 if detail.get("https_redirect") else 0.0,
                                     "unit": "bool"})
                # 证书透明度 SCT
                raw_records.append({**tls_base, "metric_type": "tls_sct",
                                     "value": 1.0 if detail.get("has_sct") else 0.0,
                                     "unit": "bool"})

        if probe_type in ("icmp", "both"):
            icmp_results = icmp_probe.probe(target, count=icmp_count)
            if isinstance(icmp_results, list):
                raw_records.extend(icmp_results)
            else:
                raw_records.append(icmp_results)

        threat_result = threat_intel.probe(target, api_key=otx_key)
        raw_records.append(threat_result)

    _store_raw(raw_records, db_path)

    cleaned = cleaner.clean(raw_records)
    if cleaned.empty:
        logger.warning("No clean records after collection cycle")
        return

    normalised = normalizer.normalize_series(cleaned, db_path)
    fused = fusion.fuse_and_store(normalised, db_path)
    if fused.empty:
        return

    scores = health_score.compute_and_store(fused, db_path, weight_overrides)

    cfg_rules = cfg.get_setting("rules", default={})
    engine.evaluate(
        scores, fused, db_path,
        health_threshold=cfg_rules.get("health_score_threshold", 60.0),
        deviation_multiplier=cfg_rules.get("deviation_multiplier", 2.0),
        cooldown_minutes=cfg_rules.get("alert_cooldown_minutes", 10),
    )

    # 网页内容完整性检测（首页 + 站内多页面，独立于性能指标，单独执行）
    for target in targets:
        if target.get("type", "both") in ("http", "both"):
            try:
                result = content_monitor.probe(target, db_path,
                                               timeout=cfg.get_setting("collection", "http_timeout_seconds", default=10))
                cooldown = cfg_rules.get("alert_cooldown_minutes", 10)
                changed_pages = []
                if result.get("changed"):
                    changed_pages.append(result)
                for sub in result.get("sub_pages", []):
                    if sub.get("changed"):
                        changed_pages.append(sub)

                for page in changed_pages:
                    from src.rules.alert_manager import store_alert
                    page_label = page.get("target_url", "")
                    alert = {
                        "target_name": page["target_name"],
                        "rule_type":   "content_change",
                        "severity":    "critical",
                        "message":     f"网页内容发生变化：{page_label}",
                        "detail": (
                            f"变化摘要：{page['change_summary']}。\n"
                            f"① 立即访问网站确认页面内容是否正常，排查是否遭到篡改或挂马；\n"
                            f"② 检查 Web 服务器访问日志，确认变化时间点前后是否有异常来源 IP 的请求；\n"
                            f"③ 若确认被篡改，立即下线服务，从最近备份恢复，并修改所有管理员密码；\n"
                            f"④ 若为正常更新，可在告警管理页面确认处理，平台将重建内容基线。"
                        ),
                    }
                    store_alert(db_path, alert, cooldown)
            except Exception as exc:
                logger.warning("Content monitor error for %s: %s", target.get("name"), exc)

    # 被动子域名/资产发现（证书透明度日志查询，不主动访问目标，纯扩大感知面）
    for target in targets:
        try:
            new_assets = subdomain_discovery.sync_assets(target, db_path)
            if new_assets:
                from src.rules.alert_manager import store_alert
                alert = {
                    "target_name": target.get("name", ""),
                    "rule_type":   "new_asset_discovered",
                    "severity":    "warning",
                    "message":     f"发现 {len(new_assets)} 个新的对外暴露子域名",
                    "detail": (
                        f"新增子域名：{', '.join(new_assets)}。\n"
                        f"① 确认这些子域名是否为该单位授权运营的系统；\n"
                        f"② 若为未知/遗忘的历史系统，建议排查是否存在弱口令或未修补漏洞；\n"
                        f"③ 可前往「数据启示」页面查看该目标当前已发现的完整资产清单。"
                    ),
                }
                store_alert(db_path, alert, cfg_rules.get("alert_cooldown_minutes", 10))
        except Exception as exc:
            logger.warning("Subdomain discovery error for %s: %s", target.get("name"), exc)

    # 未来风险预警指数：融合健康度预测趋势、威胁情报趋势、内容篡改频率，
    # 区别于上面的规则引擎（检测当前已发生的异常），本步骤预测未来风险
    try:
        risk_forecast.compute_and_store(db_path, targets)
    except Exception as exc:
        logger.warning("Risk index computation error: %s", exc, exc_info=True)

    # ── 威胁情报跨目标关联分析 ──────────────────────────────────────────────
    try:
        current_threat_scores = {}
        for rec in raw_records:
            if rec.get("metric_type") == "threat_score" and rec.get("value") is not None:
                current_threat_scores[rec["target_name"]] = float(rec["value"])
        if current_threat_scores:
            corr_events = threat_correlation.compute_and_store(
                db_path, targets, current_threat_scores
            )
            if corr_events:
                from src.rules.alert_manager import store_alert
                for ev in corr_events:
                    if ev["type"] == "sync_threat":
                        store_alert(db_path, {
                            "target_name": ev["targets"][0],
                            "rule_type": "threat_correlation",
                            "severity": "critical" if ev["max_score"] >= 6 else "warning",
                            "message": f"跨目标威胁关联：{ev['pattern']}",
                            "detail": ev["detail"],
                        }, cfg_rules.get("alert_cooldown_minutes", 10))
    except Exception as exc:
        logger.warning("Threat correlation error: %s", exc)

    # ── 自适应基线更新（每轮采集后更新基线，每天重算一次完整基线） ────────────
    try:
        adaptive_baseline.update_baselines(db_path, targets)
    except Exception as exc:
        logger.warning("Adaptive baseline update error: %s", exc)

    # ── 攻击链推断（检测多阶段关联事件并存储） ────────────────────────────────
    try:
        from src.analysis import root_cause
        for target in targets:
            name = target.get("name", "")
            chain = root_cause.build_attack_chain(db_path, name, hours=48)
            if chain["events"] and len(chain["events"]) >= 2:
                # 检测多阶段攻击模式
                stages = [e["stage"] for e in chain["events"]]
                unique_stages = []
                for s in stages:
                    if s not in unique_stages:
                        unique_stages.append(s)

                # 至少 2 个不同阶段才记录
                if len(unique_stages) >= 2:
                    first_event = chain["events"][0]["time"]
                    last_event = chain["events"][-1]["time"]

                    # 计算置信度（基于阶段数量和事件密度）
                    confidence = min(len(unique_stages) / 4.0, 1.0)
                    if len(chain["events"]) >= 5:
                        confidence = min(confidence + 0.2, 1.0)

                    # 确定攻击链类型
                    if "疑似失陷" in unique_stages:
                        chain_type = "域名劫持/内容篡改"
                    elif "弱点暴露" in unique_stages and "异常行为" in unique_stages:
                        chain_type = "配置劣化→服务影响"
                    elif "侦察特征" in unique_stages:
                        chain_type = "定向攻击"
                    else:
                        chain_type = "异常关联"

                    detail = f"检测到 {len(unique_stages)} 阶段攻击链：{' → '.join(unique_stages)}"

                    try:
                        db.execute(
                            db_path,
                            """INSERT INTO attack_chains
                               (target_name, chain_type, stage_sequence, confidence,
                                first_event_at, last_event_at, detail, computed_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                name,
                                chain_type,
                                " → ".join(unique_stages),
                                confidence,
                                first_event.isoformat() if hasattr(first_event, "isoformat") else str(first_event),
                                last_event.isoformat() if hasattr(last_event, "isoformat") else str(last_event),
                                detail,
                                datetime.now(timezone.utc).isoformat(),
                            ),
                        )
                    except Exception as exc:
                        logger.warning("Failed to store attack chain for %s: %s", name, exc)
    except Exception as exc:
        logger.warning("Attack chain detection error: %s", exc)

    logger.info("Collection cycle complete — %d targets processed", len(targets))


def _get_interval_minutes() -> int:
    """从配置读取采集间隔（分钟），默认 60 分钟。"""
    cfg = Config.get()
    return int(cfg.get_setting("collection", "interval_minutes", default=60))


def _loop() -> None:
    while not _stop_event.is_set():
        interval = _get_interval_minutes()
        wait_seconds = interval * 60
        logger.info(
            "Next collection in %d minutes (interval=%d min)",
            interval, interval,
        )
        if _stop_event.wait(wait_seconds):
            break
        try:
            run_collection_cycle()
        except Exception as exc:
            logger.error("Collection cycle error: %s", exc, exc_info=True)


def start_scheduler() -> None:
    global _scheduler_thread, _stop_event
    if _scheduler_thread and _scheduler_thread.is_alive():
        return

    _stop_event.clear()

    # 启动时在独立线程里执行一次采集，不阻塞 Streamlit 页面渲染
    def _initial_collect():
        try:
            run_collection_cycle()
        except Exception as exc:
            logger.error("Initial collection cycle error: %s", exc, exc_info=True)

    threading.Thread(target=_initial_collect, daemon=True, name="collector-init").start()

    _scheduler_thread = threading.Thread(
        target=_loop, daemon=True, name="collector"
    )
    _scheduler_thread.start()
    interval = _get_interval_minutes()
    logger.info("Scheduler started (every %d minutes)", interval)


def stop_scheduler() -> None:
    _stop_event.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
    logger.info("Scheduler stopped")


if __name__ == "__main__":
    _cfg = Config.get()
    setup_logging(
        level=_cfg.get_setting("logging", "level", default="INFO"),
        log_file=_cfg.get_setting("logging", "file", default="logs/app.log"),
    )
    db.init_db(_cfg.db_path)
    logger.info("Starting standalone collector")
    _loop()
