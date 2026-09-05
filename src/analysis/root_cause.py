"""
根因关联分析模块
检测健康评分骤降事件，自动关联同时段的指标变化和告警，生成根因摘要。
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import pandas as pd

from src.storage import db


_DROP_THRESHOLD = 5.0   # 单次评分下降超过此值视为骤降事件
_WINDOW_MINUTES = 90    # 骤降前后各 N 分钟内查找关联变化


def _detect_drops(health_df: pd.DataFrame, target_name: str) -> List[Dict]:
    """找出某目标的健康评分骤降事件，返回列表。"""
    sub = health_df[health_df["target_name"] == target_name].copy()
    if sub.empty:
        return []
    sub = sub.sort_values("scored_at").reset_index(drop=True)
    events = []
    for i in range(1, len(sub)):
        prev_score = float(sub.loc[i - 1, "score"])
        curr_score = float(sub.loc[i, "score"])
        drop = prev_score - curr_score
        if drop >= _DROP_THRESHOLD:
            events.append({
                "time": sub.loc[i, "scored_at"],
                "from_score": prev_score,
                "to_score": curr_score,
                "drop": drop,
            })
    return events


def _find_tls_changes(db_path: str, target_name: str,
                      event_time: Any, window_minutes: int) -> List[str]:
    """在骤降时间点附近找出 TLS 子项变化。"""
    if isinstance(event_time, str):
        event_time = pd.to_datetime(event_time, utc=True)

    t_start = (event_time - timedelta(minutes=window_minutes)).isoformat()
    t_end   = (event_time + timedelta(minutes=window_minutes)).isoformat()

    tls_metrics = [
        "tls_security", "tls_cert_days", "tls_version_score", "tls_header_score",
        "tls_https_redirect", "tls_sct",
        "tls_hdr_hsts", "tls_hdr_csp", "tls_hdr_x_frame_options",
        "tls_hdr_x_content_type_options", "tls_hdr_referrer_policy",
        "tls_hdr_permissions_policy",
    ]
    _METRIC_LABELS = {
        "tls_security":                    "TLS综合评分",
        "tls_cert_days":                   "证书剩余天数",
        "tls_version_score":               "TLS协议版本评分",
        "tls_header_score":                "安全响应头评分",
        "tls_https_redirect":              "HTTPS强制重定向",
        "tls_sct":                         "证书透明度(SCT)",
        "tls_hdr_hsts":                    "HSTS响应头",
        "tls_hdr_csp":                     "CSP响应头",
        "tls_hdr_x_frame_options":         "X-Frame-Options响应头",
        "tls_hdr_x_content_type_options":  "X-Content-Type-Options响应头",
        "tls_hdr_referrer_policy":         "Referrer-Policy响应头",
        "tls_hdr_permissions_policy":      "Permissions-Policy响应头",
    }

    changes = []
    for m in tls_metrics:
        rows = db.query_df(
            db_path,
            "SELECT value, collected_at FROM raw_metrics "
            "WHERE target_name=? AND metric_type=? AND collected_at BETWEEN ? AND ? "
            "ORDER BY collected_at ASC",
            (target_name, m, t_start, t_end),
        )
        if len(rows) < 2:
            continue
        v_first = float(rows.iloc[0]["value"])
        v_last  = float(rows.iloc[-1]["value"])
        diff = v_last - v_first
        label = _METRIC_LABELS.get(m, m)
        if abs(diff) >= 0.5:
            direction = "下降" if diff < 0 else "上升"
            changes.append(f"{label} {direction} {abs(diff):.1f}（{v_first:.1f} → {v_last:.1f}）")

    return changes


def _find_related_alerts(db_path: str, target_name: str,
                         event_time: Any, window_minutes: int) -> List[str]:
    """找出骤降时间点附近触发的告警。"""
    if isinstance(event_time, str):
        event_time = pd.to_datetime(event_time, utc=True)

    t_start = (event_time - timedelta(minutes=window_minutes)).isoformat()
    t_end   = (event_time + timedelta(minutes=window_minutes)).isoformat()

    rows = db.query_df(
        db_path,
        "SELECT rule_type, severity, message, created_at FROM alerts "
        "WHERE target_name=? AND created_at BETWEEN ? AND ? ORDER BY created_at ASC",
        (target_name, t_start, t_end),
    )
    results = []
    for _, r in rows.iterrows():
        sev_label = {"critical": "严重", "warning": "警告", "info": "提示"}.get(r["severity"], r["severity"])
        results.append(f"[{sev_label}] {r['message']}")
    return results


def _find_metric_anomalies(db_path: str, target_name: str,
                            event_time: Any, window_minutes: int) -> List[str]:
    """找出骤降时间点附近的原始指标异常（可用性、响应时延等）。"""
    if isinstance(event_time, str):
        event_time = pd.to_datetime(event_time, utc=True)

    t_start = (event_time - timedelta(minutes=window_minutes)).isoformat()
    t_end   = (event_time + timedelta(minutes=window_minutes)).isoformat()

    anomalies = []

    # 可用性骤降
    rows = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='http' "
        "AND collected_at BETWEEN ? AND ? ORDER BY collected_at ASC",
        (target_name, t_start, t_end),
    )
    if not rows.empty:
        down = int((rows["value"] == 0).sum())
        if down > 0:
            anomalies.append(f"HTTP不可用 {down} 次")

    # 响应时延突增
    rows = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='response_time_ms' "
        "AND collected_at BETWEEN ? AND ? ORDER BY collected_at ASC",
        (target_name, t_start, t_end),
    )
    if not rows.empty and len(rows) >= 2:
        v_mean = rows["value"].mean()
        v_max  = rows["value"].max()
        if v_max > v_mean * 2 and v_max > 1000:
            anomalies.append(f"响应时延峰值 {v_max:.0f}ms（均值 {v_mean:.0f}ms）")

    # 丢包率升高
    rows = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='icmp_loss' "
        "AND collected_at BETWEEN ? AND ? ORDER BY collected_at ASC",
        (target_name, t_start, t_end),
    )
    if not rows.empty:
        max_loss = rows["value"].max()
        if max_loss > 10:
            anomalies.append(f"ICMP丢包率最高 {max_loss:.1f}%")

    # 威胁情报突增
    rows = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='threat_score' "
        "AND collected_at BETWEEN ? AND ? ORDER BY collected_at ASC",
        (target_name, t_start, t_end),
    )
    if not rows.empty:
        max_threat = rows["value"].max()
        if max_threat >= 3:
            anomalies.append(f"威胁情报评分达 {max_threat:.1f}（≥3为警戒）")

    return anomalies


# ── 攻击链阶段分类（简化版 Cyber Kill Chain，映射到本平台实际可观测的信号） ──────────
# 侦察特征：新暴露资产出现、外部威胁情报标记升高，通常发生在真正影响服务之前
# 弱点暴露：TLS/HTTPS 安全配置劣化，代表攻击面上出现可被利用的薄弱点
# 异常行为：可用性/时延/丢包/健康度骤降等运行时异常，代表攻击尝试或影响已经产生
# 疑似失陷：网页内容被篡改，代表攻击已经得手、需要立即响应
_RULE_STAGE_MAP = {
    "new_asset_discovered": {"stage": "侦察特征", "rank": 1, "icon": "🔭"},
    "threat_spike":         {"stage": "侦察特征", "rank": 1, "icon": "🛰️"},
    "tls_degradation":      {"stage": "弱点暴露", "rank": 2, "icon": "🔓"},
    "health_threshold":     {"stage": "异常行为", "rank": 3, "icon": "⚠️"},
    "metric_deviation":     {"stage": "异常行为", "rank": 3, "icon": "📉"},
    "content_change":       {"stage": "疑似失陷", "rank": 4, "icon": "🚨"},
}
_DEFAULT_STAGE = {"stage": "其他事件", "rank": 0, "icon": "ℹ️"}

STAGE_ORDER = ["侦察特征", "弱点暴露", "异常行为", "疑似失陷"]


def _classify_rule(rule_type: str) -> Dict[str, Any]:
    return _RULE_STAGE_MAP.get(rule_type, _DEFAULT_STAGE)


def build_attack_chain(db_path: str, target_name: str, hours: int = 48) -> Dict[str, Any]:
    """
    汇总窗口内该目标的告警与健康度骤降事件，按攻击链阶段
    （侦察特征 → 弱点暴露 → 异常行为 → 疑似失陷）分类并按时间排序，
    返回时间轴事件列表，供 UI 绘制"攻击链复盘"视图。

    与 analyze() 的关系：analyze() 只回答"某次骤降的原因是什么"，
    本函数回答"这段时间内的安全事件是如何按阶段演化的"，是更宏观的叙事视角。
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    alerts_df = db.query_df(
        db_path,
        "SELECT rule_type, severity, message, detail, created_at FROM alerts "
        "WHERE target_name=? AND created_at>=? ORDER BY created_at ASC",
        (target_name, since),
    )

    events: List[Dict[str, Any]] = []
    for _, r in alerts_df.iterrows():
        meta = _classify_rule(r["rule_type"])
        events.append({
            "time": pd.to_datetime(r["created_at"], utc=True, errors="coerce"),
            "stage": meta["stage"],
            "stage_rank": meta["rank"],
            "icon": meta["icon"],
            "title": r["message"],
            "detail": r["detail"] or "",
            "severity": r["severity"],
            "source": "告警",
        })

    # 健康度骤降事件同样归入"异常行为"阶段，复用 analyze() 已有的根因摘要
    for ev in analyze(db_path, target_name, hours=hours):
        t = ev["time"]
        if not isinstance(t, pd.Timestamp):
            t = pd.to_datetime(t, utc=True, errors="coerce")
        events.append({
            "time": t,
            "stage": "异常行为",
            "stage_rank": 3,
            "icon": "📉",
            "title": f"健康度骤降 {ev['from_score']:.1f} → {ev['to_score']:.1f}（-{ev['drop']:.1f}）",
            "detail": ev["summary"],
            "severity": "critical" if ev["drop"] >= 10 else "warning",
            "source": "评分分析",
        })

    events = [e for e in events if pd.notna(e["time"])]
    events.sort(key=lambda e: e["time"])

    stage_counts: Dict[str, int] = {}
    for e in events:
        stage_counts[e["stage"]] = stage_counts.get(e["stage"], 0) + 1

    return {
        "target_name": target_name,
        "events": events,
        "stage_counts": stage_counts,
    }


def analyze(db_path: str, target_name: str, hours: int = 48) -> List[Dict]:
    """
    分析指定目标在过去 hours 小时内的健康评分骤降事件，返回根因分析结果列表。
    每个元素包含：time, from_score, to_score, drop, tls_changes, alerts, metric_anomalies, summary
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    health_df = db.query_df(
        db_path,
        "SELECT target_name, score, scored_at FROM health_scores "
        "WHERE target_name=? AND scored_at >= ? ORDER BY scored_at ASC",
        (target_name, since),
    )
    if not health_df.empty:
        health_df["scored_at"] = pd.to_datetime(health_df["scored_at"], utc=True, errors="coerce")

    drops = _detect_drops(health_df, target_name)
    results = []

    for event in drops:
        tls_changes   = _find_tls_changes(db_path, target_name, event["time"], _WINDOW_MINUTES)
        alerts        = _find_related_alerts(db_path, target_name, event["time"], _WINDOW_MINUTES)
        anomalies     = _find_metric_anomalies(db_path, target_name, event["time"], _WINDOW_MINUTES)

        # 生成根因摘要
        causes = []
        if tls_changes:
            causes.append(f"TLS/安全层变化：{tls_changes[0]}" + ("等" if len(tls_changes) > 1 else ""))
        if anomalies:
            causes.extend(anomalies[:2])
        if alerts:
            causes.append(f"同期告警：{alerts[0]}" + ("等" if len(alerts) > 1 else ""))

        if causes:
            summary = "可能原因：" + "；".join(causes)
        else:
            summary = "未找到明显关联原因，可能为网络抖动或外部访问条件变化"

        results.append({
            "time": event["time"],
            "from_score": event["from_score"],
            "to_score": event["to_score"],
            "drop": event["drop"],
            "tls_changes": tls_changes,
            "alerts": alerts,
            "metric_anomalies": anomalies,
            "summary": summary,
        })

    return results