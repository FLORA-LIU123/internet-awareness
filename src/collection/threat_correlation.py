"""
威胁情报跨目标关联分析模块

升级原有的"查询 IP 是否在黑名单"逻辑，增加：
1. 跨目标同步威胁检测 —— 多个目标同时出现威胁分数升高时，判定为关联攻击事件
2. IoC 趋势追踪 —— 记录每次采集的威胁分数，计算短期斜率，预警上升趋势
3. 关联告警推送 —— 关联事件触发额外告警，帮助判断是定向攻击还是广谱扫描
"""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import numpy as np

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 同步威胁检测阈值
_SYNC_THRESHOLD = 3.0       # 威胁分数超过此值视为"激活"
_SYNC_WINDOW_MIN = 120      # 120 分钟内多目标同时激活视为关联事件
_TREND_WINDOW_H  = 48       # 计算斜率的回看窗口（小时）
_TREND_SPIKE     = 0.5      # 每次采集涨幅超过此值视为趋势上升


def compute_and_store(db_path: str, targets: list,
                      current_scores: Dict[str, float]) -> List[Dict[str, Any]]:
    """
    基于本轮采集结果，执行跨目标关联分析，结果写入 threat_correlations 表。
    current_scores: {target_name: threat_score}
    返回触发的关联事件列表。
    """
    ts = datetime.now(timezone.utc).isoformat()
    events: List[Dict[str, Any]] = []

    # ── 1. 收集激活目标 ────────────────────────────────────────────────────────
    active = {n: s for n, s in current_scores.items()
              if s is not None and s >= _SYNC_THRESHOLD}

    # ── 2. 跨目标同步检测 ──────────────────────────────────────────────────────
    if len(active) >= 2:
        names = list(active.keys())
        correlated_str = "、".join(names)
        max_score = max(active.values())
        pattern = _classify_pattern(active)

        for name, score in active.items():
            others = [n for n in names if n != name]
            _store_correlation(db_path, ts, name, score, 0, correlated_str, pattern)

        events.append({
            "type": "sync_threat",
            "targets": names,
            "max_score": max_score,
            "pattern": pattern,
            "detail": f"{len(active)} 个目标同步威胁分数升高（{correlated_str}），"
                      f"最高分 {max_score:.1f}，疑似{pattern}",
        })
        logger.warning("跨目标关联威胁：%s", correlated_str)

    else:
        # 单目标也记录，供后续趋势分析
        for name, score in active.items():
            _store_correlation(db_path, ts, name, score, 0, None, "单目标威胁")

    # ── 3. 趋势斜率检测 ────────────────────────────────────────────────────────
    for name, score in current_scores.items():
        if score is None:
            continue
        trend = _check_trend(db_path, name)
        if trend["rising"]:
            events.append({
                "type": "trend_rising",
                "target": name,
                "slope": trend["slope"],
                "current": score,
                "detail": f"{name} 威胁分数持续上升（斜率 +{trend['slope']:.2f}/次），"
                           f"当前 {score:.1f}",
            })

    return events


def _classify_pattern(active: Dict[str, float]) -> str:
    scores = list(active.values())
    avg = sum(scores) / len(scores)
    if avg >= 6:
        return "高强度协同攻击"
    if len(active) >= 4:
        return "广谱扫描或僵尸网络"
    return "定向多目标攻击"


def _check_trend(db_path: str, target: str) -> Dict[str, Any]:
    since = (datetime.now(timezone.utc) - timedelta(hours=_TREND_WINDOW_H)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT value FROM raw_metrics WHERE target_name=? "
        "AND metric_type='threat_score' AND collected_at>=? "
        "ORDER BY collected_at ASC",
        (target, since),
    )
    if df.empty or len(df) < 3:
        return {"rising": False, "slope": 0.0}

    y = df["value"].dropna().astype(float).values
    if len(y) < 3:
        return {"rising": False, "slope": 0.0}
    x = np.arange(len(y))
    slope = float(np.polyfit(x, y, 1)[0])
    rising = slope > _TREND_SPIKE and y[-1] >= _SYNC_THRESHOLD
    return {"rising": rising, "slope": round(slope, 3)}


def _store_correlation(db_path: str, ts: str, target: str,
                       score: float, pulse_count: int,
                       correlated_with: Optional[str],
                       pattern: Optional[str]) -> None:
    import uuid
    correlation_id = str(uuid.uuid4())[:8]
    try:
        db.execute(
            db_path,
            """INSERT INTO threat_correlations
               (correlation_id, target_name, threat_score, pulse_count,
                correlated_with, pattern, computed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (correlation_id, target, score, pulse_count,
             correlated_with, pattern, ts),
        )
    except Exception as e:
        logger.warning("存储威胁关联记录失败：%s", e)


def get_latest(db_path: str, hours: int = 72) -> list:
    """返回最近 N 小时的威胁关联事件，供 UI 展示。"""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        """SELECT target_name, threat_score, correlated_with, pattern, computed_at
           FROM threat_correlations
           WHERE computed_at >= ? AND correlated_with IS NOT NULL
           ORDER BY computed_at DESC LIMIT 200""",
        (since,),
    )
    return df.to_dict("records") if not df.empty else []


def get_trend_series(db_path: str, target: str, hours: int = 168) -> list:
    """返回某目标的威胁分数历史时间序列。"""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT value AS threat_score, collected_at FROM raw_metrics "
        "WHERE target_name=? AND metric_type='threat_score' "
        "AND collected_at>=? ORDER BY collected_at ASC",
        (target, since),
    )
    return df.to_dict("records") if not df.empty else []