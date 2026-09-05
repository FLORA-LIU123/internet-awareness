"""
未来风险预警指数（Forward-Looking Risk Index）

与规则引擎（src/rules/engine.py）的区别：规则引擎检测"当前已发生"的异常，
本模块预测"未来 1-2 天可能出现"的风险，是从"监测"到"预警"的关键一步。

综合三类前瞻信号，加权融合为 0-100 的风险指数（越高越危险）：
  1. 健康度预测下探风险 — 复用 NeuralProphet/Holt-Winters 对健康度的预测，
     检查未来预测区间是否逼近或跌破警戒线（60分）。
  2. 威胁情报趋势风险   — OTX 威胁分数的当前水平 + 近期变化斜率（是否在上升）。
  3. 内容篡改频率风险   — 近期时间窗口内网页内容篡改事件的次数。

权重复用与 AHP 评分模块类似的加权求和思路，但作为独立的预警维度，
不与 health_score 混合，避免"当前状态"和"未来风险"两个概念混淆。
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

from src.prediction import prophet_model
from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 三个风险分量的融合权重（合计 1.0）
_WEIGHTS = {
    "health_trend_risk":   0.5,
    "threat_trend_risk":   0.3,
    "content_tamper_risk": 0.2,
}

_HEALTH_WARN_LINE = 60.0
_CONTENT_LOOKBACK_HOURS = 72
_THREAT_LOOKBACK_HOURS = 48


def _load_health_series(db_path: str, target: str, lookback_hours: int = 720) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT scored_at AS ds, score AS y FROM health_scores "
        "WHERE target_name=? AND scored_at>=? ORDER BY scored_at",
        (target, since),
    )
    if df.empty:
        return df
    df["ds"] = pd.to_datetime(df["ds"], utc=True)
    df["y"] = pd.to_numeric(df["y"], errors="coerce")
    df = df.dropna(subset=["y"])
    if df.empty:
        return df
    df = df.set_index("ds").resample("D")["y"].mean().dropna().reset_index()
    df["ds"] = df["ds"].dt.tz_convert(None)
    return df


def _health_trend_risk(db_path: str, target: str) -> Dict[str, Any]:
    """
    预测未来2天健康度，若预测值（含置信区间下界）跌破警戒线，则风险升高。
    风险值 0-100：基于"预测值/预测下界距警戒线还有多远"换算。
    """
    series = _load_health_series(db_path, target)
    fc = prophet_model.forecast_series(series, forecast_days=2, min_points=3)

    if fc is None or fc.empty:
        return {"risk": 0.0, "detail": "数据不足，无法预测健康度趋势", "confident": False}

    now_naive = pd.Timestamp.utcnow().normalize().tz_localize(None)
    future = fc[fc["ds"] > now_naive]
    if future.empty:
        return {"risk": 0.0, "detail": "暂无未来预测数据点", "confident": False}

    next_yhat  = float(future.iloc[0]["yhat"])
    next_lower = float(future.iloc[0]["yhat_lower"])

    # 风险换算：预测下界比警戒线低多少，每低 1 分记 2 风险分（上限 100）
    # 预测值本身也纳入考量：即使下界略低于警戒线，若预测值仍健康，风险打折
    gap_lower = _HEALTH_WARN_LINE - next_lower
    gap_yhat  = _HEALTH_WARN_LINE - next_yhat

    if gap_yhat <= 0 and gap_lower <= 0:
        risk = 0.0
        detail = f"预测健康度 {next_yhat:.1f} 分，稳定高于警戒线 {_HEALTH_WARN_LINE:.0f} 分"
    else:
        risk = min(max(gap_lower, 0) * 2.0 + max(gap_yhat, 0) * 1.5, 100.0)
        detail = (
            f"预测未来健康度 {next_yhat:.1f} 分（下界 {next_lower:.1f}），"
            f"{'已跌破' if gap_yhat > 0 else '逼近'}警戒线 {_HEALTH_WARN_LINE:.0f} 分"
        )

    return {"risk": round(risk, 1), "detail": detail, "confident": True,
            "predicted_score": round(next_yhat, 1)}


def _threat_trend_risk(db_path: str, target: str) -> Dict[str, Any]:
    """
    威胁情报评分的当前水平 + 短期斜率。评分越高、上升越快，风险越高。
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=_THREAT_LOOKBACK_HOURS)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT value, collected_at FROM raw_metrics WHERE target_name=? "
        "AND metric_type='threat_score' AND collected_at>=? ORDER BY collected_at",
        (target, since),
    )
    df = df.dropna(subset=["value"]) if not df.empty else df
    if df.empty:
        return {"risk": 0.0, "detail": "暂无威胁情报数据", "confident": False}

    current = float(df.iloc[-1]["value"])
    # 基础风险：当前威胁分 0-10 映射到 0-70
    base_risk = min(current / 10.0 * 70.0, 70.0)

    slope_risk = 0.0
    if len(df) >= 3:
        y = df["value"].astype(float).values
        x = np.arange(len(y))
        slope = np.polyfit(x, y, 1)[0]
        if slope > 0:
            # 上升趋势加成，最多 30 分
            slope_risk = min(slope * 15.0, 30.0)

    risk = min(base_risk + slope_risk, 100.0)
    trend_word = "上升" if slope_risk > 0 else "平稳或下降"
    detail = f"当前威胁评分 {current:.1f}（0-10），近 {_THREAT_LOOKBACK_HOURS}h 趋势{trend_word}"
    return {"risk": round(risk, 1), "detail": detail, "confident": True,
            "current_threat_score": current}


def _content_tamper_risk(db_path: str, target: str) -> Dict[str, Any]:
    """
    近期内容篡改事件次数越多，风险越高（每次记 35 分，上限 100）。
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=_CONTENT_LOOKBACK_HOURS)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT COUNT(*) AS cnt FROM content_snapshots "
        "WHERE target_name=? AND collected_at>=? AND changed=1",
        (target, since),
    )
    count = 0 if df.empty else int(df.iloc[0]["cnt"])
    risk = min(count * 35.0, 100.0)
    detail = (f"过去 {_CONTENT_LOOKBACK_HOURS}h 内检测到 {count} 次内容变化"
              if count > 0 else f"过去 {_CONTENT_LOOKBACK_HOURS}h 内容无异常变化")
    return {"risk": round(risk, 1), "detail": detail, "confident": True, "tamper_count": count}


def _risk_level(score: float) -> str:
    if score >= 70:
        return "严重预警"
    if score >= 40:
        return "高风险"
    if score >= 15:
        return "中风险"
    return "低风险"


def compute(db_path: str, target: str) -> Dict[str, Any]:
    """计算单个目标的未来风险预警指数，返回结构化结果（不写库）。"""
    health = _health_trend_risk(db_path, target)
    threat = _threat_trend_risk(db_path, target)
    content = _content_tamper_risk(db_path, target)

    total = (
        health["risk"] * _WEIGHTS["health_trend_risk"]
        + threat["risk"] * _WEIGHTS["threat_trend_risk"]
        + content["risk"] * _WEIGHTS["content_tamper_risk"]
    )
    total = round(min(total, 100.0), 1)

    return {
        "target_name": target,
        "risk_score": total,
        "risk_level": _risk_level(total),
        "components": {
            "health_trend_risk":   health,
            "threat_trend_risk":   threat,
            "content_tamper_risk": content,
        },
    }


def compute_and_store(db_path: str, targets: list) -> pd.DataFrame:
    """对所有目标计算风险指数并写入 risk_index 表，返回汇总 DataFrame。"""
    ts = datetime.now(timezone.utc).isoformat()
    rows = []
    for target in targets:
        name = target.get("name") if isinstance(target, dict) else target
        if not name:
            continue
        try:
            result = compute(db_path, name)
        except Exception as exc:
            logger.error("Risk index computation failed for %s: %s", name, exc, exc_info=True)
            continue

        db.execute(
            db_path,
            """INSERT INTO risk_index
               (target_name, risk_score, risk_level, health_trend_risk,
                threat_trend_risk, content_tamper_risk, computed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result["target_name"],
                result["risk_score"],
                result["risk_level"],
                result["components"]["health_trend_risk"]["risk"],
                result["components"]["threat_trend_risk"]["risk"],
                result["components"]["content_tamper_risk"]["risk"],
                ts,
            ),
        )
        logger.info("Risk index for %s: %.1f (%s)", name, result["risk_score"], result["risk_level"])
        rows.append({
            "target_name": result["target_name"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "computed_at": ts,
        })

    return pd.DataFrame(rows)


def get_latest(db_path: str) -> pd.DataFrame:
    """每个目标最新一条风险指数记录，供 UI 总览展示。"""
    return db.query_df(
        db_path,
        """
        SELECT r.target_name, r.risk_score, r.risk_level, r.health_trend_risk,
               r.threat_trend_risk, r.content_tamper_risk, r.computed_at
        FROM risk_index r
        INNER JOIN (
            SELECT target_name, MAX(computed_at) AS latest
            FROM risk_index GROUP BY target_name
        ) m ON r.target_name = m.target_name AND r.computed_at = m.latest
        ORDER BY r.risk_score DESC
        """,
    )


def get_history(db_path: str, target: str, hours: int = 168) -> pd.DataFrame:
    """某目标的风险指数历史，供趋势图使用。"""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT risk_score, risk_level, health_trend_risk, threat_trend_risk, "
        "content_tamper_risk, computed_at FROM risk_index "
        "WHERE target_name=? AND computed_at>=? ORDER BY computed_at",
        (target, since),
    )
    if not df.empty:
        df["computed_at"] = pd.to_datetime(df["computed_at"], utc=True, errors="coerce")
    return df