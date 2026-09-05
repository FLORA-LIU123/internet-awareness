"""
自适应基线告警模块

传统固定阈值告警的局限：
- 高校门户晚间高峰期响应慢是正常的，工作日的政务网和凌晨的政务网基线完全不同
- 固定阈值导致大量误报（正常波动）或漏报（异常被阈值掩盖）

本模块为每个目标的每个指标建立"时段-星期"二维基线：
- 基线 = 历史同时段（小时+星期）的均值和标准差
- 告警判定 = 当前值偏离基线超过 N 倍标准差
- 基线自动更新：每次采集后，用新数据更新均值和标准差（指数加权移动平均）

效果：大幅减少误报，让告警更可信。
"""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import numpy as np

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# 告警判定：偏离基线超过此倍数视为异常
_DEVIATION_MULTIPLIER = 2.5
# 基线更新：新数据点的权重（指数加权移动平均）
_ALPHA = 0.3
# 最少样本数：低于此数不触发告警（避免冷启动误报）
_MIN_SAMPLES = 5

# 需要建立基线的指标列表
_BASELINE_METRICS = [
    "response_time_ms",
    "icmp_latency",
    "icmp_loss",
    "threat_score",
    "tls_security",
]


def update_baselines(db_path: str, targets: list) -> None:
    """
    为每个目标的每个指标更新基线。
    从 raw_metrics 读取最近 7 天数据，按 (hour_of_day, day_of_week) 分组计算均值和标准差。
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=7)).isoformat()
    ts = now.isoformat()

    for target in targets:
        name = target.get("name", "")
        if not name:
            continue

        for metric in _BASELINE_METRICS:
            df = db.query_df(
                db_path,
                "SELECT value, collected_at FROM raw_metrics "
                "WHERE target_name=? AND metric_type=? AND collected_at>=? "
                "ORDER BY collected_at ASC",
                (name, metric, since),
            )
            if df.empty:
                continue

            df["value"] = df["value"].astype(float)
            df["collected_at"] = df["collected_at"].apply(
                lambda x: datetime.fromisoformat(x.replace("Z", "+00:00"))
                if isinstance(x, str) else x
            )
            df["hour"] = df["collected_at"].apply(lambda x: x.hour if hasattr(x, "hour") else 0)
            df["dow"] = df["collected_at"].apply(lambda x: x.weekday() if hasattr(x, "weekday") else 0)

            for (hour, dow), group in df.groupby(["hour", "dow"]):
                values = group["value"].dropna().values
                if len(values) < _MIN_SAMPLES:
                    continue

                mean = float(np.mean(values))
                std = float(np.std(values)) if len(values) > 1 else 0.0

                # 检查是否已有基线
                existing = db.query_df(
                    db_path,
                    "SELECT baseline_mean, baseline_std, sample_count FROM time_baselines "
                    "WHERE target_name=? AND metric=? AND hour_of_day=? AND day_of_week=?",
                    (name, metric, hour, dow),
                )

                if existing.empty:
                    # 新建基线
                    db.execute(
                        db_path,
                        """INSERT INTO time_baselines
                           (target_name, metric, hour_of_day, day_of_week,
                            baseline_mean, baseline_std, sample_count, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (name, metric, hour, dow, mean, std, len(values), ts),
                    )
                else:
                    # 更新基线（指数加权移动平均）
                    old_mean = float(existing.iloc[0]["baseline_mean"])
                    old_std = float(existing.iloc[0]["baseline_std"])
                    old_count = int(existing.iloc[0]["sample_count"])

                    new_mean = _ALPHA * mean + (1 - _ALPHA) * old_mean
                    new_std = _ALPHA * std + (1 - _ALPHA) * old_std
                    new_count = old_count + len(values)

                    db.execute(
                        db_path,
                        """UPDATE time_baselines
                           SET baseline_mean=?, baseline_std=?, sample_count=?, updated_at=?
                           WHERE target_name=? AND metric=? AND hour_of_day=? AND day_of_week=?""",
                        (new_mean, new_std, new_count, ts, name, metric, hour, dow),
                    )

    logger.info("基线更新完成")


def check_deviation(db_path: str, target: str, metric: str,
                    current_value: float) -> Optional[Dict[str, Any]]:
    """
    检查当前值是否偏离基线。
    返回告警信息，或 None（正常/无基线）。
    """
    now = datetime.now(timezone.utc)
    hour = now.hour
    dow = now.weekday()

    baseline = db.query_df(
        db_path,
        "SELECT baseline_mean, baseline_std, sample_count FROM time_baselines "
        "WHERE target_name=? AND metric=? AND hour_of_day=? AND day_of_week=?",
        (target, metric, hour, dow),
    )

    if baseline.empty:
        return None

    mean = float(baseline.iloc[0]["baseline_mean"])
    std = float(baseline.iloc[0]["baseline_std"])
    count = int(baseline.iloc[0]["sample_count"])

    if count < _MIN_SAMPLES:
        return None

    # 标准差为 0 时，用均值的 10% 作为最小偏差阈值
    if std == 0:
        std = max(abs(mean) * 0.1, 1.0)

    deviation = abs(current_value - mean)
    z_score = deviation / std

    if z_score < _DEVIATION_MULTIPLIER:
        return None

    # 判断方向
    direction = "偏高" if current_value > mean else "偏低"
    severity = "warning" if z_score < 3.0 else "critical"

    return {
        "target_name": target,
        "metric": metric,
        "current": current_value,
        "baseline_mean": mean,
        "baseline_std": std,
        "z_score": z_score,
        "deviation": deviation,
        "direction": direction,
        "severity": severity,
        "message": f"{metric} 异常{direction}：当前 {current_value:.1f}，"
                   f"基线 {mean:.1f}±{std:.1f}（偏离 {z_score:.1f}σ）",
    }


def evaluate_all(db_path: str, targets: list,
                 current_values: Dict[str, Dict[str, float]]) -> List[Dict[str, Any]]:
    """
    对所有目标的所有指标执行基线偏离检查。
    current_values: {target_name: {metric: value}}
    返回触发的告警列表。
    """
    alerts = []
    for target in targets:
        name = target.get("name", "")
        if name not in current_values:
            continue
        for metric, value in current_values[name].items():
            if value is None:
                continue
            alert = check_deviation(db_path, name, metric, value)
            if alert:
                alerts.append(alert)
    return alerts


def get_baseline_series(db_path: str, target: str, metric: str,
                        hours: int = 168) -> list:
    """返回某目标某指标的完整时段基线数据，供 UI 热力图使用。"""
    df = db.query_df(
        db_path,
        "SELECT hour_of_day, day_of_week, baseline_mean, baseline_std, sample_count "
        "FROM time_baselines WHERE target_name=? AND metric=? "
        "ORDER BY hour_of_day, day_of_week",
        (target, metric),
    )
    return df.to_dict("records") if not df.empty else []


def get_baseline_data(db_path: str, target: str, metric: str) -> list:
    """返回某目标某指标的所有时段基线（别名，与 get_baseline_series 等价）。"""
    return get_baseline_series(db_path, target, metric)


def get_heatmap_data(db_path: str, target: str) -> dict:
    """
    返回所有指标的时段基线热力图数据。
    格式：{metric_name: [{"hour_of_day": h, "day_of_week": d,
                           "baseline_mean": m, "baseline_std": s}, ...]}
    """
    result = {}
    for raw_metric, _, _ in _METRICS:
        data = get_baseline_data(db_path, target, raw_metric)
        if data:
            result[raw_metric] = data
    return result