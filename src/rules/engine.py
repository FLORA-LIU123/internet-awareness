from typing import Any, Dict, List, Optional

import pandas as pd

from src.prediction import prophet_model
from src.rules.alert_manager import store_alert
from src.utils.logger import get_logger

logger = get_logger(__name__)

_METRIC_COLS = {
    "availability":      "availability_score",
    "response_time":     "response_time_score",
    "link_connectivity": "link_score",
    "security_risk":     "security_score",
}

# 安全专项规则阈值
_TLS_SECURITY_WARN  = 70.0   # TLS安全评分低于此值触发警告
_TLS_SECURITY_CRIT  = 50.0   # TLS安全评分低于此值触发严重告警
_THREAT_SPIKE_WARN  = 3.0    # 威胁情报分超过此值触发警告
_THREAT_SPIKE_CRIT  = 6.0    # 威胁情报分超过此值触发严重告警


def _health_threshold_rule(target: str, score: float,
                            threshold: float) -> Optional[Dict[str, Any]]:
    if score < threshold:
        return {
            "target_name": target,
            "rule_type": "health_threshold",
            "severity": "critical" if score < threshold * 0.7 else "warning",
            "message": f"服务健康度评分下降至 {score:.1f} 分（阈值 {threshold:.0f} 分）",
            "detail": f"当前健康度 {score:.1f}，低于预设警戒阈值 {threshold:.0f}",
        }
    return None


def _deviation_rule(target: str, metric_col: str, actual: float,
                    prediction: Dict[str, float],
                    multiplier: float) -> Optional[Dict[str, Any]]:
    yhat = prediction["yhat"]
    lower = prediction["yhat_lower"]
    upper = prediction["yhat_upper"]
    band = (upper - lower) / 2 or 1.0
    deviation = abs(actual - yhat)

    if deviation > multiplier * band:
        direction = "升高" if actual > yhat else "降低"
        return {
            "target_name": target,
            "rule_type": "metric_deviation",
            "severity": "warning",
            "message": (
                f"指标 {metric_col} 异常{direction}：实际值 {actual:.1f}，"
                f"预测值 {yhat:.1f}（偏差 {deviation:.1f}）"
            ),
            "detail": (
                f"预测区间 [{lower:.1f}, {upper:.1f}]，"
                f"偏差倍数 {deviation / band:.1f}x（阈值 {multiplier}x）"
            ),
        }
    return None


def _tls_degradation_rule(target: str, tls_score: float) -> Optional[Dict[str, Any]]:
    """TLS/HTTPS 安全专项规则：检测证书、协议版本、安全响应头劣化。"""
    if tls_score <= _TLS_SECURITY_CRIT:
        return {
            "target_name": target,
            "rule_type": "tls_degradation",
            "severity": "critical",
            "message": (
                f"TLS/HTTPS 安全评分严重劣化至 {tls_score:.1f} 分（危险阈值 {_TLS_SECURITY_CRIT:.0f}）"
            ),
            "detail": (
                f"可能原因：① SSL证书已过期或即将过期；② 仍使用TLS 1.0/1.1等不安全协议版本；"
                f"③ 缺少HSTS/CSP/X-Frame-Options等关键安全响应头；④ 未启用HTTPS强制跳转。"
                f"建议立即登录服务器检查证书有效期（openssl s_client -connect 域名:443），"
                f"并通过 ssllabs.com 进行完整评级检查。"
            ),
        }
    elif tls_score <= _TLS_SECURITY_WARN:
        return {
            "target_name": target,
            "rule_type": "tls_degradation",
            "severity": "warning",
            "message": (
                f"TLS/HTTPS 安全评分偏低至 {tls_score:.1f} 分（警告阈值 {_TLS_SECURITY_WARN:.0f}）"
            ),
            "detail": (
                f"安全响应头配置不完整或TLS配置存在改进空间。建议排查："
                f"① 是否缺少 Content-Security-Policy 或 Referrer-Policy 头；"
                f"② 证书剩余有效期是否低于30天；③ 是否未配置证书透明度（SCT）扩展。"
                f"可前往「实时监测」页面的 TLS/HTTPS 安全检测区查看详细子项评分。"
            ),
        }
    return None


def _threat_spike_rule(target: str, threat_score: float) -> Optional[Dict[str, Any]]:
    """威胁情报专项规则：检测 AlienVault OTX 威胁分数异常升高。"""
    if threat_score >= _THREAT_SPIKE_CRIT:
        return {
            "target_name": target,
            "rule_type": "threat_spike",
            "severity": "critical",
            "message": (
                f"威胁情报评分达到高危级别 {threat_score:.1f} 分（危险阈值 {_THREAT_SPIKE_CRIT:.0f}）"
            ),
            "detail": (
                f"AlienVault OTX 情报显示该目标IP已被多个威胁情报源标记（pulse数量较多）。"
                f"建议立即执行：① 检查服务器最近登录日志（/var/log/auth.log 或 Windows事件日志）；"
                f"② 核查是否有异常进程或定时任务；③ 通过 otx.alienvault.com 查看具体威胁标签；"
                f"④ 联系运营商确认IP是否被列入公开黑名单，评估是否需要更换出口IP。"
            ),
        }
    elif threat_score >= _THREAT_SPIKE_WARN:
        return {
            "target_name": target,
            "rule_type": "threat_spike",
            "severity": "warning",
            "message": (
                f"威胁情报评分升高至 {threat_score:.1f} 分（警告阈值 {_THREAT_SPIKE_WARN:.0f}）"
            ),
            "detail": (
                f"该目标IP在威胁情报平台中有少量异常标记，需持续关注。"
                f"建议：① 登录 otx.alienvault.com/indicator/ip/{target} 查看具体脉冲来源；"
                f"② 检查Web访问日志中是否有异常来源IP的高频请求；"
                f"③ 确认WAF防火墙规则是否覆盖已知攻击特征。"
            ),
        }
    return None


def evaluate(health_scores_df: pd.DataFrame,
             fused_df: pd.DataFrame,
             db_path: str,
             health_threshold: float = 60.0,
             deviation_multiplier: float = 2.0,
             cooldown_minutes: int = 10,
             forecast_horizon_hours: int = 6,
             min_training_points: int = 30,
             refit_interval_minutes: int = 30) -> List[Dict[str, Any]]:
    """
    Run all rules against the latest health scores and fused metrics.
    Persist triggered alerts and return the list of alert dicts.
    """
    triggered: List[Dict[str, Any]] = []

    for _, hs_row in health_scores_df.iterrows():
        target = hs_row["target_name"]
        score = float(hs_row["score"])

        # Rule 1: health score threshold
        alert = _health_threshold_rule(target, score, health_threshold)
        if alert:
            if store_alert(db_path, alert, cooldown_minutes):
                triggered.append(alert)

        # Rule 2: per-metric deviation from Prophet forecast
        fused_rows = fused_df[fused_df["target_name"] == target]
        if fused_rows.empty:
            continue
        fused_row = fused_rows.iloc[-1].to_dict()

        for metric_name, col in _METRIC_COLS.items():
            actual = fused_row.get(col)
            if actual is None:
                continue
            pred = prophet_model.get_latest_prediction(
                db_path, target, col,
                horizon_hours=forecast_horizon_hours,
                min_points=min_training_points,
                refit_interval_minutes=refit_interval_minutes,
            )
            if pred is None:
                continue
            alert = _deviation_rule(target, col, float(actual), pred, deviation_multiplier)
            if alert:
                if store_alert(db_path, alert, cooldown_minutes):
                    triggered.append(alert)

    # Rule 3 & 4: 安全专项规则，直接从 raw_metrics 最新值判断
    _evaluate_security_rules(fused_df, db_path, cooldown_minutes, triggered)

    return triggered


def _evaluate_security_rules(fused_df: pd.DataFrame, db_path: str,
                              cooldown_minutes: int,
                              triggered: List[Dict[str, Any]]) -> None:
    """从 raw_metrics 取最新 TLS 和威胁情报原始值，执行安全专项规则。"""
    try:
        from src.storage import db as storage_db
        for target in fused_df["target_name"].unique():
            # TLS 劣化规则：取最新 tls_security 原始分
            tls_df = storage_db.query_df(
                db_path,
                "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='tls_security' "
                "ORDER BY collected_at DESC LIMIT 1",
                (target,),
            )
            if not tls_df.empty and tls_df.iloc[0]["value"] is not None:
                tls_val = float(tls_df.iloc[0]["value"])
                alert = _tls_degradation_rule(target, tls_val)
                if alert and store_alert(db_path, alert, cooldown_minutes):
                    triggered.append(alert)

            # 威胁情报突增规则：取最新 threat_score 原始分
            threat_df = storage_db.query_df(
                db_path,
                "SELECT value FROM raw_metrics WHERE target_name=? AND metric_type='threat_score' "
                "ORDER BY collected_at DESC LIMIT 1",
                (target,),
            )
            if not threat_df.empty and threat_df.iloc[0]["value"] is not None:
                threat_val = float(threat_df.iloc[0]["value"])
                alert = _threat_spike_rule(target, threat_val)
                if alert and store_alert(db_path, alert, cooldown_minutes):
                    triggered.append(alert)

    except Exception as exc:
        logger.warning("安全专项规则执行异常：%s", exc)
