from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)


def get_active_alerts(db_path: str, target: Optional[str] = None,
                      limit: int = 100) -> pd.DataFrame:
    where = "WHERE acknowledged = 0"
    params: tuple = ()
    if target:
        where += " AND target_name = ?"
        params = (target,)
    sql = f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT {limit}"
    return db.query_df(db_path, sql, params)


def get_all_alerts(db_path: str, target: Optional[str] = None,
                   hours: int = 72, limit: int = 500) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    where = "WHERE created_at >= ?"
    params: tuple = (since,)
    if target:
        where += " AND target_name = ?"
        params = (since, target)
    sql = f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT {limit}"
    return db.query_df(db_path, sql, params)


def acknowledge(db_path: str, alert_id: int) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    db.execute(
        db_path,
        "UPDATE alerts SET acknowledged=1, ack_at=? WHERE id=?",
        (ts, alert_id),
    )
    logger.info("Alert %d acknowledged", alert_id)


def _is_duplicate(db_path: str, target: str, rule_type: str,
                  cooldown_minutes: int) -> bool:
    since = (datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)).isoformat()
    df = db.query_df(
        db_path,
        "SELECT id FROM alerts WHERE target_name=? AND rule_type=? AND created_at>=? LIMIT 1",
        (target, rule_type, since),
    )
    return not df.empty


def store_alert(db_path: str, alert: Dict[str, Any],
                cooldown_minutes: int = 10) -> bool:
    """Persist an alert if not within cooldown window. Returns True if stored."""
    if _is_duplicate(db_path, alert["target_name"], alert["rule_type"], cooldown_minutes):
        return False
    ts = datetime.now(timezone.utc).isoformat()
    db.execute(
        db_path,
        """INSERT INTO alerts (target_name, rule_type, severity, message, detail, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            alert["target_name"],
            alert["rule_type"],
            alert.get("severity", "warning"),
            alert["message"],
            alert.get("detail", ""),
            ts,
        ),
    )
    logger.warning("ALERT [%s] %s: %s", alert["severity"], alert["target_name"], alert["message"])
    return True
