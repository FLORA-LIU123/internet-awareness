from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# dim_key -> (db_column, raw metric_type values that feed it)
_METRIC_MAP: Dict[str, tuple] = {
    "availability":      ("availability_score",   ["http"]),
    "response_time":     ("response_time_score",  ["response_time_ms", "icmp_latency"]),
    "link_connectivity": ("link_score",            ["icmp_loss", "ping_ms"]),
    "security_risk":     ("security_score",        ["threat_score", "tls_security"]),
}


def _mean_score(df: pd.DataFrame, metric_types: List[str]) -> Optional[float]:
    subset = df[df["metric_type"].isin(metric_types)]["normalized_score"]
    subset = pd.to_numeric(subset, errors="coerce").dropna()
    return round(float(subset.mean()), 2) if not subset.empty else None


def fuse_and_store(normalized_df: pd.DataFrame, db_path: str) -> pd.DataFrame:
    """
    Aggregate normalised per-metric rows into one fused row per target,
    persist to fused_metrics, and return the fused DataFrame.
    """
    if normalized_df.empty:
        return pd.DataFrame()

    rows = []
    ts = datetime.now(timezone.utc).isoformat()

    for target_name, group in normalized_df.groupby("target_name"):
        row: Dict[str, Any] = {"target_name": target_name, "fused_at": ts}
        for dim, (db_col, metric_types) in _METRIC_MAP.items():
            row[db_col] = _mean_score(group, metric_types)
        rows.append(row)

    fused_df = pd.DataFrame(rows)

    for _, r in fused_df.iterrows():
        db.execute(
            db_path,
            """INSERT INTO fused_metrics
               (target_name, availability_score, response_time_score,
                link_score, security_score, fused_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                r["target_name"],
                r.get("availability_score"),
                r.get("response_time_score"),
                r.get("link_score"),
                r.get("security_score"),
                r["fused_at"],
            ),
        )

    logger.debug("Fused %d target rows at %s", len(fused_df), ts)
    return fused_df
