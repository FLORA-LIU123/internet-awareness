from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import pandas as pd

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Metrics where a higher raw value means worse performance (inverted for scoring)
_INVERT_METRICS = {"response_time_ms", "icmp_latency", "icmp_loss", "threat_score"}


# Sensible initial bounds per metric type so cold-start doesn't collapse scores to 0
_DEFAULT_BOUNDS: Dict[str, Tuple[float, float]] = {
    "response_time_ms": (0.0, 5000.0),   # 0–5 s
    "icmp_latency":     (0.0, 500.0),    # 0–500 ms
    "icmp_loss":        (0.0, 100.0),    # 0–100 %
    "threat_score":     (0.0, 10.0),     # OTX 0–10
    "http":             (0.0, 100.0),    # availability score 0/100
    "ping_ms":          (0.0, 500.0),
    "tls_security":     (0.0, 100.0),   # TLS/HTTP security composite score
}


def _get_bounds(db_path: str, target: str, metric: str) -> Tuple[float, float]:
    df = db.query_df(
        db_path,
        "SELECT min_val, max_val FROM metric_bounds WHERE target_name=? AND metric_name=?",
        (target, metric),
    )
    if df.empty:
        return _DEFAULT_BOUNDS.get(metric, (0.0, 100.0))
    return float(df.iloc[0]["min_val"]), float(df.iloc[0]["max_val"])


def _update_bounds(db_path: str, target: str, metric: str,
                   new_min: float, new_max: float) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    db.execute(
        db_path,
        """INSERT INTO metric_bounds (target_name, metric_name, min_val, max_val, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(target_name, metric_name) DO UPDATE SET
               min_val=excluded.min_val,
               max_val=excluded.max_val,
               updated_at=excluded.updated_at""",
        (target, metric, new_min, new_max, ts),
    )


def normalize(value: float, min_val: float, max_val: float, invert: bool = False) -> float:
    """Map value to [0, 100] using Min-Max scaling."""
    if max_val == min_val:
        return 50.0
    score = (value - min_val) / (max_val - min_val) * 100.0
    score = max(0.0, min(100.0, score))
    return round(100.0 - score if invert else score, 2)


def normalize_series(df: pd.DataFrame, db_path: str) -> pd.DataFrame:
    """Add a 'normalized_score' column to a cleaned metrics DataFrame."""
    if df.empty or "value" not in df.columns:
        return df

    df = df.copy()
    df["normalized_score"] = None

    for (target, metric), group in df.groupby(["target_name", "metric_type"]):
        vals = pd.to_numeric(group["value"], errors="coerce").dropna()
        if vals.empty:
            continue

        cur_min, cur_max = _get_bounds(db_path, target, metric)
        new_min = min(cur_min, float(vals.min()))
        new_max = max(cur_max, float(vals.max()))
        _update_bounds(db_path, target, metric, new_min, new_max)

        invert = metric in _INVERT_METRICS
        for idx in group.index:
            raw = pd.to_numeric(df.at[idx, "value"], errors="coerce")
            if pd.notna(raw):
                df.at[idx, "normalized_score"] = normalize(
                    float(raw), new_min, new_max, invert=invert
                )

    return df
