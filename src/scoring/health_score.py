from datetime import datetime, timezone
from typing import Any, Dict, Optional

import math

import pandas as pd

from src.scoring.ahp_weights import get_weights
from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Maps AHP dimension name -> DB column in fused_metrics
_DIM_COLS = {
    "availability":      "availability_score",
    "response_time":     "response_time_score",
    "link_connectivity": "link_score",
    "security_risk":     "security_score",
}


def compute(fused_row: Dict[str, Any],
            weight_overrides: Optional[Dict[str, float]] = None) -> float:
    """Compute H = Σ(wi × Si) for a single fused metrics row."""
    weights = get_weights(weight_overrides)
    total, weight_sum = 0.0, 0.0

    for dim, col in _DIM_COLS.items():
        score = fused_row.get(col)
        if score is not None and not (isinstance(score, float) and math.isnan(score)):
            w = weights.get(dim, 0.0)
            total += w * float(score)
            weight_sum += w

    if weight_sum == 0:
        return 0.0
    return round(total / weight_sum, 2)


def compute_and_store(fused_df: pd.DataFrame, db_path: str,
                      weight_overrides: Optional[Dict[str, float]] = None) -> pd.DataFrame:
    """Compute health scores for all rows in fused_df and persist them."""
    if fused_df.empty:
        return pd.DataFrame()

    ts = datetime.now(timezone.utc).isoformat()
    results = []
    params_list = []

    for _, row in fused_df.iterrows():
        score = compute(row.to_dict(), weight_overrides)
        if score is None:
            score = 0.0
        results.append({"target_name": row["target_name"], "score": score, "scored_at": ts})
        params_list.append((row["target_name"], score, ts))
        logger.info("Health score for %s: %.1f", row["target_name"], score)

    db.executemany(
        db_path,
        "INSERT INTO health_scores (target_name, score, scored_at) VALUES (?, ?, ?)",
        params_list,
    )
    return pd.DataFrame(results)
