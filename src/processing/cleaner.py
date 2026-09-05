from typing import Any, Dict, List, Optional

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Columns that must not be null for a row to be kept
_REQUIRED_COLS = {"target_name", "metric_type", "collected_at"}

# IQR multiplier for outlier removal
_IQR_FACTOR = 3.0


def clean(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Clean a list of raw metric dicts and return a sanitised DataFrame."""
    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)

    # Drop rows missing required fields
    for col in _REQUIRED_COLS:
        if col in df.columns:
            df = df[df[col].notna() & (df[col] != "")]

    # Parse timestamps
    if "collected_at" in df.columns:
        df["collected_at"] = pd.to_datetime(df["collected_at"], utc=True, errors="coerce")
        df = df[df["collected_at"].notna()]

    # Remove duplicate (target_name, metric_type, collected_at) rows
    if {"target_name", "metric_type", "collected_at"}.issubset(df.columns):
        df = df.drop_duplicates(subset=["target_name", "metric_type", "collected_at"])

    # Remove numeric outliers per (target_name, metric_type) group
    if "value" in df.columns:
        df = _remove_outliers(df)

    df = df.reset_index(drop=True)
    logger.debug("Cleaned %d records -> %d after cleaning", len(records), len(df))
    return df


def _remove_outliers(df: pd.DataFrame) -> pd.DataFrame:
    mask = pd.Series([True] * len(df), index=df.index)
    numeric = df["value"].apply(pd.to_numeric, errors="coerce")

    for (target, metric), group in df.groupby(["target_name", "metric_type"]):
        vals = numeric.loc[group.index].dropna()
        if len(vals) < 4:
            continue
        q1, q3 = vals.quantile(0.25), vals.quantile(0.75)
        iqr = q3 - q1
        lo, hi = q1 - _IQR_FACTOR * iqr, q3 + _IQR_FACTOR * iqr
        outliers = group.index[numeric.loc[group.index].notna() &
                               ((numeric.loc[group.index] < lo) |
                                (numeric.loc[group.index] > hi))]
        mask.loc[outliers] = False

    removed = (~mask).sum()
    if removed:
        logger.debug("Removed %d outlier rows", removed)
    return df[mask]
