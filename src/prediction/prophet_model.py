"""
Time-series forecasting with three-tier strategy:
  1. NeuralProphet  — preferred, requires PyTorch
  2. Holt-Winters   — automatic fallback, pure Python via statsmodels
  3. Linear trend   — last resort for very sparse data (< 5 points)

Raw data is resampled to a uniform daily grid before training.
Forecast horizon is always 7 days (one week) ahead.
"""
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import numpy as np
import pandas as pd

# On Windows, pytorch_lightning triggers a fresh DLL load of c10.dll and its
# dependencies. torch.__init__._load_dll_libraries() registers all required
# directories via os.add_dll_directory(); calling it explicitly here ensures
# the DLL search path is set up before neuralprophet imports pytorch_lightning,
# regardless of import order in the Streamlit process.
try:
    import torch as _torch
    if hasattr(_torch, "_load_dll_libraries"):
        _torch._load_dll_libraries()
except Exception:
    pass

from src.storage import db
from src.utils.logger import get_logger

logger = get_logger(__name__)

_cache: Dict[Tuple[str, str], Any] = {}
_cache_lock = threading.Lock()

DEFAULT_FORECAST_DAYS = 7
_RESAMPLE_FREQ = "D"
_RESAMPLE_FREQ_STR = "D"

# Module-level import cache — None means not yet attempted, False means unavailable
_NeuralProphet = None


# ── Data loading ─────────────────────────────────────────────────────────────

def _load_series(db_path: str, target: str, metric_col: str,
                 lookback_hours: int = 720) -> pd.DataFrame:
    """Load and resample to a uniform daily grid (naive UTC ds, float y)."""
    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    sql = f"""
        SELECT fused_at AS ds, {metric_col} AS y
        FROM fused_metrics
        WHERE target_name = ?
          AND fused_at >= ?
          AND {metric_col} IS NOT NULL
        ORDER BY fused_at
    """
    df = db.query_df(db_path, sql, (target, since))
    if df.empty:
        return df

    df["ds"] = pd.to_datetime(df["ds"], utc=True)
    df["y"] = pd.to_numeric(df["y"], errors="coerce")
    df = df.dropna(subset=["y"])
    if df.empty:
        return df

    df = df.set_index("ds").resample(_RESAMPLE_FREQ)["y"].mean().dropna().reset_index()
    df["ds"] = df["ds"].dt.tz_convert(None)
    return df


# ── Tier 3: linear trend (sparse data only) ──────────────────────────────────

def _linear_forecast(df: pd.DataFrame, forecast_days: int = DEFAULT_FORECAST_DAYS) -> pd.DataFrame:
    """Simple linear regression — only used when < 5 daily points available."""
    n = len(df)
    x = np.arange(n, dtype=float)
    y = df["y"].values.astype(float)

    slope, intercept = np.polyfit(x, y, 1)
    std = max(y.std() if n > 2 else 5.0, 1.0)

    last_ds = df["ds"].iloc[-1]
    future_ds = [last_ds + timedelta(days=i + 1) for i in range(forecast_days)]
    future_x = np.arange(n, n + forecast_days, dtype=float)
    future_y = slope * future_x + intercept

    time_factor = np.linspace(1.0, 2.5, forecast_days)
    lower = future_y - std * time_factor
    upper = future_y + std * time_factor

    out = pd.DataFrame({
        "ds":         list(df["ds"]) + future_ds,
        "yhat":       np.concatenate([y, future_y]),
        "yhat_lower": np.concatenate([y - std * 0.5, lower]),
        "yhat_upper": np.concatenate([y + std * 0.5, upper]),
    })
    out["yhat"]       = out["yhat"].clip(0, 100)
    out["yhat_lower"] = out["yhat_lower"].clip(0, 105)
    out["yhat_upper"] = out["yhat_upper"].clip(0, 105)
    return out

def _holtwinters_forecast(df: pd.DataFrame, forecast_days: int = DEFAULT_FORECAST_DAYS) -> pd.DataFrame:
    """
    Holt-Winters triple exponential smoothing via statsmodels.
    No PyTorch dependency — pure Python fallback when NeuralProphet is unavailable.
    Automatically selects additive/damped trend based on data length.
    """
    from statsmodels.tsa.holtwinters import ExponentialSmoothing

    y = df["y"].values.astype(float)
    n = len(y)

    # Need at least 2 seasonal periods for seasonal model; use trend-only otherwise
    use_seasonal = n >= 14
    try:
        model = ExponentialSmoothing(
            y,
            trend="add",
            damped_trend=True,
            seasonal="add" if use_seasonal else None,
            seasonal_periods=7 if use_seasonal else None,
            initialization_method="estimated",
        )
        fit = model.fit(optimized=True, remove_bias=False)
    except Exception:
        # If seasonal fitting fails, fall back to simple trend-only
        model = ExponentialSmoothing(y, trend="add", damped_trend=True)
        fit = model.fit(optimized=True)

    future_y = fit.forecast(forecast_days)

    # Confidence interval: use in-sample residual std, widening over horizon.
    # Use at least 1.0 std so the band is always visible on the chart.
    resid_std = max(np.std(fit.resid), 1.0)
    time_factor = np.linspace(1.0, 2.0, forecast_days)
    lower = future_y - resid_std * 1.96 * time_factor
    upper = future_y + resid_std * 1.96 * time_factor

    last_ds = df["ds"].iloc[-1]
    future_ds = [last_ds + timedelta(days=i + 1) for i in range(forecast_days)]

    # Historic fitted values with confidence band
    hist_fitted = fit.fittedvalues
    hist_std = resid_std * 0.5
    out = pd.DataFrame({
        "ds":         list(df["ds"]) + future_ds,
        "yhat":       np.concatenate([hist_fitted, future_y]),
        "yhat_lower": np.concatenate([hist_fitted - hist_std, lower]),
        "yhat_upper": np.concatenate([hist_fitted + hist_std, upper]),
    })
    out["yhat"]       = out["yhat"].clip(0, 100)
    out["yhat_lower"] = out["yhat_lower"].clip(0, 105)
    out["yhat_upper"] = out["yhat_upper"].clip(0, 105)
    return out


# ── Tier 1: NeuralProphet ────────────────────────────────────────────────────

def _get_neuralprophet():
    """Import NeuralProphet once and cache the class. Returns None only if import fails."""
    global _NeuralProphet
    if _NeuralProphet is not None:
        return _NeuralProphet
    try:
        import torch  # noqa: F401 — must be imported first so Windows DLL search path is set
        from neuralprophet import NeuralProphet, set_log_level
        set_log_level("ERROR")
        _NeuralProphet = NeuralProphet
        logger.info("NeuralProphet loaded successfully")
        return _NeuralProphet
    except Exception as exc:
        logger.warning("NeuralProphet import failed (%s), will use Holt-Winters", exc)
        return None


def _fit_and_predict(df: pd.DataFrame, forecast_days: int = DEFAULT_FORECAST_DAYS) -> pd.DataFrame:
    """
    Fit NeuralProphet. Falls back to Holt-Winters if PyTorch unavailable or
    if the series is a constant (singular value — NeuralProphet cannot normalise it).
    """
    NeuralProphet = _get_neuralprophet()
    if NeuralProphet is None:
        result = _holtwinters_forecast(df, forecast_days)
        result.attrs["_used_model"] = "Holt-Winters 指数平滑"
        return result

    # NeuralProphet cannot handle constant series (zero variance → singular value error).
    if df["y"].nunique() <= 1:
        logger.debug("Constant series detected, using Holt-Winters instead of NeuralProphet")
        result = _holtwinters_forecast(df, forecast_days)
        result.attrs["_used_model"] = "Holt-Winters 指数平滑"
        return result

    n_points = len(df)
    m = NeuralProphet(
        yearly_seasonality=False,
        weekly_seasonality=n_points >= 14,
        daily_seasonality=False,
        quantiles=[0.1, 0.9],
        epochs=min(300, max(50, n_points * 8)),
        batch_size=min(32, max(4, n_points // 2)),
        learning_rate=0.003,
        # Disable LR auto-finder: it uses torch.load with weights_only=True which
        # breaks on torch>=2.6 with NeuralProphet's custom config classes.
        # A fixed LR is fine for short time-series forecasting.
        trainer_config={"accelerator": "cpu", "enable_progress_bar": False},
    )

    m.fit(df, freq=_RESAMPLE_FREQ_STR, progress=False, minimal=True)
    future = m.make_future_dataframe(df, periods=forecast_days, n_historic_predictions=True)
    forecast_df = m.predict(future)

    yhat_col  = "yhat1"
    lower_col = "yhat1 10.0%"
    upper_col = "yhat1 90.0%"

    out = forecast_df[["ds", yhat_col]].rename(columns={yhat_col: "yhat"}).copy()
    if lower_col in forecast_df.columns:
        out["yhat_lower"] = forecast_df[lower_col].values
        out["yhat_upper"] = forecast_df[upper_col].values
    else:
        std = max(df["y"].std() if len(df) > 2 else 5.0, 1.0)
        out["yhat_lower"] = out["yhat"] - 1.5 * std
        out["yhat_upper"] = out["yhat"] + 1.5 * std

    # Ensure minimum visible band width (at least 1 point) so the confidence
    # interval is always visible on the chart even for near-constant series.
    band_width = out["yhat_upper"] - out["yhat_lower"]
    too_narrow = band_width < 1.0
    if too_narrow.any():
        std_fallback = max(df["y"].std(), 0.5)
        out.loc[too_narrow, "yhat_lower"] = out.loc[too_narrow, "yhat"] - std_fallback
        out.loc[too_narrow, "yhat_upper"] = out.loc[too_narrow, "yhat"] + std_fallback

    out["yhat"]       = out["yhat"].clip(0, 100)
    # Allow confidence bounds to slightly exceed [0,100] so the band stays
    # visible when the forecast is near a boundary — chart y-axis goes to 105.
    out["yhat_lower"] = out["yhat_lower"].clip(0, 105)
    out["yhat_upper"] = out["yhat_upper"].clip(0, 105)
    out.attrs["_used_model"] = "NeuralProphet"
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def forecast(db_path: str, target: str, metric_col: str,
             forecast_days: int = DEFAULT_FORECAST_DAYS,
             min_points: int = 2,
             refit_interval_minutes: int = 30,
             horizon_hours: int = 0) -> Optional[pd.DataFrame]:
    """
    Return forecast DataFrame: ds (naive UTC), yhat, yhat_lower, yhat_upper.
    attrs["method"] and attrs["train_days"] are set on the result.

    Strategy:
      >= 5 points  → NeuralProphet (or Holt-Winters if PyTorch unavailable)
      3-4 points   → linear trend
      < 3 points   → None
    """
    cache_key = (target, metric_col)
    now = datetime.now(timezone.utc)

    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached:
            fitted_at, last_forecast = cached
            if (now - fitted_at).total_seconds() / 60 < refit_interval_minutes:
                return last_forecast

    df = _load_series(db_path, target, metric_col)
    if len(df) < min_points:
        logger.debug("Not enough data for %s/%s (%d pts)", target, metric_col, len(df))
        return None

    try:
        if len(df) >= 5:
            result = _fit_and_predict(df, forecast_days)
            # _fit_and_predict may silently fall back to Holt-Winters (constant series,
            # NeuralProphet unavailable, etc.) — read the actual model used from attrs.
            method = result.attrs.get("_used_model", "NeuralProphet" if _NeuralProphet is not None else "Holt-Winters 指数平滑")
        else:
            result = _linear_forecast(df, forecast_days)
            method = "线性趋势外推（数据积累中）"

        result.attrs["method"] = method
        result.attrs["train_days"] = len(df)
        with _cache_lock:
            _cache[cache_key] = (now, result)
        logger.info("%s OK: %s/%s (%d days → %d rows, %dd ahead)",
                    method, target, metric_col, len(df), len(result), forecast_days)
        return result

    except Exception as exc:
        logger.error("Forecast error %s/%s: %s", target, metric_col, exc, exc_info=True)
        try:
            result = _holtwinters_forecast(df, forecast_days)
            result.attrs["method"] = "Holt-Winters 指数平滑"
            result.attrs["train_days"] = len(df)
            with _cache_lock:
                _cache[cache_key] = (now, result)
            return result
        except Exception:
            return None


def forecast_series(df: pd.DataFrame, forecast_days: int = DEFAULT_FORECAST_DAYS,
                    min_points: int = 3) -> Optional[pd.DataFrame]:
    """
    Public wrapper around the tiered fit/predict strategy for a caller-supplied
    (ds, y) daily series that doesn't live in fused_metrics (e.g. health_scores).
    Same tiering as forecast(): >=5 pts NeuralProphet/Holt-Winters, else linear.
    """
    if len(df) < min_points:
        return None
    try:
        if len(df) >= 5:
            return _fit_and_predict(df, forecast_days)
        return _linear_forecast(df, forecast_days)
    except Exception as exc:
        logger.error("forecast_series error: %s", exc, exc_info=True)
        try:
            return _holtwinters_forecast(df, forecast_days)
        except Exception:
            return None


def get_latest_prediction(db_path: str, target: str, metric_col: str,
                          **kwargs: Any) -> Optional[Dict[str, float]]:
    """Return next-step prediction {yhat, yhat_lower, yhat_upper}."""
    fc = forecast(db_path, target, metric_col, **kwargs)
    if fc is None or fc.empty:
        return None
    now_naive = pd.Timestamp.utcnow().normalize().tz_localize(None)
    future_rows = fc[fc["ds"] > now_naive]
    if future_rows.empty:
        return None
    row = future_rows.iloc[0]
    return {
        "yhat":       round(float(row["yhat"]), 2),
        "yhat_lower": round(float(row["yhat_lower"]), 2),
        "yhat_upper": round(float(row["yhat_upper"]), 2),
    }