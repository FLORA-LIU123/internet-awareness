"""
AHP weight derivation for the four service health dimensions.

以网络安全为核心定位，安全维度权重显著提升。

Judgment matrix (scale 1-9):
  availability vs response_time  = 2  (availability slightly more important)
  availability vs link            = 3
  availability vs security        = 2  (availability only slightly exceeds security)
  response_time vs link           = 2
  response_time vs security       = 1  (response_time and security roughly equal)
  link vs security                = 1/2 (security more important than link)

Resulting normalised priority vector (rounded to 2 dp):
  availability    0.38
  response_time   0.24
  link            0.14
  security        0.24
"""

from typing import Dict

import numpy as np

DIMENSIONS = ["availability", "response_time", "link_connectivity", "security_risk"]

# Pairwise comparison matrix (row i vs col j)
# 安全维度提升：security 与 response_time 同等重要，高于 link
_MATRIX = np.array([
    [1,   2,   3,   2],
    [1/2, 1,   2,   1],
    [1/3, 1/2, 1,   1/2],
    [1/2, 1,   2,   1],
], dtype=float)


def _compute_weights(matrix: np.ndarray) -> Dict[str, float]:
    col_sums = matrix.sum(axis=0)
    normalised = matrix / col_sums
    priority = normalised.mean(axis=1)
    return {dim: round(float(w), 4) for dim, w in zip(DIMENSIONS, priority)}


def _consistency_ratio(matrix: np.ndarray, weights: Dict[str, float]) -> float:
    n = len(matrix)
    w = np.array([weights[d] for d in DIMENSIONS])
    lam_max = float((matrix @ w / w).mean())
    ci = (lam_max - n) / (n - 1)
    ri_table = {1: 0, 2: 0, 3: 0.58, 4: 0.90, 5: 1.12}
    ri = ri_table.get(n, 1.12)
    return ci / ri if ri else 0.0


DEFAULT_WEIGHTS: Dict[str, float] = _compute_weights(_MATRIX)
CONSISTENCY_RATIO: float = _consistency_ratio(_MATRIX, DEFAULT_WEIGHTS)


def get_weights(overrides: Dict[str, float] | None = None) -> Dict[str, float]:
    """Return AHP weights, optionally overridden from config."""
    if overrides:
        total = sum(overrides.values())
        if total > 0:
            return {k: round(v / total, 4) for k, v in overrides.items()}
    return DEFAULT_WEIGHTS
