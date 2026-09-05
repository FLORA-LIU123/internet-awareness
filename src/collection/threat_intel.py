from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


def _query_otx(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
    url = f"{_OTX_BASE}/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("OTX returned %d for IP %s", resp.status_code, ip)
    except Exception as exc:
        logger.error("OTX query error for %s: %s", ip, exc)
    return None


def _query_otx_reputation(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Query OTX reputation endpoint for additional risk signals."""
    url = f"{_OTX_BASE}/IPv4/{ip}/reputation"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _compute_threat_score(general: Dict[str, Any],
                           reputation: Optional[Dict[str, Any]] = None) -> float:
    """
    Compute a 0–10 threat score from OTX data.

    Scoring breakdown (max 10):
      - pulse_count:    0 pulses=0, 1=2, 2=4, 3=6, 5+=8, 10+=10  (up to 6 pts)
      - reputation:     threat_score from reputation endpoint       (up to 3 pts)
      - validation:     any malicious validation tags               (1 pt)
    """
    score = 0.0

    # Pulse count contribution (0–6)
    pulse_count = general.get("pulse_info", {}).get("count", 0)
    if pulse_count >= 10:
        score += 6.0
    elif pulse_count >= 5:
        score += 4.5
    elif pulse_count >= 3:
        score += 3.5
    elif pulse_count >= 2:
        score += 2.5
    elif pulse_count >= 1:
        score += 1.5

    # Reputation score contribution (0–3)
    if reputation and isinstance(reputation, dict):
        rep_score = (reputation.get("reputation") or {}).get("threat_score", 0) or 0
        score += min(float(rep_score) / 100.0 * 3.0, 3.0)

    # Validation tags (0–1)
    validation = general.get("validation", [])
    if isinstance(validation, list) and len(validation) > 0:
        score += 1.0

    return round(min(score, 10.0), 2)


def probe(target: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Query AlienVault OTX for the target IP and return a threat score (0–10)."""
    ip   = target.get("ip", "")
    name = target.get("name", ip)
    ts   = datetime.now(timezone.utc).isoformat()

    base: Dict[str, Any] = {
        "target_name": name,
        "target_url":  target.get("url", ""),
        "target_ip":   ip,
        "metric_type": "threat_score",
        "unit":        "score",
        "status_code": None,
        "collected_at": ts,
    }

    if not ip:
        logger.warning("No IP for target %s; skipping threat intel", name)
        return {**base, "value": None}

    if not api_key:
        logger.info("No OTX API key configured; returning neutral threat score")
        return {**base, "value": 0.0}

    general    = _query_otx(ip, api_key)
    reputation = _query_otx_reputation(ip, api_key)

    if general is None:
        return {**base, "value": None}

    score = _compute_threat_score(general, reputation)
    pulse_count = general.get("pulse_info", {}).get("count", 0)
    logger.info("Threat score for %s (%s): %.2f (pulses=%d)", name, ip, score, pulse_count)
    return {**base, "value": score}