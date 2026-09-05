import time
from datetime import datetime, timezone
from typing import Any, Dict

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)


def probe(target: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    """Send an HTTP GET to target URL and return availability metrics."""
    url = target.get("url", "")
    name = target.get("name", url)
    result: Dict[str, Any] = {
        "target_name": name,
        "target_url": url,
        "target_ip": target.get("ip", ""),
        "metric_type": "http",
        "value": None,
        "unit": "ms",
        "status_code": None,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "available": False,
    }

    if not url:
        logger.warning("No URL configured for target %s", name)
        return result

    try:
        start = time.perf_counter()
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "SituationalAwareness/1.0"})
        elapsed_ms = (time.perf_counter() - start) * 1000

        result["value"] = round(elapsed_ms, 2)
        result["status_code"] = resp.status_code
        result["available"] = resp.status_code < 500
        logger.debug("HTTP probe %s -> %d in %.1f ms", url, resp.status_code, elapsed_ms)
    except requests.exceptions.Timeout:
        result["status_code"] = 0
        logger.warning("HTTP probe timeout: %s", url)
    except requests.exceptions.ConnectionError:
        result["status_code"] = -1
        logger.warning("HTTP probe connection error: %s", url)
    except Exception as exc:
        result["status_code"] = -2
        logger.error("HTTP probe unexpected error for %s: %s", url, exc)

    return result
