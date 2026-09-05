import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


def _run_speedtest() -> Dict[str, Optional[float]]:
    """Run speedtest-cli and return download/upload in Mbps and ping in ms."""
    result: Dict[str, Optional[float]] = {
        "download_mbps": None,
        "upload_mbps": None,
        "ping_ms": None,
    }
    try:
        proc = subprocess.run(
            ["speedtest-cli", "--simple"],
            capture_output=True, text=True, timeout=120,
        )
        for line in proc.stdout.splitlines():
            lower = line.lower()
            if lower.startswith("ping"):
                result["ping_ms"] = float(line.split()[1])
            elif lower.startswith("download"):
                result["download_mbps"] = float(line.split()[1])
            elif lower.startswith("upload"):
                result["upload_mbps"] = float(line.split()[1])
    except FileNotFoundError:
        logger.warning("speedtest-cli not installed; skipping speed test")
    except subprocess.TimeoutExpired:
        logger.warning("speedtest-cli timed out")
    except Exception as exc:
        logger.error("Speed test error: %s", exc)
    return result


def probe() -> Dict[str, Any]:
    """Run a global speed test and return structured metrics."""
    ts = datetime.now(timezone.utc).isoformat()
    data = _run_speedtest()
    logger.debug("Speed test: download=%.1f Mbps upload=%.1f Mbps ping=%.1f ms",
                 data["download_mbps"] or 0, data["upload_mbps"] or 0, data["ping_ms"] or 0)
    return {
        "collected_at": ts,
        "download_mbps": data["download_mbps"],
        "upload_mbps": data["upload_mbps"],
        "ping_ms": data["ping_ms"],
    }
