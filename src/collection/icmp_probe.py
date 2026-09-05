import subprocess
import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


def _parse_ping_output(output: str) -> Dict[str, Optional[float]]:
    """Parse cross-platform ping output for avg latency and packet loss."""
    result: Dict[str, Optional[float]] = {"avg_ms": None, "packet_loss_pct": None}

    import re

    # Packet loss patterns:
    #   Windows EN:  "0% loss" / "0% packet loss"
    #   Windows CN:  "(0% 丢失)" or "(0%丢失)"
    #   Unix:        "0% packet loss"
    m = re.search(r"\(?([\d.]+)%\s*(?:loss|packet loss|丢失|丢包)", output, re.IGNORECASE)
    if m:
        result["packet_loss_pct"] = float(m.group(1))
    else:
        # Fallback: first standalone percentage in the stats section
        m = re.search(r"([\d.]+)%", output)
        if m:
            result["packet_loss_pct"] = float(m.group(1))

    # Average RTT patterns:
    #   Windows EN:  "Average = 25ms"
    #   Windows CN:  "平均 = 25ms"  (may be garbled as "ƽ�� = 25ms")
    #   Unix:        "rtt min/avg/max/mdev = 10.1/25.3/40.5/5.2 ms"
    m = re.search(r"(?:average|平均|ƽ��)\s*=\s*([\d.]+)\s*ms", output, re.IGNORECASE)
    if m:
        result["avg_ms"] = float(m.group(1))
        return result
    # Unix format
    m = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms", output)
    if m:
        result["avg_ms"] = float(m.group(1))
        return result
    # Windows fallback: any "= Xms" near the end of output
    m = re.search(r"=\s*([\d.]+)ms", output.split("\n")[-3] if "\n" in output else output,
                  re.IGNORECASE)
    if m:
        result["avg_ms"] = float(m.group(1))
    return result


def probe(target: Dict[str, Any], count: int = 4) -> Dict[str, Any]:
    """ICMP ping target IP and return latency / packet-loss metrics."""
    ip = target.get("ip", "")
    name = target.get("name", ip)
    base: Dict[str, Any] = {
        "target_name": name,
        "target_url": target.get("url", ""),
        "target_ip": ip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }

    if not ip:
        logger.warning("No IP configured for target %s", name)
        return {**base, "metric_type": "icmp_latency", "value": None, "unit": "ms",
                "status_code": None}

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), ip]
    else:
        cmd = ["ping", "-c", str(count), ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30)
        # Try UTF-8 first, fall back to GBK (Windows Chinese), then latin-1
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                output = proc.stdout.decode(enc)
                break
            except (UnicodeDecodeError, AttributeError):
                continue
        else:
            output = proc.stdout.decode("latin-1", errors="replace")

        parsed = _parse_ping_output(output)
        logger.debug("ICMP probe %s -> avg=%s ms loss=%s%%",
                     ip, parsed["avg_ms"], parsed["packet_loss_pct"])
        return [
            {**base, "metric_type": "icmp_latency",
             "value": parsed["avg_ms"], "unit": "ms", "status_code": None},
            {**base, "metric_type": "icmp_loss",
             "value": parsed["packet_loss_pct"], "unit": "%", "status_code": None},
        ]
    except subprocess.TimeoutExpired:
        logger.warning("ICMP probe timeout for %s", ip)
    except FileNotFoundError:
        logger.error("ping command not found")
    except Exception as exc:
        logger.error("ICMP probe error for %s: %s", ip, exc)

    return [
        {**base, "metric_type": "icmp_latency", "value": None, "unit": "ms", "status_code": None},
        {**base, "metric_type": "icmp_loss", "value": 100.0, "unit": "%", "status_code": None},
    ]
