import logging
import logging.handlers
import os
from pathlib import Path


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def setup_logging(level: str = "INFO", log_file: str = "logs/app.log",
                  max_bytes: int = 10_485_760, backup_count: int = 5) -> None:
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not root.handlers:
        import sys
        ch = logging.StreamHandler()
        if hasattr(ch.stream, 'reconfigure'):
            ch.stream.reconfigure(encoding='utf-8')
        ch.setFormatter(fmt)
        root.addHandler(ch)

        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
