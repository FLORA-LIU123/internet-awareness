import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, List, Optional, Tuple

import pandas as pd

from src.storage.schema import DDL_STATEMENTS
from src.utils.logger import get_logger

logger = get_logger(__name__)


def _resolve_path(db_path: str) -> Path:
    p = Path(db_path)
    if not p.is_absolute():
        p = Path(__file__).resolve().parents[2] / p
    return p


def _migrate(conn: sqlite3.Connection) -> None:
    """对已存在的表补齐新增列（CREATE TABLE IF NOT EXISTS 不会修改既有表结构）。"""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(content_snapshots)")}
    if "page_path" not in cols:
        conn.execute(
            "ALTER TABLE content_snapshots ADD COLUMN page_path TEXT NOT NULL DEFAULT ''"
        )
        logger.info("Migrated content_snapshots: added page_path column")


def init_db(db_path: str) -> None:
    path = _resolve_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        for stmt in DDL_STATEMENTS:
            conn.execute(stmt)
        _migrate(conn)
        conn.commit()
    logger.info("Database initialised at %s", path)


@contextmanager
def get_connection(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    path = _resolve_path(db_path)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> None:
    with get_connection(db_path) as conn:
        conn.execute(sql, params)


def executemany(db_path: str, sql: str, params_list: List[Tuple[Any, ...]]) -> None:
    with get_connection(db_path) as conn:
        conn.executemany(sql, params_list)


def query_df(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> pd.DataFrame:
    path = _resolve_path(db_path)
    with sqlite3.connect(str(path)) as conn:
        return pd.read_sql_query(sql, conn, params=params)
