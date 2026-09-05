DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS raw_metrics (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name TEXT    NOT NULL,
        target_url  TEXT,
        target_ip   TEXT,
        metric_type TEXT    NOT NULL,
        value       REAL,
        unit        TEXT,
        status_code INTEGER,
        collected_at TEXT   NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_raw_target_time
        ON raw_metrics (target_name, collected_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS fused_metrics (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name         TEXT    NOT NULL,
        availability_score  REAL,
        response_time_score REAL,
        link_score          REAL,
        security_score      REAL,
        fused_at            TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_fused_target_time
        ON fused_metrics (target_name, fused_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS health_scores (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name  TEXT    NOT NULL,
        score        REAL    NOT NULL,
        scored_at    TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_health_target_time
        ON health_scores (target_name, scored_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name  TEXT    NOT NULL,
        rule_type    TEXT    NOT NULL,
        severity     TEXT    NOT NULL,
        message      TEXT    NOT NULL,
        detail       TEXT,
        acknowledged INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT    NOT NULL,
        ack_at       TEXT
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_target_time
        ON alerts (target_name, created_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS metric_bounds (
        target_name  TEXT NOT NULL,
        metric_name  TEXT NOT NULL,
        min_val      REAL NOT NULL DEFAULT 0,
        max_val      REAL NOT NULL DEFAULT 1,
        updated_at   TEXT NOT NULL,
        PRIMARY KEY (target_name, metric_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS content_snapshots (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name     TEXT    NOT NULL,
        target_url      TEXT    NOT NULL,
        page_path       TEXT    NOT NULL DEFAULT '',
        content_hash    TEXT    NOT NULL,
        content_length  INTEGER,
        status_code     INTEGER,
        changed         INTEGER NOT NULL DEFAULT 0,
        prev_hash       TEXT,
        change_summary  TEXT,
        collected_at    TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_snapshots_target_time
        ON content_snapshots (target_name, collected_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS discovered_assets (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name  TEXT    NOT NULL,
        root_domain  TEXT    NOT NULL,
        subdomain    TEXT    NOT NULL,
        source       TEXT    NOT NULL DEFAULT 'crt.sh',
        first_seen   TEXT    NOT NULL,
        last_seen    TEXT    NOT NULL,
        UNIQUE (target_name, subdomain)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_assets_target
        ON discovered_assets (target_name)
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_index (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name         TEXT    NOT NULL,
        risk_score          REAL    NOT NULL,
        risk_level          TEXT    NOT NULL,
        health_trend_risk   REAL,
        threat_trend_risk   REAL,
        content_tamper_risk REAL,
        computed_at         TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_risk_target_time
        ON risk_index (target_name, computed_at)
    """,
    # ── 威胁情报跨目标关联 ────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS threat_correlations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        correlation_id  TEXT    NOT NULL,
        target_name     TEXT    NOT NULL,
        threat_score    REAL    NOT NULL,
        pulse_count     INTEGER NOT NULL DEFAULT 0,
        correlated_with TEXT,
        pattern         TEXT,
        computed_at     TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_threat_corr_time
        ON threat_correlations (computed_at)
    """,
    # ── 内容完整性精细检测 ────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS content_integrity_checks (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name     TEXT    NOT NULL,
        target_url      TEXT    NOT NULL,
        region_hashes   TEXT,
        injected_kws    TEXT,
        tamper_score    REAL    NOT NULL DEFAULT 0,
        checked_at      TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_integrity_target_time
        ON content_integrity_checks (target_name, checked_at)
    """,
    # ── 攻击链推断结果缓存 ────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS attack_chains (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        target_name     TEXT    NOT NULL,
        chain_type      TEXT    NOT NULL,
        stage_sequence  TEXT    NOT NULL,
        confidence      REAL    NOT NULL DEFAULT 0,
        first_event_at  TEXT    NOT NULL,
        last_event_at   TEXT    NOT NULL,
        detail          TEXT,
        computed_at     TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_chain_target_time
        ON attack_chains (target_name, computed_at)
    """,
    # ── 自适应基线 ────────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS time_baselines (
        target_name     TEXT    NOT NULL,
        metric          TEXT    NOT NULL,
        hour_of_day     INTEGER NOT NULL,
        day_of_week     INTEGER NOT NULL,
        baseline_mean   REAL    NOT NULL,
        baseline_std    REAL    NOT NULL DEFAULT 0,
        sample_count    INTEGER NOT NULL DEFAULT 0,
        updated_at      TEXT    NOT NULL,
        PRIMARY KEY (target_name, metric, hour_of_day, day_of_week)
    )
    """,
]