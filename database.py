"""
ShieldOS Engine — SQLite Database Layer
"""
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any

from config import DB_PATH

log = logging.getLogger("shieldos.database")

_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init_db() -> None:
    """Create all tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            path        TEXT NOT NULL,
            filename    TEXT NOT NULL,
            file_size   INTEGER,
            file_hash   TEXT,
            scan_type   TEXT,
            result      TEXT,
            threat_name TEXT,
            threat_type TEXT,
            severity    TEXT,
            action      TEXT,
            client_id   TEXT,
            engine      TEXT
        );

        CREATE TABLE IF NOT EXISTS quarantine (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            original_path   TEXT,
            quarantine_path TEXT,
            filename        TEXT,
            file_hash       TEXT,
            threat_name     TEXT,
            threat_type     TEXT,
            severity        TEXT,
            restored        INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_path TEXT,
            schedule    TEXT,
            last_run    TEXT,
            enabled     INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            hash        TEXT PRIMARY KEY,
            path        TEXT,
            added_by    TEXT,
            timestamp   TEXT
        );

        CREATE TABLE IF NOT EXISTS vt_cache (
            sha256      TEXT PRIMARY KEY,
            result_json TEXT,
            cached_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp
            ON scan_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_history_result
            ON scan_history(result);
        CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp
            ON quarantine(timestamp);
    """)
    conn.commit()
    log.info("Database initialised at %s", DB_PATH)


# ── Scan history ───────────────────────────────────────────────────────────

def log_scan(
    path: str,
    filename: str,
    result: str,
    file_size: int = 0,
    file_hash: str = "",
    scan_type: str = "manual",
    threat_name: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    action: str = "allowed",
    client_id: str = "SC-01",
    engine: Optional[str] = None,
) -> int:
    conn = _get_conn()
    cursor = conn.execute(
        """
        INSERT INTO scan_history
            (timestamp, path, filename, file_size, file_hash,
             scan_type, result, threat_name, threat_type, severity,
             action, client_id, engine)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            datetime.utcnow().isoformat(),
            path, filename, file_size, file_hash,
            scan_type, result, threat_name, threat_type, severity,
            action, client_id, engine,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_scan_history(limit: int = 100, offset: int = 0) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def get_threats(limit: int = 50) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        """SELECT * FROM scan_history
           WHERE result IN ('threat','suspicious')
           ORDER BY timestamp DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    threats = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE result='threat'"
    ).fetchone()[0]
    quarantined = conn.execute(
        "SELECT COUNT(*) FROM quarantine WHERE restored=0"
    ).fetchone()[0]
    last_scan_row = conn.execute(
        "SELECT timestamp FROM scan_history ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    last_scan = last_scan_row[0] if last_scan_row else None
    history_count = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    return {
        "total_scanned":    total,
        "threats_found":    threats,
        "quarantined":      quarantined,
        "last_scan":        last_scan,
        "scan_history_count": history_count,
    }


# ── Config ─────────────────────────────────────────────────────────────────

def get_config(key: str) -> Optional[str]:
    conn = _get_conn()
    row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_config(key: str, value: Any) -> None:
    conn = _get_conn()
    if isinstance(value, (list, dict)):
        value = json.dumps(value)
    else:
        value = str(value)
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        (key, value),
    )
    conn.commit()


def save_full_config(cfg: dict) -> None:
    for k, v in cfg.items():
        set_config(k, v)


# ── Quarantine ─────────────────────────────────────────────────────────────

def add_quarantine_entry(
    original_path: str,
    quarantine_path: str,
    filename: str,
    file_hash: str,
    threat_name: str,
    threat_type: str = "unknown",
    severity: str = "high",
) -> int:
    conn = _get_conn()
    cursor = conn.execute(
        """
        INSERT INTO quarantine
            (timestamp, original_path, quarantine_path, filename,
             file_hash, threat_name, threat_type, severity, restored)
        VALUES (?,?,?,?,?,?,?,?,0)
        """,
        (
            datetime.utcnow().isoformat(),
            original_path, quarantine_path, filename,
            file_hash, threat_name, threat_type, severity,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_quarantine(include_restored: bool = False) -> list[dict]:
    conn = _get_conn()
    query = "SELECT * FROM quarantine"
    if not include_restored:
        query += " WHERE restored=0"
    query += " ORDER BY timestamp DESC"
    rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


def get_quarantine_entry(qid: int) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    return dict(row) if row else None


def mark_quarantine_restored(qid: int) -> None:
    conn = _get_conn()
    conn.execute("UPDATE quarantine SET restored=1 WHERE id=?", (qid,))
    conn.commit()


def delete_quarantine_entry(qid: int) -> None:
    conn = _get_conn()
    conn.execute("DELETE FROM quarantine WHERE id=?", (qid,))
    conn.commit()


def get_quarantine_stats() -> dict:
    conn = _get_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM quarantine WHERE restored=0"
    ).fetchone()[0]
    oldest = conn.execute(
        "SELECT MIN(timestamp) FROM quarantine WHERE restored=0"
    ).fetchone()[0]
    return {"count": count, "oldest": oldest}


# ── Whitelist ──────────────────────────────────────────────────────────────

def add_to_whitelist(file_hash: str, path: str, added_by: str = "user") -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR IGNORE INTO whitelist (hash, path, added_by, timestamp)
        VALUES (?,?,?,?)
        """,
        (file_hash, path, added_by, datetime.utcnow().isoformat()),
    )
    conn.commit()


def is_whitelisted(file_hash: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT 1 FROM whitelist WHERE hash=?", (file_hash,)
    ).fetchone()
    return row is not None


def get_whitelist() -> list[dict]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM whitelist ORDER BY timestamp DESC").fetchall()
    return [dict(r) for r in rows]


# ── VirusTotal cache ───────────────────────────────────────────────────────

def vt_cache_get(sha256: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT result_json, cached_at FROM vt_cache WHERE sha256=?", (sha256,)
    ).fetchone()
    if not row:
        return None
    cached_at = datetime.fromisoformat(row["cached_at"])
    if datetime.utcnow() - cached_at > timedelta(hours=24):
        return None
    return json.loads(row["result_json"])


def vt_cache_set(sha256: str, result: dict) -> None:
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO vt_cache (sha256, result_json, cached_at) VALUES (?,?,?)",
        (sha256, json.dumps(result), datetime.utcnow().isoformat()),
    )
    conn.commit()


# ── Scheduled scans ────────────────────────────────────────────────────────

def get_scheduled_scans() -> list[dict]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM scheduled_scans WHERE enabled=1").fetchall()
    return [dict(r) for r in rows]


def update_scheduled_scan_last_run(scan_id: int) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE scheduled_scans SET last_run=? WHERE id=?",
        (datetime.utcnow().isoformat(), scan_id),
    )
    conn.commit()


def clear_scan_history() -> None:
    conn = _get_conn()
    conn.execute("DELETE FROM scan_history")
    conn.commit()


def close_db() -> None:
    global _conn
    if _conn:
        _conn.close()
        _conn = None
