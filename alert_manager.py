"""Stores and retrieves Alerts using a local SQLite database."""

import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from typing import List, Optional

from siem.detector import Alert

DB_PATH = "siem_alerts.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user TEXT NOT NULL,
    description TEXT NOT NULL
);
"""


@contextmanager
def get_connection(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH) -> None:
    """Create the alerts table if it doesn't already exist."""
    with get_connection(db_path) as conn:
        conn.execute(SCHEMA)
        conn.commit()


def save_alerts(alerts: List[Alert], db_path: str = DB_PATH) -> int:
    """Insert a list of Alerts into the database. Returns the number inserted."""
    if not alerts:
        return 0

    with get_connection(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO alerts (timestamp, alert_type, severity, source_ip, user, description)
            VALUES (:timestamp, :alert_type, :severity, :source_ip, :user, :description)
            """,
            [
                {**asdict(a), "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
                for a in alerts
            ],
        )
        conn.commit()
        return len(alerts)


def fetch_alerts(
    db_path: str = DB_PATH,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    date: Optional[str] = None,
) -> List[sqlite3.Row]:
    """Fetch alerts, optionally filtered by severity, source_ip, or a date (YYYY-MM-DD)."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if date:
        query += " AND timestamp LIKE ?"
        params.append(f"{date}%")

    query += " ORDER BY timestamp DESC"

    with get_connection(db_path) as conn:
        return conn.execute(query, params).fetchall()


def alert_counts(db_path: str = DB_PATH) -> dict:
    """Return summary counts used by the dashboard header (total, by severity)."""
    with get_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        high = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE severity = 'High'"
        ).fetchone()["c"]
        medium = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE severity = 'Medium'"
        ).fetchone()["c"]
        low = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE severity = 'Low'"
        ).fetchone()["c"]

    return {"total": total, "high": high, "medium": medium, "low": low}
