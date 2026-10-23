"""SQLite storage.

WAL mode lets the dashboard read while the sensor writes. When the sensor
runs under sudo, the database files are handed back to the real user so the
dashboard (running without root) can still write labels and acks.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    last_ip    TEXT,
    hostname   TEXT,
    vendor     TEXT,
    label      TEXT,
    randomized INTEGER NOT NULL DEFAULT 0,
    packets    INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0
);

-- One row per (device, registrable domain): the per-device DNS baseline.
CREATE TABLE IF NOT EXISTS device_domains (
    mac          TEXT NOT NULL,
    domain       TEXT NOT NULL,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    queries      INTEGER NOT NULL DEFAULT 0,
    sample_qname TEXT,
    PRIMARY KEY (mac, domain)
);

-- Hour-of-day activity per device: the time-of-day and volume baselines.
CREATE TABLE IF NOT EXISTS activity (
    mac         TEXT NOT NULL,
    day         TEXT NOT NULL,      -- local date, YYYY-MM-DD
    hour        INTEGER NOT NULL,   -- local hour, 0-23
    packets     INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    ext_packets INTEGER NOT NULL DEFAULT 0,  -- sent to internet addresses
    ext_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, day, hour)
);

-- Who each device talks to, with the DNS name that resolved to that IP.
CREATE TABLE IF NOT EXISTS destinations (
    mac        TEXT NOT NULL,
    dst_ip     TEXT NOT NULL,
    dst_port   INTEGER NOT NULL,
    proto      TEXT NOT NULL,
    domain     TEXT,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    packets    INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, dst_ip, dst_port, proto)
);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    mac      TEXT,
    title    TEXT NOT NULL,
    detail   TEXT,
    dedupe   TEXT NOT NULL UNIQUE,
    acked    INTEGER NOT NULL DEFAULT 0,
    pushed   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS activity_mac ON activity (mac, hour);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.commit()
    give_back_to_sudo_user(path)
    return conn


def give_back_to_sudo_user(path: Path) -> None:
    """Under sudo, chown the db (and WAL files) to the user who ran sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for p in (path.parent, path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            if p.exists():
                os.chown(p, int(uid), int(gid))
        except OSError:
            pass


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
