"""
app/database.py — Database initialization for WRAITH.

Responsibilities:
    - Create the SQLite database file and directory if they don't exist.
    - Create the logs table with all required columns.
    - Enforce WAL mode for high-concurrency read/writes.
    - Provide get_db_connection() helper.
"""

import sqlite3
import os

def init_db(db_path: str) -> None:
    """
    Initialize the SQLite database.
    Create the data/ directory, logs table, and indexes if they
    do not already exist. Enforces Write-Ahead Logging (WAL).
    """
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        # CRITICAL: Enforce WAL mode to prevent database locking under HTTP flood
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        
        cursor = conn.cursor()
        
        # Aligned with logger.py INSERT statement
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs(
                id INTEGER PRIMARY KEY,
                timestamp TEXT DEFAULT (datetime('now')) NOT NULL,
                ip_address TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                headers TEXT,
                payload TEXT,
                user_agent TEXT,
                attack_type TEXT DEFAULT 'Normal',
                threat_score INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                layer TEXT DEFAULT NULL,
                report TEXT,
                is_simulation INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_score
            ON logs (threat_score)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_address
            ON logs (ip_address)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON logs (timestamp)
        """)

        conn.commit()
    finally:
        conn.close()
        
    print(f"[WRAITH] Database initialized and WAL mode engaged: {db_path}")

def get_db_connection(db_path: str) -> sqlite3.Connection:
    """
    Open and return a SQLite connection with row_factory set to sqlite3.Row.
    Caller is responsible for closing the connection after use.
    """
    conn = sqlite3.connect(db_path, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn