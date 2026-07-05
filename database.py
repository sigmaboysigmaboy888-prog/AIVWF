"""
SQLite database manager for scan history.
"""
import sqlite3
import json
from typing import List, Dict, Optional
from datetime import datetime

DB_NAME = 'scans.db'

class Database:
    def __init__(self, db_path: str = DB_NAME):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    summary_json TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    payload TEXT,
                    evidence TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ai_response TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)

    def insert_scan(self, url: str, result: Dict) -> int:
        """Insert a scan record and return its ID."""
        timestamp = datetime.now().isoformat()
        summary = result.get('summary', '')
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO scans (url, timestamp, summary_json) VALUES (?, ?, ?)",
                (url, timestamp, json.dumps(result))
            )
            return cur.lastrowid

    def insert_vulnerability(self, scan_id: int, vuln_type: str, payload: str, evidence: str):
        with self.conn:
            self.conn.execute(
                "INSERT INTO vulnerabilities (scan_id, type, payload, evidence) VALUES (?, ?, ?, ?)",
                (scan_id, vuln_type, payload, evidence)
            )

    def insert_analysis(self, scan_id: int, ai_response: str):
        with self.conn:
            self.conn.execute(
                "INSERT INTO analysis (scan_id, ai_response) VALUES (?, ?)",
                (scan_id, ai_response)
            )

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_vulnerabilities_for_scan(self, scan_id: int) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM vulnerabilities WHERE scan_id=?", (scan_id,))
        return [dict(row) for row in cur.fetchall()]

    def get_all_scans(self, limit=100) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def delete_old_scans(self, keep=100):
        with self.conn:
            self.conn.execute("""
                DELETE FROM scans WHERE id NOT IN (
                    SELECT id FROM scans ORDER BY timestamp DESC LIMIT ?
                )
            """, (keep,))
