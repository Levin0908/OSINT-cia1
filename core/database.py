"""SQLite persistence layer for investigations.

Stores every completed investigation so analysts can browse history,
reproduce findings, and share evidence. The schema is intentionally
flat and denormalized for portability.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
from core.models import InvestigationResult


class Database:
    """Thread-safe SQLite wrapper."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or config.DB_PATH
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # low-level helpers
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    is_url INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    summary TEXT,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    malicious INTEGER NOT NULL DEFAULT 0,
                    confidence INTEGER NOT NULL DEFAULT 0,
                    tags TEXT,
                    collected_at TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_investigation ON iocs(investigation_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_invest_target ON investigations(target);
                """
            )

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------
    def save(self, result: InvestigationResult) -> int:
        """Persist an investigation and return its assigned id."""
        if result.id is None:
            result.id = int(datetime.utcnow().timestamp() * 1000)
        payload = json.dumps(result.model_dump(mode="json"), default=str)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO investigations
                   (target, is_url, timestamp, risk_score, risk_level, verdict, summary, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.target,
                    int(result.is_url),
                    result.timestamp.isoformat(),
                    result.risk_score,
                    result.risk_level,
                    result.verdict,
                    result.summary,
                    payload,
                ),
            )
            investigation_id = cur.lastrowid
            for ioc in result.iocs:
                conn.execute(
                    """INSERT INTO iocs
                       (investigation_id, type, value, source, malicious, confidence, tags, collected_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        investigation_id,
                        ioc.type,
                        ioc.value,
                        ioc.source,
                        int(ioc.malicious),
                        ioc.confidence,
                        ",".join(ioc.tags),
                        ioc.collected_at.isoformat(),
                    ),
                )
            conn.commit()
        return investigation_id

    # ------------------------------------------------------------------
    # read
    # ------------------------------------------------------------------
    def list_investigations(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """SELECT id, target, is_url, timestamp, risk_score, risk_level, verdict, summary
                   FROM investigations
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_investigation(self, investigation_id: int) -> Optional[InvestigationResult]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
            if not row:
                return None
            data = json.loads(row["payload"])
            data["id"] = investigation_id
            return InvestigationResult.model_validate(data)

    def search_iocs(self, value: str) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """SELECT i.investigation_id, i.type, i.value, i.source, i.malicious,
                          i.confidence, i.tags, i.collected_at,
                          v.target, v.risk_score, v.risk_level
                   FROM iocs i
                   JOIN investigations v ON v.id = i.investigation_id
                   WHERE i.value LIKE ?
                   ORDER BY i.investigation_id DESC
                   LIMIT 50""",
                (f"%{value}%",),
            ).fetchall()
            return [dict(r) for r in rows]

    def statistics(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM investigations").fetchone()["c"]
            level_rows = conn.execute(
                "SELECT risk_level, COUNT(*) AS c FROM investigations GROUP BY risk_level"
            ).fetchall()
            verdict_rows = conn.execute(
                "SELECT verdict, COUNT(*) AS c FROM investigations GROUP BY verdict"
            ).fetchall()
            top_domains = conn.execute(
                """SELECT value AS domain, COUNT(*) AS hits
                   FROM iocs WHERE type = 'ip'
                   GROUP BY value ORDER BY hits DESC LIMIT 10"""
            ).fetchall()
            return {
                "total_investigations": total,
                "by_risk_level": {r["risk_level"]: r["c"] for r in level_rows},
                "by_verdict": {r["verdict"]: r["c"] for r in verdict_rows},
                "top_ips": [dict(r) for r in top_domains],
            }
