"""SQLite FTS5 / RAG memory vault for nga with secret redaction and provenance tracking."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, utc_now_iso
from nga.core.security import compute_sha256_text, redact_secrets

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def _build_fts_query(query: str) -> str:
    """Convert natural language query into a safe FTS5 prefix/OR query."""
    tokens = _TOKEN_RE.findall(query or "")
    if not tokens:
        return ""
    cleaned_tokens: list[str] = []
    seen: set[str] = set()
    for tok in tokens[:12]:
        low = tok.lower()
        if low not in seen:
            seen.add(low)
            cleaned_tokens.append(f'"{low}"*')
    return " OR ".join(cleaned_tokens)


class AaireMemoryVault:
    """Persistent RAG memory vault backed by SQLite with optional FTS5 full-text index."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        default_dir = Path.home() / ".nga" / "vault"
        self.db_path = Path(db_path) if db_path is not None else (default_dir / "memory_vault.sqlite")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fts_enabled = False
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_hash TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memories_ns ON memories(namespace);"
            )
            try:
                conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                        title,
                        body,
                        tags_json,
                        content='memories',
                        content_rowid='id'
                    );
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                        INSERT INTO memories_fts(rowid, title, body, tags_json)
                        VALUES (new.id, new.title, new.body, new.tags_json);
                    END;
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                        INSERT INTO memories_fts(memories_fts, rowid, title, body, tags_json)
                        VALUES ('delete', old.id, old.title, old.body, old.tags_json);
                    END;
                    """
                )
                self._fts_enabled = True
            except sqlite3.OperationalError:
                self._fts_enabled = False
            conn.commit()
  
