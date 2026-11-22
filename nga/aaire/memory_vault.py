"""SQLite FTS5 / RAG memory vault for nga with secret redaction, Unicode support, and provenance."""

from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, utc_now_iso
from nga.core.security import compute_sha256_text, redact_secrets

_TOKEN_RE = re.compile(r"[^\W_]{2,}", re.UNICODE)
MAX_MEMORY_BODY_CHARS = 64_000


def _normalize_namespace(namespace: str | None) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(namespace or "agent_general").strip()).strip("_")
    return cleaned or "agent_general"


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _build_fts_query(query: str) -> str:
    """Convert natural-language query (ASCII or Unicode) into a safe FTS5 prefix/OR query."""
    tokens = _TOKEN_RE.findall(str(query or ""))
    if not tokens:
        return ""
    cleaned_tokens: list[str] = []
    seen: set[str] = set()
    for tok in tokens[:12]:
        low = tok.lower().replace('"', "")
        if low and low not in seen:
            seen.add(low)
            cleaned_tokens.append(f'"{low}"*')
    return " OR ".join(cleaned_tokens)


class AaireMemoryVault:
    """Persistent RAG memory vault backed by SQLite with FTS5 full-text index and safe connection closing."""

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
        with self._lock, closing(self._connect()) as conn:
            with conn:
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
                conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_ns ON memories(namespace);")
                try:
                    conn.execute(
                        """
                        CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                            title,
                            body,
                            tags_json,
                            content='memories',
                            content_rowid='id',
                            tokenize='unicode61'
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
                    conn.execute(
                        """
                        CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                            INSERT INTO memories_fts(memories_fts, rowid, title, body, tags_json)
                            VALUES ('delete', old.id, old.title, old.body, old.tags_json);
                            INSERT INTO memories_fts(rowid, title, body, tags_json)
                            VALUES (new.id, new.title, new.body, new.tags_json);
                        END;
                        """
                    )
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO memories_fts(rowid, title, body, tags_json)
                        SELECT id, title, body, tags_json FROM memories
                        WHERE id NOT IN (SELECT rowid FROM memories_fts);
                        """
                    )
                    self._fts_enabled = True
                except sqlite3.OperationalError:
                    self._fts_enabled = False

    def store(
        self,
        title: str,
        body: str,
        namespace: str = "agent_general",
        tags: list[str] | None = None,
        source: str = "agent",
    ) -> dict[str, Any] | NgaError:
        """Redact secrets, store or deduplicate a memory record, and return metadata."""
        clean_title = redact_secrets(str(title or "")).strip()[:300]
        clean_body = redact_secrets(str(body or "")).strip()[:MAX_MEMORY_BODY_CHARS]
        if not clean_title and not clean_body:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.memory_vault",
                message="Memory entry must contain non-empty title or body.",
                recoverable=True,
                suggested_fix="Pass non-empty title or body text.",
            )

        safe_title = clean_title or "untitled_note"
        safe_ns = _normalize_namespace(namespace)
        safe_source = redact_secrets(str(source or "agent")).strip()[:80] or "agent"
        tag_list = [redact_secrets(str(t)).strip()[:60] for t in (tags or []) if str(t).strip()][:20]
        tags_encoded = json.dumps(tag_list)

        content_hash = compute_sha256_text(f"{safe_ns}\n{safe_title}\n{clean_body}")
        now_iso = utc_now_iso()

        try:
            with self._lock, closing(self._connect()) as conn:
                existing = conn.execute(
                    "SELECT id, namespace, title, tags_json, source, created_at FROM memories WHERE content_hash = ?",
                    (content_hash,),
                ).fetchone()
                if existing is not None:
                    return {
                        "id": int(existing["id"]),
                        "content_hash": content_hash,
                        "namespace": existing["namespace"],
                        "title": existing["title"],
                        "tags": json.loads(existing["tags_json"] or "[]"),
                        "source": existing["source"],
                        "created_at": existing["created_at"],
                        "deduplicated": True,
                    }

                with conn:
                    cur = conn.execute(
                        """
                        INSERT INTO memories(content_hash, namespace, title, body, tags_json, source, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (content_hash, safe_ns, safe_title, clean_body, tags_encoded, safe_source, now_iso),
                    )
                row_id = int(cur.lastrowid or 0)

            return {
                "id": row_id,
                "content_hash": content_hash,
                "namespace": safe_ns,
                "title": safe_title,
                "tags": tag_list,
                "source": safe_source,
                "created_at": now_iso,
                "deduplicated": False,
            }
        except (sqlite3.Error, OSError) as exc:
            return NgaError(
                error_code=ErrorCode.STORAGE_ERROR.value,
                module="nga.aaire.memory_vault",
                message=redact_secrets(f"Failed storing memory record: {exc}"),
                recoverable=True,
                suggested_fix="Check SQLite vault path and write permissions.",
            )

    def retrieve(
        self,
        query: str,
        namespace: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieve relevant memory chunks using FTS5 BM25 ranking or safe escaped SQL fallback."""
        try:
            safe_limit = max(1, min(50, int(limit)))
        except (TypeError, ValueError):
            safe_limit = 5

        clean_q = redact_secrets(str(query or "")).strip()
        if not clean_q:
            return []

        norm_ns = _normalize_namespace(namespace) if (namespace is not None and str(namespace).strip()) else None
        results: list[dict[str, Any]] = []

        try:
            with self._lock, closing(self._connect()) as conn:
                if self._fts_enabled:
                    fts_q = _build_fts_query(clean_q)
                    if fts_q:
                        try:
                            if norm_ns:
                                rows = conn.execute(
                                    """
                                    SELECT m.id, m.namespace, m.title, m.body, m.tags_json, m.source, m.created_at,
                                           bm25(memories_fts) AS rank_score
                                    FROM memories_fts
                                    JOIN memories m ON m.id = memories_fts.rowid
                                    WHERE memories_fts MATCH ? AND m.namespace = ?
                                    ORDER BY rank_score ASC
                                    LIMIT ?
                                    """,
                                    (fts_q, norm_ns, safe_limit),
                                ).fetchall()
                            else:
                                rows = conn.execute(
                                    """
                                    SELECT m.id, m.namespace, m.title, m.body, m.tags_json, m.source, m.created_at,
                                           bm25(memories_fts) AS rank_score
                                    FROM memories_fts
                                    JOIN memories m ON m.id = memories_fts.rowid
                                    WHERE memories_fts MATCH ?
                                    ORDER BY rank_score ASC
                                    LIMIT ?
                                    """,
                                    (fts_q, safe_limit),
                                ).fetchall()

                            for r in rows:
                                results.append(
                                    {
                                        "id": int(r["id"]),
                                        "namespace": r["namespace"],
                                        "title": r["title"],
                                        "body": r["body"],
                                        "tags": json.loads(r["tags_json"] or "[]"),
                                        "source": r["source"],
                                        "created_at": r["created_at"],
                                        "rank_score": float(r["rank_score"]),
                                    }
                                )
                            if results:
                                return results
                        except sqlite3.OperationalError:
                            pass

                terms = _TOKEN_RE.findall(clean_q)[:6] or [clean_q[:120]]
                clauses: list[str] = []
                params: list[Any] = []
                for term in terms:
                    esc = _escape_like(term[:120])
                    pat = f"%{esc}%"
                    clauses.append("(title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\' OR tags_json LIKE ? ESCAPE '\\')")
                    params.extend([pat, pat, pat])

                where_search = "(" + " OR ".join(clauses) + ")"
                if norm_ns:
                    sql = (
                        "SELECT id, namespace, title, body, tags_json, source, created_at "
                        f"FROM memories WHERE namespace = ? AND {where_search} ORDER BY id DESC LIMIT ?"
                    )
                    rows = conn.execute(sql, [norm_ns, *params, safe_limit]).fetchall()
                else:
                    sql = (
                        "SELECT id, namespace, title, body, tags_json, source, created_at "
                        f"FROM memories WHERE {where_search} ORDER BY id DESC LIMIT ?"
                    )
                    rows = conn.execute(sql, [*params, safe_limit]).fetchall()

                for r in rows:
                    results.append(
                        {
                            "id": int(r["id"]),
                            "namespace": r["namespace"],
                            "title": r["title"],
                            "body": r["body"],
                            "tags": json.loads(r["tags_json"] or "[]"),
                            "source": r["source"],
                            "created_at": r["created_at"],
                            "rank_score": 0.0,
                        }
                    )
        except sqlite3.Error:
            return []

        return results
            
