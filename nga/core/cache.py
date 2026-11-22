"""Content-addressed SQLite cache for NextGen-Anything (`nga`) to speed up repeated inspections."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, utc_now_iso


def _normalize_namespace(namespace: str | None) -> str:
    cleaned = str(namespace or "default").strip()
    return cleaned or "default"


class NgaCache:
    """Thread-safe SQLite-backed SHA-256 content cache with TTL support and clean connection closing."""

    def __init__(
        self,
        db_path: Path | str,
        default_ttl_seconds: int = 86400,
        ttl_seconds: int | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        chosen_ttl = default_ttl_seconds if ttl_seconds is None else ttl_seconds
        self.default_ttl_seconds = max(1, int(chosen_ttl))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
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
                    CREATE TABLE IF NOT EXISTS nga_cache (
                        cache_key TEXT PRIMARY KEY,
                        namespace TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        updated_iso TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_nga_cache_ns ON nga_cache(namespace, expires_at);"
                )

    @staticmethod
    def make_key(namespace: str, raw_material: str | bytes) -> str:
        """Build a deterministic SHA-256 cache key for a given namespace and input."""
        clean_ns = _normalize_namespace(namespace)
        digest = hashlib.sha256()
        digest.update(clean_ns.encode("utf-8"))
        digest.update(b"::")
        if isinstance(raw_material, bytes):
            digest.update(raw_material)
        else:
            digest.update(str(raw_material).encode("utf-8", errors="replace"))
        return digest.hexdigest()

    def get(self, namespace: str, raw_material: str | bytes) -> dict[str, Any] | None:
        """Retrieve cached JSON payload if present and not expired."""
        clean_ns = _normalize_namespace(namespace)
        key = self.make_key(clean_ns, raw_material)
        now_ts = int(time.time())
        try:
            with self._lock, closing(self._connect()) as conn:
                row = conn.execute(
                    """
                    SELECT payload_json, expires_at FROM nga_cache
                    WHERE cache_key = ? AND namespace = ?
                    """,
                    (key, clean_ns),
                ).fetchone()
                if row is None:
                    return None
                if int(row["expires_at"]) <= now_ts:
                    with conn:
                        conn.execute("DELETE FROM nga_cache WHERE cache_key = ?", (key,))
                    return None
                parsed = json.loads(row["payload_json"])
                return parsed if isinstance(parsed, dict) else {"value": parsed}
        except (sqlite3.Error, json.JSONDecodeError, OSError):
            return None

    def set(
        self,
        namespace: str,
        raw_material: str | bytes,
        payload: dict[str, Any],
        ttl_seconds: int | None = None,
    ) -> dict[str, Any] | NgaError:
        """Store a JSON-serializable payload in the cache."""
        clean_ns = _normalize_namespace(namespace)
        key = self.make_key(clean_ns, raw_material)
        now_ts = int(time.time())
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_ts = now_ts + ttl
        updated_iso = utc_now_iso()

        try:
            serialized = json.dumps(payload, default=str)
            with self._lock, closing(self._connect()) as conn:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO nga_cache (cache_key, namespace, payload_json, created_at, expires_at, updated_iso)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(cache_key) DO UPDATE SET
                            namespace = excluded.namespace,
                            payload_json = excluded.payload_json,
                            created_at = excluded.created_at,
                            expires_at = excluded.expires_at,
                            updated_iso = excluded.updated_iso;
                        """,
                        (key, clean_ns, serialized, now_ts, expires_ts, updated_iso),
                    )
            return {"cache_key": key, "namespace": clean_ns, "expires_at": expires_ts}
        except (sqlite3.Error, TypeError, ValueError, OSError) as exc:
            return NgaError(
                error_code=ErrorCode.STORAGE_ERROR.value,
                module="nga.core.cache",
                message=f"Failed writing to cache: {exc}",
                recoverable=True,
                suggested_fix="Check disk permissions or SQLite database path.",
            )

    def purge_expired(self) -> int:
        """Delete expired cache entries and return count removed."""
        now_ts = int(time.time())
        try:
            with self._lock, closing(self._connect()) as conn:
                with conn:
                    cur = conn.execute("DELETE FROM nga_cache WHERE expires_at <= ?", (now_ts,))
                    return int(cur.rowcount or 0)
        except sqlite3.Error:
            return 0

    def clear_namespace(self, namespace: str | None = None) -> int:
        """Clear entries for a specific namespace or the entire cache."""
        try:
            with self._lock, closing(self._connect()) as conn:
                with conn:
                    if namespace is not None and str(namespace).strip():
                        clean_ns = _normalize_namespace(namespace)
                        cur = conn.execute("DELETE FROM nga_cache WHERE namespace = ?", (clean_ns,))
                    else:
                        cur = conn.execute("DELETE FROM nga_cache")
                    return int(cur.rowcount or 0)
        except sqlite3.Error:
            return 0

    def stats(self) -> dict[str, Any]:
        """Return cache summary statistics."""
        now_ts = int(time.time())
        total_entries = 0
        active_entries = 0
        try:
            with self._lock, closing(self._connect()) as conn:
                total_row = conn.execute("SELECT COUNT(*) AS cnt FROM nga_cache").fetchone()
                active_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM nga_cache WHERE expires_at > ?",
                    (now_ts,),
                ).fetchone()
                total_entries = int(total_row["cnt"]) if total_row else 0
                active_entries = int(active_row["cnt"]) if active_row else 0
        except sqlite3.Error:
            pass

        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "db_path": str(self.db_path),
            "db_size_bytes": db_size,
            "total_entries": total_entries,
            "active_entries": active_entries,
        }
        
