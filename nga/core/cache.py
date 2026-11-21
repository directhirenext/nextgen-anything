"""Content-addressed SQLite cache for NextGen-Anything (`nga`) to speed up repeated inspections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, utc_now_iso


class NgaCache:
    """SQLite-backed SHA-256 content cache with TTL support and safe connection lifecycle."""

    def __init__(self, db_path: Path, default_ttl_seconds: int = 86400) -> None:
        self.db_path = Path(db_path)
        self.default_ttl_seconds = max(1, int(default_ttl_seconds))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
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
            conn.commit()

    @staticmethod
    def make_key(namespace: str, raw_material: str | bytes) -> str:
        """Build a deterministic SHA-256 cache key for a given namespace and input."""
        digest = hashlib.sha256()
        digest.update(namespace.strip().encode("utf-8"))
        digest.update(b"::")
        if isinstance(raw_material, bytes):
            digest.update(raw_material)
        else:
            digest.update(str(raw_material).encode("utf-8", errors="replace"))
        return digest.hexdigest()

    def get(self, namespace: str, raw_material: str | bytes) -> dict[str, Any] | None:
        """Retrieve cached JSON payload if present and not expired."""
        key = self.make_key(namespace, raw_material)
        now_ts = int(time.time())
        try:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT payload_json, expires_at FROM nga_cache
                    WHERE cache_key = ? AND namespace = ?
                    """,
                    (key, namespace),
                ).fetchone()
                if row is None:
                    return None
                if int(row["expires_at"]) <= now_ts:
                    conn.execute("DELETE FROM nga_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                    return None
                parsed = json.loads(row["payload_json"])
                return parsed if isinstance(parsed, dict) else {"value": parsed}
        except (sqlite3.Error, json.JSONDecodeError):
            return None

    def set(
        self,
        namespace: str,
        raw_material: str | bytes,
        payload: dict[str, Any],
        ttl_seconds: int | None = None,
    ) -> dict[str, Any] | NgaError:
        """Store a JSON-serializable payload in the cache."""
        key = self.make_key(namespace, raw_material)
        now_ts = int(time.time())
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_ts = now_ts + ttl
        updated_iso = utc_now_iso()

        try:
            serialized = json.dumps(payload, default=str)
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO nga_cache (cache_key, namespace, payload_json, created_at, expires_at, updated_iso)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        payload_json = excluded.payload_json,
                        created_at = excluded.created_at,
                        expires_at = excluded.expires_at,
                        updated_iso = excluded.updated_iso;
                    """,
                    (key, namespace, serialized, now_ts, expires_ts, updated_iso),
                )
                conn.commit()
            return {"cache_key": key, "namespace": namespace, "expires_at": expires_ts}
        except Exception as exc:
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
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM nga_cache WHERE expires_at <= ?", (now_ts,))
            conn.commit()
            return int(cur.rowcount or 0)

    def clear_namespace(self, namespace: str | None = None) -> int:
        """Clear entries for a specific namespace or the entire cache."""
        with self._connect() as conn:
            if namespace:
                cur = conn.execute("DELETE FROM nga_cache WHERE namespace = ?", (namespace,))
            else:
                cur = conn.execute("DELETE FROM nga_cache")
            conn.commit()
            return int(cur.rowcount or 0)

    def stats(self) -> dict[str, Any]:
        """Return cache summary statistics."""
        now_ts = int(time.time())
        with self._connect() as conn:
            total_row = conn.execute("SELECT COUNT(*) AS cnt FROM nga_cache").fetchone()
            active_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM nga_cache WHERE expires_at > ?",
                (now_ts,),
            ).fetchone()
        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "db_path": str(self.db_path),
            "db_size_bytes": db_size,
            "total_entries": int(total_row["cnt"]) if total_row else 0,
            "active_entries": int(active_row["cnt"]) if active_row else 0,
      }
          
