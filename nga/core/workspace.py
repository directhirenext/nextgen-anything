"""Workspace state, single-instance lock hygiene, journal logging, and cryptographic Merkle chain."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any
import uuid

from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, utc_now_iso


def _atomic_write_json(target_path: Path, payload: Any) -> None:
    """Write JSON atomically using a unique temporary sibling file."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{target_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    tmp_path = target_path.parent / tmp_name
    try:
        tmp_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp_path.replace(target_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def _is_pid_alive(pid: int) -> bool:
    """Check whether a host process ID is still running (POSIX + Windows safe)."""
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "posix":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
    # On Windows, fall back conservatively to mtime-based stale detection.
    return True


class WorkspaceLock:
    """Cross-OS thread- and process-safe re-entrant lockfile guard with dead-PID stale recovery."""

    def __init__(self, lock_path: Path, stale_seconds: int = 300) -> None:
        self.lock_path = Path(lock_path)
        self.stale_seconds = max(10, int(stale_seconds))
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._owner_token = ""

    def acquire(self, wait_timeout: float = 5.0) -> tuple[bool, NgaError | None]:
        """Acquire exclusive thread + filesystem lockfile with dead-PID stale recovery."""
        if not self._thread_lock.acquire(timeout=max(0.1, float(wait_timeout))):
            return False, NgaError(
                error_code=ErrorCode.STORAGE_ERROR.value,
                module="nga.core.workspace",
                message=f"Workspace thread lock busy: {self.lock_path}",
                recoverable=True,
                suggested_fix="Wait for active CLI/Web/MCP operation to finish.",
            )

        if self._depth > 0:
            self._depth += 1
            return True, None

        token = f"{os.getpid()}:{uuid.uuid4().hex[:10]}"
        deadline = time.monotonic() + max(0.1, float(wait_timeout))
        while time.monotonic() <= deadline:
            try:
                fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"pid": os.getpid(), "token": token, "created_at": time.time()}, handle)
                self._owner_token = token
                self._depth = 1
                return True, None
            except FileExistsError:
                if self._is_stale():
                    self._try_clear_stale_lock()
                    continue
                time.sleep(0.03)
            except OSError as exc:
                self._thread_lock.release()
                return False, NgaError(
                    error_code=ErrorCode.STORAGE_ERROR.value,
                    module="nga.core.workspace",
                    message=f"Unable to create workspace lock: {exc}",
                    recoverable=True,
                    suggested_fix="Check filesystem write permissions in workspace directory.",
                )

        self._thread_lock.release()
        return False, NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.core.workspace",
            message=f"Workspace lock busy: {self.lock_path}",
            recoverable=True,
            suggested_fix="Wait for active CLI/Web/MCP operation to finish or remove stale lock.",
        )

    def _is_stale(self) -> bool:
        try:
            stat = self.lock_path.stat()
            if (time.time() - stat.st_mtime) > self.stale_seconds:
                return True
            raw = self.lock_path.read_text(encoding="utf-8", errors="replace").strip()
            if not raw:
                return (time.time() - stat.st_mtime) > 1.0
            meta = json.loads(raw)
            if isinstance(meta, dict) and isinstance(meta.get("pid"), int):
                pid = int(meta["pid"])
                if pid != os.getpid() and not _is_pid_alive(pid):
                    return True
            return False
        except FileNotFoundError:
            return False
        except (OSError, json.JSONDecodeError, ValueError):
            try:
                return (time.time() - self.lock_path.stat().st_mtime) > 2.0
            except OSError:
                return False

    def _try_clear_stale_lock(self) -> None:
        """Remove stale lockfile using an atomic rename guard to minimize unlink races."""
        stale_tmp = self.lock_path.parent / f".stale.{self.lock_path.name}.{uuid.uuid4().hex[:8]}"
        try:
            self.lock_path.rename(stale_tmp)
            stale_tmp.unlink(missing_ok=True)
        except OSError:
            self.lock_path.unlink(missing_ok=True)

    def release(self) -> None:
        """Release lockfile if owned by this instance."""
        if self._depth <= 0:
            return
        self._depth -= 1
        try:
            if self._depth == 0:
                try:
                    raw = self.lock_path.read_text(encoding="utf-8", errors="replace")
                    meta = json.loads(raw) if raw.strip() else {}
                    if not isinstance(meta, dict) or meta.get("token") == self._owner_token:
                        self.lock_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._owner_token = ""
        finally:
            self._thread_lock.release()

    def __enter__(self) -> WorkspaceLock:
        ok, err = self.acquire()
        if not ok and err is not None:
            raise RuntimeError(err.message)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


class MerkleAuditChain:
    """Locked, atomic append-only SHA-256 tamper-evident ledger for workspace events."""

    def __init__(self, chain_path: Path, lock: WorkspaceLock | None = None) -> None:
        self.chain_path = Path(chain_path)
        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = lock if lock is not None else WorkspaceLock(self.chain_path.with_suffix(".lock"))
        with self._lock:
            if not self.chain_path.exists():
                self._save_blocks([])

    def _load_blocks(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(self.chain_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save_blocks(self, blocks: list[dict[str, Any]]) -> None:
        _atomic_write_json(self.chain_path, blocks)

    @staticmethod
    def _hash_block(index: int, timestamp: str, event_type: str, payload: dict[str, Any], prev_hash: str) -> str:
        canonical = json.dumps(
            {
                "index": index,
                "timestamp": timestamp,
                "event_type": event_type,
                "payload": payload,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append a cryptographically chained audit record atomically under lock."""
        with self._lock:
            blocks = self._load_blocks()
            prev_hash = blocks[-1]["hash"] if blocks else "0" * 64
            index = len(blocks)
            timestamp = utc_now_iso()
            block_hash = self._hash_block(index, timestamp, event_type, payload, prev_hash)
            block = {
                "index": index,
                "timestamp": timestamp,
                "event_type": event_type,
                "payload": payload,
                "prev_hash": prev_hash,
                "hash": block_hash,
            }
            blocks.append(block)
            self._save_blocks(blocks)
            return block

    def verify_integrity(self) -> dict[str, Any]:
        """Recompute all hashes to verify the Merkle audit log has not been altered."""
        with self._lock:
            blocks = self._load_blocks()
        expected_prev = "0" * 64
        for idx, block in enumerate(blocks):
            if not isinstance(block, dict):
                return {"valid": False, "checked_blocks": idx, "corrupted_index": idx}
            if block.get("index") != idx or block.get("prev_hash") != expected_prev:
                return {"valid": False, "checked_blocks": idx, "corrupted_index": idx}
            recomputed = self._hash_block(
                idx,
                str(block.get("timestamp", "")),
                str(block.get("event_type", "")),
                block.get("payload") if isinstance(block.get("payload"), dict) else {},
                expected_prev,
            )
            if block.get("hash") != recomputed:
                return {"valid": False, "checked_blocks": idx, "corrupted_index": idx}
            expected_prev = recomputed
        return {
            "valid": True,
            "checked_blocks": len(blocks),
            "head_hash": expected_prev if blocks else None,
        }

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent audit blocks."""
        with self._lock:
            blocks = self._load_blocks()
        return blocks[-max(1, int(limit)) :]


class WorkspaceHandleRegistry(HandleRegistry):
    """HandleRegistry bound to a NgaWorkspace so new registrations persist to state.json."""

    def __init__(self, workspace: NgaWorkspace) -> None:
        super().__init__()
        self._workspace = workspace
        self._sync_from_disk()

    def _sync_from_disk(self) -> None:
        state = self._workspace.load_state()
        loaded = HandleRegistry.from_dict(state.get("handles"))
        self._key_to_handle = dict(loaded._key_to_handle)
        self._handle_to_key = dict(loaded._handle_to_key)
        self._handle_to_meta = {k: dict(v) for k, v in loaded._handle_to_meta.items()}
        self._counter = loaded._counter

    def register(self, key: str, metadata: dict[str, Any] | None = None) -> int:
        with self._workspace.lock:
            self._sync_from_disk()
            handle = super().register(key, metadata)
            state = self._workspace.load_state()
            state["handles"] = self.to_dict()
            self._workspace.save_state(state)
            return handle

    def register_with_handle(
        self,
        handle: int,
        key: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        with self._workspace.lock:
            self._sync_from_disk()
            assigned = super().register_with_handle(handle, key, metadata)
            state = self._workspace.load_state()
            state["handles"] = self.to_dict()
            self._workspace.save_state(state)
            return assigned


class NgaWorkspace:
    """Manages a project workspace directory, handle registry, pins, journal, and Merkle chain."""

    def __init__(self, project_name: str = "default", base_dir: Path | str | None = None) -> None:
        safe_name = (
            "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(project_name or "").strip())
            or "default"
        )
        if base_dir is not None and str(base_dir).strip():
            root = Path(base_dir)
        else:
            root = Path.home() / ".nga" / "workspaces"
        self.project_name = safe_name
        self.root = root / safe_name
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir = self.root / "artifacts"
        self.generated_dir = self.root / "generated"
        self.sandboxes_dir = self.root / "sandboxes"
        for sub in (self.artifacts_dir, self.generated_dir, self.sandboxes_dir):
            sub.mkdir(parents=True, exist_ok=True)

        self.state_path = self.root / "state.json"
        self.lock = WorkspaceLock(self.root / ".workspace.lock")
        self.merkle = MerkleAuditChain(self.root / "merkle_chain.json")
        self._ensure_state()

    def _ensure_state(self) -> None:
        with self.lock:
            if not self.state_path.exists():
                initial = {
                    "project_name": self.project_name,
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                    "target": None,
                    "pins": [],
                    "handles": HandleRegistry().to_dict(),
                    "journal": [],
                }
                _atomic_write_json(self.state_path, initial)

    def load_state(self) -> dict[str, Any]:
        """Read current workspace state dictionary safely."""
        with self.lock:
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                self._ensure_state()
                try:
                    data = json.loads(self.state_path.read_text(encoding="utf-8"))
                    return data if isinstance(data, dict) else {}
                except (OSError, json.JSONDecodeError):
                    return {}

    def save_state(self, state: dict[str, Any]) -> None:
        """Persist workspace state dictionary atomically under lock."""
        with self.lock:
            state["updated_at"] = utc_now_iso()
            _atomic_write_json(self.state_path, state)

    def get_handles(self) -> HandleRegistry:
        """Return a workspace-synced HandleRegistry that persists registrations to state.json."""
        return WorkspaceHandleRegistry(self)

    def register_handle(self, key: str, metadata: dict[str, Any] | None = None) -> int:
        """Register an entity key in the workspace handle registry and persist it."""
        return self.get_handles().register(key, metadata)

    def set_target(self, target: str, target_type: str = "auto") -> dict[str, Any]:
        """Set active target for this workspace and record an audit block."""
        with self.lock:
            state = self.load_state()
            state["target"] = {
                "value": target,
                "type": target_type,
                "set_at": utc_now_iso(),
            }
            self.save_state(state)
            block = self.merkle.append("SET_TARGET", {"target": target, "type": target_type})
            return {"target": state["target"], "merkle_index": block["index"]}

    def add_pin(self, label: str, handle: int | None = None, note: str = "") -> dict[str, Any]:
        """Pin an important finding, route, or handle in the workspace."""
        with self.lock:
            state = self.load_state()
            pins = state.setdefault("pins", [])
            pin_entry = {
                "label": label,
                "handle": handle,
                "note": note,
                "pinned_at": utc_now_iso(),
            }
            pins.append(pin_entry)
            self.save_state(state)
            self.merkle.append("ADD_PIN", pin_entry)
            return pin_entry

    def log_journal(self, stage: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        """Append a structured progress entry to the workspace journal."""
        with self.lock:
            state = self.load_state()
            journal = state.setdefault("journal", [])
            entry = {
                "timestamp": utc_now_iso(),
                "stage": stage,
                "message": message,
                "details": details or {},
            }
            journal.append(entry)
            if len(journal) > 500:
                state["journal"] = journal[-500:]
            self.save_state(state)
            return entry
        
