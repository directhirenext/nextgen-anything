"""Workspace state, single-instance lock hygiene, journal logging, and cryptographic Merkle chain."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any

from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, utc_now_iso


class WorkspaceLock:
    """Cross-OS lockfile guard preventing concurrent state corruption across CLI, Web UI, and MCP."""

    def __init__(self, lock_path: Path, stale_seconds: int = 300) -> None:
        self.lock_path = Path(lock_path)
        self.stale_seconds = max(10, int(stale_seconds))
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._acquired = False

    def acquire(self, wait_timeout: float = 5.0) -> tuple[bool, NgaError | None]:
        """Acquire exclusive lockfile with stale-lock recovery."""
        deadline = time.monotonic() + max(0.1, float(wait_timeout))
        while time.monotonic() <= deadline:
            try:
                fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"pid": os.getpid(), "created_at": time.time()}, handle)
                self._acquired = True
                return True, None
            except FileExistsError:
                if self._is_stale():
                    self.lock_path.unlink(missing_ok=True)
                    continue
                time.sleep(0.05)
            except OSError as exc:
                return False, NgaError(
                    error_code=ErrorCode.STORAGE_ERROR.value,
                    module="nga.core.workspace",
                    message=f"Unable to create workspace lock: {exc}",
                    recoverable=True,
                    suggested_fix="Check filesystem write permissions in ~/.nga/.",
                )

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
            return (time.time() - stat.st_mtime) > self.stale_seconds
        except OSError:
            return True

    def release(self) -> None:
        """Release lockfile if owned by this instance."""
        if self._acquired:
            self.lock_path.unlink(missing_ok=True)
            self._acquired = False

    def __enter__(self) -> WorkspaceLock:
        ok, err = self.acquire()
        if not ok and err is not None:
            raise RuntimeError(err.message)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


class MerkleAuditChain:
    """Append-only SHA-256 tamper-evident ledger recording workspace state transitions and simulations."""

    def __init__(self, chain_path: Path) -> None:
        self.chain_path = Path(chain_path)
        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.chain_path.exists():
            self._save_blocks([])

    def _load_blocks(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(self.chain_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save_blocks(self, blocks: list[dict[str, Any]]) -> None:
        self.chain_path.write_text(json.dumps(blocks, indent=2, default=str), encoding="utf-8")

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
        """Append a cryptographically chained audit record."""
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
        blocks = self._load_blocks()
        expected_prev = "0" * 64
        for idx, block in enumerate(blocks):
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
        blocks = self._load_blocks()
        return blocks[-max(1, int(limit)) :]


class NgaWorkspace:
    """Manages a project workspace directory, handle registry, pins, journal, and Merkle chain."""

    def __init__(self, project_name: str = "default", base_dir: Path | None = None) -> None:
        safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in project_name.strip()) or "default"
        root = Path(base_dir) if base_dir else (Path.home() / ".nga" / "workspaces")
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
            self.state_path.write_text(json.dumps(initial, indent=2), encoding="utf-8")

    def load_state(self) -> dict[str, Any]:
        """Read current workspace state dictionary."""
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            self._ensure_state()
            return json.loads(self.state_path.read_text(encoding="utf-8"))

    def save_state(self, state: dict[str, Any]) -> None:
        """Persist workspace state dictionary atomically."""
        state["updated_at"] = utc_now_iso()
        tmp_path = self.state_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        tmp_path.replace(self.state_path)

    def get_handles(self) -> HandleRegistry:
        """Load the workspace integer HandleRegistry."""
        state = self.load_state()
        return HandleRegistry.from_dict(state.get("handles"))

    def register_handle(self, key: str, metadata: dict[str, Any] | None = None) -> int:
        """Register an entity key in the workspace handle registry and persist it."""
        with self.lock:
            state = self.load_state()
            reg = HandleRegistry.from_dict(state.get("handles"))
            handle = reg.register(key, metadata)
            state["handles"] = reg.to_dict()
            self.save_state(state)
            return handle

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
      
