"""Typed contracts, integer handle registry, simulation statuses, and deterministic error payloads."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


class SimulationStatus(str, Enum):
    """Status values produced by sandbox simulation runs."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SIMULATION_PASSED = "SIMULATION_PASSED"
    SIMULATION_FAILED = "SIMULATION_FAILED"
    STALLED = "STALLED"
    BLOCKED = "BLOCKED"


class ObligationStatus(str, Enum):
    """Status values for items in the reconstruction obligation ledger."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    SKIPPED = "skipped"


class ErrorCode(str, Enum):
    """Canonical error codes returned by `nga` modules."""

    INVALID_INPUT = "NGA_INVALID_INPUT"
    NOT_FOUND = "NGA_NOT_FOUND"
    PATH_TRAVERSAL = "NGA_PATH_TRAVERSAL"
    BUDGET_EXCEEDED = "NGA_BUDGET_EXCEEDED"
    TIMEOUT = "NGA_TIMEOUT"
    SANDBOX_VIOLATION = "NGA_SANDBOX_VIOLATION"
    SIMULATION_FAILED = "NGA_SIMULATION_FAILED"
    STALL_DETECTED = "NGA_STALL_DETECTED"
    TOOL_UNAVAILABLE = "NGA_TOOL_UNAVAILABLE"
    PLUGIN_ERROR = "NGA_PLUGIN_ERROR"
    STORAGE_ERROR = "NGA_STORAGE_ERROR"
    INTERNAL_ERROR = "NGA_INTERNAL_ERROR"


@dataclass(frozen=True)
class NgaError:
    """Deterministic error object across CLI, Web UI, Web Embed, and MCP."""

    error_code: str
    module: str
    message: str
    recoverable: bool = True
    suggested_fix: str = "Verify inputs, permissions, or target path and retry."
    timestamp: str = field(default_factory=utc_now_iso)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize error as dictionary."""
        return {
            "ok": False,
            "error_code": self.error_code,
            "module": self.module,
            "message": self.message,
            "recoverable": self.recoverable,
            "suggested_fix": self.suggested_fix,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialize error as JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class ToolResponse:
    """Standardized success response with pagination and optional simulation state."""

    module: str
    data: dict[str, Any]
    summary: str = ""
    truncated: bool = False
    next_offset: int | None = None
    simulation_status: str | None = None
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert response to dictionary."""
        payload: dict[str, Any] = {
            "ok": True,
            "module": self.module,
            "summary": self.summary,
            "truncated": self.truncated,
            "next_offset": self.next_offset,
            "timestamp": self.timestamp,
            "data": self.data,
        }
        if self.simulation_status is not None:
            payload["simulation_status"] = self.simulation_status
        return payload

    def to_json(self, indent: int | None = None) -> str:
        """Serialize response to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class SimulationReport:
    """Report produced when executing/simulating code or tools inside the sandbox."""

    run_id: str
    target_label: str
    status: SimulationStatus
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    stdout_preview: str = ""
    stderr_preview: str = ""
    error_signature: str = ""
    duration_ms: int = 0
    created_at: str = field(default_factory=utc_now_iso)

    @property
    def passed(self) -> bool:
        """True only when simulation passed with zero failed checks."""
        return self.status == SimulationStatus.SIMULATION_PASSED and len(self.checks_failed) == 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize simulation report."""
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["passed"] = self.passed
        return payload


@dataclass
class LedgerObligation:
    """Tracked reconstruction item such as an endpoint, module, route, or behavior."""

    handle: int
    obligation_id: str
    category: str
    title: str
    status: ObligationStatus = ObligationStatus.PENDING
    notes: str = ""
    evidence_hash: str = ""
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize obligation item."""
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


class HandleRegistry:
    """Maps string keys to compact integer handles (#1, #2, ...) to keep outputs concise."""

    def __init__(self) -> None:
        self._key_to_handle: dict[str, int] = {}
        self._handle_to_key: dict[int, str] = {}
        self._handle_to_meta: dict[int, dict[str, Any]] = {}
        self._counter: int = 0

    def register(self, key: str, metadata: dict[str, Any] | None = None) -> int:
        """Register key if new and return its integer handle."""
        clean_key = str(key).strip()
        if not clean_key:
            raise ValueError("Handle key cannot be empty.")
        if clean_key in self._key_to_handle:
            handle = self._id_to_handle_lookup(clean_key)
            if metadata:
                self._handle_to_meta[handle].update(metadata)
            return handle

        self._counter += 1
        handle = self._counter
        self._key_to_handle[clean_key] = handle
        self._handle_to_key[handle] = clean_key
        self._handle_to_meta[handle] = dict(metadata) if metadata else {}
        return handle

    def _id_to_handle_lookup(self, clean_key: str) -> int:
        return self._key_to_handle[clean_key]

    def resolve_key(self, handle: int) -> str | None:
        """Resolve integer handle to original key."""
        return self._handle_to_key.get(int(handle))

    def resolve_handle(self, key: str) -> int | None:
        """Resolve key to integer handle."""
        return self._key_to_handle.get(str(key).strip())

    def get_meta(self, handle: int) -> dict[str, Any] | None:
        """Get metadata stored for a handle."""
        return self._handle_to_meta.get(int(handle))

    def list_all(self) -> list[dict[str, Any]]:
        """List all handle entries ordered by handle ID."""
        return [
            {
                "handle": h,
                "key": self._handle_to_key[h],
                "meta": self._handle_to_meta.get(h, {}),
            }
            for h in sorted(self._handle_to_key.keys())
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serialize registry state."""
        return {
            "counter": self._counter,
            "entries": self.list_all(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> HandleRegistry:
        """Deserialize registry state safely."""
        reg = cls()
        if not isinstance(payload, dict):
            return reg
        entries = payload.get("entries", [])
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                key = str(entry.get("key", "")).strip()
                meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
                if key:
                    reg.register(key, meta)
        counter = payload.get("counter")
        if isinstance(counter, int) and counter >= reg._counter:
            reg._counter = counter
        return reg
      
