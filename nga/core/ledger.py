"""Reconstruction Obligation Ledger for tracking discovered targets, coverage, and readiness."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
import uuid

from nga.core.contracts import (
    ErrorCode,
    HandleRegistry,
    LedgerObligation,
    NgaError,
    ObligationStatus,
    utc_now_iso,
)
from nga.core.security import compute_sha256_text
from nga.core.workspace import WorkspaceLock


def _parse_status(status: ObligationStatus | str) -> ObligationStatus | NgaError:
    if isinstance(status, ObligationStatus):
        return status
    try:
        return ObligationStatus(str(status).strip().lower())
    except ValueError:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.ledger",
            message=f"Invalid obligation status: {status}",
            recoverable=True,
            suggested_fix="Use one of: pending, in_progress, verified, skipped.",
        )


class ObligationLedger:
    """Thread- and process-safe ledger tracking obligations and coverage metrics."""

    def __init__(self, ledger_path: Path | str, handles: HandleRegistry | None = None) -> None:
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = WorkspaceLock(self.ledger_path.with_suffix(".lock"))
        self.handles = handles if handles is not None else HandleRegistry()
        with self._lock:
            if not self.ledger_path.exists():
                self._save_raw({"updated_at": utc_now_iso(), "items": []})
            else:
                self._hydrate_existing_handles()

    def _hydrate_existing_handles(self) -> None:
        """Restore persisted obligation handles into the registry to prevent ID collisions."""
        store = self._load_raw()
        for entry in store.get("items", []):
            if not isinstance(entry, dict):
                continue
            oid = str(entry.get("obligation_id", "")).strip()
            raw_h = entry.get("handle")
            if not oid:
                continue
            meta = {
                "category": str(entry.get("category", "general")),
                "title": str(entry.get("title", oid)),
            }
            if isinstance(raw_h, int) and raw_h > 0:
                self.handles.register_with_handle(raw_h, f"obligation::{oid}", meta)
            else:
                self.handles.register(f"obligation::{oid}", meta)

    def _load_raw(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("items"), list):
                return raw
        except (OSError, json.JSONDecodeError):
            pass
        fresh = {"updated_at": utc_now_iso(), "items": []}
        self._save_raw(fresh)
        return fresh

    def _save_raw(self, payload: dict[str, Any]) -> None:
        payload["updated_at"] = utc_now_iso()
        tmp_name = f".{self.ledger_path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        tmp_path = self.ledger_path.parent / tmp_name
        try:
            tmp_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            tmp_path.replace(self.ledger_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    def add_obligation(
        self,
        obligation_id: str,
        category: str,
        title: str,
        status: ObligationStatus | str = ObligationStatus.PENDING,
        notes: str = "",
        evidence_text: str = "",
    ) -> LedgerObligation | NgaError:
        """Add a new obligation or update an existing one by obligation_id."""
        clean_id = str(obligation_id or "").strip()
        clean_cat = str(category or "").strip() or "general"
        clean_title = str(title or "").strip()
        if not clean_id or not clean_title:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.core.ledger",
                message="obligation_id and title are required to register an obligation.",
                recoverable=True,
                suggested_fix="Provide non-empty obligation_id and title strings.",
            )

        parsed_status = _parse_status(status)
        if isinstance(parsed_status, NgaError):
            return parsed_status

        evidence_hash = compute_sha256_text(evidence_text) if evidence_text else ""

        with self._lock:
            store = self._load_raw()
            items: list[dict[str, Any]] = store["items"]
            now_iso = utc_now_iso()

            for entry in items:
                if str(entry.get("obligation_id", "")).strip() == clean_id:
                    existing_h = entry.get("handle")
                    if isinstance(existing_h, int) and existing_h > 0:
                        handle = self.handles.register_with_handle(
                            existing_h,
                            f"obligation::{clean_id}",
                            metadata={"category": clean_cat, "title": clean_title},
                        )
                    else:
                        handle = self.handles.register(
                            f"obligation::{clean_id}",
                            metadata={"category": clean_cat, "title": clean_title},
                        )
                    entry["handle"] = handle
                    entry["category"] = clean_cat
                    entry["title"] = clean_title
                    entry["status"] = parsed_status.value
                    if notes:
                        entry["notes"] = notes
                    if evidence_hash:
                        entry["evidence_hash"] = evidence_hash
                    entry["updated_at"] = now_iso
                    self._save_raw(store)
                    return LedgerObligation(
                        handle=handle,
                        obligation_id=clean_id,
                        category=clean_cat,
                        title=clean_title,
                        status=parsed_status,
                        notes=str(entry.get("notes", "")),
                        evidence_hash=str(entry.get("evidence_hash", "")),
                        updated_at=now_iso,
                    )

            handle = self.handles.register(
                f"obligation::{clean_id}",
                metadata={"category": clean_cat, "title": clean_title},
            )
            new_item = {
                "handle": handle,
                "obligation_id": clean_id,
                "category": clean_cat,
                "title": clean_title,
                "status": parsed_status.value,
                "notes": notes,
                "evidence_hash": evidence_hash,
                "updated_at": now_iso,
            }
            items.append(new_item)
            self._save_raw(store)
            return LedgerObligation(
                handle=handle,
                obligation_id=clean_id,
                category=clean_cat,
                title=clean_title,
                status=parsed_status,
                notes=notes,
                evidence_hash=evidence_hash,
                updated_at=now_iso,
            )

    def update_status(
        self,
        handle_or_id: int | str,
        status: ObligationStatus | str,
        notes: str | None = None,
    ) -> LedgerObligation | NgaError:
        """Update status (and optional notes) of an obligation using integer handle or obligation_id."""
        parsed_status = _parse_status(status)
        if isinstance(parsed_status, NgaError):
            return parsed_status

        target_handle: int | None = None
        target_id: str | None = None
        if isinstance(handle_or_id, int):
            target_handle = handle_or_id
            resolved = self.handles.resolve_key(handle_or_id)
            if resolved and resolved.startswith("obligation::"):
                target_id = resolved.removeprefix("obligation::")
        else:
            raw_str = str(handle_or_id or "").strip()
            if raw_str.isdigit():
                target_handle = int(raw_str)
                resolved = self.handles.resolve_key(target_handle)
                if resolved and resolved.startswith("obligation::"):
                    target_id = resolved.removeprefix("obligation::")
            else:
                target_id = raw_str

        with self._lock:
            store = self._load_raw()
            now_iso = utc_now_iso()
            for entry in store["items"]:
                matches_handle = target_handle is not None and int(entry.get("handle", -1)) == target_handle
                matches_id = target_id is not None and str(entry.get("obligation_id", "")) == target_id
                if matches_handle or matches_id:
                    entry["status"] = parsed_status.value
                    if notes is not None:
                        entry["notes"] = notes
                    entry["updated_at"] = now_iso
                    self._save_raw(store)
                    return LedgerObligation(
                        handle=int(entry.get("handle", target_handle or 0)),
                        obligation_id=str(entry.get("obligation_id", "")),
                        category=str(entry.get("category", "general")),
                        title=str(entry.get("title", "")),
                        status=parsed_status,
                        notes=str(entry.get("notes", "")),
                        evidence_hash=str(entry.get("evidence_hash", "")),
                        updated_at=now_iso,
                    )

        return NgaError(
            error_code=ErrorCode.NOT_FOUND.value,
            module="nga.core.ledger",
            message=f"Obligation not found for identifier: {handle_or_id}",
            recoverable=True,
            suggested_fix="List obligations first to inspect valid integer handles or obligation IDs.",
        )

    def list_obligations(
        self,
        status_filter: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return paginated obligations list plus coverage summary."""
        with self._lock:
            store = self._load_raw()
        all_items = store["items"]
        if status_filter:
            wanted = status_filter.strip().lower()
            filtered = [i for i in all_items if str(i.get("status", "")).lower() == wanted]
        else:
            filtered = all_items

        start = max(0, int(offset))
        page_size = max(1, min(200, int(limit)))
        sliced = filtered[start : start + page_size]
        next_off = (start + len(sliced)) if (start + len(sliced)) < len(filtered) else None

        return {
            "items": sliced,
            "total_filtered": len(filtered),
            "offset": start,
            "limit": page_size,
            "next_offset": next_off,
            "coverage": self.coverage_summary(),
        }

    def coverage_summary(self) -> dict[str, Any]:
        """Compute counts, percentage verified, and reconstruction readiness score."""
        with self._lock:
            items = self._load_raw()["items"]
        total = len(items)
        counts = {
            ObligationStatus.PENDING.value: 0,
            ObligationStatus.IN_PROGRESS.value: 0,
            ObligationStatus.VERIFIED.value: 0,
            ObligationStatus.SKIPPED.value: 0,
        }
        for item in items:
            st = str(item.get("status", ObligationStatus.PENDING.value)).lower()
            if st in counts:
                counts[st] += 1

        active_total = total - counts[ObligationStatus.SKIPPED.value]
        verified = counts[ObligationStatus.VERIFIED.value]
        in_progress = counts[ObligationStatus.IN_PROGRESS.value]

        if total == 0:
            verified_pct = 0.0
            weighted_score = 0.0
            ready_to_finalize = False
        elif active_total == 0:
            verified_pct = 100.0
            weighted_score = 100.0
            ready_to_finalize = True
        else:
            verified_pct = round((verified / active_total) * 100.0, 2)
            weighted_score = round(((verified + 0.5 * in_progress) / active_total) * 100.0, 2)
            ready_to_finalize = verified == active_total

        return {
            "total": total,
            "counts": counts,
            "verified_percent": verified_pct,
            "weighted_readiness_percent": weighted_score,
            "ready_to_finalize": ready_to_finalize,
                    }
    
