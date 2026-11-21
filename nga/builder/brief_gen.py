"""Clean-room architectural blueprint and stack selector for NextGen-Anything (`nga`)."""

from __future__ import annotations

from typing import Any

from nga.core.contracts import ToolResponse, utc_now_iso
from nga.core.security import compute_sha256_text, redact_secrets


def select_recommended_stack(target_kind: str, prefer_lightweight: bool = True) -> dict[str, Any]:
    """Select a clean-room target stack suited for cross-OS and portable execution."""
    normalized = str(target_kind or "web").strip().lower()
    if normalized in {"web", "html", "js", "javascript", "frontend", "api"}:
        return {
            "stack_id": "web_vanilla_python_api",
            "frontend": "Semantic HTML5 + CSS3 + Modular Vanilla JS (zero bundler lock-in)",
            "backend": "Python 3.10+ HTTP/JSON Service" if prefer_lightweight else "Python FastAPI / Node Service",
            "storage": "SQLite + JSON schemas",
        }
    if normalized in {"archive", "apk", "zip", "asar", "mobile"}:
        return {
            "stack_id": "cross_platform_service_web",
            "frontend": "Responsive HTML5/CSS3/JS Web Client",
            "backend": "Python 3.10+ Modular Service + JSON Contracts",
            "storage": "SQLite + Merkle State Log",
        }
    if normalized in {"binary", "elf", "pe", "macho", "wasm", "native"}:
        return {
            "stack_id": "systems_rust_or_python",
            "frontend": "CLI + Local Web Inspector",
            "core": "Python 3.10+ with optional Rust crate (`nga-fast-core`)",
            "storage": "Content-addressed SQLite cache + JSON artifacts",
        }
    return {
        "stack_id": "universal_python_modular",
        "frontend": "HTML5/CSS3/Vanilla JS + CLI",
        "backend": "Python 3.10+ Stdlib-First Modules",
        "storage": "SQLite + JSON",
    }


def generate_architecture_brief(
    target_label: str,
    target_kind: str = "web",
    findings: dict[str, Any] | None = None,
    prefer_lightweight: bool = True,
) -> ToolResponse:
    """Generate a deterministic clean-room reconstruction brief from inspection findings."""
    clean_target = redact_secrets(str(target_label).strip() or "unspecified_target")
    stack = select_recommended_stack(target_kind=target_kind, prefer_lightweight=prefer_lightweight)
    summary_data = findings if isinstance(findings, dict) else {}

    routes_count = len(summary_data.get("routes", [])) if isinstance(summary_data.get("routes"), list) else 0
    endpoints_count = (
        len(summary_data.get("endpoints", [])) if isinstance(summary_data.get("endpoints"), list) else 0
    )
    entries_count = (
        int(summary_data.get("safe_entries_indexed", summary_data.get("file_count", 0)) or 0)
    )

    brief_doc = {
        "brief_version": "1.0",
        "created_at": utc_now_iso(),
        "target_label": clean_target,
        "target_kind": target_kind,
        "recommended_stack": stack,
        "observed_inventory": {
            "routes_detected": routes_count,
            "api_endpoints_detected": endpoints_count,
            "archive_entries_indexed": entries_count,
        },
        "clean_room_principles": [
            "Reconstruct behavior and interfaces from specifications without copying proprietary assets.",
            "Keep every generated module self-contained, typed, and verifiable in the sandbox.",
            "Track every route, endpoint, and feature in the Reconstruction Obligation Ledger.",
            "Validate every output through the pre-output simulation gate before final delivery.",
        ],
    }

    brief_hash = compute_sha256_text(str(brief_doc))

    return ToolResponse(
        module="nga.builder.brief_gen",
        summary=f"Generated clean-room brief ({stack['stack_id']}) for '{clean_target}' [sha256={brief_hash[:12]}].",
        data={
            "brief_sha256": brief_hash,
            "brief": brief_doc,
        },
  )
  
