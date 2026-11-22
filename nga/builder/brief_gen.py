"""Clean-room architectural blueprint and stack selector for NextGen-Anything (`nga`)."""

from __future__ import annotations

import json
from typing import Any

from nga.core.contracts import ToolResponse, utc_now_iso
from nga.core.security import compute_sha256_text, redact_secrets


def select_recommended_stack(target_kind: str, prefer_lightweight: bool = True) -> dict[str, Any]:
    """Select a clean-room target stack suited for cross-OS and portable execution."""
    normalized = str(target_kind or "web").strip().lower()
    if normalized in {"web", "html", "js", "javascript", "frontend", "api", "har"}:
        return {
            "stack_id": "web_vanilla_python_api",
            "frontend": "Semantic HTML5 + CSS3 + Modular Vanilla JS (zero bundler lock-in)",
            "backend": "Python 3.10+ HTTP/JSON Service" if prefer_lightweight else "Python FastAPI / Node Service",
            "storage": "SQLite + JSON schemas",
        }
    if normalized in {"archive", "apk", "zip", "asar", "mobile", "android"}:
        return {
            "stack_id": "cross_platform_service_web_and_android_src",
            "frontend": "Responsive HTML5/CSS3/JS Web & PWA Client",
            "backend": "Python 3.10+ Modular Service + JSON Contracts",
            "mobile_source": "Clean-room Android Gradle + Kotlin/WebView source scaffold (buildable via Android SDK/CI)",
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


def _unwrap_findings(findings: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(findings, dict):
        return {}
    merged = dict(findings)
    for nested_key in ("analysis", "package", "metadata", "data"):
        nested = merged.get(nested_key)
        if isinstance(nested, dict):
            for k, v in nested.items():
                merged.setdefault(k, v)
    return merged


def generate_architecture_brief(
    target_label: str,
    target_kind: str = "web",
    findings: dict[str, Any] | None = None,
    prefer_lightweight: bool = True,
    custom_requirements: str = "",
) -> ToolResponse:
    """Generate a deterministic clean-room reconstruction brief from inspection findings."""
    clean_target = redact_secrets(str(target_label or "").strip() or "unspecified_target")
    clean_kind = str(target_kind or "web").strip().lower() or "web"
    clean_custom = redact_secrets(str(custom_requirements or "").strip())
    stack = select_recommended_stack(target_kind=clean_kind, prefer_lightweight=prefer_lightweight)
    flat = _unwrap_findings(findings)

    routes_list = flat.get("routes") if isinstance(flat.get("routes"), list) else []
    if not routes_list and isinstance(flat.get("embedded_routes"), list):
        routes_list = flat["embedded_routes"]

    endpoints_list = flat.get("endpoints") if isinstance(flat.get("endpoints"), list) else []
    forms_list = flat.get("forms") if isinstance(flat.get("forms"), list) else []
    entries_count = int(flat.get("safe_entries_indexed", flat.get("file_count", 0)) or 0)

    apk_meta = flat.get("apk_metadata") if isinstance(flat.get("apk_metadata"), dict) else {}
    pkg_name = str(apk_meta.get("package_name", "") or "")
    perms_count = len(apk_meta.get("permissions", [])) if isinstance(apk_meta.get("permissions"), list) else 0
    dex_cls_count = len(apk_meta.get("dex_classes", [])) if isinstance(apk_meta.get("dex_classes"), list) else 0

    deterministic_body = {
        "brief_version": "1.1",
        "target_label": clean_target,
        "target_kind": clean_kind,
        "custom_requirements": clean_custom,
        "recommended_stack": stack,
        "observed_inventory": {
            "routes_detected": len(routes_list),
            "api_endpoints_detected": len(endpoints_list),
            "forms_detected": len(forms_list),
            "archive_entries_indexed": entries_count,
            "apk_package_name": pkg_name,
            "apk_permissions_count": perms_count,
            "dex_classes_count": dex_cls_count,
        },
        "clean_room_principles": [
            "Reconstruct behavior and interfaces from specifications without copying proprietary assets.",
            "Keep every generated module self-contained, typed, and verifiable in the sandbox.",
            "Track every route, endpoint, and feature in the Reconstruction Obligation Ledger.",
            "Validate every output through the pre-output simulation gate before final delivery.",
        ],
    }

    brief_hash = compute_sha256_text(json.dumps(deterministic_body, sort_keys=True, default=str))
    brief_doc = {
        "brief_sha256": brief_hash,
        "created_at": utc_now_iso(),
        **deterministic_body,
    }

    return ToolResponse(
        module="nga.builder.brief_gen",
        summary=f"Generated clean-room brief ({stack['stack_id']}) for '{clean_target}' [sha256={brief_hash[:12]}].",
        data={
            "brief_sha256": brief_hash,
            "brief": brief_doc,
        },
                )
    
