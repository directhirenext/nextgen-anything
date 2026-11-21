"""HAR (HTTP Archive) traffic parser, schema extractor, and mock route builder for `nga`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    compute_sha256_text,
    redact_secrets,
    safe_resolve_path,
    sanitize_headers,
)


def _infer_json_schema(value: Any, depth: int = 0) -> Any:
    """Infer a compact structural schema from a JSON value with bounded recursion depth."""
    if depth >= 4:
        return {"type": type(value).__name__, "truncated_depth": True}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        redacted = redact_secrets(value)
        return {"type": "string", "sample_length": len(redacted)}
    if isinstance(value, list):
        sample_item = _infer_json_schema(value[0], depth + 1) if value else {"type": "unknown"}
        return {"type": "array", "length": len(value), "items": sample_item}
    if isinstance(value, dict):
        props: dict[str, Any] = {}
        for k in list(value.keys())[:40]:
            props[str(k)] = _infer_json_schema(value[k], depth + 1)
        return {"type": "object", "properties": props}
    return {"type": "unknown"}


def analyze_har_payload(
    har_data: dict[str, Any],
    source_label: str = "capture.har",
    handles: HandleRegistry | None = None,
    max_entries: int = 100,
) -> dict[str, Any]:
    """Extract sanitized endpoints, schemas, and mockable routes from parsed HAR JSON."""
    reg = handles if handles is not None else HandleRegistry()
    cap = max(1, min(500, int(max_entries)))

    log_obj = har_data.get("log") if isinstance(har_data.get("log"), dict) else har_data
    raw_entries = log_obj.get("entries") if isinstance(log_obj, dict) and isinstance(log_obj.get("entries"), list) else []

    endpoints: list[dict[str, Any]] = []
    mock_routes: list[dict[str, Any]] = []
    seen_endpoint_keys: set[str] = set()

    for entry in raw_entries[:cap]:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}

        method = str(req.get("method", "GET")).upper().strip() or "GET"
        raw_url = redact_secrets(str(req.get("url", "")).strip())
        parsed = urlparse(raw_url)
        path_only = parsed.path or "/"
        status_code = int(resp.get("status", 200) or 200)

        req_headers = sanitize_headers(req.get("headers") if isinstance(req.get("headers"), list) else {})
        resp_headers = sanitize_headers(resp.get("headers") if isinstance(resp.get("headers"), list) else {})

        content_obj = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        mime_type = str(content_obj.get("mimeType", "")).strip()
        raw_body = str(content_obj.get("text", "") or "")
        redacted_body = redact_secrets(raw_body)

        inferred_schema: Any = None
        parsed_json_body: Any = None
        if "json" in mime_type.lower() or redacted_body.lstrip().startswith(("{", "[")):
            try:
                parsed_json_body = json.loads(redacted_body)
                inferred_schema = _infer_json_schema(parsed_json_body)
            except json.JSONDecodeError:
                inferred_schema = None

        endpoint_sig = f"{method} {path_only}"
        handle = reg.register(
            f"endpoint::{endpoint_sig}",
            metadata={"method": method, "path": path_only, "status": status_code, "source": source_label},
        )

        if endpoint_sig not in seen_endpoint_keys:
            seen_endpoint_keys.add(endpoint_sig)
            endpoints.append(
                {
                    "handle": handle,
                    "method": method,
                    "path": path_only,
                    "host": parsed.netloc,
                    "status": status_code,
                    "mime_type": mime_type,
                    "request_headers_count": len(req_headers),
                    "response_headers_count": len(resp_headers),
                    "schema": inferred_schema,
                }
            )

            # Build safe mock entry with bounded preview body
            bounded_resp = apply_output_budget(redacted_body, max_chars=2500)
            mock_routes.append(
                {
                    "handle": handle,
                    "method": method,
                    "path": path_only,
                    "status": status_code,
                    "content_type": mime_type or "application/json",
                    "headers": {
                        k: v
                        for k, v in resp_headers.items()
                        if k.lower() in {"content-type", "cache-control", "x-content-type-options"}
                    },
                    "body_preview": bounded_resp["content"],
                    "parsed_json": parsed_json_body if parsed_json_body is not None else None,
                }
            )

    canonical_str = json.dumps(endpoints, sort_keys=True, default=str)
    return {
        "source": source_label,
        "har_sha256": compute_sha256_text(canonical_str),
        "total_entries_seen": len(raw_entries),
        "unique_endpoints": len(endpoints),
        "endpoints": endpoints,
        "mock_routes": mock_routes,
    }


def inspect_local_har(
    har_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> ToolResponse | NgaError:
    """Safely load, redact, cache, and analyze a local HAR capture file."""
    root = Path(base_root) if base_root is not None else Path.cwd()
    ok_path, resolved_or_err = safe_resolve_path(root, har_path)
    if not ok_path or not isinstance(resolved_or_err, Path):
        return resolved_or_err if isinstance(resolved_or_err, NgaError) else NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.network_har",
            message="Invalid HAR file path.",
        )

    if not resolved_or_err.exists() or not resolved_or_err.is_file():
        return NgaError(
            error_code=ErrorCode.NOT_FOUND.value,
            module="nga.analyzers.network_har",
            message=f"HAR file not found: {resolved_or_err}",
            recoverable=True,
            suggested_fix="Provide a valid path to a .har JSON file.",
        )

    try:
        raw_text = resolved_or_err.read_text(encoding="utf-8", errors="replace")
        parsed_har = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.network_har",
            message=f"Failed parsing HAR file '{resolved_or_err.name}': {exc}",
            recoverable=True,
            suggested_fix="Ensure the file is valid UTF-8 HAR JSON.",
        )

    if not isinstance(parsed_har, dict):
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.network_har",
            message="HAR root JSON must be an object.",
            recoverable=True,
            suggested_fix="Export a standard HTTP Archive (.har) JSON file.",
        )

    redacted_raw = redact_secrets(raw_text)
    cached = cache.get("network_har", redacted_raw) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        analysis = cached
        from_cache = True
    else:
        analysis = analyze_har_payload(parsed_har, source_label=resolved_or_err.name, handles=reg)
        if cache is not None:
            cache.set("network_har", redacted_raw, analysis)
        from_cache = False

    serialized_endpoints = json.dumps(analysis.get("endpoints", []), indent=2, default=str)
    budgeted = apply_output_budget(serialized_endpoints, max_chars=max_output_chars, offset=offset)

    return ToolResponse(
        module="nga.analyzers.network_har",
        summary=(
            f"HAR '{resolved_or_err.name}': {analysis['unique_endpoints']} unique endpoints "
            f"from {analysis['total_entries_seen']} entries (cache_hit={from_cache})."
        ),
        truncated=bool(budgeted["truncated"]),
        next_offset=budgeted["next_offset"],
        data={
            "file": str(resolved_or_err),
            "cache_hit": from_cache,
            "har_sha256": analysis["har_sha256"],
            "unique_endpoints": analysis["unique_endpoints"],
            "endpoints": analysis["endpoints"],
            "mock_routes_count": len(analysis["mock_routes"]),
            "endpoints_json_slice": budgeted,
        },
      )
  
