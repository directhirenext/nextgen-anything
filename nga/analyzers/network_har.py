"""HAR (HTTP Archive) traffic parser, schema extractor, and mock route builder for `nga`."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

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

MAX_HAR_FILE_BYTES = 16 * 1024 * 1024  # 16 MB safety cap

_SENSITIVE_FIELD_RE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
}


def _safe_int(value: Any, default: int = 200) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _redact_json_value(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets inside parsed JSON without breaking JSON syntax."""
    if depth >= 8:
        return value
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_redact_json_value(item, depth + 1) for item in value[:100]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:100]:
            key_str = str(k)
            if key_str.lower() in _SENSITIVE_FIELD_RE_KEYS and isinstance(v, str):
                out[key_str] = "[REDACTED]"
            else:
                out[key_str] = _redact_json_value(v, depth + 1)
        return out
    return value


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


def _extract_request_fields_and_schema(req: dict[str, Any]) -> tuple[list[str], Any]:
    """Extract form/JSON input field names and inferred schema from HAR request postData."""
    post_data = req.get("postData")
    if not isinstance(post_data, dict):
        return [], None

    fields: list[str] = []
    seen_fields: set[str] = set()
    req_schema: Any = None

    params = post_data.get("params")
    if isinstance(params, list):
        for p in params[:60]:
            if isinstance(p, dict):
                name = str(p.get("name", "")).strip()
                if name and name not in seen_fields:
                    seen_fields.add(name)
                    fields.append(name)

    raw_text = str(post_data.get("text", "") or "").strip()
    mime = str(post_data.get("mimeType", "") or "").lower()
    if raw_text:
        if "json" in mime or raw_text.startswith(("{", "[")):
            try:
                parsed = json.loads(raw_text)
                safe_parsed = _redact_json_value(parsed)
                req_schema = _infer_json_schema(safe_parsed)
                if isinstance(safe_parsed, dict):
                    for k in list(safe_parsed.keys())[:40]:
                        ks = str(k).strip()
                        if ks and ks not in seen_fields:
                            seen_fields.add(ks)
                            fields.append(ks)
            except json.JSONDecodeError:
                pass
        elif "x-www-form-urlencoded" in mime:
            for k in list(parse_qs(raw_text).keys())[:40]:
                ks = str(k).strip()
                if ks and ks not in seen_fields:
                    seen_fields.add(ks)
                    fields.append(ks)

    return fields, req_schema


def _decode_response_text(content_obj: dict[str, Any]) -> str:
    """Decode HAR response text including base64-encoded payloads safely."""
    raw_text = str(content_obj.get("text", "") or "")
    if not raw_text:
        return ""
    encoding = str(content_obj.get("encoding", "") or "").strip().lower()
    if encoding == "base64":
        try:
            decoded_bytes = base64.b64decode(raw_text.encode("ascii", errors="ignore"), validate=False)
            return decoded_bytes[:200_000].decode("utf-8", errors="replace")
        except (ValueError, OSError):
            return ""
    return raw_text


def _rehydrate_har_handles(analysis: dict[str, Any], handles: HandleRegistry, source_label: str) -> None:
    """Ensure cached HAR endpoints register handles into the active registry."""
    endpoints = analysis.get("endpoints")
    mock_routes = analysis.get("mock_routes")
    handle_by_sig: dict[str, int] = {}
    if isinstance(endpoints, list):
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            sig = f"{ep.get('method', 'GET')} {ep.get('path', '/')}"
            h = handles.register(
                f"endpoint::{sig}",
                metadata={
                    "method": ep.get("method", "GET"),
                    "path": ep.get("path", "/"),
                    "status": ep.get("status", 200),
                    "source": source_label,
                },
            )
            ep["handle"] = h
            handle_by_sig[sig] = h
    if isinstance(mock_routes, list):
        for mr in mock_routes:
            if isinstance(mr, dict):
                sig = f"{mr.get('method', 'GET')} {mr.get('path', '/')}"
                if sig in handle_by_sig:
                    mr["handle"] = handle_by_sig[sig]


def analyze_har_payload(
    har_data: dict[str, Any],
    source_label: str = "capture.har",
    handles: HandleRegistry | None = None,
    max_entries: int = 100,
) -> dict[str, Any]:
    """Extract sanitized endpoints, request fields, schemas, and mockable routes from HAR JSON."""
    reg = handles if handles is not None else HandleRegistry()
    cap = max(1, min(500, int(max_entries)))

    log_obj = har_data.get("log") if isinstance(har_data.get("log"), dict) else har_data
    raw_entries = log_obj.get("entries") if isinstance(log_obj, dict) and isinstance(log_obj.get("entries"), list) else []

    endpoints: list[dict[str, Any]] = []
    mock_routes: list[dict[str, Any]] = []
    index_by_sig: dict[str, int] = {}

    for entry in raw_entries[:cap]:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}

        method = str(req.get("method", "GET")).upper().strip() or "GET"
        raw_url = redact_secrets(str(req.get("url", "")).strip())
        parsed = urlparse(raw_url)
        path_only = parsed.path or "/"
        query_keys = sorted(set(parse_qs(parsed.query).keys()))[:30]
        status_code = _safe_int(resp.get("status", 200), default=200)

        req_headers = sanitize_headers(req.get("headers") if isinstance(req.get("headers"), (list, dict)) else {})
        resp_headers = sanitize_headers(resp.get("headers") if isinstance(resp.get("headers"), (list, dict)) else {})
        req_fields, req_schema = _extract_request_fields_and_schema(req)

        content_obj = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        mime_type = str(content_obj.get("mimeType", "")).strip()
        decoded_body = _decode_response_text(content_obj)

        inferred_schema: Any = None
        parsed_json_body: Any = None
        if "json" in mime_type.lower() or decoded_body.lstrip().startswith(("{", "[")):
            try:
                loaded_json = json.loads(decoded_body)
                parsed_json_body = _redact_json_value(loaded_json)
                inferred_schema = _infer_json_schema(parsed_json_body)
            except json.JSONDecodeError:
                parsed_json_body = None
                inferred_schema = None

        if parsed_json_body is not None:
            redacted_body = json.dumps(parsed_json_body, default=str)
        else:
            redacted_body = redact_secrets(decoded_body)

        endpoint_sig = f"{method} {path_only}"
        handle = reg.register(
            f"endpoint::{endpoint_sig}",
            metadata={"method": method, "path": path_only, "status": status_code, "source": source_label},
        )

        ep_record = {
            "handle": handle,
            "method": method,
            "path": path_only,
            "host": parsed.netloc,
            "status": status_code,
            "mime_type": mime_type,
            "query_params": query_keys,
            "fields": req_fields,
            "request_schema": req_schema,
            "request_headers_count": len(req_headers),
            "response_headers_count": len(resp_headers),
            "schema": inferred_schema,
        }

        bounded_resp = apply_output_budget(redacted_body, max_chars=2500)
        mock_record = {
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
            "parsed_json": parsed_json_body,
        }

        if endpoint_sig not in index_by_sig:
            index_by_sig[endpoint_sig] = len(endpoints)
            endpoints.append(ep_record)
            mock_routes.append(mock_record)
        else:
            existing_idx = index_by_sig[endpoint_sig]
            existing_ep = endpoints[existing_idx]
            existing_ok = 200 <= int(existing_ep["status"]) < 300
            new_ok = 200 <= status_code < 300
            # Upgrade non-2xx placeholder if a successful 2xx sample is seen later, or merge newly seen fields.
            if (not existing_ok and new_ok) or (existing_ep["schema"] is None and inferred_schema is not None):
                merged_fields = list(dict.fromkeys([*existing_ep.get("fields", []), *req_fields]))
                ep_record["fields"] = merged_fields
                endpoints[existing_idx] = ep_record
                mock_routes[existing_idx] = mock_record
            elif req_fields:
                existing_ep["fields"] = list(dict.fromkeys([*existing_ep.get("fields", []), *req_fields]))

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
    max_file_bytes: int = MAX_HAR_FILE_BYTES,
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

    read_cap = max(4096, int(max_file_bytes))
    try:
        file_size = resolved_or_err.stat().st_size
        if file_size > read_cap:
            return NgaError(
                error_code=ErrorCode.BUDGET_EXCEEDED.value,
                module="nga.analyzers.network_har",
                message=f"HAR file '{resolved_or_err.name}' ({file_size} bytes) exceeds limit ({read_cap} bytes).",
                recoverable=True,
                suggested_fix="Trim HAR capture or raise max_file_bytes explicitly.",
            )
        raw_text = resolved_or_err.read_bytes().decode("utf-8", errors="replace")
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

    cache_key_material = compute_sha256_text(raw_text)
    cached = cache.get("network_har", cache_key_material) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        analysis = cached
        _rehydrate_har_handles(analysis, reg, resolved_or_err.name)
        from_cache = True
    else:
        analysis = analyze_har_payload(parsed_har, source_label=resolved_or_err.name, handles=reg)
        if cache is not None:
            cache.set("network_har", cache_key_material, analysis)
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
            "mock_routes": analysis["mock_routes"],
            "mock_routes_count": len(analysis["mock_routes"]),
            "endpoints_json_slice": budgeted,
        },
        )
                                   
