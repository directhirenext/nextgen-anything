"""Security, secret redaction, path traversal containment, AST guard, and output budgets."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
from typing import Any

from nga.core.contracts import ErrorCode, NgaError

DEFAULT_MAX_OUTPUT_CHARS = 12000
DEFAULT_MAX_ARCHIVE_ENTRIES = 2000
DEFAULT_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-~+/=]+"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/=]{12,}"), r"\1[REDACTED_TOKEN]"),
    (
        re.compile(r'(?i)(["\']?(?:api[_-]?key|secret|token|password|passwd|access[_-]?token|refresh[_-]?token|private[_-]?key)["\']?\s*[:=]\s*["\']?)([^"\'\s,;}{]{6,})(["\']?)'),
        r"\1[REDACTED]\3",
    ),
    (re.compile(r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{25,})\b"), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}

_BLOCKED_AST_MODULES = {
    "os",
    "sys",
    "subprocess",
    "shutil",
    "socket",
    "ctypes",
    "importlib",
    "pickle",
    "marshal",
    "pty",
    "resource",
    "signal",
    "multiprocessing",
    "threading",
    "builtins",
    "inspect",
    "gc",
}

_BLOCKED_AST_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "breakpoint",
    "getattr",
    "setattr",
    "delattr",
    "hasattr",
    "globals",
    "locals",
    "vars",
    "dir",
}

_BLOCKED_DUNDER_ATTRS = {
    "__class__",
    "__base__",
    "__bases__",
    "__subclasses__",
    "__mro__",
    "__globals__",
    "__builtins__",
    "__code__",
    "__closure__",
    "__import__",
    "__loader__",
    "__spec__",
}


def redact_secrets(text: str) -> str:
    """Mask bearer tokens, API keys, passwords, and private keys in arbitrary text."""
    if not text:
        return text
    sanitized = text
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_headers(headers: dict[str, Any] | list[dict[str, Any]] | None) -> dict[str, str]:
    """Deduplicate HTTP headers case-insensitively and redact sensitive auth/cookie values."""
    if not headers:
        return {}
    normalized: dict[str, str] = {}
    items: list[tuple[str, str]] = []

    if isinstance(headers, dict):
        items = [(str(k), str(v)) for k, v in headers.items()]
    elif isinstance(headers, list):
        for entry in headers:
            if isinstance(entry, dict) and "name" in entry:
                items.append((str(entry.get("name", "")), str(entry.get("value", ""))))

    for raw_key, raw_val in items:
        key = raw_key.strip()
        if not key:
            continue
        lower_key = key.lower()
        canonical_key = next((existing for existing in normalized if existing.lower() == lower_key), key)
        if lower_key in _SENSITIVE_HEADER_KEYS:
            normalized[canonical_key] = "[REDACTED_HEADER]"
        else:
            normalized[canonical_key] = redact_secrets(raw_val.strip())
    return normalized


def safe_resolve_path(base_dir: Path, target_path: str | Path) -> tuple[bool, Path | NgaError]:
    """Resolve `target_path` inside `base_dir` while blocking symlink escapes and traversal."""
    try:
        base_resolved = base_dir.resolve()
        raw_target = Path(target_path)
        candidate = raw_target.resolve() if raw_target.is_absolute() else (base_resolved / raw_target).resolve()
        candidate.relative_to(base_resolved)
        return True, candidate
    except ValueError:
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message=f"Path traversal blocked: '{target_path}' escapes base directory '{base_dir}'.",
            recoverable=False,
            suggested_fix="Provide a relative path strictly inside the active workspace or allowed root.",
        )
    except OSError as exc:
        return False, NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.security",
            message=f"Invalid filesystem path '{target_path}': {exc}",
            recoverable=True,
            suggested_fix="Verify the path string contains valid OS characters.",
        )


def sanitize_archive_member_name(member_name: str) -> tuple[bool, str | NgaError]:
    """Validate archive member entry name against Zip-Slip traversal and trailing-dot collisions."""
    cleaned = member_name.replace("\\", "/").strip()
    if not cleaned or cleaned.startswith("/") or cleaned.startswith("~"):
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message=f"Unsafe archive entry path rejected: '{member_name}'",
            recoverable=False,
            suggested_fix="Strip leading slashes or home prefixes from archive entries.",
        )

    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if not parts:
        return False, NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.security",
            message=f"Empty normalized archive entry: '{member_name}'",
            recoverable=True,
            suggested_fix="Ignore directory-only or empty archive entries.",
        )

    safe_parts: list[str] = []
    for part in parts:
        if part == ".." or ":" in part:
            return False, NgaError(
                error_code=ErrorCode.PATH_TRAVERSAL.value,
                module="nga.core.security",
                message=f"Archive entry contains traversal or drive segment: '{member_name}'",
                recoverable=False,
                suggested_fix="Reject archives containing '..' or drive specifiers.",
            )
        normalized_part = part.rstrip(". ") or "_"
        safe_parts.append(normalized_part)

    return True, "/".join(safe_parts)


def check_python_ast_safety(code: str) -> dict[str, Any]:
    """Inspect Python source AST for syntax errors, dangerous imports, calls, and dunder reflection."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {
            "safe": False,
            "syntax_valid": False,
            "findings": [f"SyntaxError at line {exc.lineno}: {exc.msg}"],
        }

    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".")[0]
                if root_pkg in _BLOCKED_AST_MODULES:
                    findings.append({"line": node.lineno, "issue": f"Blocked import: {alias.name}"})
        elif isinstance(node, ast.ImportFrom):
            root_pkg = (node.module or "").split(".")[0]
            if root_pkg in _BLOCKED_AST_MODULES:
                findings.append({"line": node.lineno, "issue": f"Blocked from-import: {node.module}"})
        elif isinstance(node, ast.Attribute):
            if node.attr in _BLOCKED_DUNDER_ATTRS:
                findings.append({"line": node.lineno, "issue": f"Blocked dunder reflection attribute: {node.attr}"})
        elif isinstance(node, ast.Name):
            if node.id in _BLOCKED_DUNDER_ATTRS:
                findings.append({"line": node.lineno, "issue": f"Blocked dunder identifier: {node.id}"})
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in _BLOCKED_AST_CALLS:
                findings.append({"line": node.lineno, "issue": f"Blocked builtin/call: {func_name}"})

    return {
        "safe": len(findings) == 0,
        "syntax_valid": True,
        "findings": findings,
    }


def apply_output_budget(
    text: str,
    max_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> dict[str, Any]:
    """Enforce deterministic output budget with offset pagination metadata."""
    safe_offset = max(0, int(offset))
    safe_limit = max(256, int(max_chars))
    total_len = len(text)
    sliced = text[safe_offset : safe_offset + safe_limit]
    end_pos = safe_offset + len(sliced)
    truncated = end_pos < total_len
    return {
        "content": sliced,
        "total_chars": total_len,
        "offset": safe_offset,
        "returned_chars": len(sliced),
        "truncated": truncated,
        "next_offset": end_pos if truncated else None,
    }


def compute_sha256_bytes(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_sha256_text(text: str) -> str:
    """Return lowercase SHA-256 hex digest for UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

