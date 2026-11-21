"""Security guardrails: secret/PII redaction, path traversal guards, AST safety checks, and output token budgets."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
from typing import Any

from nga.core.contracts import ErrorCode, NgaError

DEFAULT_MAX_OUTPUT_CHARS = 12000
DEFAULT_MAX_ARCHIVE_ENTRIES = 2000
DEFAULT_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(bearer\s+)[a-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?)([^'\"\s,&;]+)"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:sk-|ghp_|gho_|glpat-|xox[baprs]-)[A-Za-z0-9_-]{10,}\b"),
)

_DANGEROUS_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "input",
    }
)

_DANGEROUS_ATTR_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "spawnl"),
        ("os", "spawnle"),
        ("os", "spawnlp"),
        ("os", "spawnlpe"),
        ("os", "spawnv"),
        ("os", "spawnve"),
        ("os", "spawnvp"),
        ("os", "spawnvpe"),
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
        ("shutil", "rmtree"),
    }
)


def redact_secrets(text: str, mask: str = "[REDACTED]") -> str:
    """Redact common API keys, bearer tokens, JWTs, and credential assignments from text."""
    if not text:
        return text
    result = text
    for idx, pattern in enumerate(_TOKEN_PATTERNS):
        if idx in (0, 1):
            result = pattern.sub(rf"\1{mask}", result)
        else:
            result = pattern.sub(mask, result)
    return result


def sanitize_headers(headers: dict[str, Any] | list[tuple[str, Any]] | None) -> dict[str, str]:
    """Normalize HTTP headers, deduplicate case-insensitively, and mask sensitive values."""
    normalized: dict[str, str] = {}
    if not headers:
        return normalized

    pairs: list[tuple[str, str]]
    if isinstance(headers, dict):
        pairs = [(str(k), str(v)) for k, v in headers.items()]
    else:
        pairs = [(str(k), str(v)) for k, v in headers]

    for raw_name, raw_val in pairs:
        name = raw_name.strip()
        if not name:
            continue
        if name.lower() in SENSITIVE_HEADER_NAMES:
            value = "[REDACTED]"
        else:
            value = redact_secrets(raw_val.strip())
        normalized[name] = value

    return normalized


def safe_resolve_path(base_dir: Path, target_rel_or_abs: str | Path) -> tuple[bool, Path | NgaError]:
    """Ensure target path stays strictly inside base_dir (prevents Zip-Slip and path traversal)."""
    try:
        root = base_dir.resolve()
        raw_path = Path(target_rel_or_abs)
        candidate = (root / raw_path).resolve() if not raw_path.is_absolute() else raw_path.resolve()
        if candidate == root or root in candidate.parents:
            return True, candidate
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message=f"Path escapes allowed root directory: {target_rel_or_abs}",
            recoverable=False,
            suggested_fix="Provide a path strictly inside the authorized workspace or sandbox directory.",
        )
    except Exception as exc:
        return False, NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.security",
            message=f"Invalid path value '{target_rel_or_abs}': {exc}",
            recoverable=True,
            suggested_fix="Check path syntax and characters.",
        )


def sanitize_archive_member_name(member_name: str) -> tuple[bool, str | NgaError]:
    """Validate archive entry names against traversal, drive prefixes, and trailing-dot collisions."""
    cleaned = member_name.replace("\\", "/").strip()
    if not cleaned or cleaned.startswith("/") or (len(cleaned) >= 2 and cleaned[1] == ":"):
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message=f"Unsafe archive member path: {member_name}",
            recoverable=False,
            suggested_fix="Remove leading slashes or drive letters from archive entries.",
        )

    parts = [p for p in cleaned.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message=f"Parent directory traversal ('..') detected in archive member: {member_name}",
            recoverable=False,
            suggested_fix="Reject or sanitize archive entries containing '..'.",
        )

    if not parts:
        return False, NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.security",
            message=f"Empty archive member path: {member_name}",
            recoverable=True,
            suggested_fix="Skip empty archive directory entries.",
        )

    safe_parts = [p.rstrip(".") if p.endswith(".") and p not in {".", ".."} else p for p in parts]
    safe_parts = [p if p else "_entry_" for p in safe_parts]
    return True, "/".join(safe_parts)


def check_python_ast_safety(source_code: str) -> dict[str, Any]:
    """Perform static AST analysis on Python code before sandbox simulation/execution."""
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return {
            "safe": False,
            "syntax_valid": False,
            "findings": [
                {
                    "line": exc.lineno or 1,
                    "severity": "error",
                    "issue": f"SyntaxError: {exc.msg}",
                }
            ],
        }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
                findings.append(
                    {
                        "line": getattr(node, "lineno", 0),
                        "severity": "high",
                        "issue": f"Potentially unsafe builtin call '{node.func.id}()'",
                    }
                )
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in _DANGEROUS_ATTR_CALLS:
                    findings.append(
                        {
                            "line": getattr(node, "lineno", 0),
                            "severity": "high",
                            "issue": f"Restricted system call '{pair[0]}.{pair[1]}()'",
                        }
                    )

    high_count = sum(1 for item in findings if item.get("severity") == "high")
    return {
        "safe": high_count == 0,
        "syntax_valid": True,
        "findings": findings,
    }


def apply_output_budget(
    text: str,
    max_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> dict[str, Any]:
    """Slice text with offset and enforce a strict character budget so LLM context windows stay bounded."""
    budget = max(256, int(max_chars))
    start = max(0, int(offset))
    total_len = len(text)

    if start >= total_len:
        return {
            "content": "",
            "total_chars": total_len,
            "offset": start,
            "returned_chars": 0,
            "truncated": False,
            "next_offset": None,
        }

    chunk = text[start : start + budget]
    next_off = start + len(chunk)
    is_truncated = next_off < total_len

    return {
        "content": chunk,
        "total_chars": total_len,
        "offset": start,
        "returned_chars": len(chunk),
        "truncated": is_truncated,
        "next_offset": next_off if is_truncated else None,
    }


def compute_sha256_text(text: str) -> str:
    """Compute SHA-256 hex digest for a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()
