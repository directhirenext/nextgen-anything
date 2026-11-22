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
    (re.compile(r"(?i)(/bot)\d{6,15}:[A-Za-z0-9_-]{20,}"), r"\1[REDACTED_TELEGRAM_TOKEN]"),
    (re.compile(r"\b\d{7,15}:AA[A-Za-z0-9_-]{20,}\b"), "[REDACTED_TELEGRAM_TOKEN]"),
    (
        re.compile(
            r'(?i)(["\']?(?:api[_-]?key|secret|token|password|passwd|access[_-]?token|refresh[_-]?token|private[_-]?key)["\']?\s*[:=]\s*["\']?)([^"\'\s,;}{]{6,})(["\']?)'
        ),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(
            r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z\-_]{25,}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
]

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-nga-token",
    "x-telegram-bot-api-secret-token",
    "x-csrf-token",
    "x-xsrf-token",
}

_BLOCKED_AST_MODULES = {
    "os",
    "sys",
    "subprocess",
    "shutil",
    "socket",
    "ssl",
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
    "pathlib",
    "io",
    "runpy",
    "code",
    "codeop",
    "webbrowser",
    "tempfile",
    "glob",
    "fnmatch",
    "asyncio",
    "concurrent",
    "fcntl",
    "mmap",
    "posix",
    "nt",
    "winreg",
    "msvcrt",
    "pkgutil",
    "zipimport",
    "pdb",
    "bdb",
    "faulthandler",
    "shelve",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "venv",
    "pip",
}

_BLOCKED_AST_SUBMODULES = {
    "urllib.request",
    "urllib.error",
    "http.client",
    "http.cookiejar",
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
    "memoryview",
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
    "__dict__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__reduce__",
    "__reduce_ex__",
    "__traceback__",
    "tb_frame",
    "tb_next",
    "f_builtins",
    "f_globals",
    "f_locals",
    "f_back",
    "f_code",
    "gi_frame",
    "gi_code",
    "cr_frame",
    "cr_code",
    "ag_frame",
    "ag_code",
}

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


def redact_secrets(text: str) -> str:
    """Mask bearer tokens, Telegram tokens, API keys, JWTs, AWS keys, passwords, and private keys."""
    if not text:
        return text
    sanitized = str(text)
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
    """Resolve `target_path` inside `base_dir` while blocking NUL bytes, symlink escapes, and traversal."""
    raw_str = str(target_path)
    if "\x00" in raw_str:
        return False, NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.core.security",
            message="Invalid filesystem path containing NUL byte.",
            recoverable=False,
            suggested_fix="Provide a clean relative path without control characters.",
        )

    try:
        base_resolved = Path(base_dir).resolve()
        raw_target = Path(raw_str)
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
    """Validate archive member entry name against Zip-Slip, drive letters, NUL bytes, and OS collisions."""
    raw = str(member_name or "")
    if "\x00" in raw or any(ord(ch) < 32 for ch in raw):
        return False, NgaError(
            error_code=ErrorCode.PATH_TRAVERSAL.value,
            module="nga.core.security",
            message="Unsafe archive entry containing control or NUL characters rejected.",
            recoverable=False,
            suggested_fix="Reject archives containing control characters in entry names.",
        )

    cleaned = raw.replace("\\", "/").strip()
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
        stem = normalized_part.split(".")[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            normalized_part = f"_{normalized_part}"
        safe_parts.append(normalized_part)

    return True, "/".join(safe_parts)


def _is_blocked_module_name(full_name: str) -> bool:
    clean = str(full_name or "").strip()
    if not clean:
        return False
    root_pkg = clean.split(".")[0]
    if root_pkg in _BLOCKED_AST_MODULES:
        return True
    for blocked_sub in _BLOCKED_AST_SUBMODULES:
        if clean == blocked_sub or clean.startswith(f"{blocked_sub}."):
            return True
    return False


def check_python_ast_safety(code: str) -> dict[str, Any]:
    """Inspect Python source AST for syntax errors, dangerous imports, calls, and frame/dunder escapes."""
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
                if _is_blocked_module_name(alias.name):
                    findings.append({"line": node.lineno, "issue": f"Blocked import: {alias.name}"})
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _is_blocked_module_name(mod):
                findings.append({"line": node.lineno, "issue": f"Blocked from-import: {mod}"})
            else:
                for alias in node.names:
                    candidate = f"{mod}.{alias.name}" if mod else alias.name
                    if _is_blocked_module_name(candidate):
                        findings.append({"line": node.lineno, "issue": f"Blocked from-import target: {candidate}"})
        elif isinstance(node, ast.Attribute):
            if node.attr in _BLOCKED_DUNDER_ATTRS:
                findings.append({"line": node.lineno, "issue": f"Blocked reflection attribute: {node.attr}"})
        elif isinstance(node, ast.Name):
            if node.id in _BLOCKED_DUNDER_ATTRS:
                findings.append({"line": node.lineno, "issue": f"Blocked reflection identifier: {node.id}"})
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in _BLOCKED_AST_CALLS:
                findings.append({"line": node.lineno, "issue": f"Blocked builtin/call: {func_name}"})
            elif func_name == "type" and len(node.args) == 3:
                findings.append({"line": node.lineno, "issue": "Blocked dynamic 3-argument type() class creation"})

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
    """Enforce deterministic output budget with exact character slicing and offset pagination."""
    safe_text = str(text or "")
    safe_offset = max(0, int(offset))
    safe_limit = max(1, int(max_chars))
    total_len = len(safe_text)
    sliced = safe_text[safe_offset : safe_offset + safe_limit]
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
