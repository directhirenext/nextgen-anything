"""Binary metadata, format signature, ASCII/UTF-16LE string scanner, and optional disassembler bridge for `nga`."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any

from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    compute_sha256_bytes,
    redact_secrets,
    safe_resolve_path,
)

_PRINTABLE_ASCII_RE = re.compile(rb"[ -~]{4,512}")
_PRINTABLE_UTF16LE_RE = re.compile(rb"(?:[ -~]\x00){4,256}")
_BIN_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,220}")
_BIN_ROUTE_RE = re.compile(
    r"(/(?:api|v\d+|auth|login|users|items|orders|tasks|jobs|health|status|graphql|admin)[A-Za-z0-9_./:-]{0,120})",
    re.IGNORECASE,
)

_SAFE_DISASM_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PREFIX",
    "LD_LIBRARY_PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
)


def _build_disasm_env() -> dict[str, str]:
    env: dict[str, str] = {"LANG": os.environ.get("LANG", "C.UTF-8")}
    for key in _SAFE_DISASM_ENV_KEYS:
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


def detect_binary_format(header: bytes, binary_path: Path | None = None) -> dict[str, Any]:
    """Identify ELF, PE/MZ, Mach-O, Java .class, WASM, or unknown binary magic signatures."""
    if len(header) >= 4 and header[:4] == b"\x7fELF":
        ei_class = header[4] if len(header) > 4 else 0
        ei_data = header[5] if len(header) > 5 else 0
        e_machine = 0
        if len(header) >= 20:
            fmt = "<H" if ei_data == 1 else (">H" if ei_data == 2 else "<H")
            e_machine = struct.unpack(fmt, header[18:20])[0]
        arch_map = {
            0x03: "x86",
            0x28: "arm32",
            0x3E: "x86_64",
            0xB7: "aarch64",
            0xF3: "riscv",
            0x08: "mips",
        }
        return {
            "format": "elf",
            "bits": 64 if ei_class == 2 else (32 if ei_class == 1 else 0),
            "endianness": "little" if ei_data == 1 else ("big" if ei_data == 2 else "unknown"),
            "arch": arch_map.get(e_machine, f"machine_0x{e_machine:x}"),
        }

    if len(header) >= 2 and header[:2] == b"MZ":
        pe_arch = "pe_unknown"
        if len(header) >= 64:
            pe_offset = struct.unpack("<I", header[60:64])[0]
            pe_chunk = b""
            if pe_offset + 6 <= len(header):
                pe_chunk = header[pe_offset : pe_offset + 6]
            elif binary_path is not None and pe_offset < 16 * 1024 * 1024:
                try:
                    with binary_path.open("rb") as fh:
                        fh.seek(pe_offset)
                        pe_chunk = fh.read(6)
                except OSError:
                    pe_chunk = b""
            if len(pe_chunk) >= 6 and pe_chunk[:4] == b"PE\x00\x00":
                machine_code = struct.unpack("<H", pe_chunk[4:6])[0]
                pe_arch = {
                    0x014C: "x86",
                    0x8664: "x86_64",
                    0xAA64: "aarch64",
                    0x01C4: "arm32",
                }.get(machine_code, f"pe_0x{machine_code:x}")
        return {
            "format": "pe",
            "bits": 64 if pe_arch in {"x86_64", "aarch64"} else 32,
            "endianness": "little",
            "arch": pe_arch,
        }

    if len(header) >= 8 and header[:4] == b"\xca\xfe\xba\xbe":
        nfat_or_ver = struct.unpack(">I", header[4:8])[0]
        java_major = struct.unpack(">H", header[6:8])[0]
        if nfat_or_ver > 30 and 44 <= java_major <= 80:
            return {
                "format": "java_class",
                "bits": 0,
                "endianness": "big",
                "arch": f"jvm_major_{java_major}",
            }
        return {
            "format": "macho_fat",
            "bits": 0,
            "endianness": "big",
            "arch": "apple_universal",
        }

    macho_magics = {
        b"\xfe\xed\xfa\xce": ("macho", 32, "big"),
        b"\xce\xfa\xed\xfe": ("macho", 32, "little"),
        b"\xfe\xed\xfa\xcf": ("macho", 64, "big"),
        b"\xcf\xfa\xed\xfe": ("macho", 64, "little"),
        b"\xbe\xba\xfe\xca": ("macho_fat", 0, "little"),
    }
    if len(header) >= 4 and header[:4] in macho_magics:
        fmt_name, bits, endian = macho_magics[header[:4]]
        return {
            "format": fmt_name,
            "bits": bits,
            "endianness": endian,
            "arch": "apple_universal_or_native",
        }

    if len(header) >= 8 and header[:4] == b"\x00asm":
        wasm_version = struct.unpack("<I", header[4:8])[0]
        return {
            "format": "wasm",
            "bits": 32,
            "endianness": "little",
            "arch": f"wasm_v{wasm_version}",
        }

    return {
        "format": "unknown_or_raw",
        "bits": 0,
        "endianness": "unknown",
        "arch": "unknown",
    }


def extract_redacted_strings(data: bytes, max_strings: int = 120) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings from binary data with redaction and deduplication."""
    cap = max(10, min(500, int(max_strings)))
    found: list[str] = []
    seen: set[str] = set()

    for match in _PRINTABLE_ASCII_RE.finditer(data):
        raw_str = match.group(0).decode("ascii", errors="ignore").strip()
        if len(raw_str) < 4:
            continue
        cleaned = redact_secrets(raw_str)
        if cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)
            if len(found) >= cap:
                return found

    for match in _PRINTABLE_UTF16LE_RE.finditer(data):
        raw_str = match.group(0).decode("utf-16le", errors="ignore").strip()
        if len(raw_str) < 4:
            continue
        cleaned = redact_secrets(raw_str)
        if cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)
            if len(found) >= cap:
                return found

    return found


def _extract_routes_and_urls(strings_list: list[str]) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    routes: list[str] = []
    seen_u: set[str] = set()
    seen_r: set[str] = set()
    for s in strings_list:
        for u in _BIN_URL_RE.findall(s):
            if u not in seen_u and len(urls) < 60:
                seen_u.add(u)
                urls.append(u)
        for r in _BIN_ROUTE_RE.findall(s):
            if r not in seen_r and len(routes) < 60:
                seen_r.add(r)
                routes.append(r)
    return routes, urls


def _probe_optional_disassembler(binary_path: Path, timeout_seconds: float = 15.0) -> dict[str, Any]:
    """Optionally query `rizin` with failover to `radare2` using flag-injection-safe arguments."""
    errors: list[dict[str, str]] = []
    safe_env = _build_disasm_env()
    for tool_name in ("rizin", "radare2"):
        exe = shutil.which(tool_name)
        if not exe:
            continue
        try:
            proc = subprocess.run(
                [exe, "-q", "-c", "i;afl~?", "--", str(binary_path.resolve())],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                env=safe_env,
                timeout=max(1.0, float(timeout_seconds)),
                check=False,
            )
            if proc.returncode == 0:
                bounded = apply_output_budget(redact_secrets((proc.stdout or "").strip()), max_chars=2500)
                return {
                    "used": True,
                    "tool": tool_name,
                    "returncode": proc.returncode,
                    "info_preview": bounded["content"],
                }
            errors.append(
                {
                    "tool": tool_name,
                    "error": redact_secrets((proc.stderr or f"exit {proc.returncode}").strip())[:300],
                }
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            errors.append({"tool": tool_name, "error": redact_secrets(str(exc))[:300]})

    out: dict[str, Any] = {"used": False, "tool": None}
    if errors:
        out["attempts"] = errors
    return out


def _rehydrate_binary_handles(meta_result: dict[str, Any], handles: HandleRegistry) -> None:
    items = meta_result.get("strings")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("value"):
                item["handle"] = handles.register(f"str::{item['value']}", {"kind": "binary_string"})


def inspect_binary_target(
    binary_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
    timeout_seconds: float = 15.0,
) -> ToolResponse | NgaError:
    """Inspect a local binary file safely with caching, format detection, ASCII/UTF-16LE strings, and budgets."""
    root = Path(base_root) if base_root is not None else Path.cwd()
    ok_path, resolved_or_err = safe_resolve_path(root, binary_path)
    if not ok_path or not isinstance(resolved_or_err, Path):
        return resolved_or_err if isinstance(resolved_or_err, NgaError) else NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.binary_meta",
            message="Invalid binary path.",
        )

    if not resolved_or_err.exists() or not resolved_or_err.is_file():
        return NgaError(
            error_code=ErrorCode.NOT_FOUND.value,
            module="nga.analyzers.binary_meta",
            message=f"Binary file not found: {resolved_or_err}",
            recoverable=True,
            suggested_fix="Provide an existing local binary file path.",
        )

    try:
        file_size = resolved_or_err.stat().st_size
        read_cap = min(file_size, 8 * 1024 * 1024)
        with resolved_or_err.open("rb") as fh:
            sample_bytes = fh.read(read_cap)
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.binary_meta",
            message=f"Unable to read binary file: {exc}",
            recoverable=True,
        )

    bin_hash = compute_sha256_bytes(sample_bytes)
    cached = cache.get("binary_meta", f"{bin_hash}:{file_size}") if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        meta_result = cached
        _rehydrate_binary_handles(meta_result, reg)
        from_cache = True
    else:
        fmt_info = detect_binary_format(sample_bytes[:65536], binary_path=resolved_or_err)
        strings_found = extract_redacted_strings(sample_bytes, max_strings=150)
        routes_found, urls_found = _extract_routes_and_urls(strings_found)
        string_handles = [
            {"handle": reg.register(f"str::{s}", {"kind": "binary_string"}), "value": s}
            for s in strings_found[:80]
        ]
        disasm_bridge = _probe_optional_disassembler(resolved_or_err, timeout_seconds=timeout_seconds)

        meta_result = {
            "file": str(resolved_or_err),
            "file_size_bytes": file_size,
            "bytes_scanned": len(sample_bytes),
            "sha256_sample": bin_hash,
            "format_info": fmt_info,
            "strings_count": len(strings_found),
            "strings": string_handles,
            "routes": routes_found,
            "urls": urls_found,
            "disassembler_bridge": disasm_bridge,
        }
        if cache is not None:
            cache.set("binary_meta", f"{bin_hash}:{file_size}", meta_result)
        from_cache = False

    strings_slice = apply_output_budget(
        "\n".join(item["value"] for item in meta_result.get("strings", [])),
        max_chars=max_output_chars,
        offset=offset,
    )

    return ToolResponse(
        module="nga.analyzers.binary_meta",
        summary=(
            f"Binary '{resolved_or_err.name}': format={meta_result['format_info']['format']} "
            f"({meta_result['format_info']['arch']}), strings={meta_result['strings_count']}, "
            f"cache_hit={from_cache}."
        ),
        truncated=bool(strings_slice["truncated"]),
        next_offset=strings_slice["next_offset"],
        data={
            "cache_hit": from_cache,
            "metadata": meta_result,
            "routes": meta_result.get("routes", []),
            "urls": meta_result.get("urls", []),
            "strings_slice": strings_slice,
        },
    )
    
