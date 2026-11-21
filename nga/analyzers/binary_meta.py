"""Binary metadata, format signature, string scanner, and optional disassembler bridge for `nga`."""

from __future__ import annotations

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

_PRINTABLE_STR_RE = re.compile(rb"[ -~]{4,120}")


def detect_binary_format(header: bytes) -> dict[str, Any]:
    """Identify ELF, PE/MZ, Mach-O, WASM, or unknown binary magic signatures."""
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
            if pe_offset + 6 <= len(header) and header[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                machine_code = struct.unpack("<H", header[pe_offset + 4 : pe_offset + 6])[0]
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

    macho_magics = {
        b"\xfe\xed\xfa\xce": ("macho", 32, "big"),
        b"\xce\xfa\xed\xfe": ("macho", 32, "little"),
        b"\xfe\xed\xfa\xcf": ("macho", 64, "big"),
        b"\xcf\xfa\xed\xfe": ("macho", 64, "little"),
        b"\xca\xfe\xba\xbe": ("macho_fat", 0, "big"),
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
    """Extract printable ASCII strings from binary data with secret redaction and deduplication."""
    cap = max(10, min(500, int(max_strings)))
    found: list[str] = []
    seen: set[str] = set()

    for match in _PRINTABLE_STR_RE.finditer(data):
        raw_str = match.group(0).decode("ascii", errors="ignore").strip()
        if len(raw_str) < 4:
            continue
        cleaned = redact_secrets(raw_str)
        if cleaned not in seen:
            seen.add(cleaned)
            found.append(cleaned)
            if len(found) >= cap:
                break

    return found


def _probe_optional_disassembler(binary_path: Path, timeout_seconds: float = 15.0) -> dict[str, Any]:
    """Optionally query `rizin` or `radare2` if available on PATH without failing if absent."""
    for tool_name in ("rizin", "radare2"):
        exe = shutil.which(tool_name)
        if not exe:
            continue
        try:
            proc = subprocess.run(
                [exe, "-q", "-c", "i;afl~?", str(binary_path)],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=timeout_seconds,
            )
            bounded = apply_output_budget(redact_secrets((proc.stdout or "").strip()), max_chars=2500)
            return {
                "used": True,
                "tool": tool_name,
                "returncode": proc.returncode,
                "info_preview": bounded["content"],
            }
        except Exception as exc:
            return {
                "used": False,
                "tool": tool_name,
                "error": str(exc),
            }
    return {"used": False, "tool": None}


def inspect_binary_target(
    binary_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
    timeout_seconds: float = 15.0,
) -> ToolResponse | NgaError:
    """Inspect a local binary file safely with caching, format detection, strings, and budgets."""
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
        from_cache = True
    else:
        fmt_info = detect_binary_format(sample_bytes[:4096])
        strings_found = extract_redacted_strings(sample_bytes, max_strings=120)
        string_handles = [
            {"handle": reg.register(f"str::{s}", {"kind": "binary_string"}), "value": s}
            for s in strings_found[:60]
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
            "strings_slice": strings_slice,
        },
  )
      
