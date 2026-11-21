"""Safe archive and package inspector (.zip, .apk, .jar, .asar) with Zip-Slip and bomb guards."""

from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any
import zipfile

from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_ARCHIVE_ENTRIES,
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_MAX_UNCOMPRESSED_BYTES,
    apply_output_budget,
    compute_sha256_bytes,
    redact_secrets,
    safe_resolve_path,
    sanitize_archive_member_name,
)


def _inspect_asar_archive(archive_path: Path, handles: HandleRegistry) -> dict[str, Any] | NgaError:
    """Parse Electron ASAR pickle header and file inventory safely without extracting untrusted paths."""
    try:
        with archive_path.open("rb") as fh:
            header_prefix = fh.read(16)
            if len(header_prefix) < 16:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.analyzers.archive_pkg",
                    message="File is too small to be a valid ASAR archive.",
                    recoverable=True,
                )
            _, header_size = struct.unpack("<IIII", header_prefix)
            if header_size <= 0 or header_size > 16 * 1024 * 1024:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.analyzers.archive_pkg",
                    message=f"Invalid or oversized ASAR header size: {header_size}",
                    recoverable=True,
                )
            header_bytes = fh.read(header_size)
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.archive_pkg",
            message=f"Failed reading ASAR archive: {exc}",
            recoverable=True,
        )

    # ASAR header is a Chromium pickle containing a JSON string
    json_start = header_bytes.find(b"{")
    json_end = header_bytes.rfind(b"}")
    if json_start == -1 or json_end == -1 or json_end <= json_start:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.archive_pkg",
            message="Unable to locate JSON file map inside ASAR header.",
            recoverable=True,
        )

    try:
        tree_obj = json.loads(header_bytes[json_start : json_end + 1].decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.archive_pkg",
            message=f"Malformed JSON inside ASAR header: {exc}",
            recoverable=True,
        )

    files_found: list[dict[str, Any]] = []
    unsafe_entries: list[str] = []

    def _walk_node(node: dict[str, Any], prefix: str) -> None:
        if len(files_found) >= DEFAULT_MAX_ARCHIVE_ENTRIES:
            return
        sub_files = node.get("files")
        if not isinstance(sub_files, dict):
            return
        for name, meta in sub_files.items():
            if len(files_found) >= DEFAULT_MAX_ARCHIVE_ENTRIES:
                break
            rel = f"{prefix}/{name}".lstrip("/")
            ok_name, safe_or_err = sanitize_archive_member_name(rel)
            if not ok_name or not isinstance(safe_or_err, str):
                unsafe_entries.append(rel)
                continue
            if isinstance(meta, dict) and "files" in meta:
                _walk_node(meta, safe_or_err)
            else:
                size_val = int(meta.get("size", 0)) if isinstance(meta, dict) else 0
                h = handles.register(f"asar::{safe_or_err}", {"size": size_val})
                files_found.append({"handle": h, "path": safe_or_err, "size": size_val})

    if isinstance(tree_obj, dict):
        _walk_node(tree_obj, "")

    return {
        "format": "asar",
        "file_count": len(files_found),
        "unsafe_entries_blocked": len(unsafe_entries),
        "unsafe_samples": unsafe_entries[:20],
        "entries": files_found[:200],
    }


def _inspect_zip_like_archive(
    archive_path: Path,
    handles: HandleRegistry,
    max_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> dict[str, Any] | NgaError:
    """Inspect ZIP/APK/JAR entries with Zip-Slip protection, bomb limits, and Android manifest hints."""
    entries: list[dict[str, Any]] = []
    unsafe_entries: list[str] = []
    total_uncompressed = 0
    total_compressed = 0
    android_markers: list[str] = []

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                return NgaError(
                    error_code=ErrorCode.BUDGET_EXCEEDED.value,
                    module="nga.analyzers.archive_pkg",
                    message=f"Archive entry count ({len(infos)}) exceeds safety limit ({max_entries}).",
                    recoverable=True,
                    suggested_fix="Inspect a smaller archive or raise max_entries budget.",
                )

            for info in infos:
                raw_name = info.filename
                if raw_name.endswith("/"):
                    continue
                ok_name, safe_or_err = sanitize_archive_member_name(raw_name)
                if not ok_name or not isinstance(safe_or_err, str):
                    unsafe_entries.append(raw_name)
                    continue

                uncomp = max(0, int(info.file_size))
                comp = max(0, int(info.compress_size))
                total_uncompressed += uncomp
                total_compressed += comp

                if total_uncompressed > max_uncompressed_bytes:
                    return NgaError(
                        error_code=ErrorCode.BUDGET_EXCEEDED.value,
                        module="nga.analyzers.archive_pkg",
                        message=f"Cumulative uncompressed size exceeds limit ({max_uncompressed_bytes} bytes).",
                        recoverable=True,
                        suggested_fix="Reject decompression bomb or analyze smaller package.",
                    )

                lower_safe = safe_or_err.lower()
                if lower_safe in {"androidmanifest.xml", "classes.dex", "resources.arsc"} or lower_safe.endswith(".dex"):
                    android_markers.append(safe_or_err)

                h = handles.register(
                    f"pkg::{safe_or_err}",
                    {"uncompressed_size": uncomp, "compressed_size": comp},
                )
                if len(entries) < 200:
                    entries.append(
                        {
                            "handle": h,
                            "path": safe_or_err,
                            "uncompressed_size": uncomp,
                            "compressed_size": comp,
                        }
                    )

            # Extract readable strings preview from AndroidManifest.xml if present as text/XML
            manifest_preview = ""
            if "AndroidManifest.xml" in zf.namelist():
                try:
                    raw_manifest = zf.read("AndroidManifest.xml")
                    decoded = redact_secrets(raw_manifest.decode("utf-8", errors="ignore"))
                    printable = "".join(ch if ch.isprintable() or ch in "\n\r\t" else " " for ch in decoded)
                    manifest_preview = apply_output_budget(printable.strip(), max_chars=2000)["content"]
                except Exception:
                    manifest_preview = ""

    except zipfile.BadZipFile as exc:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.archive_pkg",
            message=f"Corrupt or invalid ZIP/APK archive '{archive_path.name}': {exc}",
            recoverable=True,
        )
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.archive_pkg",
            message=f"Failed reading archive '{archive_path.name}': {exc}",
            recoverable=True,
        )

    ext = archive_path.suffix.lower()
    detected_format = "apk" if (ext == ".apk" or android_markers) else ("jar" if ext == ".jar" else "zip")

    return {
        "format": detected_format,
        "total_entries": len(entries) + len(unsafe_entries),
        "safe_entries_indexed": len(entries),
        "unsafe_entries_blocked": len(unsafe_entries),
        "unsafe_samples": unsafe_entries[:20],
        "total_uncompressed_bytes": total_uncompressed,
        "total_compressed_bytes": total_compressed,
        "android_markers": sorted(set(android_markers)),
        "manifest_preview": manifest_preview,
        "entries": entries,
    }


def inspect_archive_package(
    package_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> ToolResponse | NgaError:
    """Safely inspect a local .zip, .apk, .jar, or .asar package with caching and budgets."""
    root = Path(base_root) if base_root is not None else Path.cwd()
    ok_path, resolved_or_err = safe_resolve_path(root, package_path)
    if not ok_path or not isinstance(resolved_or_err, Path):
        return resolved_or_err if isinstance(resolved_or_err, NgaError) else NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.archive_pkg",
            message="Invalid archive file path.",
        )

    if not resolved_or_err.exists() or not resolved_or_err.is_file():
        return NgaError(
            error_code=ErrorCode.NOT_FOUND.value,
            module="nga.analyzers.archive_pkg",
            message=f"Archive file not found: {resolved_or_err}",
            recoverable=True,
            suggested_fix="Provide an existing .zip, .apk, .jar, or .asar file.",
        )

    try:
        file_bytes = resolved_or_err.read_bytes()
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.archive_pkg",
            message=f"Unable to read archive file: {exc}",
            recoverable=True,
        )

    pkg_hash = compute_sha256_bytes(file_bytes)
    cached = cache.get("archive_pkg", pkg_hash) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        result = cached
        from_cache = True
    else:
        ext = resolved_or_err.suffix.lower()
        if ext == ".asar":
            inspected = _inspect_asar_archive(resolved_or_err, reg)
        else:
            inspected = _inspect_zip_like_archive(resolved_or_err, reg)

        if isinstance(inspected, NgaError):
            return inspected

        result = inspected
        result["sha256"] = pkg_hash
        if cache is not None:
            cache.set("archive_pkg", pkg_hash, result)
        from_cache = False

    entries_slice = apply_output_budget(
        json.dumps(result.get("entries", []), indent=2, default=str),
        max_chars=max_output_chars,
        offset=offset,
    )

    return ToolResponse(
        module="nga.analyzers.archive_pkg",
        summary=(
            f"Package '{resolved_or_err.name}' ({result.get('format')}): "
            f"blocked_unsafe={result.get('unsafe_entries_blocked', 0)}, cache_hit={from_cache}."
        ),
        truncated=bool(entries_slice["truncated"]),
        next_offset=entries_slice["next_offset"],
        data={
            "file": str(resolved_or_err),
            "cache_hit": from_cache,
            "package": result,
            "entries_slice": entries_slice,
        },
  )
                   
