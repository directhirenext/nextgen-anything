"""Safe archive and package inspector (.zip, .apk, .jar, .asar) with AXML/DEX parsing and bomb guards."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any
import zipfile

from nga.analyzers.network_har import analyze_har_payload
from nga.analyzers.web_js import analyze_html_source, analyze_js_source
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_ARCHIVE_ENTRIES,
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_MAX_UNCOMPRESSED_BYTES,
    apply_output_budget,
    redact_secrets,
    safe_resolve_path,
    sanitize_archive_member_name,
)

MAX_ARCHIVE_FILE_BYTES = 100 * 1024 * 1024  # 100 MB on-disk cap
MAX_MANIFEST_READ_BYTES = 2 * 1024 * 1024  # 2 MB cap for AndroidManifest.xml
MAX_DEX_READ_BYTES = 6 * 1024 * 1024  # 6 MB cap per DEX read
MAX_INNER_TEXT_BYTES = 512 * 1024  # 512 KB cap per inner HTML/JS/HAR asset
MAX_INNER_TEXT_FILES = 15

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,220}")
_API_ROUTE_RE = re.compile(
    r"(/(?:api|v\d+|auth|login|users|profile|items|orders|tasks|jobs|payments|search|admin|dashboard|graphql)[A-Za-z0-9_./:-]{0,120})",
    re.IGNORECASE,
)
_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,6}$")
_DEX_CLASS_RE = re.compile(r"^L([a-zA-Z0-9_/$]+);$")


def _sha256_file_streaming(file_path: Path, chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a file using bounded streaming chunks."""
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_zip_member_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, max_bytes: int) -> bytes:
    """Read a ZIP member stream strictly capped at `max_bytes` to stop decompression bombs."""
    cap = max(1, int(max_bytes))
    with zf.open(info, "r") as stream:
        return stream.read(cap)


def _decode_axml_string_pool(raw_data: bytes, max_strings: int = 800) -> list[str]:
    """Decode UTF-8/UTF-16LE string pool from binary Android AXML (AndroidManifest.xml)."""
    if len(raw_data) < 36 or raw_data[:4] != b"\x03\x00\x08\x00":
        return []

    chunk_off = 8
    while chunk_off + 8 <= len(raw_data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", raw_data, chunk_off)
        if chunk_size < 8 or chunk_off + chunk_size > len(raw_data):
            break
        if chunk_type == 0x0001 and header_size >= 28 and chunk_off + 28 <= len(raw_data):
            string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
                "<IIIII", raw_data, chunk_off + 8
            )
            is_utf8 = bool(flags & 0x00000100)
            offsets_base = chunk_off + header_size
            pool_base = chunk_off + strings_start
            pool_end = chunk_off + chunk_size
            extracted: list[str] = []
            count = min(string_count, max_strings)
            for idx in range(count):
                off_pos = offsets_base + idx * 4
                if off_pos + 4 > pool_end:
                    break
                rel_off = struct.unpack_from("<I", raw_data, off_pos)[0]
                pos = pool_base + rel_off
                if pos >= pool_end:
                    continue
                if is_utf8:
                    # Skip UTF-16 char length (1-2 bytes)
                    if pos >= pool_end:
                        continue
                    b0 = raw_data[pos]
                    pos += 2 if (b0 & 0x80) else 1
                    if pos >= pool_end:
                        continue
                    # Read UTF-8 byte length (1-2 bytes)
                    b1 = raw_data[pos]
                    if b1 & 0x80:
                        if pos + 1 >= pool_end:
                            continue
                        byte_len = ((b1 & 0x7F) << 8) | raw_data[pos + 1]
                        pos += 2
                    else:
                        byte_len = b1
                        pos += 1
                    text = raw_data[pos : min(pool_end, pos + byte_len)].decode("utf-8", errors="ignore")
                else:
                    if pos + 2 > pool_end:
                        continue
                    u16_len = struct.unpack_from("<H", raw_data, pos)[0]
                    pos += 2
                    if u16_len & 0x8000:
                        if pos + 2 > pool_end:
                            continue
                        low = struct.unpack_from("<H", raw_data, pos)[0]
                        u16_len = ((u16_len & 0x7FFF) << 16) | low
                        pos += 2
                    byte_len = min(u16_len * 2, pool_end - pos)
                    text = raw_data[pos : pos + byte_len].decode("utf-16le", errors="ignore")
                cleaned = redact_secrets(text.strip())
                if cleaned:
                    extracted.append(cleaned)
            return extracted
        chunk_off += chunk_size
    return []


def _parse_android_manifest(raw_manifest: bytes) -> dict[str, Any]:
    """Extract package name, permissions, components, and URLs from binary AXML or plain XML manifest."""
    is_binary_axml = len(raw_manifest) >= 8 and raw_manifest[:4] == b"\x03\x00\x08\x00"
    if is_binary_axml:
        strings = _decode_axml_string_pool(raw_manifest, max_strings=800)
        preview_source = "\n".join(strings)
    else:
        decoded = redact_secrets(raw_manifest.decode("utf-8", errors="ignore"))
        preview_source = "".join(ch if ch.isprintable() or ch in "\n\r\t" else " " for ch in decoded)
        strings = re.findall(r"""["']([^"']{3,160})["']""", preview_source)

    permissions: list[str] = []
    components: list[str] = []
    package_candidates: list[str] = []
    urls: list[str] = []

    seen_perm: set[str] = set()
    seen_comp: set[str] = set()
    seen_urls: set[str] = set()

    for s in strings:
        if "permission." in s and s not in seen_perm:
            seen_perm.add(s)
            permissions.append(s)
        elif (
            s.startswith(".")
            or any(tag in s for tag in ("Activity", "Service", "Receiver", "Provider", "Application"))
        ) and "." in s and len(s) <= 140:
            if s not in seen_comp:
                seen_comp.add(s)
                components.append(s)
        elif _PACKAGE_RE.match(s) and not s.startswith(("android.", "java.", "javax.", "kotlin.")):
            if s not in package_candidates:
                package_candidates.append(s)

        for u in _URL_RE.findall(s):
            clean_u = redact_secrets(u)
            if clean_u not in seen_urls:
                seen_urls.add(clean_u)
                urls.append(clean_u)

    if not is_binary_axml:
        pkg_match = re.search(r"""package\s*=\s*["']([a-zA-Z0-9_.]+)["']""", preview_source)
        if pkg_match:
            package_candidates.insert(0, pkg_match.group(1))

    return {
        "format": "binary_axml" if is_binary_axml else "text_xml",
        "package_name": package_candidates[0] if package_candidates else "",
        "permissions": permissions[:80],
        "components": components[:80],
        "urls": urls[:50],
        "preview": apply_output_budget(preview_source.strip(), max_chars=2000)["content"],
    }


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Decode unsigned LEB128 integer used by Dalvik DEX format."""
    result = 0
    shift = 0
    pos = offset
    limit = min(len(data), offset + 5)
    while pos < limit:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, pos


def _parse_dex_strings_and_classes(raw_dex: bytes, max_strings: int = 3000) -> dict[str, Any]:
    """Extract Dalvik DEX class names, API URLs, and route strings without external tools."""
    if len(raw_dex) < 112 or not raw_dex.startswith(b"dex\n") or raw_dex[7:8] != b"\x00":
        return {"valid_dex": False, "classes": [], "urls": [], "routes": []}

    string_ids_size, string_ids_off = struct.unpack_from("<II", raw_dex, 56)
    classes: list[str] = []
    urls: list[str] = []
    routes: list[str] = []
    seen_classes: set[str] = set()
    seen_urls: set[str] = set()
    seen_routes: set[str] = set()

    count = min(string_ids_size, max_strings)
    for idx in range(count):
        id_pos = string_ids_off + idx * 4
        if id_pos + 4 > len(raw_dex):
            break
        str_data_off = struct.unpack_from("<I", raw_dex, id_pos)[0]
        if str_data_off <= 0 or str_data_off >= len(raw_dex):
            continue
        _utf16_len, text_start = _read_uleb128(raw_dex, str_data_off)
        nul_pos = raw_dex.find(b"\x00", text_start, min(len(raw_dex), text_start + 512))
        if nul_pos == -1:
            continue
        text = raw_dex[text_start:nul_pos].decode("utf-8", errors="ignore").strip()
        if not text:
            continue

        cls_match = _DEX_CLASS_RE.match(text)
        if cls_match:
            dotted = cls_match.group(1).replace("/", ".")
            if not dotted.startswith(("java.", "javax.", "android.", "androidx.", "kotlin.", "dalvik.")):
                if dotted not in seen_classes and len(classes) < 120:
                    seen_classes.add(dotted)
                    classes.append(dotted)
            continue

        redacted = redact_secrets(text)
        for u in _URL_RE.findall(redacted):
            if u not in seen_urls and len(urls) < 80:
                seen_urls.add(u)
                urls.append(u)
        for r in _API_ROUTE_RE.findall(redacted):
            if r not in seen_routes and len(routes) < 80:
                seen_routes.add(r)
                routes.append(r)

    return {
        "valid_dex": True,
        "dex_version": raw_dex[4:7].decode("ascii", errors="ignore"),
        "string_ids_total": int(string_ids_size),
        "classes": classes,
        "urls": urls,
        "routes": routes,
    }


def _inspect_asar_archive(archive_path: Path, handles: HandleRegistry) -> dict[str, Any] | NgaError:
    """Parse Electron ASAR pickle header and file inventory iteratively without extraction."""
    try:
        file_size = archive_path.stat().st_size
        with archive_path.open("rb") as fh:
            header_prefix = fh.read(16)
            if len(header_prefix) < 16:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.analyzers.archive_pkg",
                    message="File is too small to be a valid ASAR archive.",
                    recoverable=True,
                )
            _size1, header_pickle_size, _header_payload_size, json_byte_len = struct.unpack("<IIII", header_prefix)
            read_len = json_byte_len if 2 <= json_byte_len <= 16 * 1024 * 1024 else header_pickle_size
            if read_len <= 0 or read_len > 16 * 1024 * 1024 or read_len > file_size:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.analyzers.archive_pkg",
                    message=f"Invalid or oversized ASAR header size: {read_len}",
                    recoverable=True,
                )
            header_bytes = fh.read(read_len)
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.archive_pkg",
            message=f"Failed reading ASAR archive: {exc}",
            recoverable=True,
        )

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
    total_safe_count = 0

    if isinstance(tree_obj, dict):
        stack: list[tuple[dict[str, Any], str, int]] = [(tree_obj, "", 0)]
        while stack:
            node, prefix, depth = stack.pop()
            if depth > 64:
                continue
            sub_files = node.get("files")
            if not isinstance(sub_files, dict):
                continue
            for name, meta in reversed(list(sub_files.items())):
                if total_safe_count >= DEFAULT_MAX_ARCHIVE_ENTRIES:
                    break
                rel = f"{prefix}/{name}".lstrip("/")
                ok_name, safe_or_err = sanitize_archive_member_name(rel)
                if not ok_name or not isinstance(safe_or_err, str):
                    unsafe_entries.append(rel)
                    continue
                if isinstance(meta, dict) and isinstance(meta.get("files"), dict):
                    stack.append((meta, safe_or_err, depth + 1))
                else:
                    total_safe_count += 1
                    size_val = max(0, _safe_int(meta.get("size", 0) if isinstance(meta, dict) else 0, 0))
                    h = handles.register(f"asar::{safe_or_err}", {"size": size_val})
                    if len(files_found) < 200:
                        files_found.append({"handle": h, "path": safe_or_err, "size": size_val})

    return {
        "format": "asar",
        "file_count": total_safe_count,
        "total_entries": total_safe_count + len(unsafe_entries),
        "safe_entries_indexed": total_safe_count,
        "unsafe_entries_blocked": len(unsafe_entries),
        "unsafe_samples": unsafe_entries[:20],
        "entries": files_found,
        "routes": [],
        "forms": [],
        "endpoints": [],
    }


def _inspect_zip_like_archive(
    archive_path: Path,
    handles: HandleRegistry,
    max_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> dict[str, Any] | NgaError:
    """Inspect ZIP/APK/JAR entries with Zip-Slip protection, AXML/DEX analysis, and inner web scanning."""
    entries: list[dict[str, Any]] = []
    unsafe_entries: list[str] = []
    total_safe_count = 0
    total_uncompressed = 0
    total_compressed = 0
    android_markers: list[str] = []

    apk_manifest: dict[str, Any] = {}
    dex_classes: list[str] = []
    dex_urls: list[str] = []
    discovered_routes: list[str] = []
    discovered_forms: list[dict[str, Any]] = []
    discovered_endpoints: list[dict[str, Any]] = []
    seen_routes: set[str] = set()
    inner_scanned = 0

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

            manifest_info: zipfile.ZipInfo | None = None
            dex_infos: list[zipfile.ZipInfo] = []
            inner_web_infos: list[tuple[zipfile.ZipInfo, str]] = []

            for info in infos:
                raw_name = info.filename
                if raw_name.endswith("/"):
                    continue
                ok_name, safe_or_err = sanitize_archive_member_name(raw_name)
                if not ok_name or not isinstance(safe_or_err, str):
                    unsafe_entries.append(raw_name)
                    continue

                uncomp = max(0, _safe_int(info.file_size, 0))
                comp = max(0, _safe_int(info.compress_size, 0))
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

                total_safe_count += 1
                lower_safe = safe_or_err.lower()
                if lower_safe in {"androidmanifest.xml", "classes.dex", "resources.arsc"} or lower_safe.endswith(".dex"):
                    android_markers.append(safe_or_err)
                if lower_safe == "androidmanifest.xml" and manifest_info is None:
                    manifest_info = info
                elif lower_safe.endswith(".dex") and len(dex_infos) < 3:
                    dex_infos.append(info)
                elif (
                    len(inner_web_infos) < MAX_INNER_TEXT_FILES
                    and uncomp <= MAX_INNER_TEXT_BYTES
                    and lower_safe.endswith((".html", ".htm", ".js", ".mjs", ".har"))
                ):
                    inner_web_infos.append((info, safe_or_err))

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

            if manifest_info is not None:
                try:
                    raw_manifest = _read_zip_member_bounded(zf, manifest_info, MAX_MANIFEST_READ_BYTES)
                    apk_manifest = _parse_android_manifest(raw_manifest)
                    for u in apk_manifest.get("urls", []):
                        if u not in dex_urls:
                            dex_urls.append(u)
                except Exception:
                    apk_manifest = {}

            for dex_info in dex_infos:
                try:
                    raw_dex = _read_zip_member_bounded(zf, dex_info, MAX_DEX_READ_BYTES)
                    dex_parsed = _parse_dex_strings_and_classes(raw_dex)
                    for cls in dex_parsed.get("classes", []):
                        if cls not in dex_classes and len(dex_classes) < 150:
                            dex_classes.append(cls)
                    for u in dex_parsed.get("urls", []):
                        if u not in dex_urls and len(dex_urls) < 100:
                            dex_urls.append(u)
                    for r in dex_parsed.get("routes", []):
                        if r not in seen_routes:
                            seen_routes.add(r)
                            discovered_routes.append(r)
                except Exception:
                    continue

            for info, safe_name in inner_web_infos:
                try:
                    raw_inner = _read_zip_member_bounded(zf, info, MAX_INNER_TEXT_BYTES)
                    text_inner = redact_secrets(raw_inner.decode("utf-8", errors="replace"))
                    inner_scanned += 1
                    low = safe_name.lower()
                    if low.endswith(".har"):
                        loaded_har = json.loads(text_inner)
                        if isinstance(loaded_har, dict):
                            har_res = analyze_har_payload(loaded_har, source_label=safe_name, handles=handles)
                            for ep in har_res.get("endpoints", []):
                                if len(discovered_endpoints) < 80:
                                    discovered_endpoints.append(ep)
                    elif low.endswith((".html", ".htm")):
                        html_res = analyze_html_source(text_inner, base_url=safe_name, handles=handles)
                        for f in html_res.get("forms", []):
                            if len(discovered_forms) < 50:
                                discovered_forms.append(f)
                        for r_item in html_res.get("routes", []):
                            rp = r_item.get("path", "") if isinstance(r_item, dict) else str(r_item)
                            if rp and rp not in seen_routes:
                                seen_routes.add(rp)
                                discovered_routes.append(rp)
                    else:
                        js_res = analyze_js_source(text_inner, source_label=safe_name, handles=handles)
                        for r_item in js_res.get("routes", []):
                            rp = r_item.get("path", "") if isinstance(r_item, dict) else str(r_item)
                            if rp and rp not in seen_routes:
                                seen_routes.add(rp)
                                discovered_routes.append(rp)
                except Exception:
                    continue

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
        "total_entries": total_safe_count + len(unsafe_entries),
        "safe_entries_indexed": total_safe_count,
        "entries_returned": len(entries),
        "unsafe_entries_blocked": len(unsafe_entries),
        "unsafe_samples": unsafe_entries[:20],
        "total_uncompressed_bytes": total_uncompressed,
        "total_compressed_bytes": total_compressed,
        "android_markers": sorted(set(android_markers)),
        "apk_metadata": {
            "package_name": apk_manifest.get("package_name", ""),
            "manifest_format": apk_manifest.get("format", ""),
            "permissions": apk_manifest.get("permissions", []),
            "components": apk_manifest.get("components", []),
            "dex_classes": dex_classes,
            "discovered_urls": dex_urls,
        },
        "manifest_preview": apk_manifest.get("preview", ""),
        "inner_assets_scanned": inner_scanned,
        "routes": discovered_routes[:100],
        "forms": discovered_forms,
        "endpoints": discovered_endpoints,
        "entries": entries,
    }


def _rehydrate_archive_handles(result: dict[str, Any], handles: HandleRegistry) -> None:
    prefix = "asar" if result.get("format") == "asar" else "pkg"
    entries = result.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("path"):
                entry["handle"] = handles.register(
                    f"{prefix}::{entry['path']}",
                    {"size": entry.get("uncompressed_size", entry.get("size", 0))},
                )


def inspect_archive_package(
    package_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
    max_archive_bytes: int = MAX_ARCHIVE_FILE_BYTES,
) -> ToolResponse | NgaError:
    """Safely inspect a local .zip, .apk, .jar, or .asar package with streaming hash, AXML/DEX, and budgets."""
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

    size_cap = max(1024, int(max_archive_bytes))
    try:
        file_size = resolved_or_err.stat().st_size
        if file_size > size_cap:
            return NgaError(
                error_code=ErrorCode.BUDGET_EXCEEDED.value,
                module="nga.analyzers.archive_pkg",
                message=f"Archive '{resolved_or_err.name}' ({file_size} bytes) exceeds limit ({size_cap} bytes).",
                recoverable=True,
                suggested_fix="Provide a smaller archive or raise max_archive_bytes.",
            )
        pkg_hash = _sha256_file_streaming(resolved_or_err)
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.archive_pkg",
            message=f"Unable to read archive file: {exc}",
            recoverable=True,
        )

    cached = cache.get("archive_pkg", pkg_hash) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        result = cached
        _rehydrate_archive_handles(result, reg)
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
            f"entries={result.get('safe_entries_indexed', 0)}, "
            f"blocked_unsafe={result.get('unsafe_entries_blocked', 0)}, cache_hit={from_cache}."
        ),
        truncated=bool(entries_slice["truncated"]),
        next_offset=entries_slice["next_offset"],
        data={
            "file": str(resolved_or_err),
            "cache_hit": from_cache,
            "package": result,
            "routes": result.get("routes", []),
            "forms": result.get("forms", []),
            "endpoints": result.get("endpoints", []),
            "apk_metadata": result.get("apk_metadata", {}),
            "entries_slice": entries_slice,
        },
    )
