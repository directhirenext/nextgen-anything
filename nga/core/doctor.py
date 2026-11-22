"""Cross-OS environment doctor and optional toolchain resolver for NextGen-Anything (`nga`)."""

from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
from typing import Any

from nga.core.contracts import ToolResponse

OPTIONAL_EXTERNAL_TOOLS: dict[str, dict[str, str]] = {
    "jadx": {
        "category": "android_decompiler",
        "purpose": "Decompiles Android APK/DEX bytecode to readable Java source.",
        "fallback": "Built-in pure-Python ZIP/AndroidManifest(AXML)/DEX scanner.",
    },
    "apktool": {
        "category": "android_resources",
        "purpose": "Unpacks Android resources and smali bytecode.",
        "fallback": "Built-in pure-Python APK archive and binary XML parser.",
    },
    "rizin": {
        "category": "native_disassembler",
        "purpose": "Disassembles native ELF/PE/Mach-O binaries.",
        "fallback": "Built-in pure-Python ELF/PE/Mach-O/WASM header, section & string parser.",
    },
    "radare2": {
        "category": "native_disassembler",
        "purpose": "Alternative CLI binary disassembler.",
        "fallback": "Built-in pure-Python binary metadata & string analyzer.",
    },
    "node": {
        "category": "js_runtime",
        "purpose": "Executes Node.js scripts and JavaScript syntax/AST helpers.",
        "fallback": "Built-in pure-Python JS bundle, route, and sourcemap analyzer.",
    },
    "cargo": {
        "category": "rust_toolchain",
        "purpose": "Builds optional high-speed Rust crate (`nga-fast-core`).",
        "fallback": "Pure-Python engine runs identically with zero Rust dependency.",
    },
    "curl": {
        "category": "http_client",
        "purpose": "Performs CLI HTTP probes.",
        "fallback": "Python standard library `urllib.request` HTTP client.",
    },
}


def _probe_termux_path() -> bool:
    """Safely check for Android Termux directory without raising SELinux PermissionError."""
    try:
        return Path("/data/data/com.termux/files/usr").exists()
    except OSError:
        return False


def _probe_sqlite_capabilities() -> dict[str, Any]:
    """Verify real SQLite execution and FTS5 virtual table availability."""
    sqlite_ok = False
    fts5_ok = False
    try:
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute("CREATE TABLE _nga_probe (id INTEGER PRIMARY KEY);")
            sqlite_ok = True
            try:
                conn.execute("CREATE VIRTUAL TABLE _nga_fts_probe USING fts5(content);")
                fts5_ok = True
            except sqlite3.OperationalError:
                fts5_ok = False
    except sqlite3.Error:
        sqlite_ok = False
        fts5_ok = False

    return {
        "sqlite_available": sqlite_ok,
        "sqlite_version": sqlite3.sqlite_version,
        "fts5_available": fts5_ok,
    }


def detect_host_platform() -> dict[str, Any]:
    """Identify host operating system, Android/Termux environment, architecture, and Python version."""
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    prefix = os.environ.get("PREFIX", "")
    termux_version = os.environ.get("TERMUX_VERSION", "")

    is_termux = bool(termux_version or "com.termux" in prefix or _probe_termux_path())

    if is_termux:
        os_id = "android-termux"
    elif sys_name.startswith("linux"):
        os_id = "linux"
    elif sys_name.startswith("windows") or os.name == "nt":
        os_id = "windows"
    elif sys_name == "darwin":
        os_id = "macos"
    else:
        os_id = sys_name or "unknown"

    return {
        "os_id": os_id,
        "system": platform.system(),
        "release": platform.release(),
        "architecture": machine or "unknown",
        "is_termux": is_termux,
        "is_mobile_constrained": is_termux,
        "python_version": platform.python_version(),
        "python_supported": sys.version_info >= (3, 10),
        "python_executable": sys.executable,
    }


def scan_toolchains() -> dict[str, dict[str, Any]]:
    """Probe PATH for optional external tools without raising errors when absent."""
    results: dict[str, dict[str, Any]] = {}
    for tool_name, meta in OPTIONAL_EXTERNAL_TOOLS.items():
        resolved = shutil.which(tool_name)
        results[tool_name] = {
            "available": resolved is not None,
            "path": resolved,
            "category": meta["category"],
            "purpose": meta["purpose"],
            "active_mode": "native_cli_bridge" if resolved else "built_in_python_fallback",
            "fallback": meta["fallback"],
        }
    return results


def run_environment_doctor(workspace_root: Path | str | None = None) -> ToolResponse:
    """Run real cross-OS runtime, SQLite/FTS5, filesystem write, and toolchain diagnostics."""
    host = detect_host_platform()
    toolchains = scan_toolchains()
    sqlite_info = _probe_sqlite_capabilities()
    root = Path(workspace_root) if workspace_root is not None else (Path.home() / ".nga")

    writable = False
    write_error = ""
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe_file = root / f".doctor_write_probe_{os.getpid()}"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        writable = True
    except OSError as exc:
        writable = False
        write_error = str(exc)

    py_ok = bool(host["python_supported"])
    sqlite_ok = bool(sqlite_info["sqlite_available"])
    fts5_ok = bool(sqlite_info["fts5_available"])

    warnings: list[str] = []
    if not py_ok:
        warnings.append(f"Python {host['python_version']} detected; Python 3.10+ is required.")
    if not writable:
        warnings.append(f"Workspace path '{root}' is not writable: {write_error}")
    if not sqlite_ok:
        warnings.append("SQLite runtime probe failed; cache and memory vault cannot operate.")
    elif not fts5_ok:
        warnings.append("SQLite FTS5 extension unavailable; memory vault will use SQL fallback search.")

    storage_state = "ready (SQLite + FTS5)" if (sqlite_ok and fts5_ok and writable) else (
        "degraded (SQLite fallback, no FTS5)" if (sqlite_ok and writable) else "unavailable (read-only or no SQLite)"
    )
    sandbox_state = (
        "ready (isolated Python subprocess + AST guard)"
        if (py_ok and writable)
        else "degraded (workspace not writable or unsupported Python)"
    )

    available_count = sum(1 for item in toolchains.values() if item["available"])
    capabilities = {
        "web_js_analyzer": "ready (built-in Python)" if py_ok else "degraded (Python < 3.10)",
        "network_har_analyzer": "ready (built-in Python)" if py_ok else "degraded (Python < 3.10)",
        "archive_pkg_inspector": "ready (built-in Python)" if py_ok else "degraded (Python < 3.10)",
        "binary_meta_inspector": (
            "ready (rizin/radare2 + Python)"
            if (toolchains["rizin"]["available"] or toolchains["radare2"]["available"])
            else "ready (built-in pure-Python ELF/PE/Mach-O/WASM parser)"
        ),
        "android_apk_inspector": (
            "ready (jadx + Python)"
            if toolchains["jadx"]["available"]
            else "ready (built-in pure-Python APK/AXML/DEX scanner)"
        ),
        "storage_and_memory_vault": storage_state,
        "sandbox_and_simulator": sandbox_state,
        "standin_mock_server": "ready (built-in Python HTTP server)",
        "interfaces": "ready (CLI + MCP JSON-RPC + Local Web UI + Website Embed Widget)",
    }

    overall_ok = py_ok and writable and sqlite_ok
    readiness_label = "All core engines ready." if overall_ok else f"Degraded readiness ({len(warnings)} warning(s))."
    summary = (
        f"Host OS: {host['os_id']} ({host['architecture']}) | "
        f"Python {host['python_version']} | "
        f"SQLite {sqlite_info['sqlite_version']} (FTS5={'yes' if fts5_ok else 'no'}) | "
        f"Optional external tools: {available_count}/{len(toolchains)} detected | "
        f"{readiness_label}"
    )

    return ToolResponse(
        module="nga.core.doctor",
        ok=overall_ok,
        summary=summary,
        data={
            "os_platform": host["os_id"],
            "python_version": host["python_version"],
            "architecture": host["architecture"],
            "is_termux": host["is_termux"],
            "sqlite_fts5_available": fts5_ok,
            "host": host,
            "sqlite": sqlite_info,
            "workspace_root": str(root),
            "workspace_writable": writable,
            "warnings": warnings,
            "capabilities": capabilities,
            "toolchains": toolchains,
        },
    )
    
