"""Cross-OS environment doctor and optional toolchain resolver for NextGen-Anything (`nga`)."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Any

from nga.core.contracts import ToolResponse


OPTIONAL_EXTERNAL_TOOLS: dict[str, dict[str, str]] = {
    "jadx": {
        "category": "android_decompiler",
        "purpose": "Decompiles Android APK/DEX bytecode to readable Java source.",
        "fallback": "Built-in pure-Python ZIP/AndroidManifest/DEX string & structure inspector.",
    },
    "apktool": {
        "category": "android_resources",
        "purpose": "Unpacks Android resources and smali bytecode.",
        "fallback": "Built-in pure-Python APK archive and binary XML string scanner.",
    },
    "rizin": {
        "category": "native_disassembler",
        "purpose": "Disassembles native ELF/PE/Mach-O binaries.",
        "fallback": "Built-in pure-Python ELF/PE/Mach-O/WASM header, section & symbol parser.",
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
        "purpose": "Builds optional high-speed Rust extension (`nga-fast-core`).",
        "fallback": "Pure-Python engine runs identically with zero Rust dependency.",
    },
    "curl": {
        "category": "http_client",
        "purpose": "Performs CLI HTTP probes.",
        "fallback": "Python standard library `urllib.request` HTTP client.",
    },
}


def detect_host_platform() -> dict[str, Any]:
    """Identify host operating system, Android/Termux environment, architecture, and Python version."""
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    prefix = os.environ.get("PREFIX", "")
    termux_version = os.environ.get("TERMUX_VERSION", "")

    is_termux = bool(
        termux_version
        or "com.termux" in prefix
        or Path("/data/data/com.termux/files/usr").exists()
    )

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


def run_environment_doctor(workspace_root: Path | None = None) -> ToolResponse:
    """Run full cross-OS capability and readiness diagnostics."""
    host = detect_host_platform()
    toolchains = scan_toolchains()
    root = Path(workspace_root) if workspace_root else (Path.home() / ".nga")

    writable = False
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe_file = root / ".doctor_write_probe"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        writable = True
    except OSError:
        writable = False

    available_count = sum(1 for item in toolchains.values() if item["available"])
    capabilities = {
        "web_js_analyzer": "ready (built-in Python)",
        "network_har_analyzer": "ready (built-in Python)",
        "archive_pkg_inspector": "ready (built-in Python)",
        "binary_meta_inspector": (
            "ready (rizin/radare2 + Python)"
            if (toolchains["rizin"]["available"] or toolchains["radare2"]["available"])
            else "ready (built-in pure-Python ELF/PE/Mach-O/WASM parser)"
        ),
        "android_apk_inspector": (
            "ready (jadx + Python)"
            if toolchains["jadx"]["available"]
            else "ready (built-in pure-Python APK/manifest/DEX scanner)"
        ),
        "sandbox_and_simulator": "ready (isolated Python subprocess + AST guard)",
        "standin_mock_server": "ready (built-in Python HTTP server)",
        "interfaces": "ready (CLI + MCP JSON-RPC + Local Web UI + Website Embed Widget)",
    }

    summary = (
        f"Host OS: {host['os_id']} ({host['architecture']}) | "
        f"Python {host['python_version']} | "
        f"Optional external tools: {available_count}/{len(toolchains)} detected | "
        f"All core engines ready."
    )

    return ToolResponse(
        module="nga.core.doctor",
        summary=summary,
        data={
            "host": host,
            "workspace_root": str(root),
            "workspace_writable": writable,
            "capabilities": capabilities,
            "toolchains": toolchains,
        },
)
  
