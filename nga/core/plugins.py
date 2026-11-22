"""Language-agnostic plugin registry and execution runner using JSON over stdin/stdout."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    redact_secrets,
    safe_resolve_path,
)

_BLOCKED_SHELL_BINARIES = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "csh",
    "tcsh",
    "ksh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}

_SAFE_ENV_KEYS = (
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
    "WINDIR",
)


def default_plugins_dir() -> Path:
    """Return default user plugins directory (~/.nga/plugins)."""
    return Path.home() / ".nga" / "plugins"


def _build_plugin_env(plugin_dir: Path) -> dict[str, str]:
    """Build a minimal cross-OS runtime environment without leaking host secrets."""
    env: dict[str, str] = {
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "NGA_PLUGIN_DIR": str(plugin_dir),
    }
    for key in _SAFE_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None and val != "":
            env[key] = val
    return env


def _has_unsafe_arg_traversal(arg: str, plugin_dir: Path) -> bool:
    """Reject control characters or relative path traversal escaping plugin_dir."""
    if "\x00" in arg:
        return True
    cleaned = arg.replace("\\", "/")
    if ".." in cleaned.split("/"):
        return True
    if cleaned.startswith(("./", "../")):
        ok_rel, _ = safe_resolve_path(plugin_dir, cleaned)
        if not ok_rel:
            return True
    return False


class PluginRegistry:
    """Discovers and executes external plugins in any language (Python, Rust, Go, Node, etc.)."""

    def __init__(
        self,
        plugins_dir: Path | str | None = None,
        timeout_seconds: float = 30.0,
        allow_shell_plugins: bool = False,
    ) -> None:
        self.plugins_dir = Path(plugins_dir) if plugins_dir is not None else default_plugins_dir()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.allow_shell_plugins = bool(allow_shell_plugins)

    def _resolve_command_executable(self, raw_exe: str, plugin_dir: Path) -> tuple[str | None, bool, str]:
        """Resolve plugin executable safely, blocking raw shells unless explicitly permitted."""
        exe_str = str(raw_exe or "").strip()
        if not exe_str or "\x00" in exe_str:
            return None, False, "Empty or invalid executable name."

        base_name = Path(exe_str).name.lower()
        if not self.allow_shell_plugins and base_name in _BLOCKED_SHELL_BINARIES:
            return None, False, f"Direct shell executable blocked: {base_name}"

        if exe_str in {"python", "python3"}:
            return sys.executable, True, ""

        # Prefer local executable strictly contained inside plugin_dir
        if "/" in exe_str or "\\" in exe_str or exe_str.startswith("."):
            ok_rel, resolved_path = safe_resolve_path(plugin_dir, exe_str)
            if ok_rel and isinstance(resolved_path, Path) and resolved_path.is_file():
                return str(resolved_path), True, ""
            return None, False, f"Local plugin executable missing or escapes plugin_dir: {exe_str}"

        resolved_which = shutil.which(exe_str)
        if resolved_which:
            return resolved_which, True, ""

        ok_rel, resolved_path = safe_resolve_path(plugin_dir, exe_str)
        if ok_rel and isinstance(resolved_path, Path) and resolved_path.is_file():
            return str(resolved_path), True, ""

        return None, False, f"Executable not found on PATH or inside plugin_dir: {exe_str}"

    def _parse_manifest_dir(self, entry: Path) -> dict[str, Any] | None:
        """Read and validate a single plugin directory containing `plugin.json`."""
        manifest_path = entry / "plugin.json"
        if not manifest_path.is_file():
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(manifest, dict):
            return None

        name = str(manifest.get("name", entry.name)).strip()
        raw_cmd = manifest.get("command")
        if not name or not isinstance(raw_cmd, list) or not raw_cmd:
            return None

        cmd = [str(part) for part in raw_cmd]
        resolved_exe, exe_ok, exe_reason = self._resolve_command_executable(cmd[0], entry)

        unsafe_arg = next((a for a in cmd[1:] if _has_unsafe_arg_traversal(a, entry)), None)
        if unsafe_arg is not None:
            exe_ok = False
            exe_reason = f"Unsafe plugin command argument blocked: {unsafe_arg}"

        return {
            "name": name,
            "version": str(manifest.get("version", "0.1.0")),
            "language": str(manifest.get("language", "polyglot")),
            "description": str(manifest.get("description", "")),
            "plugin_dir": str(entry.resolve()),
            "command": cmd,
            "executable_found": exe_ok and resolved_exe is not None,
            "resolved_executable": resolved_exe,
            "validation_error": exe_reason if not exe_ok else "",
        }

    def discover(self) -> list[dict[str, Any]]:
        """Scan plugin subfolders for valid `plugin.json` manifests."""
        discovered: list[dict[str, Any]] = []
        if not self.plugins_dir.exists():
            return discovered

        for entry in sorted(self.plugins_dir.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir():
                continue
            parsed = self._parse_manifest_dir(entry)
            if parsed is not None:
                discovered.append(parsed)
        return discovered

    def _find_plugin(self, clean_name: str) -> dict[str, Any] | None:
        """Locate a plugin by direct folder match first, falling back to full scan."""
        ok_direct, direct_dir = safe_resolve_path(self.plugins_dir, clean_name)
        if ok_direct and isinstance(direct_dir, Path) and direct_dir.is_dir():
            parsed = self._parse_manifest_dir(direct_dir)
            if parsed is not None and parsed["name"] == clean_name:
                return parsed
        return next((p for p in self.discover() if p["name"] == clean_name), None)

    def invoke(
        self,
        plugin_name: str,
        action: str = "run",
        payload: dict[str, Any] | None = None,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    ) -> ToolResponse | NgaError:
        """Execute a discovered plugin by sending JSON via stdin and reading redacted budgeted stdout."""
        clean_name = str(plugin_name or "").strip()
        if not clean_name:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.core.plugins",
                message="Plugin name cannot be empty.",
                recoverable=True,
                suggested_fix="Pass a valid registered plugin name.",
            )

        plugin_info = self._find_plugin(clean_name)
        if plugin_info is None:
            return NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.core.plugins",
                message=f"Plugin '{clean_name}' not found in {self.plugins_dir}.",
                recoverable=True,
                suggested_fix="Add a folder with a valid plugin.json manifest under ~/.nga/plugins/.",
            )

        if not plugin_info["executable_found"] or not plugin_info["resolved_executable"]:
            err_detail = plugin_info.get("validation_error") or f"Executable unavailable: {plugin_info['command']}"
            code = (
                ErrorCode.SANDBOX_VIOLATION.value
                if "blocked" in err_detail.lower() or "escapes" in err_detail.lower()
                else ErrorCode.TOOL_UNAVAILABLE.value
            )
            return NgaError(
                error_code=code,
                module="nga.core.plugins",
                message=f"Plugin '{clean_name}' cannot run: {err_detail}",
                recoverable=True,
                suggested_fix="Fix command path in plugin.json or install the required runtime.",
            )

        cmd_args = [str(plugin_info["resolved_executable"]), *plugin_info["command"][1:]]
        request_obj = {
            "plugin": clean_name,
            "action": str(action or "run").strip() or "run",
            "payload": payload if isinstance(payload, dict) else {},
        }
        stdin_text = json.dumps(request_obj, default=str) + "\n"
        plugin_dir = Path(plugin_info["plugin_dir"])
        clean_env = _build_plugin_env(plugin_dir)

        start_ts = time.monotonic()
        try:
            proc = subprocess.run(
                cmd_args,
                input=stdin_text,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                cwd=str(plugin_dir),
                env=clean_env,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return NgaError(
                error_code=ErrorCode.TIMEOUT.value,
                module="nga.core.plugins",
                message=f"Plugin '{clean_name}' timed out after {self.timeout_seconds}s.",
                recoverable=True,
                suggested_fix="Optimize plugin execution or increase timeout_seconds.",
            )
        except OSError as exc:
            return NgaError(
                error_code=ErrorCode.PLUGIN_ERROR.value,
                module="nga.core.plugins",
                message=redact_secrets(f"Failed starting plugin '{clean_name}': {exc}"),
                recoverable=True,
                suggested_fix="Verify executable permissions (+x) and runtime availability.",
            )

        elapsed_ms = int((time.monotonic() - start_ts) * 1000)
        if proc.returncode != 0:
            stderr_clean = redact_secrets(proc.stderr or "")
            stderr_bounded = apply_output_budget(stderr_clean, max_chars=2000)
            return NgaError(
                error_code=ErrorCode.PLUGIN_ERROR.value,
                module="nga.core.plugins",
                message=f"Plugin '{clean_name}' exited with code {proc.returncode}.",
                recoverable=True,
                suggested_fix="Inspect plugin stderr and verify valid JSON output on stdout.",
                details={
                    "returncode": proc.returncode,
                    "stderr_preview": stderr_bounded["content"],
                    "duration_ms": elapsed_ms,
                },
            )

        safe_cap = max(1, int(max_output_chars))
        redacted_stdout = redact_secrets((proc.stdout or "").strip())
        truncated = False
        next_offset: int | None = None
        parsed_stdout: Any = None

        if redacted_stdout:
            if len(redacted_stdout) > safe_cap:
                bounded = apply_output_budget(redacted_stdout, max_chars=safe_cap, offset=0)
                truncated = bool(bounded["truncated"])
                next_offset = bounded["next_offset"]
                parsed_stdout = {
                    "raw_stdout": bounded["content"],
                    "total_chars": bounded["total_chars"],
                    "truncated": truncated,
                }
            else:
                try:
                    parsed_stdout = json.loads(redacted_stdout)
                except json.JSONDecodeError:
                    parsed_stdout = {"raw_stdout": redacted_stdout, "truncated": False}

        return ToolResponse(
            module="nga.core.plugins",
            summary=f"Plugin '{clean_name}' ({request_obj['action']}) completed in {elapsed_ms}ms.",
            truncated=truncated,
            next_offset=next_offset,
            data={
                "plugin": clean_name,
                "action": request_obj["action"],
                "duration_ms": elapsed_ms,
                "output": parsed_stdout,
            },
            )
            
