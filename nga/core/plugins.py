"""Language-agnostic plugin registry and execution runner using JSON over stdin/stdout."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.core.security import apply_output_budget, safe_resolve_path


def default_plugins_dir() -> Path:
    """Return default user plugins directory (~/.nga/plugins)."""
    return Path.home() / ".nga" / "plugins"


class PluginRegistry:
    """Discovers and executes external plugins in any language (Python, Rust, Go, Node, Shell)."""

    def __init__(self, plugins_dir: Path | None = None, timeout_seconds: float = 30.0) -> None:
        self.plugins_dir = Path(plugins_dir) if plugins_dir else default_plugins_dir()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = max(1.0, float(timeout_seconds))

    def discover(self) -> list[dict[str, Any]]:
        """Scan plugin subfolders for valid `plugin.json` manifests."""
        discovered: list[dict[str, Any]] = []
        if not self.plugins_dir.exists():
            return discovered

        for entry in sorted(self.plugins_dir.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "plugin.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    continue
                name = str(manifest.get("name", entry.name)).strip()
                cmd = manifest.get("command")
                if not name or not isinstance(cmd, list) or not cmd:
                    continue
                resolved_exe = shutil.which(str(cmd[0]))
                if resolved_exe is None:
                    ok_rel, resolved_path = safe_resolve_path(entry, str(cmd[0]))
                    if ok_rel and isinstance(resolved_path, Path) and resolved_path.is_file():
                        resolved_exe = str(resolved_path)

                discovered.append(
                    {
                        "name": name,
                        "version": str(manifest.get("version", "0.1.0")),
                        "language": str(manifest.get("language", "polyglot")),
                        "description": str(manifest.get("description", "")),
                        "plugin_dir": str(entry),
                        "command": [str(part) for part in cmd],
                        "executable_found": resolved_exe is not None,
                        "resolved_executable": resolved_exe,
                    }
                )
            except (OSError, json.JSONDecodeError):
                continue

        return discovered

    def invoke(
        self,
        plugin_name: str,
        action: str = "run",
        payload: dict[str, Any] | None = None,
        max_output_chars: int = 12000,
    ) -> ToolResponse | NgaError:
        """Execute a discovered plugin by sending JSON via stdin and reading JSON from stdout."""
        clean_name = str(plugin_name).strip()
        if not clean_name:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.core.plugins",
                message="Plugin name cannot be empty.",
                recoverable=True,
                suggested_fix="Pass a valid registered plugin name.",
            )

        plugin_info = next((p for p in self.discover() if p["name"] == clean_name), None)
        if plugin_info is None:
            return NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.core.plugins",
                message=f"Plugin '{clean_name}' not found in {self.plugins_dir}.",
                recoverable=True,
                suggested_fix="Add a folder with a valid plugin.json manifest under ~/.nga/plugins/.",
            )

        if not plugin_info["executable_found"]:
            return NgaError(
                error_code=ErrorCode.TOOL_UNAVAILABLE.value,
                module="nga.core.plugins",
                message=f"Plugin executable not found for '{clean_name}': {plugin_info['command']}",
                recoverable=True,
                suggested_fix="Install the required runtime/binary or fix command path in plugin.json.",
            )

        cmd_args = list(plugin_info["command"])
        if cmd_args[0] == plugin_info["command"][0] and plugin_info["resolved_executable"]:
            cmd_args[0] = str(plugin_info["resolved_executable"])

        request_obj = {
            "plugin": clean_name,
            "action": str(action).strip() or "run",
            "payload": payload or {},
        }
        stdin_text = json.dumps(request_obj, default=str) + "\n"

        clean_env = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONIOENCODING": "utf-8",
        }

        start_ts = time.monotonic()
        try:
            proc = subprocess.run(
                cmd_args,
                input=stdin_text,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                cwd=plugin_info["plugin_dir"],
                env=clean_env,
                timeout=self.timeout_seconds,
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
                message=f"Failed starting plugin '{clean_name}': {exc}",
                recoverable=True,
                suggested_fix="Verify executable permissions (+x) and runtime availability.",
            )

        elapsed_ms = int((time.monotonic() - start_ts) * 1000)
        if proc.returncode != 0:
            stderr_bounded = apply_output_budget(proc.stderr or "", max_chars=2000)
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

        stdout_text = (proc.stdout or "").strip()
        parsed_stdout: Any = None
        if stdout_text:
            try:
                parsed_stdout = json.loads(stdout_text)
            except json.JSONDecodeError:
                bounded = apply_output_budget(stdout_text, max_chars=max_output_chars)
                parsed_stdout = {"raw_stdout": bounded["content"], "truncated": bounded["truncated"]}

        return ToolResponse(
            module="nga.core.plugins",
            summary=f"Plugin '{clean_name}' ({action}) completed in {elapsed_ms}ms.",
            data={
                "plugin": clean_name,
                "action": action,
                "duration_ms": elapsed_ms,
                "output": parsed_stdout,
            },
  )
                  
