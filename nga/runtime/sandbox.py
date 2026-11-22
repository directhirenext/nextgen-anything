"""Isolated execution sandbox with AST validation, path containment, timeouts, and process cleanup."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any
import uuid

from nga.core.contracts import (
    ErrorCode,
    NgaError,
    SimulationReport,
    SimulationStatus,
    utc_now_iso,
)
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    check_python_ast_safety,
    compute_sha256_text,
    redact_secrets,
    safe_resolve_path,
)


class ExecutionSandbox:
    """Ephemeral isolated workspace runner for validating code and commands before output."""

    def __init__(
        self,
        base_sandbox_dir: Path | None = None,
        timeout_seconds: float = 15.0,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        keep_failed_runs: bool = True,
    ) -> None:
        self.base_sandbox_dir = Path(base_sandbox_dir) if base_sandbox_dir else (Path.home() / ".nga" / "sandboxes")
        self.base_sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = max(1.0, min(120.0, float(timeout_seconds)))
        self.max_output_chars = max(512, int(max_output_chars))
        self.keep_failed_runs = bool(keep_failed_runs)

    def _build_restricted_env(self, sandbox_dir: Path) -> dict[str, str]:
        """Construct a sanitized environment dictionary without leaking host secrets."""
        return {
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(sandbox_dir),
            "TMPDIR": str(sandbox_dir / "tmp"),
            "TEMP": str(sandbox_dir / "tmp"),
            "TMP": str(sandbox_dir / "tmp"),
        }

    def _cleanup_dir(self, target_dir: Path) -> None:
        """Remove an ephemeral sandbox folder safely if inside base_sandbox_dir."""
        ok, resolved = safe_resolve_path(self.base_sandbox_dir, target_dir)
        if ok and isinstance(resolved, Path) and resolved != self.base_sandbox_dir.resolve() and resolved.exists():
            shutil.rmtree(resolved, ignore_errors=True)

    @staticmethod
    def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
        """Safely terminate process and process group across Linux, Android Termux, macOS, and Windows."""
        if os.name == "posix":
            try:
                os.killpg(proc.pid, 9)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    def run_python_snippet(
        self,
        code: str,
        target_label: str = "python_snippet",
        files: dict[str, str] | None = None,
    ) -> SimulationReport | NgaError:
        """Validate Python code via AST guard, run inside isolated sandbox folder, and return report."""
        if not isinstance(code, str) or not code.strip():
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.runtime.sandbox",
                message="Python code snippet cannot be empty.",
                recoverable=True,
                suggested_fix="Provide non-empty Python source code to test in the sandbox.",
            )

        run_id = f"sbx_{uuid.uuid4().hex[:12]}"
        run_dir = self.base_sandbox_dir / run_id
        tmp_dir = run_dir / "tmp"
        run_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        ast_check = check_python_ast_safety(code)
        if not ast_check.get("safe", False):
            findings = ast_check.get("findings", [])
            sig = compute_sha256_text(f"AST_BLOCKED:{findings}")[:16]
            report = SimulationReport(
                run_id=run_id,
                target_label=target_label,
                status=SimulationStatus.BLOCKED,
                checks_passed=[],
                checks_failed=[
                    f"ast_guard:{item.get('issue', item) if isinstance(item, dict) else item}"
                    for item in findings
                ],
                stdout_preview="",
                stderr_preview=redact_secrets(str(findings)),
                error_signature=sig,
                duration_ms=0,
                created_at=utc_now_iso(),
            )
            if not self.keep_failed_runs:
                self._cleanup_dir(run_dir)
            return report

        if files:
            for rel_name, content in files.items():
                ok_p, dest_p = safe_resolve_path(run_dir, rel_name)
                if not ok_p or not isinstance(dest_p, Path):
                    self._cleanup_dir(run_dir)
                    return NgaError(
                        error_code=ErrorCode.PATH_TRAVERSAL.value,
                        module="nga.runtime.sandbox",
                        message=f"Sandbox file path escaped run directory: {rel_name}",
                        recoverable=False,
                        suggested_fix="Keep all sandbox files relative to the sandbox directory.",
                    )
                dest_p.parent.mkdir(parents=True, exist_ok=True)
                dest_p.write_text(str(content), encoding="utf-8")

        entry_file = run_dir / "candidate_script.py"
        entry_file.write_text(code, encoding="utf-8")

        checks_passed: list[str] = ["ast_syntax_and_safety_check"]
        checks_failed: list[str] = []
        start_perf = time.monotonic()

        popen_kwargs: dict[str, Any] = {
            "args": [sys.executable, "-I", str(entry_file)],
            "cwd": str(run_dir),
            "env": self._build_restricted_env(run_dir),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(**popen_kwargs)
            try:
                stdout_raw, stderr_raw = proc.communicate(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                self._terminate_process_tree(proc)
                duration_ms = int((time.monotonic() - start_perf) * 1000)
                err_sig = compute_sha256_text(f"TIMEOUT:{target_label}:{self.timeout_seconds}")[:16]
                report = SimulationReport(
                    run_id=run_id,
                    target_label=target_label,
                    status=SimulationStatus.SIMULATION_FAILED,
                    checks_passed=checks_passed,
                    checks_failed=[f"execution_timeout_after_{self.timeout_seconds}s"],
                    stdout_preview="",
                    stderr_preview=f"Sandbox execution timed out after {self.timeout_seconds}s.",
                    error_signature=err_sig,
                    duration_ms=duration_ms,
                )
                if not self.keep_failed_runs:
                    self._cleanup_dir(run_dir)
                return report
        except OSError as exc:
            return NgaError(
                error_code=ErrorCode.SANDBOX_VIOLATION.value,
                module="nga.runtime.sandbox",
                message=f"Failed starting sandbox process: {exc}",
                recoverable=True,
                suggested_fix="Verify Python interpreter permissions and sandbox directory access.",
            )

        duration_ms = int((time.monotonic() - start_perf) * 1000)
        stdout_clean = redact_secrets(apply_output_budget(stdout_raw or "", max_chars=self.max_output_chars)["content"])
        stderr_clean = redact_secrets(apply_output_budget(stderr_raw or "", max_chars=self.max_output_chars)["content"])

        if proc.returncode == 0:
            checks_passed.append("exit_code_zero")
            status = SimulationStatus.SIMULATION_PASSED
            err_sig = ""
            self._cleanup_dir(run_dir)
        else:
            checks_failed.append(f"nonzero_exit_code_{proc.returncode}")
            status = SimulationStatus.SIMULATION_FAILED
            err_sig = compute_sha256_text(f"EXIT:{proc.returncode}:{stderr_clean[:400]}")[:16]
            if not self.keep_failed_runs:
                self._cleanup_dir(run_dir)

        return SimulationReport(
            run_id=run_id,
            target_label=target_label,
            status=status,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            stdout_preview=stdout_clean,
            stderr_preview=stderr_clean,
            error_signature=err_sig,
            duration_ms=duration_ms,
        )
        
