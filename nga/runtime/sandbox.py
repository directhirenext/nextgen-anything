"""Isolated execution sandbox with AST validation, path containment, timeouts, and process cleanup."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
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

_SAFE_HOST_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "PREFIX",
    "LD_LIBRARY_PATH",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
)

_SBX_PATH_RE = re.compile(r"(?:[A-Za-z]:)?(?:[/\\][^\s\"':,)]*sbx_[a-f0-9]+[^\s\"':,)]*|/tmp/[^\s\"':,)]+)", re.IGNORECASE)
_SBX_FILE_RE = re.compile(r'File\s+"[^"]+",\s+line\s+\d+', re.IGNORECASE)
_ATTEMPT_SUFFIX_RE = re.compile(r"#attempt\d+$", re.IGNORECASE)


def _normalize_err_for_sig(text: str) -> str:
    cleaned = _SBX_FILE_RE.sub('File "<sandbox>", line N', str(text or ""))
    cleaned = _SBX_PATH_RE.sub("<sandbox>", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _read_stream_bounded(stream: Any, max_bytes: int, out_bucket: list[str]) -> None:
    """Drain a subprocess pipe up to `max_bytes` to prevent memory exhaustion on print floods."""
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            data = stream.read(4096)
            if not data:
                break
            raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
            if total < max_bytes:
                remaining = max_bytes - total
                chunks.append(raw[:remaining])
            total += len(raw)
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
    out_bucket.append(b"".join(chunks).decode("utf-8", errors="replace"))


class ExecutionSandbox:
    """Ephemeral isolated workspace runner for validating code and commands before output."""

    def __init__(
        self,
        base_sandbox_dir: Path | None = None,
        timeout_seconds: float = 15.0,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        keep_failed_runs: bool = True,
        max_retained_runs: int = 20,
    ) -> None:
        self.base_sandbox_dir = Path(base_sandbox_dir) if base_sandbox_dir else (Path.home() / ".nga" / "sandboxes")
        self.base_sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = max(1.0, min(120.0, float(timeout_seconds)))
        self.max_output_chars = max(512, int(max_output_chars))
        self.keep_failed_runs = bool(keep_failed_runs)
        self.max_retained_runs = max(1, int(max_retained_runs))

    def _build_restricted_env(self, sandbox_dir: Path) -> dict[str, str]:
        """Construct a cross-OS sanitized environment dictionary without leaking host secrets."""
        env: dict[str, str] = {
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(sandbox_dir),
            "USERPROFILE": str(sandbox_dir),
            "TMPDIR": str(sandbox_dir / "tmp"),
            "TEMP": str(sandbox_dir / "tmp"),
            "TMP": str(sandbox_dir / "tmp"),
        }
        for key in _SAFE_HOST_ENV_KEYS:
            val = os.environ.get(key)
            if val:
                env[key] = val
        return env

    def _cleanup_dir(self, target_dir: Path) -> None:
        """Remove an ephemeral sandbox folder safely if inside base_sandbox_dir."""
        ok, resolved = safe_resolve_path(self.base_sandbox_dir, target_dir)
        if ok and isinstance(resolved, Path) and resolved != self.base_sandbox_dir.resolve() and resolved.exists():
            shutil.rmtree(resolved, ignore_errors=True)

    def _prune_old_runs(self) -> None:
        """Keep disk usage bounded by removing oldest retained `sbx_*` directories."""
        try:
            runs = [
                p for p in self.base_sandbox_dir.iterdir()
                if p.is_dir() and p.name.startswith("sbx_")
            ]
            if len(runs) <= self.max_retained_runs:
                return
            runs.sort(key=lambda p: p.stat().st_mtime)
            for old_dir in runs[: len(runs) - self.max_retained_runs]:
                self._cleanup_dir(old_dir)
        except OSError:
            pass

    @staticmethod
    def _terminate_process_tree(proc: subprocess.Popen[bytes]) -> None:
        """Safely terminate process and process group across Linux, Android Termux, macOS, and Windows."""
        if os.name == "posix":
            try:
                os.killpg(proc.pid, 9)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        elif os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except Exception:
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
        """Validate Python code and helper files via AST guard, run in isolated sandbox, and return report."""
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

        all_findings: list[str] = []
        ast_check = check_python_ast_safety(code)
        if not ast_check.get("safe", False):
            for item in ast_check.get("findings", []):
                issue = item.get("issue", item) if isinstance(item, dict) else item
                all_findings.append(f"ast_guard:{issue}")

        if files:
            for rel_name, content in files.items():
                if str(rel_name).lower().endswith(".py"):
                    sub_check = check_python_ast_safety(str(content))
                    if not sub_check.get("safe", False):
                        for item in sub_check.get("findings", []):
                            issue = item.get("issue", item) if isinstance(item, dict) else item
                            all_findings.append(f"ast_guard({rel_name}):{issue}")

        if all_findings:
            sig = compute_sha256_text(f"AST_BLOCKED:{'|'.join(all_findings)}")[:16]
            report = SimulationReport(
                run_id=run_id,
                target_label=target_label,
                status=SimulationStatus.BLOCKED,
                checks_passed=[],
                checks_failed=all_findings,
                stdout_preview="",
                stderr_preview=redact_secrets("; ".join(all_findings)),
                error_signature=sig,
                duration_ms=0,
                created_at=utc_now_iso(),
            )
            if not self.keep_failed_runs:
                self._cleanup_dir(run_dir)
            else:
                self._prune_old_runs()
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

        py_flags = ["-s", "-E"] if files else ["-I"]
        popen_kwargs: dict[str, Any] = {
            "args": [sys.executable, *py_flags, str(entry_file)],
            "cwd": str(run_dir),
            "env": self._build_restricted_env(run_dir),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        byte_cap = max(self.max_output_chars * 4, 262_144)
        out_bucket: list[str] = []
        err_bucket: list[str] = []

        try:
            proc = subprocess.Popen(**popen_kwargs)
            t_out = threading.Thread(target=_read_stream_bounded, args=(proc.stdout, byte_cap, out_bucket), daemon=True)
            t_err = threading.Thread(target=_read_stream_bounded, args=(proc.stderr, byte_cap, err_bucket), daemon=True)
            t_out.start()
            t_err.start()
            try:
                proc.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                self._terminate_process_tree(proc)
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                duration_ms = int((time.monotonic() - start_perf) * 1000)
                base_label = _ATTEMPT_SUFFIX_RE.sub("", str(target_label))
                err_sig = compute_sha256_text(f"TIMEOUT:{base_label}:{self.timeout_seconds}")[:16]
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
                else:
                    self._prune_old_runs()
                return report

            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)
        except OSError as exc:
            self._cleanup_dir(run_dir)
            return NgaError(
                error_code=ErrorCode.SANDBOX_VIOLATION.value,
                module="nga.runtime.sandbox",
                message=f"Failed starting sandbox process: {exc}",
                recoverable=True,
                suggested_fix="Verify Python interpreter permissions and sandbox directory access.",
            )

        duration_ms = int((time.monotonic() - start_perf) * 1000)
        stdout_raw = out_bucket[0] if out_bucket else ""
        stderr_raw = err_bucket[0] if err_bucket else ""
        stdout_clean = redact_secrets(apply_output_budget(stdout_raw, max_chars=self.max_output_chars)["content"])
        stderr_clean = redact_secrets(apply_output_budget(stderr_raw, max_chars=self.max_output_chars)["content"])

        if proc.returncode == 0:
            checks_passed.append("exit_code_zero")
            status = SimulationStatus.SIMULATION_PASSED
            err_sig = ""
            self._cleanup_dir(run_dir)
        else:
            checks_failed.append(f"nonzero_exit_code_{proc.returncode}")
            status = SimulationStatus.SIMULATION_FAILED
            norm_err = _normalize_err_for_sig(stderr_clean[:400])
            err_sig = compute_sha256_text(f"EXIT:{proc.returncode}:{norm_err}")[:16]
            if not self.keep_failed_runs:
                self._cleanup_dir(run_dir)
            else:
                self._prune_old_runs()

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
                
