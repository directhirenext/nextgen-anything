"""Zero-dependency Telegram Bot API bridge connecting messaging commands to the autonomous agent."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import uuid

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.builder.brief_gen import generate_architecture_brief
from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.security import redact_secrets
from nga.runtime.simulator import SimulationGate


def _parse_slash_command(text: str) -> tuple[str, str]:
    """Split `/cmd@bot arg1 arg2` into normalized (`/cmd`, `arg1 arg2`)."""
    stripped = str(text or "").strip()
    if not stripped.startswith("/"):
        return "", stripped
    head, _, rest = stripped.partition(" ")
    cmd_only = head.split("@", 1)[0].lower().strip()
    return cmd_only, rest.strip()


class TelegramBotBridge:
    """Secure Telegram Bot API connector with chat allowlist, persisted offset, and sandbox checks."""

    def __init__(
        self,
        bot_token: str | None = None,
        allowed_chat_ids: list[int | str] | None = None,
        agent: AutonomousIntentAgent | None = None,
        simulator: SimulationGate | None = None,
        api_base: str = "https://api.telegram.org",
        timeout: float = 25.0,
        state_path: Path | str | None = None,
        require_allowlist: bool = False,
    ) -> None:
        raw_token = bot_token if bot_token is not None else os.environ.get("NGA_TELEGRAM_TOKEN", "")
        self.bot_token = str(raw_token or "").strip()
        self.api_base = str(api_base or "https://api.telegram.org").rstrip("/")
        self.timeout = max(5.0, float(timeout))
        self.agent = agent if agent is not None else AutonomousIntentAgent()
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.require_allowlist = bool(require_allowlist)

        env_allowed = os.environ.get("NGA_TELEGRAM_ALLOWED_CHATS", "")
        combined_ids: list[Any] = list(allowed_chat_ids or [])
        if not combined_ids and env_allowed.strip():
            combined_ids = [part.strip() for part in env_allowed.split(",") if part.strip()]

        self.allowed_chat_ids: set[str] = {
            str(cid).strip() for cid in combined_ids if str(cid).strip()
        }
        self.state_path = Path(state_path) if state_path is not None else None
        self._last_update_id: int = self._load_persisted_offset()

    def _load_persisted_offset(self) -> int:
        if self.state_path is None or not self.state_path.exists():
            return 0
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return max(0, int(raw.get("last_update_id", 0) or 0))
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        return 0

    def _save_persisted_offset(self) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.state_path.parent / f".{self.state_path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
            tmp_path.write_text(json.dumps({"last_update_id": self._last_update_id}, indent=2), encoding="utf-8")
            tmp_path.replace(self.state_path)
        except OSError:
            pass

    def _sanitize_error_text(self, raw_text: str) -> str:
        masked = str(raw_text or "")
        if self.bot_token:
            masked = masked.replace(self.bot_token, "[REDACTED_TELEGRAM_TOKEN]")
        return redact_secrets(masked)

    def _call_telegram_api(self, method: str, payload: dict[str, Any] | None = None) -> dict[str, Any] | NgaError:
        """Invoke a Telegram Bot API HTTPS method safely with secret redaction on errors."""
        if not self.bot_token:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.telegram_bridge",
                message="Telegram bot token is not configured.",
                recoverable=True,
                suggested_fix="Set NGA_TELEGRAM_TOKEN environment variable or pass bot_token.",
            )

        parsed_base = urlparse(self.api_base)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.telegram_bridge",
                message="Invalid Telegram api_base URL; only http:// or https:// is allowed.",
                recoverable=True,
            )

        url = f"{self.api_base}/bot{self.bot_token}/{method}"
        body_bytes = json.dumps(payload or {}, default=str).encode("utf-8")
        req = Request(
            url=url,
            data=body_bytes,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and parsed.get("ok"):
                    return parsed
                desc = (
                    self._sanitize_error_text(str(parsed.get("description", "Telegram API error")))
                    if isinstance(parsed, dict)
                    else "Invalid response"
                )
                return NgaError(
                    error_code=ErrorCode.EXECUTION_FAILED.value,
                    module="nga.aaire.telegram_bridge",
                    message=f"Telegram API '{method}' failed: {desc}",
                    recoverable=True,
                )
        except HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read(1024).decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            code = ErrorCode.AUTH_ERROR.value if exc.code in {401, 403} else ErrorCode.EXECUTION_FAILED.value
            return NgaError(
                error_code=code,
                module="nga.aaire.telegram_bridge",
                message=self._sanitize_error_text(f"Telegram HTTP {exc.code} on '{method}': {err_body or exc.reason}"),
                recoverable=exc.code not in {401, 403},
            )
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return NgaError(
                error_code=ErrorCode.NETWORK_ERROR.value,
                module="nga.aaire.telegram_bridge",
                message=self._sanitize_error_text(f"Telegram request '{method}' failed: {exc}"),
                recoverable=True,
            )

    def send_message(self, chat_id: int | str, text: str) -> dict[str, Any] | NgaError:
        """Send a safe, redacted text reply to a Telegram chat."""
        safe_text = self._sanitize_error_text(str(text or "")).strip()[:4000]
        if not safe_text:
            safe_text = "(empty response)"
        return self._call_telegram_api(
            "sendMessage",
            {
                "chat_id": str(chat_id),
                "text": safe_text,
            },
        )

    def process_update(self, update: dict[str, Any]) -> ToolResponse | NgaError:
        """Handle a single incoming Telegram update dictionary deterministically."""
        if not isinstance(update, dict):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.telegram_bridge",
                message="Telegram update payload must be a JSON object.",
                recoverable=True,
            )

        msg = update.get("message") or update.get("edited_message")
        if not isinstance(msg, dict):
            return ToolResponse(
                module="nga.aaire.telegram_bridge",
                summary="Ignored non-message update.",
                data={"handled": False},
            )

        chat = msg.get("chat") if isinstance(msg.get("chat"), dict) else {}
        chat_id = str(chat.get("id", "")).strip()
        if not chat_id:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.telegram_bridge",
                message="Incoming message missing chat.id.",
                recoverable=True,
            )

        if self.require_allowlist and not self.allowed_chat_ids:
            return NgaError(
                error_code=ErrorCode.SANDBOX_VIOLATION.value,
                module="nga.aaire.telegram_bridge",
                message="Telegram bridge requires explicit allowed_chat_ids when require_allowlist=True.",
                recoverable=False,
                suggested_fix="Configure allowed_chat_ids or NGA_TELEGRAM_ALLOWED_CHATS.",
            )

        if self.allowed_chat_ids and chat_id not in self.allowed_chat_ids:
            return NgaError(
                error_code=ErrorCode.SANDBOX_VIOLATION.value,
                module="nga.aaire.telegram_bridge",
                message=f"Unauthorized Telegram chat_id blocked: {chat_id}",
                recoverable=False,
                suggested_fix="Add trusted chat_id to allowed_chat_ids.",
            )

        raw_text = str(msg.get("text", "")).strip()
        if not raw_text:
            return ToolResponse(
                module="nga.aaire.telegram_bridge",
                summary="Ignored message without text content.",
                data={"handled": False, "chat_id": chat_id},
            )

        reply_text = self._route_command(raw_text)
        return ToolResponse(
            module="nga.aaire.telegram_bridge",
            summary=f"Processed message from chat {chat_id}.",
            data={
                "handled": True,
                "chat_id": chat_id,
                "reply_text": reply_text,
            },
        )

    def _route_command(self, text: str) -> str:
        """Route slash commands or natural-language goals to local subsystems."""
        cmd, arg = _parse_slash_command(text)

        if cmd in {"/start", "/help"}:
            return (
                "NextGen-Anything (nga) Autonomous Bridge Ready.\n"
                "Commands:\n"
                "/doctor - Check OS, Python, SQLite & tool readiness\n"
                "/brief <target> - Generate clean-room architecture brief\n"
                "/recall <query> - Search memory vault\n"
                "/sim <python_code> - Run Python snippet in sandbox\n"
                "Or send any natural-language goal for the autonomous agent."
            )

        if cmd in {"/doctor", "/status"}:
            doc = run_environment_doctor()
            os_name = doc.data.get("os_platform") or doc.data.get("host", {}).get("os_id", "unknown")
            py_ver = doc.data.get("python_version") or doc.data.get("host", {}).get("python_version", "unknown")
            return f"[OK] {doc.summary}\nOS: {os_name} | Python: {py_ver}"

        if cmd == "/brief":
            label = redact_secrets(arg).strip() or "telegram_target"
            brief = generate_architecture_brief(target_label=label, target_kind="web")
            return f"[BRIEF] {brief.summary}"

        if cmd == "/recall":
            query = redact_secrets(arg).strip()
            hits = self.agent.vault.retrieve(query, namespace=self.agent.namespace, limit=3)
            if not hits:
                return "No matching records found in memory vault."
            lines = [f"- {h['title']}: {h['body'][:140]}" for h in hits]
            return "Recalled memories:\n" + "\n".join(lines)

        if cmd in {"/sim", "/simulate"}:
            if not arg:
                return "[SIM ERROR] Provide Python code after /sim."
            rep = self.simulator.simulate_crafted_python(code=arg, target_label="telegram_sim")
            if isinstance(rep, NgaError):
                return f"[SIM ERROR] {rep.message}"
            return f"[SIM {rep.status.value}] ({rep.duration_ms}ms)\n{rep.stdout_preview or rep.stderr_preview}"

        cleaned_goal = redact_secrets(text).strip()
        turn = self.agent.run_turn(prompt=cleaned_goal, target_label="telegram_turn")
        if isinstance(turn, NgaError):
            return f"[AGENT ERROR] {turn.message}"
        return turn.summary

    def poll_once(self, limit: int = 10) -> list[dict[str, Any]] | NgaError:
        """Fetch and process one batch of updates via Telegram getUpdates."""
        res = self._call_telegram_api(
            "getUpdates",
            {
                "offset": self._last_update_id + 1,
                "limit": max(1, min(50, int(limit))),
                "timeout": 0,
            },
        )
        if isinstance(res, NgaError):
            return res

        updates = res.get("result") if isinstance(res.get("result"), list) else []
        processed: list[dict[str, Any]] = []
        offset_advanced = False

        for upd in updates:
            if not isinstance(upd, dict):
                continue
            try:
                uid = int(upd.get("update_id", 0) or 0)
            except (TypeError, ValueError):
                uid = 0
            if uid > self._last_update_id:
                self._last_update_id = uid
                offset_advanced = True

            outcome = self.process_update(upd)
            out_dict = outcome.to_dict()
            if not isinstance(outcome, NgaError) and outcome.data.get("handled"):
                cid = outcome.data.get("chat_id")
                rtext = outcome.data.get("reply_text", "")
                if cid and rtext:
                    send_res = self.send_message(cid, rtext)
                    out_dict["reply_sent"] = not isinstance(send_res, NgaError)
                    if isinstance(send_res, NgaError):
                        out_dict["reply_error"] = send_res.message
            processed.append(out_dict)

        if offset_advanced:
            self._save_persisted_offset()

        return processed
                    
