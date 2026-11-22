"""Zero-dependency Telegram Bot API bridge connecting messaging commands to the autonomous agent."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.builder.brief_gen import generate_architecture_brief
from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.security import redact_secrets
from nga.runtime.simulator import SimulationGate


class TelegramBotBridge:
    """Secure Telegram Bot API connector with chat allowlist, command routing, and sandbox checks."""

    def __init__(
        self,
        bot_token: str | None = None,
        allowed_chat_ids: list[int | str] | None = None,
        agent: AutonomousIntentAgent | None = None,
        simulator: SimulationGate | None = None,
        api_base: str = "https://api.telegram.org",
        timeout: float = 25.0,
    ) -> None:
        raw_token = bot_token if bot_token is not None else os.environ.get("NGA_TELEGRAM_TOKEN", "")
        self.bot_token = str(raw_token or "").strip()
        self.api_base = str(api_base or "https://api.telegram.org").rstrip("/")
        self.timeout = max(5.0, float(timeout))
        self.agent = agent if agent is not None else AutonomousIntentAgent()
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.allowed_chat_ids: set[str] = {
            str(cid).strip() for cid in (allowed_chat_ids or []) if str(cid).strip()
        }
        self._last_update_id: int = 0

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
                desc = redact_secrets(str(parsed.get("description", "Telegram API error"))) if isinstance(parsed, dict) else "Invalid response"
                return NgaError(
                    error_code=ErrorCode.EXECUTION_FAILED.value,
                    module="nga.aaire.telegram_bridge",
                    message=f"Telegram API '{method}' failed: {desc}",
                    recoverable=True,
                )
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return NgaError(
                error_code=ErrorCode.EXECUTION_FAILED.value,
                module="nga.aaire.telegram_bridge",
                message=redact_secrets(f"Telegram request '{method}' failed: {exc}"),
                recoverable=True,
            )

    def send_message(self, chat_id: int | str, text: str) -> dict[str, Any] | NgaError:
        """Send a safe, redacted text reply to a Telegram chat."""
        safe_text = redact_secrets(str(text or "")).strip()[:4000]
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
        cleaned = redact_secrets(text).strip()

        if cleaned.startswith("/doctor") or cleaned.startswith("/status"):
            doc = run_environment_doctor()
            return f"[OK] {doc.summary}\nOS: {doc.data.get('os_platform')} | Python: {doc.data.get('python_version')}"

        if cleaned.startswith("/brief"):
            label = cleaned.partition(" ")[2].strip() or "telegram_target"
            brief = generate_architecture_brief(target_label=label, target_kind="web")
            return f"[BRIEF] {brief.summary}"

        if cleaned.startswith("/recall"):
            query = cleaned.partition(" ")[2].strip()
            hits = self.agent.vault.retrieve(query, namespace=self.agent.namespace, limit=3)
            if not hits:
                return "No matching records found in memory vault."
            lines = [f"- {h['title']}: {h['body'][:140]}" for h in hits]
            return "Recalled memories:\n" + "\n".join(lines)

        if cleaned.startswith("/sim"):
            code = cleaned.partition(" ")[2].strip()
            rep = self.simulator.simulate_crafted_python(code=code, target_label="telegram_sim")
            if isinstance(rep, NgaError):
                return f"[SIM ERROR] {rep.message}"
            return f"[SIM {rep.status.value}] ({rep.duration_ms}ms)\n{rep.stdout_preview or rep.stderr_preview}"

        turn = self.agent.run_turn(prompt=cleaned, target_label="telegram_turn")
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
        for upd in updates:
            if not isinstance(upd, dict):
                continue
            uid = int(upd.get("update_id", 0) or 0)
            if uid > self._last_update_id:
                self._last_update_id = uid
            outcome = self.process_update(upd)
            out_dict = outcome.to_dict()
            processed.append(out_dict)
            if not isinstance(outcome, NgaError) and outcome.data.get("handled"):
                cid = outcome.data.get("chat_id")
                rtext = outcome.data.get("reply_text", "")
                if cid and rtext:
                    self.send_message(cid, rtext)

        return processed
      
