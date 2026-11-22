"""Universal zero-dependency LLM engine supporting any OpenAI-compatible, Ollama, Gemini, Anthropic, or plugin model."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from nga.core.contracts import ErrorCode, NgaError
from nga.core.plugins import PluginRegistry
from nga.core.security import redact_secrets


@dataclass
class UniversalLlmConfig:
    """Configuration for any LLM provider (free, open-source, paid, local, or custom plugin)."""

    base_url: str = ""
    model: str = ""
    api_key: str = ""
    protocol: str = "auto"  # auto | openai_compatible | ollama | gemini | anthropic | plugin
    plugin_name: str = ""
    temperature: float = 0.2
    max_tokens: int = 2048
    timeout_seconds: float = 45.0
    extra_headers: dict[str, str] | None = None

    @classmethod
    def from_env(cls) -> UniversalLlmConfig:
        """Load universal LLM settings from environment variables without hardcoding any single vendor."""
        base_url = (
            os.environ.get("NGA_LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("OLLAMA_HOST")
            or ""
        ).strip()
        model = (
            os.environ.get("NGA_LLM_MODEL")
            or os.environ.get("OPENAI_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or ""
        ).strip()
        api_key = (
            os.environ.get("NGA_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("OPENROUTER_API_KEY")
            or os.environ.get("GROQ_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or ""
        ).strip()
        protocol = str(os.environ.get("NGA_LLM_PROTOCOL", "auto") or "auto").strip().lower()
        plugin_name = str(os.environ.get("NGA_LLM_PLUGIN", "") or "").strip()

        raw_temp = os.environ.get("NGA_LLM_TEMPERATURE", "0.2")
        raw_max_tok = os.environ.get("NGA_LLM_MAX_TOKENS", "2048")
        raw_timeout = os.environ.get("NGA_LLM_TIMEOUT", "45.0")

        try:
            temp = max(0.0, min(2.0, float(raw_temp)))
        except ValueError:
            temp = 0.2
        try:
            max_tok = max(64, min(16384, int(raw_max_tok)))
        except ValueError:
            max_tok = 2048
        try:
            timeout = max(3.0, min(300.0, float(raw_timeout)))
        except ValueError:
            timeout = 45.0

        return cls(
            base_url=base_url,
            model=model,
            api_key=api_key,
            protocol=protocol,
            plugin_name=plugin_name,
            temperature=temp,
            max_tokens=max_tok,
            timeout_seconds=timeout,
        )


def _is_valid_http_endpoint(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


class UniversalLlmEngine:
    """Provider-agnostic completion client with automatic protocol detection and safe error handling."""

    def __init__(
        self,
        config: UniversalLlmConfig | None = None,
        plugin_registry: PluginRegistry | None = None,
    ) -> None:
        self.config = config if config is not None else UniversalLlmConfig.from_env()
        self.plugin_registry = plugin_registry

    def is_configured(self) -> bool:
        """Return True if an external endpoint, plugin, or provider key is configured."""
        cfg = self.config
        if cfg.plugin_name.strip():
            return True
        if _is_valid_http_endpoint(cfg.base_url):
            return True
        return bool(cfg.api_key.strip() and cfg.model.strip())

    def detect_protocol(self) -> str:
        """Resolve protocol mode ('openai_compatible', 'ollama', 'gemini', 'anthropic', 'plugin')."""
        proto = str(self.config.protocol or "auto").strip().lower()
        if proto != "auto":
            return proto
        if self.config.plugin_name.strip():
            return "plugin"
        low_url = self.config.base_url.lower()
        low_model = self.config.model.lower()
        if "generativelanguage.googleapis.com" in low_url or low_model.startswith("gemini"):
            return "gemini"
        if "api.anthropic.com" in low_url or low_model.startswith("claude"):
            return "anthropic"
        if ":11434" in low_url and not low_url.rstrip("/").endswith("/v1"):
            return "ollama"
        return "openai_compatible"

    def _post_json(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> dict[str, Any] | NgaError:
        if not _is_valid_http_endpoint(url):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.llm_engine",
                message=f"Invalid LLM endpoint URL: {redact_secrets(url)}",
                recoverable=True,
                suggested_fix="Set a valid http:// or https:// URL in base_url.",
            )

        body = json.dumps(payload, default=str).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "NextGen-Anything-AAIRE/0.1",
        }
        for k, v in headers.items():
            if k and v:
                req_headers[str(k)] = str(v)

        req = Request(url=url, data=body, headers=req_headers, method="POST")
        try:
            with urlopen(req, timeout=max(2.0, float(timeout_seconds))) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw_text)
                if isinstance(parsed, dict):
                    return parsed
                return {"raw": parsed}
        except HTTPError as exc:
            err_raw = ""
            try:
                err_raw = exc.read(2048).decode("utf-8", errors="replace")
            except Exception:
                err_raw = ""
            clean_msg = redact_secrets(f"LLM HTTP {exc.code} ({exc.reason}): {err_raw[:300]}")
            code = ErrorCode.AUTH_ERROR.value if exc.code in {401, 403} else ErrorCode.EXECUTION_FAILED.value
            return NgaError(
                error_code=code,
                module="nga.aaire.llm_engine",
                message=clean_msg,
                recoverable=exc.code not in {401, 403},
                suggested_fix="Verify LLM endpoint URL, API key/quota, or model identifier.",
            )
        except TimeoutError as exc:
            return NgaError(
                error_code=ErrorCode.TIMEOUT.value,
                module="nga.aaire.llm_engine",
                message=redact_secrets(f"LLM request timed out: {exc}"),
                recoverable=True,
                suggested_fix="Increase timeout_seconds or choose a faster/local model.",
            )
        except (URLError, OSError, json.JSONDecodeError) as exc:
            return NgaError(
                error_code=ErrorCode.NETWORK_ERROR.value,
                module="nga.aaire.llm_engine",
                message=redact_secrets(f"LLM transport error: {exc}"),
                recoverable=True,
                suggested_fix="Check network access, local server status (e.g. Ollama/vLLM/LM Studio), or URL.",
            )

    def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> dict[str, Any] | NgaError:
        """Send a prompt to any configured LLM or plugin and return {'text': ..., 'protocol': ..., 'model': ...}."""
        clean_prompt = str(prompt or "").strip()
        if not clean_prompt:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.llm_engine",
                message="LLM prompt cannot be empty.",
                recoverable=True,
            )

        cfg = self.config
        proto = self.detect_protocol()
        tok_limit = max(64, int(max_tokens if max_tokens is not None else cfg.max_tokens))
        temp_val = float(temperature if temperature is not None else cfg.temperature)
        sys_txt = str(system_prompt or "You are an autonomous software engineer and reverse-engineering architect.")

        if proto == "plugin":
            reg = self.plugin_registry if self.plugin_registry is not None else PluginRegistry()
            p_res = reg.invoke(
                plugin_name=cfg.plugin_name,
                action="llm_complete",
                payload={
                    "prompt": clean_prompt,
                    "system_prompt": sys_txt,
                    "model": cfg.model,
                    "temperature": temp_val,
                    "max_tokens": tok_limit,
                },
            )
            if isinstance(p_res, NgaError):
                return p_res
            out_obj = p_res.data.get("output") if isinstance(p_res.data, dict) else {}
            text_out = ""
            if isinstance(out_obj, dict):
                text_out = str(out_obj.get("text") or out_obj.get("response") or out_obj.get("raw_stdout") or "")
            else:
                text_out = str(out_obj or "")
            return {
                "text": text_out.strip(),
                "protocol": "plugin",
                "model": cfg.model or cfg.plugin_name,
            }

        base = cfg.base_url.rstrip("/")
        headers: dict[str, str] = dict(cfg.extra_headers or {})
        if cfg.api_key:
            headers.setdefault("Authorization", f"Bearer {cfg.api_key}")

        if proto == "ollama":
            endpoint = f"{base}/api/chat" if not base.endswith("/api/chat") else base
            model_name = cfg.model or "llama3.2"
            res = self._post_json(
                endpoint,
                {
                    "model": model_name,
                    "stream": False,
                    "options": {"temperature": temp_val, "num_predict": tok_limit},
                    "messages": [
                        {"role": "system", "content": sys_txt},
                        {"role": "user", "content": clean_prompt},
                    ],
                },
                headers,
                cfg.timeout_seconds,
            )
            if isinstance(res, NgaError):
                return res
            msg_obj = res.get("message") if isinstance(res.get("message"), dict) else {}
            return {
                "text": str(msg_obj.get("content") or res.get("response") or "").strip(),
                "protocol": "ollama",
                "model": model_name,
            }

        if proto == "gemini":
            model_name = cfg.model or "gemini-2.5-flash"
            root_url = base or "https://generativelanguage.googleapis.com"
            if "/models/" in root_url:
                endpoint = root_url
            else:
                endpoint = f"{root_url}/v1beta/models/{model_name}:generateContent"
            gem_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            if cfg.api_key:
                gem_headers["x-goog-api-key"] = cfg.api_key
            res = self._post_json(
                endpoint,
                {
                    "systemInstruction": {"parts": [{"text": sys_txt}]},
                    "contents": [{"role": "user", "parts": [{"text": clean_prompt}]}],
                    "generationConfig": {"temperature": temp_val, "maxOutputTokens": tok_limit},
                },
                gem_headers,
                cfg.timeout_seconds,
            )
            if isinstance(res, NgaError):
                return res
            cands = res.get("candidates") if isinstance(res.get("candidates"), list) else []
            extracted = ""
            if cands and isinstance(cands[0], dict):
                content_obj = cands[0].get("content") if isinstance(cands[0].get("content"), dict) else {}
                parts = content_obj.get("parts") if isinstance(content_obj.get("parts"), list) else []
                extracted = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
            return {
                "text": extracted.strip(),
                "protocol": "gemini",
                "model": model_name,
            }

        if proto == "anthropic":
            model_name = cfg.model or "claude-sonnet-4-5"
            endpoint = f"{base}/v1/messages" if base and not base.endswith("/v1/messages") else (base or "https://api.anthropic.com/v1/messages")
            ant_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            if cfg.api_key:
                ant_headers["x-api-key"] = cfg.api_key
            ant_headers.setdefault("anthropic-version", "2023-06-01")
            res = self._post_json(
                endpoint,
                {
                    "model": model_name,
                    "max_tokens": tok_limit,
                    "temperature": temp_val,
                    "system": sys_txt,
                    "messages": [{"role": "user", "content": clean_prompt}],
                },
                ant_headers,
                cfg.timeout_seconds,
            )
            if isinstance(res, NgaError):
                return res
            blocks = res.get("content") if isinstance(res.get("content"), list) else []
            extracted = "".join(
                str(b.get("text", "")) for b in blocks if isinstance(b, dict) and b.get("type") == "text"
            )
            return {
                "text": extracted.strip(),
                "protocol": "anthropic",
                "model": model_name,
            }

        # Default universal OpenAI-compatible protocol (works with OpenRouter, Groq, DeepSeek, Ollama /v1, vLLM, LM Studio, etc.)
        if not base:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.llm_engine",
                message="No LLM base_url or provider configuration set.",
                recoverable=True,
                suggested_fix="Set NGA_LLM_BASE_URL (and NGA_LLM_MODEL / NGA_LLM_API_KEY if required), or run offline mode.",
            )
        endpoint = f"{base}/chat/completions" if not base.endswith("/chat/completions") else base
        model_name = cfg.model or "default"
        res = self._post_json(
            endpoint,
            {
                "model": model_name,
                "temperature": temp_val,
                "max_tokens": tok_limit,
                "messages": [
                    {"role": "system", "content": sys_txt},
                    {"role": "user", "content": clean_prompt},
                ],
            },
            headers,
            cfg.timeout_seconds,
        )
        if isinstance(res, NgaError):
            return res
        choices = res.get("choices") if isinstance(res.get("choices"), list) else []
        extracted = ""
        if choices and isinstance(choices[0], dict):
            msg = choices[0].get("message") if isinstance(choices[0].get("message"), dict) else {}
            extracted = str(msg.get("content") or choices[0].get("text") or "")
        return {
            "text": extracted.strip(),
            "protocol": "openai_compatible",
            "model": model_name,
  }
                       
