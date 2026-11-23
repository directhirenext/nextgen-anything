"""Lightweight Python SDK client for communicating with NextGen-Anything (`nga`) REST & MCP interfaces."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from nga.core.security import redact_secrets


class NgaHttpClient:
    """Zero-dependency HTTP client targeting `nga ui` REST endpoints with optional token auth."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8765",
        timeout: float = 15.0,
        api_token: str = "",
    ) -> None:
        self.base_url = str(base_url or "http://127.0.0.1:8765").strip().rstrip("/")
        self.timeout = max(1.0, float(timeout))
        self.api_token = str(api_token or "").strip()

    def _validate_base_url(self) -> tuple[bool, str]:
        low = self.base_url.lower()
        if not (low.startswith("http://") or low.startswith("https://")):
            return False, f"Invalid base_url scheme in '{self.base_url}'; use http:// or https://."
        return True, ""

    def _request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        ok_url, url_err = self._validate_base_url()
        if not ok_url:
            return {
                "ok": False,
                "error_code": "NGA_INVALID_INPUT",
                "message": redact_secrets(url_err),
                "recoverable": False,
            }

        clean_path = path if str(path).startswith("/") else f"/{path}"
        url = f"{self.base_url}{clean_path}"
        upper_method = str(method or "GET").upper()
        data_bytes = json.dumps(payload or {}, default=str).encode("utf-8") if upper_method != "GET" else None

        headers: dict[str, str] = {"Accept": "application/json"}
        if data_bytes is not None:
            headers["Content-Type"] = "application/json"
        if self.api_token:
            headers["X-NGA-Token"] = self.api_token
            headers["Authorization"] = f"Bearer {self.api_token}"

        req = Request(url=url, data=data_bytes, headers=headers, method=upper_method)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw_text)
                except json.JSONDecodeError as exc:
                    return {
                        "ok": False,
                        "error_code": "NGA_INVALID_RESPONSE",
                        "message": redact_secrets(f"Non-JSON response from {url}: {exc}"),
                        "recoverable": True,
                        "raw_preview": redact_secrets(raw_text[:500]),
                    }
                return parsed if isinstance(parsed, dict) else {"ok": True, "data": parsed}
        except HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read(2048).decode("utf-8", errors="replace") if exc.fp else ""
            except Exception:
                err_body = ""
            try:
                parsed_err = json.loads(err_body)
                if isinstance(parsed_err, dict):
                    return parsed_err
            except json.JSONDecodeError:
                pass
            return {
                "ok": False,
                "error_code": "NGA_AUTH_ERROR" if exc.code in {401, 403} else "NGA_HTTP_ERROR",
                "message": redact_secrets(f"HTTP {exc.code}: {exc.reason} {err_body[:200]}".strip()),
                "recoverable": exc.code not in {401, 403},
            }
        except TimeoutError as exc:
            return {
                "ok": False,
                "error_code": "NGA_TIMEOUT",
                "message": redact_secrets(f"Request timed out connecting to {url}: {exc}"),
                "recoverable": True,
                "suggested_fix": "Increase timeout or verify `nga ui` responsiveness.",
            }
        except (URLError, OSError) as exc:
            return {
                "ok": False,
                "error_code": "NGA_NETWORK_UNREACHABLE",
                "message": redact_secrets(f"Failed connecting to {url}: {exc}"),
                "recoverable": True,
                "suggested_fix": "Start `nga ui --port 8765` and verify base_url.",
            }

    def doctor(self) -> dict[str, Any]:
        """Call GET /api/doctor."""
        return self._request_json("GET", "/api/doctor")

    def inspect(self, kind: str, target: str) -> dict[str, Any]:
        """Call POST /api/inspect."""
        return self._request_json("POST", "/api/inspect", {"kind": kind, "target": target})

    def live_inspect(self, url: str) -> dict[str, Any]:
        """Call POST /api/live_inspect."""
        return self._request_json("POST", "/api/live_inspect", {"url": url})

    def upload(self, filename: str, content: str, is_base64: bool = False) -> dict[str, Any]:
        """Call POST /api/upload."""
        key = "content_base64" if is_base64 else "content"
        return self._request_json("POST", "/api/upload", {"filename": filename, "is_base64": is_base64, key: content})

    def simulate_python(self, code: str, label: str = "sdk_snippet", smoke_code: str = "") -> dict[str, Any]:
        """Call POST /api/simulate using canonical 'smoke' field."""
        return self._request_json(
            "POST",
            "/api/simulate",
            {"code": code, "label": label, "smoke": smoke_code},
        )

    def synthesize(
        self,
        findings: dict[str, Any],
        app_name: str = "reconstructed_app",
        output_dir: str = "synthesized_out",
        custom_prompt: str = "",
        include_android_scaffold: bool = False,
    ) -> dict[str, Any]:
        """Call POST /api/synthesize."""
        return self._request_json(
            "POST",
            "/api/synthesize",
            {
                "app_name": app_name,
                "findings": findings,
                "output_dir": output_dir,
                "custom_prompt": custom_prompt,
                "include_android_scaffold": include_android_scaffold,
            },
        )

    def rebuild(
        self,
        kind: str,
        target: str,
        output_dir: str = "rebuilt_app",
        app_name: str = "",
        custom_prompt: str = "",
    ) -> dict[str, Any]:
        """Call POST /api/rebuild."""
        return self._request_json(
            "POST",
            "/api/rebuild",
            {
                "kind": kind,
                "target": target,
                "output_dir": output_dir,
                "app_name": app_name,
                "custom_prompt": custom_prompt,
            },
        )

    def agent_turn(self, prompt: str, candidate_code: str = "", target_label: str = "sdk_agent") -> dict[str, Any]:
        """Call POST /api/agent."""
        return self._request_json(
            "POST",
            "/api/agent",
            {"prompt": prompt, "candidate_code": candidate_code, "target_label": target_label},
        )

    def memory_store(
        self,
        title: str,
        body: str,
        namespace: str = "agent_core",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Call POST /api/memory."""
        return self._request_json(
            "POST",
            "/api/memory",
            {"title": title, "body": body, "namespace": namespace, "tags": tags or []},
        )

    def memory_retrieve(self, query: str, namespace: str | None = None, limit: int = 5) -> dict[str, Any]:
        """Call GET /api/memory."""
        params: dict[str, Any] = {"q": str(query), "limit": int(limit)}
        if namespace:
            params["namespace"] = str(namespace)
        return self._request_json("GET", f"/api/memory?{urlencode(params, quote_via=quote)}")

    def brief(self, label: str, kind: str = "web", custom_requirements: str = "") -> dict[str, Any]:
        """Call POST /api/brief."""
        return self._request_json(
            "POST",
            "/api/brief",
            {"label": label, "kind": kind, "custom_requirements": custom_requirements},
        )

    def ledger_list(self) -> dict[str, Any]:
        """Call GET /api/ledger."""
        return self._request_json("GET", "/api/ledger")

    def ledger_add(
        self,
        obligation_id: str,
        category: str = "endpoint",
        title: str = "",
        status: str = "pending",
    ) -> dict[str, Any]:
        """Call POST /api/ledger to add an obligation."""
        return self._request_json(
            "POST",
            "/api/ledger",
            {"action": "add", "obligation_id": obligation_id, "category": category, "title": title or obligation_id, "status": status},
        )

    def ledger_update(self, obligation_id: str, status: str) -> dict[str, Any]:
        """Call POST /api/ledger to update an obligation status."""
        return self._request_json("POST", "/api/ledger", {"action": "update", "obligation_id": obligation_id, "status": status})
                
