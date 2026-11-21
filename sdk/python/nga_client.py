"""Lightweight Python SDK client for communicating with NextGen-Anything (`nga`) REST & MCP interfaces."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class NgaHttpClient:
    """Zero-dependency HTTP client targeting `nga ui` REST endpoints."""

    def __init__(self, base_url: str = "http://127.0.0.1:8765", timeout: float = 15.0) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.timeout = max(1.0, float(timeout))

    def _request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        data_bytes = json.dumps(payload or {}, default=str).encode("utf-8") if method.upper() != "GET" else None
        headers = {"Accept": "application/json"}
        if data_bytes is not None:
            headers["Content-Type"] = "application/json"

        req = Request(url=url, data=data_bytes, headers=headers, method=method.upper())
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw_text)
                return parsed if isinstance(parsed, dict) else {"ok": True, "data": parsed}
        except HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            try:
                parsed_err = json.loads(err_body)
                if isinstance(parsed_err, dict):
                    return parsed_err
            except json.JSONDecodeError:
                pass
            return {
                "ok": False,
                "error_code": "NGA_HTTP_ERROR",
                "message": f"HTTP {exc.code}: {exc.reason}",
                "recoverable": True,
            }
        except (URLError, TimeoutError, OSError) as exc:
            return {
                "ok": False,
                "error_code": "NGA_NETWORK_UNREACHABLE",
                "message": f"Failed connecting to {url}: {exc}",
                "recoverable": True,
                "suggested_fix": "Start `nga ui --port 8765` and verify base_url.",
            }

    def doctor(self) -> dict[str, Any]:
        """Call GET /api/doctor."""
        return self._request_json("GET", "/api/doctor")

    def inspect(self, kind: str, target: str) -> dict[str, Any]:
        """Call POST /api/inspect."""
        return self._request_json("POST", "/api/inspect", {"kind": kind, "target": target})

    def simulate_python(self, code: str, label: str = "sdk_snippet", smoke_code: str = "") -> dict[str, Any]:
        """Call POST /api/simulate."""
        return self._request_json(
            "POST",
            "/api/simulate",
            {"code": code, "label": label, "smoke_code": smoke_code},
        )

    def brief(self, label: str, kind: str = "web") -> dict[str, Any]:
        """Call POST /api/brief."""
        return self._request_json("POST", "/api/brief", {"label": label, "kind": kind})

    def ledger_list(self) -> dict[str, Any]:
        """Call GET /api/ledger."""
        return self._request_json("GET", "/api/ledger")
          
