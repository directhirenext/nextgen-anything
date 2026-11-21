"""Local offline HTTP mock/replay server driven by extracted API routes and schemas for `nga`."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any
from urllib.parse import urlparse

from nga.core.contracts import ErrorCode, NgaError, ToolResponse, utc_now_iso
from nga.core.security import apply_output_budget, redact_secrets, sanitize_headers


def build_routes_from_har_analysis(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert `analyze_har_payload` mock_routes into normalized stand-in server route rules."""
    raw_routes = analysis.get("mock_routes") if isinstance(analysis, dict) else None
    if not isinstance(raw_routes, list):
        return []

    routes: list[dict[str, Any]] = []
    for item in raw_routes:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method", "GET")).upper().strip() or "GET"
        path = str(item.get("path", "/")).strip() or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        status = int(item.get("status", 200) or 200)
        content_type = str(item.get("content_type", "application/json")).strip() or "application/json"
        safe_headers = sanitize_headers(item.get("headers"))

        if item.get("parsed_json") is not None:
            body_text = redact_secrets(json.dumps(item["parsed_json"], indent=2, default=str))
            content_type = "application/json"
        else:
            body_text = redact_secrets(str(item.get("body_preview", "") or ""))

        bounded_body = apply_output_budget(body_text, max_chars=8000)["content"]
        routes.append(
            {
                "method": method,
                "path": path,
                "status": status,
                "content_type": content_type,
                "headers": safe_headers,
                "body": bounded_body,
            }
        )
    return routes


class StandInMockServer:
    """Thread-safe local HTTP server (loopback 127.0.0.1) serving recorded/mocked API routes."""

    def __init__(
        self,
        routes: list[dict[str, Any]] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.host = "127.0.0.1" if host in {"", "0.0.0.0", "localhost"} else str(host)
        self.requested_port = max(0, min(65535, int(port)))
        self._routes: list[dict[str, Any]] = []
        self._request_log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.bound_port: int | None = None

        if routes:
            self.load_routes(routes)

    def load_routes(self, routes: list[dict[str, Any]]) -> int:
        """Replace active route table with sanitized, secret-redacted route definitions."""
        normalized: list[dict[str, Any]] = []
        for r in routes:
            if not isinstance(r, dict):
                continue
            method = str(r.get("method", "GET")).upper().strip() or "GET"
            path = str(r.get("path", "/")).strip() or "/"
            if not path.startswith("/"):
                path = f"/{path}"
            status = int(r.get("status", 200) or 200)
            content_type = str(r.get("content_type", "application/json")).strip() or "application/json"
            headers = sanitize_headers(r.get("headers"))
            body = redact_secrets(str(r.get("body", "{}")))
            normalized.append(
                {
                    "method": method,
                    "path": path,
                    "status": status,
                    "content_type": content_type,
                    "headers": headers,
                    "body": body,
                }
            )
        with self._lock:
            self._routes = normalized
        return len(normalized)

    def _match_route(self, method: str, path: str) -> dict[str, Any] | None:
        upper_method = method.upper().strip()
        with self._lock:
            for route in self._routes:
                if route["method"] == upper_method and route["path"] == path:
                    return dict(route)
            for route in self._routes:
                if route["path"] == path:
                    return dict(route)
        return None

    def _record_request(self, method: str, path: str, matched: bool, status_sent: int) -> None:
        with self._lock:
            self._request_log.append(
                {
                    "timestamp": utc_now_iso(),
                    "method": method,
                    "path": path,
                    "matched": matched,
                    "status": status_sent,
                }
            )
            if len(self._request_log) > 200:
                self._request_log = self._request_log[-200:]

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                # Silence noisy stderr logs in headless/CLI/MCP modes
                return

            def _handle_any(self, method: str) -> None:
                parsed = urlparse(self.path)
                req_path = parsed.path or "/"

                # Built-in health endpoint
                if req_path == "/__nga__/health":
                    payload = json.dumps(
                        {
                            "ok": True,
                            "service": "nga-standin-server",
                            "routes_loaded": len(outer._routes),
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    outer._record_request(method, req_path, True, 200)
                    return

                # Consume request body if present
                content_len_raw = self.headers.get("Content-Length", "0")
                try:
                    content_len = max(0, min(1_000_000, int(content_len_raw)))
                except ValueError:
                    content_len = 0
                if content_len > 0:
                    _ = self.rfile.read(content_len)

                matched = outer._match_route(method, req_path)
                if matched is not None:
                    resp_bytes = matched["body"].encode("utf-8", errors="replace")
                    status_code = int(matched["status"])
                    self.send_response(status_code)
                    self.send_header("Content-Type", matched["content_type"])
                    for hk, hv in matched["headers"].items():
                        if hk.lower() not in {"content-length", "transfer-encoding", "connection"}:
                            self.send_header(hk, hv)
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)
                    outer._record_request(method, req_path, True, status_code)
                else:
                    fallback_body = json.dumps(
                        {
                            "ok": False,
                            "standin": True,
                            "message": f"No mocked route matched {method} {req_path}",
                        }
                    ).encode("utf-8")
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(fallback_body)))
                    self.end_headers()
                    self.wfile.write(fallback_body)
                    outer._record_request(method, req_path, False, 404)

            def do_GET(self) -> None:
                self._handle_any("GET")

            def do_POST(self) -> None:
                self._handle_any("POST")

            def do_PUT(self) -> None:
                self._handle_any("PUT")

            def do_PATCH(self) -> None:
                self._handle_any("PATCH")

            def do_DELETE(self) -> None:
                self._handle_any("DELETE")

        return _Handler

    def start(self) -> ToolResponse | NgaError:
        """Start the background mock server on loopback address."""
        if self._httpd is not None and self.bound_port is not None:
            return ToolResponse(
                module="nga.runtime.standin_server",
                summary=f"Stand-in server already running at http://{self.host}:{self.bound_port}",
                data={
                    "running": True,
                    "url": f"http://{self.host}:{self.bound_port}",
                    "port": self.bound_port,
                    "routes_count": len(self._routes),
                },
            )

        try:
            httpd = ThreadingHTTPServer((self.host, self.requested_port), self._make_handler())
            httpd.daemon_threads = True
            actual_port = int(httpd.server_address[1])
            thread = threading.Thread(target=httpd.serve_forever, name="nga-standin-http", daemon=True)
            thread.start()

            self._httpd = httpd
            self._thread = thread
            self.bound_port = actual_port

            return ToolResponse(
                module="nga.runtime.standin_server",
                summary=f"Stand-in server started at http://{self.host}:{actual_port} with {len(self._routes)} route(s).",
                data={
                    "running": True,
                    "url": f"http://{self.host}:{actual_port}",
                    "port": actual_port,
                    "routes_count": len(self._routes),
                },
            )
        except OSError as exc:
            return NgaError(
                error_code=ErrorCode.STORAGE_ERROR.value,
                module="nga.runtime.standin_server",
                message=f"Failed starting stand-in server on {self.host}:{self.requested_port}: {exc}",
                recoverable=True,
                suggested_fix="Choose a different port (e.g., --port 0 for auto-free port) and retry.",
            )

    def stop(self) -> ToolResponse:
        """Stop the background mock server cleanly."""
        port_was = self.bound_port
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            self._thread = None
        self.bound_port = None

        return ToolResponse(
            module="nga.runtime.standin_server",
            summary="Stand-in server stopped cleanly.",
            data={"running": False, "previous_port": port_was},
        )

    def get_request_log(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent requests handled by the mock server."""
        with self._lock:
            return self._request_log[-max(1, min(200, int(limit))) :]
