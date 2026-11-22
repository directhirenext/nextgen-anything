"""Local offline HTTP mock/replay server driven by extracted API routes and schemas for `nga`."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any
from urllib.parse import urlparse

from nga.core.contracts import ErrorCode, NgaError, ToolResponse, utc_now_iso
from nga.core.security import apply_output_budget, redact_secrets, sanitize_headers

_ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_MAX_MOCK_BODY_CHARS = 16_000


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
        status = max(100, min(599, _safe_int(item.get("status", 200), 200)))
        content_type = str(item.get("content_type", "application/json")).strip() or "application/json"
        safe_headers = sanitize_headers(item.get("headers"))

        if item.get("parsed_json") is not None:
            encoded = redact_secrets(json.dumps(item["parsed_json"], indent=2, default=str))
            if len(encoded) > _MAX_MOCK_BODY_CHARS:
                preview = apply_output_budget(encoded, max_chars=_MAX_MOCK_BODY_CHARS - 256)["content"]
                body_text = json.dumps(
                    {
                        "ok": True,
                        "truncated": True,
                        "total_chars": len(encoded),
                        "preview": preview,
                    },
                    indent=2,
                )
            else:
                body_text = encoded
            content_type = "application/json; charset=utf-8"
        else:
            raw_preview = redact_secrets(str(item.get("body_preview", "") or ""))
            body_text = apply_output_budget(raw_preview, max_chars=_MAX_MOCK_BODY_CHARS)["content"]

        routes.append(
            {
                "method": method,
                "path": path,
                "status": status,
                "content_type": content_type,
                "headers": safe_headers,
                "body": body_text,
            }
        )
    return routes


class StandInMockServer:
    """Thread-safe local loopback HTTP server serving recorded/mocked API routes."""

    def __init__(
        self,
        routes: list[dict[str, Any]] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        clean_host = str(host or "127.0.0.1").strip().lower()
        self.host = "127.0.0.1" if clean_host not in _ALLOWED_LOOPBACK_HOSTS else ("127.0.0.1" if clean_host == "localhost" else clean_host)
        self.requested_port = max(0, min(65535, _safe_int(port, 0)))
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
            status = max(100, min(599, _safe_int(r.get("status", 200), 200)))
            content_type = str(r.get("content_type", "application/json; charset=utf-8")).strip() or "application/json; charset=utf-8"
            headers = sanitize_headers(r.get("headers"))
            raw_body = r.get("body", "{}")
            body = redact_secrets(json.dumps(raw_body, indent=2, default=str) if isinstance(raw_body, (dict, list)) else str(raw_body))
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

    def _match_route(self, method: str, path: str) -> tuple[dict[str, Any] | None, list[str]]:
        """Strictly match (method, path); return allowed methods if path exists for other methods."""
        upper_method = method.upper().strip()
        allowed_methods: list[str] = []
        with self._lock:
            for route in self._routes:
                if route["path"] == path:
                    if route["method"] not in allowed_methods:
                        allowed_methods.append(route["method"])
                    if route["method"] == upper_method or (upper_method == "HEAD" and route["method"] == "GET"):
                        return dict(route), allowed_methods
        return None, allowed_methods

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
                return

            def _handle_any(self, method: str) -> None:
                parsed = urlparse(self.path)
                req_path = parsed.path or "/"

                if req_path in {"/__nga__/health", "/__health"} and method in {"GET", "HEAD"}:
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
                    if method != "HEAD":
                        self.wfile.write(payload)
                    outer._record_request(method, req_path, True, 200)
                    return

                content_len = max(0, min(1_000_000, _safe_int(self.headers.get("Content-Length", "0"), 0)))
                if content_len > 0:
                    _ = self.rfile.read(content_len)

                matched, allowed_methods = outer._match_route(method, req_path)
                if method == "OPTIONS":
                    self.send_response(204)
                    self.send_header("Allow", ", ".join(allowed_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]))
                    self.end_headers()
                    outer._record_request(method, req_path, True, 204)
                    return

                if matched is not None:
                    resp_bytes = matched["body"].encode("utf-8", errors="replace")
                    status_code = int(matched["status"])
                    self.send_response(status_code)
                    self.send_header("Content-Type", matched["content_type"])
                    for hk, hv in matched["headers"].items():
                        if hk.lower() not in {"content-type", "content-length", "transfer-encoding", "connection"}:
                            self.send_header(hk, hv)
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(resp_bytes)
                    outer._record_request(method, req_path, True, status_code)
                elif allowed_methods:
                    err_body = json.dumps(
                        {
                            "ok": False,
                            "standin": True,
                            "message": f"Method {method} not allowed for {req_path}",
                            "allowed_methods": allowed_methods,
                        }
                    ).encode("utf-8")
                    self.send_response(405)
                    self.send_header("Allow", ", ".join(allowed_methods))
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(err_body)))
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(err_body)
                    outer._record_request(method, req_path, False, 405)
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
                    if method != "HEAD":
                        self.wfile.write(fallback_body)
                    outer._record_request(method, req_path, False, 404)

            def do_GET(self) -> None:
                self._handle_any("GET")

            def do_HEAD(self) -> None:
                self._handle_any("HEAD")

            def do_OPTIONS(self) -> None:
                self._handle_any("OPTIONS")

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
        with self._lock:
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
                routes_count = len(self._routes)
            except OSError as exc:
                return NgaError(
                    error_code=ErrorCode.STORAGE_ERROR.value,
                    module="nga.runtime.standin_server",
                    message=f"Failed starting stand-in server on {self.host}:{self.requested_port}: {exc}",
                    recoverable=True,
                    suggested_fix="Choose a different port (e.g., --port 0 for auto-free port) and retry.",
                )

        return ToolResponse(
            module="nga.runtime.standin_server",
            summary=f"Stand-in server started at http://{self.host}:{actual_port} with {routes_count} route(s).",
            data={
                "running": True,
                "url": f"http://{self.host}:{actual_port}",
                "port": actual_port,
                "routes_count": routes_count,
            },
        )

    def stop(self) -> ToolResponse:
        """Stop the background mock server cleanly."""
        with self._lock:
            port_was = self.bound_port
            httpd = self._httpd
            thread = self._thread
            self._httpd = None
            self._thread = None
            self.bound_port = None

        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

        return ToolResponse(
            module="nga.runtime.standin_server",
            summary="Stand-in server stopped cleanly.",
            data={"running": False, "previous_port": port_was},
        )

    def get_request_log(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent requests handled by the mock server."""
        with self._lock:
            return self._request_log[-max(1, min(200, int(limit))) :]
            
