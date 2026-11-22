"""Pure-Python HTML, JavaScript bundle, route, API endpoint, and sourcemap analyzer for `nga`."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    compute_sha256_text,
    redact_secrets,
    safe_resolve_path,
)

MAX_WEB_FILE_BYTES = 8 * 1024 * 1024  # 8 MB cap to protect mobile/Termux RAM

_ROUTE_RE = re.compile(
    r"""["'`](/(?:api|v\d+|auth|login|logout|register|signup|oauth|graphql|rpc|users|accounts|profile|posts|jobs|items|orders|tasks|notes|records|products|payments|billing|webhooks|search|admin|dashboard|settings|upload|download|export|health|status|ping|submit|forms|messages|chat)[A-Za-z0-9_./:-]*)["'`]""",
    re.IGNORECASE,
)
_GENERIC_API_PATH_RE = re.compile(
    r"""["'`](/(?:[a-zA-Z][a-zA-Z0-9_-]{1,24})/(?:[a-zA-Z0-9_:.-]{1,48})(?:/[a-zA-Z0-9_:.-]{1,48})*)["'`]"""
)
_STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|scss|less|woff2?|ttf|eot|otf|mp4|mp3|wav|pdf|map)$",
    re.IGNORECASE,
)
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete|head)|\.request|\$\.(?:ajax|get|post))\s*\(\s*["'`]([^"'`\s]+)["'`]"""
)
_STORAGE_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]"""
)
_SOURCEMAP_RE = re.compile(r"""sourceMappingURL=([^\s*'"`]+)""")
_IMPORT_RE = re.compile(r"""(?:import\s+[\s\S]{1,120}?\s+from\s+|require\s*\()\s*["'`]([^"'`]+)["'`]""")

_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
_HTML_EXTENSIONS = {".html", ".htm", ".xhtml"}


class _HtmlStructureParser(HTMLParser):
    """Extracts title, headings, links, scripts, stylesheets, inline scripts, and forms."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.in_heading = False
        self.in_inline_script = False
        self.title_parts: list[str] = []
        self.headings: list[str] = []
        self._heading_buf: list[str] = []
        self.inline_scripts: list[str] = []
        self._script_buf: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def _flush_form(self) -> None:
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "title":
            self.in_title = True
        elif t in {"h1", "h2", "h3"}:
            self.in_heading = True
            self._heading_buf = []
        elif t == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
        elif t == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.scripts.append(src)
            else:
                self.in_inline_script = True
                self._script_buf = []
        elif t == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "").strip()
            if href and "stylesheet" in rel:
                self.stylesheets.append(href)
        elif t == "form":
            self._flush_form()
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method", "GET") or "GET").upper(),
                "inputs": [],
            }
        elif t in {"input", "select", "textarea"} and self._current_form is not None:
            name = attr_map.get("name") or attr_map.get("id") or ""
            if name:
                self._current_form["inputs"].append(
                    {"tag": t, "name": name, "type": attr_map.get("type", "text")}
                )

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t in {"h1", "h2", "h3"} and self.in_heading:
            self.in_heading = False
            heading_text = " ".join(self._heading_buf).strip()
            if heading_text and len(self.headings) < 50:
                self.headings.append(heading_text[:120])
            self._heading_buf = []
        elif t == "script" and self.in_inline_script:
            self.in_inline_script = False
            joined = "".join(self._script_buf).strip()
            if joined:
                self.inline_scripts.append(joined)
            self._script_buf = []
        elif t == "form":
            self._flush_form()

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_parts.append(data.strip())
        elif self.in_heading and data.strip():
            self._heading_buf.append(data.strip())
        elif self.in_inline_script:
            self._script_buf.append(data)

    def close(self) -> None:
        super().close()
        self._flush_form()


def _is_likely_html(ext: str, text: str) -> bool:
    if ext in _HTML_EXTENSIONS:
        return True
    if ext in _JS_EXTENSIONS:
        return False
    head = text.lstrip()[:512].lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body", "<form", "<div"))


def _register_analysis_handles(analysis: dict[str, Any], handles: HandleRegistry, source_label: str) -> None:
    """Re-hydrate handles into the active registry (important on cache hits)."""
    for key in ("routes", "embedded_routes"):
        items = analysis.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("path"):
                    item["handle"] = handles.register(
                        f"route::{item['path']}",
                        {"kind": "route", "source": source_label},
                    )
    for key in ("api_calls", "embedded_api_calls"):
        items = analysis.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("endpoint"):
                    item["handle"] = handles.register(
                        f"api::{item['endpoint']}",
                        {"kind": "api_call", "source": source_label},
                    )
    scripts = analysis.get("scripts")
    if isinstance(scripts, list):
        for s in scripts:
            if isinstance(s, str) and s.strip():
                handles.register(f"script::{s}", {"kind": "script", "source": source_label})


def analyze_js_source(
    js_text: str,
    source_label: str = "inline.js",
    handles: HandleRegistry | None = None,
    max_items: int = 100,
) -> dict[str, Any]:
    """Extract routes, API calls, storage keys, imports, and sourcemap URLs from JS source."""
    reg = handles if handles is not None else HandleRegistry()
    cap = max(10, min(500, int(max_items)))

    route_set: set[str] = set(_ROUTE_RE.findall(js_text))
    for candidate in _GENERIC_API_PATH_RE.findall(js_text):
        if _STATIC_EXT_RE.search(candidate):
            continue
        if candidate.startswith(("//", "/node_modules", "/assets", "/static", "/images", "/img", "/fonts")):
            continue
        route_set.add(candidate)

    routes = sorted(route_set)[:cap]
    api_calls = sorted(set(_FETCH_RE.findall(js_text)))[:cap]
    storage_keys = sorted(set(_STORAGE_RE.findall(js_text)))[:cap]
    imports = sorted(set(_IMPORT_RE.findall(js_text)))[:cap]
    sourcemaps = sorted(set(m.strip() for m in _SOURCEMAP_RE.findall(js_text) if m.strip()))[:cap]

    route_handles = [
        {"handle": reg.register(f"route::{r}", {"kind": "route", "source": source_label}), "path": r}
        for r in routes
    ]
    api_handles = [
        {"handle": reg.register(f"api::{u}", {"kind": "api_call", "source": source_label}), "endpoint": u}
        for u in api_calls
    ]

    return {
        "source": source_label,
        "content_sha256": compute_sha256_text(js_text),
        "byte_length": len(js_text.encode("utf-8", errors="replace")),
        "routes": route_handles,
        "api_calls": api_handles,
        "storage_keys": storage_keys,
        "imports": imports,
        "sourcemaps": sourcemaps,
    }


def analyze_html_source(
    html_text: str,
    base_url: str = "",
    handles: HandleRegistry | None = None,
) -> dict[str, Any]:
    """Parse HTML document structure, headings, scripts, links, styles, forms, and inline JS patterns."""
    reg = handles if handles is not None else HandleRegistry()
    parser = _HtmlStructureParser()
    parser.feed(html_text)
    parser.close()

    resolved_scripts: list[str] = []
    for s in parser.scripts:
        resolved = urljoin(base_url, s) if base_url else s
        reg.register(f"script::{resolved}", {"kind": "script"})
        resolved_scripts.append(resolved)

    resolved_links: list[str] = []
    for href in parser.links:
        parsed = urlparse(href)
        if parsed.scheme in {"", "http", "https"}:
            resolved_links.append(urljoin(base_url, href) if base_url else href)

    js_corpus = "\n".join(parser.inline_scripts) if parser.inline_scripts else html_text
    js_insights = analyze_js_source(js_corpus, source_label=base_url or "html_inline", handles=reg)

    return {
        "title": " ".join(parser.title_parts).strip(),
        "headings": parser.headings,
        "content_sha256": compute_sha256_text(html_text),
        "scripts": resolved_scripts[:100],
        "stylesheets": [urljoin(base_url, c) if base_url else c for c in parser.stylesheets[:50]],
        "links": resolved_links[:100],
        "forms": parser.forms[:50],
        "inline_scripts_count": len(parser.inline_scripts),
        "routes": js_insights["routes"],
        "api_calls": js_insights["api_calls"],
        "embedded_routes": js_insights["routes"],
        "embedded_api_calls": js_insights["api_calls"],
        "embedded_storage_keys": js_insights["storage_keys"],
        "sourcemaps": js_insights["sourcemaps"],
    }


def _build_web_tool_response(
    source_label: str,
    file_or_url: str,
    redacted_text: str,
    analysis: dict[str, Any],
    from_cache: bool,
    max_output_chars: int,
    offset: int,
) -> ToolResponse:
    preview_budget = apply_output_budget(redacted_text, max_chars=min(max(1, int(max_output_chars)), 4000), offset=offset)
    return ToolResponse(
        module="nga.analyzers.web_js",
        summary=(
            f"Analyzed {analysis.get('kind', 'web')} target '{source_label}' "
            f"(forms={len(analysis.get('forms', []))}, routes={len(analysis.get('routes', []))}, "
            f"cache_hit={from_cache}, sha256={analysis['content_sha256'][:12]}...)."
        ),
        truncated=bool(preview_budget["truncated"]),
        next_offset=preview_budget["next_offset"],
        data={
            "file": file_or_url,
            "kind": analysis.get("kind", "web"),
            "cache_hit": from_cache,
            "title": analysis.get("title", ""),
            "headings": analysis.get("headings", []),
            "forms": analysis.get("forms", []),
            "routes": analysis.get("routes", []),
            "api_calls": analysis.get("api_calls", []),
            "embedded_routes": analysis.get("embedded_routes", analysis.get("routes", [])),
            "embedded_api_calls": analysis.get("embedded_api_calls", analysis.get("api_calls", [])),
            "storage_keys": analysis.get("embedded_storage_keys", analysis.get("storage_keys", [])),
            "scripts": analysis.get("scripts", []),
            "analysis": analysis,
            "redacted_preview": preview_budget,
        },
    )


def inspect_local_web_target(
    target_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
    max_file_bytes: int = MAX_WEB_FILE_BYTES,
) -> ToolResponse | NgaError:
    """Inspect a local HTML or JavaScript file safely with size caps, caching, and output budgets."""
    root = Path(base_root) if base_root is not None else Path.cwd()
    ok_path, resolved_or_err = safe_resolve_path(root, target_path)
    if not ok_path or not isinstance(resolved_or_err, Path):
        return resolved_or_err if isinstance(resolved_or_err, NgaError) else NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.web_js",
            message="Invalid target path provided.",
        )

    if not resolved_or_err.exists() or not resolved_or_err.is_file():
        return NgaError(
            error_code=ErrorCode.NOT_FOUND.value,
            module="nga.analyzers.web_js",
            message=f"Target file not found: {resolved_or_err}",
            recoverable=True,
            suggested_fix="Provide an existing local .html, .htm, .js, .mjs, or .cjs file.",
        )

    read_cap = max(1024, int(max_file_bytes))
    try:
        file_size = resolved_or_err.stat().st_size
        if file_size > read_cap:
            return NgaError(
                error_code=ErrorCode.BUDGET_EXCEEDED.value,
                module="nga.analyzers.web_js",
                message=f"Web target '{resolved_or_err.name}' ({file_size} bytes) exceeds limit ({read_cap} bytes).",
                recoverable=True,
                suggested_fix="Analyze a smaller file or raise max_file_bytes explicitly.",
            )
        raw_text = resolved_or_err.read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.web_js",
            message=f"Unable to read target file: {exc}",
            recoverable=True,
            suggested_fix="Check file read permissions.",
        )

    redacted_text = redact_secrets(raw_text)
    ext = resolved_or_err.suffix.lower()
    is_html = _is_likely_html(ext, redacted_text)
    cache_material = f"{'html' if is_html else 'js'}::{resolved_or_err.name}::{redacted_text}"
    cached = cache.get("web_js_analysis", cache_material) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        analysis = cached
        _register_analysis_handles(analysis, reg, resolved_or_err.name)
        from_cache = True
    else:
        if is_html:
            analysis = analyze_html_source(redacted_text, base_url=resolved_or_err.name, handles=reg)
            analysis["kind"] = "html"
        else:
            analysis = analyze_js_source(redacted_text, source_label=resolved_or_err.name, handles=reg)
            analysis["kind"] = "javascript"

        if cache is not None:
            cache.set("web_js_analysis", cache_material, analysis)
        from_cache = False

    return _build_web_tool_response(
        source_label=resolved_or_err.name,
        file_or_url=str(resolved_or_err),
        redacted_text=redacted_text,
        analysis=analysis,
        from_cache=from_cache,
        max_output_chars=max_output_chars,
        offset=offset,
    )


def inspect_live_web_url(
    url: str,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    timeout_seconds: float = 15.0,
    max_bytes: int = 2 * 1024 * 1024,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> ToolResponse | NgaError:
    """Fetch and inspect a live HTTP/HTTPS web page or JS bundle safely with bounded downloads."""
    clean_url = str(url or "").strip()
    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.analyzers.web_js",
            message="Only valid http:// or https:// URLs are supported for live web inspection.",
            recoverable=True,
            suggested_fix="Pass a full URL such as https://example.com or http://127.0.0.1:8080/.",
        )

    req = Request(
        clean_url,
        headers={
            "User-Agent": "NextGen-Anything-Inspector/0.1",
            "Accept": "text/html,application/javascript,text/javascript,*/*;q=0.8",
        },
        method="GET",
    )
    byte_cap = max(4096, min(MAX_WEB_FILE_BYTES, int(max_bytes)))
    try:
        with urlopen(req, timeout=max(2.0, float(timeout_seconds))) as resp:
            content_type = str(resp.headers.get("Content-Type", "") or "").lower()
            raw_bytes = resp.read(byte_cap + 1)
            if len(raw_bytes) > byte_cap:
                raw_bytes = raw_bytes[:byte_cap]
            raw_text = raw_bytes.decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return NgaError(
            error_code=ErrorCode.NETWORK_ERROR.value,
            module="nga.analyzers.web_js",
            message=redact_secrets(f"Failed fetching URL '{clean_url}': {exc}"),
            recoverable=True,
            suggested_fix="Check network connectivity and verify the URL is reachable.",
        )

    redacted_text = redact_secrets(raw_text)
    ext = Path(parsed.path).suffix.lower()
    is_html = ("html" in content_type) or _is_likely_html(ext, redacted_text)
    cache_material = f"live::{'html' if is_html else 'js'}::{clean_url}::{redacted_text}"
    cached = cache.get("web_js_live", cache_material) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        analysis = cached
        _register_analysis_handles(analysis, reg, clean_url)
        from_cache = True
    else:
        if is_html:
            analysis = analyze_html_source(redacted_text, base_url=clean_url, handles=reg)
            analysis["kind"] = "html"
        else:
            analysis = analyze_js_source(redacted_text, source_label=clean_url, handles=reg)
            analysis["kind"] = "javascript"
        if cache is not None:
            cache.set("web_js_live", cache_material, analysis)
        from_cache = False

    return _build_web_tool_response(
        source_label=parsed.netloc + (parsed.path or "/"),
        file_or_url=clean_url,
        redacted_text=redacted_text,
        analysis=analysis,
        from_cache=from_cache,
        max_output_chars=max_output_chars,
        offset=offset,
        )
    
