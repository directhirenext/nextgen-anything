"""Pure-Python HTML, JavaScript bundle, route, API endpoint, and sourcemap analyzer for `nga`."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, HandleRegistry, NgaError, ToolResponse
from nga.core.security import (
    DEFAULT_MAX_OUTPUT_CHARS,
    apply_output_budget,
    compute_sha256_text,
    redact_secrets,
    safe_resolve_path,
)

_ROUTE_RE = re.compile(r"""["'`](/(?:api|v\d+|auth|users|posts|jobs|items|search|admin|dashboard)[A-Za-z0-9_./:-]*)["'`]""")
_FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.request)\s*\(\s*["'`]([^"'`]+)["'`]""")
_STORAGE_RE = re.compile(r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["'`]([^"'`]+)["'`]""")
_SOURCEMAP_RE = re.compile(r"""sourceMappingURL=([^\s*'"`]+)""")
_IMPORT_RE = re.compile(r"""(?:import\s+.*?\s+from\s+|require\s*\()\s*["'`]([^"'`]+)["'`]""")


class _HtmlStructureParser(HTMLParser):
    """Extracts title, links, scripts, stylesheets, and forms from HTML markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "title":
            self.in_title = True
        elif t == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
        elif t == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.scripts.append(src)
        elif t == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "").strip()
            if href and "stylesheet" in rel:
                self.stylesheets.append(href)
        elif t == "form":
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
        elif t == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_parts.append(data.strip())


def analyze_js_source(
    js_text: str,
    source_label: str = "inline.js",
    handles: HandleRegistry | None = None,
    max_items: int = 100,
) -> dict[str, Any]:
    """Extract routes, API calls, storage keys, imports, and sourcemap URLs from JS source."""
    reg = handles if handles is not None else HandleRegistry()
    cap = max(10, min(500, int(max_items)))

    routes = sorted(set(_ROUTE_RE.findall(js_text)))[:cap]
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
    """Parse HTML document structure, scripts, links, styles, forms, and inline JS patterns."""
    reg = handles if handles is not None else HandleRegistry()
    parser = _HtmlStructureParser()
    parser.feed(html_text)

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

    js_insights = analyze_js_source(html_text, source_label=base_url or "html_inline", handles=reg)

    return {
        "title": " ".join(parser.title_parts).strip(),
        "content_sha256": compute_sha256_text(html_text),
        "scripts": resolved_scripts[:100],
        "stylesheets": [urljoin(base_url, c) if base_url else c for c in parser.stylesheets[:50]],
        "links": resolved_links[:100],
        "forms": parser.forms[:50],
        "embedded_routes": js_insights["routes"],
        "embedded_api_calls": js_insights["api_calls"],
        "embedded_storage_keys": js_insights["storage_keys"],
        "sourcemaps": js_insights["sourcemaps"],
    }


def inspect_local_web_target(
    target_path: str | Path,
    base_root: Path | None = None,
    cache: NgaCache | None = None,
    handles: HandleRegistry | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    offset: int = 0,
) -> ToolResponse | NgaError:
    """Inspect a local HTML or JavaScript file safely with caching and output budget enforcement."""
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

    try:
        raw_text = resolved_or_err.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.analyzers.web_js",
            message=f"Unable to read target file: {exc}",
            recoverable=True,
            suggested_fix="Check file read permissions.",
        )

    redacted_text = redact_secrets(raw_text)
    cached = cache.get("web_js_analysis", redacted_text) if cache is not None else None
    reg = handles if handles is not None else HandleRegistry()

    if cached is not None:
        analysis = cached
        from_cache = True
    else:
        ext = resolved_or_err.suffix.lower()
        if ext in {".html", ".htm"} or "<html" in redacted_text.lower():
            analysis = analyze_html_source(redacted_text, base_url=resolved_or_err.name, handles=reg)
            analysis["kind"] = "html"
        else:
            analysis = analyze_js_source(redacted_text, source_label=resolved_or_err.name, handles=reg)
            analysis["kind"] = "javascript"

        if cache is not None:
            cache.set("web_js_analysis", redacted_text, analysis)
        from_cache = False

    preview_budget = apply_output_budget(redacted_text, max_chars=min(max_output_chars, 4000), offset=offset)

    return ToolResponse(
        module="nga.analyzers.web_js",
        summary=(
            f"Analyzed {analysis.get('kind', 'web')} target '{resolved_or_err.name}' "
            f"(cache_hit={from_cache}, sha256={analysis['content_sha256'][:12]}...)."
        ),
        truncated=bool(preview_budget["truncated"]),
        next_offset=preview_budget["next_offset"],
        data={
            "file": str(resolved_or_err),
            "cache_hit": from_cache,
            "analysis": analysis,
            "redacted_preview": preview_budget,
        },
      )
          
