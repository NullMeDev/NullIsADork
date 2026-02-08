"""
JS Bundle Analyzer — Extract API routes, secrets, and endpoints from JavaScript bundles

Targets modern SPA/SSR frameworks (Next.js, React, Vue, Angular, Nuxt) where:
  - All API routes are hidden in webpack/turbopack bundles
  - No traditional <form> or URL params exist in the HTML
  - Endpoints are only discoverable by parsing bundled JavaScript

Features:
  - Next.js _next/static/chunks/*.js analysis
  - API route extraction (/api/*, fetch(), axios calls)
  - Hardcoded secret/token extraction from JS bundles
  - GraphQL endpoint and query extraction
  - WebSocket URL extraction
  - React Router / Next.js page route extraction
  - Environment variable leaks (process.env.*, NEXT_PUBLIC_*)
  - Source map detection and parsing

v3.16 — Phase: SPA/API Intelligence
"""

import asyncio
import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp
from loguru import logger


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class JSEndpoint:
    """An API endpoint extracted from JavaScript."""
    url: str
    method: str = "GET"           # GET, POST, PUT, DELETE, PATCH
    source_file: str = ""         # Which JS file it was found in
    context: str = ""             # Surrounding code snippet
    auth_required: bool = False   # If auth headers detected nearby
    content_type: str = ""        # Expected content-type (json, form, etc.)


@dataclass
class JSSecret:
    """A secret/token/key found in JavaScript bundles."""
    key_name: str
    value: str
    secret_type: str              # api_key, token, password, env_var, etc.
    source_file: str = ""
    confidence: float = 0.8       # 0.0 - 1.0


@dataclass
class JSAnalysisResult:
    """Complete analysis result from JS bundle scanning."""
    target_url: str
    js_files_analyzed: int = 0
    total_js_bytes: int = 0

    # Discovered endpoints
    api_endpoints: List[JSEndpoint] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)

    # Page routes (React Router, Next.js pages)
    page_routes: List[str] = field(default_factory=list)

    # Secrets and env vars
    secrets: List[JSSecret] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)

    # Framework detection
    framework: str = ""           # next.js, react, vue, angular, nuxt, svelte
    build_tool: str = ""          # webpack, vite, turbopack, esbuild

    # Source maps
    source_maps: List[str] = field(default_factory=list)

    # Raw script URLs found
    script_urls: List[str] = field(default_factory=list)


# ── Regex patterns ────────────────────────────────────────────────────────────

# API endpoint patterns in JS code
API_PATTERNS = [
    # fetch() calls
    re.compile(r'''fetch\s*\(\s*["'`]([^"'`]+?)["'`]''', re.IGNORECASE),
    re.compile(r'''fetch\s*\(\s*["'`]([^"'`]*?/api/[^"'`]+?)["'`]''', re.IGNORECASE),
    # axios calls
    re.compile(r'''axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+?)["'`]''', re.IGNORECASE),
    re.compile(r'''axios\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+?)["'`]''', re.IGNORECASE),
    # XMLHttpRequest
    re.compile(r'''\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+?)["'`]''', re.IGNORECASE),
    # Generic URL patterns that look like API endpoints
    re.compile(r'''["'`](/api/[a-zA-Z0-9_/.-]+)["'`]'''),
    re.compile(r'''["'`](/v[0-9]+/[a-zA-Z0-9_/.-]+)["'`]'''),
    re.compile(r'''["'`](https?://[^"'`\s]+/api/[^"'`\s]+)["'`]'''),
    # Template literals with API paths
    re.compile(r'''`([^`]*?/api/[^`]*?)`'''),
    # baseURL / apiUrl / endpoint assignments
    re.compile(r'''(?:baseURL|apiUrl|apiBase|endpoint|API_URL|BASE_URL)\s*[:=]\s*["'`]([^"'`]+?)["'`]''', re.IGNORECASE),
]

# GraphQL patterns
GRAPHQL_PATTERNS = [
    re.compile(r'''["'`](/graphql[^"'`]*)["'`]''', re.IGNORECASE),
    re.compile(r'''["'`](https?://[^"'`]+/graphql[^"'`]*)["'`]''', re.IGNORECASE),
    re.compile(r'''["'`](/__graphql[^"'`]*)["'`]''', re.IGNORECASE),
    re.compile(r'''query\s+(\w+)\s*(?:\([^)]*\))?\s*\{''', re.IGNORECASE),
    re.compile(r'''mutation\s+(\w+)\s*(?:\([^)]*\))?\s*\{''', re.IGNORECASE),
]

# WebSocket patterns
WS_PATTERNS = [
    re.compile(r'''["'`](wss?://[^"'`\s]+)["'`]''', re.IGNORECASE),
    re.compile(r'''new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]''', re.IGNORECASE),
]

# Secret/token patterns in JS
JS_SECRET_PATTERNS = [
    # API Keys (generic)
    (re.compile(r'''(?:api[_-]?key|apikey|api_token)\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]''', re.IGNORECASE), "api_key"),
    # Bearer tokens
    (re.compile(r'''["'`]Bearer\s+([a-zA-Z0-9_\-\.]{20,})["'`]'''), "bearer_token"),
    # AWS keys
    (re.compile(r'''["'`](AKIA[A-Z0-9]{16})["'`]'''), "aws_access_key"),
    (re.compile(r'''["'`]([a-zA-Z0-9/+=]{40})["'`]'''), "possible_aws_secret"),
    # Stripe keys
    (re.compile(r'''["'`](sk_(?:live|test)_[a-zA-Z0-9]{24,})["'`]'''), "stripe_secret"),
    (re.compile(r'''["'`](pk_(?:live|test)_[a-zA-Z0-9]{24,})["'`]'''), "stripe_publishable"),
    # Firebase
    (re.compile(r'''["'`](AIza[a-zA-Z0-9_\-]{35})["'`]'''), "firebase_api_key"),
    # JWT tokens
    (re.compile(r'''["'`](eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,})["'`]'''), "jwt_token"),
    # Generic secrets
    (re.compile(r'''(?:secret|password|passwd|token|private[_-]?key)\s*[:=]\s*["'`]([^"'`]{8,})["'`]''', re.IGNORECASE), "generic_secret"),
    # Telegram bot tokens
    (re.compile(r'''["'`](\d{8,10}:[A-Za-z0-9_-]{35})["'`]'''), "telegram_bot_token"),
    # GitHub tokens
    (re.compile(r'''["'`](gh[ps]_[A-Za-z0-9_]{36,})["'`]'''), "github_token"),
    # Google API keys
    (re.compile(r'''["'`](AIzaSy[a-zA-Z0-9_\-]{33})["'`]'''), "google_api_key"),
    # SendGrid
    (re.compile(r'''["'`](SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})["'`]'''), "sendgrid_api_key"),
    # Twilio
    (re.compile(r'''["'`](SK[a-f0-9]{32})["'`]'''), "twilio_api_key"),
    # Slack tokens
    (re.compile(r'''["'`](xox[bpas]-[a-zA-Z0-9\-]+)["'`]'''), "slack_token"),
    # Discord tokens
    (re.compile(r'''["'`]([MN][A-Za-z\d]{23,28}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,})["'`]'''), "discord_token"),
    # Supabase
    (re.compile(r'''["'`](eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["'`]'''), "supabase_anon_key"),
    # Private keys (partial)
    (re.compile(r'''-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'''), "private_key_header"),
]

# Environment variable leaks
ENV_VAR_PATTERNS = [
    re.compile(r'''process\.env\.([A-Z_][A-Z0-9_]+)'''),
    re.compile(r'''NEXT_PUBLIC_([A-Z0-9_]+)\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''import\.meta\.env\.([A-Z_][A-Z0-9_]+)'''),
    re.compile(r'''__ENV__\.([A-Z_][A-Z0-9_]+)'''),
    # Inline env values (NEXT_PUBLIC_ are public, but may reveal architecture)
    re.compile(r'''["'`](NEXT_PUBLIC_[A-Z0-9_]+)["'`]\s*:\s*["'`]([^"'`]+)["'`]'''),
]

# Framework detection
FRAMEWORK_SIGNATURES = {
    "next.js": [
        re.compile(r'''_next/static'''),
        re.compile(r'''__NEXT_DATA__'''),
        re.compile(r'''next/router'''),
        re.compile(r'''next/link'''),
        re.compile(r'''nextjs''', re.IGNORECASE),
    ],
    "react": [
        re.compile(r'''react(?:\.production|\.development)'''),
        re.compile(r'''ReactDOM'''),
        re.compile(r'''__REACT_DEVTOOLS'''),
        re.compile(r'''jsx|createElement'''),
    ],
    "vue": [
        re.compile(r'''__VUE__'''),
        re.compile(r'''vue(?:\.runtime|\.esm)'''),
        re.compile(r'''v-(?:if|for|bind|on|model)'''),
    ],
    "angular": [
        re.compile(r'''@angular/core'''),
        re.compile(r'''ng-version'''),
        re.compile(r'''NgModule'''),
    ],
    "nuxt": [
        re.compile(r'''__NUXT__'''),
        re.compile(r'''nuxt(?:\.js|\.config)''', re.IGNORECASE),
    ],
    "svelte": [
        re.compile(r'''svelte/internal'''),
        re.compile(r'''__svelte'''),
    ],
}

BUILD_TOOL_SIGNATURES = {
    "webpack": [re.compile(r'''webpackChunk|__webpack_require__|webpack/runtime''')],
    "vite": [re.compile(r'''@vite/client|import\.meta\.hot''')],
    "turbopack": [re.compile(r'''turbopack|__turbopack''')],
    "esbuild": [re.compile(r'''esbuild''')],
    "rollup": [re.compile(r'''rollup''')],
}

# Next.js specific route extraction
NEXTJS_ROUTE_PATTERNS = [
    re.compile(r'''(?:pages|app)/([a-zA-Z0-9_\-\[\]/]+)'''),
    re.compile(r'''"page"\s*:\s*"([^"]+)"'''),
    re.compile(r'''"route"\s*:\s*"([^"]+)"'''),
    re.compile(r'''pathname\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''router\.push\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''router\.replace\s*\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''Link\s+href\s*=\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''href\s*:\s*["'`]([^"'`]+)["'`]'''),
]

# Source map detection
SOURCE_MAP_PATTERN = re.compile(r'''//[#@]\s*sourceMappingURL=([^\s]+)''')

# Skip patterns — not real endpoints
SKIP_ENDPOINT_PATTERNS = [
    re.compile(r'''^(https?://)?(cdn\.|fonts\.|static\.|assets\.)''', re.IGNORECASE),
    re.compile(r'''\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)''', re.IGNORECASE),
    re.compile(r'''^(data:|blob:|javascript:|#|mailto:)''', re.IGNORECASE),
    re.compile(r'''^https?://(www\.)?(google|facebook|twitter|github|cloudflare|gstatic|googleapis)\.(com|net|org)''', re.IGNORECASE),
    re.compile(r'''webpack|__webpack|hot-update|hmr''', re.IGNORECASE),
]


# ── Analyzer class ────────────────────────────────────────────────────────────

class JSBundleAnalyzer:
    """Analyze JavaScript bundles from SPA/SSR websites to extract hidden attack surface."""

    def __init__(
        self,
        timeout: int = 30,
        max_js_files: int = 60,
        max_js_size_mb: float = 15.0,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ):
        self.timeout = timeout
        self.max_js_files = max_js_files
        self.max_js_size = int(max_js_size_mb * 1024 * 1024)
        self.user_agent = user_agent

    # ── Main entry ────────────────────────────────────────────────────────

    async def analyze(
        self,
        url: str,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        html_content: Optional[str] = None,
    ) -> JSAnalysisResult:
        """
        Analyze a URL's JavaScript bundles.

        1. Fetch the main HTML page
        2. Extract all <script> src URLs
        3. Download each JS file
        4. Parse each for endpoints, secrets, env vars, routes
        5. Return consolidated JSAnalysisResult
        """
        result = JSAnalysisResult(target_url=url)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
        }
        if extra_headers:
            headers.update(extra_headers)

        jar = aiohttp.CookieJar(unsafe=True)
        conn = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            headers=headers, cookie_jar=jar, connector=conn, timeout=timeout_cfg
        ) as session:
            # Inject cookies
            if cookies:
                for name, value in cookies.items():
                    from yarl import URL as YarlURL
                    jar.update_cookies({name: value}, response_url=YarlURL(url))

            # Step 1: Fetch HTML (or use provided)
            if html_content is None:
                html_content = await self._fetch_page(session, url)
                if not html_content:
                    logger.warning(f"[JSAnalyzer] Failed to fetch {url}")
                    return result

            # Step 2: Extract script URLs from HTML
            script_urls = self._extract_script_urls(html_content, base_url, url)
            result.script_urls = script_urls
            logger.info(f"[JSAnalyzer] Found {len(script_urls)} JS files on {parsed.netloc}")

            # Also check for inline __NEXT_DATA__ JSON
            self._parse_next_data(html_content, result)

            # Also check HTML for initial framework detection
            self._detect_framework_from_html(html_content, result)

            # Step 3: Download and analyze each JS file
            js_contents: List[Tuple[str, str]] = []
            tasks = []
            for js_url in script_urls[:self.max_js_files]:
                tasks.append(self._fetch_js(session, js_url))

            fetched = await asyncio.gather(*tasks, return_exceptions=True)
            for js_url, resp in zip(script_urls[:self.max_js_files], fetched):
                if isinstance(resp, Exception) or resp is None:
                    continue
                js_contents.append((js_url, resp))
                result.js_files_analyzed += 1
                result.total_js_bytes += len(resp)

            logger.info(
                f"[JSAnalyzer] Downloaded {result.js_files_analyzed} JS files "
                f"({result.total_js_bytes / 1024:.0f} KB) from {parsed.netloc}"
            )

            # Step 4: Analyze each JS file
            for js_url, js_code in js_contents:
                self._analyze_js_code(js_code, js_url, base_url, result)

            # Deduplicate
            self._deduplicate(result)

        logger.info(
            f"[JSAnalyzer] Analysis complete for {parsed.netloc}: "
            f"{len(result.api_endpoints)} API endpoints, "
            f"{len(result.secrets)} secrets, "
            f"{len(result.page_routes)} routes, "
            f"{len(result.graphql_endpoints)} GraphQL, "
            f"{len(result.websocket_urls)} WebSocket, "
            f"{len(result.env_vars)} env vars"
        )
        return result

    # ── HTTP helpers ──────────────────────────────────────────────────────

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch HTML page content."""
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "text/html" in ct or "application/xhtml" in ct:
                        return await resp.text(errors="replace")
        except Exception as e:
            logger.debug(f"[JSAnalyzer] Fetch HTML failed: {e}")
        return None

    async def _fetch_js(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch a JavaScript file."""
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                size = int(resp.headers.get("Content-Length", 0))
                if size > self.max_js_size:
                    logger.debug(f"[JSAnalyzer] Skipping oversized JS: {url} ({size} bytes)")
                    return None
                text = await resp.text(errors="replace")
                if len(text) > self.max_js_size:
                    return None
                return text
        except Exception as e:
            logger.debug(f"[JSAnalyzer] Fetch JS failed {url}: {e}")
        return None

    # ── HTML parsing ──────────────────────────────────────────────────────

    def _extract_script_urls(self, html: str, base_url: str, page_url: str) -> List[str]:
        """Extract all <script src="..."> URLs from HTML."""
        urls = []
        seen = set()

        # <script src="...">
        for m in re.finditer(r'''<script[^>]+src\s*=\s*["']([^"']+)["']''', html, re.IGNORECASE):
            src = m.group(1)
            full_url = self._resolve_url(src, base_url, page_url)
            if full_url and full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)

        # Also look for preload/prefetch links to JS
        for m in re.finditer(
            r'''<link[^>]+href\s*=\s*["']([^"']+\.js[^"']*)["'][^>]*(?:rel\s*=\s*["'](?:preload|prefetch|modulepreload)["'])''',
            html, re.IGNORECASE
        ):
            src = m.group(1)
            full_url = self._resolve_url(src, base_url, page_url)
            if full_url and full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)

        # Next.js buildManifest / _ssgManifest
        for m in re.finditer(r'''["'](_next/static/[^"']+\.js)["']''', html):
            src = m.group(1)
            full_url = self._resolve_url(src, base_url, page_url)
            if full_url and full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)

        return urls

    def _resolve_url(self, src: str, base_url: str, page_url: str) -> Optional[str]:
        """Resolve a script src to absolute URL."""
        if src.startswith("data:") or src.startswith("blob:"):
            return None
        if src.startswith("//"):
            return "https:" + src
        if src.startswith("http"):
            return src
        if src.startswith("/"):
            return base_url + src
        return urljoin(page_url, src)

    def _parse_next_data(self, html: str, result: JSAnalysisResult):
        """Extract routes and data from __NEXT_DATA__ JSON blob."""
        m = re.search(r'''<script\s+id="__NEXT_DATA__"\s+type="application/json"[^>]*>(.*?)</script>''', html, re.DOTALL)
        if not m:
            return

        try:
            data = json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            return

        result.framework = "next.js"

        # Extract page route
        if "page" in data:
            result.page_routes.append(data["page"])

        # Extract buildId (fingerprint)
        build_id = data.get("buildId", "")

        # Look for API routes in props
        self._extract_from_nested(data, result)

    def _extract_from_nested(self, obj, result: JSAnalysisResult, depth: int = 0):
        """Recursively extract URLs/secrets from nested JSON data."""
        if depth > 10:
            return

        if isinstance(obj, str):
            # Check for API endpoints
            if "/api/" in obj or obj.startswith("http"):
                if self._is_valid_endpoint(obj):
                    result.api_endpoints.append(JSEndpoint(url=obj, source_file="__NEXT_DATA__"))
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                # Key names that suggest secrets
                lower_k = k.lower()
                if any(s in lower_k for s in ("key", "token", "secret", "password", "api_key")):
                    if isinstance(v, str) and len(v) > 8:
                        result.secrets.append(JSSecret(
                            key_name=k, value=v, secret_type="nested_json_secret",
                            source_file="__NEXT_DATA__", confidence=0.6
                        ))
                self._extract_from_nested(v, result, depth + 1)
            return

        if isinstance(obj, list):
            for item in obj[:100]:  # limit
                self._extract_from_nested(item, result, depth + 1)

    def _detect_framework_from_html(self, html: str, result: JSAnalysisResult):
        """Detect framework from HTML meta tags and script patterns."""
        if "__NEXT_DATA__" in html or "_next/static" in html:
            result.framework = result.framework or "next.js"
        elif "__NUXT__" in html or "_nuxt/" in html:
            result.framework = result.framework or "nuxt"
        elif "ng-version" in html:
            result.framework = result.framework or "angular"

        # x-powered-by header would have been nice but we only have HTML here
        # Check for meta generator
        m = re.search(r'''<meta\s+name="generator"\s+content="([^"]+)"''', html, re.IGNORECASE)
        if m:
            gen = m.group(1).lower()
            if "next" in gen:
                result.framework = "next.js"
            elif "nuxt" in gen:
                result.framework = "nuxt"
            elif "gatsby" in gen:
                result.framework = "gatsby"

    # ── JS code analysis ──────────────────────────────────────────────────

    def _analyze_js_code(self, js_code: str, js_url: str, base_url: str, result: JSAnalysisResult):
        """Analyze a single JS file for endpoints, secrets, routes, etc."""
        # Framework detection
        self._detect_framework_from_js(js_code, result)
        self._detect_build_tool(js_code, result)

        # API endpoints
        self._extract_api_endpoints(js_code, js_url, base_url, result)

        # GraphQL
        self._extract_graphql(js_code, js_url, base_url, result)

        # WebSockets
        self._extract_websockets(js_code, js_url, result)

        # Secrets/tokens
        self._extract_secrets(js_code, js_url, result)

        # Environment variables
        self._extract_env_vars(js_code, js_url, result)

        # Page routes
        self._extract_routes(js_code, js_url, result)

        # Source maps
        self._check_source_maps(js_code, js_url, base_url, result)

    def _detect_framework_from_js(self, js_code: str, result: JSAnalysisResult):
        """Detect framework from JS code patterns."""
        if result.framework:
            return  # Already detected
        for framework, patterns in FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(js_code):
                    result.framework = framework
                    return

    def _detect_build_tool(self, js_code: str, result: JSAnalysisResult):
        """Detect build tool from JS code patterns."""
        if result.build_tool:
            return
        for tool, patterns in BUILD_TOOL_SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(js_code):
                    result.build_tool = tool
                    return

    def _extract_api_endpoints(self, js_code: str, js_url: str, base_url: str, result: JSAnalysisResult):
        """Extract API endpoints from fetch/axios/XHR calls."""
        for pattern in API_PATTERNS:
            for m in pattern.finditer(js_code):
                groups = m.groups()
                method = "GET"
                endpoint = ""

                if len(groups) == 2:
                    # axios.get/post or XHR .open("METHOD", "url")
                    method = groups[0].upper()
                    endpoint = groups[1]
                elif len(groups) == 1:
                    endpoint = groups[0]

                if not endpoint or not self._is_valid_endpoint(endpoint):
                    continue

                # Resolve relative URLs
                if endpoint.startswith("/"):
                    full_url = base_url + endpoint
                elif not endpoint.startswith("http"):
                    full_url = base_url + "/" + endpoint
                else:
                    full_url = endpoint

                # Extract context (surrounding code)
                start = max(0, m.start() - 100)
                end = min(len(js_code), m.end() + 100)
                context = js_code[start:end].strip()

                # Detect if auth is nearby
                auth_required = bool(re.search(
                    r'''(?:auth|bearer|token|cookie|session|credential|header)''',
                    context, re.IGNORECASE
                ))

                # Detect content type
                content_type = ""
                ct_match = re.search(r'''['" ](?:Content-Type|content-type)['" ]\s*[:=]\s*["']([^"']+)["']''', context)
                if ct_match:
                    content_type = ct_match.group(1)

                result.api_endpoints.append(JSEndpoint(
                    url=full_url,
                    method=method,
                    source_file=js_url,
                    context=context[:200],
                    auth_required=auth_required,
                    content_type=content_type,
                ))

    def _extract_graphql(self, js_code: str, js_url: str, base_url: str, result: JSAnalysisResult):
        """Extract GraphQL endpoints and query names."""
        for pattern in GRAPHQL_PATTERNS:
            for m in pattern.finditer(js_code):
                endpoint = m.group(1)
                if endpoint.startswith("/"):
                    endpoint = base_url + endpoint
                if endpoint not in result.graphql_endpoints:
                    result.graphql_endpoints.append(endpoint)

    def _extract_websockets(self, js_code: str, js_url: str, result: JSAnalysisResult):
        """Extract WebSocket URLs."""
        for pattern in WS_PATTERNS:
            for m in pattern.finditer(js_code):
                ws_url = m.group(1)
                if ws_url not in result.websocket_urls:
                    result.websocket_urls.append(ws_url)

    def _extract_secrets(self, js_code: str, js_url: str, result: JSAnalysisResult):
        """Extract hardcoded secrets and tokens from JS."""
        for pattern, secret_type in JS_SECRET_PATTERNS:
            for m in pattern.finditer(js_code):
                value = m.group(1) if m.lastindex else m.group(0)

                # Skip obviously fake/placeholder values
                if self._is_placeholder(value):
                    continue

                # Confidence scoring
                confidence = 0.7
                if secret_type in ("aws_access_key", "stripe_secret", "telegram_bot_token", "github_token"):
                    confidence = 0.95
                elif secret_type in ("firebase_api_key", "google_api_key", "sendgrid_api_key"):
                    confidence = 0.9
                elif secret_type == "generic_secret":
                    confidence = 0.4
                elif secret_type == "possible_aws_secret":
                    confidence = 0.3

                result.secrets.append(JSSecret(
                    key_name=secret_type,
                    value=value[:200],  # truncate for safety
                    secret_type=secret_type,
                    source_file=js_url,
                    confidence=confidence,
                ))

    def _extract_env_vars(self, js_code: str, js_url: str, result: JSAnalysisResult):
        """Extract environment variable references and values."""
        for pattern in ENV_VAR_PATTERNS:
            for m in pattern.finditer(js_code):
                groups = m.groups()
                if len(groups) == 2:
                    # Name + value
                    result.env_vars[groups[0]] = groups[1]
                elif len(groups) == 1:
                    # Just the name
                    result.env_vars.setdefault(groups[0], "")

    def _extract_routes(self, js_code: str, js_url: str, result: JSAnalysisResult):
        """Extract page routes from React Router / Next.js patterns."""
        for pattern in NEXTJS_ROUTE_PATTERNS:
            for m in pattern.finditer(js_code):
                route = m.group(1)
                # Validate that it looks like a route
                if (
                    route.startswith("/")
                    and not route.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico"))
                    and not any(p.search(route) for p in SKIP_ENDPOINT_PATTERNS)
                    and len(route) < 200
                    and route not in result.page_routes
                ):
                    result.page_routes.append(route)

    def _check_source_maps(self, js_code: str, js_url: str, base_url: str, result: JSAnalysisResult):
        """Check for source map references."""
        m = SOURCE_MAP_PATTERN.search(js_code)
        if m:
            map_url = m.group(1)
            if map_url.startswith("/"):
                map_url = base_url + map_url
            elif not map_url.startswith("http"):
                # Relative to JS file
                js_dir = js_url.rsplit("/", 1)[0]
                map_url = js_dir + "/" + map_url
            if map_url not in result.source_maps:
                result.source_maps.append(map_url)

    # ── Validation helpers ────────────────────────────────────────────────

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if an extracted string looks like a real API endpoint."""
        if not endpoint or len(endpoint) < 2 or len(endpoint) > 500:
            return False

        # Skip static assets, external CDNs, webpack internals
        for pattern in SKIP_ENDPOINT_PATTERNS:
            if pattern.search(endpoint):
                return False

        # Must have a path component or be a relative path
        if endpoint.startswith("http"):
            parsed = urlparse(endpoint)
            if not parsed.path or parsed.path == "/":
                return False

        return True

    def _is_placeholder(self, value: str) -> bool:
        """Check if a secret value is a placeholder/example."""
        lower = value.lower()
        placeholders = [
            "your_", "xxxx", "example", "test_", "demo", "placeholder",
            "change_me", "replace", "insert_", "todo", "fixme", "dummy",
            "sample", "0000000", "aaaaaaa", "123456",
        ]
        return any(p in lower for p in placeholders)

    # ── Deduplication ─────────────────────────────────────────────────────

    def _deduplicate(self, result: JSAnalysisResult):
        """Remove duplicate endpoints and secrets."""
        # Deduplicate API endpoints by URL+method
        seen_endpoints = set()
        unique_endpoints = []
        for ep in result.api_endpoints:
            key = (ep.url, ep.method)
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique_endpoints.append(ep)
        result.api_endpoints = unique_endpoints

        # Deduplicate secrets by value
        seen_secrets = set()
        unique_secrets = []
        for s in result.secrets:
            if s.value not in seen_secrets:
                seen_secrets.add(s.value)
                unique_secrets.append(s)
        result.secrets = unique_secrets

        # Deduplicate routes
        result.page_routes = list(dict.fromkeys(result.page_routes))

        # Deduplicate GraphQL
        result.graphql_endpoints = list(dict.fromkeys(result.graphql_endpoints))


# ── Convenience function ──────────────────────────────────────────────────────

async def analyze_js_bundles(
    url: str,
    cookies: Optional[Dict[str, str]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    html_content: Optional[str] = None,
) -> JSAnalysisResult:
    """Convenience wrapper — analyze JS bundles for a URL."""
    analyzer = JSBundleAnalyzer()
    return await analyzer.analyze(
        url=url,
        cookies=cookies,
        extra_headers=extra_headers,
        html_content=html_content,
    )
