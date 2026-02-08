"""
API Endpoint Bruteforcer — Discover hidden API routes on modern web apps

When JS bundle analysis + traditional crawling find nothing, this module
actively probes for common API endpoint patterns specific to each framework.

Features:
  - Framework-specific endpoint wordlists (Next.js, Django, Laravel, Express, Rails, FastAPI)
  - Common REST/GraphQL/WebSocket endpoint probing
  - Response analysis (status codes, content types, auth requirements)
  - IDOR detection (sequential ID probing)
  - Auth bypass testing (method switching, header manipulation, path traversal)
  - Rate-limit aware (adaptive delay)
  - Supports authenticated probing (session cookies / Bearer tokens)

v3.16 — Phase: SPA/API Intelligence
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp
from loguru import logger


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    """Result of probing a single endpoint."""
    url: str
    method: str
    status: int
    content_type: str = ""
    content_length: int = 0
    body_preview: str = ""          # First 500 chars
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False     # 401/403 response
    redirect_url: str = ""          # If 301/302/307/308
    interesting: bool = False       # Worth investigating further
    reason: str = ""                # Why it's interesting
    response_time_ms: float = 0.0


@dataclass
class BruteforceResult:
    """Complete results from API endpoint bruteforcing."""
    target_url: str
    framework: str = ""
    endpoints_probed: int = 0
    endpoints_found: List[ProbeResult] = field(default_factory=list)
    auth_endpoints: List[ProbeResult] = field(default_factory=list)
    open_endpoints: List[ProbeResult] = field(default_factory=list)
    graphql_found: bool = False
    graphql_introspection: bool = False  # If introspection query succeeds
    interesting_headers: Dict[str, str] = field(default_factory=dict)
    openapi_spec_url: str = ""       # URL of discovered OpenAPI/Swagger spec
    openapi_endpoints: List[Dict] = field(default_factory=list)  # Parsed API endpoints from spec
    error: str = ""


# ── Endpoint wordlists per framework ─────────────────────────────────────────

# Common API paths that work across frameworks
COMMON_API_PATHS = [
    # Health / Info
    "/api/health", "/api/status", "/api/info", "/api/version",
    "/api/ping", "/health", "/healthz", "/ready", "/readyz",
    "/api/v1/health", "/api/v2/health",
    "/.well-known/openid-configuration",

    # Auth endpoints
    "/api/auth", "/api/auth/login", "/api/auth/register", "/api/auth/signup",
    "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/auth/verify", "/api/auth/refresh", "/api/auth/logout",
    "/api/auth/me", "/api/auth/session", "/api/auth/callback",
    "/api/auth/providers", "/api/auth/csrf",
    "/api/login", "/api/register", "/api/signup",
    "/auth/login", "/auth/register", "/auth/callback",
    "/login", "/register", "/signup",

    # User endpoints
    "/api/user", "/api/users", "/api/user/me", "/api/user/profile",
    "/api/users/1", "/api/users/admin",
    "/api/v1/user", "/api/v1/users",
    "/api/account", "/api/profile",

    # Admin endpoints
    "/api/admin", "/admin", "/api/admin/users", "/api/admin/settings",
    "/api/admin/config", "/api/admin/dashboard",
    "/admin/login", "/administrator",
    "/_admin", "/api/internal",

    # Data / CRUD
    "/api/data", "/api/items", "/api/products", "/api/orders",
    "/api/posts", "/api/comments", "/api/search",
    "/api/upload", "/api/download", "/api/export", "/api/import",
    "/api/config", "/api/settings",

    # Payment / Billing
    "/api/payment", "/api/payments", "/api/billing",
    "/api/checkout", "/api/subscription", "/api/plan",
    "/api/webhook", "/api/webhooks",
    "/api/stripe", "/api/stripe/webhook",

    # GraphQL
    "/graphql", "/api/graphql", "/__graphql",
    "/graphql/playground", "/graphql/console",
    "/graphiql", "/altair",

    # Swagger / API Docs (expanded)
    "/swagger.json", "/openapi.json", "/api-docs",
    "/api-docs/openapi.json", "/api-docs/swagger.json",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/docs", "/api/docs", "/redoc",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/.well-known/openapi.json",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/api-docs/", "/api-docs.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/swagger/v1/swagger.json", "/api/swagger/v2/swagger.json",
    "/openapi/v3/api-docs", "/openapi/v3/api-docs.json",
    "/api/schema", "/api/schema.json", "/schema.json",

    # Debug / Internal
    "/debug", "/api/debug", "/_debug",
    "/trace", "/metrics", "/api/metrics",
    "/env", "/api/env", "/config",
    "/.env", "/phpinfo.php",
    "/server-status", "/server-info",

    # Common file leaks  
    "/robots.txt", "/sitemap.xml", "/.git/HEAD",
    "/.git/config", "/.svn/entries", "/.DS_Store",
    "/wp-config.php", "/config.php", "/database.yml",
    "/Dockerfile", "/docker-compose.yml",
    "/.github/workflows", "/package.json",
]

# Next.js specific
NEXTJS_API_PATHS = [
    "/api/auth/[...nextauth]", "/api/auth/providers",
    "/api/auth/csrf", "/api/auth/session",
    "/api/auth/signin", "/api/auth/signout",
    "/api/auth/callback", "/api/auth/error",
    "/api/trpc", "/api/trpc/[trpc]",
    "/_next/data", "/_next/image",
    "/api/revalidate", "/api/preview",
    "/api/draft", "/api/og",
]

# Django / DRF
DJANGO_API_PATHS = [
    "/admin/", "/admin/login/", "/api/v1/",
    "/api/token/", "/api/token/refresh/",
    "/accounts/login/", "/accounts/signup/",
    "/rest-auth/", "/dj-rest-auth/",
    "/__debug__/", "/silk/",
    "/api/schema/", "/api/schema/swagger-ui/",
    "/api/schema/redoc/",
]

# Laravel
LARAVEL_API_PATHS = [
    "/api/v1/", "/sanctum/csrf-cookie",
    "/oauth/token", "/oauth/authorize",
    "/telescope", "/horizon",
    "/_ignition/health-check",
    "/storage/", "/public/storage/",
    "/.env", "/artisan",
]

# Express / Node.js
EXPRESS_API_PATHS = [
    "/api/v1/", "/api/v2/",
    "/auth/google", "/auth/github", "/auth/facebook",
    "/socket.io/", "/ws",
    "/api/upload", "/api/file",
    "/__coverage__",
]

# Rails
RAILS_API_PATHS = [
    "/rails/info", "/rails/info/routes",
    "/rails/mailers", "/sidekiq",
    "/api/v1/", "/users/sign_in", "/users/sign_up",
    "/cable", "/action_cable",
]

# FastAPI / Starlette
FASTAPI_API_PATHS = [
    "/docs", "/redoc", "/openapi.json",
    "/api/v1/", "/token",
    "/ws/", "/websocket",
]

# Framework map
FRAMEWORK_PATHS = {
    "next.js": NEXTJS_API_PATHS,
    "react": [],  # React doesn't define API routes
    "django": DJANGO_API_PATHS,
    "laravel": LARAVEL_API_PATHS,
    "express": EXPRESS_API_PATHS,
    "rails": RAILS_API_PATHS,
    "fastapi": FASTAPI_API_PATHS,
}

# GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name kind description fields { name type { name kind } } } } }"
})

# Methods to try
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Auth bypass headers
AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]


# ── Bruteforcer class ─────────────────────────────────────────────────────────

class APIBruteforcer:
    """Probe for hidden API endpoints on modern web applications."""

    def __init__(
        self,
        timeout: int = 15,
        max_concurrent: int = 5,
        delay: float = 0.3,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay = delay
        self.user_agent = user_agent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._rate_limited = False
        self._current_delay = delay

    # ── Main entry ────────────────────────────────────────────────────────

    async def bruteforce(
        self,
        url: str,
        framework: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        custom_paths: Optional[List[str]] = None,
        try_auth_bypass: bool = True,
        try_graphql_introspection: bool = True,
        try_method_switching: bool = True,
    ) -> BruteforceResult:
        """
        Bruteforce API endpoints on a target URL.

        1. Build path list (common + framework-specific + custom)
        2. Probe each path with GET
        3. For 401/403 responses, try auth bypass techniques
        4. For GraphQL endpoints, try introspection
        5. For found endpoints, try method switching
        """
        result = BruteforceResult(target_url=url, framework=framework)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Build path list
        paths = list(COMMON_API_PATHS)
        if framework and framework in FRAMEWORK_PATHS:
            paths.extend(FRAMEWORK_PATHS[framework])
        if custom_paths:
            paths.extend(custom_paths)

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
        paths = unique_paths

        logger.info(f"[APIBrute] Probing {len(paths)} endpoints on {parsed.netloc} (framework: {framework or 'unknown'})")

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if extra_headers:
            headers.update(extra_headers)

        jar = aiohttp.CookieJar(unsafe=True)
        conn = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrent)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(
            headers=headers, cookie_jar=jar, connector=conn, timeout=timeout_cfg
        ) as session:
            # Inject cookies
            if cookies:
                for name, value in cookies.items():
                    from yarl import URL as YarlURL
                    jar.update_cookies({name: value}, response_url=YarlURL(url))

            # Phase 1: Initial probe of all paths (GET)
            tasks = []
            for path in paths:
                probe_url = base_url + path
                tasks.append(self._probe_endpoint(session, probe_url, "GET"))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for probe in results:
                if isinstance(probe, Exception) or probe is None:
                    continue
                result.endpoints_probed += 1

                if probe.interesting:
                    result.endpoints_found.append(probe)

                    if probe.auth_required:
                        result.auth_endpoints.append(probe)
                    else:
                        result.open_endpoints.append(probe)

                    # Collect interesting headers
                    for h in ("x-powered-by", "server", "x-request-id", "x-trace-id"):
                        if h in probe.headers:
                            result.interesting_headers[h] = probe.headers[h]

            logger.info(
                f"[APIBrute] Phase 1 complete: {result.endpoints_probed} probed, "
                f"{len(result.endpoints_found)} found ({len(result.open_endpoints)} open, "
                f"{len(result.auth_endpoints)} auth-required)"
            )

            # Phase 1.5: OpenAPI / Swagger spec discovery
            # Try fetching homepage HTML to detect Swagger UI
            try:
                homepage_html = ""
                async with session.get(base_url + "/", allow_redirects=True) as resp:
                    if resp.status == 200:
                        homepage_html = await resp.text(errors="replace")
                await self._discover_and_parse_spec(session, base_url, homepage_html, result)
            except Exception as e:
                logger.debug(f"[APIBrute] OpenAPI discovery error: {e}")

            # Also check if any Phase-1 probe returned a spec body
            if not result.openapi_spec_url:
                for probe in list(result.endpoints_found):
                    preview = probe.body_preview.lower()
                    if preview and any(kw in preview for kw in ('"openapi"', '"swagger"', '"paths"')):
                        try:
                            # Re-fetch full body to parse spec
                            async with session.get(probe.url, allow_redirects=True) as resp2:
                                if resp2.status == 200:
                                    import json as _json
                                    full_body = await resp2.text(errors="replace")
                                    spec_data = _json.loads(full_body)
                                    if spec_data.get("openapi") or spec_data.get("swagger") or spec_data.get("paths"):
                                        result.openapi_spec_url = probe.url
                                        result.openapi_endpoints = self._parse_openapi_spec(spec_data, base_url)
                                        logger.info(
                                            f"[APIBrute] 📋 OpenAPI spec from probe {probe.url}: "
                                            f"{len(result.openapi_endpoints)} endpoints"
                                        )
                                        break
                        except Exception:
                            pass

            # Phase 2: GraphQL introspection
            if try_graphql_introspection:
                graphql_urls = [base_url + p for p in ("/graphql", "/api/graphql", "/__graphql", "/graphiql")]
                for gql_url in graphql_urls:
                    intro_result = await self._try_graphql_introspection(session, gql_url)
                    if intro_result:
                        result.graphql_found = True
                        result.graphql_introspection = True
                        result.endpoints_found.append(intro_result)
                        result.open_endpoints.append(intro_result)
                        logger.info(f"[APIBrute] 🎯 GraphQL introspection successful: {gql_url}")
                        break

            # Phase 3: Auth bypass on 401/403 endpoints
            if try_auth_bypass and result.auth_endpoints:
                bypassed = await self._try_auth_bypass(session, result.auth_endpoints[:10])
                for bp in bypassed:
                    result.open_endpoints.append(bp)
                    result.endpoints_found.append(bp)

            # Phase 4: Method switching on found endpoints
            if try_method_switching and result.auth_endpoints:
                switched = await self._try_method_switching(session, result.auth_endpoints[:10])
                for sw in switched:
                    result.open_endpoints.append(sw)
                    result.endpoints_found.append(sw)

        logger.info(
            f"[APIBrute] Complete for {parsed.netloc}: "
            f"{len(result.endpoints_found)} endpoints found, "
            f"{len(result.open_endpoints)} open, "
            f"graphql={'yes' if result.graphql_found else 'no'}, "
            f"openapi={'yes (' + str(len(result.openapi_endpoints)) + ' endpoints)' if result.openapi_spec_url else 'no'}"
        )
        return result

    # ── Probing ───────────────────────────────────────────────────────────

    async def _probe_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        extra_headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Optional[ProbeResult]:
        """Probe a single endpoint and analyze the response."""
        async with self._semaphore:
            # Rate limiting
            if self._rate_limited:
                await asyncio.sleep(self._current_delay * 3)
            else:
                await asyncio.sleep(self._current_delay)

            try:
                start = time.monotonic()
                kwargs = {"allow_redirects": False}
                if extra_headers:
                    kwargs["headers"] = extra_headers
                if body:
                    kwargs["data"] = body

                async with session.request(method, url, **kwargs) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    ct = resp.headers.get("Content-Type", "")
                    cl = int(resp.headers.get("Content-Length", 0))

                    # Read body for analysis
                    body_text = ""
                    try:
                        body_text = await resp.text(errors="replace")
                        cl = cl or len(body_text)
                    except Exception:
                        pass

                    # Build headers dict
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    # Handle 429 rate limiting
                    if resp.status == 429:
                        self._rate_limited = True
                        self._current_delay = min(self._current_delay * 2, 10.0)
                        return None

                    probe = ProbeResult(
                        url=url,
                        method=method,
                        status=resp.status,
                        content_type=ct,
                        content_length=cl,
                        body_preview=body_text[:500],
                        headers=resp_headers,
                        auth_required=(resp.status in (401, 403)),
                        redirect_url=resp.headers.get("Location", ""),
                        response_time_ms=elapsed,
                    )

                    # Determine if interesting
                    probe.interesting, probe.reason = self._assess_interest(probe, body_text)
                    return probe

            except asyncio.TimeoutError:
                return None
            except Exception as e:
                logger.debug(f"[APIBrute] Probe error {method} {url}: {e}")
                return None

    def _assess_interest(self, probe: ProbeResult, body: str) -> Tuple[bool, str]:
        """Determine if a probe result is worth reporting."""
        status = probe.status

        # Definitely not interesting
        if status in (404, 405, 502, 503, 504):
            # But 405 might reveal what methods ARE allowed
            if status == 405 and "allow" in probe.headers:
                return True, f"Method not allowed but reveals allowed methods: {probe.headers['allow']}"
            return False, ""

        # Redirect to login / auth page
        if status in (301, 302, 307, 308):
            redir = probe.redirect_url.lower()
            if any(kw in redir for kw in ("login", "signin", "auth", "authenticate")):
                return True, f"Redirects to auth: {probe.redirect_url}"
            return False, ""

        # Auth required — interesting (we know the endpoint exists)
        if status == 401:
            return True, "401 Unauthorized — endpoint exists but requires auth"
        if status == 403:
            return True, "403 Forbidden — endpoint exists but access denied"

        # 200 OK — definitely interesting
        if status == 200:
            # JSON response
            if "application/json" in probe.content_type:
                return True, "200 OK with JSON response"
            # HTML but might be an API error page
            if probe.content_length < 200 and body.strip():
                return True, f"200 OK with small response ({probe.content_length} bytes)"
            # Non-trivial content
            if probe.content_length > 0 and "text/html" not in probe.content_type:
                return True, f"200 OK with {probe.content_type}"
            # Check for data in HTML
            if "text/html" in probe.content_type:
                # Don't flag generic marketing/login pages
                if any(kw in body.lower() for kw in ("api", "endpoint", "swagger", "schema", "graphql", "debug", "admin")):
                    return True, "200 OK HTML with API-related content"
                return False, ""
            return True, "200 OK"

        # Other 2xx
        if 200 <= status < 300:
            return True, f"{status} success response"

        return False, ""

    # ── OpenAPI / Swagger spec parsing ────────────────────────────────────

    def _extract_swagger_spec_url(self, html: str, base_url: str) -> Optional[str]:
        """Extract OpenAPI/Swagger spec URL from Swagger UI HTML pages."""
        from urllib.parse import urljoin
        patterns = [
            # SwaggerUIBundle({ url: "..." })
            re.compile(r'SwaggerUIBundle\s*\(\s*\{[^}]*?url\s*:\s*["\']([^"\']+)["\']', re.DOTALL | re.I),
            # swaggerUi.url = "..."
            re.compile(r'swagger(?:Ui|UI)\s*\.\s*url\s*=\s*["\']([^"\']+)["\']', re.I),
            # spec-url="..." or specUrl="..."
            re.compile(r'(?:spec[_-]?url|specUrl|configUrl)\s*[=:]\s*["\']([^"\']+)["\']', re.I),
            # url: "/api-docs/openapi.json"  (generic JS object)
            re.compile(r'["\']?url["\']?\s*:\s*["\']([^"\']*(?:swagger|openapi|api-docs)[^"\']*\.(?:json|yaml|yml))["\']', re.I),
            # Direct link to spec files
            re.compile(r'href=["\']([^"\']*(?:swagger|openapi|api-docs)[^"\']*\.(?:json|yaml|yml))["\']', re.I),
        ]
        for pat in patterns:
            m = pat.search(html)
            if m:
                spec_url = m.group(1)
                if not spec_url.startswith(("http://", "https://")):
                    spec_url = urljoin(base_url, spec_url)
                return spec_url
        return None

    def _parse_openapi_spec(self, spec_data: dict, base_url: str) -> List[Dict]:
        """Parse an OpenAPI/Swagger spec and extract all endpoint definitions.

        Returns list of dicts: {path, method, summary, parameters, auth_required, tags}
        """
        from urllib.parse import urljoin
        endpoints = []

        # Get servers/basePath
        servers = spec_data.get("servers", [])
        base_path = ""
        if servers:
            server_url = servers[0].get("url", "")
            if server_url and not server_url.startswith(("http://", "https://")):
                base_path = server_url.rstrip("/")
        # Swagger 2.0 basePath
        if not base_path:
            base_path = spec_data.get("basePath", "").rstrip("/")

        paths = spec_data.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method_upper = method.upper()
                if method_upper not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                    continue
                if not isinstance(details, dict):
                    continue

                full_path = base_path + path

                # Check if auth is required
                auth_required = bool(details.get("security")) or bool(
                    spec_data.get("security") and not details.get("security") == []
                )

                # Extract parameters
                params = []
                for p in details.get("parameters", []):
                    if isinstance(p, dict):
                        params.append({
                            "name": p.get("name", ""),
                            "in": p.get("in", ""),
                            "required": p.get("required", False),
                            "type": p.get("schema", {}).get("type", "") if isinstance(p.get("schema"), dict) else "",
                        })

                endpoints.append({
                    "path": full_path,
                    "method": method_upper,
                    "summary": details.get("summary", ""),
                    "description": details.get("description", "")[:200],
                    "parameters": params,
                    "auth_required": auth_required,
                    "tags": details.get("tags", []),
                })

        return endpoints

    async def _discover_and_parse_spec(
        self, session: aiohttp.ClientSession, base_url: str, html_content: str,
        result: "BruteforceResult",
    ) -> None:
        """Discover OpenAPI/Swagger spec and parse endpoints from it."""
        import json as _json

        # Try to extract spec URL from HTML (Swagger UI detection)
        spec_url = self._extract_swagger_spec_url(html_content, base_url)

        if not spec_url:
            # Try common spec file locations
            spec_paths = [
                "/api-docs/openapi.json", "/api-docs/swagger.json",
                "/swagger.json", "/openapi.json",
                "/api-docs.json", "/api/openapi.json", "/api/swagger.json",
                "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
                "/api-docs/", "/swagger/v1/swagger.json",
            ]
            for path in spec_paths:
                probe_url = base_url + path
                try:
                    async with session.get(probe_url, allow_redirects=True) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("Content-Type", "")
                            if "json" in ct or "yaml" in ct or path.endswith(".json"):
                                spec_url = probe_url
                                break
                except Exception:
                    continue

        if not spec_url:
            return

        # Fetch and parse the spec
        try:
            async with session.get(spec_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return
                body = await resp.text(errors="replace")
                try:
                    spec_data = _json.loads(body)
                except (ValueError, _json.JSONDecodeError):
                    return

                # Validate it looks like an OpenAPI/Swagger spec
                if not (spec_data.get("openapi") or spec_data.get("swagger") or spec_data.get("paths")):
                    return

                result.openapi_spec_url = spec_url
                result.openapi_endpoints = self._parse_openapi_spec(spec_data, base_url)

                logger.info(
                    f"[APIBrute] 📋 OpenAPI spec found at {spec_url}: "
                    f"{len(result.openapi_endpoints)} endpoints parsed"
                )

                # Also create ProbeResult entries for each open endpoint
                for ep in result.openapi_endpoints:
                    probe = ProbeResult(
                        url=base_url + ep["path"],
                        method=ep["method"],
                        status=200,
                        content_type="application/json",
                        interesting=True,
                        reason=f"OpenAPI spec: {ep['summary'] or ep['path']}",
                    )
                    if ep["auth_required"]:
                        result.auth_endpoints.append(probe)
                    else:
                        result.open_endpoints.append(probe)
                    result.endpoints_found.append(probe)

        except Exception as e:
            logger.debug(f"[APIBrute] Spec parse error ({spec_url}): {e}")

    # ── GraphQL introspection ─────────────────────────────────────────────

    async def _try_graphql_introspection(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[ProbeResult]:
        """Try GraphQL introspection query."""
        try:
            async with session.post(
                url,
                data=GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            ) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="replace")
                    if "__schema" in body or "types" in body:
                        return ProbeResult(
                            url=url,
                            method="POST",
                            status=200,
                            content_type="application/json",
                            body_preview=body[:500],
                            interesting=True,
                            reason="🎯 GraphQL introspection OPEN — full schema exposed",
                        )
        except Exception:
            pass
        return None

    # ── Auth bypass ───────────────────────────────────────────────────────

    async def _try_auth_bypass(
        self, session: aiohttp.ClientSession, auth_endpoints: List[ProbeResult]
    ) -> List[ProbeResult]:
        """Try common auth bypass techniques on 401/403 endpoints."""
        bypassed = []

        for ep in auth_endpoints:
            parsed = urlparse(ep.url)

            # Technique 1: Header-based bypasses
            for bypass_headers in AUTH_BYPASS_HEADERS:
                probe = await self._probe_endpoint(
                    session, ep.url, "GET", extra_headers=bypass_headers
                )
                if probe and probe.status == 200:
                    probe.reason = f"🔓 AUTH BYPASS via {list(bypass_headers.keys())[0]}"
                    probe.interesting = True
                    bypassed.append(probe)
                    break

            # Technique 2: Path manipulation
            path_variants = [
                ep.url + "/",
                ep.url + "/.",
                ep.url + "%00",
                ep.url + "%0a",
                ep.url + "?",
                ep.url + "#",
                ep.url + ";",
                ep.url.replace(parsed.path, parsed.path + "..;/"),
            ]
            for variant in path_variants:
                probe = await self._probe_endpoint(session, variant, "GET")
                if probe and probe.status == 200 and not probe.auth_required:
                    probe.reason = f"🔓 AUTH BYPASS via path manipulation: {variant}"
                    probe.interesting = True
                    bypassed.append(probe)
                    break

        if bypassed:
            logger.info(f"[APIBrute] 🔓 Auth bypassed on {len(bypassed)} endpoints")
        return bypassed

    # ── Method switching ──────────────────────────────────────────────────

    async def _try_method_switching(
        self, session: aiohttp.ClientSession, auth_endpoints: List[ProbeResult]
    ) -> List[ProbeResult]:
        """Try different HTTP methods on auth-required endpoints."""
        switched = []

        for ep in auth_endpoints:
            for method in ("POST", "PUT", "PATCH", "OPTIONS", "HEAD"):
                if method == ep.method:
                    continue
                probe = await self._probe_endpoint(session, ep.url, method)
                if probe and not probe.auth_required and probe.interesting:
                    probe.reason = f"🔀 Method switch: {ep.method}→{method} bypasses auth"
                    switched.append(probe)
                    break

        if switched:
            logger.info(f"[APIBrute] 🔀 Method switching found {len(switched)} bypasses")
        return switched


# ── Convenience function ──────────────────────────────────────────────────────

async def bruteforce_api(
    url: str,
    framework: str = "",
    cookies: Optional[Dict[str, str]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    custom_paths: Optional[List[str]] = None,
) -> BruteforceResult:
    """Convenience wrapper — bruteforce API endpoints on a URL."""
    bruter = APIBruteforcer()
    return await bruter.bruteforce(
        url=url,
        framework=framework,
        cookies=cookies,
        extra_headers=extra_headers,
        custom_paths=custom_paths,
    )
