"""
MedyDorker v3.9 — Recursive BFS Crawler with Depth Control

BFS crawler with configurable depth limit, smart page prioritization,
concurrent fetching, proxy rotation, and structured result collection.

Replaces all flat crawl logic across the pipeline with a single
shared crawler that secret_extractor, cookie_hunter, ecommerce_checker,
and the SQLi scanner can all consume.
"""

import asyncio
import hashlib
import heapq
import logging
import re
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)
from urllib.parse import (
    parse_qs,
    urljoin,
    urlparse,
    urlunparse,
)

import aiohttp

logger = logging.getLogger("recursive_crawler")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class CrawlPage:
    """Single crawled page with all extracted data."""

    url: str
    depth: int
    status_code: int = 0
    content_type: str = ""
    html: str = ""
    title: str = ""
    links_found: int = 0
    forms: List[Dict[str, Any]] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    scripts: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    fetch_time: float = 0.0


@dataclass
class CrawlResult:
    """Aggregate result of a full recursive crawl."""

    seed_url: str
    domain: str
    pages: List[CrawlPage] = field(default_factory=list)
    all_urls: Set[str] = field(default_factory=set)
    param_urls: Set[str] = field(default_factory=set)
    form_targets: List[Dict[str, Any]] = field(default_factory=list)
    all_cookies: Dict[str, str] = field(default_factory=dict)
    b3_cookies: Dict[str, str] = field(default_factory=dict)
    script_urls: Set[str] = field(default_factory=set)
    max_depth_reached: int = 0
    total_fetched: int = 0
    elapsed: float = 0.0
    errors: int = 0

    @property
    def html_pages(self) -> List[CrawlPage]:
        """Only pages with HTML content (excludes errors, non-HTML)."""
        return [p for p in self.pages if p.html]

    @property
    def pages_by_depth(self) -> Dict[int, List[CrawlPage]]:
        """Group pages by crawl depth."""
        out: Dict[int, List[CrawlPage]] = {}
        for p in self.pages:
            out.setdefault(p.depth, []).append(p)
        return out


# ═══════════════════════════════════════════════════════════════
#   PAGE PRIORITY SCORING
# ═══════════════════════════════════════════════════════════════

# Higher score = crawled sooner (priority queue uses negated scores)
PRIORITY_KEYWORDS: Dict[str, int] = {
    # Payment & checkout — highest value
    "checkout": 50,
    "payment": 50,
    "pay": 45,
    "cart": 45,
    "basket": 45,
    "billing": 45,
    "donate": 40,
    "subscribe": 40,
    "purchase": 40,
    "order": 38,
    "invoice": 38,
    "transaction": 35,
    "receipt": 35,
    # Credentials & admin
    "login": 40,
    "signin": 40,
    "sign-in": 40,
    "admin": 42,
    "wp-admin": 44,
    "administrator": 42,
    "dashboard": 38,
    "account": 35,
    "my-account": 36,
    "register": 30,
    "signup": 30,
    "sign-up": 30,
    "profile": 28,
    "password": 35,
    "reset": 25,
    # API & config
    "api": 35,
    "graphql": 35,
    "wp-json": 38,
    "rest": 30,
    "config": 32,
    "configuration": 32,
    "settings": 30,
    "setup": 28,
    ".env": 40,
    "debug": 30,
    # Database / data
    "database": 35,
    "phpmyadmin": 40,
    "adminer": 38,
    "sql": 30,
    "dump": 30,
    "backup": 35,
    "export": 28,
    # E-commerce specifics
    "shop": 30,
    "store": 28,
    "product": 25,
    "catalog": 25,
    "woocommerce": 35,
    "shopify": 35,
    "magento": 35,
    "prestashop": 35,
    "opencart": 35,
    # Sensitive files
    "sitemap": 20,
    "robots.txt": 18,
    "xmlrpc": 28,
    "wp-login": 40,
    "wp-cron": 25,
    "install": 30,
    "upgrade": 25,
}

# URL params that indicate high-value targets (SQLi etc.)
HIGH_VALUE_PARAMS = {
    "id", "cat", "pid", "item", "product", "page", "article",
    "news", "view", "category", "show", "select", "report",
    "action", "file", "path", "user", "name", "search",
    "query", "q", "s", "key", "token", "redirect", "url",
    "ref", "next", "return", "callback", "download", "type",
}

# B3 tracing cookie names
B3_COOKIE_NAMES = {
    "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
    "x-b3-sampled", "x-b3-flags", "b3",
}


def score_url(url: str) -> int:
    """Compute a priority score for a URL. Higher = more interesting."""
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    query_lower = parsed.query.lower()
    full_lower = url.lower()
    score = 0

    # Keyword scoring on path
    for kw, pts in PRIORITY_KEYWORDS.items():
        if kw in path_lower:
            score += pts

    # Query params scoring
    if parsed.query:
        score += 15  # Any params = SQLi potential
        params = parse_qs(parsed.query)
        for pname in params:
            if pname.lower() in HIGH_VALUE_PARAMS:
                score += 12

    # Depth penalty: deeper paths = slightly lower priority at equal score
    depth = len([s for s in parsed.path.split("/") if s])
    score -= depth * 2

    # File extension hints
    if path_lower.endswith((".php", ".asp", ".aspx", ".jsp", ".cgi")):
        score += 10  # Dynamic pages
    elif path_lower.endswith((".json", ".xml", ".yml", ".yaml")):
        score += 8  # Config files
    elif path_lower.endswith((".js",)):
        score += 5
    elif path_lower.endswith((".css", ".png", ".jpg", ".jpeg", ".gif",
                              ".svg", ".ico", ".woff", ".woff2", ".ttf",
                              ".eot", ".mp4", ".mp3", ".pdf", ".zip",
                              ".tar", ".gz", ".rar")):
        score -= 50  # Static assets — deprioritize heavily

    return score


# ═══════════════════════════════════════════════════════════════
#   URL NORMALIZATION
# ═══════════════════════════════════════════════════════════════

# Extensions to skip entirely
SKIP_EXTENSIONS = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
    ".exe", ".dll", ".bin", ".iso", ".dmg",
    ".map", ".webp", ".avif",
}


def normalize_url(url: str, base_domain: str) -> Optional[str]:
    """
    Normalize a URL for dedup. Returns None if the URL should be skipped.
    - Strips fragments
    - Strips trailing slashes on path
    - Lowercases scheme + host
    - Skips non-HTTP, off-domain, mailto, tel, javascript, data URIs
    - Skips static asset extensions
    """
    url = url.strip()

    # Skip non-link schemes
    if url.startswith(("mailto:", "tel:", "javascript:", "data:", "#", "ftp:")):
        return None

    parsed = urlparse(url)

    # Must be http(s) or protocol-relative
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return None

    # Domain filter
    host = parsed.netloc.lower().split(":")[0]  # strip port for comparison
    base = base_domain.lower().split(":")[0]
    if host and host != base:
        return None

    # Extension filter
    path = parsed.path
    for ext in SKIP_EXTENSIONS:
        if path.lower().endswith(ext):
            return None

    # Rebuild clean URL (strip fragment, normalize)
    clean_path = path.rstrip("/") or "/"
    clean = urlunparse((
        parsed.scheme.lower() or "https",
        parsed.netloc.lower(),
        clean_path,
        parsed.params,
        parsed.query,
        "",  # no fragment
    ))
    return clean


# ═══════════════════════════════════════════════════════════════
#   LINK EXTRACTOR
# ═══════════════════════════════════════════════════════════════

# Regex-based link extraction (faster than BeautifulSoup for large pages)
RE_HREF = re.compile(
    r'''(?:href|src|action)\s*=\s*["']([^"'#][^"']{0,500})["']''',
    re.IGNORECASE,
)
RE_META_REFRESH = re.compile(
    r'''<meta[^>]+content\s*=\s*["']\d+;\s*url=([^"']+)["']''',
    re.IGNORECASE,
)
RE_JS_REDIRECT = re.compile(
    r'''(?:window\.location|location\.href|location\.replace)\s*[=\(]\s*["']([^"']+)["']''',
    re.IGNORECASE,
)
RE_FORM = re.compile(
    r"<form[^>]*>.*?</form>",
    re.IGNORECASE | re.DOTALL,
)
RE_FORM_ACTION = re.compile(
    r'''action\s*=\s*["']([^"']*)["']''',
    re.IGNORECASE,
)
RE_INPUT_NAME = re.compile(
    r'''<(?:input|select|textarea)[^>]+name\s*=\s*["']([^"']+)["']''',
    re.IGNORECASE,
)
RE_FORM_METHOD = re.compile(
    r'''method\s*=\s*["'](\w+)["']''',
    re.IGNORECASE,
)
RE_SCRIPT_SRC = re.compile(
    r'''<script[^>]+src\s*=\s*["']([^"']+)["']''',
    re.IGNORECASE,
)
RE_TITLE = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.IGNORECASE | re.DOTALL,
)


def extract_links(html: str, page_url: str, base_domain: str) -> Tuple[
    Set[str], List[Dict[str, Any]], Set[str]
]:
    """
    Extract links, forms, and script URLs from HTML.

    Returns:
        (link_urls, forms, script_urls)
        - link_urls: set of normalized same-domain URLs
        - forms: list of {action, method, inputs} dicts
        - script_urls: set of same-domain script URLs
    """
    links: Set[str] = set()
    forms: List[Dict[str, Any]] = []
    scripts: Set[str] = set()

    # -- Links from href/src/action attributes --
    for match in RE_HREF.finditer(html):
        raw = match.group(1)
        full = urljoin(page_url, raw)
        norm = normalize_url(full, base_domain)
        if norm:
            links.add(norm)

    # -- Meta refresh redirects --
    for match in RE_META_REFRESH.finditer(html):
        full = urljoin(page_url, match.group(1))
        norm = normalize_url(full, base_domain)
        if norm:
            links.add(norm)

    # -- JS location redirects --
    for match in RE_JS_REDIRECT.finditer(html):
        full = urljoin(page_url, match.group(1))
        norm = normalize_url(full, base_domain)
        if norm:
            links.add(norm)

    # -- Forms --
    for form_match in RE_FORM.finditer(html):
        form_html = form_match.group(0)
        action_m = RE_FORM_ACTION.search(form_html)
        method_m = RE_FORM_METHOD.search(form_html)

        action = urljoin(page_url, action_m.group(1)) if action_m else page_url
        method = (method_m.group(1).upper() if method_m else "GET")
        inputs = RE_INPUT_NAME.findall(form_html)

        norm_action = normalize_url(action, base_domain)
        if norm_action and inputs:
            forms.append({
                "action": norm_action,
                "method": method,
                "inputs": inputs,
                "source_page": page_url,
            })
            # Also add the action URL as a link
            links.add(norm_action)

    # -- Script sources --
    for match in RE_SCRIPT_SRC.finditer(html):
        full = urljoin(page_url, match.group(1))
        parsed = urlparse(full)
        host = parsed.netloc.lower().split(":")[0]
        base = base_domain.lower().split(":")[0]
        if host == base:
            scripts.add(full)

    return links, forms, scripts


def extract_title(html: str) -> str:
    """Pull <title> from HTML."""
    match = RE_TITLE.search(html[:4096])  # only scan head
    if match:
        return match.group(1).strip()[:200]
    return ""


# ═══════════════════════════════════════════════════════════════
#   RECURSIVE CRAWLER
# ═══════════════════════════════════════════════════════════════

class RecursiveCrawler:
    """
    BFS recursive crawler with:
    - Configurable max depth & max pages
    - Priority queue (high-value pages crawled first)
    - Concurrent fetching with semaphore
    - URL normalization & dedup
    - Same-domain enforcement
    - Cookie collection (including B3)
    - Form discovery (POST SQLi targets)
    - Script URL collection
    - Proxy rotation support
    - Real-time page callback for live processing
    - Stats tracking
    """

    def __init__(
        self,
        config: Any,
        proxy_manager: Optional[Any] = None,
    ):
        self.config = config
        self.proxy_manager = proxy_manager

        # Config-driven limits
        self.max_depth: int = getattr(config, "deep_crawl_max_depth", 3)
        self.max_pages: int = getattr(config, "deep_crawl_max_pages", 50)
        self.page_timeout: int = getattr(config, "deep_crawl_timeout", 10)
        self.concurrent: int = getattr(config, "deep_crawl_concurrent", 10)
        self.crawl_delay: float = getattr(config, "deep_crawl_delay", 0.1)
        self.respect_robots: bool = getattr(config, "deep_crawl_robots", False)
        self.skip_static: bool = True

        # Priority boost keywords (can be extended via config)
        self.extra_priority_kw: Dict[str, int] = {}

        # Internal state — reset per crawl
        self._seen: Set[str] = set()
        self._counter: int = 0  # heap tiebreaker

        # Stats
        self.stats = {
            "total_crawls": 0,
            "total_pages": 0,
            "total_errors": 0,
            "domains_crawled": set(),
        }

    # ─────────────────────────────────────────────
    #   PUBLIC API
    # ─────────────────────────────────────────────

    async def crawl(
        self,
        seed_url: str,
        session: Optional[aiohttp.ClientSession] = None,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None,
        on_page: Optional[Callable[[CrawlPage], Coroutine]] = None,
        extra_seeds: Optional[List[str]] = None,
    ) -> CrawlResult:
        """
        BFS crawl starting from seed_url.

        Args:
            seed_url: Starting URL
            session: Optional aiohttp session (creates one if not provided)
            max_depth: Override config max depth for this crawl
            max_pages: Override config max pages for this crawl
            on_page: Async callback invoked for each successfully fetched page
                     (for real-time secret extraction, cookie processing, etc.)
            extra_seeds: Additional seed URLs to start from (at depth 0)

        Returns:
            CrawlResult with all discovered pages, URLs, forms, cookies
        """
        _max_depth = max_depth if max_depth is not None else self.max_depth
        _max_pages = max_pages if max_pages is not None else self.max_pages

        parsed = urlparse(seed_url)
        base_domain = parsed.netloc
        base_url = f"{parsed.scheme}://{base_domain}"

        result = CrawlResult(
            seed_url=seed_url,
            domain=base_domain,
        )

        self._seen = set()
        self._counter = 0
        start_time = time.time()

        # Priority queue: (neg_score, counter, url, depth)
        pq: List[Tuple[int, int, str, int]] = []

        # Seed URLs
        seeds = [seed_url]
        if extra_seeds:
            seeds.extend(extra_seeds)

        for s in seeds:
            norm = normalize_url(s, base_domain)
            if norm and norm not in self._seen:
                self._seen.add(norm)
                sc = score_url(norm)
                self._counter += 1
                heapq.heappush(pq, (-sc, self._counter, norm, 0))

        # Robots.txt parsing
        disallowed: Set[str] = set()
        if self.respect_robots:
            disallowed = await self._fetch_robots(base_url, session)

        # Semaphore for concurrency control
        sem = asyncio.Semaphore(self.concurrent)
        own_session = False

        if session is None:
            timeout = aiohttp.ClientTimeout(total=self.page_timeout + 5)
            session = aiohttp.ClientSession(
                timeout=timeout,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
                headers={"User-Agent": self._ua()},
            )
            own_session = True

        try:
            fetched = 0
            pending: Set[asyncio.Task] = set()

            while (pq or pending) and fetched < _max_pages:
                # Fill up to concurrent limit from queue
                while pq and len(pending) < self.concurrent and fetched + len(pending) < _max_pages:
                    neg_score, _, url, depth = heapq.heappop(pq)

                    if depth > _max_depth:
                        continue

                    # Robots check
                    if disallowed:
                        p = urlparse(url).path
                        if any(p.startswith(d) for d in disallowed):
                            continue

                    task = asyncio.create_task(
                        self._fetch_page(url, depth, session, sem)
                    )
                    task._crawl_url = url  # type: ignore
                    task._crawl_depth = depth  # type: ignore
                    pending.add(task)

                if not pending:
                    break

                # Wait for at least one to complete
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )

                for task in done:
                    page: CrawlPage = task.result()
                    fetched += 1
                    result.total_fetched = fetched
                    result.pages.append(page)
                    result.all_urls.add(page.url)

                    if page.depth > result.max_depth_reached:
                        result.max_depth_reached = page.depth

                    if page.error:
                        result.errors += 1
                        continue

                    # Collect cookies
                    for cname, cval in page.cookies.items():
                        result.all_cookies[cname] = cval
                        if cname.lower() in B3_COOKIE_NAMES:
                            result.b3_cookies[cname] = cval

                    # Discover new links (only if we haven't hit max depth)
                    if page.html and page.depth < _max_depth:
                        new_links, forms, scripts = extract_links(
                            page.html, page.url, base_domain
                        )

                        for link in new_links:
                            if link not in self._seen:
                                self._seen.add(link)
                                result.all_urls.add(link)
                                # Track param URLs
                                if urlparse(link).query:
                                    result.param_urls.add(link)
                                sc = score_url(link)
                                self._counter += 1
                                heapq.heappush(
                                    pq,
                                    (-sc, self._counter, link, page.depth + 1),
                                )

                        # Forms
                        for form in forms:
                            result.form_targets.append(form)
                            if form.get("action"):
                                result.param_urls.add(form["action"])

                        # Scripts
                        for script in scripts:
                            result.script_urls.add(script)

                    # Also track param URLs from the page itself
                    if urlparse(page.url).query:
                        result.param_urls.add(page.url)

                    # Invoke real-time callback
                    if on_page and page.html:
                        try:
                            await on_page(page)
                        except Exception as e:
                            logger.debug(f"on_page callback error: {e}")

                    # Throttle
                    if self.crawl_delay > 0:
                        await asyncio.sleep(self.crawl_delay)

            # Cancel any remaining pending tasks
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        finally:
            if own_session:
                await session.close()

        result.elapsed = time.time() - start_time

        # Stats
        self.stats["total_crawls"] += 1
        self.stats["total_pages"] += result.total_fetched
        self.stats["total_errors"] += result.errors
        self.stats["domains_crawled"].add(base_domain)

        logger.info(
            f"Crawl complete: {base_domain} | "
            f"pages={result.total_fetched} | depth={result.max_depth_reached} | "
            f"urls={len(result.all_urls)} | params={len(result.param_urls)} | "
            f"forms={len(result.form_targets)} | cookies={len(result.all_cookies)} | "
            f"b3={len(result.b3_cookies)} | errors={result.errors} | "
            f"elapsed={result.elapsed:.1f}s"
        )

        return result

    async def quick_crawl(
        self,
        seed_url: str,
        session: Optional[aiohttp.ClientSession] = None,
        max_depth: int = 1,
        max_pages: int = 20,
        on_page: Optional[Callable[[CrawlPage], Coroutine]] = None,
    ) -> CrawlResult:
        """
        Lightweight crawl — shallow depth, fewer pages.
        Used in the main dorking pipeline where speed matters.
        """
        return await self.crawl(
            seed_url,
            session=session,
            max_depth=max_depth,
            max_pages=max_pages,
            on_page=on_page,
        )

    def get_stats_text(self) -> str:
        """Human-readable stats for /crawlstats command."""
        s = self.stats
        lines = [
            "🕸️ <b>Recursive Crawler Stats</b>",
            f"Total crawls: <b>{s['total_crawls']}</b>",
            f"Total pages fetched: <b>{s['total_pages']}</b>",
            f"Total errors: <b>{s['total_errors']}</b>",
            f"Unique domains: <b>{len(s['domains_crawled'])}</b>",
        ]
        return "\n".join(lines)

    # ─────────────────────────────────────────────
    #   INTERNAL — FETCH
    # ─────────────────────────────────────────────

    async def _fetch_page(
        self,
        url: str,
        depth: int,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
    ) -> CrawlPage:
        """Fetch a single page with semaphore and proxy rotation."""
        page = CrawlPage(url=url, depth=depth)
        t0 = time.time()

        try:
            async with sem:
                kwargs: Dict[str, Any] = {
                    "ssl": False,
                    "allow_redirects": True,
                    "timeout": aiohttp.ClientTimeout(total=self.page_timeout),
                }

                # Proxy rotation
                if self.proxy_manager:
                    proxy_url = await self.proxy_manager.get_proxy_url()
                    if proxy_url:
                        kwargs["proxy"] = proxy_url

                async with session.get(url, **kwargs) as resp:
                    page.status_code = resp.status
                    page.content_type = resp.headers.get("Content-Type", "")

                    # Collect response headers
                    for hname in ("Server", "X-Powered-By", "X-Generator",
                                  "Set-Cookie", "X-B3-TraceId", "X-B3-SpanId"):
                        val = resp.headers.get(hname)
                        if val:
                            page.response_headers[hname] = val

                    # Only read body for HTML
                    if resp.status != 200:
                        page.error = f"HTTP {resp.status}"
                        page.fetch_time = time.time() - t0
                        return page

                    ct = page.content_type.lower()
                    if "text/html" not in ct and "application/xhtml" not in ct:
                        # Non-HTML — record but don't parse
                        page.fetch_time = time.time() - t0
                        return page

                    page.html = await resp.text(errors="ignore")
                    page.title = extract_title(page.html)

                    # Extract cookies
                    for cname, cookie in resp.cookies.items():
                        if cookie.value:
                            page.cookies[cname] = cookie.value

                    # Count links (for stats — full extraction happens in caller)
                    links, forms, scripts = extract_links(
                        page.html, url, urlparse(url).netloc
                    )
                    page.links_found = len(links)
                    page.forms = forms
                    page.scripts = list(scripts)

        except asyncio.TimeoutError:
            page.error = "timeout"
        except aiohttp.ClientError as e:
            page.error = f"client_error: {str(e)[:100]}"
        except Exception as e:
            page.error = f"error: {str(e)[:100]}"

        page.fetch_time = time.time() - t0
        return page

    # ─────────────────────────────────────────────
    #   INTERNAL — ROBOTS.TXT
    # ─────────────────────────────────────────────

    async def _fetch_robots(
        self,
        base_url: str,
        session: Optional[aiohttp.ClientSession],
    ) -> Set[str]:
        """Parse robots.txt for Disallow paths."""
        disallowed: Set[str] = set()
        robots_url = f"{base_url}/robots.txt"
        try:
            _session = session
            own = False
            if _session is None:
                _session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=5)
                )
                own = True
            try:
                async with _session.get(robots_url, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="ignore")
                        in_ua_block = False
                        for line in text.splitlines():
                            line = line.strip()
                            if line.lower().startswith("user-agent:"):
                                ua = line.split(":", 1)[1].strip()
                                in_ua_block = ua == "*"
                            elif line.lower().startswith("disallow:") and in_ua_block:
                                path = line.split(":", 1)[1].strip()
                                if path:
                                    disallowed.add(path)
            finally:
                if own:
                    await _session.close()
        except Exception:
            pass
        return disallowed

    # ─────────────────────────────────────────────
    #   INTERNAL — HELPERS
    # ─────────────────────────────────────────────

    @staticmethod
    def _ua() -> str:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )


# ═══════════════════════════════════════════════════════════════
#   CONVENIENCE: Generate seed URLs from known patterns
# ═══════════════════════════════════════════════════════════════

COMMON_SEEDS = [
    "/",
    "/sitemap.xml",
    "/robots.txt",
    "/shop/",
    "/store/",
    "/checkout/",
    "/cart/",
    "/my-account/",
    "/account/",
    "/login/",
    "/wp-login.php",
    "/wp-admin/",
    "/admin/",
    "/api/",
    "/wp-json/wp/v2/users",
    "/graphql",
]


def generate_seed_urls(base_url: str) -> List[str]:
    """Generate initial seed URLs for a domain from common paths."""
    seeds = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in COMMON_SEEDS:
        seeds.append(f"{base}{path}")
    return seeds
