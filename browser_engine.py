"""
Headless Browser Search Engine — Playwright-based search resilience

Uses a real Chromium browser to perform searches on engines that aggressively
block aiohttp/requests (DDG, Startpage, Google). This is the last-resort
fallback when:
  1. Normal HTTP scraping → rate limited / 0 results
  2. Proxy rotation → still blocked
  3. Captcha solving → captcha solved but still no results
  4. Firecrawl → paid API, limited credits

Features:
- Persistent browser context (reuses across searches, not per-query)
- Stealth mode (anti-fingerprinting, realistic viewport/UA/timings)
- Random human-like delays, mouse movements, scroll behavior
- Multi-engine support: Google, Bing, DuckDuckGo, Startpage, Yahoo, Brave
- Proxy injection per-context
- Cookie persistence across sessions
- Automatic captcha detection (integrates with captcha_solver if available)
- Configurable concurrency (semaphore-bounded browser tabs)

v3.7 — Phase: Search Engine Resilience
"""

import asyncio
import random
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs, unquote

from loguru import logger

# Import crawl data classes for browser_crawl integration
from recursive_crawler import CrawlResult, CrawlPage, extract_links, extract_title, generate_seed_urls

# Playwright is optional — graceful fallback if not installed
_HAS_PLAYWRIGHT = False
try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
        TimeoutError as PlaywrightTimeout,
    )
    _HAS_PLAYWRIGHT = True
except ImportError:
    pass

# Captcha solver integration (optional)
_HAS_CAPTCHA = False
try:
    from captcha_solver import CaptchaSolver, SitekeyExtractor
    _HAS_CAPTCHA = True
except ImportError:
    pass

# Stealth plugin (optional — helps bypass Cloudflare)
_HAS_STEALTH = False
_stealth_instance = None
try:
    from playwright_stealth import Stealth
    _stealth_instance = Stealth()
    _HAS_STEALTH = True
except ImportError:
    pass


# ====================== STEALTH CONFIG ======================

STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-infobars",
    "--disable-extensions",
    "--disable-popup-blocking",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-sandbox",
    "--lang=en-US",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1440, "height": 900},
    {"width": 1536, "height": 864},
    {"width": 1280, "height": 720},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]


# ====================== SEARCH ENGINE PARSERS ======================

class SearchParser:
    """Parses search result pages from different engines."""

    @staticmethod
    def google(html: str) -> List[str]:
        """Parse Google search results."""
        urls = []
        # Google result links in <a> with /url?q= pattern
        for match in re.finditer(r'<a[^>]+href="(/url\?q=([^"&]+))', html):
            url = unquote(match.group(2))
            if url.startswith("http") and not _is_search_domain(url):
                urls.append(url)
        # Direct result links
        for match in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*data-', html):
            url = match.group(1)
            if not _is_search_domain(url):
                urls.append(url)
        return _dedup(urls)

    @staticmethod
    def bing(html: str) -> List[str]:
        """Parse Bing search results."""
        urls = []
        for match in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*(?:class="[^"]*tilk|<h2)', html):
            url = match.group(1)
            if not _is_search_domain(url):
                urls.append(url)
        # Bing cite elements
        for match in re.finditer(r'<cite[^>]*>(https?://[^<]+)</cite>', html):
            url = match.group(1).strip()
            if url.startswith("http"):
                urls.append(url)
        return _dedup(urls)

    @staticmethod
    def duckduckgo(html: str) -> List[str]:
        """Parse DuckDuckGo search results."""
        urls = []
        for match in re.finditer(r'uddg=([^&"]+)', html):
            url = unquote(match.group(1))
            if url.startswith("http") and not _is_search_domain(url):
                urls.append(url)
        # Direct result links
        for match in re.finditer(r'class="result__a"[^>]+href="(https?://[^"]+)"', html):
            url = match.group(1)
            if not _is_search_domain(url):
                urls.append(url)
        return _dedup(urls)

    @staticmethod
    def startpage(html: str) -> List[str]:
        """Parse Startpage search results."""
        urls = []
        for match in re.finditer(r'class="w-gl__result-url"[^>]*>(https?://[^<]+)<', html):
            url = match.group(1).strip()
            urls.append(url)
        for match in re.finditer(r'<a[^>]+class="[^"]*result[^"]*"[^>]+href="(https?://[^"]+)"', html):
            url = match.group(1)
            if not _is_search_domain(url):
                urls.append(url)
        return _dedup(urls)

    @staticmethod
    def yahoo(html: str) -> List[str]:
        """Parse Yahoo search results."""
        urls = []
        for match in re.finditer(r'<a[^>]+class="[^"]*d-ib[^"]*"[^>]+href="(https?://[^"]+)"', html):
            url = match.group(1)
            if "r.search.yahoo.com" in url:
                # Extract real URL from redirect
                m2 = re.search(r'/RU=([^/]+)/', url)
                if m2:
                    url = unquote(m2.group(1))
            if not _is_search_domain(url):
                urls.append(url)
        return _dedup(urls)

    @staticmethod
    def brave(html: str) -> List[str]:
        """Parse Brave search results."""
        urls = []
        for match in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*result-header', html):
            url = match.group(1)
            if not _is_search_domain(url):
                urls.append(url)
        for match in re.finditer(r'<cite[^>]*class="[^"]*snippet-url[^"]*"[^>]*>(https?://[^<]+)<', html):
            url = match.group(1).strip()
            urls.append(url)
        return _dedup(urls)


# Engines config: name → (search URL template, parser function, wait selector)
BROWSER_ENGINES = {
    "google": {
        "url": "https://www.google.com/search?q={query}&num={num}",
        "parser": SearchParser.google,
        "wait": "#search, #rso, .g",
        "captcha_indicators": ["recaptcha", "captcha", "unusual traffic"],
    },
    "bing": {
        "url": "https://www.bing.com/search?q={query}&count={num}",
        "parser": SearchParser.bing,
        "wait": "#b_results, .b_algo",
        "captcha_indicators": ["captcha"],
    },
    "duckduckgo": {
        "url": "https://html.duckduckgo.com/html/?q={query}",
        "parser": SearchParser.duckduckgo,
        "wait": ".result, .results",
        "captcha_indicators": ["captcha", "robot", "automated"],
    },
    "startpage": {
        "url": "https://www.startpage.com/sp/search?q={query}",
        "parser": SearchParser.startpage,
        "wait": ".w-gl, .mainline-results",
        "captcha_indicators": ["captcha", "robot"],
    },
    "yahoo": {
        "url": "https://search.yahoo.com/search?p={query}&n={num}",
        "parser": SearchParser.yahoo,
        "wait": "#web, .searchCenterMiddle",
        "captcha_indicators": ["captcha", "robot", "not a robot"],
    },
    "brave": {
        "url": "https://search.brave.com/search?q={query}",
        "parser": SearchParser.brave,
        "wait": "#results, .snippet",
        "captcha_indicators": ["captcha"],
    },
}


# ====================== HELPER FUNCTIONS ======================

SEARCH_DOMAINS = {
    "google.com", "google.co", "bing.com", "duckduckgo.com",
    "startpage.com", "yahoo.com", "brave.com", "ecosia.org",
    "qwant.com", "aol.com", "msn.com", "yandex.com",
}

def _is_search_domain(url: str) -> bool:
    """Check if URL belongs to a search engine (not a real result)."""
    try:
        host = urlparse(url).hostname or ""
        for sd in SEARCH_DOMAINS:
            if host.endswith(sd):
                return True
    except Exception:
        pass
    return False

def _dedup(urls: List[str]) -> List[str]:
    """Deduplicate URLs preserving order."""
    seen = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


# ====================== BROWSER MANAGER ======================

class BrowserManager:
    """
    Manages a persistent Playwright browser instance for search engine scraping.
    
    Lifecycle:
    - Lazy init: browser starts on first search request
    - Persistent context: reuses browser across searches
    - Auto-restart on crash
    - Graceful shutdown
    """

    def __init__(self,
                 headless: bool = True,
                 proxy: Optional[str] = None,
                 max_concurrent: int = 3,
                 page_timeout: int = 30000,
                 user_data_dir: Optional[str] = None):
        self.headless = headless
        self.proxy = proxy
        self.max_concurrent = max_concurrent
        self.page_timeout = page_timeout
        self.user_data_dir = user_data_dir
        
        self._playwright: Optional['Playwright'] = None
        self._browser: Optional['Browser'] = None
        self._context: Optional['BrowserContext'] = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._lock = asyncio.Lock()
        self._started = False
        
        # Stats
        self.searches_done: int = 0
        self.total_results: int = 0
        self.errors: int = 0
        self.captchas_hit: int = 0

    @property
    def available(self) -> bool:
        return _HAS_PLAYWRIGHT

    async def start(self):
        """Start the browser (lazy, only called when needed)."""
        if not _HAS_PLAYWRIGHT:
            logger.warning("[Browser] Playwright not installed. Run: pip install playwright && playwright install chromium")
            return
        
        async with self._lock:
            if self._started:
                return
            
            try:
                self._playwright = await async_playwright().start()
                
                stealth_args = list(STEALTH_ARGS)
                # Use new headless mode which is undetectable
                if self.headless:
                    stealth_args.append("--headless=new")
                
                launch_args = {
                    "headless": False,  # We pass --headless=new via args instead
                    "args": stealth_args if self.headless else STEALTH_ARGS,
                }
                
                if self.proxy:
                    launch_args["proxy"] = {"server": self.proxy}
                
                self._browser = await self._playwright.chromium.launch(**launch_args)
                
                # Create a stealth context
                viewport = random.choice(VIEWPORTS)
                ua = random.choice(USER_AGENTS)
                
                self._context = await self._browser.new_context(
                    viewport=viewport,
                    user_agent=ua,
                    locale="en-US",
                    timezone_id="America/New_York",
                    color_scheme="light",
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                
                # Anti-detection: override navigator.webdriver
                await self._context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    window.chrome = { runtime: {} };
                    Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 0});
                    // Hide headless indicators
                    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
                    Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
                    if (navigator.connection) {
                        Object.defineProperty(navigator.connection, 'rtt', {get: () => 50});
                    }
                    // WebGL vendor/renderer spoofing
                    const getParameter = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(parameter) {
                        if (parameter === 37445) return 'Intel Inc.';
                        if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                        return getParameter.call(this, parameter);
                    };
                """)
                
                # Apply stealth patches to the context
                if _HAS_STEALTH and _stealth_instance:
                    try:
                        await _stealth_instance.apply_stealth_async(self._context)
                        logger.info("[Browser] Stealth patches applied to context")
                    except Exception as e:
                        logger.warning(f"[Browser] Stealth apply failed: {e}")
                
                self._started = True
                logger.info(f"[Browser] Chromium started (headless={self.headless}, stealth={_HAS_STEALTH}, viewport={viewport['width']}x{viewport['height']})")
                
            except Exception as e:
                logger.error(f"[Browser] Failed to start: {e}")
                await self._cleanup()

    async def stop(self):
        """Shut down the browser."""
        await self._cleanup()
        logger.info("[Browser] Stopped")

    async def _cleanup(self):
        """Clean up browser resources."""
        self._started = False
        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._context = None
        self._browser = None
        self._playwright = None

    async def _ensure_started(self):
        """Start browser if not already running."""
        if not self._started:
            await self.start()
        if not self._started:
            raise RuntimeError("Browser failed to start")

    async def search(self, engine_name: str, query: str,
                     num_results: int = 15,
                     captcha_solver: Optional['CaptchaSolver'] = None) -> List[str]:
        """
        Perform a search using the headless browser.
        
        Args:
            engine_name: Key from BROWSER_ENGINES (google, bing, duckduckgo, etc.)
            query: Search query string
            num_results: Desired number of results
            captcha_solver: Optional CaptchaSolver for auto-solving
            
        Returns:
            List of result URLs
        """
        if not _HAS_PLAYWRIGHT:
            return []
        
        engine_cfg = BROWSER_ENGINES.get(engine_name)
        if not engine_cfg:
            logger.warning(f"[Browser] Unknown engine: {engine_name}")
            return []
        
        await self._ensure_started()
        
        async with self._semaphore:
            page = None
            try:
                page = await self._context.new_page()
                page.set_default_timeout(self.page_timeout)
                
                # Build search URL
                search_url = engine_cfg["url"].format(
                    query=quote(query),
                    num=num_results,
                )
                
                # Navigate with human-like behavior
                await self._human_navigate(page, search_url)
                
                # Wait for results to load
                try:
                    await page.wait_for_selector(
                        engine_cfg["wait"],
                        timeout=self.page_timeout,
                    )
                except Exception:
                    # Results might still be there even if selector didn't match
                    pass
                
                # Small human-like delay
                await asyncio.sleep(random.uniform(0.8, 2.0))
                
                # Scroll down slightly (triggers lazy-loading on some engines)
                await self._human_scroll(page)
                
                # Get page content
                html = await page.content()
                
                # Check for captcha
                captcha_detected = self._check_captcha(html, engine_cfg)
                if captcha_detected:
                    self.captchas_hit += 1
                    logger.warning(f"[Browser] Captcha on {engine_name}")
                    
                    # Try to solve if solver available
                    if captcha_solver and _HAS_CAPTCHA:
                        solved = await self._try_solve_captcha(
                            page, html, captcha_solver, engine_cfg
                        )
                        if solved:
                            html = await page.content()
                        else:
                            return []
                    else:
                        return []
                
                # Parse results
                urls = engine_cfg["parser"](html)
                
                # If few results, try scrolling more and re-parsing
                if len(urls) < num_results // 2:
                    await self._human_scroll(page, times=3)
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                    html = await page.content()
                    urls = engine_cfg["parser"](html)
                
                self.searches_done += 1
                self.total_results += len(urls)
                
                logger.info(f"[Browser] {engine_name}: {len(urls)} results for: {query[:60]}")
                return urls[:num_results]
                
            except Exception as e:
                self.errors += 1
                logger.error(f"[Browser] Search error ({engine_name}): {e}")
                return []
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass

    async def search_multi_engine(self, query: str, num_results: int = 15,
                                   engines: Optional[List[str]] = None,
                                   captcha_solver: Optional['CaptchaSolver'] = None) -> List[str]:
        """
        Try multiple engines in order, return first successful result set.
        
        Falls through engines until one returns results.
        """
        engine_order = engines or ["google", "bing", "duckduckgo", "startpage", "brave"]
        
        all_urls = []
        for engine_name in engine_order:
            urls = await self.search(engine_name, query, num_results, captcha_solver)
            if urls:
                all_urls.extend(urls)
                if len(all_urls) >= num_results:
                    break
            # Delay between engine attempts
            await asyncio.sleep(random.uniform(1.5, 3.0))
        
        return _dedup(all_urls)[:num_results]

    # ==================== HUMAN SIMULATION ====================

    async def _human_navigate(self, page: 'Page', url: str):
        """Navigate to URL with human-like timing."""
        # Random pre-navigation delay
        await asyncio.sleep(random.uniform(0.3, 1.0))
        await page.goto(url, wait_until="domcontentloaded")
        await asyncio.sleep(random.uniform(0.5, 1.5))

    async def _human_scroll(self, page: 'Page', times: int = 1):
        """Scroll down the page like a human would."""
        for _ in range(times):
            scroll_amount = random.randint(200, 600)
            await page.evaluate(f"window.scrollBy(0, {scroll_amount})")
            await asyncio.sleep(random.uniform(0.3, 0.8))

    async def _human_type(self, page: 'Page', selector: str, text: str):
        """Type text with human-like delays between keystrokes."""
        element = await page.query_selector(selector)
        if not element:
            return
        await element.click()
        for char in text:
            await element.type(char, delay=random.randint(30, 120))
        await asyncio.sleep(random.uniform(0.2, 0.5))

    # ==================== CAPTCHA HANDLING ====================

    def _check_captcha(self, html: str, engine_cfg: Dict) -> bool:
        """Check if the page contains a captcha."""
        lower = html.lower()[:5000]
        for indicator in engine_cfg.get("captcha_indicators", []):
            if indicator.lower() in lower:
                # More specific checks to avoid false positives
                if re.search(
                    r'captcha|recaptcha|hcaptcha|challenge|verify.*human|unusual.*traffic|robot',
                    lower
                ):
                    return True
        return False

    async def _try_solve_captcha(self, page: 'Page', html: str,
                                   solver: 'CaptchaSolver',
                                   engine_cfg: Dict) -> bool:
        """Attempt to solve a detected captcha."""
        if not _HAS_CAPTCHA:
            return False
        
        try:
            captcha_info = SitekeyExtractor.detect(html)
            if not captcha_info or not captcha_info.get("sitekey"):
                logger.debug("[Browser] Captcha detected but no sitekey found")
                return False
            
            page_url = page.url
            result = await solver.solve(captcha_info, page_url)
            
            if result.success:
                logger.info(f"[Browser] Captcha solved via {result.provider} in {result.solve_time:.1f}s")
                
                # Inject the captcha token into the page
                token = result.token or result.solution
                if token:
                    await page.evaluate(f"""
                        (() => {{
                            // Try reCAPTCHA v2
                            const textarea = document.querySelector('#g-recaptcha-response, [name="g-recaptcha-response"]');
                            if (textarea) {{
                                textarea.value = '{token}';
                                textarea.style.display = 'block';
                            }}
                            // Try hCaptcha
                            const hc = document.querySelector('[name="h-captcha-response"]');
                            if (hc) {{
                                hc.value = '{token}';
                            }}
                            // Try submitting the form
                            const form = document.querySelector('form');
                            if (form) form.submit();
                        }})()
                    """)
                    await asyncio.sleep(3)
                    return True
            
            logger.warning(f"[Browser] Captcha solve failed: {result.error}")
        except Exception as e:
            logger.error(f"[Browser] Captcha solve error: {e}")
        
        return False

    # ==================== FLARESOLVERR CF BYPASS ====================

    async def _flaresolverr_solve(self, url: str, timeout: int = 60000) -> Optional[Dict]:
        """
        Use FlareSolverr to solve Cloudflare challenges.

        FlareSolverr runs as a Docker service on localhost:8191 and uses its own
        headless browser to solve CF Turnstile/managed challenges.

        Returns dict with: {cookies: [...], user_agent: str, html: str} or None on failure.
        """
        flare_url = "http://localhost:8191/v1"
        payload = {
            "cmd": "request.get",
            "url": url,
            "maxTimeout": timeout,
        }

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(flare_url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout / 1000 + 10)) as resp:
                    if resp.status != 200:
                        logger.warning(f"[FlareSolverr] HTTP {resp.status}")
                        return None

                    data = await resp.json()
                    if data.get("status") != "ok":
                        logger.warning(f"[FlareSolverr] Failed: {data.get('message', 'unknown')}")
                        return None

                    solution = data.get("solution", {})
                    cookies = solution.get("cookies", [])
                    html = solution.get("response", "")
                    user_agent = solution.get("userAgent", "")

                    logger.info(f"[FlareSolverr] Solved {url} — {len(cookies)} cookies, {len(html)} bytes HTML")
                    return {
                        "cookies": cookies,
                        "user_agent": user_agent,
                        "html": html,
                        "status": solution.get("status", 200),
                    }
        except Exception as e:
            logger.debug(f"[FlareSolverr] Error: {e}")
            return None

    @staticmethod
    async def _flaresolverr_available() -> bool:
        """Quick check if FlareSolverr is running on localhost:8191."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:8191/", timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("msg") == "FlareSolverr is ready!"
        except Exception:
            pass
        return False

    async def _inject_flaresolverr_cookies(self, page: 'Page', flare_result: Dict, domain: str):
        """Inject FlareSolverr cookies into the Playwright browser context."""
        cookies_to_add = []
        for cookie in flare_result.get("cookies", []):
            cookies_to_add.append({
                "name": cookie["name"],
                "value": cookie["value"],
                "domain": cookie.get("domain", f".{domain}"),
                "path": cookie.get("path", "/"),
                "httpOnly": cookie.get("httpOnly", False),
                "secure": cookie.get("secure", True),
                "sameSite": cookie.get("sameSite", "Lax"),
            })

        if cookies_to_add:
            try:
                await self._context.add_cookies(cookies_to_add)
                logger.info(f"[FlareSolverr] Injected {len(cookies_to_add)} cookies into browser context")
            except Exception as e:
                logger.warning(f"[FlareSolverr] Cookie injection error: {e}")

    # ==================== BROWSER SITE CRAWL (Cloudflare bypass) ====================

    async def browser_crawl(
        self,
        seed_url: str,
        max_pages: int = 30,
        max_depth: int = 3,
        page_timeout: int = 20000,
        delay: float = 1.5,
    ) -> 'CrawlResult':
        """
        Crawl a website using a real Playwright browser to bypass Cloudflare/WAF.

        This is the fallback for sites where aiohttp gets blocked. The real
        Chromium browser executes JS challenges, passes fingerprint checks, and
        renders full page content.

        BFS crawl: starts at seed_url, follows same-domain links up to max_depth.
        Extracts: HTML, cookies, forms, scripts, param URLs — returned as a
        standard CrawlResult compatible with the existing pipeline.

        Args:
            seed_url:     Starting URL to crawl
            max_pages:    Maximum number of pages to fetch
            max_depth:    Maximum link-follow depth from seed
            page_timeout: Per-page navigation timeout in ms
            delay:        Delay between page loads (seconds) for politeness

        Returns:
            CrawlResult with all extracted data
        """
        if not _HAS_PLAYWRIGHT:
            logger.warning("[BrowserCrawl] Playwright not available")
            parsed = urlparse(seed_url)
            return CrawlResult(seed_url=seed_url, domain=parsed.netloc)

        await self._ensure_started()

        parsed_seed = urlparse(seed_url)
        base_domain = parsed_seed.netloc.lower().split(":")[0]
        base_scheme_host = f"{parsed_seed.scheme}://{parsed_seed.netloc}"

        result = CrawlResult(seed_url=seed_url, domain=base_domain)

        # Check if FlareSolverr is available for CF bypass
        has_flaresolverr = await self._flaresolverr_available()
        if has_flaresolverr:
            logger.info("[BrowserCrawl] FlareSolverr detected — will use for CF bypass")

        # BFS queue: (url, depth)
        from collections import deque
        queue: deque = deque()
        queue.append((seed_url, 0))
        seen: set = {seed_url}
        fetched = 0

        # URLs to skip (WAF/CDN internal paths)
        SKIP_PATTERNS = [
            "/cdn-cgi/", "/challenge-platform/", "/__cf_chl_",
            "/captcha/", "/recaptcha/", "/hcaptcha/",
        ]

        B3_COOKIE_NAMES = {
            "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
            "x-b3-sampled", "x-b3-flags", "b3",
        }

        start_time = time.time()

        logger.info(f"[BrowserCrawl] Starting: {seed_url} (max_pages={max_pages}, max_depth={max_depth})")

        page = None
        try:
            page = await self._context.new_page()
            page.set_default_timeout(page_timeout)
            
            while queue and fetched < max_pages:
                url, depth = queue.popleft()
                
                # Skip WAF/CDN internal URLs
                url_lower = url.lower()
                if any(pat in url_lower for pat in SKIP_PATTERNS):
                    logger.debug(f"[BrowserCrawl] Skipping CDN/WAF URL: {url[:80]}")
                    continue
                
                crawl_page = CrawlPage(url=url, depth=depth)
                t0 = time.time()

                try:
                    # Navigate with human-like behavior
                    await self._human_navigate(page, url)

                    # Wait a bit for dynamic content / Cloudflare challenge to clear
                    await asyncio.sleep(random.uniform(0.5, 1.2))

                    # Check for Cloudflare challenge page
                    cf_cleared = False
                    
                    # Quick check: is this a CF challenge page?
                    title = await page.title()
                    content_snippet = await page.evaluate(
                        "() => document.body ? document.body.innerText.substring(0, 500) : ''"
                    )
                    page_text = (title + content_snippet).lower()
                    cf_indicators = [
                        "just a moment", "checking your browser",
                        "attention required", "please wait", "verifying",
                        "enable javascript", "checking if the site",
                    ]
                    is_cf_challenge = any(sig in page_text for sig in cf_indicators)
                    
                    if is_cf_challenge and has_flaresolverr:
                        # Go straight to FlareSolverr — don't waste time with Playwright waiting
                        logger.debug(f"[BrowserCrawl] CF challenge on {url}, using FlareSolverr directly")
                    elif is_cf_challenge:
                        # No FlareSolverr — try Playwright-based bypass (2 attempts)
                        for attempt in range(2):
                            logger.debug(f"[BrowserCrawl] CF challenge on {url}, attempt {attempt+1}/2")
                            
                            # Try to find and click Turnstile checkbox/iframe
                            try:
                                cf_frames = page.frames
                                for frame in cf_frames:
                                    if "challenges.cloudflare.com" in (frame.url or ""):
                                        try:
                                            checkbox = await frame.query_selector(
                                                'input[type="checkbox"], .cb-i, #challenge-stage'
                                            )
                                            if checkbox:
                                                await checkbox.click()
                                                await asyncio.sleep(3)
                                        except Exception:
                                            pass
                                
                                for sel in ['input[type="checkbox"]', '.cf-turnstile',
                                            '#challenge-form input[type="submit"]']:
                                    try:
                                        el = await page.query_selector(sel)
                                        if el and await el.is_visible():
                                            await el.click()
                                            await asyncio.sleep(2)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            
                            wait_time = 5 + attempt * 3 + random.uniform(1, 3)
                            await asyncio.sleep(wait_time)
                            
                            # Re-check
                            title = await page.title()
                            content_snippet = await page.evaluate(
                                "() => document.body ? document.body.innerText.substring(0, 500) : ''"
                            )
                            page_text = (title + content_snippet).lower()
                            if not any(sig in page_text for sig in cf_indicators):
                                is_cf_challenge = False
                                break
                    
                    if not is_cf_challenge:
                        cf_cleared = True
                    
                    if not cf_cleared:
                        logger.warning(f"[BrowserCrawl] CF challenge not cleared for {url}, trying FlareSolverr...")
                        
                        # Try FlareSolverr as last resort
                        flare_result = await self._flaresolverr_solve(url)
                        if flare_result and flare_result.get("html"):
                            flare_html = flare_result["html"]
                            flare_title = extract_title(flare_html)
                            # Check if FlareSolverr actually got real content (not another challenge)
                            cf_indicators = ["just a moment", "checking your browser", "attention required",
                                             "please wait", "checking if the site"]
                            if not any(sig in flare_title.lower() for sig in cf_indicators) and len(flare_html) > 500:
                                logger.info(f"[BrowserCrawl] FlareSolverr bypassed CF for {url} ({len(flare_html)} bytes)")
                                cf_cleared = True
                                # Inject cookies so subsequent pages work too
                                await self._inject_flaresolverr_cookies(page, flare_result, base_domain)
                                # Use the FlareSolverr HTML directly for this page
                                crawl_page.html = flare_html
                                crawl_page.title = flare_title
                            else:
                                logger.warning(f"[BrowserCrawl] FlareSolverr also got challenge page for {url}")
                        
                        if not cf_cleared:
                            # Mark as error — this isn't real content
                            crawl_page.error = "cloudflare_challenge_not_cleared"
                            crawl_page.html = ""
                            
                            # If this is the seed URL, inject common paths as seeds
                            if fetched == 0:
                                extra_seeds = generate_seed_urls(base_scheme_host)
                                for es in extra_seeds:
                                    if es not in seen:
                                        es_lower = es.lower()
                                        if not any(pat in es_lower for pat in SKIP_PATTERNS):
                                            seen.add(es)
                                            queue.append((es, 0))
                                logger.info(f"[BrowserCrawl] Added {len(extra_seeds)} seed URLs to bypass CF on root")
                    else:
                        # Scroll to trigger lazy-loaded content
                        await self._human_scroll(page, times=2)
                        await asyncio.sleep(random.uniform(0.3, 0.7))

                    # Get final URL (after redirects / challenges)
                    final_url = page.url
                    crawl_page.status_code = 200  # if we got here, page loaded

                    # Get full HTML (only if CF was cleared and not already set by FlareSolverr)
                    if cf_cleared and not crawl_page.html:
                        html = await page.content()
                        crawl_page.html = html
                        crawl_page.title = extract_title(html)
                    elif cf_cleared and crawl_page.html:
                        # HTML was set by FlareSolverr — also try to reload via browser with
                        # injected cookies for richer content
                        try:
                            await self._human_navigate(page, url)
                            await asyncio.sleep(random.uniform(1.0, 2.0))
                            await self._human_scroll(page, times=2)
                            browser_html = await page.content()
                            browser_title = extract_title(browser_html)
                            # Use browser version if it's real content and bigger
                            if ("just a moment" not in browser_title.lower()
                                    and len(browser_html) > len(crawl_page.html)):
                                crawl_page.html = browser_html
                                crawl_page.title = browser_title
                                final_url = page.url
                                logger.debug(f"[BrowserCrawl] Browser reload after cookie injection got better content")
                        except Exception:
                            pass  # Keep FlareSolverr HTML
                        html = crawl_page.html
                    else:
                        html = ""

                    # Extract cookies from browser context
                    try:
                        browser_cookies = await self._context.cookies(final_url)
                        for cookie in browser_cookies:
                            cname = cookie.get("name", "")
                            cval = cookie.get("value", "")
                            if cname and cval:
                                crawl_page.cookies[cname] = cval
                                result.all_cookies[cname] = cval
                                if cname.lower() in B3_COOKIE_NAMES:
                                    result.b3_cookies[cname] = cval
                    except Exception as e:
                        logger.debug(f"[BrowserCrawl] Cookie extraction error: {e}")

                    # Extract response headers via Performance API
                    try:
                        perf_headers = await page.evaluate("""
                            () => {
                                const entries = performance.getEntriesByType('navigation');
                                if (entries.length > 0) {
                                    const e = entries[0];
                                    return {
                                        server: e.serverTiming ? e.serverTiming.map(s => s.name).join(',') : '',
                                        type: e.type,
                                    };
                                }
                                return {};
                            }
                        """)
                        if perf_headers:
                            crawl_page.response_headers = perf_headers
                    except Exception:
                        pass

                    # Extract links, forms, scripts using the same parser as RecursiveCrawler
                    if html and depth < max_depth:
                        new_links, forms, scripts = extract_links(html, final_url, base_domain)

                        crawl_page.links_found = len(new_links)
                        crawl_page.forms = forms
                        crawl_page.scripts = list(scripts)

                        for link in new_links:
                            if link not in seen:
                                # Skip CDN/WAF internal URLs
                                if any(pat in link.lower() for pat in SKIP_PATTERNS):
                                    continue
                                seen.add(link)
                                result.all_urls.add(link)
                                if urlparse(link).query:
                                    result.param_urls.add(link)
                                queue.append((link, depth + 1))

                        for form in forms:
                            result.form_targets.append(form)
                            if form.get("action"):
                                result.param_urls.add(form["action"])

                        for script in scripts:
                            result.script_urls.add(script)

                    # Track param URLs from the page itself
                    if urlparse(final_url).query:
                        result.param_urls.add(final_url)

                except Exception as e:
                    crawl_page.error = f"browser_error: {str(e)[:150]}"
                    result.errors += 1
                    logger.debug(f"[BrowserCrawl] Error on {url}: {e}")

                crawl_page.fetch_time = time.time() - t0
                fetched += 1
                result.pages.append(crawl_page)
                result.all_urls.add(url)
                result.total_fetched = fetched

                if depth > result.max_depth_reached:
                    result.max_depth_reached = depth

                # Polite delay between pages
                if queue and fetched < max_pages:
                    await asyncio.sleep(delay + random.uniform(0.2, 0.8))

        except Exception as e:
            logger.error(f"[BrowserCrawl] Fatal error: {e}")
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

        result.elapsed = time.time() - start_time

        logger.info(
            f"[BrowserCrawl] Done: {base_domain} | "
            f"pages={result.total_fetched} | depth={result.max_depth_reached} | "
            f"urls={len(result.all_urls)} | params={len(result.param_urls)} | "
            f"forms={len(result.form_targets)} | cookies={len(result.all_cookies)} | "
            f"b3={len(result.b3_cookies)} | errors={result.errors} | "
            f"elapsed={result.elapsed:.1f}s"
        )

        return result

    def get_stats(self) -> Dict:
        """Return browser engine stats."""
        return {
            "available": self.available,
            "running": self._started,
            "searches": self.searches_done,
            "total_results": self.total_results,
            "errors": self.errors,
            "captchas_hit": self.captchas_hit,
            "avg_results": (
                self.total_results / self.searches_done
                if self.searches_done > 0 else 0
            ),
        }


# ====================== FLARESOLVERR CRAWLER ======================

async def flaresolverr_crawl(
    seed_url: str,
    max_pages: int = 30,
    max_depth: int = 3,
    delay: float = 1.0,
    timeout: int = 60000,
) -> CrawlResult:
    """
    Crawl a website using FlareSolverr to bypass Cloudflare on every request.

    This is a pure-FlareSolverr crawler — doesn't need Playwright at all.
    Each page is fetched via FlareSolverr's managed browser which handles
    CF Turnstile/managed challenges automatically.

    BFS crawl: extracts links from each page and follows same-domain links.

    Args:
        seed_url:  Starting URL
        max_pages: Max pages to fetch
        max_depth: Max link-follow depth
        delay:     Delay between requests (seconds)
        timeout:   FlareSolverr timeout per request (ms)

    Returns:
        CrawlResult compatible with the pipeline
    """
    import aiohttp
    from collections import deque

    parsed_seed = urlparse(seed_url)
    base_domain = parsed_seed.netloc.lower().split(":")[0]
    flare_url = "http://localhost:8191/v1"

    result = CrawlResult(seed_url=seed_url, domain=base_domain)

    queue: deque = deque()
    queue.append((seed_url, 0))
    seen: set = {seed_url}
    fetched = 0

    B3_COOKIE_NAMES = {
        "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
        "x-b3-sampled", "x-b3-flags", "b3",
    }

    SKIP_PATTERNS = [
        "/cdn-cgi/", "/challenge-platform/", "/__cf_chl_",
        "/captcha/", "/recaptcha/", "/hcaptcha/",
    ]

    # CF challenge indicators
    CF_INDICATORS = [
        "just a moment", "checking your browser", "attention required",
        "please wait", "checking if the site", "enable javascript",
    ]

    start_time = time.time()
    logger.info(f"[FlareCrawl] Starting: {seed_url} (max_pages={max_pages}, max_depth={max_depth})")

    # Reuse a single FlareSolverr session for cookie persistence
    session_id = None

    async with aiohttp.ClientSession() as session:
        # Create a FlareSolverr session for cookie persistence
        try:
            create_resp = await session.post(flare_url, json={"cmd": "sessions.create"},
                                              timeout=aiohttp.ClientTimeout(total=15))
            if create_resp.status == 200:
                create_data = await create_resp.json()
                if create_data.get("status") == "ok":
                    session_id = create_data.get("session")
                    logger.info(f"[FlareCrawl] Created FlareSolverr session: {session_id}")
        except Exception as e:
            logger.debug(f"[FlareCrawl] Session create failed: {e}")

        while queue and fetched < max_pages:
            url, depth = queue.popleft()

            # Skip WAF/CDN internal URLs
            url_lower = url.lower()
            if any(pat in url_lower for pat in SKIP_PATTERNS):
                continue

            crawl_page = CrawlPage(url=url, depth=depth)
            t0 = time.time()

            try:
                payload = {
                    "cmd": "request.get",
                    "url": url,
                    "maxTimeout": timeout,
                }
                if session_id:
                    payload["session"] = session_id

                async with session.post(
                    flare_url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout / 1000 + 15)
                ) as resp:
                    if resp.status != 200:
                        crawl_page.error = f"flaresolverr_http_{resp.status}"
                        logger.debug(f"[FlareCrawl] HTTP {resp.status} for {url}")
                    else:
                        data = await resp.json()
                        if data.get("status") != "ok":
                            crawl_page.error = f"flaresolverr_error: {data.get('message', '')[:100]}"
                        else:
                            solution = data.get("solution", {})
                            html = solution.get("response", "")
                            cookies = solution.get("cookies", [])

                            crawl_page.status_code = solution.get("status", 200)
                            crawl_page.html = html
                            crawl_page.title = extract_title(html)

                            # Check if we still got a CF challenge
                            if any(sig in crawl_page.title.lower() for sig in CF_INDICATORS):
                                crawl_page.error = "cloudflare_not_bypassed"
                                crawl_page.html = ""
                                logger.debug(f"[FlareCrawl] CF not bypassed for {url}")
                            else:
                                # Extract cookies
                                for cookie in cookies:
                                    cname = cookie.get("name", "")
                                    cval = cookie.get("value", "")
                                    if cname and cval:
                                        crawl_page.cookies[cname] = cval
                                        result.all_cookies[cname] = cval
                                        if cname.lower() in B3_COOKIE_NAMES:
                                            result.b3_cookies[cname] = cval

                                # Extract links, forms, scripts
                                if html and depth < max_depth:
                                    new_links, forms, scripts = extract_links(
                                        html, url, base_domain
                                    )
                                    crawl_page.links_found = len(new_links)
                                    crawl_page.forms = forms
                                    crawl_page.scripts = list(scripts)

                                    for link in new_links:
                                        if link not in seen:
                                            if any(pat in link.lower() for pat in SKIP_PATTERNS):
                                                continue
                                            seen.add(link)
                                            result.all_urls.add(link)
                                            if urlparse(link).query:
                                                result.param_urls.add(link)
                                            queue.append((link, depth + 1))

                                    for form in forms:
                                        result.form_targets.append(form)
                                        if form.get("action"):
                                            result.param_urls.add(form["action"])

                                    for script in scripts:
                                        result.script_urls.add(script)

                                # Track param URLs from the page itself
                                if urlparse(url).query:
                                    result.param_urls.add(url)

            except asyncio.TimeoutError:
                crawl_page.error = "flaresolverr_timeout"
            except Exception as e:
                crawl_page.error = f"flaresolverr_error: {str(e)[:100]}"
                logger.debug(f"[FlareCrawl] Error on {url}: {e}")

            crawl_page.fetch_time = time.time() - t0
            fetched += 1
            result.pages.append(crawl_page)
            result.all_urls.add(url)
            result.total_fetched = fetched

            if depth > result.max_depth_reached:
                result.max_depth_reached = depth

            # Delay between requests
            if queue and fetched < max_pages:
                await asyncio.sleep(delay + random.uniform(0.2, 0.5))

        # Destroy FlareSolverr session
        if session_id:
            try:
                await session.post(flare_url, json={
                    "cmd": "sessions.destroy",
                    "session": session_id,
                }, timeout=aiohttp.ClientTimeout(total=10))
            except Exception:
                pass

    result.elapsed = time.time() - start_time

    logger.info(
        f"[FlareCrawl] Done: {base_domain} | "
        f"pages={result.total_fetched} | depth={result.max_depth_reached} | "
        f"urls={len(result.all_urls)} | params={len(result.param_urls)} | "
        f"forms={len(result.form_targets)} | cookies={len(result.all_cookies)} | "
        f"b3={len(result.b3_cookies)} | errors={result.errors} | "
        f"elapsed={result.elapsed:.1f}s"
    )

    return result


# ====================== SPA CONTENT EXTRACTION (v3.16) =================================

from dataclasses import dataclass, field

@dataclass
class SPAExtractionResult:
    """Result of rendering a SPA page with Playwright and extracting content."""
    url: str
    rendered_html: str = ""
    rendered_text: str = ""
    # Forms found in rendered DOM
    forms: List[Dict] = field(default_factory=list)
    # URL params found in rendered links
    param_urls: List[str] = field(default_factory=list)
    # Internal links
    internal_links: List[str] = field(default_factory=list)
    # Intercepted network requests (XHR/fetch)
    api_calls: List[Dict] = field(default_factory=list)
    # Cookies set during rendering
    cookies: Dict[str, str] = field(default_factory=dict)
    # JS errors encountered
    js_errors: List[str] = field(default_factory=list)
    # Console messages
    console_msgs: List[str] = field(default_factory=list)
    # Rendered page title
    title: str = ""
    # Framework detected
    framework: str = ""
    error: str = ""


async def spa_extract(
    url: str,
    cookies: Optional[Dict[str, str]] = None,
    wait_seconds: float = 3.0,
    scroll: bool = True,
    intercept_api: bool = True,
    headless: bool = True,
    timeout: int = 30000,
) -> SPAExtractionResult:
    """
    Render a SPA page with Playwright and extract the REAL content.
    
    This solves the core problem with modern SPAs:
    - aiohttp gets empty HTML shell (no forms, no params, no links)
    - Playwright renders the full React/Vue/Angular app
    - We intercept all XHR/fetch calls to discover API endpoints
    - We extract forms, links, and params from the rendered DOM
    
    Features:
      - Full JS rendering (React, Vue, Angular, Next.js, etc.)
      - Network request interception (captures all API calls)
      - Cookie injection (for authenticated scanning) 
      - Auto-scroll to trigger lazy-loaded content
      - Console/JS error capture
      - Returns rendered HTML + extracted attack surface
    """
    result = SPAExtractionResult(url=url)
    
    if not _HAS_PLAYWRIGHT:
        result.error = "Playwright not installed"
        return result
    
    api_calls_captured: List[Dict] = []
    console_messages: List[str] = []
    js_errors: List[str] = []
    
    playwright_instance = None
    browser = None
    
    try:
        playwright_instance = await async_playwright().start()
        browser = await playwright_instance.chromium.launch(
            headless=headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--disable-extensions",
                "--disable-dev-shm-usage",
            ],
        )
        
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            java_script_enabled=True,
            bypass_csp=True,
            ignore_https_errors=True,
        )
        
        # Apply stealth if available
        if _HAS_STEALTH and _stealth_instance:
            try:
                await _stealth_instance.apply_stealth_async(context)
            except Exception as e:
                logger.warning(f"[SPA] Stealth apply failed: {e}")
        
        # Inject cookies
        if cookies:
            parsed = urlparse(url)
            domain = parsed.hostname  # hostname only, no port
            cookie_list = []
            for name, value in cookies.items():
                from urllib.parse import unquote
                c = {
                    "name": name,
                    "value": unquote(value),
                    "domain": domain,
                    "path": "/",
                }
                # __Secure- prefix requires secure flag
                if name.startswith("__Secure-") or name.startswith("__Host-"):
                    c["secure"] = True
                cookie_list.append(c)
            await context.add_cookies(cookie_list)
        
        page = await context.new_page()
        page.set_default_timeout(timeout)
        
        # Setup network interception
        if intercept_api:
            async def on_request(request):
                req_url = request.url
                # Capture XHR/fetch requests (not images, CSS, etc.)
                if request.resource_type in ("xhr", "fetch", "websocket"):
                    api_calls_captured.append({
                        "url": req_url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "headers": dict(request.headers) if request.headers else {},
                        "post_data": request.post_data[:500] if request.post_data else None,
                    })
                # Also capture API-looking document requests
                elif request.resource_type == "document" and "/api/" in req_url:
                    api_calls_captured.append({
                        "url": req_url,
                        "method": request.method,
                        "resource_type": "document_api",
                        "headers": {},
                        "post_data": None,
                    })
            
            page.on("request", on_request)
        
        # Capture console messages
        def on_console(msg):
            text = f"[{msg.type}] {msg.text}"
            console_messages.append(text)
        
        page.on("console", on_console)
        
        # Capture JS errors
        def on_page_error(error):
            js_errors.append(str(error))
        
        page.on("pageerror", on_page_error)
        
        # Navigate to the page
        logger.info(f"[SPA] Rendering {url} with Playwright...")
        try:
            response = await page.goto(url, wait_until="networkidle", timeout=timeout)
        except PlaywrightTimeout:
            # Even on timeout, we may have partial content
            logger.warning(f"[SPA] Navigation timeout for {url}, extracting partial content")
        
        # Wait for SPA to fully render
        await asyncio.sleep(wait_seconds)
        
        # Scroll to trigger lazy loading
        if scroll:
            for _ in range(5):
                await page.evaluate("window.scrollBy(0, window.innerHeight)")
                await asyncio.sleep(0.5)
            # Scroll back to top
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(1.0)
        
        # Extract rendered HTML
        result.rendered_html = await page.content()
        result.rendered_text = await page.evaluate("document.body?.innerText || ''")
        result.title = await page.title()
        
        # Extract forms from rendered DOM
        forms_data = await page.evaluate("""() => {
            const forms = [];
            document.querySelectorAll('form').forEach(form => {
                const inputs = [];
                form.querySelectorAll('input, textarea, select').forEach(el => {
                    inputs.push({
                        tag: el.tagName.toLowerCase(),
                        type: el.type || '',
                        name: el.name || '',
                        id: el.id || '',
                        value: el.value || '',
                        placeholder: el.placeholder || '',
                    });
                });
                forms.push({
                    action: form.action || '',
                    method: form.method || 'GET',
                    id: form.id || '',
                    inputs: inputs,
                });
            });
            return forms;
        }""")
        result.forms = forms_data
        
        # Extract all links from rendered DOM
        links_data = await page.evaluate("""() => {
            const links = [];
            document.querySelectorAll('a[href]').forEach(a => {
                links.push(a.href);
            });
            return links;
        }""")
        
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc.lower()
        for link in links_data:
            try:
                lp = urlparse(link)
                if lp.netloc.lower() == base_domain or not lp.netloc:
                    result.internal_links.append(link)
                    if lp.query:
                        result.param_urls.append(link)
            except Exception:
                pass
        
        # Extract cookies
        browser_cookies = await context.cookies()
        for c in browser_cookies:
            result.cookies[c["name"]] = c["value"]
        
        # Store captured API calls
        result.api_calls = api_calls_captured
        result.console_msgs = console_messages
        result.js_errors = js_errors
        
        # Framework detection from rendered content
        if "__NEXT_DATA__" in result.rendered_html or "_next/static" in result.rendered_html:
            result.framework = "next.js"
        elif "__NUXT__" in result.rendered_html:
            result.framework = "nuxt"
        elif "ng-version" in result.rendered_html:
            result.framework = "angular"
        elif "data-reactroot" in result.rendered_html or "__REACT" in result.rendered_html:
            result.framework = "react"
        elif "__vue__" in result.rendered_html.lower():
            result.framework = "vue"
        
        logger.info(
            f"[SPA] Extraction complete for {parsed_base.netloc}: "
            f"forms={len(result.forms)}, param_urls={len(result.param_urls)}, "
            f"links={len(result.internal_links)}, api_calls={len(result.api_calls)}, "
            f"cookies={len(result.cookies)}, framework={result.framework or 'unknown'}"
        )
        
    except Exception as e:
        result.error = str(e)
        logger.error(f"[SPA] Extraction error for {url}: {e}")
    finally:
        if browser:
            await browser.close()
        if playwright_instance:
            await playwright_instance.stop()
    
    return result


async def spa_extract_with_flaresolverr(
    url: str,
    cookies: Optional[Dict[str, str]] = None,
    wait_seconds: float = 3.0,
) -> SPAExtractionResult:
    """
    Fallback SPA extraction using FlareSolverr when Playwright fails
    or when Cloudflare blocks direct browser access.
    
    FlareSolverr handles CF Turnstile automatically, then we parse
    the rendered HTML it returns for forms, links, params.
    """
    import aiohttp
    from bs4 import BeautifulSoup
    
    result = SPAExtractionResult(url=url)
    flare_url = "http://localhost:8191/v1"
    
    try:
        async with aiohttp.ClientSession() as session:
            # Create FlareSolverr session
            payload = {"cmd": "sessions.create"}
            async with session.post(flare_url, json=payload) as resp:
                data = await resp.json()
                flare_session = data.get("session", "")
            
            if not flare_session:
                result.error = "Failed to create FlareSolverr session"
                return result
            
            try:
                # Fetch page through FlareSolverr
                payload = {
                    "cmd": "request.get",
                    "url": url,
                    "session": flare_session,
                    "maxTimeout": 60000,
                }
                if cookies:
                    payload["cookies"] = [
                        {"name": k, "value": v, "url": url}
                        for k, v in cookies.items()
                    ]
                
                async with session.post(flare_url, json=payload, timeout=aiohttp.ClientTimeout(total=90)) as resp:
                    data = await resp.json()
                
                solution = data.get("solution", {})
                html = solution.get("response", "")
                
                if not html:
                    result.error = "FlareSolverr returned empty response"
                    return result
                
                result.rendered_html = html
                
                # Parse cookies
                for cookie in solution.get("cookies", []):
                    result.cookies[cookie["name"]] = cookie["value"]
                
                # Parse rendered HTML
                soup = BeautifulSoup(html, "lxml")
                
                # Title
                title_tag = soup.find("title")
                result.title = title_tag.get_text(strip=True) if title_tag else ""
                
                # Text content
                result.rendered_text = soup.get_text(separator="\n", strip=True)[:10000]
                
                # Forms
                for form in soup.find_all("form"):
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inputs.append({
                            "tag": inp.name,
                            "type": inp.get("type", ""),
                            "name": inp.get("name", ""),
                            "id": inp.get("id", ""),
                            "value": inp.get("value", ""),
                            "placeholder": inp.get("placeholder", ""),
                        })
                    result.forms.append({
                        "action": form.get("action", ""),
                        "method": form.get("method", "GET"),
                        "id": form.get("id", ""),
                        "inputs": inputs,
                    })
                
                # Links
                parsed_base = urlparse(url)
                base_domain = parsed_base.netloc.lower()
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("/"):
                        href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
                    try:
                        lp = urlparse(href)
                        if lp.netloc.lower() == base_domain or not lp.netloc:
                            result.internal_links.append(href)
                            if lp.query:
                                result.param_urls.append(href)
                    except Exception:
                        pass
                
                # Framework detection
                if "__NEXT_DATA__" in html or "_next/static" in html:
                    result.framework = "next.js"
                elif "__NUXT__" in html:
                    result.framework = "nuxt"
                elif "ng-version" in html:
                    result.framework = "angular"
                
                logger.info(
                    f"[SPA-Flare] Extraction complete: forms={len(result.forms)}, "
                    f"links={len(result.internal_links)}, params={len(result.param_urls)}, "
                    f"cookies={len(result.cookies)}"
                )
                
            finally:
                # Destroy session
                try:
                    payload = {"cmd": "sessions.destroy", "session": flare_session}
                    await session.post(flare_url, json=payload)
                except Exception:
                    pass
    
    except Exception as e:
        result.error = str(e)
        logger.error(f"[SPA-Flare] Extraction error for {url}: {e}")
    
    return result


# ====================== BROWSER SEARCH ENGINE (for ENGINE_REGISTRY) ======================

class BrowserSearchEngine:
    """
    SearchEngine-compatible wrapper for BrowserManager.
    
    Used in MultiSearch as a fallback when all HTTP-based engines fail.
    Not in ENGINE_REGISTRY — called separately after all engines exhaust.
    """
    name = "browser"

    def __init__(self, browser_manager: BrowserManager,
                 captcha_solver=None,
                 engines: Optional[List[str]] = None):
        self.browser = browser_manager
        self.captcha_solver = captcha_solver
        self.engines = engines or ["google", "bing", "duckduckgo", "startpage"]

    async def search(self, query: str, num_results: int = 15) -> List[str]:
        """Search using the headless browser as last resort."""
        return await self.browser.search_multi_engine(
            query=query,
            num_results=num_results,
            engines=self.engines,
            captcha_solver=self.captcha_solver,
        )
