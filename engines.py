"""
Search Engines Module v2 — Health tracking, pagination, session reuse,
adaptive rate limiting, dork effectiveness scoring
"""

import re
import random
import asyncio
import time
from typing import List, Optional, Dict, Tuple
from urllib.parse import quote, urljoin, urlparse
from bs4 import BeautifulSoup
import aiohttp
from loguru import logger
from collections import defaultdict
from enum import Enum

# Captcha solver integration (Phase 1)
try:
    from captcha_solver import CaptchaSolver, SitekeyExtractor, CaptchaType
    _HAS_CAPTCHA_SOLVER = True
except ImportError:
    _HAS_CAPTCHA_SOLVER = False

# Proxy manager integration (Phase 2)
try:
    from proxy_manager import ProxyManager, ProxyInfo
    _HAS_PROXY_MANAGER = True
except ImportError:
    _HAS_PROXY_MANAGER = False

# Headless browser integration (Phase 3 — search resilience)
try:
    from browser_engine import BrowserManager, BrowserSearchEngine
    _HAS_BROWSER = True
except ImportError:
    _HAS_BROWSER = False


# ────────────────────────── ENGINE STATUS ENUM ──────────────────────────

class EngineStatus(Enum):
    """Per-engine operational status (from DVParser EngineManager pattern)."""
    ACTIVE = "active"          # Normal operation
    COOLDOWN = "cooldown"      # Temporary backoff after failures
    BLOCKED = "blocked"        # Detected IP/engine ban (403/captcha)
    THROTTLED = "throttled"    # Returning fewer results than expected


# ────────────────────────── ENGINE HEALTH TRACKER ──────────────────────────

class EngineHealth:
    """Tracks success/failure rate per engine with cooldown, per-engine
    adaptive delays, and fine-grained status tracking.

    Enhanced with DVParser EngineManager pattern:
    - EngineStatus enum (ACTIVE / COOLDOWN / BLOCKED / THROTTLED)
    - Per-engine adaptive delay based on individual failure rate
    - Blocked status on captcha / 403 detection
    - Throttled status when result count drops below threshold
    """

    def __init__(self, cooldown: float = 120, blocked_cooldown: float = 600):
        self.cooldown = cooldown
        self.blocked_cooldown = blocked_cooldown
        self._success: Dict[str, int] = defaultdict(int)
        self._failure: Dict[str, int] = defaultdict(int)
        self._consecutive_fail: Dict[str, int] = defaultdict(int)
        self._cooldown_until: Dict[str, float] = {}
        self._status: Dict[str, EngineStatus] = {}
        self._requests: Dict[str, int] = defaultdict(int)
        # Per-engine delay params (adaptive) — tuned for speed
        self._base_delay_min: float = 0.3
        self._base_delay_max: float = 1.0
        # Exponential backoff for persistently blocked engines
        self._block_count: Dict[str, int] = defaultdict(int)

    def record_success(self, engine: str, count: int = 1):
        self._success[engine] += 1
        self._requests[engine] += 1
        self._consecutive_fail[engine] = 0
        self._block_count[engine] = 0  # Reset exponential backoff on success
        # If engine was throttled and now returning well, restore ACTIVE
        if self._status.get(engine) == EngineStatus.THROTTLED and count >= 3:
            self._status[engine] = EngineStatus.ACTIVE
        elif self._status.get(engine) != EngineStatus.BLOCKED:
            self._status[engine] = EngineStatus.ACTIVE

    def record_failure(self, engine: str):
        self._failure[engine] += 1
        self._requests[engine] += 1
        self._consecutive_fail[engine] += 1
        if self._consecutive_fail[engine] >= 5:
            # Extended cooldown after 5 consecutive failures
            self._cooldown_until[engine] = time.time() + self.cooldown * 2
            self._status[engine] = EngineStatus.BLOCKED
            logger.warning(f"Engine {engine} BLOCKED — {self.cooldown * 2:.0f}s cooldown")
        elif self._consecutive_fail[engine] >= 3:
            self._cooldown_until[engine] = time.time() + self.cooldown
            self._status[engine] = EngineStatus.COOLDOWN
            logger.warning(f"Engine {engine} cooled down for {self.cooldown}s")

    def record_blocked(self, engine: str):
        """Mark engine as blocked (captcha / 403 / hard ban).
        Uses exponential backoff — engines that keep getting blocked
        stay blocked longer (up to 1 hour).
        Idempotent: if already BLOCKED, concurrent tasks won't re-escalate."""
        if self._status.get(engine) == EngineStatus.BLOCKED:
            return  # Already blocked — don't re-escalate from concurrent requests
        self._failure[engine] += 1
        self._requests[engine] += 1
        self._consecutive_fail[engine] += 1
        self._block_count[engine] += 1
        # Exponential backoff: 900s, 1800s, 3600s, 3600s, ...
        backoff_multiplier = min(self._block_count[engine], 4)  # Cap at 4x
        effective_cooldown = self.blocked_cooldown * backoff_multiplier
        self._cooldown_until[engine] = time.time() + effective_cooldown
        self._status[engine] = EngineStatus.BLOCKED
        if self._block_count[engine] <= 2:
            logger.warning(f"Engine {engine} BLOCKED (captcha/ban) — {effective_cooldown:.0f}s cooldown")
        # After 2 blocks, stop spamming logs — it's clearly a persistent block

    def record_throttled(self, engine: str):
        """Mark engine as throttled (returning fewer results than expected)."""
        self._status[engine] = EngineStatus.THROTTLED

    def get_status(self, engine: str) -> EngineStatus:
        """Get current status of an engine."""
        if not self.is_available(engine):
            return self._status.get(engine, EngineStatus.COOLDOWN)
        return self._status.get(engine, EngineStatus.ACTIVE)

    def is_available(self, engine: str) -> bool:
        return time.time() >= self._cooldown_until.get(engine, 0)

    def success_rate(self, engine: str) -> float:
        total = self._success[engine] + self._failure[engine]
        return self._success[engine] / total if total else 1.0

    def get_delay_for_engine(self, engine: str) -> float:
        """Per-engine adaptive delay based on individual failure rate.
        Higher failure rate → longer delay. Blocked engines get max delay.
        From DVParser EngineManager pattern."""
        status = self.get_status(engine)
        if status == EngineStatus.BLOCKED:
            return 0.0  # Skip instantly — blocked engines are checked in is_available()
        if status == EngineStatus.THROTTLED:
            return random.uniform(1.0, 2.0)  # Brief delay for throttled

        fail_rate = 1.0 - self.success_rate(engine)
        # Scale delay: 0% fail = base, 50% fail = 1.5x base, 100% fail = 2x base
        multiplier = 1.0 + (fail_rate * 1.0)
        delay_min = self._base_delay_min * multiplier
        delay_max = self._base_delay_max * multiplier
        return random.uniform(delay_min, min(delay_max, 3.0))

    def sorted_engines(self, names: List[str]) -> List[str]:
        available = [n for n in names if self.is_available(n)]
        cooled = [n for n in names if not self.is_available(n)]
        # Sort available by: ACTIVE first, then THROTTLED, then by success rate
        def _sort_key(n):
            status = self.get_status(n)
            status_priority = {EngineStatus.ACTIVE: 0, EngineStatus.THROTTLED: 1,
                               EngineStatus.COOLDOWN: 2, EngineStatus.BLOCKED: 3}
            return (status_priority.get(status, 9), -self.success_rate(n))
        available.sort(key=_sort_key)
        return available + cooled

    def get_stats(self) -> Dict:
        engines = set(list(self._success.keys()) + list(self._failure.keys()))
        return {
            name: {
                "success": self._success[name],
                "fail": self._failure[name],
                "requests": self._requests[name],
                "rate": f"{self.success_rate(name):.0%}",
                "status": self.get_status(name).value,
                "available": self.is_available(name),
                "delay": f"{self.get_delay_for_engine(name):.1f}s",
            }
            for name in engines
        }


# ────────────────────────── DORK EFFECTIVENESS SCORER ──────────────────────────

class DorkScorer:
    """Scores dorks by URL yield. Prioritises productive dorks."""

    def __init__(self):
        self._hits: Dict[str, int] = defaultdict(int)
        self._uses: Dict[str, int] = defaultdict(int)

    def record(self, dork: str, url_count: int):
        self._hits[dork] += url_count
        self._uses[dork] += 1

    def score(self, dork: str) -> float:
        uses = self._uses.get(dork, 0)
        return self._hits[dork] / uses if uses else 0.5

    def sort_dorks(self, dorks: List[str]) -> List[str]:
        tried = [d for d in dorks if d in self._uses]
        untried = [d for d in dorks if d not in self._uses]
        tried.sort(key=lambda d: self.score(d), reverse=True)
        result = []
        untried_iter = iter(untried)
        for i, d in enumerate(tried):
            result.append(d)
            if (i + 1) % 5 == 0:
                try:
                    result.append(next(untried_iter))
                except StopIteration:
                    pass
        for d in untried_iter:
            result.append(d)
        return result

    def get_top(self, n: int = 20) -> List[Tuple[str, float]]:
        scored = [(d, self.score(d)) for d in self._uses]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:n]


# ────────────────────────── ADAPTIVE RATE LIMITER ──────────────────────────

class AdaptiveRateLimiter:
    """Exponential backoff on rate-limits, tighten delay when flowing."""

    def __init__(self, base_min: float = 3, base_max: float = 8, max_delay: float = 120):
        self.base_min = base_min
        self.base_max = base_max
        self.max_delay = max_delay
        self._current_min = base_min
        self._current_max = base_max
        self._last_escalation: float = 0.0  # Debounce concurrent hits

    def got_rate_limited(self):
        now = time.time()
        if now - self._last_escalation < 10.0:
            return  # Debounce: concurrent tasks hitting same block — don't stack
        self._last_escalation = now
        self._current_min = min(self._current_min * 2, self.max_delay)
        self._current_max = min(self._current_max * 2, self.max_delay)
        logger.info(f"Rate limited — delay now {self._current_min:.0f}-{self._current_max:.0f}s")

    def got_success(self):
        self._current_min = max(self._current_min * 0.9, self.base_min)
        self._current_max = max(self._current_max * 0.9, self.base_max)

    async def wait(self):
        await asyncio.sleep(random.uniform(self._current_min, self._current_max))

    @property
    def current_range(self) -> Tuple[float, float]:
        return (self._current_min, self._current_max)


# ────────────────────────── RATE LIMIT EXCEPTION ──────────────────────────

class RateLimitError(Exception):
    def __init__(self, engine: str, html: str = "", url: str = ""):
        self.engine = engine
        self.html = html      # Page body (for captcha detection)
        self.url = url        # Request URL (for captcha solving)
        super().__init__(f"{engine} rate-limited")


class CaptchaDetectedError(RateLimitError):
    """Raised when a solvable captcha is detected (subclass of RateLimitError)."""
    def __init__(self, engine: str, html: str = "", url: str = "",
                 captcha_info: Optional[Dict] = None):
        super().__init__(engine, html, url)
        self.captcha_info = captcha_info or {}


# ────────────────────────── SEARCH ENGINE BASE ──────────────────────────

class SearchEngine:
    name: str = "base"

    def __init__(self, proxy: Optional[str] = None, session: aiohttp.ClientSession = None):
        self.proxy = proxy
        self._session = session
        self.headers = {
            "User-Agent": self._random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def _random_ua(self) -> str:
        return random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0 Safari/537.36",
        ])

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session and not self._session.closed:
            return self._session
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False, limit=10),
        )
        return self._session

    async def close(self):
        """Close the underlying HTTP session to prevent resource leaks."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        raise NotImplementedError

    def _is_rate_limited(self, status: int, body: str) -> bool:
        if status in (429, 403):
            return True
        for p in [r"too many requests", r"rate.?limit", r"captcha",
                  r"unusual traffic", r"please verify", r"robot"]:
            if re.search(p, body[:2000], re.I):
                return True
        return False

    def _detect_captcha_in_response(self, status: int, body: str, url: str):
        """Check if response contains a solvable captcha. Raises CaptchaDetectedError if so,
        RateLimitError if rate-limited but no solvable captcha, or does nothing if OK."""
        if not self._is_rate_limited(status, body):
            return  # Not rate limited, proceed normally

        # Check if we can detect a solvable captcha
        if _HAS_CAPTCHA_SOLVER:
            captcha_info = SitekeyExtractor.detect(body)
            if captcha_info and captcha_info.get("sitekey"):
                raise CaptchaDetectedError(
                    engine=self.name, html=body, url=url,
                    captcha_info=captcha_info
                )

        # Generic rate limit (no solvable captcha found)
        raise RateLimitError(self.name, html=body, url=url)


# ────────────────────────── ENGINE IMPLEMENTATIONS ──────────────────────────

class DuckDuckGoSearch(SearchEngine):
    name = "duckduckgo"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        if page > 0:
            url += f"&s={page * 30}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for link in soup.find_all("a", class_="result__a"):
                        href = link.get("href", "")
                        if href and not href.startswith("/"):
                            if "uddg=" in href:
                                m = re.search(r'uddg=([^&]+)', href)
                                if m:
                                    from urllib.parse import unquote
                                    href = unquote(m.group(1))
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[DDG] Search error: {e}")
            return []


class BingSearch(SearchEngine):
    name = "bing"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * num_results
        url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}&first={offset + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="b_algo"):
                        link = li.find("a")
                        if link:
                            href = link.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Bing] Search error: {e}")
            return []


class StartpageSearch(SearchEngine):
    name = "startpage"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get("https://www.startpage.com/", headers=self.headers,
                                       proxy=self.proxy, ssl=False):
                    pass
                data = {"query": query, "cat": "web", "language": "english"}
                if page > 0:
                    data["page"] = str(page + 1)
                async with session.post("https://www.startpage.com/sp/search", headers=self.headers,
                                        data=data, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, "https://www.startpage.com/sp/search")
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_="w-gl__result"):
                        link = div.find("a", class_="w-gl__result-url")
                        if link:
                            href = link.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for a in soup.find_all("a", class_="result-link"):
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Startpage] Search error: {e}")
            return []


class YahooSearch(SearchEngine):
    name = "yahoo"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * 10
        url = f"https://search.yahoo.com/search?p={quote(query)}&n={num_results}&b={offset + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_="compTitle"):
                        link = div.find("a")
                        if link:
                            href = link.get("href", "")
                            if "RU=" in href:
                                m = re.search(r'RU=([^/]+)', href)
                                if m:
                                    from urllib.parse import unquote
                                    href = unquote(m.group(1))
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Yahoo] Search error: {e}")
            return []


class EcosiaSearch(SearchEngine):
    name = "ecosia"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.ecosia.org/search?method=index&q={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_="result__link"):
                        href = a.get("href", "")
                        if href and href.startswith("http"):
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for div in soup.find_all("div", {"class": re.compile(r"result")}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http"):
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Ecosia] Search error: {e}")
            return []


class QwantSearch(SearchEngine):
    name = "qwant"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * num_results
        url = f"https://api.qwant.com/v3/search/web?q={quote(query)}&count={num_results}&locale=en_US&offset={offset}"
        try:
            headers = self.headers.copy()
            headers["Accept"] = "application/json"
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    results = []
                    items = data.get("data", {}).get("result", {}).get("items", {}).get("mainline", [])
                    for group in items:
                        for item in group.get("items", []):
                            u = item.get("url", "")
                            if u and u.startswith("http"):
                                results.append(u)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Qwant] Search error: {e}")
            return []


class BraveSearch(SearchEngine):
    name = "brave"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * 10
        url = f"https://search.brave.com/search?q={quote(query)}&source=web&offset={offset}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_="snippet"):
                        a = div.find("a", class_="result-header")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for a in soup.find_all("a", {"class": re.compile(r"heading")}):
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Brave] Search error: {e}")
            return []


class AOLSearch(SearchEngine):
    name = "aol"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * 10
        url = f"https://search.aol.com/aol/search?q={quote(query)}&b={offset + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_="algo-sr"):
                        a = div.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[AOL] Search error: {e}")
            return []


# ────────────────────────── YANDEX ENGINE ──────────────────────────

class YandexSearch(SearchEngine):
    """Yandex — large independent index, good non-Western coverage."""
    name = "yandex"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.com/search/?text={quote(query)}&p={page}&lr=84"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-US,en;q=0.9,ru;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    # Organic results: <li class="serp-item"> → <a> with href
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: data-cid organic blocks
                    if not results:
                        for div in soup.find_all("div", attrs={"data-cid": True}):
                            a = div.find("a", class_=re.compile(r"link|title|organic", re.I))
                            if not a:
                                a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http") and "yandex" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    # Third pass: any link matching organic patterns
                    if not results:
                        for a in soup.find_all("a"):
                            href = a.get("href", "")
                            if (href and href.startswith("http")
                                    and "yandex" not in href
                                    and "yastatic" not in href
                                    and not href.endswith(".js")):
                                text = a.get_text(strip=True)
                                if text and len(text) > 10:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Yandex] Search error: {e}")
            return []


# ────────────────────────── ASK.COM ENGINE ──────────────────────────

class AskSearch(SearchEngine):
    """Ask.com — lightweight search engine."""
    name = "ask"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.ask.com/web?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    # Ask.com uses PartialSearchResults-item divs
                    for div in soup.find_all("div", class_=re.compile(r"PartialSearchResults-item|result", re.I)):
                        a = div.find("a", class_=re.compile(r"PartialSearchResults-item-title-link|result-link", re.I))
                        if not a:
                            a = div.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "ask.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: generic anchor search
                    if not results:
                        for a in soup.find_all("a"):
                            href = a.get("href", "")
                            if (href and href.startswith("http")
                                    and "ask.com" not in href
                                    and "/web?" not in href):
                                text = a.get_text(strip=True)
                                if text and len(text) > 8:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Ask] Search error: {e}")
            return []


# ────────────────────────── DOGPILE ENGINE ──────────────────────────

class DogpileSearch(SearchEngine):
    """Dogpile — meta-search aggregator hitting multiple backends."""
    name = "dogpile"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        qsi = page * 10 + 1
        url = f"https://www.dogpile.com/serp?q={quote(query)}&qsi={qsi}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    # Dogpile organic results
                    for div in soup.find_all("div", class_=re.compile(r"web-bing__result|result", re.I)):
                        a = div.find("a", class_=re.compile(r"web-bing__title|result__a", re.I))
                        if not a:
                            a = div.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "dogpile.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: look for any external links in result containers
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http")
                                    and "dogpile.com" not in href
                                    and "infospace.com" not in href):
                                text = a.get_text(strip=True)
                                if text and len(text) > 8:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Dogpile] Search error: {e}")
            return []


# ────────────────────────── SEARXNG ENGINE ──────────────────────────

# Pool of public SearXNG instances for load distribution
SEARXNG_INSTANCES = [
    "https://searx.be",
    "https://search.bus-hit.me",
    "https://searx.tiekoetter.com",
    "https://search.ononoki.org",
    "https://searx.zhenyapav.com",
    "https://etsi.me",
    "https://priv.au",
    "https://searx.work",
    "https://search.sapti.me",
    "https://paulgo.io",
]


class SearXNGSearch(SearchEngine):
    """SearXNG — open meta-search engine hitting multiple backends per query."""
    name = "searxng"

    def __init__(self, proxy: Optional[str] = None, session: aiohttp.ClientSession = None,
                 instance_url: Optional[str] = None):
        super().__init__(proxy=proxy, session=session)
        self._instances = list(SEARXNG_INSTANCES)
        random.shuffle(self._instances)
        self._instance_idx = 0
        self._custom_instance = instance_url

    def _next_instance(self) -> str:
        if self._custom_instance:
            return self._custom_instance.rstrip("/")
        inst = self._instances[self._instance_idx % len(self._instances)]
        self._instance_idx += 1
        return inst

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        # Try JSON API first, then HTML fallback
        for attempt in range(min(3, len(self._instances))):
            base = self._next_instance()
            # JSON API endpoint
            api_url = f"{base}/search?q={quote(query)}&format=json&pageno={page + 1}&language=en&safesearch=0"
            try:
                session = await self._get_session()
                own = session is not self._session
                try:
                    headers = self.headers.copy()
                    headers["Accept"] = "application/json, text/html"
                    async with session.get(api_url, headers=headers, proxy=self.proxy,
                                           ssl=False, allow_redirects=True) as resp:
                        if resp.status != 200:
                            continue
                        content_type = resp.headers.get("Content-Type", "")
                        if "json" in content_type:
                            data = await resp.json()
                            results = []
                            for item in data.get("results", []):
                                u = item.get("url", "")
                                if u and u.startswith("http"):
                                    results.append(u)
                                    if len(results) >= num_results:
                                        break
                            if results:
                                return results
                        else:
                            # HTML fallback
                            html = await resp.text()
                            self._detect_captcha_in_response(resp.status, html, api_url)
                            soup = BeautifulSoup(html, "html.parser")
                            results = []
                            for h3 in soup.find_all("h3"):
                                a = h3.find("a")
                                if a:
                                    href = a.get("href", "")
                                    if href and href.startswith("http"):
                                        results.append(href)
                                        if len(results) >= num_results:
                                            break
                            # Alt: result div pattern
                            if not results:
                                for div in soup.find_all("article", class_="result"):
                                    a = div.find("a")
                                    if a:
                                        href = a.get("href", "")
                                        if href and href.startswith("http"):
                                            results.append(href)
                                            if len(results) >= num_results:
                                                break
                            if results:
                                return results
                finally:
                    if own:
                        await session.close()
            except RateLimitError:
                raise
            except Exception as e:
                logger.debug(f"[SearXNG] Instance {base} failed: {e}")
                continue

        logger.error("[SearXNG] All instances failed")
        return []


# ────────────────────────── YOU.COM ENGINE ──────────────────────────

class YouSearch(SearchEngine):
    """You.com — modern search engine with good web coverage."""
    name = "you"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://you.com/search?q={quote(query)}&tbm=web"
        if page > 0:
            url += f"&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    results = []
                    # You.com embeds results in data attributes and JS payloads;
                    # extract URLs from the HTML using regex as primary approach
                    soup = BeautifulSoup(html, "html.parser")
                    # Method 1: <a> tags with data-testid or in result containers
                    for a in soup.find_all("a", attrs={"data-testid": re.compile(r"result", re.I)}):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "you.com" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    # Method 2: result card divs
                    if not results:
                        for div in soup.find_all("div", attrs={"data-testid": re.compile(r"web-result|snippet", re.I)}):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "you.com" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    # Method 3: JSON-LD or embedded script data
                    if not results:
                        for script in soup.find_all("script"):
                            text = script.string or ""
                            urls = re.findall(r'"url"\s*:\s*"(https?://[^"]+)"', text)
                            for u in urls:
                                if "you.com" not in u and u not in results:
                                    results.append(u)
                                    if len(results) >= num_results:
                                        break
                            if len(results) >= num_results:
                                break
                    # Method 4: any external link with meaningful text
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http")
                                    and "you.com" not in href
                                    and not href.endswith((".js", ".css", ".png", ".jpg"))):
                                text = a.get_text(strip=True)
                                if text and len(text) > 10:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[You] Search error: {e}")
            return []


# ────────────────────────── MOJEEK ENGINE ──────────────────────────

class MojeekSearch(SearchEngine):
    """Mojeek — independent UK search engine with its own crawler. No JS needed."""
    name = "mojeek"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * num_results
        url = f"https://www.mojeek.com/search?q={quote(query)}&s={offset}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    # Primary: <ul class="results-standard"> → <li> → <a>
                    for li in soup.find_all("li", class_=re.compile(r"results-standard")):
                        a = li.find("a", href=True)
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "mojeek" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: any <a class="ob"> (Mojeek organic block links)
                    if not results:
                        for a in soup.find_all("a", class_="ob"):
                            href = a.get("href", "")
                            if href and href.startswith("http") and "mojeek" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback 2: generic <li> with title links
                    if not results:
                        for li in soup.find_all("li"):
                            a = li.find("a", href=True)
                            if a:
                                href = a.get("href", "")
                                if (href and href.startswith("http")
                                        and "mojeek" not in href
                                        and not href.endswith((".css", ".js", ".png"))):
                                    text = a.get_text(strip=True)
                                    if text and len(text) > 8:
                                        results.append(href)
                                        if len(results) >= num_results:
                                            break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Mojeek] Search error: {e}")
            return []


# ────────────────────────── NAVER ENGINE ──────────────────────────

class NaverSearch(SearchEngine):
    """Naver — South Korea's largest search engine with its own web crawler.
    Supports inurl/site dorking. Excellent non-duplicate coverage."""
    name = "naver"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        start = page * 10 + 1
        url = f"https://search.naver.com/search.naver?where=webkr&query={quote(query)}&start={start}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-US,en;q=0.9,ko;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    seen = set()
                    # Naver web results: <a class="link_tit" or class="total_tit"> or <a> in <div class="total_wrap">
                    for div in soup.find_all("div", class_=re.compile(r"total_wrap|api_txt_lines|web_detail")):
                        a = div.find("a", href=True)
                        if a:
                            href = a.get("href", "")
                            if (href and href.startswith("http")
                                    and "naver.com" not in href
                                    and "naver.net" not in href
                                    and href not in seen):
                                seen.add(href)
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: any external link with meaningful text
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http")
                                    and "naver.com" not in href
                                    and "naver.net" not in href
                                    and href not in seen):
                                text = a.get_text(strip=True)
                                if text and len(text) > 5:
                                    seen.add(href)
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Naver] Search error: {e}")
            return []


# ────────────────────────── FIRECRAWL ENGINE ──────────────────────────

class FirecrawlSearch(SearchEngine):
    """Firecrawl-powered search — no captchas, no rate limits, JS rendering built-in."""
    name = "firecrawl"

    def __init__(self, api_key: str = "", search_limit: int = 20,
                 proxy: Optional[str] = None, session: aiohttp.ClientSession = None,
                 as_fallback: bool = False):
        super().__init__(proxy=proxy, session=session)
        self.api_key = api_key
        self.search_limit = search_limit
        self.as_fallback = as_fallback
        self._fc = None

    def _get_firecrawl(self):
        if self._fc is None:
            try:
                from firecrawl import FirecrawlApp
                self._fc = FirecrawlApp(api_key=self.api_key)
            except ImportError:
                logger.error("[Firecrawl] firecrawl-py not installed: pip install firecrawl-py")
                return None
            except Exception as e:
                logger.error(f"[Firecrawl] Init error: {e}")
                return None
        return self._fc

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        """Search via Firecrawl API. Page param ignored — FC handles internally."""
        if page > 0:
            return []  # Firecrawl doesn't paginate like HTTP engines

        fc = self._get_firecrawl()
        if not fc:
            return []

        try:
            limit = min(num_results, self.search_limit)
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: fc.search(query=query, limit=limit)
            )

            urls = []
            # v2 API: result.web is a list of SearchResultWeb objects
            web_results = []
            if result and hasattr(result, 'web') and result.web:
                web_results = result.web
            elif result and hasattr(result, 'data') and result.data:
                # Fallback for potential older API
                web_results = result.data

            for item in web_results:
                url = None
                if hasattr(item, 'url'):
                    url = item.url
                elif isinstance(item, dict):
                    url = item.get("url", "")
                if url and url.startswith("http"):
                    urls.append(url)
                    if len(urls) >= num_results:
                        break

            logger.info(f"[Firecrawl] Search returned {len(urls)} URLs for: {query[:60]}")
            return urls

        except Exception as e:
            logger.error(f"[Firecrawl] Search error: {e}")
            return []

    async def scrape(self, url: str, formats: List[str] = None) -> Optional[Dict]:
        """Scrape a page via Firecrawl — returns markdown, HTML, links."""
        fc = self._get_firecrawl()
        if not fc:
            return None

        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: fc.scrape(url, formats=formats or ["markdown", "html", "links"])
            )
            if result:
                # v2 API: result is a Document (pydantic model)
                doc = {}
                if hasattr(result, 'model_dump'):
                    doc = result.model_dump()
                elif hasattr(result, '__dict__'):
                    doc = vars(result)
                elif isinstance(result, dict):
                    doc = result
                # Flatten metadata.url into top-level
                meta = doc.get("metadata")
                if meta:
                    if hasattr(meta, 'url'):
                        doc["url"] = meta.url
                    elif isinstance(meta, dict):
                        doc["url"] = meta.get("url", "") or meta.get("source_url", "")
                return doc
        except Exception as e:
            logger.error(f"[Firecrawl] Scrape error for {url}: {e}")
        return None

    async def crawl(self, url: str, limit: int = 100) -> List[Dict]:
        """Crawl a domain via Firecrawl — returns all pages with content."""
        fc = self._get_firecrawl()
        if not fc:
            return []

        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: fc.crawl(url=url, limit=limit)
            )
            pages = []
            if result and hasattr(result, 'data') and result.data:
                for pg in result.data:
                    page_dict = {}
                    if hasattr(pg, 'model_dump'):
                        page_dict = pg.model_dump()
                    elif hasattr(pg, '__dict__'):
                        page_dict = vars(pg)
                    elif isinstance(pg, dict):
                        page_dict = pg
                    if page_dict:
                        # Normalize metadata for consumer code
                        meta = page_dict.get("metadata")
                        if meta:
                            if hasattr(meta, 'model_dump'):
                                page_dict["metadata"] = meta.model_dump()
                            elif hasattr(meta, '__dict__') and not isinstance(meta, dict):
                                page_dict["metadata"] = vars(meta)
                        pages.append(page_dict)

            logger.info(f"[Firecrawl] Crawl returned {len(pages)} pages for: {url}")
            return pages

        except Exception as e:
            logger.error(f"[Firecrawl] Crawl error for {url}: {e}")
        return []

    async def map_urls(self, url: str, limit: int = 500) -> List[str]:
        """Map a domain — discover all URLs without scraping content."""
        fc = self._get_firecrawl()
        if not fc:
            return []

        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: fc.map(url=url, limit=limit)
            )
            urls = []
            if result and hasattr(result, 'links') and result.links:
                # v2 API: result.links is list of LinkResult(url, title, description)
                for item in result.links:
                    u = None
                    if hasattr(item, 'url'):
                        u = item.url
                    elif isinstance(item, str):
                        u = item
                    elif isinstance(item, dict):
                        u = item.get("url", "")
                    if u and u.startswith("http"):
                        urls.append(u)

            logger.info(f"[Firecrawl] Map found {len(urls)} URLs for: {url}")
            return urls

        except Exception as e:
            logger.error(f"[Firecrawl] Map error for {url}: {e}")
        return []


# ────────────────────────── INTERNATIONAL / REGIONAL ENGINES ──────────────────────────


class BingRegionalSearch(SearchEngine):
    """Bing with a country code parameter (?cc=XX) for regional results."""
    name = "bing_regional"  # Overridden by subclasses
    cc = "us"               # Country code, overridden by subclass

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * num_results
        url = (
            f"https://www.bing.com/search?q={quote(query)}"
            f"&count={num_results}&first={offset + 1}&cc={self.cc}"
        )
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-US,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="b_algo"):
                        link = li.find("a")
                        if link:
                            href = link.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[{self.name}] Search error: {e}")
            return []


# Factory: create Bing regional subclasses for many countries
_BING_REGIONS = {
    "ar": "Argentina", "au": "Australia", "at": "Austria", "be": "Belgium",
    "br": "Brazil", "ca": "Canada", "cl": "Chile", "dk": "Denmark",
    "fi": "Finland", "fr": "France", "de": "Germany", "in": "India",
    "id": "Indonesia", "it": "Italy", "jp": "Japan", "kr": "South Korea",
    "my": "Malaysia", "mx": "Mexico", "nl": "Netherlands", "nz": "New Zealand",
    "no": "Norway", "pl": "Poland", "pt": "Portugal", "ru": "Russia",
    "sa": "Saudi Arabia", "za": "South Africa", "es": "Spain", "se": "Sweden",
    "ch": "Switzerland", "tw": "Taiwan", "th": "Thailand", "tr": "Turkey",
    "gb": "United Kingdom", "us": "United States", "ph": "Philippines",
    "vn": "Vietnam", "eg": "Egypt", "ng": "Nigeria", "ke": "Kenya",
    "co": "Colombia", "pe": "Peru", "ua": "Ukraine", "ro": "Romania",
    "cz": "Czech Republic", "hu": "Hungary", "il": "Israel", "ae": "UAE",
    "sg": "Singapore", "hk": "Hong Kong", "pk": "Pakistan", "bd": "Bangladesh",
}

_BING_REGIONAL_CLASSES = {}
for _cc, _country in _BING_REGIONS.items():
    _cls_name = f"Bing{_cc.upper()}Search"
    _engine_name = f"bing_{_cc}"
    _cls = type(_cls_name, (BingRegionalSearch,), {"name": _engine_name, "cc": _cc})
    _cls.__doc__ = f"Bing — {_country} ({_cc.upper()})"
    _BING_REGIONAL_CLASSES[_engine_name] = _cls
    globals()[_cls_name] = _cls  # Make them importable


class YahooJPSearch(SearchEngine):
    """Yahoo Japan — separate index from US Yahoo, huge in Japan."""
    name = "yahoo_jp"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * 10
        url = f"https://search.yahoo.co.jp/search?p={quote(query)}&b={offset + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ja,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"Sr|algo")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "yahoo.co.jp" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YahooJP] Search error: {e}")
            return []


class BaiduSearch(SearchEngine):
    """Baidu — China's dominant search engine, massive independent index."""
    name = "baidu"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.baidu.com/s?wd={quote(query)}&pn={page * 10}&rn={num_results}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|c-container")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "baidu.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Baidu uses redirect links — if results are baidu.com/link?url=...
                    # they'll still work when followed; collect them
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if href.startswith("http://www.baidu.com/link"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Baidu] Search error: {e}")
            return []


class SogouSearch(SearchEngine):
    """Sogou — China's #2 search engine, independent crawler, Tencent-backed."""
    name = "sogou"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.sogou.com/web?query={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"vrwrap|rb")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "sogou.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Sogou] Search error: {e}")
            return []


class SeznamSearch(SearchEngine):
    """Seznam — Czech Republic's native search engine with its own index."""
    name = "seznam"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.seznam.cz/?q={quote(query)}&from={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "cs,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"Result|result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "seznam.cz" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Seznam] Search error: {e}")
            return []


class CocCocSearch(SearchEngine):
    """Coc Coc — Vietnam's most popular browser/search engine."""
    name = "coccoc"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://coccoc.com/search#query={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "vi,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result-link|title")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "coccoc.com" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[CocCoc] Search error: {e}")
            return []


class YandexRUSearch(SearchEngine):
    """Yandex.ru — Russian domestic Yandex domain, different rate limits."""
    name = "yandex_ru"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.ru/search/?text={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ru,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for div in soup.find_all("div", attrs={"data-cid": True}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http") and "yandex" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YandexRU] Search error: {e}")
            return []


class YandexTRSearch(SearchEngine):
    """Yandex Turkey — yandex.com.tr, popular in Turkey."""
    name = "yandex_tr"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.com.tr/search/?text={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "tr,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YandexTR] Search error: {e}")
            return []


class GooSearch(SearchEngine):
    """Goo.ne.jp — Japan's search engine powered by NTT, independent index."""
    name = "goo_jp"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.goo.ne.jp/web.jsp?MT={quote(query)}&from={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ja,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|organic")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "goo.ne.jp" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[GooJP] Search error: {e}")
            return []


class DaumSearch(SearchEngine):
    """Daum — South Korea's #2 search engine (Kakao-owned), independent index."""
    name = "daum"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.daum.net/search?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ko,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"f_link_url|link_favico|tit")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "daum.net" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for div in soup.find_all("div", class_=re.compile(r"wrap_tit")):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "daum.net" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Daum] Search error: {e}")
            return []


class QwantLiteSearch(SearchEngine):
    """Qwant Lite — lightweight HTML version of Qwant, good for scraping."""
    name = "qwant_lite"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://lite.qwant.com/?q={quote(query)}&t=web&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result|url")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "qwant" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http") and "qwant" not in href
                                    and not href.endswith((".css", ".js", ".png"))):
                                text = a.get_text(strip=True)
                                if text and len(text) > 10:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[QwantLite] Search error: {e}")
            return []


class SwisscowsSearch(SearchEngine):
    """Swisscows — Swiss privacy search engine with its own index."""
    name = "swisscows"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://swisscows.com/en/web?query={quote(query)}&offset={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en,de;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("article", class_=re.compile(r"web-results")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "swisscows" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http") and "swisscows" not in href
                                    and not href.endswith((".css", ".js"))):
                                text = a.get_text(strip=True)
                                if text and len(text) > 10:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Swisscows] Search error: {e}")
            return []


class ExalidSearch(SearchEngine):
    """Exalead — French search engine by Dassault Systemes, European index."""
    name = "exalead"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.exalead.com/search/web/results/?q={quote(query)}&elements_per_page={num_results}&start_index={page * num_results}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "fr,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"title|result-link")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "exalead" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Exalead] Search error: {e}")
            return []


class GibiruSearch(SearchEngine):
    """Gibiru — uncensored/unfiltered search engine."""
    name = "gibiru"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://gibiru.com/results.html?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if (href.startswith("http") and "gibiru.com" not in href
                                and not href.endswith((".js", ".css"))):
                            text = a.get_text(strip=True)
                            if text and len(text) > 5:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Gibiru] Search error: {e}")
            return []


class MetagerSearch(SearchEngine):
    """MetaGer — German privacy meta-search engine (non-profit)."""
    name = "metager"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://metager.org/meta/meta.ger3?eingabe={quote(query)}&page={page + 1}&lang=all"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "de,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "metager" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[MetaGer] Search error: {e}")
            return []


class PresearchSearch(SearchEngine):
    """Presearch — decentralized search engine with its own index."""
    name = "presearch"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://presearch.com/search?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result-link|title")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "presearch" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if (href.startswith("http") and "presearch" not in href
                                    and not href.endswith((".css", ".js"))):
                                text = a.get_text(strip=True)
                                if text and len(text) > 10:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Presearch] Search error: {e}")
            return []


class YepSearch(SearchEngine):
    """Yep.com — privacy search engine by Ahrefs with its own web crawler."""
    name = "yep"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yep.com/web?q={quote(query)}&no={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if (href.startswith("http") and "yep.com" not in href
                                and not href.endswith((".css", ".js"))):
                            text = a.get_text(strip=True)
                            if text and len(text) > 10:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Yep] Search error: {e}")
            return []


class AlexandriaNLSearch(SearchEngine):
    """Alexandria.nl — European open search engine with independent index."""
    name = "alexandria"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.alexandria.nl/?q={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result|link")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "alexandria" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Alexandria] Search error: {e}")
            return []


# ────────────────────────── INDEPENDENT COUNTRY ENGINES (WAVE 2) ──────────────────────────


class MailRuSearch(SearchEngine):
    """Mail.ru — Russia's major portal with independent search (go.mail.ru)."""
    name = "mailru"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://go.mail.ru/search?q={quote(query)}&sf={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ru,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result__title|ResultTitle")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "mail.ru" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for li in soup.find_all("li", class_=re.compile(r"result")):
                            a = li.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "mail.ru" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[MailRu] Search error: {e}")
            return []


class RamblerSearch(SearchEngine):
    """Rambler — one of Russia's oldest web portals with search."""
    name = "rambler"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://nova.rambler.ru/search?query={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ru,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"serp-item__title|link")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "rambler.ru" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for div in soup.find_all("div", class_=re.compile(r"serp-item|result")):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "rambler.ru" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Rambler] Search error: {e}")
            return []


class HaosouSearch(SearchEngine):
    """360 Search (Haosou/so.com) — China's #3 search engine by Qihoo 360."""
    name = "haosou"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.so.com/s?q={quote(query)}&pn={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_=re.compile(r"res-list")):
                        a = li.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "so.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if href.startswith("http") and "so.com" not in href and "360.cn" not in href:
                                text = a.get_text(strip=True)
                                if text and len(text) > 8:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Haosou] Search error: {e}")
            return []


class ShenmaSearch(SearchEngine):
    """Shenma (sm.cn) — Alibaba/UCWeb mobile-first Chinese search engine."""
    name = "shenma"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://m.sm.cn/s?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.5"
                headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if href.startswith("http") and "sm.cn" not in href and "ucweb" not in href:
                            text = a.get_text(strip=True)
                            if text and len(text) > 5:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Shenma] Search error: {e}")
            return []


class PetalSearch(SearchEngine):
    """Petal Search — Huawei's own search engine, large mobile index."""
    name = "petal"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://petalsearch.com/search?query={quote(query)}&pn={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en,zh;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "petalsearch" not in href and "huawei" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Petal] Search error: {e}")
            return []


class ZumSearch(SearchEngine):
    """Zum — South Korea's #3 search portal."""
    name = "zum"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.zum.com/search.zum?query={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ko,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"item|result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "zum.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Zum] Search error: {e}")
            return []


class NateSearch(SearchEngine):
    """Nate — South Korean portal by SK Communications."""
    name = "nate"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.daum.net/nate?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ko,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"f_link|tit|link_url")):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "nate.com" not in href and "daum.net" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for div in soup.find_all("div", class_=re.compile(r"wrap_tit|result")):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "nate.com" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Nate] Search error: {e}")
            return []


class ParsijooSearch(SearchEngine):
    """Parsijoo — Iran's native Persian-language search engine."""
    name = "parsijoo"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://parsijoo.ir/web?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "fa,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "parsijoo" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Parsijoo] Search error: {e}")
            return []


class NajdiSearch(SearchEngine):
    """Najdi.si — Slovenia's main search engine with independent tech."""
    name = "najdi"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.najdi.si/search?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "sl,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "najdi.si" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Najdi] Search error: {e}")
            return []


class SearchChSearch(SearchEngine):
    """Search.ch — Switzerland's local search engine."""
    name = "search_ch"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.ch/web/?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "de,fr;q=0.8,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|SearchResult")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "search.ch" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[SearchCH] Search error: {e}")
            return []


class SapoSearch(SearchEngine):
    """Sapo — Portugal's oldest and largest native web portal with search."""
    name = "sapo"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.sapo.pt/pesquisa/web/results?q={quote(query)}&bk={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "pt,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"searchResult|result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "sapo.pt" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Sapo] Search error: {e}")
            return []


class VirgilioSearch(SearchEngine):
    """Virgilio — Italy's first web portal (1996), native Italian search."""
    name = "virgilio"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://ricerca.virgilio.it/ricerca?qs={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "it,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|atom")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "virgilio.it" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Virgilio] Search error: {e}")
            return []


class FireballSearch(SearchEngine):
    """Fireball — Germany's native search engine (since 1996)."""
    name = "fireball"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.fireball.de/search?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "de,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "fireball.de" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Fireball] Search error: {e}")
            return []


class WallaSearch(SearchEngine):
    """Walla — Israel's leading Hebrew-language web portal and search."""
    name = "walla"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.walla.co.il/?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "he,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "walla.co.il" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Walla] Search error: {e}")
            return []


class KvasirSearch(SearchEngine):
    """Kvasir — Norway's native search portal."""
    name = "kvasir"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.kvasir.no/alle?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "no,nb;q=0.9,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "kvasir.no" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Kvasir] Search error: {e}")
            return []


class LeitSearch(SearchEngine):
    """Leit.is — Iceland's native search engine for Icelandic content."""
    name = "leit"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.leit.is/leit?q={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "is,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "leit.is" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Leit] Search error: {e}")
            return []


class OnetSearch(SearchEngine):
    """Onet — Poland's most popular web portal with native search."""
    name = "onet"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://szukaj.onet.pl/wyniki?q={quote(query)}&pg={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "pl,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|webResult")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "onet.pl" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Onet] Search error: {e}")
            return []


class InteriaSearch(SearchEngine):
    """Interia — major Polish web portal with search."""
    name = "interia"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.interia.pl/szukaj?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "pl,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|search-item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "interia.pl" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Interia] Search error: {e}")
            return []


class CentrumSearch(SearchEngine):
    """Centrum.cz — Czech web portal with search."""
    name = "centrum"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.centrum.cz/?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "cs,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "centrum.cz" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Centrum] Search error: {e}")
            return []


class MetaUaSearch(SearchEngine):
    """Meta.ua — Ukrainian search engine with Ukrainian/Russian morphology."""
    name = "meta_ua"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://meta.ua/search/?q={quote(query)}&pg={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "uk,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "meta.ua" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[MetaUA] Search error: {e}")
            return []


class SanookSearch(SearchEngine):
    """Sanook — Thailand's major web portal and search engine."""
    name = "sanook"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.sanook.com/web/?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "th,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "sanook.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Sanook] Search error: {e}")
            return []


class CariSearch(SearchEngine):
    """Cari — Malaysia's first search engine (1996), local content portal."""
    name = "cari"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.cari.com.my/search/?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ms,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|contentRow")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "cari.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Cari] Search error: {e}")
            return []


class RediffSearch(SearchEngine):
    """Rediff — India's major native web portal with search."""
    name = "rediff"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.rediff.com/search?query={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-IN,en;q=0.9,hi;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|listing")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "rediff.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Rediff] Search error: {e}")
            return []


class UolBuscaSearch(SearchEngine):
    """UOL Busca — Brazil's largest content company/portal search."""
    name = "uol"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://busca.uol.com.br/web/?q={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "pt-BR,pt;q=0.9,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|web-result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "uol.com.br" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[UOL] Search error: {e}")
            return []


class AnanziSearch(SearchEngine):
    """Ananzi — South Africa's first native search engine (1996)."""
    name = "ananzi"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.ananzi.co.za/web/?q={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-ZA,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|listing")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "ananzi.co.za" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Ananzi] Search error: {e}")
            return []


class MarginaliaSearch(SearchEngine):
    """Marginalia — Swedish independent search engine, DIY crawler/index."""
    name = "marginalia"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://search.marginalia.nu/search?query={quote(query)}&profile=default&js=default&adtech=default"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"search-result|result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "marginalia" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Marginalia] Search error: {e}")
            return []


class WibySearch(SearchEngine):
    """Wiby — Canadian search engine for the classic/non-commercial web."""
    name = "wiby"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://wiby.me/?q={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        if href.startswith("http") and "wiby.me" not in href:
                            text = a.get_text(strip=True)
                            if text and len(text) > 3:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Wiby] Search error: {e}")
            return []


class EgerinSearch(SearchEngine):
    """Egerin — Kurdish-language search engine (Sweden-based)."""
    name = "egerin"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.egerin.com/search?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ku,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "egerin.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Egerin] Search error: {e}")
            return []


class YongzinSearch(SearchEngine):
    """Yongzin — Tibetan-language search engine (China)."""
    name = "yongzin"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.yongzin.com/search?q={quote(query)}&page={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "bo,zh;q=0.5,en;q=0.3"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|item")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "yongzin" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Yongzin] Search error: {e}")
            return []


# ────────────────────────── YAHOO REGIONAL VARIANTS ──────────────────────────

class YahooRegionalSearch(SearchEngine):
    """Yahoo with a country subdomain for regional results.
    Uses {cc}.search.yahoo.com pattern (from DVParser engine list)."""
    name = "yahoo_regional"  # Overridden by subclasses
    cc = "us"                # Country code subdomain
    domain = "search.yahoo.com"  # Override for special domains

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        offset = page * 10
        url = f"https://{self.domain}/search?p={quote(query)}&n={num_results}&b={offset + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "en-US,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_="compTitle"):
                        link = div.find("a")
                        if link:
                            href = link.get("href", "")
                            if "RU=" in href:
                                m = re.search(r'RU=([^/]+)', href)
                                if m:
                                    from urllib.parse import unquote
                                    href = unquote(m.group(1))
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    # Fallback: dd algo results
                    if not results:
                        for div in soup.find_all("div", class_="dd"):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if "RU=" in href:
                                    m = re.search(r'RU=([^/]+)', href)
                                    if m:
                                        from urllib.parse import unquote
                                        href = unquote(m.group(1))
                                if href.startswith("http") and "yahoo.com" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[{self.name}] Search error: {e}")
            return []


# Factory: create Yahoo regional subclasses for 20 countries (from DVParser)
_YAHOO_REGIONS = {
    "uk": ("uk.search.yahoo.com", "United Kingdom"),
    "ca": ("ca.search.yahoo.com", "Canada"),
    "au": ("au.search.yahoo.com", "Australia"),
    "in": ("in.search.yahoo.com", "India"),
    "de": ("de.search.yahoo.com", "Germany"),
    "fr": ("fr.search.yahoo.com", "France"),
    "es": ("es.search.yahoo.com", "Spain"),
    "it": ("it.search.yahoo.com", "Italy"),
    "br": ("br.search.yahoo.com", "Brazil"),
    "mx": ("mx.search.yahoo.com", "Mexico"),
    "ar": ("ar.search.yahoo.com", "Argentina"),
    "tw": ("tw.search.yahoo.com", "Taiwan"),
    "hk": ("hk.search.yahoo.com", "Hong Kong"),
    "sg": ("sg.search.yahoo.com", "Singapore"),
    "ph": ("ph.search.yahoo.com", "Philippines"),
    "th": ("th.search.yahoo.com", "Thailand"),
    "id": ("id.search.yahoo.com", "Indonesia"),
    "my": ("malaysia.search.yahoo.com", "Malaysia"),
    "vn": ("vn.search.yahoo.com", "Vietnam"),
    "nz": ("nz.search.yahoo.com", "New Zealand"),
}

_YAHOO_REGIONAL_CLASSES = {}
for _ycc, (_ydomain, _ycountry) in _YAHOO_REGIONS.items():
    _ycls_name = f"Yahoo{_ycc.upper()}Search"
    _yengine_name = f"yahoo_{_ycc}"
    _ycls = type(_ycls_name, (YahooRegionalSearch,),
                 {"name": _yengine_name, "cc": _ycc, "domain": _ydomain})
    _ycls.__doc__ = f"Yahoo — {_ycountry} ({_ycc.upper()})"
    _YAHOO_REGIONAL_CLASSES[_yengine_name] = _ycls
    globals()[_ycls_name] = _ycls


# ────────────────────────── YANDEX REGIONAL VARIANTS (DVParser) ──────────────────────────

class YandexUASearch(SearchEngine):
    """Yandex Ukraine — yandex.ua, Ukrainian domestic domain."""
    name = "yandex_ua"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.ua/search/?text={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "uk,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for div in soup.find_all("div", attrs={"data-cid": True}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http") and "yandex" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YandexUA] Search error: {e}")
            return []


class YandexKZSearch(SearchEngine):
    """Yandex Kazakhstan — yandex.kz, popular in Central Asia."""
    name = "yandex_kz"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.kz/search/?text={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "kk,ru;q=0.8,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for div in soup.find_all("div", attrs={"data-cid": True}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http") and "yandex" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YandexKZ] Search error: {e}")
            return []


class YandexBYSearch(SearchEngine):
    """Yandex Belarus — yandex.by, Belarusian domestic domain."""
    name = "yandex_by"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://yandex.by/search/?text={quote(query)}&p={page}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "be,ru;q=0.8,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for li in soup.find_all("li", class_="serp-item"):
                        a = li.find("a")
                        if a:
                            href = a.get("href", "")
                            if href and href.startswith("http") and "yandex" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for div in soup.find_all("div", attrs={"data-cid": True}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http") and "yandex" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[YandexBY] Search error: {e}")
            return []


# ────────────────────────── ADDITIONAL ENGINES (DVParser) ──────────────────────────

class ExciteJPSearch(SearchEngine):
    """Excite Japan — excite.co.jp, Japanese search portal."""
    name = "excite_jp"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.excite.co.jp/search.gw?search={quote(query)}&start={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                headers = self.headers.copy()
                headers["Accept-Language"] = "ja,en;q=0.5"
                async with session.get(url, headers=headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for a in soup.find_all("a", class_=re.compile(r"result|title", re.I)):
                        href = a.get("href", "")
                        if href and href.startswith("http") and "excite.co.jp" not in href:
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    if not results:
                        for div in soup.find_all("div", class_=re.compile(r"result|item")):
                            a = div.find("a", href=True)
                            if a:
                                href = a["href"]
                                if href.startswith("http") and "excite.co.jp" not in href:
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[ExciteJP] Search error: {e}")
            return []


class GigablastSearch(SearchEngine):
    """Gigablast — independent US search engine with its own index."""
    name = "gigablast"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.gigablast.com/search?q={quote(query)}&s={page * 10}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|gbres")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "gigablast.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    if not results:
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            text = a.get_text(strip=True)
                            if (href.startswith("http") and "gigablast.com" not in href
                                    and text and len(text) > 10):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Gigablast] Search error: {e}")
            return []


class LukolSearch(SearchEngine):
    """Lukol — anonymous search proxy, strips tracking."""
    name = "lukol"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.lukol.com/s.php?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|web-result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "lukol.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Lukol] Search error: {e}")
            return []


class OscoboSearch(SearchEngine):
    """Oscobo — UK-based privacy search engine."""
    name = "oscobo"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://www.oscobo.com/search.php?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|web-result|line")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "oscobo.com" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Oscobo] Search error: {e}")
            return []


class InfinitySearch(SearchEngine):
    """Infinity Search — privacy-focused meta search engine."""
    name = "infinity"

    async def search(self, query: str, num_results: int = 10, page: int = 0) -> List[str]:
        url = f"https://infinitysearch.co/search?q={quote(query)}&p={page + 1}"
        try:
            session = await self._get_session()
            own = session is not self._session
            try:
                async with session.get(url, headers=self.headers, proxy=self.proxy, ssl=False) as resp:
                    if resp.status != 200:
                        return []
                    html = await resp.text()
                    self._detect_captcha_in_response(resp.status, html, url)
                    soup = BeautifulSoup(html, "html.parser")
                    results = []
                    for div in soup.find_all("div", class_=re.compile(r"result|search-result")):
                        a = div.find("a", href=True)
                        if a:
                            href = a["href"]
                            if href.startswith("http") and "infinitysearch" not in href:
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    return results
            finally:
                if own:
                    await session.close()
        except RateLimitError:
            raise
        except Exception as e:
            logger.error(f"[Infinity] Search error: {e}")
            return []


# ────────────────────────── ENGINE REGISTRY ──────────────────────────

ENGINE_REGISTRY = {
    # ── Core engines (US / global) ──
    "firecrawl": FirecrawlSearch,
    "duckduckgo": DuckDuckGoSearch,
    "bing": BingSearch,
    "startpage": StartpageSearch,
    "yahoo": YahooSearch,
    "ecosia": EcosiaSearch,
    "qwant": QwantSearch,
    "brave": BraveSearch,
    "aol": AOLSearch,
    "yandex": YandexSearch,
    "ask": AskSearch,
    "dogpile": DogpileSearch,
    "searxng": SearXNGSearch,
    "you": YouSearch,
    "mojeek": MojeekSearch,
    "naver": NaverSearch,
    # ── Independent international engines (Wave 1) ──
    "baidu": BaiduSearch,           # China #1
    "sogou": SogouSearch,           # China #2
    "yahoo_jp": YahooJPSearch,      # Japan
    "goo_jp": GooSearch,            # Japan (NTT)
    "daum": DaumSearch,             # South Korea #2
    "seznam": SeznamSearch,         # Czech Republic
    "coccoc": CocCocSearch,         # Vietnam
    "yandex_ru": YandexRUSearch,    # Russia domestic
    "yandex_tr": YandexTRSearch,    # Turkey
    "qwant_lite": QwantLiteSearch,  # France (HTML version)
    "swisscows": SwisscowsSearch,   # Switzerland
    "exalead": ExalidSearch,        # France (Dassault)
    "gibiru": GibiruSearch,         # Uncensored
    "metager": MetagerSearch,       # Germany (non-profit)
    "presearch": PresearchSearch,   # Decentralized
    "yep": YepSearch,               # Ahrefs (own index)
    "alexandria": AlexandriaNLSearch,  # Netherlands/EU
    # ── Independent country engines (Wave 2) ──
    "mailru": MailRuSearch,         # Russia — go.mail.ru
    "rambler": RamblerSearch,       # Russia — oldest portal
    "haosou": HaosouSearch,         # China #3 — 360/so.com
    "shenma": ShenmaSearch,         # China — Alibaba mobile
    "petal": PetalSearch,           # China — Huawei
    "zum": ZumSearch,               # South Korea #3
    "nate": NateSearch,             # South Korea — SK Communications
    "parsijoo": ParsijooSearch,     # Iran — Persian search
    "najdi": NajdiSearch,           # Slovenia — najdi.si
    "search_ch": SearchChSearch,    # Switzerland — search.ch
    "sapo": SapoSearch,             # Portugal — oldest portal
    "virgilio": VirgilioSearch,     # Italy — first portal (1996)
    "fireball": FireballSearch,     # Germany — native (1996)
    "walla": WallaSearch,           # Israel — Hebrew search
    "kvasir": KvasirSearch,         # Norway — native portal
    "leit": LeitSearch,             # Iceland — leit.is
    "onet": OnetSearch,             # Poland #1 — portal
    "interia": InteriaSearch,       # Poland #2 — portal
    "centrum": CentrumSearch,       # Czech Republic #2
    "meta_ua": MetaUaSearch,        # Ukraine — morphology
    "sanook": SanookSearch,         # Thailand — major portal
    "cari": CariSearch,             # Malaysia — first engine (1996)
    "rediff": RediffSearch,         # India — native portal
    "uol": UolBuscaSearch,          # Brazil — largest portal
    "ananzi": AnanziSearch,         # South Africa — first engine
    "marginalia": MarginaliaSearch, # Sweden — indie DIY
    "wiby": WibySearch,             # Canada — classic web
    "egerin": EgerinSearch,         # Kurdistan — Kurdish language
    "yongzin": YongzinSearch,       # Tibet — Tibetan language
    # ── Yandex regional variants (DVParser) ──
    "yandex_ua": YandexUASearch,    # Ukraine
    "yandex_kz": YandexKZSearch,    # Kazakhstan
    "yandex_by": YandexBYSearch,    # Belarus
    # ── Additional engines (DVParser) ──
    "excite_jp": ExciteJPSearch,    # Japan — Excite portal
    "gigablast": GigablastSearch,   # US — independent index
    "lukol": LukolSearch,           # Anonymous proxy search
    "oscobo": OscoboSearch,         # UK — privacy search
    "infinity": InfinitySearch,     # Privacy meta-search
    # ── Bing regional variants (48 countries) ──
    **_BING_REGIONAL_CLASSES,
    # ── Yahoo regional variants (20 countries, from DVParser) ──
    **_YAHOO_REGIONAL_CLASSES,
}


# ────────────────────────── MULTI-SEARCH ORCHESTRATOR ──────────────────────────

class MultiSearch:
    """Search with health tracking, pagination, session reuse, adaptive rate limiting."""

    def __init__(self, proxies: Optional[List[str]] = None,
                 engines: Optional[List[str]] = None,
                 max_pages: int = 3):
        self.proxies = proxies or []
        self.proxy_index = 0
        self.search_count = 0
        self.engine_names = engines or list(ENGINE_REGISTRY.keys())
        self.max_pages = max_pages
        self.health = EngineHealth(cooldown=300)
        self.rate_limiter = AdaptiveRateLimiter(base_min=3, base_max=8)
        self.dork_scorer = DorkScorer()
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Firecrawl config (set by pipeline after init)
        self.firecrawl_api_key: str = ""
        self.firecrawl_search_limit: int = 20
        self.firecrawl_as_fallback: bool = False
        
        # Captcha solver (set by pipeline after init)
        self.captcha_solver = None  # CaptchaSolver instance
        
        # Proxy manager (Phase 2 — set by pipeline after init)
        self.proxy_manager: Optional['ProxyManager'] = None  # Smart proxy rotation
        
        # Headless browser (Phase 3 — search resilience, set by pipeline after init)
        self.browser_manager: Optional['BrowserManager'] = None
        self.browser_fallback_enabled: bool = False
        self.browser_engines: List[str] = ["google", "bing", "duckduckgo", "startpage"]

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False, limit=20, ttl_dns_cache=600),
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        if self.browser_manager:
            await self.browser_manager.stop()

    def _get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        return self.proxies[self.proxy_index % len(self.proxies)]

    def _rotate_proxy(self):
        if self.proxies:
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)

    async def _get_smart_proxy(self, domain: str = "") -> Tuple[Optional[str], Optional['ProxyInfo']]:
        """Get proxy URL from ProxyManager if available, else fallback to legacy list.
        Returns (proxy_url_string, proxy_info_object)."""
        if self.proxy_manager and self.proxy_manager.has_proxies:
            proxy_info = await self.proxy_manager.get_proxy(domain)
            if proxy_info:
                return proxy_info.url, proxy_info
        # Fallback to legacy proxy list
        url = self._get_proxy()
        return url, None

    async def search(self, query: str, num_results: int = 10) -> List[str]:
        self.search_count += 1
        
        # Smart proxy selection (ProxyManager → legacy fallback → None)
        proxy_url, proxy_info = await self._get_smart_proxy()
        if not proxy_url:
            # Legacy fallback
            proxy_url = self._get_proxy()
            if self.search_count % 5 == 0:
                self._rotate_proxy()

        session = await self._get_session()

        for attempt, use_proxy in enumerate([proxy_url, None] if proxy_url else [None]):
            if attempt > 0:
                logger.info("SEARCH | Retrying without proxy...")

            ordered = self.health.sorted_engines(self.engine_names)
            available = [n for n in ordered if self.health.is_available(n)]
            if not available:
                available = ordered

            all_results = []
            engine_results = {}
            all_errored = True

            for name in available:
                # Live check — another concurrent task may have blocked this engine
                if not self.health.is_available(name):
                    continue
                engine_cls = ENGINE_REGISTRY.get(name)
                if not engine_cls:
                    continue

                # Rotate proxy per engine to avoid IP-based cross-engine bans
                if self.proxy_manager and self.proxy_manager.has_proxies:
                    _pi = await self.proxy_manager.get_proxy(name)
                    if _pi:
                        use_proxy = _pi.url
                        proxy_info = _pi
                    # else keep current use_proxy
                elif self.proxies and len(self.proxies) > 1:
                    self._rotate_proxy()
                    use_proxy = self._get_proxy()

                # Firecrawl needs API key; skip if fallback-only (handled below)
                if name == "firecrawl":
                    if not self.firecrawl_api_key:
                        continue
                    if self.firecrawl_as_fallback:
                        continue  # Will try after all others fail
                    engine = engine_cls(
                        api_key=self.firecrawl_api_key,
                        search_limit=self.firecrawl_search_limit,
                        proxy=use_proxy,
                        session=session,
                    )
                else:
                    engine = engine_cls(proxy=use_proxy, session=session)

                for pg in range(self.max_pages):
                    try:
                        _req_start = time.time()
                        results = await engine.search(query, num_results, page=pg)
                        if results:
                            all_errored = False
                            self.health.record_success(name, len(results))
                            self.rate_limiter.got_success()
                            all_results.extend(results)
                            engine_results[name] = engine_results.get(name, 0) + len(results)
                            # Report proxy success
                            if proxy_info and self.proxy_manager:
                                latency = (time.time() - _req_start) * 1000
                                await self.proxy_manager.report_success(proxy_info, latency)
                            if len(all_results) >= num_results:
                                break
                            await asyncio.sleep(random.uniform(0.3, 0.8))
                        else:
                            if name not in engine_results:
                                engine_results[name] = 0
                            all_errored = False
                            break
                    except CaptchaDetectedError as ce:
                        # Solvable captcha detected — try to solve it
                        if (self.captcha_solver and _HAS_CAPTCHA_SOLVER
                                and self.captcha_solver.available
                                and self.captcha_solver.auto_solve_search):
                            logger.info(f"SEARCH | {name} served captcha ({ce.captcha_info.get('type', '?')}), attempting solve...")
                            solve_result = await self.captcha_solver.solve(
                                ce.captcha_info, ce.url
                            )
                            if solve_result.success:
                                logger.info(f"SEARCH | Captcha solved via {solve_result.provider} "
                                           f"in {solve_result.solve_time:.1f}s — retrying {name}")
                                engine_results[name] = "CAPTCHA_SOLVED"
                                # Retry this engine page (captcha token can't be injected into
                                # search engine responses easily, but solving may clear the block
                                # on the provider side for future requests)
                                await asyncio.sleep(2)  # Brief pause after solve
                                continue  # Retry this page
                            else:
                                logger.warning(f"SEARCH | Captcha solve failed for {name}: {solve_result.error}")
                        # Fall through to rate limit handling
                        self.health.record_failure(name)
                        self.rate_limiter.got_rate_limited()
                        engine_results[name] = f"CAPTCHA_{ce.captcha_info.get('type', 'unknown').upper()}"
                        break
                    except RateLimitError:
                        self.health.record_blocked(name)  # Use blocked status for rate limits
                        self.rate_limiter.got_rate_limited()
                        engine_results[name] = "RATE_LIMITED"
                        # Report rate limit to proxy manager — ban this proxy
                        if proxy_info and self.proxy_manager:
                            await self.proxy_manager.report_rate_limited(proxy_info)
                            # Get a fresh proxy for remaining engines
                            proxy_url_new, proxy_info_new = await self._get_smart_proxy()
                            if proxy_url_new:
                                use_proxy = proxy_url_new
                                proxy_info = proxy_info_new
                        break
                    except Exception as e:
                        self.health.record_failure(name)
                        engine_results[name] = f"ERROR: {str(e)[:50]}"
                        # Report generic failure to proxy manager
                        if proxy_info and self.proxy_manager:
                            await self.proxy_manager.report_failure(proxy_info)
                        break

                if len(all_results) >= num_results:
                    break
                # Per-engine adaptive delay — only for engines that returned nothing
                if name not in engine_results or engine_results[name] == 0:
                    engine_delay = self.health.get_delay_for_engine(name)
                    await asyncio.sleep(engine_delay)
                else:
                    await asyncio.sleep(0.1)  # Got results — move fast

            # Firecrawl fallback: if all engines returned 0 and FC is fallback-only
            if not all_results and self.firecrawl_as_fallback and self.firecrawl_api_key:
                if "firecrawl" not in engine_results:
                    fc_engine = FirecrawlSearch(
                        api_key=self.firecrawl_api_key,
                        search_limit=self.firecrawl_search_limit,
                        session=session,
                    )
                    try:
                        fc_results = await fc_engine.search(query, num_results)
                        if fc_results:
                            all_results.extend(fc_results)
                            engine_results["firecrawl"] = len(fc_results)
                            self.health.record_success("firecrawl", len(fc_results))
                            all_errored = False
                    except Exception as e:
                        engine_results["firecrawl"] = f"ERROR: {str(e)[:50]}"
                        self.health.record_failure("firecrawl")

            # Browser fallback: if all engines + Firecrawl returned 0
            if (not all_results and self.browser_fallback_enabled
                    and self.browser_manager and _HAS_BROWSER
                    and self.browser_manager.available):
                try:
                    browser_se = BrowserSearchEngine(
                        browser_manager=self.browser_manager,
                        captcha_solver=self.captcha_solver if _HAS_CAPTCHA_SOLVER else None,
                        engines=self.browser_engines,
                    )
                    br_results = await browser_se.search(query, num_results)
                    if br_results:
                        all_results.extend(br_results)
                        engine_results["browser"] = len(br_results)
                        all_errored = False
                    else:
                        engine_results["browser"] = 0
                except Exception as e:
                    engine_results["browser"] = f"ERROR: {str(e)[:50]}"

            summary = " | ".join([f"{k}: {v}" for k, v in engine_results.items()])
            logger.info(f"SEARCH | {summary}")

            if all_errored and use_proxy and not all_results:
                continue
            break

        seen = set()
        unique = []
        for u in all_results:
            if u not in seen:
                seen.add(u)
                unique.append(u)

        self.dork_scorer.record(query, len(unique))
        logger.info(f"SEARCH | {len(unique)} unique URLs (from {len(all_results)} total)")
        return unique[:num_results]

    def get_engine_stats(self) -> Dict:
        return self.health.get_stats()

    def get_top_dorks(self, n: int = 20) -> List[Tuple[str, float]]:
        return self.dork_scorer.get_top(n)
