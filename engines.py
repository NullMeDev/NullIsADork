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


# ────────────────────────── ENGINE HEALTH TRACKER ──────────────────────────

class EngineHealth:
    """Tracks success/failure rate per engine with cooldown."""

    def __init__(self, cooldown: float = 300):
        self.cooldown = cooldown
        self._success: Dict[str, int] = defaultdict(int)
        self._failure: Dict[str, int] = defaultdict(int)
        self._consecutive_fail: Dict[str, int] = defaultdict(int)
        self._cooldown_until: Dict[str, float] = {}

    def record_success(self, engine: str, count: int = 1):
        self._success[engine] += 1
        self._consecutive_fail[engine] = 0

    def record_failure(self, engine: str):
        self._failure[engine] += 1
        self._consecutive_fail[engine] += 1
        if self._consecutive_fail[engine] >= 3:
            self._cooldown_until[engine] = time.time() + self.cooldown
            logger.warning(f"Engine {engine} cooled down for {self.cooldown}s")

    def is_available(self, engine: str) -> bool:
        return time.time() >= self._cooldown_until.get(engine, 0)

    def success_rate(self, engine: str) -> float:
        total = self._success[engine] + self._failure[engine]
        return self._success[engine] / total if total else 1.0

    def sorted_engines(self, names: List[str]) -> List[str]:
        available = [n for n in names if self.is_available(n)]
        cooled = [n for n in names if not self.is_available(n)]
        available.sort(key=lambda n: self.success_rate(n), reverse=True)
        return available + cooled

    def get_stats(self) -> Dict:
        engines = set(list(self._success.keys()) + list(self._failure.keys()))
        return {
            name: {
                "success": self._success[name],
                "fail": self._failure[name],
                "rate": f"{self.success_rate(name):.0%}",
                "available": self.is_available(name),
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

    def got_rate_limited(self):
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


# ────────────────────────── ENGINE REGISTRY ──────────────────────────

ENGINE_REGISTRY = {
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
                engine_cls = ENGINE_REGISTRY.get(name)
                if not engine_cls:
                    continue
                
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
                            await asyncio.sleep(random.uniform(1, 2))
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
                        self.health.record_failure(name)
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
                await asyncio.sleep(random.uniform(0.5, 1.5))

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
