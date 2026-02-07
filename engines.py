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
    def __init__(self, engine: str):
        self.engine = engine
        super().__init__(f"{engine} rate-limited")


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
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30),
                                     connector=aiohttp.TCPConnector(ssl=False, limit=10))

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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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
                    if self._is_rate_limited(resp.status, html):
                        raise RateLimitError(self.name)
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


# ────────────────────────── ENGINE REGISTRY ──────────────────────────

ENGINE_REGISTRY = {
    "duckduckgo": DuckDuckGoSearch,
    "bing": BingSearch,
    "startpage": StartpageSearch,
    "yahoo": YahooSearch,
    "ecosia": EcosiaSearch,
    "qwant": QwantSearch,
    "brave": BraveSearch,
    "aol": AOLSearch,
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

    def _get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        return self.proxies[self.proxy_index % len(self.proxies)]

    def _rotate_proxy(self):
        if self.proxies:
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)

    async def search(self, query: str, num_results: int = 10) -> List[str]:
        proxy = self._get_proxy()
        self.search_count += 1
        if self.search_count % 5 == 0:
            self._rotate_proxy()

        session = await self._get_session()

        for attempt, use_proxy in enumerate([proxy, None] if proxy else [None]):
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
                engine = engine_cls(proxy=use_proxy, session=session)

                for pg in range(self.max_pages):
                    try:
                        results = await engine.search(query, num_results, page=pg)
                        if results:
                            all_errored = False
                            self.health.record_success(name, len(results))
                            self.rate_limiter.got_success()
                            all_results.extend(results)
                            engine_results[name] = engine_results.get(name, 0) + len(results)
                            if len(all_results) >= num_results:
                                break
                            await asyncio.sleep(random.uniform(1, 2))
                        else:
                            if name not in engine_results:
                                engine_results[name] = 0
                            all_errored = False
                            break
                    except RateLimitError:
                        self.health.record_failure(name)
                        self.rate_limiter.got_rate_limited()
                        engine_results[name] = "RATE_LIMITED"
                        break
                    except Exception as e:
                        self.health.record_failure(name)
                        engine_results[name] = f"ERROR: {str(e)[:50]}"
                        break

                if len(all_results) >= num_results:
                    break
                await asyncio.sleep(random.uniform(0.5, 1.5))

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
