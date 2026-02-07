"""
Search Engines Module - Handles searching across multiple engines
"""

import re
import random
import asyncio
from typing import List, Optional, Dict
from urllib.parse import quote, urljoin, urlparse
from bs4 import BeautifulSoup
import aiohttp
from loguru import logger


class SearchEngine:
    """Base class for search engines."""
    
    name: str = "base"
    
    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
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
        """Return a random user agent."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        ]
        return random.choice(user_agents)
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search and return URLs. Override in subclasses."""
        raise NotImplementedError


class DuckDuckGoSearch(SearchEngine):
    """DuckDuckGo HTML search - most tolerant of automation."""
    
    name = "duckduckgo"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search DuckDuckGo HTML version."""
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"DuckDuckGo returned {response.status}")
                        return []
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for link in soup.find_all("a", class_="result__a"):
                        href = link.get("href", "")
                        if href and not href.startswith("/"):
                            # DDG sometimes wraps URLs
                            if "uddg=" in href:
                                # Extract actual URL from DDG redirect
                                match = re.search(r'uddg=([^&]+)', href)
                                if match:
                                    from urllib.parse import unquote
                                    href = unquote(match.group(1))
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    
                    logger.info(f"[DDG] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[DDG] Search error: {e}")
            return []


class BingSearch(SearchEngine):
    """Bing search - decent automation tolerance."""
    
    name = "bing"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Bing."""
        url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Bing returned {response.status}")
                        return []
                    
                    html = await response.text()
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
                    
                    logger.info(f"[Bing] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Bing] Search error: {e}")
            return []


class StartpageSearch(SearchEngine):
    """Startpage search - private Google results."""
    
    name = "startpage"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Startpage."""
        url = "https://www.startpage.com/sp/search"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # First, get the search page to get any required tokens
                async with session.get(
                    "https://www.startpage.com/",
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as init_resp:
                    pass  # Just initialize cookies
                
                # Now search
                data = {
                    "query": query,
                    "cat": "web",
                    "language": "english",
                }
                
                async with session.post(
                    url,
                    headers=self.headers,
                    data=data,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Startpage returned {response.status}")
                        return []
                    
                    html = await response.text()
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
                    
                    # Alternative selector
                    if not results:
                        for a in soup.find_all("a", class_="result-link"):
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    
                    logger.info(f"[Startpage] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Startpage] Search error: {e}")
            return []


class YahooSearch(SearchEngine):
    """Yahoo search."""
    
    name = "yahoo"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Yahoo."""
        url = f"https://search.yahoo.com/search?p={quote(query)}&n={num_results}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Yahoo returned {response.status}")
                        return []
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for div in soup.find_all("div", class_="compTitle"):
                        link = div.find("a")
                        if link:
                            href = link.get("href", "")
                            # Yahoo wraps URLs, extract actual URL
                            if "RU=" in href:
                                match = re.search(r'RU=([^/]+)', href)
                                if match:
                                    from urllib.parse import unquote
                                    href = unquote(match.group(1))
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    
                    logger.info(f"[Yahoo] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Yahoo] Search error: {e}")
            return []


class EcosiaSearch(SearchEngine):
    """Ecosia search - eco-friendly Bing-powered."""
    
    name = "ecosia"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Ecosia."""
        url = f"https://www.ecosia.org/search?method=index&q={quote(query)}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Ecosia returned {response.status}")
                        return []
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for a in soup.find_all("a", class_="result__link"):
                        href = a.get("href", "")
                        if href and href.startswith("http"):
                            results.append(href)
                            if len(results) >= num_results:
                                break
                    
                    # Alternative selectors
                    if not results:
                        for div in soup.find_all("div", {"class": re.compile(r"result")}):
                            a = div.find("a")
                            if a:
                                href = a.get("href", "")
                                if href and href.startswith("http"):
                                    results.append(href)
                                    if len(results) >= num_results:
                                        break
                    
                    logger.info(f"[Ecosia] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Ecosia] Search error: {e}")
            return []


class QwantSearch(SearchEngine):
    """Qwant search - European privacy-focused engine."""
    
    name = "qwant"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Qwant via API."""
        url = f"https://api.qwant.com/v3/search/web?q={quote(query)}&count={num_results}&locale=en_US&offset=0"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            headers = self.headers.copy()
            headers["Accept"] = "application/json"
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Qwant returned {response.status}")
                        return []
                    
                    data = await response.json()
                    results = []
                    
                    items = data.get("data", {}).get("result", {}).get("items", {}).get("mainline", [])
                    for group in items:
                        for item in group.get("items", []):
                            url_val = item.get("url", "")
                            if url_val and url_val.startswith("http"):
                                results.append(url_val)
                                if len(results) >= num_results:
                                    break
                    
                    logger.info(f"[Qwant] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Qwant] Search error: {e}")
            return []


class BraveSearch(SearchEngine):
    """Brave Search - independent index."""
    
    name = "brave"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search Brave."""
        url = f"https://search.brave.com/search?q={quote(query)}&source=web"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"Brave returned {response.status}")
                        return []
                    
                    html = await response.text()
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
                    
                    # Alternative selector
                    if not results:
                        for a in soup.find_all("a", {"class": re.compile(r"heading")}):
                            href = a.get("href", "")
                            if href and href.startswith("http"):
                                results.append(href)
                                if len(results) >= num_results:
                                    break
                    
                    logger.info(f"[Brave] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[Brave] Search error: {e}")
            return []


class AOLSearch(SearchEngine):
    """AOL search - powered by Bing."""
    
    name = "aol"
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """Search AOL."""
        url = f"https://search.aol.com/aol/search?q={quote(query)}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    if response.status != 200:
                        logger.warning(f"AOL returned {response.status}")
                        return []
                    
                    html = await response.text()
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
                    
                    logger.info(f"[AOL] Found {len(results)} results for query")
                    return results
                    
        except Exception as e:
            logger.error(f"[AOL] Search error: {e}")
            return []


# Engine registry
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


class MultiSearch:
    """Search across multiple engines with fallback."""
    
    def __init__(self, proxies: Optional[List[str]] = None, 
                 engines: Optional[List[str]] = None):
        self.proxies = proxies or []
        self.proxy_index = 0
        self.search_count = 0
        self.engine_names = engines or list(ENGINE_REGISTRY.keys())
    
    def _get_proxy(self) -> Optional[str]:
        """Get next proxy in rotation."""
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        return proxy
    
    def _rotate_proxy(self):
        """Rotate to next proxy."""
        if self.proxies:
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
            logger.debug(f"Rotated to proxy index {self.proxy_index}")
    
    async def search(self, query: str, num_results: int = 10) -> List[str]:
        """
        Search across engines with fallback.
        Tries DuckDuckGo first, then others if it fails.
        """
        proxy = self._get_proxy()
        self.search_count += 1
        
        logger.debug(f"SEARCH | Query: {query[:60]}... | Using proxy: {proxy[:30] if proxy else 'None'}...")
        
        # Rotate proxy every N searches
        if self.search_count % 5 == 0:
            self._rotate_proxy()
        
        engines = [ENGINE_REGISTRY[name](proxy) for name in self.engine_names 
                   if name in ENGINE_REGISTRY]
        
        # Shuffle to distribute load
        random.shuffle(engines)
        engine_order = ", ".join([e.name for e in engines])
        logger.debug(f"SEARCH | Engine order: {engine_order}")
        
        all_results = []
        engine_results = {}
        
        for engine in engines:
            try:
                logger.debug(f"SEARCH | Trying {engine.name}...")
                results = await engine.search(query, num_results)
                engine_results[engine.name] = len(results)
                
                if results:
                    logger.info(f"SEARCH | {engine.name}: {len(results)} results")
                    for i, url in enumerate(results[:3]):
                        logger.debug(f"SEARCH | {engine.name} result {i+1}: {url[:80]}...")
                    all_results.extend(results)
                    # If we got enough results, stop
                    if len(all_results) >= num_results:
                        break
                    # Add small delay between engines
                    await asyncio.sleep(random.uniform(1, 3))
                else:
                    logger.debug(f"SEARCH | {engine.name}: 0 results")
            except Exception as e:
                engine_results[engine.name] = f"ERROR: {str(e)[:50]}"
                logger.error(f"SEARCH | {engine.name} failed: {e}")
                continue
        
        # Log summary
        summary = " | ".join([f"{k}: {v}" for k, v in engine_results.items()])
        logger.info(f"SEARCH | Summary: {summary}")
        
        # Deduplicate while preserving order
        seen = set()
        unique_results = []
        for url in all_results:
            if url not in seen:
                seen.add(url)
                unique_results.append(url)
        
        logger.info(f"SEARCH | Total unique URLs: {len(unique_results)} (from {len(all_results)} total)")
        return unique_results[:num_results]
