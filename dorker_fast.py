#!/usr/bin/env python3
"""
Medin Dorker v2 - FAST Parallel Site Discovery

Key improvements over v1:
- Parallel dork processing (configurable concurrency)
- Parallel search across engines
- Proxy health tracking with auto-disable
- Detailed error logging
- Minimal delays
- Stats tracking

Usage:
    python dorker_fast.py --token BOT_TOKEN --chat CHAT_ID [--workers 10]
"""

import os
import sys
import json
import random
import asyncio
import argparse
import aiohttp
import re
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import quote, urlparse, unquote
from dataclasses import dataclass, field
from collections import defaultdict
from bs4 import BeautifulSoup

from loguru import logger


# ============== CONFIGURATION ==============

@dataclass
class FastDorkerConfig:
    """Configuration for fast dorker."""
    
    # Telegram
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    
    # Concurrency
    max_concurrent_dorks: int = 10  # Process this many dorks at once
    max_concurrent_searches: int = 4  # Search engines per dork
    max_concurrent_validations: int = 15  # Validate this many URLs at once
    
    # Timing (FAST!)
    delay_between_batches: float = 2.0  # Seconds between dork batches
    delay_between_cycles: int = 60  # Seconds between full cycles
    search_timeout: int = 15  # Timeout for search requests
    validation_timeout: int = 10  # Timeout for validation
    
    # Proxy settings
    proxy_file: str = "proxies.txt"
    proxy_fail_threshold: int = 5  # Disable proxy after N failures
    proxy_success_reset: int = 3  # Successes to reset failure count
    
    # Storage
    found_sites_file: str = "found_sites.json"
    seen_domains_file: str = "seen_domains.txt"
    stats_file: str = "dorker_stats.json"
    
    # Score threshold
    min_score_to_save: int = 20
    min_score_to_notify: int = 50


# ============== PROXY MANAGER ==============

class ProxyManager:
    """Manages proxy rotation and health."""
    
    def __init__(self, proxy_file: str, fail_threshold: int = 5):
        self.proxy_file = proxy_file
        self.fail_threshold = fail_threshold
        self.proxies: List[str] = []
        self.proxy_failures: Dict[str, int] = defaultdict(int)
        self.proxy_successes: Dict[str, int] = defaultdict(int)
        self.disabled_proxies: Set[str] = set()
        self.current_index = 0
        self.lock = asyncio.Lock()
        
        self._load_proxies()
    
    def _load_proxies(self):
        """Load proxies from file."""
        proxy_path = Path(self.proxy_file)
        if not proxy_path.exists():
            logger.warning(f"Proxy file not found: {proxy_path}")
            return
        
        with open(proxy_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Convert to URL format
                    if not line.startswith("http"):
                        parts = line.split(":")
                        if len(parts) == 4:
                            host, port, user, passwd = parts
                            line = f"http://{user}:{passwd}@{host}:{port}"
                        elif len(parts) == 2:
                            line = f"http://{line}"
                    self.proxies.append(line)
        
        logger.info(f"Loaded {len(self.proxies)} proxies")
    
    async def get_proxy(self) -> Optional[str]:
        """Get next available proxy."""
        async with self.lock:
            available = [p for p in self.proxies if p not in self.disabled_proxies]
            if not available:
                # Re-enable all if none available
                logger.warning("All proxies disabled! Re-enabling...")
                self.disabled_proxies.clear()
                self.proxy_failures.clear()
                available = self.proxies
            
            if not available:
                return None
            
            self.current_index = (self.current_index + 1) % len(available)
            return available[self.current_index]
    
    async def report_failure(self, proxy: str, error: str):
        """Report a proxy failure."""
        async with self.lock:
            self.proxy_failures[proxy] += 1
            failures = self.proxy_failures[proxy]
            
            logger.warning(f"PROXY_FAIL | {proxy[:40]}... | Failures: {failures} | Error: {error[:50]}")
            
            if failures >= self.fail_threshold:
                self.disabled_proxies.add(proxy)
                logger.error(f"PROXY_DISABLED | {proxy[:40]}... | Too many failures ({failures})")
    
    async def report_success(self, proxy: str):
        """Report a proxy success."""
        async with self.lock:
            self.proxy_successes[proxy] += 1
            # Reset failures after consistent success
            if self.proxy_successes[proxy] >= 3:
                self.proxy_failures[proxy] = 0
                self.proxy_successes[proxy] = 0
    
    def get_stats(self) -> Dict:
        """Get proxy statistics."""
        return {
            "total": len(self.proxies),
            "active": len(self.proxies) - len(self.disabled_proxies),
            "disabled": len(self.disabled_proxies),
            "failures": dict(self.proxy_failures),
        }


# ============== SEARCH ENGINES ==============

class SearchEngine:
    """Base search engine."""
    
    name: str = "base"
    
    def __init__(self, proxy_manager: ProxyManager, timeout: int = 15):
        self.proxy_manager = proxy_manager
        self.timeout = timeout
        self.headers = {
            "User-Agent": self._random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    
    def _random_ua(self) -> str:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
        ]
        return random.choice(uas)
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Optional[str]]:
        """Search and return (urls, error_message)."""
        raise NotImplementedError


class BingSearch(SearchEngine):
    name = "bing"
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Optional[str]]:
        url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}"
        proxy = await self.proxy_manager.get_proxy()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self.headers, proxy=proxy, ssl=False) as resp:
                    if resp.status != 200:
                        error = f"HTTP {resp.status}"
                        if proxy:
                            await self.proxy_manager.report_failure(proxy, error)
                        return [], error
                    
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for li in soup.find_all("li", class_="b_algo"):
                        link = li.find("a")
                        if link:
                            href = link.get("href", "")
                            if href and str(href).startswith("http"):
                                results.append(str(href))
                    
                    if proxy and results:
                        await self.proxy_manager.report_success(proxy)
                    
                    return results[:num_results], None
                    
        except asyncio.TimeoutError:
            error = "Timeout"
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error
        except Exception as e:
            error = str(e)[:100]
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error


class DuckDuckGoSearch(SearchEngine):
    name = "duckduckgo"
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Optional[str]]:
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        proxy = await self.proxy_manager.get_proxy()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self.headers, proxy=proxy, ssl=False) as resp:
                    if resp.status != 200:
                        error = f"HTTP {resp.status}"
                        if proxy:
                            await self.proxy_manager.report_failure(proxy, error)
                        return [], error
                    
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for link in soup.find_all("a", class_="result__a"):
                        href = link.get("href", "")
                        if href and not str(href).startswith("/"):
                            # Extract from DDG redirect
                            if "uddg=" in str(href):
                                match = re.search(r'uddg=([^&]+)', str(href))
                                if match:
                                    href = unquote(match.group(1))
                            results.append(str(href))
                    
                    if proxy and results:
                        await self.proxy_manager.report_success(proxy)
                    
                    return results[:num_results], None
                    
        except asyncio.TimeoutError:
            error = "Timeout"
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error
        except Exception as e:
            error = str(e)[:100]
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error


class YahooSearch(SearchEngine):
    name = "yahoo"
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Optional[str]]:
        url = f"https://search.yahoo.com/search?p={quote(query)}&n={num_results}"
        proxy = await self.proxy_manager.get_proxy()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self.headers, proxy=proxy, ssl=False) as resp:
                    if resp.status != 200:
                        error = f"HTTP {resp.status}"
                        if proxy:
                            await self.proxy_manager.report_failure(proxy, error)
                        return [], error
                    
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for div in soup.find_all("div", class_="compTitle"):
                        link = div.find("a")
                        if link:
                            href = link.get("href", "")
                            # Extract from Yahoo redirect
                            if href and "RU=" in str(href):
                                match = re.search(r'RU=([^/]+)', str(href))
                                if match:
                                    href = unquote(match.group(1))
                            if href and str(href).startswith("http"):
                                results.append(str(href))
                    
                    if proxy and results:
                        await self.proxy_manager.report_success(proxy)
                    
                    return results[:num_results], None
                    
        except asyncio.TimeoutError:
            error = "Timeout"
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error
        except Exception as e:
            error = str(e)[:100]
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error


class StartpageSearch(SearchEngine):
    name = "startpage"
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Optional[str]]:
        url = "https://www.startpage.com/sp/search"
        proxy = await self.proxy_manager.get_proxy()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                data = {"query": query, "cat": "web", "language": "english"}
                async with session.post(url, headers=self.headers, data=data, proxy=proxy, ssl=False) as resp:
                    if resp.status != 200:
                        error = f"HTTP {resp.status}"
                        if proxy:
                            await self.proxy_manager.report_failure(proxy, error)
                        return [], error
                    
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    results = []
                    for div in soup.find_all("div", class_="w-gl__result"):
                        link = div.find("a", class_="w-gl__result-url")
                        if link:
                            href = link.get("href", "")
                            if href and str(href).startswith("http"):
                                results.append(str(href))
                    
                    # Alternative selector
                    if not results:
                        for a in soup.find_all("a", class_="result-link"):
                            href = a.get("href", "")
                            if href and str(href).startswith("http"):
                                results.append(str(href))
                    
                    if proxy and results:
                        await self.proxy_manager.report_success(proxy)
                    
                    return results[:num_results], None
                    
        except asyncio.TimeoutError:
            error = "Timeout"
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error
        except Exception as e:
            error = str(e)[:100]
            if proxy:
                await self.proxy_manager.report_failure(proxy, error)
            return [], error


# ============== PARALLEL SEARCH ==============

class ParallelSearcher:
    """Searches multiple engines in parallel."""
    
    def __init__(self, proxy_manager: ProxyManager, timeout: int = 15):
        self.proxy_manager = proxy_manager
        self.engines = [
            BingSearch(proxy_manager, timeout),
            DuckDuckGoSearch(proxy_manager, timeout),
            YahooSearch(proxy_manager, timeout),
            StartpageSearch(proxy_manager, timeout),
        ]
        self.stats = {
            "total_searches": 0,
            "engine_results": defaultdict(int),
            "engine_errors": defaultdict(int),
        }
    
    async def search(self, query: str, num_results: int = 15) -> Tuple[List[str], Dict]:
        """Search all engines in parallel, return unique URLs and stats."""
        self.stats["total_searches"] += 1
        
        # Run all engines in parallel
        tasks = [engine.search(query, num_results) for engine in self.engines]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_urls = []
        search_stats = {}
        
        for engine, result in zip(self.engines, results):
            if isinstance(result, Exception):
                search_stats[engine.name] = f"ERROR: {str(result)[:30]}"
                self.stats["engine_errors"][engine.name] += 1
                logger.error(f"SEARCH_ERROR | {engine.name} | {result}")
            else:
                urls, error = result
                if error:
                    search_stats[engine.name] = f"FAIL: {error}"
                    self.stats["engine_errors"][engine.name] += 1
                    logger.warning(f"SEARCH_FAIL | {engine.name} | {error}")
                else:
                    search_stats[engine.name] = len(urls)
                    self.stats["engine_results"][engine.name] += len(urls)
                    all_urls.extend(urls)
        
        # Deduplicate
        seen = set()
        unique = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        
        return unique[:num_results * 2], search_stats


# ============== SITE VALIDATOR ==============

@dataclass
class SiteInfo:
    """Validated site information."""
    url: str
    domain: str
    pk_key: Optional[str] = None
    platform: Optional[str] = None
    gateways: List[str] = field(default_factory=list)
    has_captcha: bool = False
    has_cloudflare: bool = False
    has_graphql: bool = False
    has_3ds: bool = False
    checkout_url: Optional[str] = None
    score: int = 0
    found_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "pk_key": self.pk_key,
            "platform": self.platform,
            "gateways": self.gateways,
            "has_captcha": self.has_captcha,
            "has_cloudflare": self.has_cloudflare,
            "has_graphql": self.has_graphql,
            "has_3ds": self.has_3ds,
            "checkout_url": self.checkout_url,
            "score": self.score,
            "found_at": self.found_at.isoformat(),
        }


class SiteValidator:
    """Validates sites for payment integration."""
    
    SKIP_DOMAINS = {
        "github.com", "github.io", "stackoverflow.com", "stackexchange.com",
        "stripe.com", "stripe.dev", "wordpress.org", "woocommerce.com",
        "shopify.com", "facebook.com", "twitter.com", "youtube.com",
        "linkedin.com", "instagram.com", "medium.com", "reddit.com",
        "npmjs.com", "pypi.org", "google.com", "docs.google.com",
        "wikipedia.org", "w3schools.com", "mozilla.org",
    }
    
    def __init__(self, proxy_manager: ProxyManager, timeout: int = 10):
        self.proxy_manager = proxy_manager
        self.timeout = timeout
        self.stats = {"validated": 0, "valid": 0, "errors": 0}
    
    def _extract_domain(self, url: str) -> str:
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""
    
    def _should_skip(self, domain: str) -> bool:
        for skip in self.SKIP_DOMAINS:
            if skip in domain:
                return True
        return False
    
    def _detect_platform(self, html: str) -> Optional[str]:
        html_lower = html.lower()
        if "woocommerce" in html_lower or "wc-" in html_lower:
            return "WooCommerce"
        if "shopify" in html_lower:
            return "Shopify"
        if "magento" in html_lower:
            return "Magento"
        if "squarespace" in html_lower:
            return "Squarespace"
        if "wix" in html_lower:
            return "Wix"
        if "wordpress" in html_lower or "wp-" in html_lower:
            return "WordPress"
        return None
    
    def _detect_gateways(self, html: str) -> List[str]:
        gateways = set()
        html_lower = html.lower()
        
        # Stripe (already checked via PK, but good to double check)
        if "stripe" in html_lower or "pk_live" in html:
            gateways.add("Stripe")
            
        # PayPal
        if "paypal" in html_lower:
            gateways.add("PayPal")
            
        # Braintree
        if "braintree" in html_lower:
            gateways.add("Braintree")
            
        # Square
        if "squareup" in html_lower or "sq-payment" in html_lower:
            gateways.add("Square")
            
        # Bolt
        if "bolt.com" in html_lower or "connect.bolt.com" in html_lower:
            gateways.add("Bolt")
            
        # Adyen
        if "adyen" in html_lower:
            gateways.add("Adyen")
            
        # Klarna
        if "klarna" in html_lower:
            gateways.add("Klarna")
            
        # Affirm
        if "affirm" in html_lower:
            gateways.add("Affirm")
            
        # Authorize.net
        if "authorize.net" in html_lower or "authorizenet" in html_lower:
            gateways.add("Authorize.Net")
            
        # 2Checkout
        if "2checkout" in html_lower:
            gateways.add("2Checkout")
            
        return list(gateways)

    def _calculate_score(self, info: SiteInfo) -> int:
        score = 0
        if info.pk_key:
            score += 40
        else:
            return 0
        
        # Platform bonus
        if info.platform:
            if info.platform == "WooCommerce":
                score += 25
            elif info.platform in ["WordPress", "Shopify"]:
                score += 15
            else:
                score += 10
        
        # Gateway bonus
        if len(info.gateways) > 1:
            score += 10 * (len(info.gateways) - 1)  # +10 for each extra gateway
        
        if "Braintree" in info.gateways:
            score += 15
        
        # Security penalties/bonuses
        if not info.has_captcha:
            score += 20
        else:
            score -= 20
        
        if not info.has_cloudflare:
            score += 10
        else:
            score -= 10
            
        # GraphQL bonus (often easier to exploit)
        if info.has_graphql:
            score += 10
            
        # 3DS penalty (harder to card)
        if info.has_3ds:
            score -= 15
        
        return max(0, min(100, score))
    
    async def validate(self, url: str) -> Optional[SiteInfo]:
        """Validate a single URL."""
        domain = self._extract_domain(url)
        if not domain or self._should_skip(domain):
            return None
        
        self.stats["validated"] += 1
        proxy = await self.proxy_manager.get_proxy()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
            }
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, proxy=proxy, ssl=False, allow_redirects=True) as resp:
                    if resp.status != 200:
                        return None
                    
                    html = await resp.text()
                    
                    info = SiteInfo(url=url, domain=domain)
                    
                    # Find Stripe PK
                    pk_match = re.search(r'pk_live_[a-zA-Z0-9]{20,}', html)
                    if pk_match:
                        info.pk_key = pk_match.group(0)
                    
                    # Detect platform
                    info.platform = self._detect_platform(html)
                    
                    # Detect gateways
                    info.gateways = self._detect_gateways(html)
                    if info.pk_key and "Stripe" not in info.gateways:
                        info.gateways.append("Stripe")
                    
                    # Detect captcha
                    html_lower = html.lower()
                    info.has_captcha = any(x in html_lower for x in ["recaptcha", "hcaptcha", "captcha", "cf-turnstile"])
                    
                    # Detect Cloudflare
                    info.has_cloudflare = "cloudflare" in html_lower or "cf-ray" in str(resp.headers).lower()
                    
                    # Detect GraphQL
                    info.has_graphql = "graphql" in html_lower or "/graphql" in html_lower or "gql" in html_lower
                    
                    # Detect 3DS
                    info.has_3ds = any(x in html_lower for x in ["3d secure", "3ds", "three_d_secure", "threedsecure"])
                    
                    # Calculate score
                    info.score = self._calculate_score(info)
                    
                    if info.pk_key:
                        self.stats["valid"] += 1
                        if proxy:
                            await self.proxy_manager.report_success(proxy)
                    
                    return info if info.pk_key else None
                    
        except Exception as e:
            self.stats["errors"] += 1
            if proxy:
                await self.proxy_manager.report_failure(proxy, str(e)[:50])
            return None
    
    async def validate_many(self, urls: List[str], max_concurrent: int = 15) -> List[SiteInfo]:
        """Validate multiple URLs in parallel."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def validate_with_sem(url: str):
            async with semaphore:
                return await self.validate(url)
        
        tasks = [validate_with_sem(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid = []
        for r in results:
            if isinstance(r, SiteInfo) and r.pk_key:
                valid.append(r)
        
        return valid


# ============== TELEGRAM NOTIFIER ==============

class TelegramNotifier:
    """Sends notifications to Telegram."""
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}"
    
    async def send(self, text: str):
        if not self.token or not self.chat_id:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.base_url}/sendMessage",
                    json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"},
                    timeout=aiohttp.ClientTimeout(total=10)
                )
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
    
    async def notify_site(self, site: SiteInfo):
        gateways_str = ", ".join(site.gateways) if site.gateways else "Stripe"
        msg = f"""
<b>🎯 Site Found!</b>

<b>Domain:</b> <code>{site.domain}</code>
<b>Score:</b> <code>{site.score}/100</code>
<b>Platform:</b> <code>{site.platform or 'Unknown'}</code>
<b>Gateways:</b> <code>{gateways_str}</code>
<b>PK:</b> <code>{site.pk_key[:40]}...</code>
<b>Captcha:</b> <code>{'Yes ❌' if site.has_captcha else 'No ✅'}</code>
<b>Cloudflare:</b> <code>{'Yes ⚠️' if site.has_cloudflare else 'No ✅'}</code>
<b>GraphQL:</b> <code>{'Yes ℹ️' if site.has_graphql else 'No'}</code>
<b>3D Secure:</b> <code>{'Yes ⚠️' if site.has_3ds else 'No ✅'}</code>
<b>URL:</b> {site.url}
"""
        await self.send(msg.strip())


# ============== FAST DORKER ==============

class FastDorker:
    """High-performance parallel dorker."""
    
    def __init__(self, config: FastDorkerConfig):
        self.config = config
        self.seen_domains: Set[str] = set()
        self.found_sites: List[Dict] = []
        self.start_time = datetime.now()
        
        # Stats
        self.stats = {
            "cycles": 0,
            "dorks_processed": 0,
            "urls_found": 0,
            "sites_validated": 0,
            "sites_found": 0,
            "errors": 0,
        }
        
        # Components
        self.proxy_manager = ProxyManager(config.proxy_file, config.proxy_fail_threshold)
        self.searcher = ParallelSearcher(self.proxy_manager, config.search_timeout)
        self.validator = SiteValidator(self.proxy_manager, config.validation_timeout)
        self.notifier = TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id)
        
        # Load state
        self._load_state()
        
        # Dorks
        self.dorks = self._get_dorks()
        
        logger.info(f"FastDorker initialized: {len(self.dorks)} dorks, {len(self.proxy_manager.proxies)} proxies")
    
    def _load_state(self):
        """Load previous state."""
        # Seen domains
        seen_path = Path(self.config.seen_domains_file)
        if seen_path.exists():
            with open(seen_path) as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        self.seen_domains.add(domain)
            logger.info(f"Loaded {len(self.seen_domains)} seen domains")
        
        # Found sites
        found_path = Path(self.config.found_sites_file)
        if found_path.exists():
            try:
                with open(found_path) as f:
                    self.found_sites = json.load(f)
                logger.info(f"Loaded {len(self.found_sites)} found sites")
            except Exception as e:
                logger.debug(f"Failed to load found sites: {e}")
    
    def _save_state(self):
        """Save current state."""
        with open(self.config.seen_domains_file, "w") as f:
            for domain in sorted(self.seen_domains):
                f.write(domain + "\n")
        
        with open(self.config.found_sites_file, "w") as f:
            json.dump(self.found_sites, f, indent=2, default=str)
    
    def _get_dorks(self) -> List[str]:
        """Get list of dorks."""
        from config import config as cfg
        return cfg.dorks
    
    def _extract_domain(self, url: str) -> str:
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""
    
    def _is_new_domain(self, url: str) -> bool:
        domain = self._extract_domain(url)
        return domain and domain not in self.seen_domains
    
    async def process_dork(self, dork: str, dork_num: int) -> List[SiteInfo]:
        """Process a single dork."""
        logger.debug(f"[{dork_num}] Searching: {dork[:50]}...")
        
        # Search
        urls, search_stats = await self.searcher.search(dork, 15)
        self.stats["urls_found"] += len(urls)
        
        # Log search results
        total_results = sum(v for v in search_stats.values() if isinstance(v, int))
        logger.info(f"[{dork_num}] Search: {total_results} results | {search_stats}")
        
        if not urls:
            return []
        
        # Filter new domains
        new_urls = [u for u in urls if self._is_new_domain(u)]
        logger.debug(f"[{dork_num}] New domains: {len(new_urls)}/{len(urls)}")
        
        if not new_urls:
            return []
        
        # Validate
        valid_sites = await self.validator.validate_many(new_urls, self.config.max_concurrent_validations)
        
        # Mark domains as seen
        for url in urls:
            domain = self._extract_domain(url)
            if domain:
                self.seen_domains.add(domain)
        
        # Process valid sites
        for site in valid_sites:
            self.stats["sites_found"] += 1
            
            if site.score >= self.config.min_score_to_save:
                self.found_sites.append(site.to_dict())
                logger.info(f"SITE_FOUND | {site.domain} | Score: {site.score} | Platform: {site.platform}")
            
            if site.score >= self.config.min_score_to_notify:
                await self.notifier.notify_site(site)
        
        return valid_sites
    
    async def run_cycle(self):
        """Run one cycle through all dorks with parallel processing."""
        self.stats["cycles"] += 1
        cycle_start = datetime.now()
        
        logger.info(f"{'='*60}")
        logger.info(f"CYCLE #{self.stats['cycles']} STARTING")
        logger.info(f"Dorks: {len(self.dorks)} | Concurrency: {self.config.max_concurrent_dorks}")
        logger.info(f"{'='*60}")
        
        # Shuffle dorks
        dorks = self.dorks.copy()
        random.shuffle(dorks)
        
        # Process in batches
        batch_size = self.config.max_concurrent_dorks
        total_sites_this_cycle = 0
        
        for i in range(0, len(dorks), batch_size):
            batch = dorks[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(dorks) + batch_size - 1) // batch_size
            
            logger.info(f"Batch {batch_num}/{total_batches} ({len(batch)} dorks)")
            
            # Process batch in parallel
            tasks = [
                self.process_dork(dork, i + j + 1)
                for j, dork in enumerate(batch)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    self.stats["errors"] += 1
                    logger.error(f"Dork error: {result}")
                elif isinstance(result, list):
                    total_sites_this_cycle += len(result)
            
            self.stats["dorks_processed"] += len(batch)
            
            # Small delay between batches
            if i + batch_size < len(dorks):
                await asyncio.sleep(self.config.delay_between_batches)
            
            # Save state periodically
            if batch_num % 5 == 0:
                self._save_state()
        
        # Cycle complete
        cycle_time = (datetime.now() - cycle_start).total_seconds()
        
        logger.info(f"{'='*60}")
        logger.info(f"CYCLE #{self.stats['cycles']} COMPLETE")
        logger.info(f"Time: {cycle_time:.1f}s | Sites found: {total_sites_this_cycle}")
        logger.info(f"Total stats: {self.stats}")
        logger.info(f"Proxy stats: {self.proxy_manager.get_stats()}")
        logger.info(f"{'='*60}")
        
        self._save_state()
    
    async def run(self, once: bool = False):
        """Main run loop."""
        logger.info(f"{'='*60}")
        logger.info("FAST DORKER STARTING")
        logger.info(f"Mode: {'Single cycle' if once else 'Infinite'}")
        logger.info(f"Dorks: {len(self.dorks)} | Proxies: {len(self.proxy_manager.proxies)}")
        logger.info(f"Concurrency: {self.config.max_concurrent_dorks} dorks, {self.config.max_concurrent_validations} validations")
        logger.info(f"{'='*60}")
        
        await self.notifier.send(
            f"🚀 <b>FastDorker Started</b>\n\n"
            f"Dorks: {len(self.dorks)}\n"
            f"Proxies: {len(self.proxy_manager.proxies)}\n"
            f"Concurrency: {self.config.max_concurrent_dorks}"
        )
        
        while True:
            try:
                await self.run_cycle()
                
                if once:
                    break
                
                logger.info(f"Waiting {self.config.delay_between_cycles}s before next cycle...")
                await asyncio.sleep(self.config.delay_between_cycles)
                
            except KeyboardInterrupt:
                logger.info("Interrupted")
                break
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"Cycle error: {e}")
                await asyncio.sleep(30)
        
        self._save_state()
        logger.info("FastDorker stopped")


# ============== LOGGING SETUP ==============

def setup_logging(debug: bool = False):
    """Setup logging."""
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logger.remove()
    
    # Console
    logger.add(
        sys.stderr,
        level="DEBUG" if debug else "INFO",
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | <cyan>{message}</cyan>"
    )
    
    # Main log
    logger.add(
        log_dir / "fast_dorker.log",
        rotation="10 MB",
        retention="7 days",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}"
    )
    
    # Errors only
    logger.add(
        log_dir / "errors.log",
        rotation="5 MB",
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}"
    )
    
    # Sites found
    logger.add(
        log_dir / "sites.log",
        rotation="5 MB",
        level="INFO",
        filter=lambda r: "SITE_FOUND" in r["message"],
        format="{time:YYYY-MM-DD HH:mm:ss} | {message}"
    )


# ============== MAIN ==============

def main():
    parser = argparse.ArgumentParser(description="Fast Parallel Dorker")
    parser.add_argument("--token", required=True, help="Telegram bot token")
    parser.add_argument("--chat", required=True, help="Telegram chat ID")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent dorks (default: 10)")
    parser.add_argument("--once", action="store_true", help="Run one cycle only")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    
    args = parser.parse_args()
    
    setup_logging(args.debug)
    
    config = FastDorkerConfig(
        telegram_bot_token=args.token,
        telegram_chat_id=args.chat,
        max_concurrent_dorks=args.workers,
    )
    
    dorker = FastDorker(config)
    asyncio.run(dorker.run(once=args.once))


if __name__ == "__main__":
    main()
