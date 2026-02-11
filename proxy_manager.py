"""
Proxy Manager v1.0 — Smart proxy rotation, health checking & stats.

Features:
- Multi-source loading: CSV files, plain text files, inline lists
- Rotation strategies: round_robin, random, least_recently_used, weighted (by success rate)
- Automatic health checking with async connect tests
- Auto-ban on consecutive failures with configurable cooldown
- Country-based geographic filtering
- Per-domain proxy stickiness
- Real-time stats tracking per proxy
- Periodic background health checks
- Thread-safe for async usage
"""

import asyncio
import csv
import logging
import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("proxy_manager")


# ────────────────────────── DATA CLASSES ──────────────────────────


class RotationStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LRU = "least_recently_used"
    WEIGHTED = "weighted"


class ProxyProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"


@dataclass
class ProxyInfo:
    """Information about a single proxy."""
    host: str
    port: int
    country: str = ""
    city: str = ""
    protocol: ProxyProtocol = ProxyProtocol.HTTP
    
    # Authentication (optional)
    username: str = ""
    password: str = ""
    
    # Health tracking
    alive: bool = True
    latency_ms: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    consecutive_failures: int = 0
    last_used: float = 0.0
    last_checked: float = 0.0
    banned_until: float = 0.0
    
    # Source tracking
    source_file: str = ""
    source_id: str = ""

    @property
    def address(self) -> str:
        """IP:PORT string."""
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """Full proxy URL for aiohttp (e.g. http://ip:port)."""
        if self.username and self.password:
            from urllib.parse import quote
            return f"{self.protocol.value}://{quote(self.username, safe='')}:{quote(self.password, safe='')}@{self.host}:{self.port}"
        return f"{self.protocol.value}://{self.host}:{self.port}"

    @property
    def is_banned(self) -> bool:
        return self.banned_until > time.time()

    @property
    def is_available(self) -> bool:
        return self.alive and not self.is_banned

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.5  # Unknown — neutral weight
        return self.success_count / total

    @property
    def score(self) -> float:
        """Composite score for weighted selection: higher is better."""
        rate = self.success_rate
        # Penalize high latency (normalize: <500ms = good, >5000ms = bad)
        latency_factor = max(0.1, 1.0 - (self.latency_ms / 5000.0))
        # Boost proxies with more successful uses (trust)
        trust = min(1.0, self.success_count / 50.0)  # Caps at 50 successes
        return (rate * 0.6 + latency_factor * 0.2 + trust * 0.2)

    def record_success(self, latency_ms: float = 0.0):
        self.success_count += 1
        self.consecutive_failures = 0
        self.last_used = time.time()
        if latency_ms > 0:
            # Exponential moving average
            if self.latency_ms == 0:
                self.latency_ms = latency_ms
            else:
                self.latency_ms = self.latency_ms * 0.7 + latency_ms * 0.3

    def record_failure(self):
        self.fail_count += 1
        self.consecutive_failures += 1
        self.last_used = time.time()

    def ban(self, duration_seconds: int):
        self.banned_until = time.time() + duration_seconds
        self.alive = False
        logger.info(f"Proxy {self.address} banned for {duration_seconds}s "
                     f"(failures: {self.consecutive_failures})")

    def unban(self):
        self.banned_until = 0
        self.alive = True
        self.consecutive_failures = 0


@dataclass
class ProxyStats:
    """Aggregated proxy pool statistics."""
    total_proxies: int = 0
    alive_proxies: int = 0
    banned_proxies: int = 0
    dead_proxies: int = 0
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    avg_latency_ms: float = 0.0
    avg_success_rate: float = 0.0
    by_country: Dict[str, int] = field(default_factory=dict)
    by_source: Dict[str, int] = field(default_factory=dict)
    top_proxies: List[Tuple[str, float]] = field(default_factory=list)  # (address, score)
    worst_proxies: List[Tuple[str, int]] = field(default_factory=list)  # (address, fail_count)


# ────────────────────────── PROXY LOADER ──────────────────────────


class ProxyLoader:
    """Load proxies from various sources."""

    @staticmethod
    def load_csv(filepath: str, protocol: ProxyProtocol = ProxyProtocol.HTTP) -> List[ProxyInfo]:
        """Load proxies from CSV file with headers: Id,Proxy,Country,City,Status"""
        proxies = []
        if not os.path.exists(filepath):
            logger.warning(f"Proxy CSV not found: {filepath}")
            return proxies
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_proxy = row.get("Proxy", "").strip().strip('"')
                    status = row.get("Status", "").strip().strip('"')
                    country = row.get("Country", "").strip().strip('"')
                    city = row.get("City", "").strip().strip('"')
                    source_id = row.get("Id", "").strip().strip('"')
                    
                    if not raw_proxy:
                        continue
                    
                    # Parse host:port
                    parts = raw_proxy.split(":")
                    if len(parts) != 2:
                        logger.debug(f"Skipping malformed proxy: {raw_proxy}")
                        continue
                    
                    host = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except ValueError:
                        logger.debug(f"Skipping invalid port: {raw_proxy}")
                        continue
                    
                    # Only load "Working" proxies (or all if no status field)
                    if status and status.lower() not in ("working", "alive", "active", ""):
                        continue
                    
                    proxy = ProxyInfo(
                        host=host,
                        port=port,
                        country=country,
                        city=city,
                        protocol=protocol,
                        source_file=os.path.basename(filepath),
                        source_id=source_id,
                        alive=True,
                    )
                    proxies.append(proxy)
            
            logger.info(f"Loaded {len(proxies)} proxies from CSV: {filepath}")
        except Exception as e:
            logger.error(f"Error loading CSV {filepath}: {e}")
        
        return proxies

    @staticmethod
    def load_text(filepath: str, protocol: ProxyProtocol = ProxyProtocol.HTTP) -> List[ProxyInfo]:
        """Load proxies from plain text file (one per line: ip:port or protocol://ip:port)."""
        proxies = []
        if not os.path.exists(filepath):
            logger.warning(f"Proxy file not found: {filepath}")
            return proxies
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Handle protocol://user:pass@host:port or host:port
                    proto = protocol
                    auth_user = ""
                    auth_pass = ""
                    
                    if "://" in line:
                        parsed = urlparse(line)
                        proto_str = parsed.scheme.lower()
                        if proto_str == "socks5":
                            proto = ProxyProtocol.SOCKS5
                        elif proto_str == "https":
                            proto = ProxyProtocol.HTTPS
                        else:
                            proto = ProxyProtocol.HTTP
                        host = parsed.hostname or ""
                        port = parsed.port or 8080
                        auth_user = parsed.username or ""
                        auth_pass = parsed.password or ""
                    else:
                        # Plain host:port
                        parts = line.split(":")
                        if len(parts) == 2:
                            host = parts[0].strip()
                            try:
                                port = int(parts[1].strip())
                            except ValueError:
                                continue
                        elif len(parts) == 4:
                            # host:port:user:pass format
                            host = parts[0].strip()
                            try:
                                port = int(parts[1].strip())
                            except ValueError:
                                continue
                            auth_user = parts[2].strip()
                            auth_pass = parts[3].strip()
                        else:
                            continue
                    
                    if not host:
                        continue
                    
                    proxy = ProxyInfo(
                        host=host,
                        port=port,
                        protocol=proto,
                        username=auth_user,
                        password=auth_pass,
                        source_file=os.path.basename(filepath),
                        alive=True,
                    )
                    proxies.append(proxy)
            
            logger.info(f"Loaded {len(proxies)} proxies from text: {filepath}")
        except Exception as e:
            logger.error(f"Error loading text file {filepath}: {e}")
        
        return proxies

    @staticmethod
    def load_file(filepath: str, protocol: ProxyProtocol = ProxyProtocol.HTTP) -> List[ProxyInfo]:
        """Auto-detect file format and load accordingly."""
        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".csv":
            return ProxyLoader.load_csv(filepath, protocol)
        else:
            return ProxyLoader.load_text(filepath, protocol)

    @staticmethod
    def from_list(proxy_strings: List[str], protocol: ProxyProtocol = ProxyProtocol.HTTP) -> List[ProxyInfo]:
        """Convert list of proxy strings (ip:port) to ProxyInfo objects."""
        proxies = []
        for raw in proxy_strings:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            
            if "://" in raw:
                parsed = urlparse(raw)
                proto_str = parsed.scheme.lower()
                proto = ProxyProtocol.SOCKS5 if proto_str == "socks5" else (
                    ProxyProtocol.HTTPS if proto_str == "https" else ProxyProtocol.HTTP
                )
                proxy = ProxyInfo(
                    host=parsed.hostname or "",
                    port=parsed.port or 8080,
                    protocol=proto,
                    username=parsed.username or "",
                    password=parsed.password or "",
                    source_file="inline",
                    alive=True,
                )
            else:
                parts = raw.split(":")
                if len(parts) < 2:
                    continue
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                username = parts[2] if len(parts) >= 4 else ""
                password = ":".join(parts[3:]) if len(parts) >= 4 else ""
                proxy = ProxyInfo(
                    host=parts[0],
                    port=port,
                    protocol=protocol,
                    username=username,
                    password=password,
                    source_file="inline",
                    alive=True,
                )
            
            if proxy.host:
                proxies.append(proxy)
        
        return proxies


# ────────────────────────── PROXY POOL ──────────────────────────


class ProxyPool:
    """
    Smart proxy pool with rotation strategies, health checking, and auto-banning.
    
    Thread-safe for async usage via lock.
    """

    def __init__(
        self,
        strategy: RotationStrategy = RotationStrategy.WEIGHTED,
        ban_threshold: int = 5,
        ban_duration: int = 600,
        country_filter: Optional[List[str]] = None,
        sticky_per_domain: int = 0,
        health_check_enabled: bool = True,
        health_check_interval: int = 300,
        health_check_timeout: int = 10,
        health_check_url: str = "http://httpbin.org/ip",
        max_concurrent_checks: int = 50,
    ):
        self.strategy = strategy
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.country_filter = [c.upper() for c in (country_filter or [])]
        self.sticky_per_domain = sticky_per_domain
        self.health_check_enabled = health_check_enabled
        self.health_check_interval = health_check_interval
        self.health_check_timeout = health_check_timeout
        self.health_check_url = health_check_url
        self.max_concurrent_checks = max_concurrent_checks
        
        self._proxies: List[ProxyInfo] = []
        self._round_robin_index: int = 0
        self._lock = asyncio.Lock()
        self._domain_sticky: Dict[str, Tuple[ProxyInfo, int]] = {}
        self._health_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Deduplication
        self._seen_addresses: Set[str] = set()

    @property
    def total(self) -> int:
        return len(self._proxies)

    @property
    def available(self) -> List[ProxyInfo]:
        return [p for p in self._proxies if p.is_available]

    @property
    def alive_count(self) -> int:
        return len(self.available)

    @property
    def banned_count(self) -> int:
        return sum(1 for p in self._proxies if p.is_banned)

    @property
    def dead_count(self) -> int:
        return sum(1 for p in self._proxies if not p.alive and not p.is_banned)

    def add_proxies(self, proxies: List[ProxyInfo]) -> int:
        """Add proxies to the pool, deduplicating by address."""
        added = 0
        for p in proxies:
            if p.address not in self._seen_addresses:
                self._seen_addresses.add(p.address)
                self._proxies.append(p)
                added += 1
        if added:
            logger.info(f"Added {added} proxies to pool (total: {self.total}, "
                        f"skipped {len(proxies) - added} duplicates)")
        return added

    def load_files(self, filepaths: List[str],
                   protocol: ProxyProtocol = ProxyProtocol.HTTP) -> int:
        """Load proxies from multiple files (auto-detects CSV vs text)."""
        total_added = 0
        for fp in filepaths:
            fp = fp.strip()
            if not fp:
                continue
            proxies = ProxyLoader.load_file(fp, protocol)
            total_added += self.add_proxies(proxies)
        return total_added

    def _get_filtered(self) -> List[ProxyInfo]:
        """Get available proxies, optionally filtered by country."""
        avail = self.available
        if self.country_filter:
            filtered = [p for p in avail if p.country.upper() in self.country_filter]
            if filtered:
                return filtered
            # Fallback to all available if no country match
            logger.debug(f"No proxies match country filter {self.country_filter}, using all")
        return avail

    async def get_proxy(self, domain: str = "") -> Optional[ProxyInfo]:
        """Get next proxy according to rotation strategy."""
        async with self._lock:
            # Check domain stickiness
            if domain and self.sticky_per_domain > 0:
                if domain in self._domain_sticky:
                    proxy, uses = self._domain_sticky[domain]
                    if proxy.is_available and uses < self.sticky_per_domain:
                        self._domain_sticky[domain] = (proxy, uses + 1)
                        proxy.last_used = time.time()
                        return proxy
                    else:
                        del self._domain_sticky[domain]
            
            pool = self._get_filtered()
            if not pool:
                # Try to unban expired proxies
                self._unban_expired()
                pool = self._get_filtered()
                if not pool:
                    if not getattr(self, '_pool_warning_shown', False):
                        logger.warning("No available proxies in pool — falling back to direct connection")
                        self._pool_warning_shown = True
                    return None
            
            proxy = self._select(pool)
            if proxy:
                proxy.last_used = time.time()
                if domain and self.sticky_per_domain > 0:
                    self._domain_sticky[domain] = (proxy, 1)
            
            return proxy

    def _select(self, pool: List[ProxyInfo]) -> Optional[ProxyInfo]:
        """Select a proxy from the filtered pool based on strategy."""
        if not pool:
            return None

        if self.strategy == RotationStrategy.ROUND_ROBIN:
            self._round_robin_index = self._round_robin_index % len(pool)
            proxy = pool[self._round_robin_index]
            self._round_robin_index += 1
            return proxy

        elif self.strategy == RotationStrategy.RANDOM:
            return random.choice(pool)

        elif self.strategy == RotationStrategy.LRU:
            # Least recently used
            return min(pool, key=lambda p: p.last_used)

        elif self.strategy == RotationStrategy.WEIGHTED:
            # Weighted random based on composite score
            scores = [max(0.01, p.score) for p in pool]
            total = sum(scores)
            weights = [s / total for s in scores]
            return random.choices(pool, weights=weights, k=1)[0]

        return random.choice(pool)

    def _unban_expired(self):
        """Unban proxies whose ban duration has expired."""
        now = time.time()
        for p in self._proxies:
            if p.is_banned and p.banned_until <= now:
                p.unban()
                logger.debug(f"Proxy {p.address} unbanned (cooldown expired)")

    async def report_success(self, proxy: ProxyInfo, latency_ms: float = 0.0):
        """Record a successful request through this proxy."""
        async with self._lock:
            proxy.record_success(latency_ms)

    async def report_failure(self, proxy: ProxyInfo, ban: bool = False):
        """Record a failed request through this proxy."""
        async with self._lock:
            proxy.record_failure()
            if proxy.consecutive_failures >= self.ban_threshold or ban:
                proxy.ban(self.ban_duration)

    async def report_rate_limited(self, proxy: ProxyInfo):
        """Proxy got rate-limited — ban it immediately."""
        async with self._lock:
            proxy.ban(self.ban_duration)
            logger.info(f"Proxy {proxy.address} rate-limited → banned for {self.ban_duration}s")

    # ── Health Checking ──

    async def check_proxy(self, proxy: ProxyInfo) -> bool:
        """Test a single proxy by connecting through it.
        Counts as alive if we get any HTTP response (even 403/407 from Squid)."""
        proxy_url = proxy.url
        try:
            timeout = aiohttp.ClientTimeout(total=self.health_check_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start = time.time()
                async with session.get(
                    self.health_check_url,
                    proxy=proxy_url,
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    elapsed_ms = (time.time() - start) * 1000
                    # Any HTTP response means the proxy is reachable and forwarding
                    # (Squid proxies may return 403/407 but still work for other URLs)
                    if resp.status < 500:
                        proxy.alive = True
                        proxy.latency_ms = elapsed_ms
                        proxy.last_checked = time.time()
                        return True
                    else:
                        proxy.alive = False
                        proxy.last_checked = time.time()
                        return False
        except Exception:
            proxy.alive = False
            proxy.last_checked = time.time()
            return False

    async def health_check_all(self, quiet: bool = False) -> Tuple[int, int]:
        """Check all proxies. Returns (alive, dead)."""
        if not self._proxies:
            return 0, 0
        
        sem = asyncio.Semaphore(self.max_concurrent_checks)
        
        async def check_one(p: ProxyInfo):
            async with sem:
                return await self.check_proxy(p)

        if not quiet:
            logger.info(f"Health checking {len(self._proxies)} proxies...")

        tasks = [check_one(p) for p in self._proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        alive = sum(1 for r in results if r is True)
        dead = len(results) - alive
        
        if not quiet:
            logger.info(f"Health check complete: {alive} alive, {dead} dead "
                        f"({alive / len(results) * 100:.0f}% alive)")
        
        return alive, dead

    async def _health_check_loop(self):
        """Background periodic health check."""
        while self._running:
            try:
                await asyncio.sleep(self.health_check_interval)
                if self._running:
                    await self.health_check_all(quiet=True)
                    # Unban expired proxies
                    self._unban_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def start(self, initial_check: bool = True):
        """Start the proxy pool (optional initial health check + background checks)."""
        self._running = True
        
        if initial_check and self.health_check_enabled and self._proxies:
            await self.health_check_all()
        
        if self.health_check_enabled and self.health_check_interval > 0:
            self._health_task = asyncio.create_task(self._health_check_loop())
            logger.info(f"Started background health checks (every {self.health_check_interval}s)")

    async def stop(self):
        """Stop background health checks."""
        self._running = False
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
            self._health_task = None

    # ── Stats ──

    def get_stats(self) -> ProxyStats:
        """Get aggregated pool statistics."""
        stats = ProxyStats()
        stats.total_proxies = self.total
        stats.alive_proxies = self.alive_count
        stats.banned_proxies = self.banned_count
        stats.dead_proxies = self.dead_count
        
        latencies = []
        rates = []
        
        for p in self._proxies:
            stats.total_requests += p.success_count + p.fail_count
            stats.total_successes += p.success_count
            stats.total_failures += p.fail_count
            
            if p.latency_ms > 0:
                latencies.append(p.latency_ms)
            if p.success_count + p.fail_count > 0:
                rates.append(p.success_rate)
            
            # By country
            country = p.country or "Unknown"
            stats.by_country[country] = stats.by_country.get(country, 0) + 1
            
            # By source
            source = p.source_file or "unknown"
            stats.by_source[source] = stats.by_source.get(source, 0) + 1
        
        if latencies:
            stats.avg_latency_ms = sum(latencies) / len(latencies)
        if rates:
            stats.avg_success_rate = sum(rates) / len(rates)
        
        # Top 5 by score
        scored = [(p.address, p.score) for p in self._proxies if p.success_count > 0]
        scored.sort(key=lambda x: x[1], reverse=True)
        stats.top_proxies = scored[:5]
        
        # Worst 5 by fail count
        failed = [(p.address, p.fail_count) for p in self._proxies if p.fail_count > 0]
        failed.sort(key=lambda x: x[1], reverse=True)
        stats.worst_proxies = failed[:5]
        
        return stats

    def get_country_breakdown(self) -> Dict[str, int]:
        """Get proxy count by country."""
        countries: Dict[str, int] = {}
        for p in self._proxies:
            c = p.country or "Unknown"
            countries[c] = countries.get(c, 0) + 1
        return dict(sorted(countries.items(), key=lambda x: x[1], reverse=True))

    def get_proxy_list(self) -> List[str]:
        """Get list of all proxy URLs (for backward compat with engines expecting string list)."""
        return [p.url for p in self._proxies if p.is_available]


# ────────────────────────── PROXY MANAGER (TOP-LEVEL) ──────────────────────────


class ProxyManager:
    """
    Top-level proxy management: pool + rotation + integration helpers.
    
    This is the main class that main_v3.py interacts with.
    
    Usage:
        mgr = ProxyManager(config)
        await mgr.start()               # Load files + optional health check
        proxy = await mgr.get_proxy()    # Get a ProxyInfo
        url = mgr.get_proxy_url()        # Get just the URL string for aiohttp
        await mgr.report_success(proxy)
        await mgr.report_failure(proxy)
        await mgr.stop()
    """

    def __init__(
        self,
        proxy_files: Optional[List[str]] = None,
        strategy: str = "weighted",
        ban_threshold: int = 5,
        ban_duration: int = 600,
        country_filter: Optional[List[str]] = None,
        sticky_per_domain: int = 0,
        health_check: bool = True,
        health_check_interval: int = 300,
        health_check_timeout: int = 10,
        protocol: str = "http",
        max_concurrent_checks: int = 50,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.proxy_files = proxy_files or []
        self._protocol = ProxyProtocol(protocol) if protocol in ("http", "https", "socks5") else ProxyProtocol.HTTP
        
        strategy_enum = RotationStrategy(strategy) if strategy in [s.value for s in RotationStrategy] else RotationStrategy.WEIGHTED
        
        self.pool = ProxyPool(
            strategy=strategy_enum,
            ban_threshold=ban_threshold,
            ban_duration=ban_duration,
            country_filter=country_filter,
            sticky_per_domain=sticky_per_domain,
            health_check_enabled=health_check,
            health_check_interval=health_check_interval,
            health_check_timeout=health_check_timeout,
            max_concurrent_checks=max_concurrent_checks,
        )
        
        self._started = False

    @property
    def total(self) -> int:
        return self.pool.total

    @property
    def alive_count(self) -> int:
        return self.pool.alive_count

    @property
    def has_proxies(self) -> bool:
        return self.enabled and self.pool.total > 0

    async def start(self, initial_health_check: bool = True):
        """Load proxy files and start background health checking."""
        if not self.enabled:
            logger.info("Proxy manager disabled")
            return
        
        # Load from configured files
        if self.proxy_files:
            self.pool.load_files(self.proxy_files, self._protocol)
        
        if self.pool.total == 0:
            logger.warning("No proxies loaded — proxy rotation disabled")
            self.enabled = False
            return
        
        # Start pool (health check + background task)
        await self.pool.start(initial_check=initial_health_check)
        self._started = True
        
        logger.info(f"🔄 Proxy manager started: {self.pool.alive_count}/{self.pool.total} alive "
                     f"(strategy: {self.pool.strategy.value})")

    async def stop(self):
        """Stop background health checks and clean up."""
        if self._started:
            await self.pool.stop()
            self._started = False

    async def get_proxy(self, domain: str = "") -> Optional[ProxyInfo]:
        """Get next available proxy."""
        if not self.enabled:
            return None
        return await self.pool.get_proxy(domain)

    async def get_proxy_url(self, domain: str = "") -> Optional[str]:
        """Get next available proxy URL string (for aiohttp)."""
        proxy = await self.get_proxy(domain)
        return proxy.url if proxy else None

    async def report_success(self, proxy: Optional[ProxyInfo], latency_ms: float = 0.0):
        """Report a successful request through proxy."""
        if proxy:
            await self.pool.report_success(proxy, latency_ms)

    async def report_failure(self, proxy: Optional[ProxyInfo]):
        """Report a failed request through proxy."""
        if proxy:
            await self.pool.report_failure(proxy)

    async def report_rate_limited(self, proxy: Optional[ProxyInfo]):
        """Report rate limiting — bans the proxy."""
        if proxy:
            await self.pool.report_rate_limited(proxy)

    async def health_check(self) -> Tuple[int, int]:
        """Run health check on all proxies. Returns (alive, dead)."""
        return await self.pool.health_check_all()

    def get_stats(self) -> ProxyStats:
        """Get proxy pool statistics."""
        return self.pool.get_stats()

    def get_proxy_url_list(self) -> List[str]:
        """Get list of all available proxy URLs (backward compat)."""
        return self.pool.get_proxy_list()

    def get_country_breakdown(self) -> Dict[str, int]:
        """Get proxy count by country."""
        return self.pool.get_country_breakdown()
