"""
Subdomain Enumeration Module for MadyDorker

Discovers subdomains via:
1. crt.sh (Certificate Transparency logs)
2. DNS brute-force (common prefixes)
3. Common subdomain wordlist

Feeds discovered subdomains back as new URLs for the pipeline.
"""

import asyncio
import aiohttp
import socket
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict
from urllib.parse import urlparse
from loguru import logger


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    base_domain: str
    subdomains: List[str] = field(default_factory=list)
    live_subdomains: List[str] = field(default_factory=list)
    total_found: int = 0
    total_live: int = 0
    sources: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


# Common subdomain prefixes (100 most common)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "blog", "forum", "api", "dev", "staging", "stage", "test",
    "testing", "beta", "admin", "portal", "m", "mobile", "app", "store",
    "shop", "pay", "payment", "payments", "checkout", "cart", "billing",
    "dashboard", "panel", "cpanel", "whm", "plesk", "webmin",
    "secure", "ssl", "vpn", "remote", "gateway", "gw",
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "redis",
    "elastic", "elasticsearch", "kibana", "grafana",
    "cdn", "static", "assets", "media", "images", "img", "files", "upload",
    "docs", "doc", "help", "support", "wiki", "kb", "status",
    "auth", "login", "sso", "oauth", "accounts", "account", "id",
    "v1", "v2", "v3", "api-v1", "api-v2", "rest", "graphql",
    "ws", "wss", "socket", "realtime", "events",
    "jenkins", "ci", "cd", "deploy", "build", "git", "gitlab", "github",
    "jira", "confluence", "slack", "teams",
    "internal", "intranet", "corp", "private", "office",
    "backup", "bk", "old", "legacy", "archive", "temp",
    "sandbox", "demo", "preview", "uat", "qa", "preprod", "pre-prod",
    "prod", "production", "live",
    "crm", "erp", "hr", "finance",
    "search", "analytics", "tracking", "monitor", "logs",
    "smtp2", "imap", "pop3", "mx", "autodiscover", "exchange",
    "s3", "aws", "cloud", "azure", "gcp",
]


class SubdomainEnumerator:
    """Lightweight subdomain discovery for the pipeline."""
    
    def __init__(self, timeout: float = 5.0, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._sem = asyncio.Semaphore(max_concurrent)
    
    async def enumerate(self, domain: str, check_live: bool = True) -> SubdomainResult:
        """Enumerate subdomains for a domain.
        
        Args:
            domain: Base domain (e.g., example.com)
            check_live: Whether to check if subdomains resolve
            
        Returns:
            SubdomainResult with all discovered subdomains
        """
        result = SubdomainResult(base_domain=domain)
        all_subs: Set[str] = set()
        
        # Strip www. and extract base domain
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Run discovery sources in parallel
        crt_task = self._crt_sh(domain)
        dns_task = self._dns_brute(domain)
        
        try:
            crt_subs, dns_subs = await asyncio.gather(
                crt_task, dns_task, return_exceptions=True
            )
            
            if isinstance(crt_subs, set):
                all_subs.update(crt_subs)
                result.sources["crt.sh"] = len(crt_subs)
            elif isinstance(crt_subs, Exception):
                logger.debug(f"crt.sh failed for {domain}: {crt_subs}")
            
            if isinstance(dns_subs, set):
                all_subs.update(dns_subs)
                result.sources["dns_brute"] = len(dns_subs)
            elif isinstance(dns_subs, Exception):
                logger.debug(f"DNS brute failed for {domain}: {dns_subs}")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Subdomain enumeration failed for {domain}: {e}")
        
        result.subdomains = sorted(all_subs)
        result.total_found = len(all_subs)
        
        # Check which subdomains actually resolve
        if check_live and all_subs:
            live = await self._check_live(all_subs)
            result.live_subdomains = sorted(live)
            result.total_live = len(live)
        
        logger.info(
            f"[SubEnum] {domain}: {result.total_found} found, "
            f"{result.total_live} live ({result.sources})"
        )
        return result
    
    async def _crt_sh(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs."""
        subs = set()
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for line in name.split("\n"):
                                line = line.strip().lower()
                                if line.endswith(f".{domain}") or line == domain:
                                    # Skip wildcards
                                    if not line.startswith("*"):
                                        subs.add(line)
        except Exception as e:
            logger.debug(f"crt.sh query failed: {e}")
        return subs
    
    async def _dns_brute(self, domain: str) -> Set[str]:
        """Brute-force common subdomain prefixes via DNS resolution."""
        subs = set()
        
        async def _check_one(prefix: str):
            subdomain = f"{prefix}.{domain}"
            async with self._sem:
                try:
                    loop = asyncio.get_running_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, subdomain),
                        timeout=self.timeout,
                    )
                    subs.add(subdomain)
                except (socket.gaierror, asyncio.TimeoutError, OSError):
                    pass
        
        tasks = [_check_one(prefix) for prefix in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks, return_exceptions=True)
        return subs
    
    async def _check_live(self, subdomains: Set[str]) -> Set[str]:
        """Check which subdomains have live HTTP(s) services."""
        live = set()
        
        async def _probe(sub: str):
            async with self._sem:
                for scheme in ("https", "http"):
                    try:
                        timeout = aiohttp.ClientTimeout(total=self.timeout)
                        async with aiohttp.ClientSession(timeout=timeout) as session:
                            async with session.head(
                                f"{scheme}://{sub}/",
                                allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0"},
                            ) as resp:
                                if resp.status < 500:
                                    live.add(sub)
                                    return
                    except Exception:
                        continue
        
        tasks = [_probe(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        return live


# Convenience wrapper
async def enumerate_subdomains(
    domain: str,
    check_live: bool = True,
    timeout: float = 5.0,
) -> SubdomainResult:
    """Enumerate subdomains for a domain."""
    enumerator = SubdomainEnumerator(timeout=timeout)
    return await enumerator.enumerate(domain, check_live=check_live)
