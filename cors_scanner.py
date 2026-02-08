"""
CORS Misconfiguration Scanner v1.0

Detects:
1. Arbitrary origin reflection (Access-Control-Allow-Origin mirrors attacker domain)
2. Null origin allowed
3. Wildcard with credentials
4. Pre-flight misconfiguration
5. Subdomain trust abuse
6. Regex bypass (e.g. evil-target.com, targetevil.com)

Integrates with: main_v3 pipeline
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
from loguru import logger


@dataclass
class CORSResult:
    url: str
    vulnerable: bool = False
    cors_type: str = ""           # origin_reflect, null_origin, wildcard_creds, subdomain_trust, regex_bypass
    evidence: str = ""
    payload_origin: str = ""
    acao_header: str = ""         # Access-Control-Allow-Origin value
    acac_header: str = ""         # Access-Control-Allow-Credentials value
    confidence: float = 0.0
    severity: str = "high"


class CORSScanner:
    """CORS misconfiguration detection engine."""

    def __init__(self, config=None):
        self.timeout = 10

    async def scan(
        self, url: str, session: aiohttp.ClientSession, waf_name: str = None,
    ) -> List[CORSResult]:
        """
        Test URL for CORS misconfigurations.
        
        Sends requests with various Origin headers and analyzes
        Access-Control-Allow-Origin / Allow-Credentials responses.
        """
        results = []
        parsed = urlparse(url)
        target_domain = parsed.netloc

        # Generate test origins
        test_origins = self._generate_test_origins(target_domain, parsed.scheme)

        for origin, test_type in test_origins:
            try:
                headers = {"Origin": origin}
                async with session.get(url, headers=headers, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout),
                                      allow_redirects=True) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    result = self._analyze_cors(url, origin, test_type, acao, acac, target_domain)
                    if result:
                        results.append(result)

            except Exception as e:
                logger.debug(f"[CORS] Error testing {origin}: {e}")

        # Test preflight
        preflight = await self._test_preflight(url, session, target_domain)
        if preflight:
            results.append(preflight)

        if results:
            logger.info(f"[CORS] Found {len(results)} CORS issues on {url[:60]}")

        return results

    def _generate_test_origins(self, domain: str, scheme: str) -> List[tuple]:
        """Generate origins to test CORS behavior."""
        base = domain.split(':')[0]  # Strip port
        parts = base.split('.')
        
        origins = [
            (f"{scheme}://evil.com", "origin_reflect"),
            (f"{scheme}://attacker.com", "origin_reflect"),
            ("null", "null_origin"),
            (f"{scheme}://evil-{base}", "regex_bypass"),
            (f"{scheme}://{base}.evil.com", "regex_bypass"),
        ]
        
        # Subdomain trust
        if len(parts) >= 2:
            root = '.'.join(parts[-2:])
            origins.append((f"{scheme}://evil.{root}", "subdomain_trust"))
            origins.append((f"{scheme}://test.{root}", "subdomain_trust"))

        return origins

    def _analyze_cors(
        self, url: str, origin: str, test_type: str,
        acao: str, acac: str, target_domain: str,
    ) -> Optional[CORSResult]:
        """Analyze CORS response headers."""

        if not acao:
            return None

        # Arbitrary origin reflection
        if acao == origin and origin not in ("null",) and target_domain not in origin:
            return CORSResult(
                url=url,
                vulnerable=True,
                cors_type="origin_reflect",
                evidence=f"Server reflects arbitrary Origin in ACAO",
                payload_origin=origin,
                acao_header=acao,
                acac_header=acac,
                confidence=0.95 if acac.lower() == "true" else 0.80,
                severity="critical" if acac.lower() == "true" else "high",
            )

        # Null origin
        if acao == "null" and origin == "null":
            return CORSResult(
                url=url,
                vulnerable=True,
                cors_type="null_origin",
                evidence="Server allows null origin",
                payload_origin="null",
                acao_header=acao,
                acac_header=acac,
                confidence=0.90 if acac.lower() == "true" else 0.70,
                severity="high" if acac.lower() == "true" else "medium",
            )

        # Wildcard with credentials
        if acao == "*" and acac.lower() == "true":
            return CORSResult(
                url=url,
                vulnerable=True,
                cors_type="wildcard_creds",
                evidence="Wildcard ACAO with credentials allowed",
                payload_origin=origin,
                acao_header=acao,
                acac_header=acac,
                confidence=0.95,
                severity="critical",
            )

        # Regex bypass — origin accepted but shouldn't be
        if test_type == "regex_bypass" and acao == origin:
            return CORSResult(
                url=url,
                vulnerable=True,
                cors_type="regex_bypass",
                evidence=f"Loose regex allows bypass origin: {origin}",
                payload_origin=origin,
                acao_header=acao,
                acac_header=acac,
                confidence=0.85,
                severity="high",
            )

        # Subdomain trust
        if test_type == "subdomain_trust" and acao == origin:
            return CORSResult(
                url=url,
                vulnerable=True,
                cors_type="subdomain_trust",
                evidence=f"Trusts arbitrary subdomain: {origin}",
                payload_origin=origin,
                acao_header=acao,
                acac_header=acac,
                confidence=0.80,
                severity="medium",
            )

        return None

    async def _test_preflight(
        self, url: str, session: aiohttp.ClientSession, target_domain: str,
    ) -> Optional[CORSResult]:
        """Test OPTIONS preflight for misconfig."""
        try:
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
            }
            async with session.options(url, headers=headers, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                acah = resp.headers.get("Access-Control-Allow-Headers", "")

                if acao == "https://evil.com" and ("PUT" in acam or "DELETE" in acam):
                    return CORSResult(
                        url=url,
                        vulnerable=True,
                        cors_type="preflight_misconfig",
                        evidence=f"Preflight allows dangerous methods from evil origin. Methods: {acam}",
                        payload_origin="https://evil.com",
                        acao_header=acao,
                        confidence=0.90,
                        severity="high",
                    )
        except Exception:
            pass
        return None
