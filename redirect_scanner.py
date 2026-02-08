"""
Open Redirect Scanner v1.0

Detects:
1. Parameter-based redirects (url=, redirect=, next=, etc.)
2. Header injection redirects
3. JavaScript-based redirects
4. Protocol-relative redirects (//evil.com)
5. Data URI redirects
6. Encoding bypass (double encode, unicode, etc.)

Integrates with: main_v3 pipeline
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from loguru import logger


@dataclass
class RedirectResult:
    url: str
    parameter: str
    vulnerable: bool = False
    redirect_type: str = ""       # param_redirect, meta_redirect, js_redirect
    payload_used: str = ""
    final_url: str = ""           # Where it actually redirects
    confidence: float = 0.0
    severity: str = "medium"


# Redirect payloads
REDIRECT_PAYLOADS = [
    # Direct external URL
    ("https://evil.com/", "direct"),
    ("http://evil.com/", "direct"),
    # Protocol-relative
    ("//evil.com/", "protocol_relative"),
    # Backslash trick
    ("\\\\evil.com/", "backslash"),
    ("/\\evil.com/", "backslash"),
    # URL encoding bypass
    ("https:%2F%2Fevil.com/", "encoded"),
    ("https://evil%2Ecom/", "encoded"),
    ("%2F%2Fevil.com/", "double_encoded"),
    # JavaScript redirect
    ("javascript:alert(document.domain)//", "javascript"),
    # Domain confusion 
    ("https://evil.com@target.com/", "at_sign"),
    ("https://evil.com%23@target.com/", "at_sign_encoded"),
    # Null byte
    ("https://evil.com/%00/", "null_byte"),
    # Tab/newline injection
    ("https://evil.com/%09/", "whitespace"),
    ("https://evil.com/%0d%0a/", "crlf_redirect"),
    # Data URI
    ("data:text/html,<script>alert(1)</script>", "data_uri"),
]


class OpenRedirectScanner:
    """Open Redirect detection engine."""

    def __init__(self, config=None):
        self.timeout = 10
        self.max_params = 6

    async def scan(
        self, url: str, session: aiohttp.ClientSession, waf_name: str = None,
    ) -> List[RedirectResult]:
        """Test URL parameters for open redirect vulnerabilities."""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return results

        param_names = self._prioritize_params(list(params.keys()))[:self.max_params]
        logger.info(f"[REDIRECT] Testing {len(param_names)} params on {url[:60]}")

        for pname in param_names:
            for payload, ptype in REDIRECT_PAYLOADS:
                result = await self._test_redirect(url, pname, params, payload, ptype, session)
                if result:
                    results.append(result)
                    break  # Found vuln for this param, move on

        if results:
            logger.info(f"[REDIRECT] Found {len(results)} open redirects on {url[:60]}")

        return results

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Sort params by redirect likelihood."""
        HIGH = {
            'url', 'redirect', 'redir', 'next', 'return', 'returnurl', 'return_url',
            'dest', 'destination', 'continue', 'forward', 'go', 'goto', 'target',
            'out', 'link', 'to', 'uri', 'path', 'callback', 'fallback',
            'checkout_url', 'login_url', 'logout', 'image_url', 'redirect_uri',
            'redirect_url', 'success', 'error', 'data', 'reference', 'site',
        }

        def score(p):
            return 0 if p.lower() in HIGH else 1

        return sorted(params, key=score)

    async def _test_redirect(
        self, url: str, param: str, params: Dict,
        payload: str, ptype: str, session: aiohttp.ClientSession,
    ) -> Optional[RedirectResult]:
        """Test a single redirect payload."""
        try:
            test_url = self._inject_param(url, param, params, payload)
            async with session.get(test_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout),
                                  allow_redirects=False,
                                  max_redirects=0) as resp:
                
                location = resp.headers.get("Location", "")
                status = resp.status

                # 3xx redirect to external domain
                if status in (301, 302, 303, 307, 308) and location:
                    loc_parsed = urlparse(location)
                    orig_parsed = urlparse(url)

                    if loc_parsed.netloc and loc_parsed.netloc != orig_parsed.netloc:
                        if "evil.com" in location or loc_parsed.netloc != orig_parsed.netloc:
                            return RedirectResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                redirect_type=f"param_{ptype}",
                                payload_used=payload,
                                final_url=location,
                                confidence=0.95,
                                severity="medium",
                            )

                # Check for meta refresh or JS redirect in body
                if status == 200:
                    body = await resp.text(errors='replace')
                    
                    # Meta refresh
                    meta_match = re.search(
                        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'].*?url=([^"\']+)',
                        body, re.I
                    )
                    if meta_match and "evil.com" in meta_match.group(1):
                        return RedirectResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            redirect_type="meta_redirect",
                            payload_used=payload,
                            final_url=meta_match.group(1),
                            confidence=0.85,
                            severity="medium",
                        )

                    # JS redirect
                    js_redirect = re.search(
                        r'(?:window\.location|document\.location|location\.href)\s*=\s*["\']([^"\']+evil\.com[^"\']*)',
                        body, re.I,
                    )
                    if js_redirect:
                        return RedirectResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            redirect_type="js_redirect",
                            payload_used=payload,
                            final_url=js_redirect.group(1),
                            confidence=0.80,
                            severity="medium",
                        )

        except Exception as e:
            logger.debug(f"[REDIRECT] Test error: {e}")

        return None

    def _inject_param(self, url: str, param: str, params: Dict, value: str) -> str:
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
