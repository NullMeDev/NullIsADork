"""
Cookie Hunter — Active B3 & Payment Gateway Cookie Scanner

Actively probes URLs for:
  - B3 distributed tracing cookies/headers (x-b3-traceid, x-b3-spanid, etc.)
  - Payment gateway cookies (Stripe, Braintree, PayPal, Square, Adyen, Shopify, WooCommerce)
  - Session cookies that indicate commerce/checkout flows
  - Cart/basket tokens suggesting e-commerce backends

Reports every find to Telegram with full cookie details.

v3.5 — Phase 3
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from loguru import logger


# ====================== B3 TRACING PATTERNS ======================

B3_COOKIE_NAMES: Set[str] = {
    "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
    "x-b3-sampled", "x-b3-flags", "b3",
}

B3_HEADER_NAMES: Set[str] = {
    "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
    "x-b3-sampled", "x-b3-flags", "b3",
    # Extended Zipkin/Jaeger headers
    "x-request-id", "x-trace-id", "traceparent", "tracestate",
    "uber-trace-id",  # Jaeger
    "x-cloud-trace-context",  # Google Cloud
    "x-amzn-trace-id",  # AWS X-Ray
    "x-datadog-trace-id", "x-datadog-parent-id",  # Datadog
}


# ====================== GATEWAY COOKIE PATTERNS ======================

@dataclass
class GatewayCookiePattern:
    """Defines a pattern for identifying payment gateway cookies."""
    gateway: str          # Gateway name (stripe, braintree, paypal, etc.)
    cookie_regex: str     # Regex to match cookie name
    value_regex: str = "" # Optional regex to validate cookie value
    description: str = "" # Human-readable description
    severity: str = "high"  # high, medium, low


GATEWAY_COOKIE_PATTERNS: List[GatewayCookiePattern] = [
    # ---- Stripe ----
    GatewayCookiePattern("stripe", r"__stripe_mid", "", "Stripe merchant ID cookie", "high"),
    GatewayCookiePattern("stripe", r"__stripe_sid", "", "Stripe session ID cookie", "high"),
    GatewayCookiePattern("stripe", r"stripe\.csrf", "", "Stripe CSRF token", "high"),
    GatewayCookiePattern("stripe", r"checkout-.*session", "", "Stripe checkout session", "high"),
    GatewayCookiePattern("stripe", r"stripe_checkout_session", "", "Stripe Checkout session cookie", "high"),
    GatewayCookiePattern("stripe", r"__stripe_orig", "", "Stripe origin tracking", "medium"),
    GatewayCookiePattern("stripe", r"private_machine_identifier", "", "Stripe device fingerprint", "medium"),

    # ---- Braintree / B3 ----
    GatewayCookiePattern("braintree", r"bt_bb_.*", "", "Braintree bot detection cookie", "high"),
    GatewayCookiePattern("braintree", r"braintree.*", "", "Braintree gateway cookie", "high"),
    GatewayCookiePattern("braintree", r"__bt", "", "Braintree tracking", "high"),
    GatewayCookiePattern("braintree", r"bt_.*token", "", "Braintree token cookie", "high"),

    # ---- PayPal ----
    GatewayCookiePattern("paypal", r"paypal.*", "", "PayPal cookie", "high"),
    GatewayCookiePattern("paypal", r"pp_.*", r".", "PayPal prefixed cookie", "medium"),
    GatewayCookiePattern("paypal", r"X-PP-.*", "", "PayPal header cookie", "high"),
    GatewayCookiePattern("paypal", r"enforce_policy", "", "PayPal policy cookie", "medium"),
    GatewayCookiePattern("paypal", r"tsrce", "", "PayPal source tracking", "medium"),
    GatewayCookiePattern("paypal", r"PYPF", "", "PayPal session", "high"),

    # ---- Square ----
    GatewayCookiePattern("square", r"sq_.*", "", "Square payment cookie", "high"),
    GatewayCookiePattern("square", r"squareup.*", "", "Square platform cookie", "high"),
    GatewayCookiePattern("square", r"square_.*session", "", "Square session cookie", "high"),

    # ---- Adyen ----
    GatewayCookiePattern("adyen", r"adyen.*", "", "Adyen payment cookie", "high"),
    GatewayCookiePattern("adyen", r"__adyen.*", "", "Adyen tracking cookie", "high"),

    # ---- Shopify Payments ----
    GatewayCookiePattern("shopify", r"_shopify_s", "", "Shopify session", "medium"),
    GatewayCookiePattern("shopify", r"_shopify_y", "", "Shopify persistent ID", "medium"),
    GatewayCookiePattern("shopify", r"cart", r".", "Shopify cart token", "medium"),
    GatewayCookiePattern("shopify", r"checkout_token", "", "Shopify checkout token", "high"),
    GatewayCookiePattern("shopify", r"_shopify_checkout.*", "", "Shopify checkout flow", "high"),
    GatewayCookiePattern("shopify", r"shopify_pay.*", "", "Shopify Pay session", "high"),

    # ---- WooCommerce ----
    GatewayCookiePattern("woocommerce", r"wp_woocommerce_session_.*", "", "WooCommerce session", "high"),
    GatewayCookiePattern("woocommerce", r"woocommerce_cart_hash", "", "WooCommerce cart hash", "medium"),
    GatewayCookiePattern("woocommerce", r"woocommerce_items_in_cart", "", "WooCommerce cart items", "medium"),
    GatewayCookiePattern("woocommerce", r"wc_cart_.*", "", "WooCommerce cart cookie", "medium"),

    # ---- Authorize.net ----
    GatewayCookiePattern("authorize_net", r"authorizenet.*", "", "Authorize.net cookie", "high"),
    GatewayCookiePattern("authorize_net", r"anet_.*", "", "Authorize.net tracking", "high"),

    # ---- 2Checkout / Verifone ----
    GatewayCookiePattern("2checkout", r"2co.*", "", "2Checkout cookie", "high"),
    GatewayCookiePattern("2checkout", r"TWOCHECKOUT.*", "", "2Checkout session", "high"),

    # ---- Klarna ----
    GatewayCookiePattern("klarna", r"klarna.*", "", "Klarna payment cookie", "high"),
    GatewayCookiePattern("klarna", r"__klarna.*", "", "Klarna session cookie", "high"),

    # ---- Razorpay ----
    GatewayCookiePattern("razorpay", r"rzp_.*", "", "Razorpay cookie", "high"),
    GatewayCookiePattern("razorpay", r"razorpay.*", "", "Razorpay session", "high"),

    # ---- Worldpay ----
    GatewayCookiePattern("worldpay", r"worldpay.*", "", "Worldpay cookie", "high"),

    # ---- General e-commerce / checkout signals ----
    GatewayCookiePattern("commerce", r"payment_session.*", "", "Payment session token", "high"),
    GatewayCookiePattern("commerce", r"checkout_session.*", "", "Checkout session token", "high"),
    GatewayCookiePattern("commerce", r"order_token.*", "", "Order token", "medium"),
    GatewayCookiePattern("commerce", r"cart_token.*", "", "Cart token", "medium"),
    GatewayCookiePattern("commerce", r"billing_.*", "", "Billing cookie", "medium"),
]

# Pre-compile regexes
_COMPILED_PATTERNS: List[Tuple[GatewayCookiePattern, re.Pattern]] = [
    (p, re.compile(p.cookie_regex, re.IGNORECASE))
    for p in GATEWAY_COOKIE_PATTERNS
]

# ====================== GATEWAY DETECTION IN HTML ======================

GATEWAY_HTML_SIGNATURES: Dict[str, List[str]] = {
    "stripe": [
        "js.stripe.com", "Stripe(", "stripe.redirectToCheckout",
        "stripe-checkout", "data-stripe", "pk_live_", "pk_test_",
    ],
    "braintree": [
        "js.braintreegateway.com", "braintree.setup", "braintree-web",
        "braintree.client", "data-braintree",
    ],
    "paypal": [
        "paypal.com/sdk", "paypal-checkout", "paypal.Buttons",
        "paypalobjects.com", "paypal-button",
    ],
    "square": [
        "squareup.com/js", "Square.payments", "sq-payment",
        "square-payment-form",
    ],
    "adyen": [
        "checkoutshopper-live.adyen.com", "adyen.encrypt",
        "adyen-checkout", "AdyenCheckout",
    ],
    "shopify": [
        "cdn.shopify.com", "Shopify.checkout", "shopify-buy",
        "shopify_pay", "shop.app",
    ],
    "woocommerce": [
        "woocommerce", "wc-checkout", "wc-cart", "wc_add_to_cart",
        "is-type-simple", "add_to_cart",
    ],
    "klarna": [
        "klarna.com", "klarna-payments", "KlarnaPayments",
        "klarna-checkout",
    ],
    "razorpay": [
        "checkout.razorpay.com", "Razorpay(", "razorpay-payment",
    ],
}


# ====================== CHECKOUT PAGE PATHS ======================

CHECKOUT_PATHS: List[str] = [
    "/checkout", "/cart", "/basket", "/payment",
    "/pay", "/billing", "/order", "/purchase",
    "/shop/checkout", "/store/checkout",
    "/wp-json/wc/v3/", "/wp-json/wc/v2/",  # WooCommerce REST
    "/.well-known/apple-pay",  # Apple Pay
]


# ====================== DATA CLASSES ======================

@dataclass
class CookieFind:
    """A single cookie finding."""
    url: str
    domain: str
    cookie_name: str
    cookie_value: str
    category: str        # "b3", "gateway", "session", "commerce"
    gateway: str = ""    # Gateway name if applicable
    severity: str = "medium"
    source: str = ""     # "header", "set-cookie", "js", "probe"
    description: str = ""
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def display_value(self) -> str:
        """Truncated display value for Telegram."""
        v = self.cookie_value
        if len(v) > 80:
            return v[:40] + "..." + v[-20:]
        return v


@dataclass
class HuntResult:
    """Result of hunting a single URL."""
    url: str
    domain: str
    b3_finds: List[CookieFind] = field(default_factory=list)
    gateway_finds: List[CookieFind] = field(default_factory=list)
    commerce_finds: List[CookieFind] = field(default_factory=list)
    detected_gateways: List[str] = field(default_factory=list)
    checkout_pages: List[str] = field(default_factory=list)
    probing_time: float = 0.0
    error: str = ""

    @property
    def total_finds(self) -> int:
        return len(self.b3_finds) + len(self.gateway_finds) + len(self.commerce_finds)

    @property
    def has_b3(self) -> bool:
        return len(self.b3_finds) > 0

    @property
    def has_gateway(self) -> bool:
        return len(self.gateway_finds) > 0


@dataclass
class HunterStats:
    """Cumulative stats for the cookie hunter."""
    urls_probed: int = 0
    b3_total: int = 0
    gateway_total: int = 0
    commerce_total: int = 0
    gateways_by_type: Dict[str, int] = field(default_factory=dict)
    domains_with_b3: Set[str] = field(default_factory=set)
    domains_with_gateway: Set[str] = field(default_factory=set)
    errors: int = 0
    total_probe_time: float = 0.0


# ====================== COOKIE HUNTER ======================

class CookieHunter:
    """
    Actively hunts for B3 distributed tracing cookies and payment gateway cookies.
    
    Strategy:
    1. Fetch the main URL — collect all cookies + response headers
    2. Scan HTML for gateway signatures (Stripe JS, Braintree SDK, etc.)
    3. Probe discovered checkout/payment pages for additional cookies
    4. Match all cookies against B3 and gateway patterns
    5. Report each find to Telegram immediately
    """

    def __init__(self, config=None, reporter=None, db=None, proxy_manager=None):
        """
        Args:
            config: DorkerConfig instance
            reporter: TelegramReporter for posting finds
            db: DorkerDB for persistence
            proxy_manager: ProxyManager for proxy rotation
        """
        self.config = config
        self.reporter = reporter
        self.db = db
        self.proxy_manager = proxy_manager
        self.stats = HunterStats()
        
        # Rate limiting
        self._last_report_time = 0
        self._min_report_interval = 0.5  # seconds between Telegram messages
        
        # Dedup — don't report same cookie@domain twice
        self._reported: Set[str] = set()
        
        logger.info("CookieHunter initialized — hunting B3 + gateway cookies")

    # ==================== MAIN HUNT ====================

    async def hunt_url(self, url: str, session: aiohttp.ClientSession = None) -> HuntResult:
        """Hunt a single URL for B3 and gateway cookies.
        
        Args:
            url: Target URL to probe
            session: Optional shared aiohttp session
            
        Returns:
            HuntResult with all findings
        """
        domain = urlparse(url).netloc
        result = HuntResult(url=url, domain=domain)
        start = time.monotonic()
        
        own_session = False
        if session is None:
            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            own_session = True
        
        try:
            # Phase 1: Fetch main page, collect cookies + headers
            cookies, headers, html_body = await self._fetch_with_cookies(url, session)
            
            # Phase 2: Classify cookies
            for name, value in cookies.items():
                self._classify_cookie(url, domain, name, value, "set-cookie", result)
            
            # Phase 3: Check response headers for B3
            for hdr_name, hdr_value in headers.items():
                hdr_lower = hdr_name.lower()
                if hdr_lower in B3_HEADER_NAMES:
                    find = CookieFind(
                        url=url, domain=domain,
                        cookie_name=hdr_name, cookie_value=hdr_value,
                        category="b3", severity="high",
                        source="header",
                        description=f"B3 tracing header: {hdr_name}",
                    )
                    result.b3_finds.append(find)
            
            # Phase 4: Scan HTML for gateway signatures
            if html_body:
                detected = self._detect_gateways_in_html(html_body)
                result.detected_gateways = detected
                
                # Phase 5: Discover checkout/payment pages from links
                checkout_links = self._extract_checkout_links(url, html_body)
                result.checkout_pages = checkout_links
            
            # Phase 6: Probe checkout pages for more cookies
            if result.detected_gateways or result.checkout_pages:
                probe_urls = result.checkout_pages[:5]  # Max 5 probes
                
                # Also probe common checkout paths if gateways detected
                if result.detected_gateways:
                    base = f"{urlparse(url).scheme}://{domain}"
                    for path in CHECKOUT_PATHS[:6]:
                        probe_url = urljoin(base, path)
                        if probe_url not in probe_urls:
                            probe_urls.append(probe_url)
                
                probe_urls = probe_urls[:8]  # Hard cap at 8 probes
                
                for probe_url in probe_urls:
                    try:
                        p_cookies, p_headers, _ = await self._fetch_with_cookies(
                            probe_url, session
                        )
                        for name, value in p_cookies.items():
                            self._classify_cookie(probe_url, domain, name, value, "probe", result)
                        for hdr_name, hdr_value in p_headers.items():
                            if hdr_name.lower() in B3_HEADER_NAMES:
                                find = CookieFind(
                                    url=probe_url, domain=domain,
                                    cookie_name=hdr_name, cookie_value=hdr_value,
                                    category="b3", severity="high",
                                    source="probe-header",
                                    description=f"B3 header from checkout probe: {hdr_name}",
                                )
                                result.b3_finds.append(find)
                    except Exception as e:
                        logger.debug(f"Probe failed {probe_url}: {e}")
            
            # Update stats
            self.stats.urls_probed += 1
            self.stats.b3_total += len(result.b3_finds)
            self.stats.gateway_total += len(result.gateway_finds)
            self.stats.commerce_total += len(result.commerce_finds)
            
            if result.has_b3:
                self.stats.domains_with_b3.add(domain)
            if result.has_gateway:
                self.stats.domains_with_gateway.add(domain)
                for gf in result.gateway_finds:
                    self.stats.gateways_by_type[gf.gateway] = \
                        self.stats.gateways_by_type.get(gf.gateway, 0) + 1
            
        except asyncio.TimeoutError:
            result.error = "timeout"
            self.stats.errors += 1
            logger.debug(f"CookieHunter timeout: {url}")
        except aiohttp.ClientError as e:
            result.error = str(e)
            self.stats.errors += 1
            logger.debug(f"CookieHunter connection error: {url}: {e}")
        except Exception as e:
            result.error = str(e)
            self.stats.errors += 1
            logger.error(f"CookieHunter error: {url}: {e}")
        finally:
            result.probing_time = time.monotonic() - start
            self.stats.total_probe_time += result.probing_time
            if own_session:
                await session.close()
        
        return result

    async def hunt_and_report(self, url: str, session: aiohttp.ClientSession = None) -> HuntResult:
        """Hunt a URL and immediately report all findings to Telegram.
        
        This is the main entry point for the pipeline integration.
        """
        result = await self.hunt_url(url, session)
        
        # Report & persist each finding
        await self._report_findings(result)
        
        # Log summary
        if result.total_finds > 0:
            logger.info(
                f"🍪 CookieHunter [{result.domain}]: "
                f"{len(result.b3_finds)} B3, "
                f"{len(result.gateway_finds)} gateway, "
                f"{len(result.commerce_finds)} commerce cookies"
            )
            if result.detected_gateways:
                logger.info(f"  Gateways detected in HTML: {', '.join(result.detected_gateways)}")
        
        return result

    # ==================== FETCH & EXTRACT ====================

    async def _fetch_with_cookies(
        self, url: str, session: aiohttp.ClientSession
    ) -> Tuple[Dict[str, str], Dict[str, str], str]:
        """Fetch a URL and return (cookies, headers, html_body).
        
        Uses proxy if proxy_manager is available.
        """
        proxy_url = None
        proxy_info = None
        
        if self.proxy_manager:
            domain = urlparse(url).netloc
            proxy_info = await self.proxy_manager.get_proxy(domain=domain)
            if proxy_info:
                proxy_url = proxy_info.url
        
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        }
        
        cookies_found: Dict[str, str] = {}
        resp_headers: Dict[str, str] = {}
        html_body: str = ""
        
        async with session.get(
            url, headers=headers, proxy=proxy_url,
            allow_redirects=True, max_redirects=5,
        ) as resp:
            # Collect all response headers
            for key, value in resp.headers.items():
                resp_headers[key] = value
            
            # Extract cookies from Set-Cookie headers
            for cookie_header in resp.headers.getall("Set-Cookie", []):
                parts = cookie_header.split(";")[0]  # name=value
                if "=" in parts:
                    name, _, value = parts.partition("=")
                    cookies_found[name.strip()] = value.strip()
            
            # Also get cookies from the cookie jar
            for cookie in session.cookie_jar:
                cookies_found[cookie.key] = cookie.value
            
            # Read HTML body (limited to 200KB)
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" in content_type or "application/xhtml" in content_type:
                try:
                    html_body = await resp.text(errors="replace")
                    if len(html_body) > 200_000:
                        html_body = html_body[:200_000]
                except Exception:
                    html_body = ""
            
            # Report proxy success
            if proxy_info and self.proxy_manager:
                latency = resp.headers.get("X-Response-Time", None)
                self.proxy_manager.report_success(proxy_info, float(latency) if latency else None)
        
        return cookies_found, resp_headers, html_body

    # ==================== CLASSIFICATION ====================

    def _classify_cookie(
        self, url: str, domain: str, name: str, value: str,
        source: str, result: HuntResult
    ):
        """Classify a single cookie as B3, gateway, or commerce."""
        name_lower = name.lower().strip()
        
        # Dedup key
        dedup_key = f"{domain}:{name_lower}"
        if dedup_key in self._reported:
            return
        
        # Check B3 first
        if name_lower in B3_COOKIE_NAMES:
            find = CookieFind(
                url=url, domain=domain,
                cookie_name=name, cookie_value=value,
                category="b3", severity="high",
                source=source,
                description=f"B3 tracing cookie: {name}",
            )
            result.b3_finds.append(find)
            self._reported.add(dedup_key)
            return
        
        # Check gateway patterns
        for pattern, compiled in _COMPILED_PATTERNS:
            if compiled.fullmatch(name_lower) or compiled.search(name_lower):
                # Optional value validation
                if pattern.value_regex:
                    if not re.search(pattern.value_regex, value, re.IGNORECASE):
                        continue
                
                find = CookieFind(
                    url=url, domain=domain,
                    cookie_name=name, cookie_value=value,
                    category="gateway", gateway=pattern.gateway,
                    severity=pattern.severity,
                    source=source,
                    description=pattern.description or f"{pattern.gateway} cookie",
                )
                result.gateway_finds.append(find)
                self._reported.add(dedup_key)
                return
        
        # Check general commerce signals
        commerce_patterns = [
            (r"cart|basket|bag", "Cart/basket token"),
            (r"checkout|chk_", "Checkout session"),
            (r"payment|pay_|paying", "Payment cookie"),
            (r"order[_-]?(id|token|session)", "Order tracking"),
            (r"billing", "Billing cookie"),
            (r"transaction|txn", "Transaction cookie"),
        ]
        for pat, desc in commerce_patterns:
            if re.search(pat, name_lower):
                find = CookieFind(
                    url=url, domain=domain,
                    cookie_name=name, cookie_value=value,
                    category="commerce", severity="medium",
                    source=source,
                    description=desc,
                )
                result.commerce_finds.append(find)
                self._reported.add(dedup_key)
                return

    # ==================== HTML SCANNING ====================

    def _detect_gateways_in_html(self, html: str) -> List[str]:
        """Detect payment gateway signatures in HTML source."""
        detected = []
        html_lower = html.lower()
        
        for gateway, signatures in GATEWAY_HTML_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in html_lower:
                    if gateway not in detected:
                        detected.append(gateway)
                    break
        
        return detected

    def _extract_checkout_links(self, base_url: str, html: str) -> List[str]:
        """Extract checkout/payment page links from HTML."""
        links = []
        seen = set()
        
        # Find all href links
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1)
            # Check if it looks like a checkout/payment page
            href_lower = href.lower()
            if any(kw in href_lower for kw in [
                "checkout", "cart", "basket", "payment", "pay",
                "billing", "order", "purchase", "shop/cart",
            ]):
                full_url = urljoin(base_url, href)
                if full_url not in seen:
                    seen.add(full_url)
                    links.append(full_url)
        
        return links[:10]  # Cap at 10

    # ==================== REPORTING ====================

    async def _report_findings(self, result: HuntResult):
        """Report all findings to Telegram and persist to DB."""
        all_finds = result.b3_finds + result.gateway_finds + result.commerce_finds
        
        if not all_finds:
            return
        
        # Persist to DB
        for find in all_finds:
            self._persist_find(find)
        
        # Telegram reporting
        if not self.reporter:
            return
        
        # B3 finds — individual report for each
        for find in result.b3_finds:
            await self._rate_limit()
            await self._report_b3_find(find)
        
        # Gateway finds — individual report for each
        for find in result.gateway_finds:
            await self._rate_limit()
            await self._report_gateway_find(find)
        
        # Commerce finds — batch report (less spammy)
        if result.commerce_finds:
            await self._rate_limit()
            await self._report_commerce_batch(result.url, result.domain, result.commerce_finds)
        
        # If gateways were detected in HTML, report that too
        if result.detected_gateways:
            await self._rate_limit()
            await self._report_gateway_detection(result)

    async def _report_b3_find(self, find: CookieFind):
        """Report a B3 cookie/header find to Telegram."""
        try:
            import html as html_mod
            text = (
                f"🔵 <b>B3 TRACING FOUND</b> 🔵\n"
                f"\n"
                f"<b>Header/Cookie:</b> <code>{html_mod.escape(find.cookie_name)}</code>\n"
                f"<b>Value:</b> <code>{html_mod.escape(find.display_value)}</code>\n"
                f"<b>Domain:</b> <code>{html_mod.escape(find.domain)}</code>\n"
                f"<b>Source:</b> {html_mod.escape(find.source)}\n"
                f"<b>URL:</b> <code>{html_mod.escape(find.url[:120])}</code>\n"
                f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
                f"\n#b3 #tracing #cookie #{len(self.stats.domains_with_b3)}domains"
            )
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"B3 report failed: {e}")

    async def _report_gateway_find(self, find: CookieFind):
        """Report a gateway cookie find to Telegram."""
        try:
            import html as html_mod
            severity_icon = {"high": "🔥", "medium": "🔑", "low": "📌"}.get(find.severity, "🔑")
            text = (
                f"{severity_icon} <b>GATEWAY COOKIE FOUND</b> {severity_icon}\n"
                f"\n"
                f"<b>Gateway:</b> {html_mod.escape(find.gateway.upper())}\n"
                f"<b>Cookie:</b> <code>{html_mod.escape(find.cookie_name)}</code>\n"
                f"<b>Value:</b> <code>{html_mod.escape(find.display_value)}</code>\n"
                f"<b>Domain:</b> <code>{html_mod.escape(find.domain)}</code>\n"
                f"<b>Source:</b> {html_mod.escape(find.source)}\n"
                f"<b>Description:</b> {html_mod.escape(find.description)}\n"
                f"<b>URL:</b> <code>{html_mod.escape(find.url[:120])}</code>\n"
                f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
                f"\n#{find.gateway} #gateway #cookie #{self.stats.gateway_total}found"
            )
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Gateway cookie report failed: {e}")

    async def _report_commerce_batch(self, url: str, domain: str, finds: List[CookieFind]):
        """Report commerce cookies as a batch."""
        try:
            import html as html_mod
            text = (
                f"🛒 <b>COMMERCE COOKIES</b> 🛒\n"
                f"\n"
                f"<b>Domain:</b> <code>{html_mod.escape(domain)}</code>\n"
                f"<b>Count:</b> {len(finds)} cookies\n"
                f"\n"
            )
            for i, find in enumerate(finds[:15], 1):  # Max 15 in message
                text += (
                    f"<b>#{i}</b> <code>{html_mod.escape(find.cookie_name)}</code>"
                    f" = <code>{html_mod.escape(find.display_value)}</code>\n"
                    f"    [{find.description}]\n"
                )
            
            text += f"\n#commerce #cookies #{self.stats.commerce_total}found"
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Commerce batch report failed: {e}")

    async def _report_gateway_detection(self, result: HuntResult):
        """Report that gateway SDKs were detected in page HTML."""
        try:
            import html as html_mod
            gateways = ", ".join(g.upper() for g in result.detected_gateways)
            text = (
                f"🏦 <b>PAYMENT GATEWAYS DETECTED</b> 🏦\n"
                f"\n"
                f"<b>Gateways:</b> {html_mod.escape(gateways)}\n"
                f"<b>Domain:</b> <code>{html_mod.escape(result.domain)}</code>\n"
                f"<b>URL:</b> <code>{html_mod.escape(result.url[:120])}</code>\n"
            )
            if result.checkout_pages:
                text += f"<b>Checkout pages found:</b> {len(result.checkout_pages)}\n"
                for cp in result.checkout_pages[:5]:
                    text += f"  → <code>{html_mod.escape(cp[:100])}</code>\n"
            
            text += f"\n#gateway #detected #{' #'.join(result.detected_gateways)}"
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Gateway detection report failed: {e}")

    # ==================== PERSISTENCE ====================

    def _persist_find(self, find: CookieFind):
        """Store a cookie find in the database."""
        if not self.db:
            return
        
        try:
            if find.category == "b3":
                self.db.add_b3_cookie(find.url, find.cookie_name, find.cookie_value)
            else:
                self.db.add_cookie(
                    find.url, find.cookie_name, find.cookie_value,
                    cookie_type=f"{find.category}:{find.gateway}" if find.gateway else find.category,
                )
        except Exception as e:
            logger.debug(f"Cookie persist failed: {e}")

    # ==================== UTILITY ====================

    async def _rate_limit(self):
        """Enforce rate limiting between Telegram messages."""
        now = time.monotonic()
        elapsed = now - self._last_report_time
        if elapsed < self._min_report_interval:
            await asyncio.sleep(self._min_report_interval - elapsed)
        self._last_report_time = time.monotonic()

    def get_stats_text(self) -> str:
        """Get formatted stats for /cookies command."""
        lines = [
            "🍪 <b>Cookie Hunter Stats</b> 🍪",
            "",
            f"<b>URLs Probed:</b> {self.stats.urls_probed}",
            f"<b>B3 Cookies Found:</b> {self.stats.b3_total}",
            f"<b>Gateway Cookies Found:</b> {self.stats.gateway_total}",
            f"<b>Commerce Cookies Found:</b> {self.stats.commerce_total}",
            f"<b>Unique B3 Domains:</b> {len(self.stats.domains_with_b3)}",
            f"<b>Unique Gateway Domains:</b> {len(self.stats.domains_with_gateway)}",
            "",
        ]
        
        if self.stats.gateways_by_type:
            lines.append("<b>Gateway Breakdown:</b>")
            for gw, count in sorted(
                self.stats.gateways_by_type.items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {gw.upper()}: {count}")
            lines.append("")
        
        if self.stats.domains_with_b3:
            lines.append("<b>B3 Domains (last 10):</b>")
            for d in list(self.stats.domains_with_b3)[-10:]:
                lines.append(f"  <code>{d}</code>")
            lines.append("")
        
        if self.stats.domains_with_gateway:
            lines.append("<b>Gateway Domains (last 10):</b>")
            for d in list(self.stats.domains_with_gateway)[-10:]:
                lines.append(f"  <code>{d}</code>")
        
        avg_time = (
            self.stats.total_probe_time / self.stats.urls_probed
            if self.stats.urls_probed > 0 else 0
        )
        lines.append(f"\n<b>Avg probe time:</b> {avg_time:.1f}s")
        lines.append(f"<b>Errors:</b> {self.stats.errors}")
        
        return "\n".join(lines)

    def reset_dedup(self):
        """Reset dedup cache (useful between cycles)."""
        self._reported.clear()
