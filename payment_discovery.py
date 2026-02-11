"""
Payment Site Discovery Engine — Find confirmed e-commerce sites that process payments.

Instead of blind dorking and hoping for payment sites, this module discovers
sites that are *confirmed* to integrate with payment processors, then feeds
them into the vulnerability scanner.

Discovery Methods:
  1. Payment JS Include Dorks — find sites loading Stripe.js, PayPal SDK, etc.
  2. Certificate Transparency — find checkout/pay/billing subdomains
  3. Technology Fingerprint Dorks — find sites with specific cart/checkout patterns
  4. Payment Gateway Endpoint Dorks — find exposed payment API endpoints
  5. Backlink Discovery — find sites linking to payment processor docs/SDKs

All discovered sites are de-duplicated by domain and fed as high-priority
targets into the main scanner pipeline.
"""

import re
import json
import time
import asyncio
import logging
import random
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from datetime import datetime

import aiohttp

logger = logging.getLogger("payment_discovery")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                  PAYMENT GATEWAY SIGNATURES                     ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class PaymentGateway:
    """Definition of a payment gateway to search for."""
    name: str
    js_domains: List[str]          # JS CDN domains loaded by integrating sites
    api_domains: List[str]         # API endpoints sites call
    html_signatures: List[str]     # HTML patterns indicating integration
    dork_patterns: List[str]       # Google dorks to find integrating sites
    ct_subdomains: List[str]       # Subdomain patterns in CT logs
    confidence: float = 0.9


PAYMENT_GATEWAYS: List[PaymentGateway] = [
    PaymentGateway(
        name="Stripe",
        js_domains=["js.stripe.com", "checkout.stripe.com", "m.stripe.network"],
        api_domains=["api.stripe.com"],
        html_signatures=[
            r'js\.stripe\.com/v3',
            r'Stripe\s*\(\s*[\'"]pk_(live|test)_',
            r'stripe-js',
            r'data-stripe-publishable-key',
            r'StripeCheckout\.configure',
        ],
        dork_patterns=[
            'inurl:checkout "stripe" "pk_live"',
            'intext:"pk_live_" inurl:checkout',
            'intext:"pk_test_" inurl:payment',
            '"js.stripe.com/v3" inurl:checkout',
            '"js.stripe.com/v3" inurl:payment',
            '"js.stripe.com/v3" inurl:cart',
            '"js.stripe.com/v3" inurl:order',
            '"js.stripe.com/v3" inurl:subscribe',
            '"stripe-publishable-key" inurl:checkout',
            '"StripeCheckout" inurl:pay',
            'site:*.com inurl:checkout "stripe"',
            '"stripe.com/v3" -site:stripe.com -site:github.com -site:stackoverflow.com',
        ],
        ct_subdomains=["checkout", "pay", "payment", "billing", "subscribe", "order"],
    ),
    PaymentGateway(
        name="PayPal",
        js_domains=["www.paypal.com/sdk", "www.paypalobjects.com"],
        api_domains=["api.paypal.com", "api-m.paypal.com"],
        html_signatures=[
            r'paypal\.com/sdk/js',
            r'paypal-button',
            r'paypal\.Buttons',
            r'data-paypal-button',
            r'paypalobjects\.com',
        ],
        dork_patterns=[
            '"paypal.com/sdk/js" inurl:checkout',
            '"paypal.com/sdk/js" inurl:cart',
            '"paypal.com/sdk/js" inurl:payment',
            '"paypal-button" inurl:checkout',
            '"paypal.Buttons" inurl:pay',
            '"paypal.com/sdk" -site:paypal.com -site:github.com -site:stackoverflow.com',
            'inurl:checkout "paypal" "client-id"',
        ],
        ct_subdomains=["checkout", "pay", "payments", "billing", "order"],
    ),
    PaymentGateway(
        name="Square",
        js_domains=["js.squareup.com", "connect.squareup.com", "sandbox.web.squareup.com"],
        api_domains=["connect.squareup.com"],
        html_signatures=[
            r'js\.squareup\.com',
            r'sq-payment-form',
            r'SqPaymentForm',
            r'square\.com/v2',
            r'application-id.*sq0',
        ],
        dork_patterns=[
            '"js.squareup.com" inurl:checkout',
            '"js.squareup.com" inurl:payment',
            '"SqPaymentForm" inurl:pay',
            '"sq-payment-form" inurl:checkout',
            '"square" "application-id" inurl:checkout',
        ],
        ct_subdomains=["checkout", "pay", "store", "shop"],
    ),
    PaymentGateway(
        name="Braintree",
        js_domains=["js.braintreegateway.com"],
        api_domains=["api.braintreegateway.com", "payments.braintree-api.com"],
        html_signatures=[
            r'js\.braintreegateway\.com',
            r'braintree\.client\.create',
            r'braintree-web',
            r'data-braintree-dropin',
            r'braintree\.dropin\.create',
        ],
        dork_patterns=[
            '"js.braintreegateway.com" inurl:checkout',
            '"js.braintreegateway.com" inurl:payment',
            '"braintree.dropin" inurl:checkout',
            '"braintree-web" inurl:pay',
            '"braintreegateway" -site:braintreegateway.com -site:github.com',
        ],
        ct_subdomains=["checkout", "pay", "billing"],
    ),
    PaymentGateway(
        name="Authorize.Net",
        js_domains=["jstest.authorize.net", "js.authorize.net"],
        api_domains=["api.authorize.net", "apitest.authorize.net"],
        html_signatures=[
            r'js\.authorize\.net',
            r'Accept\.dispatchData',
            r'acceptjs-sandbox',
            r'AcceptUI\.js',
            r'authorize\.net.*AcceptCore',
        ],
        dork_patterns=[
            '"js.authorize.net" inurl:checkout',
            '"js.authorize.net" inurl:payment',
            '"AcceptUI" inurl:checkout',
            '"authorize.net" inurl:checkout inurl:payment',
            '"Accept.dispatchData" inurl:pay',
        ],
        ct_subdomains=["checkout", "pay", "billing", "order"],
    ),
    PaymentGateway(
        name="Adyen",
        js_domains=["checkoutshopper-live.adyen.com", "checkoutshopper-test.adyen.com"],
        api_domains=["checkout-live.adyen.com"],
        html_signatures=[
            r'checkoutshopper.*adyen\.com',
            r'adyen-checkout',
            r'AdyenCheckout',
            r'adyenjs',
        ],
        dork_patterns=[
            '"adyen.com" inurl:checkout "checkoutshopper"',
            '"adyen-checkout" inurl:payment',
            '"AdyenCheckout" inurl:pay',
            '"checkoutshopper" "adyen" -site:adyen.com -site:github.com',
        ],
        ct_subdomains=["checkout", "pay", "payments"],
    ),
    PaymentGateway(
        name="Mollie",
        js_domains=["js.mollie.com"],
        api_domains=["api.mollie.com"],
        html_signatures=[
            r'js\.mollie\.com',
            r'mollie-components',
            r'Mollie\s*\(\s*[\'"]',
        ],
        dork_patterns=[
            '"js.mollie.com" inurl:checkout',
            '"mollie" inurl:checkout inurl:payment',
            '"mollie-components" inurl:pay',
        ],
        ct_subdomains=["checkout", "pay", "betaling"],
    ),
    PaymentGateway(
        name="Razorpay",
        js_domains=["checkout.razorpay.com"],
        api_domains=["api.razorpay.com"],
        html_signatures=[
            r'checkout\.razorpay\.com',
            r'Razorpay\s*\(',
            r'rzp_live_',
            r'rzp_test_',
        ],
        dork_patterns=[
            '"checkout.razorpay.com" inurl:payment',
            '"checkout.razorpay.com" inurl:checkout',
            '"rzp_live_" inurl:checkout',
            '"razorpay" inurl:payment -site:razorpay.com -site:github.com',
        ],
        ct_subdomains=["checkout", "pay", "payment"],
    ),
    PaymentGateway(
        name="2Checkout/Verifone",
        js_domains=["2pay-js.2checkout.com", "secure.2checkout.com"],
        api_domains=["api.2checkout.com"],
        html_signatures=[
            r'2checkout\.com',
            r'2pay-js',
            r'TwoCoInlineCart',
        ],
        dork_patterns=[
            '"2checkout.com" inurl:checkout inurl:payment',
            '"2pay-js" inurl:pay',
            '"TwoCoInlineCart" inurl:checkout',
        ],
        ct_subdomains=["checkout", "pay", "order"],
    ),
    PaymentGateway(
        name="Klarna",
        js_domains=["x.klarnacdn.net", "js.klarna.com"],
        api_domains=["api.klarna.com"],
        html_signatures=[
            r'x\.klarnacdn\.net',
            r'js\.klarna\.com',
            r'klarna-payments',
            r'Klarna\.Payments',
        ],
        dork_patterns=[
            '"klarnacdn.net" inurl:checkout',
            '"klarna" inurl:checkout inurl:payment',
            '"klarna-payments" inurl:pay',
        ],
        ct_subdomains=["checkout", "pay"],
    ),
    PaymentGateway(
        name="WooCommerce",
        js_domains=[],
        api_domains=[],
        html_signatures=[
            r'woocommerce',
            r'wc-checkout',
            r'/wp-json/wc/v[23]/',
            r'woocommerce-payments',
        ],
        dork_patterns=[
            'inurl:"/wp-json/wc/v3/" inurl:orders',
            'inurl:"/wp-json/wc/v2/" inurl:payment',
            'inurl:"wc-api" inurl:checkout',
            '"woocommerce" inurl:checkout "payment_method"',
            '"wc-checkout" inurl:order-pay',
            'inurl:"/checkout/order-received/" "woocommerce"',
            '"woocommerce_checkout" inurl:pay',
            'inurl:"/my-account/orders/" "woocommerce"',
        ],
        ct_subdomains=["shop", "store", "checkout"],
    ),
    PaymentGateway(
        name="Magento",
        js_domains=[],
        api_domains=[],
        html_signatures=[
            r'Magento_Checkout',
            r'checkout/cart',
            r'mage-init',
            r'/static/version.*Magento',
        ],
        dork_patterns=[
            'inurl:"/checkout/cart/" "Magento"',
            'inurl:"/checkout/onepage/" "Magento"',
            '"Magento_Checkout" inurl:payment',
            'inurl:"/customer/account/" "Magento" inurl:checkout',
            '"mage-init" inurl:checkout inurl:payment',
        ],
        ct_subdomains=["checkout", "shop", "store"],
    ),
    PaymentGateway(
        name="Shopify",
        js_domains=["cdn.shopify.com"],
        api_domains=[],
        html_signatures=[
            r'cdn\.shopify\.com',
            r'Shopify\.theme',
            r'myshopify\.com',
        ],
        dork_patterns=[
            'site:myshopify.com inurl:checkout',
            '"cdn.shopify.com" inurl:checkout',
            '"Shopify.theme" inurl:payment',
            '"myshopify.com" inurl:/cart',
        ],
        ct_subdomains=["checkout", "shop"],
    ),
]


# ╔══════════════════════════════════════════════════════════════════╗
# ║         CERTIFICATE TRANSPARENCY LOG SEARCHER                   ║
# ╚══════════════════════════════════════════════════════════════════╝

# Common payment-related subdomain prefixes to find in CT logs
CT_PAYMENT_SUBDOMAINS = [
    "checkout", "pay", "payment", "payments", "billing",
    "cart", "store", "shop", "order", "orders", "invoice",
    "subscribe", "subscription", "donate", "pos", "terminal",
    "secure-checkout", "securepay", "epay", "ipay", "webpay",
    "paygate", "merchant", "gateway", "transaction",
]

# Generic e-commerce dorks that find ANY payment-processing site
GENERIC_ECOMMERCE_DORKS = [
    # Checkout pages with payment forms
    'inurl:checkout inurl:payment "card number" "expiry"',
    'inurl:checkout "credit card" "cvv"',
    'inurl:"order/pay" "card number"',
    'inurl:checkout "billing address" "card"',
    # Exposed cart/order APIs
    'inurl:"/api/v" inurl:checkout inurl:payment',
    'inurl:"/api/" "payment_method" "card"',
    'inurl:"/api/orders" "payment" "amount"',
    # Admin/config leaks
    'inurl:"/admin/" "payment gateway" "api key"',
    'inurl:".env" "STRIPE_SECRET" OR "PAYPAL_SECRET" OR "PAYMENT_KEY"',
    'intitle:"index of" "payment" ".sql"',
    'inurl:"/config" "payment" "secret_key"',
    # Common CMS checkout pages
    'inurl:"/index.php?route=checkout" "payment_method"',  # OpenCart
    'inurl:"/module/payment/" inurl:validation',            # PrestaShop
]


@dataclass
class DiscoveredSite:
    """A payment-processing site discovered by the engine."""
    url: str
    domain: str
    gateway: str          # Which payment gateway detected
    method: str           # How it was found (dork/ct/html_scan)
    confidence: float     # 0.0 - 1.0
    discovered_at: float = field(default_factory=time.time)
    html_matches: List[str] = field(default_factory=list)
    has_params: bool = False  # URL has query parameters (more likely injectable)


class PaymentDiscovery:
    """
    Discovers sites that integrate with payment processors.
    
    Feeds confirmed e-commerce URLs into the vulnerability scanner pipeline.
    """

    def __init__(
        self,
        gateways: Optional[List[str]] = None,
        proxy_manager=None,
        searcher=None,
        max_concurrent: int = 20,
        request_timeout: int = 15,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        # Filter gateways if specified, else use all
        if gateways:
            self.gateways = [g for g in PAYMENT_GATEWAYS if g.name.lower() in [x.lower() for x in gateways]]
        else:
            self.gateways = PAYMENT_GATEWAYS
        
        self.proxy_manager = proxy_manager
        self.searcher = searcher  # MultiSearch instance from pipeline
        self.max_concurrent = max_concurrent
        self.request_timeout = request_timeout
        self.user_agent = user_agent
        
        # State
        self.discovered: Dict[str, DiscoveredSite] = {}  # domain -> site
        self.seen_domains: Set[str] = set()
        self.stats = {
            "dork_queries": 0,
            "ct_queries": 0,
            "html_scans": 0,
            "urls_checked": 0,
            "sites_found": 0,
            "gateways_found": {},
        }
        self._sem = asyncio.Semaphore(max_concurrent)
        self._running = False

    @property
    def found_count(self) -> int:
        return len(self.discovered)

    def _extract_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc.lower().strip()
        except Exception:
            return ""

    def _is_new_domain(self, url: str) -> bool:
        domain = self._extract_domain(url)
        if not domain or domain in self.seen_domains:
            return False
        return True

    def _add_site(self, url: str, gateway: str, method: str, confidence: float,
                  html_matches: Optional[List[str]] = None):
        """Register a discovered payment site."""
        domain = self._extract_domain(url)
        if not domain:
            return
        
        # Skip payment processor domains themselves
        skip_domains = {
            "stripe.com", "paypal.com", "squareup.com", "braintreegateway.com",
            "authorize.net", "adyen.com", "mollie.com", "razorpay.com",
            "2checkout.com", "klarna.com", "shopify.com", "github.com",
            "stackoverflow.com", "medium.com", "reddit.com", "youtube.com",
            "facebook.com", "twitter.com", "x.com", "linkedin.com",
        }
        for skip in skip_domains:
            if domain.endswith(skip):
                return

        if domain in self.seen_domains:
            # Update confidence if higher
            if domain in self.discovered and confidence > self.discovered[domain].confidence:
                self.discovered[domain].confidence = confidence
            return

        self.seen_domains.add(domain)
        has_params = "?" in url and "=" in url
        site = DiscoveredSite(
            url=url,
            domain=domain,
            gateway=gateway,
            method=method,
            confidence=confidence,
            html_matches=html_matches or [],
            has_params=has_params,
        )
        self.discovered[domain] = site
        self.stats["sites_found"] += 1
        gw_stats = self.stats["gateways_found"]
        gw_stats[gateway] = gw_stats.get(gateway, 0) + 1
        logger.info(f"[PayDiscover] 🎯 {gateway} site: {domain} ({method}, conf={confidence:.0%})")

    async def _get_proxy(self) -> Optional[str]:
        """Get a proxy URL from the proxy manager."""
        if not self.proxy_manager:
            return None
        try:
            proxy = await self.proxy_manager.get_proxy()
            if proxy:
                return str(proxy.url) if hasattr(proxy, "url") else str(proxy)
        except Exception:
            pass
        return None

    async def _fetch(self, url: str, timeout: int = None) -> Optional[str]:
        """Fetch URL content with proxy support."""
        timeout = timeout or self.request_timeout
        proxy = await self._get_proxy()
        headers = {"User-Agent": self.user_agent}
        try:
            async with self._sem:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            return await resp.text(errors="replace")
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────────────────
    # Method 1: Payment JS Include Dorks
    # ─────────────────────────────────────────────────────────

    async def discover_via_dorks(
        self,
        max_per_gateway: int = 50,
        include_generic: bool = True,
        report_callback=None,
    ) -> List[DiscoveredSite]:
        """
        Use search engine dorks to find sites loading payment gateway JS.
        
        This is the primary discovery method — searches for sites that include
        payment processor JavaScript SDKs in their HTML.
        """
        all_dorks = []
        
        # Gateway-specific dorks
        for gw in self.gateways:
            for dork in gw.dork_patterns:
                all_dorks.append((dork, gw.name))
        
        # Generic e-commerce dorks
        if include_generic:
            for dork in GENERIC_ECOMMERCE_DORKS:
                all_dorks.append((dork, "Generic"))

        random.shuffle(all_dorks)
        total = len(all_dorks)
        processed = 0

        logger.info(f"[PayDiscover] Starting dork discovery: {total} dorks across {len(self.gateways)} gateways")

        if not self.searcher:
            logger.warning("[PayDiscover] No searcher instance — cannot run dork discovery")
            return []

        for dork, gateway_name in all_dorks:
            if not self._running:
                break
            
            processed += 1
            self.stats["dork_queries"] += 1

            try:
                # Use the pipeline's MultiSearch to query search engines
                urls = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.searcher.search, dork, max_results=max_per_gateway
                    ),
                    timeout=30,
                )
                if urls:
                    for url in urls:
                        if self._is_new_domain(url):
                            self._add_site(url, gateway_name, "dork", 0.7)
                    
                    if report_callback and processed % 10 == 0:
                        await report_callback(
                            f"🔍 Dork {processed}/{total}: "
                            f"{len(urls)} URLs, {self.found_count} sites total"
                        )
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"[PayDiscover] Dork search error: {e}")

            # Rate limiting
            await asyncio.sleep(random.uniform(1.0, 3.0))

        return list(self.discovered.values())

    # ─────────────────────────────────────────────────────────
    # Method 2: Certificate Transparency Log Search
    # ─────────────────────────────────────────────────────────

    async def discover_via_ct_logs(
        self,
        max_results_per_query: int = 100,
        report_callback=None,
    ) -> List[DiscoveredSite]:
        """
        Search Certificate Transparency logs for payment-related subdomains.
        
        Uses crt.sh API to find certificates issued for subdomains like:
        checkout.*, pay.*, billing.*, etc.
        """
        logger.info(f"[PayDiscover] Starting CT log discovery: {len(CT_PAYMENT_SUBDOMAINS)} subdomain patterns")
        
        queries_done = 0
        for subdomain in CT_PAYMENT_SUBDOMAINS:
            if not self._running:
                break

            queries_done += 1
            self.stats["ct_queries"] += 1

            # Query crt.sh for wildcard subdomain certificates
            ct_url = f"https://crt.sh/?q=%25.{subdomain}.%25&output=json"
            try:
                content = await self._fetch(ct_url, timeout=20)
                if not content:
                    continue
                
                entries = json.loads(content)
                if not isinstance(entries, list):
                    continue

                domains_found = set()
                for entry in entries[:max_results_per_query]:
                    name = entry.get("name_value", "")
                    # Parse out actual domain names
                    for part in name.split("\n"):
                        part = part.strip().lower()
                        if part.startswith("*."):
                            part = part[2:]
                        if "." in part and not part.startswith("."):
                            domains_found.add(part)

                for domain in domains_found:
                    url = f"https://{domain}/"
                    if self._is_new_domain(url):
                        self._add_site(url, "Unknown (CT)", "ct_log", 0.5)

                if report_callback and queries_done % 5 == 0:
                    await report_callback(
                        f"📜 CT Log {queries_done}/{len(CT_PAYMENT_SUBDOMAINS)}: "
                        f"{len(domains_found)} domains, {self.found_count} sites total"
                    )

            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.debug(f"[PayDiscover] CT log error for {subdomain}: {e}")

            await asyncio.sleep(random.uniform(2.0, 5.0))

        return list(self.discovered.values())

    # ─────────────────────────────────────────────────────────
    # Method 3: HTML Verification Scan
    # ─────────────────────────────────────────────────────────

    async def verify_payment_integration(
        self,
        urls: List[str],
        report_callback=None,
    ) -> List[DiscoveredSite]:
        """
        Verify that URLs actually load payment gateway JS by fetching and checking HTML.
        
        This upgrades confidence scores for sites where we can confirm the
        payment integration in the page source.
        """
        logger.info(f"[PayDiscover] Verifying {len(urls)} URLs for payment integration")
        
        verified = 0
        tasks = []
        
        async def _check_one(url: str):
            nonlocal verified
            self.stats["html_scans"] += 1
            self.stats["urls_checked"] += 1
            
            html = await self._fetch(url)
            if not html:
                return
            
            domain = self._extract_domain(url)
            
            for gw in self.gateways:
                matches = []
                for pattern in gw.html_signatures:
                    if re.search(pattern, html, re.IGNORECASE):
                        matches.append(pattern)
                
                if matches:
                    confidence = min(0.95, 0.7 + 0.1 * len(matches))
                    self._add_site(url, gw.name, "html_verify", confidence, matches)
                    verified += 1
                    
                    # Also check for exposed keys/tokens in the HTML
                    key_patterns = [
                        (r'pk_(live|test)_[a-zA-Z0-9]{20,}', "Stripe Publishable Key"),
                        (r'rzp_(live|test)_[a-zA-Z0-9]{14,}', "Razorpay Key"),
                        (r'sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,}', "Square Application ID"),
                    ]
                    for kp, key_name in key_patterns:
                        found = re.findall(kp, html)
                        if found:
                            logger.info(f"[PayDiscover] 🔑 {key_name} found on {domain}")
                    break  # Found gateway, no need to check others

        for url in urls:
            if not self._running:
                break
            tasks.append(_check_one(url))
            
            # Process in batches
            if len(tasks) >= self.max_concurrent:
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks = []
                if report_callback:
                    await report_callback(
                        f"🔎 Verified {verified}/{self.stats['html_scans']} URLs, "
                        f"{self.found_count} confirmed sites"
                    )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[PayDiscover] Verification complete: {verified} confirmed payment sites")
        return list(self.discovered.values())

    # ─────────────────────────────────────────────────────────
    # Method 4: BuiltWith / PublicWWW Style Technology Search
    # ─────────────────────────────────────────────────────────

    async def discover_via_tech_search(
        self,
        report_callback=None,
    ) -> List[DiscoveredSite]:
        """
        Search for sites using specific payment technologies via PublicWWW-style
        queries and technology snippet dorks.
        
        Targets sites loading specific payment JS SDKs via search engines.
        """
        tech_dorks = []
        
        for gw in self.gateways:
            for js_domain in gw.js_domains:
                # Sites that load this JS domain
                tech_dorks.append((
                    f'intext:"{js_domain}" -site:{js_domain.split(".")[-2]}.{js_domain.split(".")[-1]}',
                    gw.name,
                ))
                tech_dorks.append((
                    f'"src=\\"{js_domain}" OR "src=\'{js_domain}"',
                    gw.name,
                ))

        random.shuffle(tech_dorks)
        logger.info(f"[PayDiscover] Tech search: {len(tech_dorks)} queries")

        if not self.searcher:
            return []

        for i, (dork, gw_name) in enumerate(tech_dorks):
            if not self._running:
                break
            
            try:
                urls = await asyncio.wait_for(
                    asyncio.to_thread(self.searcher.search, dork, max_results=30),
                    timeout=30,
                )
                if urls:
                    for url in urls:
                        if self._is_new_domain(url):
                            self._add_site(url, gw_name, "tech_search", 0.75)
            except Exception:
                pass

            await asyncio.sleep(random.uniform(1.5, 3.5))
            
            if report_callback and (i + 1) % 10 == 0:
                await report_callback(
                    f"🔧 Tech search {i+1}/{len(tech_dorks)}: {self.found_count} sites found"
                )

        return list(self.discovered.values())

    # ─────────────────────────────────────────────────────────
    # Full Discovery Pipeline
    # ─────────────────────────────────────────────────────────

    async def run_full_discovery(
        self,
        methods: Optional[List[str]] = None,
        report_callback=None,
    ) -> List[DiscoveredSite]:
        """
        Run all discovery methods and return confirmed payment sites.
        
        Args:
            methods: List of methods to run. Options: "dorks", "ct", "tech", "verify"
                     If None, runs all methods.
            report_callback: Async callback for progress updates.
        
        Returns:
            List of DiscoveredSite objects, sorted by confidence (highest first).
        """
        self._running = True
        all_methods = methods or ["dorks", "ct", "tech"]
        start_time = time.time()

        logger.info(f"[PayDiscover] Starting full discovery: methods={all_methods}")

        if report_callback:
            await report_callback(
                f"🎯 <b>Payment Site Discovery Started</b>\n\n"
                f"Methods: {', '.join(all_methods)}\n"
                f"Gateways: {len(self.gateways)} ({', '.join(g.name for g in self.gateways[:5])}...)\n"
                f"Dorks: {sum(len(g.dork_patterns) for g in self.gateways) + len(GENERIC_ECOMMERCE_DORKS)}"
            )

        try:
            # Phase 1: Dork-based discovery (primary)
            if "dorks" in all_methods:
                if report_callback:
                    await report_callback("📡 Phase 1: Payment gateway dork discovery...")
                await self.discover_via_dorks(report_callback=report_callback)

            # Phase 2: CT log discovery
            if "ct" in all_methods:
                if report_callback:
                    await report_callback("📜 Phase 2: Certificate transparency log search...")
                await self.discover_via_ct_logs(report_callback=report_callback)

            # Phase 3: Technology-based search
            if "tech" in all_methods:
                if report_callback:
                    await report_callback("🔧 Phase 3: Technology fingerprint search...")
                await self.discover_via_tech_search(report_callback=report_callback)

            # Phase 4: HTML verification (optional, verifies discovered sites)
            if "verify" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("🔎 Phase 4: Verifying payment integration...")
                urls_to_verify = [s.url for s in self.discovered.values()]
                await self.verify_payment_integration(urls_to_verify, report_callback=report_callback)

        except asyncio.CancelledError:
            logger.info("[PayDiscover] Discovery cancelled")
        finally:
            self._running = False

        elapsed = time.time() - start_time
        
        # Sort by confidence (highest first), then by has_params (injectable URLs first)
        results = sorted(
            self.discovered.values(),
            key=lambda s: (s.confidence, s.has_params),
            reverse=True,
        )

        logger.info(
            f"[PayDiscover] Discovery complete: {len(results)} payment sites found "
            f"in {elapsed:.0f}s ({self.stats})"
        )

        if report_callback:
            gw_breakdown = "\n".join(
                f"  {gw}: {count}" for gw, count in sorted(
                    self.stats["gateways_found"].items(),
                    key=lambda x: x[1], reverse=True
                )[:10]
            )
            await report_callback(
                f"✅ <b>Discovery Complete</b>\n\n"
                f"🎯 <b>{len(results)}</b> payment sites found\n"
                f"⏱ Time: {elapsed:.0f}s\n"
                f"🔍 Dork queries: {self.stats['dork_queries']}\n"
                f"📜 CT queries: {self.stats['ct_queries']}\n"
                f"🔎 HTML verified: {self.stats['html_scans']}\n\n"
                f"<b>Gateway Breakdown:</b>\n{gw_breakdown}"
            )

        return results

    def stop(self):
        """Stop the discovery process."""
        self._running = False

    def get_injectable_urls(self) -> List[str]:
        """Get URLs that have query parameters (higher SQLi potential)."""
        return [
            s.url for s in self.discovered.values()
            if s.has_params
        ]

    def get_all_urls(self) -> List[str]:
        """Get all discovered URLs for scanning."""
        return [s.url for s in sorted(
            self.discovered.values(),
            key=lambda s: (s.confidence, s.has_params),
            reverse=True,
        )]

    def get_domains(self) -> List[str]:
        """Get all discovered domains."""
        return list(self.discovered.keys())

    def get_stats_summary(self) -> str:
        """Get a human-readable stats summary."""
        gw_lines = []
        for gw, count in sorted(
            self.stats["gateways_found"].items(),
            key=lambda x: x[1], reverse=True
        ):
            gw_lines.append(f"  {gw}: {count}")
        
        return (
            f"Payment Discovery Stats:\n"
            f"  Total Sites: {self.found_count}\n"
            f"  Dork Queries: {self.stats['dork_queries']}\n"
            f"  CT Queries: {self.stats['ct_queries']}\n"
            f"  HTML Verified: {self.stats['html_scans']}\n"
            f"  URLs Checked: {self.stats['urls_checked']}\n"
            f"\nGateway Breakdown:\n" + "\n".join(gw_lines)
        )
