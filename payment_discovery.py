"""
Payment Site Discovery Engine v2 — Dorker-Grade Payment Site Discovery.

Discovers confirmed e-commerce sites that process payments, then feeds them
as high-priority targets into the vulnerability scanner pipeline.

FEATURES (v2):
  1. Parallel discovery workers — concurrent dork processing with semaphore
  2. Dork effectiveness scoring — tracks yield, sorts productive dorks first
  3. Deep checkout flow crawler — follows cart > checkout > payment pages
  4. Google Shopping + Wayback Machine mining
  5. Sitemap / robots.txt / API endpoint discovery
  6. Payment form deep analysis — finds POST endpoints, hidden fields, card inputs
  7. Domain value scoring — traffic, form complexity, parameter count, tech stack
  8. Discovery checkpointing — resume after restart
  9. Adaptive discovery interval — run more when finding lots, less on dry spells
  10. Certificate Transparency + backlink expansion + store directories (existing)
"""

import re
import json
import time
import asyncio
import logging
import random
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from datetime import datetime

import aiohttp

logger = logging.getLogger("payment_discovery")


# ======================================================================
#                   PAYMENT GATEWAY SIGNATURES
# ======================================================================

@dataclass
class PaymentGateway:
    """Definition of a payment gateway to search for."""
    name: str
    js_domains: List[str]
    api_domains: List[str]
    html_signatures: List[str]
    dork_patterns: List[str]
    ct_subdomains: List[str]
    confidence: float = 0.9


PAYMENT_GATEWAYS = [
    PaymentGateway(
        name="Stripe",
        js_domains=["js.stripe.com", "checkout.stripe.com"],
        api_domains=["api.stripe.com"],
        html_signatures=[
            r'js\.stripe\.com',
            r'Stripe\s*\(\s*[\'"]pk_',
            r'stripe-js',
            r'data-stripe',
            r'pk_(live|test)_[a-zA-Z0-9]{20,}',
        ],
        dork_patterns=[
            '"js.stripe.com" inurl:checkout',
            '"js.stripe.com" inurl:payment',
            '"js.stripe.com" inurl:pay',
            '"js.stripe.com" inurl:donate',
            '"pk_live_" inurl:checkout',
            '"pk_live_" inurl:payment',
            '"stripe-js" inurl:checkout -site:stripe.com -site:github.com',
            '"js.stripe.com" inurl:order',
            '"data-stripe" inurl:checkout inurl:card',
        ],
        ct_subdomains=["checkout", "pay", "payment", "billing", "donate"],
    ),
    PaymentGateway(
        name="PayPal",
        js_domains=["www.paypal.com/sdk/js", "www.paypalobjects.com"],
        api_domains=["api.paypal.com", "api-m.paypal.com"],
        html_signatures=[
            r'paypal\.com/sdk/js',
            r'paypalobjects\.com',
            r'paypal\.Buttons',
            r'paypal-button',
            r'braintree.*paypal',
        ],
        dork_patterns=[
            '"paypal.com/sdk/js" inurl:checkout',
            '"paypal.com/sdk/js" inurl:payment',
            '"paypal-button" inurl:checkout',
            '"paypal.Buttons" inurl:pay',
            '"paypalobjects" inurl:checkout -site:paypal.com -site:github.com',
        ],
        ct_subdomains=["checkout", "pay", "billing"],
    ),
    PaymentGateway(
        name="Square",
        js_domains=["js.squareup.com", "web.squarecdn.com", "sandbox.web.squarecdn.com"],
        api_domains=["connect.squareup.com"],
        html_signatures=[
            r'js\.squareup\.com',
            r'web\.squarecdn\.com',
            r'sq-payment-form',
            r'SqPaymentForm',
            r'sq0[a-z]{3}-',
        ],
        dork_patterns=[
            '"js.squareup.com" inurl:payment',
            '"sq-payment-form" inurl:checkout',
            '"squarecdn.com" inurl:pay',
            '"SqPaymentForm" inurl:checkout',
            '"squareup" inurl:payment -site:squareup.com -site:github.com',
        ],
        ct_subdomains=["checkout", "pay", "payments"],
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


# ======================================================================
#         CERTIFICATE TRANSPARENCY LOG SEARCHER
# ======================================================================

CT_PAYMENT_SUBDOMAINS = [
    "checkout", "pay", "payment", "payments", "billing",
    "cart", "store", "shop", "order", "orders", "invoice",
    "subscribe", "subscription", "donate", "pos", "terminal",
    "secure-checkout", "securepay", "epay", "ipay", "webpay",
    "paygate", "merchant", "gateway", "transaction",
]

# Generic e-commerce dorks
GENERIC_ECOMMERCE_DORKS = [
    'inurl:checkout inurl:payment "card number" "expiry"',
    'inurl:checkout "credit card" "cvv"',
    'inurl:"order/pay" "card number"',
    'inurl:checkout "billing address" "card"',
    'inurl:"/api/v" inurl:checkout inurl:payment',
    'inurl:"/api/" "payment_method" "card"',
    'inurl:"/api/orders" "payment" "amount"',
    'inurl:"/admin/" "payment gateway" "api key"',
    'inurl:".env" "STRIPE_SECRET" OR "PAYPAL_SECRET" OR "PAYMENT_KEY"',
    'intitle:"index of" "payment" ".sql"',
    'inurl:"/config" "payment" "secret_key"',
    'inurl:"/index.php?route=checkout" "payment_method"',
    'inurl:"/module/payment/" inurl:validation',
]

# Google Shopping / product-focused dorks (NEW in v2)
SHOPPING_DORKS = [
    'inurl:"/product/" "add to cart" "checkout" "credit card"',
    'inurl:"/products/" "buy now" "payment" "card number"',
    'inurl:"shop/" "checkout" "payment method" "card"',
    'inurl:"store/" "add-to-cart" "secure checkout"',
    'inurl:"/cart/" "proceed to checkout" "payment"',
    '"shopping cart" "secure checkout" "card number" "cvv"',
    '"add to cart" "checkout" inurl:payment -github -stackoverflow',
    'inurl:"/buy/" "card" "expiry" "checkout"',
    'inurl:"price" inurl:"checkout" "payment" "card"',
    '"shop now" "secure payment" inurl:checkout',
]

# Wayback Machine path patterns (NEW in v2)
WAYBACK_PATTERNS = [
    "/checkout", "/payment", "/pay", "/cart/checkout",
    "/order/pay", "/billing", "/purchase", "/donate",
    "/checkout/payment", "/checkout/card", "/checkout/review",
]

# Store directories
STORE_DIRECTORIES = [
    ("https://www.myip.ms/browse/sites/1/ipID/23.227.38.32/ipIDlast/23.227.38.71", "Shopify", "shopify_ip"),
    ("https://trends.builtwith.com/websitelist/Stripe", "Stripe", "builtwith"),
    ("https://trends.builtwith.com/websitelist/PayPal-Commerce-Platform", "PayPal", "builtwith"),
    ("https://trends.builtwith.com/websitelist/Braintree", "Braintree", "builtwith"),
    ("https://trends.builtwith.com/websitelist/Square-Payments", "Square", "builtwith"),
    ("https://woocommerce.com/showcase/", "WooCommerce", "woo_showcase"),
]

DIRECTORY_DORKS = [
    'site:myshopify.com -site:shopify.com inurl:checkout',
    '"Powered by Shopify" inurl:checkout',
    '"Powered by Shopify" inurl:cart',
    'site:*.myshopify.com inurl:products',
    '"woocommerce" "add-to-cart" inurl:product',
    '"woocommerce" inurl:checkout inurl:order',
    'inurl:"/wp-content/plugins/woocommerce" inurl:checkout',
    '"wc-ajax" inurl:checkout',
    '"Magento" inurl:checkout inurl:cart',
    'inurl:"/checkout/onepage" "Magento"',
    'inurl:"/catalogsearch/result" inurl:q=',
    '"Powered by OpenCart" inurl:checkout',
    'inurl:index.php?route=checkout',
    '"Prestashop" inurl:order inurl:step',
    'inurl:"/module/ps_" inurl:checkout',
    '"Powered by BigCommerce" inurl:checkout',
    'site:*.mybigcommerce.com',
    'inurl:checkout inurl:payment "credit card" "CVV"',
    'inurl:checkout "card number" "expiry" "CVV" -github -stackoverflow',
    'inurl:"/cart" "proceed to checkout" "payment method"',
    'inurl:checkout "billing address" "payment information" "card"',
]

# Domains to always skip
SKIP_DOMAINS = frozenset({
    "stripe.com", "paypal.com", "squareup.com", "braintreegateway.com",
    "authorize.net", "adyen.com", "mollie.com", "razorpay.com",
    "2checkout.com", "klarna.com", "shopify.com", "github.com",
    "stackoverflow.com", "medium.com", "reddit.com", "youtube.com",
    "facebook.com", "twitter.com", "x.com", "linkedin.com",
    "google.com", "googleapis.com", "cloudflare.com", "jsdelivr.net",
    "w3.org", "wikipedia.org", "instagram.com", "npmjs.com",
    "pypi.org", "rubygems.org", "wordpress.org", "docs.python.org",
    "developer.mozilla.org", "amazon.com", "aws.amazon.com",
})


# ======================================================================
#              DORK EFFECTIVENESS SCORER (embedded)
# ======================================================================

class PaymentDorkScorer:
    """Scores payment dorks by URL yield. Prioritises productive dorks."""

    def __init__(self):
        self._hits: Dict[str, int] = defaultdict(int)
        self._uses: Dict[str, int] = defaultdict(int)
        self._sites: Dict[str, int] = defaultdict(int)
        self._last_yield: Dict[str, float] = {}

    def record(self, dork: str, url_count: int, site_count: int = 0):
        self._hits[dork] += url_count
        self._uses[dork] += 1
        self._sites[dork] += site_count
        if url_count > 0:
            self._last_yield[dork] = time.time()

    def score(self, dork: str) -> float:
        uses = self._uses.get(dork, 0)
        if uses == 0:
            return 0.5
        hits_per_use = self._hits[dork] / uses
        sites_per_use = self._sites[dork] / uses
        return sites_per_use * 0.6 + min(hits_per_use / 10, 1.0) * 0.4

    def sort_dorks(self, dorks: List[str]) -> List[str]:
        tried = [d for d in dorks if d in self._uses]
        untried = [d for d in dorks if d not in self._uses]
        tried.sort(key=lambda d: self.score(d), reverse=True)
        result = []
        untried_iter = iter(untried)
        for i, d in enumerate(tried):
            result.append(d)
            if (i + 1) % 5 == 0:
                try:
                    result.append(next(untried_iter))
                except StopIteration:
                    pass
        for d in untried_iter:
            result.append(d)
        return result

    def get_top(self, n: int = 20) -> List[Tuple[str, float]]:
        scored = [(d, self.score(d)) for d in self._uses]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:n]

    def get_yield_rate(self) -> float:
        total_uses = sum(self._uses.values())
        total_sites = sum(self._sites.values())
        if total_uses == 0:
            return 0.0
        return total_sites / total_uses

    def to_dict(self) -> dict:
        return {
            "hits": dict(self._hits),
            "uses": dict(self._uses),
            "sites": dict(self._sites),
        }

    def from_dict(self, data: dict):
        self._hits = defaultdict(int, data.get("hits", {}))
        self._uses = defaultdict(int, data.get("uses", {}))
        self._sites = defaultdict(int, data.get("sites", {}))


# ======================================================================
#                 DOMAIN VALUE SCORER
# ======================================================================

class DomainValueScorer:
    """Scores discovered domains by payment value. Higher = better target."""

    HIGH_VALUE_INDICATORS = [
        r'(?:card|cc)[\s_-]?num',
        r'expir[ey]',
        r'cvv|cvc|csv',
        r'cardholder',
        r'billing[\s_-]?address',
        r'payment[\s_-]?method',
        r'order[\s_-]?total',
        r'<form[^>]*action=["\'][^"\']*(?:pay|checkout|order|billing)',
    ]

    @staticmethod
    def score_domain(
        domain: str = "",
        html: Optional[str] = None,
        url: str = "",
        gateway_count: int = 1,
        has_params: bool = False,
        form_count: int = 0,
        input_count: int = 0,
        checkout_paths_found: int = 0,
    ) -> float:
        score = 0.1
        if gateway_count >= 1:
            score += 0.15
        if gateway_count >= 2:
            score += 0.05
        if has_params:
            score += 0.15
        if checkout_paths_found > 0:
            score += min(checkout_paths_found * 0.05, 0.15)
        url_lower = url.lower()
        for kw in ("checkout", "payment", "pay", "billing", "order", "cart"):
            if kw in url_lower:
                score += 0.05
                break
        if html:
            html_lower = html.lower()
            card_indicators = 0
            for pattern in DomainValueScorer.HIGH_VALUE_INDICATORS:
                if re.search(pattern, html_lower, re.I):
                    card_indicators += 1
            score += min(card_indicators * 0.05, 0.2)
            forms = re.findall(r'<form\b', html_lower)
            if len(forms) >= 1:
                score += 0.05
            if len(forms) >= 3:
                score += 0.05
            inputs = re.findall(r'<input\b', html_lower)
            if len(inputs) >= 5:
                score += 0.05
            if len(inputs) >= 10:
                score += 0.05
            if 'shopify' not in html_lower and 'woocommerce' not in html_lower:
                score += 0.05
        return min(score, 1.0)


# ======================================================================
#                    DISCOVERED SITE
# ======================================================================

@dataclass
class DiscoveredSite:
    """A payment-processing site discovered by the engine."""
    url: str
    domain: str
    gateway: str
    method: str
    confidence: float
    discovered_at: float = field(default_factory=time.time)
    html_matches: List[str] = field(default_factory=list)
    has_params: bool = False
    value_score: float = 0.0
    checkout_urls: List[str] = field(default_factory=list)
    form_actions: List[str] = field(default_factory=list)
    param_count: int = 0


# ======================================================================
#              PAYMENT DISCOVERY ENGINE v2
# ======================================================================

class PaymentDiscovery:
    """
    Dorker-grade payment site discovery engine.

    Features: parallel workers, dork scoring, deep checkout crawling,
    Wayback mining, sitemap parsing, form analysis, domain value scoring,
    discovery checkpointing, adaptive intervals.
    """

    def __init__(
        self,
        gateways: Optional[List[str]] = None,
        proxy_manager=None,
        searcher=None,
        db=None,
        max_concurrent: int = 25,
        request_timeout: int = 15,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        if gateways:
            self.gateways = [g for g in PAYMENT_GATEWAYS if g.name.lower() in [x.lower() for x in gateways]]
        else:
            self.gateways = PAYMENT_GATEWAYS

        self.proxy_manager = proxy_manager
        self.searcher = searcher
        self.db = db
        self.max_concurrent = max_concurrent
        self.request_timeout = request_timeout
        self.user_agent = user_agent

        # State
        self.discovered: Dict[str, DiscoveredSite] = {}
        self.seen_domains: Set[str] = set()

        # Load known domains from DB
        if self.db and hasattr(self.db, 'get_payment_site_domains'):
            self.seen_domains = self.db.get_payment_site_domains()
            logger.info(f"[PayDiscover] Loaded {len(self.seen_domains)} known payment domains from DB")

        # Dork scorer
        self.dork_scorer = PaymentDorkScorer()
        if self.db and hasattr(self.db, 'get_payment_dork_scores'):
            try:
                scores_data = self.db.get_payment_dork_scores()
                if scores_data:
                    self.dork_scorer.from_dict(scores_data)
                    logger.info(f"[PayDiscover] Restored dork scores for {len(self.dork_scorer._uses)} dorks")
            except Exception:
                pass

        # Domain value scorer
        self.value_scorer = DomainValueScorer()

        # Stats
        self.stats = {
            "dork_queries": 0,
            "ct_queries": 0,
            "html_scans": 0,
            "urls_checked": 0,
            "sites_found": 0,
            "backlink_queries": 0,
            "directory_queries": 0,
            "checkout_crawls": 0,
            "wayback_queries": 0,
            "sitemap_parses": 0,
            "form_analyses": 0,
            "gateways_found": {},
        }

        # Concurrency control
        self._sem = asyncio.Semaphore(max_concurrent)
        self._fetch_sem = asyncio.Semaphore(max_concurrent * 2)
        self._running = False

        # Checkpoint state
        self._checkpoint_cycle = 0
        self._checkpoint_dork_index = 0

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
        for skip in SKIP_DOMAINS:
            if domain.endswith(skip):
                return False
        return True

    def _add_site(self, url: str, gateway: str, method: str, confidence: float,
                  html_matches: Optional[List[str]] = None, value_score: float = 0.0,
                  checkout_urls: Optional[List[str]] = None,
                  form_actions: Optional[List[str]] = None) -> bool:
        """Register a discovered payment site. Returns True if new."""
        domain = self._extract_domain(url)
        if not domain:
            return False
        for skip in SKIP_DOMAINS:
            if domain.endswith(skip):
                return False
        if domain in self.seen_domains:
            if domain in self.discovered and confidence > self.discovered[domain].confidence:
                self.discovered[domain].confidence = confidence
                if checkout_urls:
                    self.discovered[domain].checkout_urls.extend(checkout_urls)
                if form_actions:
                    self.discovered[domain].form_actions.extend(form_actions)
            return False

        self.seen_domains.add(domain)
        has_params = "?" in url and "=" in url
        param_count = len(parse_qs(urlparse(url).query)) if has_params else 0

        site = DiscoveredSite(
            url=url, domain=domain, gateway=gateway, method=method,
            confidence=confidence, html_matches=html_matches or [],
            has_params=has_params, value_score=value_score,
            checkout_urls=checkout_urls or [], form_actions=form_actions or [],
            param_count=param_count,
        )
        self.discovered[domain] = site
        self.stats["sites_found"] += 1
        gw_stats = self.stats["gateways_found"]
        gw_stats[gateway] = gw_stats.get(gateway, 0) + 1
        logger.info(f"[PayDiscover] \U0001f3af {gateway} site: {domain} ({method}, conf={confidence:.0%}, val={value_score:.0%})")

        # Persist to DB immediately
        if self.db and hasattr(self.db, 'save_payment_site'):
            try:
                self.db.save_payment_site(
                    domain=domain, url=url, gateway=gateway, method=method,
                    confidence=confidence, has_params=has_params,
                    html_matches=html_matches,
                )
            except Exception as e:
                logger.debug(f"[PayDiscover] DB save error: {e}")
        return True

    async def _get_proxy(self) -> Optional[str]:
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
        timeout = timeout or self.request_timeout
        proxy = await self._get_proxy()
        headers = {"User-Agent": self.user_agent}
        try:
            async with self._fetch_sem:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, headers=headers, proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False, allow_redirects=True,
                    ) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "")
                            if "text" in ct or "html" in ct or "json" in ct or "xml" in ct:
                                return await resp.text(errors="replace")
        except Exception:
            pass
        return None

    def _save_checkpoint(self, phase: str, index: int, total: int):
        if self.db and hasattr(self.db, 'save_payment_checkpoint'):
            try:
                self.db.save_payment_checkpoint(
                    cycle=self._checkpoint_cycle, phase=phase,
                    index=index, total=total,
                    dork_scores=json.dumps(self.dork_scorer.to_dict()),
                )
            except Exception as e:
                logger.debug(f"[PayDiscover] Checkpoint save error: {e}")

    def _load_checkpoint(self) -> Optional[Dict]:
        if self.db and hasattr(self.db, 'get_payment_checkpoint'):
            try:
                return self.db.get_payment_checkpoint()
            except Exception:
                pass
        return None

    # ---------------------------------------------------------
    # Method 1: Parallel Dork Discovery (with scoring)
    # ---------------------------------------------------------

    async def discover_via_dorks(
        self,
        max_per_gateway: int = 50,
        include_generic: bool = True,
        include_shopping: bool = True,
        report_callback=None,
        resume_index: int = 0,
    ) -> List[DiscoveredSite]:
        """Parallel dork discovery with effectiveness scoring."""
        all_dorks = []
        for gw in self.gateways:
            for dork in gw.dork_patterns:
                all_dorks.append((dork, gw.name))
        if include_generic:
            for dork in GENERIC_ECOMMERCE_DORKS:
                all_dorks.append((dork, "Generic"))
        if include_shopping:
            for dork in SHOPPING_DORKS:
                all_dorks.append((dork, "Shopping"))

        # Build gateway lookup map
        dork_gateway_map = {}
        for dork, gw_name in all_dorks:
            dork_gateway_map[dork] = gw_name

        # Sort by dork effectiveness score
        sorted_dork_strs = self.dork_scorer.sort_dorks([d[0] for d in all_dorks])
        paired_dorks = [(d, dork_gateway_map.get(d, "Unknown")) for d in sorted_dork_strs]

        # Resume from checkpoint
        if resume_index > 0 and resume_index < len(paired_dorks):
            logger.info(f"[PayDiscover] Resuming dorks from index {resume_index}")
            paired_dorks = paired_dorks[resume_index:]

        total = len(paired_dorks)
        processed = 0

        logger.info(f"[PayDiscover] Parallel dork discovery: {total} dorks, batch_size=5")

        if not self.searcher:
            logger.warning("[PayDiscover] No searcher - cannot run dork discovery")
            return []

        async def _run_dork(dork: str, gateway_name: str) -> int:
            sites_before = self.stats["sites_found"]
            self.stats["dork_queries"] += 1
            try:
                urls = await asyncio.wait_for(
                    asyncio.to_thread(self.searcher.search, dork, max_results=max_per_gateway),
                    timeout=30,
                )
                url_count = len(urls) if urls else 0
                if urls:
                    for url in urls:
                        if self._is_new_domain(url):
                            self._add_site(url, gateway_name, "dork", 0.7)
                new_sites = self.stats["sites_found"] - sites_before
                self.dork_scorer.record(dork, url_count, new_sites)
                return new_sites
            except asyncio.TimeoutError:
                self.dork_scorer.record(dork, 0, 0)
                return 0
            except Exception as e:
                logger.debug(f"[PayDiscover] Dork error: {e}")
                self.dork_scorer.record(dork, 0, 0)
                return 0

        # Process in parallel batches of 5
        batch_size = 5
        for batch_start in range(0, total, batch_size):
            if not self._running:
                break
            batch = paired_dorks[batch_start:batch_start + batch_size]
            tasks = [_run_dork(dork, gw) for dork, gw in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            processed += len(batch)

            if processed % 20 == 0:
                self._save_checkpoint("dorks", resume_index + processed, total)
            if report_callback and processed % 15 == 0:
                yield_rate = self.dork_scorer.get_yield_rate()
                await report_callback(
                    f"\U0001f50d Dorks {processed}/{total}: "
                    f"{self.found_count} sites (yield: {yield_rate:.1%})"
                )
            await asyncio.sleep(random.uniform(1.5, 3.0))

        # Save dork scores
        if self.db and hasattr(self.db, 'save_payment_dork_scores'):
            try:
                self.db.save_payment_dork_scores(self.dork_scorer.to_dict())
            except Exception:
                pass
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 2: Certificate Transparency Log Search
    # ---------------------------------------------------------

    async def discover_via_ct_logs(
        self, max_results_per_query: int = 100, report_callback=None,
    ) -> List[DiscoveredSite]:
        """Search CT logs for payment-related subdomains. Parallel batches."""
        logger.info(f"[PayDiscover] CT log discovery: {len(CT_PAYMENT_SUBDOMAINS)} patterns")

        async def _query_ct(subdomain: str) -> int:
            self.stats["ct_queries"] += 1
            ct_url = f"https://crt.sh/?q=%25.{subdomain}.%25&output=json"
            new_sites = 0
            try:
                content = await self._fetch(ct_url, timeout=20)
                if not content:
                    return 0
                entries = json.loads(content)
                if not isinstance(entries, list):
                    return 0
                domains_found = set()
                for entry in entries[:max_results_per_query]:
                    name = entry.get("name_value", "")
                    for part in name.split("\n"):
                        part = part.strip().lower()
                        if part.startswith("*."):
                            part = part[2:]
                        if "." in part and not part.startswith("."):
                            domains_found.add(part)
                for domain in domains_found:
                    url = f"https://{domain}/"
                    if self._is_new_domain(url):
                        if self._add_site(url, "Unknown (CT)", "ct_log", 0.5):
                            new_sites += 1
            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.debug(f"[PayDiscover] CT log error for {subdomain}: {e}")
            return new_sites

        batch_size = 3
        for i in range(0, len(CT_PAYMENT_SUBDOMAINS), batch_size):
            if not self._running:
                break
            batch = CT_PAYMENT_SUBDOMAINS[i:i + batch_size]
            tasks = [_query_ct(sub) for sub in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % 9 == 0:
                await report_callback(
                    f"\U0001f4dc CT Log {min(i + batch_size, len(CT_PAYMENT_SUBDOMAINS))}/"
                    f"{len(CT_PAYMENT_SUBDOMAINS)}: {self.found_count} sites"
                )
            await asyncio.sleep(random.uniform(2.0, 4.0))
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 3: HTML Verification Scan (parallel)
    # ---------------------------------------------------------

    async def verify_payment_integration(
        self, urls: List[str], report_callback=None,
    ) -> List[DiscoveredSite]:
        """Verify URLs actually load payment gateway JS."""
        logger.info(f"[PayDiscover] Verifying {len(urls)} URLs")
        verified = 0

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
                    val_score = self.value_scorer.score_domain(
                        domain=domain, html=html, url=url,
                        gateway_count=1, has_params=("?" in url),
                    )
                    self._add_site(url, gw.name, "html_verify", confidence, matches,
                                   value_score=val_score)
                    verified += 1
                    key_patterns = [
                        (r'pk_(live|test)_[a-zA-Z0-9]{20,}', "Stripe Key"),
                        (r'rzp_(live|test)_[a-zA-Z0-9]{14,}', "Razorpay Key"),
                        (r'sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,}', "Square ID"),
                    ]
                    for kp, key_name in key_patterns:
                        if re.findall(kp, html):
                            logger.info(f"[PayDiscover] \U0001f511 {key_name} on {domain}")
                    break

        batch_size = self.max_concurrent
        for i in range(0, len(urls), batch_size):
            if not self._running:
                break
            batch = urls[i:i + batch_size]
            tasks = [_check_one(url) for url in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % (batch_size * 2) == 0:
                await report_callback(
                    f"\U0001f50e Verified {verified}/{self.stats['html_scans']} URLs"
                )
        logger.info(f"[PayDiscover] Verification complete: {verified} confirmed")
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 4: Technology Fingerprint Dorks (parallel)
    # ---------------------------------------------------------

    async def discover_via_tech_search(self, report_callback=None) -> List[DiscoveredSite]:
        """Tech fingerprint search. Parallel batches."""
        tech_dorks = []
        for gw in self.gateways:
            for js_domain in gw.js_domains:
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

        async def _run_tech_dork(dork: str, gw_name: str):
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

        batch_size = 5
        for i in range(0, len(tech_dorks), batch_size):
            if not self._running:
                break
            batch = tech_dorks[i:i + batch_size]
            tasks = [_run_tech_dork(d, g) for d, g in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(random.uniform(1.5, 3.0))
            if report_callback and (i + batch_size) % 15 == 0:
                await report_callback(
                    f"\U0001f527 Tech search {min(i + batch_size, len(tech_dorks))}/{len(tech_dorks)}: "
                    f"{self.found_count} sites"
                )
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 5: Deep Checkout Flow Crawler (NEW in v2)
    # ---------------------------------------------------------

    async def deep_checkout_crawl(
        self, sites: Optional[List[DiscoveredSite]] = None,
        report_callback=None, max_sites: int = 50,
    ) -> List[DiscoveredSite]:
        """Crawl checkout flows to find POST endpoints, parameters, card inputs."""
        if sites is None:
            sites = sorted(
                self.discovered.values(), key=lambda s: s.confidence, reverse=True,
            )[:max_sites]
        logger.info(f"[PayDiscover] Deep checkout crawl: {len(sites)} sites")

        checkout_paths = [
            "/checkout", "/checkout/", "/payment", "/payment/",
            "/pay", "/order", "/order/pay", "/cart/checkout",
            "/billing", "/purchase", "/donate", "/subscribe",
            "/checkout/payment", "/checkout/card", "/checkout/review",
            "/checkout/shipping", "/checkout/confirm",
            "/index.php?route=checkout/checkout",
            "/index.php?route=checkout/payment",
        ]

        async def _crawl_site(site: DiscoveredSite):
            self.stats["checkout_crawls"] += 1
            base_url = f"https://{site.domain}"
            found_urls = []
            found_forms = []

            for path in checkout_paths:
                if not self._running:
                    break
                url = urljoin(base_url, path)
                html = await self._fetch(url, timeout=12)
                if not html:
                    continue
                found_urls.append(url)

                form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', re.I | re.S)
                for action in form_pattern.findall(html):
                    full_url = urljoin(url, action)
                    if any(kw in action.lower() for kw in ('pay', 'checkout', 'order', 'billing', 'card', 'process')):
                        found_forms.append(full_url)

                link_pattern = re.compile(
                    r'href=["\']([^"\']*(?:checkout|payment|pay|cart|order|billing)[^"\']*)["\']', re.I
                )
                for link in link_pattern.findall(html):
                    full = urljoin(url, link)
                    if site.domain in self._extract_domain(full):
                        found_urls.append(full)

            if found_urls or found_forms:
                site.checkout_urls = list(set(found_urls))[:20]
                site.form_actions = list(set(found_forms))[:10]
                if found_forms:
                    site.confidence = min(site.confidence + 0.1, 0.98)
                    logger.info(
                        f"[PayDiscover] \U0001f6d2 {site.domain}: {len(found_urls)} checkout URLs, "
                        f"{len(found_forms)} form endpoints"
                    )

        batch_size = 10
        for i in range(0, len(sites), batch_size):
            if not self._running:
                break
            batch = sites[i:i + batch_size]
            tasks = [_crawl_site(s) for s in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % 20 == 0:
                crawled = min(i + batch_size, len(sites))
                with_forms = sum(1 for s in sites[:crawled] if s.form_actions)
                await report_callback(
                    f"\U0001f6d2 Checkout crawl: {crawled}/{len(sites)}, {with_forms} with forms"
                )
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 6: Wayback Machine Mining (NEW in v2)
    # ---------------------------------------------------------

    async def discover_via_wayback(
        self, domains: Optional[List[str]] = None,
        report_callback=None, max_domains: int = 100,
    ) -> List[DiscoveredSite]:
        """Query Wayback Machine CDX API for historical checkout/payment URLs."""
        if domains is None:
            domains = list(self.discovered.keys())[:max_domains]
        if not domains:
            return []
        logger.info(f"[PayDiscover] Wayback mining: {len(domains)} domains")

        async def _query_wayback(domain: str):
            self.stats["wayback_queries"] += 1
            for pattern in WAYBACK_PATTERNS[:5]:
                if not self._running:
                    break
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx?"
                    f"url={domain}{pattern}*&output=json&limit=20&fl=original&collapse=urlkey"
                )
                try:
                    content = await self._fetch(cdx_url, timeout=15)
                    if not content:
                        continue
                    data = json.loads(content)
                    if not isinstance(data, list) or len(data) <= 1:
                        continue
                    for row in data[1:]:
                        if row and isinstance(row, list):
                            url = row[0]
                            if isinstance(url, str) and url.startswith("http"):
                                if self._is_new_domain(url):
                                    has_params = "?" in url and "=" in url
                                    conf = 0.6 if has_params else 0.45
                                    self._add_site(url, "Unknown (Wayback)", "wayback", conf)
                except Exception:
                    pass
                await asyncio.sleep(random.uniform(0.5, 1.5))

        batch_size = 5
        for i in range(0, len(domains), batch_size):
            if not self._running:
                break
            batch = domains[i:i + batch_size]
            tasks = [_query_wayback(d) for d in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % 15 == 0:
                await report_callback(
                    f"\u23f3 Wayback: {min(i + batch_size, len(domains))}/{len(domains)}, "
                    f"{self.found_count} sites"
                )
            await asyncio.sleep(random.uniform(1.0, 2.0))
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 7: Sitemap / robots.txt / API Endpoint Finder (NEW)
    # ---------------------------------------------------------

    async def discover_via_sitemaps(
        self, domains: Optional[List[str]] = None,
        report_callback=None, max_domains: int = 100,
    ) -> List[DiscoveredSite]:
        """Parse robots.txt and sitemap.xml for checkout/payment/API paths."""
        if domains is None:
            domains = list(self.discovered.keys())[:max_domains]
        if not domains:
            return []
        logger.info(f"[PayDiscover] Sitemap/robots parsing: {len(domains)} domains")

        payment_keywords = {'checkout', 'payment', 'pay', 'billing', 'order', 'cart', 'purchase', 'donate', 'subscribe', 'api'}

        async def _parse_domain(domain: str):
            self.stats["sitemap_parses"] += 1
            base = f"https://{domain}"
            interesting_urls = []

            # 1. robots.txt
            robots = await self._fetch(f"{base}/robots.txt", timeout=10)
            if robots:
                for line in robots.split("\n"):
                    line = line.strip().lower()
                    if line.startswith(("disallow:", "allow:", "sitemap:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if any(kw in path for kw in payment_keywords):
                                if path.startswith("/"):
                                    interesting_urls.append(urljoin(base, path))
                                elif path.startswith("http"):
                                    interesting_urls.append(path)

            # 2. sitemap.xml
            for sm_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml"]:
                sm_content = await self._fetch(f"{base}{sm_path}", timeout=10)
                if not sm_content:
                    continue
                try:
                    url_pattern = re.compile(r'<loc>\s*(https?://[^<]+)\s*</loc>', re.I)
                    for url in url_pattern.findall(sm_content):
                        if any(kw in url.lower() for kw in payment_keywords):
                            interesting_urls.append(url)
                except Exception:
                    pass

            # 3. Common API endpoints
            api_paths = [
                "/api/v1/checkout", "/api/v2/checkout", "/api/v1/orders",
                "/api/v1/payments", "/api/cart", "/api/v1/cart",
                "/wp-json/wc/v3/orders", "/wp-json/wc/v2/orders",
            ]
            for api_path in api_paths:
                if not self._running:
                    break
                url = f"{base}{api_path}"
                try:
                    async with self._fetch_sem:
                        async with aiohttp.ClientSession() as session:
                            async with session.head(
                                url, headers={"User-Agent": self.user_agent},
                                timeout=aiohttp.ClientTimeout(total=5),
                                ssl=False, allow_redirects=True,
                            ) as resp:
                                if resp.status in (200, 301, 302, 403):
                                    interesting_urls.append(url)
                except Exception:
                    pass

            # Update discovered sites
            for url in interesting_urls:
                url_domain = self._extract_domain(url)
                if url_domain == domain and domain in self.discovered:
                    self.discovered[domain].checkout_urls.append(url)
                    if "?" in url and "=" in url:
                        self.discovered[domain].has_params = True
                        self.discovered[domain].confidence = min(
                            self.discovered[domain].confidence + 0.05, 0.98
                        )

        batch_size = 10
        for i in range(0, len(domains), batch_size):
            if not self._running:
                break
            batch = domains[i:i + batch_size]
            tasks = [_parse_domain(d) for d in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % 20 == 0:
                await report_callback(
                    f"\U0001f5fa Sitemaps: {min(i + batch_size, len(domains))}/{len(domains)} parsed"
                )
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 8: Payment Form Deep Analysis (NEW in v2)
    # ---------------------------------------------------------

    async def analyze_payment_forms(
        self, sites: Optional[List[DiscoveredSite]] = None,
        report_callback=None, max_sites: int = 50,
    ) -> List[DiscoveredSite]:
        """Deep analysis of payment forms: POST endpoints, hidden fields, card inputs."""
        if sites is None:
            sites = sorted(
                self.discovered.values(), key=lambda s: s.confidence, reverse=True,
            )[:max_sites]
        logger.info(f"[PayDiscover] Payment form analysis: {len(sites)} sites")

        async def _analyze_site(site: DiscoveredSite):
            self.stats["form_analyses"] += 1
            urls_to_check = [site.url] + site.checkout_urls[:5]
            all_forms = []

            for url in urls_to_check:
                if not self._running:
                    break
                html = await self._fetch(url, timeout=12)
                if not html:
                    continue

                form_re = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
                for form_attrs, form_body in form_re.findall(html):
                    form_text = (form_attrs + form_body).lower()
                    is_payment = any(kw in form_text for kw in (
                        'card', 'payment', 'checkout', 'billing', 'credit',
                        'cvv', 'cvc', 'expir', 'stripe', 'paypal', 'braintree',
                    ))
                    if not is_payment:
                        continue

                    form_data = {"url": url, "inputs": [], "action": ""}
                    action_match = re.search(r'action=["\']([^"\']+)', form_attrs, re.I)
                    if action_match:
                        form_data["action"] = urljoin(url, action_match.group(1))

                    input_re = re.compile(r'<input\b([^>]*)>', re.I | re.S)
                    for inp_attrs in input_re.findall(form_body):
                        inp = {}
                        name_m = re.search(r'name=["\']([^"\']+)', inp_attrs, re.I)
                        type_m = re.search(r'type=["\']([^"\']+)', inp_attrs, re.I)
                        if name_m:
                            inp["name"] = name_m.group(1)
                        if type_m:
                            inp["type"] = type_m.group(1)
                        if inp.get("name"):
                            form_data["inputs"].append(inp)
                    all_forms.append(form_data)

                val_score = self.value_scorer.score_domain(
                    domain=site.domain, html=html, url=url,
                    gateway_count=1, has_params=site.has_params,
                    form_count=len(all_forms),
                    input_count=sum(len(f["inputs"]) for f in all_forms),
                    checkout_paths_found=len(site.checkout_urls),
                )
                if val_score > site.value_score:
                    site.value_score = val_score

            if all_forms:
                actions = [f["action"] for f in all_forms if f["action"]]
                site.form_actions = list(set(site.form_actions + actions))[:15]
                total_params = sum(
                    len([i for i in f["inputs"] if i.get("type") != "hidden"])
                    for f in all_forms
                )
                site.param_count = max(site.param_count, total_params)
                site.confidence = min(site.confidence + 0.05, 0.98)
                logger.info(
                    f"[PayDiscover] \U0001f4dd {site.domain}: {len(all_forms)} payment forms, "
                    f"{total_params} inputs, val={site.value_score:.0%}"
                )

        batch_size = 10
        for i in range(0, len(sites), batch_size):
            if not self._running:
                break
            batch = sites[i:i + batch_size]
            tasks = [_analyze_site(s) for s in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and (i + batch_size) % 20 == 0:
                analyzed = min(i + batch_size, len(sites))
                with_forms = sum(1 for s in sites[:analyzed] if s.form_actions)
                await report_callback(
                    f"\U0001f4dd Forms: {analyzed}/{len(sites)}, {with_forms} with payment forms"
                )
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 9: Backlink Expansion (parallel)
    # ---------------------------------------------------------

    async def discover_via_backlinks(
        self, seed_urls: List[str], report_callback=None, max_depth: int = 2,
    ) -> List[DiscoveredSite]:
        """Follow outbound links from confirmed payment sites."""
        if not seed_urls:
            return []
        logger.info(f"[PayDiscover] Backlink expansion: {len(seed_urls)} seeds (depth={max_depth})")
        queue = list(seed_urls[:50])
        visited: Set[str] = set()
        depth_map = {url: 0 for url in queue}

        while queue and self._running:
            batch = []
            while queue and len(batch) < 10:
                url = queue.pop(0)
                if url not in visited:
                    batch.append(url)
                    visited.add(url)
            if not batch:
                break

            async def _expand_one(url: str):
                current_depth = depth_map.get(url, 0)
                if current_depth >= max_depth:
                    return
                self.stats["backlink_queries"] += 1
                try:
                    html = await self._fetch(url, timeout=12)
                    if not html:
                        return
                    source_domain = self._extract_domain(url)
                    link_pattern = re.compile(r'href=["\']?(https?://[^"\'>\s]+)', re.I)
                    links = link_pattern.findall(html)

                    external_links = []
                    for link in links:
                        link_domain = self._extract_domain(link)
                        if (link_domain and link_domain != source_domain
                                and link_domain not in self.seen_domains
                                and not any(link_domain.endswith(s) for s in SKIP_DOMAINS)):
                            external_links.append(link)

                    for elink in external_links[:15]:
                        if not self._running:
                            break
                        try:
                            html2 = await self._fetch(elink, timeout=10)
                            if not html2:
                                continue
                            for gw in self.gateways:
                                matches = [s for s in gw.html_signatures if re.search(s, html2, re.I)]
                                if matches:
                                    confidence = min(0.6 + len(matches) * 0.1, 0.95)
                                    self._add_site(elink, gw.name, "backlink", confidence, matches)
                                    if current_depth + 1 < max_depth:
                                        queue.append(elink)
                                        depth_map[elink] = current_depth + 1
                                    break
                            self.stats["urls_checked"] += 1
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"[PayDiscover] Backlink error: {e}")

            tasks = [_expand_one(url) for url in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            if report_callback and len(visited) % 15 == 0:
                await report_callback(
                    f"\U0001f517 Backlinks: {len(visited)} crawled, {self.found_count} sites"
                )
            await asyncio.sleep(random.uniform(0.5, 1.5))
        logger.info(f"[PayDiscover] Backlinks done: {len(visited)} pages")
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Method 10: Store Directory & Showcase Scraping
    # ---------------------------------------------------------

    async def discover_via_store_directories(self, report_callback=None) -> List[DiscoveredSite]:
        """Scrape known e-commerce directories and use directory dorks."""
        if not self._running:
            self._running = True
        logger.info("[PayDiscover] Store directory scraping...")

        # Phase A: Known directories
        for dir_url, gateway, source in STORE_DIRECTORIES:
            if not self._running:
                break
            self.stats["directory_queries"] += 1
            try:
                html = await self._fetch(dir_url, timeout=20)
                if not html:
                    continue
                domain_pattern = re.compile(
                    r'(?:href=["\']?https?://|(?:^|\s))((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})',
                    re.M
                )
                domains = set(domain_pattern.findall(html))
                for domain in domains:
                    domain = domain.lower().strip('.')
                    if self._is_new_domain(f"https://{domain}"):
                        self._add_site(f"https://{domain}", gateway, f"directory_{source}", 0.65)
                if report_callback:
                    await report_callback(f"\U0001f4c2 Directory: {source} -> {len(domains)} domains")
            except Exception as e:
                logger.debug(f"[PayDiscover] Directory error ({source}): {e}")
            await asyncio.sleep(random.uniform(2, 5))

        # Phase B: Directory dorks (parallel)
        if self.searcher:
            async def _run_dir_dork(dork: str):
                self.stats["dork_queries"] += 1
                try:
                    results = await asyncio.wait_for(
                        asyncio.to_thread(self.searcher.search, dork, max_results=30),
                        timeout=30,
                    )
                    urls = results if isinstance(results, list) else []
                    for url in urls:
                        if isinstance(url, str) and url.startswith("http"):
                            gw_name = "Ecommerce"
                            dork_lower = dork.lower()
                            for kw, name in [
                                ("shopify", "Shopify"), ("myshopify", "Shopify"),
                                ("woocommerce", "WooCommerce"), ("wc-ajax", "WooCommerce"),
                                ("magento", "Magento"), ("opencart", "OpenCart"),
                                ("prestashop", "PrestaShop"), ("bigcommerce", "BigCommerce"),
                            ]:
                                if kw in dork_lower:
                                    gw_name = name
                                    break
                            self._add_site(url, gw_name, "directory_dork", 0.70)
                except Exception:
                    pass

            batch_size = 5
            for i in range(0, len(DIRECTORY_DORKS), batch_size):
                if not self._running:
                    break
                batch = DIRECTORY_DORKS[i:i + batch_size]
                tasks = [_run_dir_dork(d) for d in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(random.uniform(2, 4))
                if report_callback and (i + batch_size) % 10 == 0:
                    await report_callback(
                        f"\U0001f3ea Store dorks: {min(i + batch_size, len(DIRECTORY_DORKS))}/{len(DIRECTORY_DORKS)}: "
                        f"{self.found_count} sites"
                    )
        logger.info(f"[PayDiscover] Store directories done: {self.found_count} total")
        return list(self.discovered.values())

    # ---------------------------------------------------------
    # Adaptive Discovery Interval
    # ---------------------------------------------------------

    def get_adaptive_interval(self, base_interval: int = 7200) -> int:
        """
        Calculate next discovery interval based on yield rate.
        High yield -> shorter interval (min 30 min)
        Low yield  -> longer interval (max 4 hours)
        """
        yield_rate = self.dork_scorer.get_yield_rate()
        if yield_rate >= 0.10:
            return max(1800, base_interval // 4)
        elif yield_rate >= 0.05:
            return max(3600, base_interval // 2)
        elif yield_rate >= 0.01:
            return base_interval
        else:
            return min(base_interval * 2, 14400)

    # ---------------------------------------------------------
    # Full Discovery Pipeline v2
    # ---------------------------------------------------------

    async def run_full_discovery(
        self, methods: Optional[List[str]] = None, report_callback=None,
    ) -> List[DiscoveredSite]:
        """Run all discovery methods with checkpointing."""
        self._running = True
        self._checkpoint_cycle += 1
        all_methods = methods or ["dorks", "ct", "tech"]
        start_time = time.time()

        # Check for resume checkpoint
        resume_dork_index = 0
        checkpoint = self._load_checkpoint()
        if checkpoint and checkpoint.get("cycle") == self._checkpoint_cycle:
            resume_dork_index = checkpoint.get("index", 0)
            logger.info(f"[PayDiscover] Resuming from checkpoint: index={resume_dork_index}")
            if checkpoint.get("dork_scores"):
                try:
                    self.dork_scorer.from_dict(json.loads(checkpoint["dork_scores"]))
                except Exception:
                    pass

        logger.info(f"[PayDiscover] Full discovery v2: methods={all_methods}")

        if report_callback:
            total_dorks = sum(len(g.dork_patterns) for g in self.gateways) + \
                         len(GENERIC_ECOMMERCE_DORKS) + len(SHOPPING_DORKS)
            await report_callback(
                f"\U0001f3af <b>Payment Discovery v2 Started</b>\n\n"
                f"Methods: {', '.join(all_methods)}\n"
                f"Gateways: {len(self.gateways)}\n"
                f"Dorks: {total_dorks} (scored)\n"
                f"Known: {len(self.seen_domains)}\n"
                f"Features: parallel, scoring, deep checkout, forms"
            )

        try:
            if "dorks" in all_methods:
                if report_callback:
                    await report_callback("\U0001f4e1 Phase 1: Parallel dork discovery (scored)...")
                await self.discover_via_dorks(
                    report_callback=report_callback, resume_index=resume_dork_index,
                    include_shopping=True,
                )

            if "ct" in all_methods:
                if report_callback:
                    await report_callback("\U0001f4dc Phase 2: CT log search...")
                await self.discover_via_ct_logs(report_callback=report_callback)

            if "tech" in all_methods:
                if report_callback:
                    await report_callback("\U0001f527 Phase 3: Tech fingerprint search...")
                await self.discover_via_tech_search(report_callback=report_callback)

            if "verify" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\U0001f50e Phase 4: Verifying payment integration...")
                urls_to_verify = [s.url for s in self.discovered.values()]
                await self.verify_payment_integration(urls_to_verify, report_callback=report_callback)

            if "backlinks" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\U0001f517 Phase 5: Backlink expansion...")
                seed_urls = [s.url for s in sorted(
                    self.discovered.values(), key=lambda s: s.confidence, reverse=True
                )[:20]]
                await self.discover_via_backlinks(seed_urls, report_callback=report_callback)

            if "directories" in all_methods:
                if report_callback:
                    await report_callback("\U0001f3ea Phase 6: Store directory scraping...")
                await self.discover_via_store_directories(report_callback=report_callback)

            if "wayback" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\u23f3 Phase 7: Wayback Machine mining...")
                await self.discover_via_wayback(report_callback=report_callback)

            if "sitemaps" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\U0001f5fa Phase 8: Sitemap/robots parsing...")
                await self.discover_via_sitemaps(report_callback=report_callback)

            if "deep_checkout" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\U0001f6d2 Phase 9: Deep checkout crawling...")
                await self.deep_checkout_crawl(report_callback=report_callback)

            if "form_analysis" in all_methods and self.discovered:
                if report_callback:
                    await report_callback("\U0001f4dd Phase 10: Payment form analysis...")
                await self.analyze_payment_forms(report_callback=report_callback)

        except asyncio.CancelledError:
            logger.info("[PayDiscover] Discovery cancelled")
        finally:
            self._running = False
            if self.db and hasattr(self.db, 'clear_payment_checkpoint'):
                try:
                    self.db.clear_payment_checkpoint()
                except Exception:
                    pass

        elapsed = time.time() - start_time
        results = sorted(
            self.discovered.values(),
            key=lambda s: (s.value_score, s.confidence, s.has_params, s.param_count),
            reverse=True,
        )
        logger.info(f"[PayDiscover] Discovery v2 complete: {len(results)} sites in {elapsed:.0f}s")

        if report_callback:
            gw_breakdown = "\n".join(
                f"  {gw}: {count}" for gw, count in sorted(
                    self.stats["gateways_found"].items(),
                    key=lambda x: x[1], reverse=True
                )[:10]
            )
            sites_with_forms = sum(1 for s in results if s.form_actions)
            sites_with_params = sum(1 for s in results if s.has_params)
            avg_val = sum(s.value_score for s in results) / max(len(results), 1)
            await report_callback(
                f"\u2705 <b>Discovery v2 Complete</b>\n\n"
                f"\U0001f3af <b>{len(results)}</b> payment sites\n"
                f"\U0001f4dd {sites_with_forms} with payment forms\n"
                f"\U0001f517 {sites_with_params} with parameters\n"
                f"\U0001f48e Avg value: {avg_val:.0%}\n"
                f"\u23f1 Time: {elapsed:.0f}s\n"
                f"\U0001f50d Dork queries: {self.stats['dork_queries']}\n"
                f"\U0001f4dc CT queries: {self.stats['ct_queries']}\n"
                f"\U0001f6d2 Checkout crawls: {self.stats['checkout_crawls']}\n"
                f"\U0001f4dd Form analyses: {self.stats['form_analyses']}\n\n"
                f"<b>Gateways:</b>\n{gw_breakdown}"
            )
        return results

    def stop(self):
        self._running = False

    def get_injectable_urls(self) -> List[str]:
        return [s.url for s in self.discovered.values() if s.has_params]

    def get_all_urls(self) -> List[str]:
        return [s.url for s in sorted(
            self.discovered.values(),
            key=lambda s: (s.value_score, s.confidence, s.has_params),
            reverse=True,
        )]

    def get_checkout_urls(self) -> List[str]:
        urls = []
        for site in self.discovered.values():
            urls.extend(site.checkout_urls)
            urls.extend(site.form_actions)
        return list(set(urls))

    def get_high_value_sites(self, min_value: float = 0.5) -> List[DiscoveredSite]:
        return sorted(
            [s for s in self.discovered.values() if s.value_score >= min_value],
            key=lambda s: s.value_score, reverse=True,
        )

    def get_domains(self) -> List[str]:
        return list(self.discovered.keys())

    def get_stats_summary(self) -> str:
        gw_lines = []
        for gw, count in sorted(
            self.stats["gateways_found"].items(), key=lambda x: x[1], reverse=True
        ):
            gw_lines.append(f"  {gw}: {count}")
        sites_with_forms = sum(1 for s in self.discovered.values() if s.form_actions)
        sites_with_ckout = sum(1 for s in self.discovered.values() if s.checkout_urls)
        yield_rate = self.dork_scorer.get_yield_rate()
        top_dorks = self.dork_scorer.get_top(5)

        return (
            f"Payment Discovery v2 Stats:\n"
            f"  Total Sites: {self.found_count}\n"
            f"  Sites w/ Payment Forms: {sites_with_forms}\n"
            f"  Sites w/ Checkout URLs: {sites_with_ckout}\n"
            f"  Dork Queries: {self.stats['dork_queries']}\n"
            f"  CT Queries: {self.stats['ct_queries']}\n"
            f"  Checkout Crawls: {self.stats['checkout_crawls']}\n"
            f"  Wayback Queries: {self.stats['wayback_queries']}\n"
            f"  Sitemap Parses: {self.stats['sitemap_parses']}\n"
            f"  Form Analyses: {self.stats['form_analyses']}\n"
            f"  Yield Rate: {yield_rate:.1%}\n"
            f"\nTop Dorks:\n" + "\n".join(f"  {d}: {s:.2f}" for d, s in top_dorks) +
            f"\n\nGateway Breakdown:\n" + "\n".join(gw_lines)
        )
