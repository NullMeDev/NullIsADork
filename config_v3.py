"""
MadyDorker v3.0 — Master Configuration

Full-pipeline config: Dorker → Scanner → Exploiter → Dumper → Reporter
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DorkerConfig:
    """Configuration for MadyDorker v3.0."""

    # =============== TELEGRAM ===============
    telegram_bot_token: str = os.getenv(
        "DORKER_BOT_TOKEN", "8187477232:AAFKPHOiLduYeYr5sqLf-0C5grtPI9OzXzE"
    )
    telegram_chat_id: str = os.getenv("DORKER_CHAT_ID", "-1003720958643")
    telegram_group_id: str = os.getenv(
        "DORKER_GROUP_ID", "-1003720958643"
    )  # Channel for ALL findings

    # =============== DORK GENERATOR ===============
    params_dir: str = os.path.join(os.path.dirname(__file__), "params")
    custom_dork_file: str = os.path.join(
        os.path.dirname(__file__), "params", "custom_dorks.txt"
    )
    max_dorks: int = 3300000
    max_per_pattern: int = 800
    dork_shuffle: bool = True

    # =============== SEARCH ENGINE ===============
    search_delay_min: int = 3
    search_delay_max: int = 8
    results_per_dork: int = 50
    engines: List[str] = field(
        default_factory=lambda: [
            "duckduckgo",
            "bing",
            "startpage",
            "yahoo",
            "ecosia",
            "qwant",
            "brave",
            "aol",
            "yandex",
            "ask",
            "dogpile",
            "searxng",
            "you",
            "mojeek",
            "naver",
        ]
    )
    engine_shuffle: bool = True
    engine_fallback: bool = True

    # =============== PROXY ===============
    use_proxies: bool = True  # 990+ working proxies on server
    proxy_files: List[str] = field(
        default_factory=lambda: [
            "/home/nulladmin/NullIsADork/proxies.csv",  # Server path (primary)
        ]
    )
    proxy_file: str = os.path.join(
        os.path.dirname(__file__), "proxies.txt"
    )  # Legacy fallback
    proxy_rotation_strategy: str = (
        "weighted"  # round_robin, random, least_recently_used, weighted
    )
    proxy_ban_threshold: int = 5  # Consecutive failures before auto-ban
    proxy_ban_duration: int = 600  # Seconds to ban a failing proxy
    proxy_health_check: bool = True  # Test proxies on startup
    proxy_health_interval: int = 300  # Seconds between background health checks
    proxy_health_timeout: int = 10  # Timeout per proxy health check
    proxy_country_filter: List[str] = field(default_factory=list)  # e.g. ["US", "CA"]
    proxy_sticky_per_domain: int = 3  # Use same proxy for N requests to same domain
    proxy_protocol: str = "http"  # http, https, socks5
    proxy_timeout: int = 15
    rotate_proxy_every: int = 5  # Legacy (unused with new manager)

    # =============== FIRECRAWL ===============
    firecrawl_api_key: str = os.getenv("FIRECRAWL_API_KEY", "")
    firecrawl_enabled: bool = True
    firecrawl_search_limit: int = 80  # Results per search query
    firecrawl_scrape_enabled: bool = True  # Use FC to scrape target pages
    firecrawl_crawl_enabled: bool = True  # Use FC for /scan domain crawls
    firecrawl_crawl_limit: int = 400  # Max pages per crawl
    firecrawl_as_fallback: bool = False  # If True, only use when other engines fail
    firecrawl_scrape_formats: List[str] = field(
        default_factory=lambda: ["markdown", "html", "links"]
    )
    firecrawl_timeout: int = 30000  # 30s in milliseconds
    firecrawl_proxy_mode: str = "auto"  # "basic", "enhanced", "auto"

    # =============== HEADLESS BROWSER (search resilience) ===============
    browser_enabled: bool = True  # Enable Playwright headless browser fallback
    browser_headless: bool = True  # Run headless (no visible window)
    browser_max_concurrent: int = 32  # Max concurrent browser tabs
    browser_page_timeout: int = 25000  # Nav timeout per page (ms)
    browser_engines: List[str] = field(
        default_factory=lambda: [
            "google",
            "bing",
            "duckduckgo",
            "startpage",
        ]
    )  # Engines to try in headless mode (ordered)

    # =============== CAPTCHA SOLVER ===============
    captcha_enabled: bool = True
    captcha_twocaptcha_key: str = os.getenv("TWOCAPTCHA_API_KEY", "")
    captcha_nopecha_key: str = os.getenv(
        "NOPECHA_API_KEY", "sub_1PrBQ7CRwBwvt6ptAKlQl20U"
    )
    captcha_anticaptcha_key: str = os.getenv("ANTICAPTCHA_API_KEY", "")
    captcha_provider_order: List[str] = field(
        default_factory=lambda: ["nopecha", "2captcha", "anticaptcha"]
    )
    captcha_max_solve_time: int = 180  # Max seconds per solve attempt
    captcha_auto_solve_search: bool = True  # Solve captchas blocking search engines
    captcha_auto_solve_target: bool = True  # Solve captchas on scanned target sites
    captcha_budget_limit: float = 0.0  # Max $ to spend per session (0=unlimited)
    captcha_max_per_domain: int = 3  # Max solve attempts per domain

    # =============== WAF DETECTION ===============
    waf_detection_enabled: bool = True
    waf_skip_extreme: bool = True  # Skip targets with extreme protection
    waf_skip_high: bool = False
    waf_timeout: int = 10
    waf_max_concurrent: int = 200

    # =============== SECRET EXTRACTION ===============
    secret_extraction_enabled: bool = True
    secret_timeout: int = 10
    secret_max_concurrent: int = 200
    # Secret types to suppress from Telegram reporting (noise/non-actionable)
    suppressed_secret_types: List[str] = field(
        default_factory=lambda: [
            "jwt",              # JWTs are short-lived, worthless by the time they're found
            "bearer",           # Same — ephemeral bearer tokens
            "password",         # Hardcoded passwords from docs/examples
            "email_password",   # Combo from docs/HTML, almost always fake
            "wp_nonce",         # WordPress nonces — per-session, useless
            "wp_ajax_url",      # Just a URL, not a secret
            "wc_ajax_url",      # WooCommerce AJAX endpoint, not a secret
            "generic_merchant", # Low-confidence merchant ID fragments
            "mapbox_token",     # Public mapbox tokens (pk.*) are not secrets
            "env_var",          # ENV var references, not actual values
            "db_host",          # Database hostnames from config, not creds
            "discord_bot",      # Discord bot tokens from public docs/examples
            "generic_pk",       # Too broad — matches any "public_key=..." context
            "generic_sk",       # Too broad — matches any "secret_key=..." context
            "wc_checkout_nonce", # WooCommerce nonces, ephemeral like WP nonces
            "braintree_token_nonce",  # Nonce, not an actual token
            "stripe_pmc",       # PaymentMethodConfiguration IDs, not secrets
            "stripe_pi",        # Payment Intent IDs — public-facing order refs, NOT secrets
            "stripe_acct",      # Connect Account IDs — public identifiers, NOT secrets
            "stripe_client_secret",  # Client-side secrets from documentation, usually FP
        ]
    )

    # =============== SQL INJECTION SCANNER ===============
    sqli_enabled: bool = True
    sqli_timeout: int = 15
    sqli_max_concurrent: int = 100
    sqli_delay: int = 5  # For time-based injection
    sqli_techniques: List[str] = field(
        default_factory=lambda: ["error", "union", "boolean", "time"]
    )
    sqli_dbms: List[str] = field(
        default_factory=lambda: ["mysql", "mssql", "postgresql", "oracle", "sqlite"]
    )

    # =============== DATA DUMPER ===============
    dumper_enabled: bool = True
    dumper_max_rows: int = 1000
    dumper_timeout: int = 20
    dumper_output_dir: str = os.path.join(os.path.dirname(__file__), "dumps")
    dumper_targeted: bool = True  # Focus on card data tables
    dumper_dios: bool = True  # Try DIOS technique

    # Blind dumper (boolean + time-based extraction)
    dumper_blind_enabled: bool = True  # Enable blind char-by-char extraction
    dumper_blind_delay: float = 3.0  # Sleep delay for time-based (seconds)
    dumper_blind_max_rows: int = 50  # Max rows per table (blind is slow)
    dumper_blind_max_tables: int = 15  # Max tables to enumerate
    dumper_blind_max_string: int = 256  # Max chars per field extraction

    # =============== DEEP CRAWLER (v3.9 — Recursive BFS) ===============
    deep_crawl_enabled: bool = True
    deep_crawl_max_pages: int = (
        400  # Max pages per domain (full scan; pipeline uses quick_crawl)
    )
    deep_crawl_max_depth: int = 5  # Max BFS depth (0=seed only, 3=3 clicks deep)
    deep_crawl_timeout: int = 10  # Timeout per page fetch (seconds)
    deep_crawl_concurrent: int = 100  # Max concurrent page fetches
    deep_crawl_delay: float = 0.01  # Delay between fetches (rate limit)
    deep_crawl_robots: bool = False  # Respect robots.txt Disallow rules
    deep_crawl_sqli_limit: int = (
        120  # Max crawler-discovered param URLs to SQLi-test in pipeline
    )

    # =============== PORT SCANNER (v3.10) ===============
    port_scan_enabled: bool = True
    port_scan_timeout: float = 2.0  # Timeout per port probe (seconds)
    port_scan_concurrent: int = 600  # Max concurrent port probes
    port_scan_banner_timeout: float = 3.0  # Timeout for banner grabbing
    port_scan_banners: bool = True  # Enable banner grabbing
    port_scan_ports: str = (
        "quick"  # "quick" (31 ports), "extended" (~80), or comma-separated
    )

    # =============== OOB SQLi (v3.11) ===============
    oob_sqli_enabled: bool = (
        True  # Uses interact.sh for DNS exfil (no callback host needed)
    )
    oob_callback_host: str = ""  # Public IP/domain for HTTP callback server
    oob_callback_port: int = 0  # 0 = ephemeral random port
    oob_callback_timeout: float = 15.0  # Seconds to wait for callback
    oob_use_interactsh: bool = True  # Use interact.sh for DNS exfil
    oob_max_extractions: int = 10  # Max data items to extract per target

    # =============== MULTI-DBMS UNION DUMPER (v3.12) ===============
    union_dump_enabled: bool = True
    union_dump_max_tables: int = 60  # Max tables to dump per target
    union_dump_max_rows: int = 1000  # Max rows per table
    union_dump_timeout: float = 15.0  # Timeout per request
    union_dump_max_columns_per_table: int = 60

    # =============== API KEY VALIDATION (v3.13) ===============
    key_validation_enabled: bool = True
    key_validation_timeout: float = 10.0  # Timeout per API validation call
    key_validation_concurrent: int = 60  # Max concurrent validations
    key_validation_report_dead: bool = False  # Also report dead keys

    # =============== ML FALSE POSITIVE FILTER (v3.14) ===============
    ml_filter_enabled: bool = True
    ml_filter_threshold: float = 0.5  # Score below this → filtered as FP
    ml_filter_model_path: str = ""  # Path to saved model (empty = fresh)
    ml_filter_min_training_samples: int = 50  # Min samples before training ML model
    ml_filter_auto_train: bool = True  # Auto-train when enough data

    # =============== REPORTER ===============
    reporter_rate_limit: float = 0.25  # Min seconds between messages
    reporter_batch_size: int = 20
    reporter_status_interval: int = 3600  # Status update every N seconds
    report_gateways: bool = True
    report_cards: bool = True
    report_sqli: bool = True
    report_dumps: bool = True
    report_secrets: bool = True

    # =============== DOMAIN REVISIT & URL DEDUP ===============
    domain_revisit_hours: int = (
        1  # Hours before revisiting a domain (0 = never revisit)
    )
    url_dedup_enabled: bool = True  # Skip exact-same URLs permanently

    # =============== JS ANALYSIS & API BRUTEFORCE (autonomous pipeline) ===============
    js_analysis_enabled: bool = True  # JS bundle analysis in process_url()
    api_bruteforce_enabled: bool = True  # API endpoint bruteforce in process_url()
    subdomain_enum_enabled: bool = True  # Subdomain discovery via crt.sh + DNS brute
    dir_fuzz_enabled: bool = True  # Directory/file fuzzing for sensitive paths

    # =============== MADY BOT INTEGRATION ===============
    mady_bot_feed: bool = True  # Auto-feed found gateways to Mady bot
    mady_bot_path: str = os.getenv(
        "MADY_BOT_PATH", "/home/null/Desktop/Mady7.0.2/Mady_Version7.0.0"
    )
    mady_bot_chat_id: str = os.getenv(
        "MADY_BOT_CHAT_ID", "8385066318"
    )  # DM Mady Bot directly
    mady_feed_channel_id: str = os.getenv(
        "MADY_FEED_CHANNEL_ID", "-1003720958643"
    )  # Dedicated findings channel
    mady_feed_show_full_key: bool = True  # Show full key values in Telegram messages

    # =============== DAEMON MODE ===============
    continuous: bool = True
    cycle_delay: int = 15  # Seconds between dork cycles
    max_cycles: int = 0  # 0 = infinite
    auto_start_pipeline: bool = (
        True  # Auto-start dorking on bot startup (no /dorkon needed)
    )
    dorks_per_cycle: int = 50  # Dorks to process per cycle (rotates through full pool)
    cycle_max_time: int = 3600  # Max seconds per cycle (3600 = 1 hour)
    cycle_max_urls: int = 300  # Max URLs to process per cycle (0 = unlimited)
    url_process_timeout: int = 120  # Per-URL processing timeout (seconds)

    # =============== STORAGE ===============
    found_sites_file: str = os.path.join(os.path.dirname(__file__), "found_sites.json")
    seen_domains_file: str = os.path.join(os.path.dirname(__file__), "seen_domains.txt")
    vulnerable_urls_file: str = os.path.join(
        os.path.dirname(__file__), "vulnerable_urls.json"
    )
    gateway_keys_file: str = os.path.join(
        os.path.dirname(__file__), "gateway_keys.json"
    )
    sqlite_db_path: str = os.path.join(os.path.dirname(__file__), "dorker.db")
    use_sqlite: bool = True  # Use SQLite instead of JSON files

    # =============== SEARCH PAGINATION ===============
    search_max_pages: int = 15  # Search pages 1-5 per engine per dork
    engine_health_cooldown: int = 300  # Seconds to cool down a failing engine

    # =============== CONCURRENT PROCESSING ===============
    concurrent_url_limit: int = 160  # Max URLs processed in parallel

    # =============== CIRCUIT BREAKER ===============
    circuit_breaker_threshold: int = 3  # Failures before blocking domain
    circuit_breaker_timeout: int = 1800  # 30 minutes block

    # =============== EXTENDED VULNERABILITY SCANNERS (v3.17) ===============
    xss_enabled: bool = True  # XSS scanner (reflected/DOM/blind)
    ssti_enabled: bool = True  # Server-Side Template Injection
    nosql_enabled: bool = True  # NoSQL injection (MongoDB/CouchDB/Redis)
    lfi_enabled: bool = True  # Local File Inclusion / Path Traversal
    ssrf_enabled: bool = True  # Server-Side Request Forgery
    cors_enabled: bool = True  # CORS misconfiguration
    redirect_enabled: bool = True  # Open Redirect
    crlf_enabled: bool = True  # CRLF Injection / HTTP Response Splitting

    # =============== AUTO DUMPER (v3.18) ===============
    auto_dump_enabled: bool = True  # Unified dump orchestrator
    auto_dump_deeper_tables: bool = (
        True  # Re-dump when interesting tables found in schema
    )
    auto_dump_nosql: bool = True  # NoSQL blind extraction after NoSQL injection
    auto_dump_combo_gen: bool = True  # Generate user:pass / email:pass combos
    auto_dump_send_files: bool = True  # Upload dump files as Telegram documents
    auto_dump_validate_keys: bool = True  # Live-validate keys found in dumps
    auto_dump_hash_analysis: bool = True  # Identify password hash types

    # =============== COOKIE EXTRACTION ===============
    cookie_extraction_enabled: bool = True  # Extract cookies from every scanned URL
    cookie_injection_enabled: bool = True  # Test cookies for SQLi
    header_injection_enabled: bool = True  # Test headers for SQLi
    post_discovery_enabled: bool = True  # Discover & test POST forms
    b3_extraction_enabled: bool = True  # Prioritize b3 tracing cookies

    # =============== COOKIE HUNTER (v3.5) ===============
    cookie_hunter_enabled: bool = True  # Active B3 + gateway cookie hunting
    cookie_hunt_probe_checkout: bool = True  # Probe /checkout, /cart, /payment paths
    cookie_hunt_max_probes: int = 50  # Max checkout pages to probe per domain
    cookie_hunt_report_commerce: bool = True  # Also report generic commerce cookies
    cookie_hunt_report_b3: bool = False  # B3 tracing headers are noise — suppress Telegram reports
    cookie_hunt_report_html_gateways: bool = (
        True  # Report gateway SDK detections in HTML
    )

    # =============== E-COMMERCE CHECKER (v3.8) ===============
    ecom_checker_enabled: bool = (
        True  # Enable Shopify/WooCommerce/Magento/PrestaShop/OpenCart checks
    )
    ecom_max_probes: int = 80  # Max endpoint probes per platform per domain
    ecom_probe_timeout: int = 10  # Timeout per probe request (seconds)
    ecom_platforms: List[str] = field(
        default_factory=lambda: [
            "shopify",
            "woocommerce",
            "magento",
            "prestashop",
            "opencart",
        ]
    )

    # =============== SOFT-404 DETECTION ===============
    soft404_detection: bool = True
    soft404_similarity_threshold: float = (
        0.85  # Pages >85% similar to 404 are soft-404s
    )

    # =============== SKIP DOMAINS ===============
    skip_domains: List[str] = field(
        default_factory=lambda: [
            # Search engine redirect/tracking URLs (waste time, not real targets)
            "search.aol.com",
            "search.yahoo.com",
            "r.search.yahoo.com",
            "cc.bingj.com",
            "duckduckgo.com",
            "search.brave.com",
            "www.startpage.com",
            "search.qwant.com",
            "www.ecosia.org",
            "search.naver.com",
            "yandex.com",
            "yandex.ru",
            "search.dogpile.com",
            "www.ask.com",
            "www.mojeek.com",
            "you.com",
            "searx.org",
            "searxng.org",
            "www.google.com",
            "www.bing.com",
            # Code hosting / documentation
            "github.com",
            "github.io",
            "githubusercontent.com",
            "stackoverflow.com",
            "stackexchange.com",
            "stripe.com",
            "stripe.dev",
            "npmjs.com",
            "npmjs.org",
            "pypi.org",
            "pypi.python.org",
            "docs.google.com",
            "drive.google.com",
            "youtube.com",
            "youtu.be",
            "twitter.com",
            "x.com",
            "facebook.com",
            "fb.com",
            "linkedin.com",
            "reddit.com",
            "wikipedia.org",
            "wikimedia.org",
            "medium.com",
            "wordpress.org",
            "wordpress.com",
            "w3schools.com",
            "developer.mozilla.org",
            "mozilla.org",
            "apache.org",
            "docker.com",
            "heroku.com",
            "vercel.app",
            "netlify.app",
            "replit.com",
            "codepen.io",
            "jsfiddle.net",
            "pastebin.com",
            "archive.org",
            "web.archive.org",
            "amazon.com",
            "amazonaws.com",
            "microsoft.com",
            "apple.com",
            "google.com",
            "cloudflare.com",
            "akamai.com",
            "fastly.com",
            "bitbucket.org",
            "gitlab.com",
            "sourceforge.net",
            "example.com",
            "localhost",
            # Government / education / major corps (never vuln targets, waste time)
            "sec.gov",
            "irs.gov",
            "fbi.gov",
            "cia.gov",
            "nasa.gov",
            ".gov.uk",
            ".edu",
            "cam.ac.uk",
            "ox.ac.uk",
            "mit.edu",
            "harvard.edu",
            "stanford.edu",
            "icann.org",
            "ietf.org",
            "w3.org",
            "owasp.org",
            # Big platforms that waste scan time with no vuln exposure
            "upwork.com",
            "fiverr.com",
            "indeed.com",
            "glassdoor.com",
            "navercorp.com",
            "naver.com",
            "baidu.com",
            "alibabacloud.com",
            "alibaba.com",
            "tencent.com",
            "oracle.com",
            "salesforce.com",
            "ibm.com",
            "cisco.com",
            "adobe.com",
            "atlassian.com",
            "zendesk.com",
            "hubspot.com",
            # Documentation / reference sites
            "docs.python.org",
            "docs.djangoproject.com",
            "reactjs.org",
            "vuejs.org",
            "angular.io",
            "developer.android.com",
            "developer.apple.com",
            "learn.microsoft.com",
            "support.google.com",
            "help.yahoo.com",
            "fintechwrapup.com",
            # Payment gateway documentation sites (huge FP source)
            "api-reference.checkout.com",
            "docs.checkout.com",
            "checkout.com",
            "docs.stripe.com",
            "dashboard.stripe.com",
            "api.stripe.com",
            "developer.paypal.com",
            "docs.adyen.com",
            "adyen.com",
            "developer.squareup.com",
            "docs.square.com",
            "squareup.com",
            "braintree.com",
            "braintreepayments.com",
            "developer.authorize.net",
            "authorize.net",
            "docs.razorpay.com",
            "razorpay.com",
            "flutterwave.com",
            "developer.flutterwave.com",
            "paystack.com",
            "developers.paystack.co",
            "docs.mollie.com",
            "mollie.com",
            "recurly.com",
            "docs.recurly.com",
            "developer.worldpay.com",
            "worldpay.com",
            "developer.2checkout.com",
            "2checkout.com",
            "docs.klarna.com",
            "klarna.com",
            "developer.afterpay.com",
            "afterpay.com",
            # SDK / API reference sites (always contain example keys)
            "platform.openai.com",
            "docs.anthropic.com",
            "console.anthropic.com",
            "docs.aws.amazon.com",
            "console.aws.amazon.com",
            "cloud.google.com",
            "console.cloud.google.com",
            "docs.github.com",
            "api.github.com",
            "docs.gitlab.com",
            "api.twilio.com",
            "twilio.com",
            "sendgrid.com",
            "docs.sendgrid.com",
            "mailgun.com",
            "documentation.mailgun.com",
            "slack.com",
            "api.slack.com",
            "discord.com",
            "docs.shopify.com",
            "shopify.dev",
            # Fintech blogs / comparison sites
            "fintechwrapup.com",
            "fintechfutures.com",
            "hackernoon.com",
            "dev.to",
            "freecodecamp.org",
            "css-tricks.com",
            "smashingmagazine.com",
            "tutorialspoint.com",
            "geeksforgeeks.org",
            "baeldung.com",
            "digitalocean.com",
        ]
    )

    # =============== VALIDATION ===============
    validation_timeout: int = 15
    max_concurrent_validations: int = 120
    min_content_length: int = 500  # Skip pages with less content

    # =============== PRIORITY CATEGORIES ===============
    # (used by generator for weighted selection)
    primary_categories: List[str] = field(
        default_factory=lambda: [
            "cards",
            "gateways",
        ]
    )
    secondary_categories: List[str] = field(
        default_factory=lambda: [
            "secrets",
            "sqli",
            "databases",
            "cloud",
        ]
    )
