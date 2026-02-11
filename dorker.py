#!/usr/bin/env python3
"""
Medin Dorker - Automated site discovery tool

Continuously searches for viable payment gateway sites and sends
findings to Telegram.

Usage:
    python dorker.py [--config config.json] [--once]
    
Environment Variables:
    DORKER_BOT_TOKEN - Telegram bot token
    DORKER_CHAT_ID - Telegram chat ID to send results
"""

import os
import sys
import json
import random
import asyncio
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict, Optional

from loguru import logger

# Add parent paths
sys.path.insert(0, str(Path(__file__).parent))

from config import DorkerConfig, config as default_config
from engines import MultiSearch
from validator import SiteValidator, SiteInfo
from notifier import TelegramNotifier


class Dorker:
    """Main dorking engine."""
    
    def __init__(self, config: DorkerConfig):
        self.config = config
        self.seen_domains: Set[str] = set()
        self.found_sites: List[Dict] = []
        self.search_count = 0
        self.valid_count = 0
        self.cycle_count = 0
        self.error_count = 0
        self.start_time = datetime.now()
        
        # Initialize components
        logger.info("=" * 60)
        logger.info("INITIALIZING MEDIN DORKER")
        logger.info("=" * 60)
        
        self.proxies = self._load_proxies()
        logger.info(f"Proxy count: {len(self.proxies)}")
        
        self.search = MultiSearch(self.proxies)
        logger.info("Search engine initialized")
        
        self.validator = SiteValidator(
            skip_domains=config.skip_domains,
            timeout=config.validation_timeout
        )
        logger.info(f"Validator initialized (timeout: {config.validation_timeout}s, skip_domains: {len(config.skip_domains)})")
        
        self.notifier = TelegramNotifier(
            config.telegram_bot_token,
            config.telegram_chat_id
        )
        logger.info(f"Telegram notifier initialized (chat_id: {config.telegram_chat_id[:10]}...)")
        
        # Load previous state
        self._load_state()
        
        logger.info(f"Total dorks configured: {len(config.dorks)}")
        logger.info("=" * 60)
    
    def _load_proxies(self) -> List[str]:
        """Load proxies from file."""
        proxy_file = Path(self.config.proxy_file)
        if not proxy_file.exists():
            logger.error(f"Proxy file not found: {proxy_file}")
            return []
        
        proxies = []
        with open(proxy_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    # Convert to URL format if needed
                    original = line
                    if not line.startswith("http"):
                        # Assume format: host:port:user:pass or host:port
                        parts = line.split(":")
                        if len(parts) == 4:
                            host, port, user, passwd = parts
                            line = f"http://{user}:{passwd}@{host}:{port}"
                        elif len(parts) == 2:
                            line = f"http://{line}"
                    proxies.append(line)
                    logger.debug(f"Loaded proxy #{len(proxies)}: {original[:30]}...")
        
        logger.info(f"Loaded {len(proxies)} proxies from {proxy_file}")
        return proxies
    
    def _load_state(self):
        """Load previous state from files."""
        # Load seen domains
        seen_file = Path(self.config.seen_domains_file)
        if seen_file.exists():
            with open(seen_file, "r") as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        self.seen_domains.add(domain)
            logger.info(f"Loaded {len(self.seen_domains)} previously seen domains")
        else:
            logger.info("No previous seen_domains.txt found, starting fresh")
        
        # Load found sites
        found_file = Path(self.config.found_sites_file)
        if found_file.exists():
            try:
                with open(found_file, "r") as f:
                    self.found_sites = json.load(f)
                logger.info(f"Loaded {len(self.found_sites)} previously found sites")
                # Log each previously found site
                for site in self.found_sites:
                    logger.debug(f"Previously found: {site.get('domain')} (score: {site.get('score')})")
            except json.JSONDecodeError as e:
                logger.error(f"Could not load found sites file: {e}")
        else:
            logger.info("No previous found_sites.json found, starting fresh")
    
    def _save_state(self):
        """Save current state to files."""
        # Save seen domains
        with open(self.config.seen_domains_file, "w") as f:
            for domain in sorted(self.seen_domains):
                f.write(domain + "\n")
        
        # Save found sites
        with open(self.config.found_sites_file, "w") as f:
            json.dump(self.found_sites, f, indent=2, default=str)
        
        logger.debug(f"State saved: {len(self.seen_domains)} domains, {len(self.found_sites)} sites")
    
    def _log_stats(self):
        """Log current statistics."""
        runtime = datetime.now() - self.start_time
        hours = runtime.total_seconds() / 3600
        
        stats = (
            f"STATS | Runtime: {runtime} | "
            f"Cycles: {self.cycle_count} | "
            f"Searches: {self.search_count} | "
            f"Valid sites: {self.valid_count} | "
            f"Domains seen: {len(self.seen_domains)} | "
            f"Errors: {self.error_count} | "
            f"Rate: {self.valid_count/max(hours, 0.01):.1f} sites/hour"
        )
        logger.info(stats)
    
    def _is_new_domain(self, url: str) -> bool:
        """Check if URL's domain is new."""
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            is_new = domain not in self.seen_domains
            if not is_new:
                logger.debug(f"Domain already seen: {domain}")
            return is_new
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return False
    
    def _mark_domain_seen(self, domain: str):
        """Mark a domain as seen."""
        if domain.startswith("www."):
            domain = domain[4:]
        self.seen_domains.add(domain.lower())
    
    async def process_dork(self, dork: str, dork_num: int, total_dorks: int) -> List[SiteInfo]:
        """
        Process a single dork query.
        
        Args:
            dork: The search query
            dork_num: Current dork number in cycle
            total_dorks: Total dorks in cycle
            
        Returns:
            List of valid SiteInfo objects
        """
        logger.info(f"[{dork_num}/{total_dorks}] Processing dork: {dork}")
        logger.debug(f"SEARCH | Dork: {dork}")
        
        # Search
        try:
            urls = await self.search.search(dork, self.config.results_per_dork)
            self.search_count += len(urls)
            logger.info(f"SEARCH | Results: {len(urls)} URLs found")
            
            if urls:
                for i, url in enumerate(urls[:5], 1):
                    logger.debug(f"SEARCH | URL {i}: {url}")
                if len(urls) > 5:
                    logger.debug(f"SEARCH | ... and {len(urls) - 5} more URLs")
        except Exception as e:
            logger.error(f"SEARCH | Error during search: {e}")
            self.error_count += 1
            return []
        
        if not urls:
            logger.warning(f"SEARCH | No results from any search engine for: {dork[:50]}...")
            return []
        
        # Filter to new domains only
        new_urls = [url for url in urls if self._is_new_domain(url)]
        logger.info(f"SEARCH | New domains: {len(new_urls)} out of {len(urls)}")
        
        if not new_urls:
            logger.debug("SEARCH | All domains already seen, skipping validation")
            return []
        
        # Validate new URLs
        logger.info(f"VALIDATE | Starting validation of {len(new_urls)} URLs...")
        try:
            valid_sites = await self.validator.validate_many(
                new_urls,
                self.config.max_concurrent_validations
            )
            logger.info(f"VALIDATE | Valid sites found: {len(valid_sites)}")
        except Exception as e:
            logger.error(f"VALIDATE | Error during validation: {e}")
            self.error_count += 1
            valid_sites = []
        
        # Mark domains as seen and save valid sites
        for site in valid_sites:
            self._mark_domain_seen(site.domain)
            
            # Log detailed site info
            logger.info(
                f"VALID_SITE | Domain: {site.domain} | "
                f"Score: {site.score} | "
                f"Platform: {site.platform} | "
                f"PK: {site.pk_key[:30] if site.pk_key else 'None'}... | "
                f"Captcha: {site.has_captcha} | "
                f"Cloudflare: {site.has_cloudflare}"
            )
            
            if site.score >= 20:  # Only keep somewhat viable sites
                self.found_sites.append(site.to_dict())
                self.valid_count += 1
                logger.info(f"SITE_FOUND | {site.domain} (score: {site.score}) added to found_sites.json")
        
        # Also mark failed URLs as seen
        for url in new_urls:
            from urllib.parse import urlparse
            try:
                domain = urlparse(url).netloc.lower()
                self._mark_domain_seen(domain)
            except Exception as e:
                logger.debug(f"Failed to mark domain seen: {e}")
        
        return valid_sites
    
    async def run_cycle(self) -> List[SiteInfo]:
        """
        Run one full cycle through all dorks.
        
        Returns:
            All valid sites found in this cycle
        """
        self.cycle_count += 1
        logger.info("=" * 60)
        logger.info(f"STARTING CYCLE #{self.cycle_count}")
        logger.info("=" * 60)
        self._log_stats()
        
        all_valid = []
        
        # Randomize dork order
        dorks = self.config.dorks.copy()
        random.shuffle(dorks)
        total_dorks = len(dorks)
        
        logger.info(f"Processing {total_dorks} dorks in random order")
        
        for i, dork in enumerate(dorks, 1):
            try:
                valid_sites = await self.process_dork(dork, i, total_dorks)
                all_valid.extend(valid_sites)
                
                # Notify for high-score sites immediately
                for site in valid_sites:
                    if site.score >= 50:
                        logger.info(f"HIGH_SCORE_SITE | Sending Telegram notification for {site.domain} (score: {site.score})")
                        try:
                            await self.notifier.send_site_found(site)
                            logger.info(f"Telegram notification sent for {site.domain}")
                        except Exception as e:
                            logger.error(f"Failed to send Telegram notification: {e}")
                            self.error_count += 1
                
                # Random delay between dorks
                delay = random.uniform(
                    self.config.search_delay_min,
                    self.config.search_delay_max
                )
                logger.debug(f"Waiting {delay:.1f}s before next dork...")
                await asyncio.sleep(delay)
                
                # Save state and log stats periodically
                if i % 5 == 0:
                    self._save_state()
                    self._log_stats()
                    
            except Exception as e:
                logger.error(f"Error processing dork '{dork[:40]}...': {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                self.error_count += 1
                
                try:
                    await self.notifier.send_error(f"Dork error: {str(e)[:200]}")
                except Exception as e2:
                    logger.debug(f"Failed to send dork error notification: {e2}")
                await asyncio.sleep(5)
        
        # Save state after cycle
        self._save_state()
        
        # Log cycle summary
        logger.info("=" * 60)
        logger.info(f"CYCLE #{self.cycle_count} COMPLETE")
        logger.info(f"Sites found this cycle: {len(all_valid)}")
        viable_sites = [s for s in all_valid if s.score >= 20]
        logger.info(f"Viable sites (score >= 20): {len(viable_sites)}")
        self._log_stats()
        logger.info("=" * 60)
        
        # Send batch summary if we found sites
        if viable_sites:
            try:
                await self.notifier.send_sites_batch(viable_sites)
                logger.info(f"Sent batch summary for {len(viable_sites)} sites")
            except Exception as e:
                logger.error(f"Failed to send batch summary: {e}")
        
        return all_valid
    
    async def run(self, once: bool = False):
        """
        Main run loop.
        
        Args:
            once: If True, run only one cycle then exit
        """
        logger.info("=" * 60)
        logger.info("MEDIN DORKER STARTING")
        logger.info(f"Mode: {'Single cycle' if once else 'Infinite loop'}")
        logger.info(f"Dorks: {len(self.config.dorks)}")
        logger.info(f"Proxies: {len(self.proxies)}")
        logger.info(f"Cycle delay: {self.config.cycle_delay}s")
        logger.info("=" * 60)
        
        # Send startup notification
        try:
            await self.notifier.send_startup(
                len(self.config.dorks),
                len(self.proxies)
            )
            logger.info("Startup notification sent to Telegram")
        except Exception as e:
            logger.error(f"Failed to send startup notification: {e}")
        
        cycle_errors = 0
        
        while True:
            try:
                # Run a cycle
                await self.run_cycle()
                cycle_errors = 0  # Reset on success
                
                if once:
                    logger.info("Single cycle complete, exiting")
                    break
                
                # Wait before next cycle
                logger.info(f"Waiting {self.config.cycle_delay}s before next cycle...")
                await asyncio.sleep(self.config.cycle_delay)
                
            except KeyboardInterrupt:
                logger.info("Interrupted by user (Ctrl+C)")
                break
            except Exception as e:
                cycle_errors += 1
                logger.error(f"CRITICAL | Cycle error #{cycle_errors}: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                self.error_count += 1
                
                try:
                    await self.notifier.send_error(f"Critical error: {str(e)}")
                except Exception as e2:
                    logger.debug(f"Failed to send critical error notification: {e2}")
                
                # Exponential backoff on repeated errors
                wait_time = min(60 * cycle_errors, 600)  # Max 10 min
                logger.info(f"Waiting {wait_time}s before retrying...")
                await asyncio.sleep(wait_time)
        
        # Final save
        self._save_state()
        self._log_stats()
        logger.info("=" * 60)
        logger.info("MEDIN DORKER STOPPED")
        logger.info(f"Final stats: {self.search_count} searched, {self.valid_count} valid, {self.error_count} errors")
        logger.info("=" * 60)


def load_config_file(path: str) -> DorkerConfig:
    """Load config from JSON file."""
    with open(path, "r") as f:
        data = json.load(f)
    
    config = DorkerConfig()
    for key, value in data.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    return config


def setup_logging(debug: bool = False):
    """Setup comprehensive logging with separate files."""
    from pathlib import Path
    
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    log_level = "DEBUG" if debug else "INFO"
    logger.remove()
    
    # Console output - colorful and readable
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>"
    )
    
    # Main log - everything
    logger.add(
        log_dir / "dorker_main.log",
        rotation="10 MB",
        retention="7 days",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}"
    )
    
    # Errors only - for quick debugging
    logger.add(
        log_dir / "dorker_errors.log",
        rotation="5 MB",
        retention="7 days",
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}"
    )
    
    # Sites found - successful discoveries
    logger.add(
        log_dir / "sites_found.log",
        rotation="5 MB",
        retention="30 days",
        level="INFO",
        filter=lambda record: "SITE_FOUND" in record["message"] or "VALID_SITE" in record["message"],
        format="{time:YYYY-MM-DD HH:mm:ss} | {message}"
    )
    
    # Search results - what each search engine returns
    logger.add(
        log_dir / "search_results.log",
        rotation="10 MB",
        retention="3 days",
        level="DEBUG",
        filter=lambda record: "SEARCH" in record["message"],
        format="{time:YYYY-MM-DD HH:mm:ss} | {message}"
    )
    
    # Validation results - site checking details
    logger.add(
        log_dir / "validation.log",
        rotation="10 MB",
        retention="3 days",
        level="DEBUG",
        filter=lambda record: "VALIDATE" in record["message"],
        format="{time:YYYY-MM-DD HH:mm:ss} | {message}"
    )
    
    # Stats log - periodic statistics
    logger.add(
        log_dir / "stats.log",
        rotation="5 MB",
        retention="7 days",
        level="INFO",
        filter=lambda record: "STATS" in record["message"],
        format="{time:YYYY-MM-DD HH:mm:ss} | {message}"
    )
    
    logger.info(f"Logging initialized. Log directory: {log_dir}")
    return log_dir


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Medin Dorker - Site discovery tool")
    parser.add_argument(
        "--config", "-c",
        help="Path to config JSON file",
        default=None
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run only one cycle then exit"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--token",
        help="Telegram bot token (overrides config/env)",
        default=None
    )
    parser.add_argument(
        "--chat",
        help="Telegram chat ID (overrides config/env)",
        default=None
    )
    
    args = parser.parse_args()
    
    # Setup comprehensive logging
    log_dir = setup_logging(args.debug)
    
    # Load config
    if args.config:
        config = load_config_file(args.config)
    else:
        config = default_config
    
    # Override with CLI args
    if args.token:
        config.telegram_bot_token = args.token
    if args.chat:
        config.telegram_chat_id = args.chat
    
    # Validate config
    if not config.telegram_bot_token or not config.telegram_chat_id:
        logger.warning("Telegram not configured - notifications will be disabled")
        logger.warning("Set DORKER_BOT_TOKEN and DORKER_CHAT_ID environment variables")
        logger.warning("Or use --token and --chat arguments")
    
    # Run
    dorker = Dorker(config)
    asyncio.run(dorker.run(once=args.once))


if __name__ == "__main__":
    main()
