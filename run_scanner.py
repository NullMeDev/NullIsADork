#!/usr/bin/env python3
"""
MadyDorker — VULNERABILITY SCANNER BOT
Focused on: SQLi, XSS, SSTI, LFI, SSRF, CORS, CRLF, port scanning,
            OOB SQLi, union dumping, NoSQL injection, redirect vulns.
Also keeps card/secret detection active as a bonus.

Runs as a separate Telegram bot from the card scanner.
"""

import os
from config_v3 import DorkerConfig
from main_v3 import main

def build_scanner_config() -> DorkerConfig:
    """Create a scanner-focused config with all vuln scanners enabled."""
    config = DorkerConfig()

    # ── Bot identity (separate scanner bot token) ──
    config.telegram_bot_token = os.getenv(
        "SCANNER_BOT_TOKEN", "8429617965:AAHbgHvX7-JWZPKJCD-7NR2xTQqCuv2-vSI"
    )
    # Same channel for both bots
    config.telegram_chat_id = os.getenv("DORKER_CHAT_ID", "-1003720958643")
    config.telegram_group_id = os.getenv("DORKER_GROUP_ID", "-1003720958643")

    # ── Separate database to avoid lock contention ──
    config.sqlite_db_path = os.path.join(os.path.dirname(__file__), "dorker_scanner.db")

    # ── ENABLE all vulnerability scanners ──
    config.sqli_enabled = True
    config.dumper_enabled = True
    config.dumper_blind_enabled = True
    config.port_scan_enabled = True
    config.oob_sqli_enabled = True
    config.union_dump_enabled = True
    config.xss_enabled = True
    config.ssti_enabled = True
    config.nosql_enabled = True
    config.lfi_enabled = True
    config.ssrf_enabled = True
    config.cors_enabled = True
    config.redirect_enabled = True
    config.crlf_enabled = True
    config.auto_dump_nosql = True
    config.deep_crawl_sqli_limit = 120

    # ── Card features stay ON (bonus detections) ──
    config.secret_extraction_enabled = True
    config.cookie_extraction_enabled = True
    config.cookie_hunter_enabled = True
    config.ecom_checker_enabled = True
    config.js_analysis_enabled = True
    config.api_bruteforce_enabled = True
    config.key_validation_enabled = True
    config.ml_filter_enabled = True
    config.deep_crawl_enabled = True

    # ── Storage/exports in scanner-specific dirs ──
    config.found_sites_file = os.path.join(os.path.dirname(__file__), "found_sites_scanner.json")
    config.seen_domains_file = os.path.join(os.path.dirname(__file__), "seen_domains_scanner.txt")
    config.vulnerable_urls_file = os.path.join(os.path.dirname(__file__), "vulnerable_urls_scanner.json")
    config.gateway_keys_file = os.path.join(os.path.dirname(__file__), "gateway_keys_scanner.json")
    config.dumper_output_dir = os.path.join(os.path.dirname(__file__), "dumps_scanner")

    return config


if __name__ == "__main__":
    main(build_scanner_config())
