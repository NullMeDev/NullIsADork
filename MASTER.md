# MedyDorker v3.1 — Master Documentation

## What Is This Project?

MedyDorker is an automated **Google dorking + SQL injection exploitation + data dumping** pipeline, controlled via a **Telegram bot**. It runs 24/7, autonomously generating search dorks, finding vulnerable URLs across the internet, testing them for SQL injection, exploiting any found vulnerabilities, and dumping databases — all while reporting findings in real-time to a Telegram chat.

The tool is designed for finding:
- **Payment gateway API keys** (Stripe, Braintree, PayPal, Square, Adyen, etc.)
- **SQL injection vulnerabilities** across discovered websites
- **Credit card data** from exploited databases (via DIOS/union-based extraction)
- **Secrets & credentials** (API keys, tokens, passwords, cloud keys)
- **Session/auth/B3 distributed tracing cookies** from scanned targets

It is inspired by tools like XDumpGO but rebuilt from scratch with a modern Python async architecture.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                  TELEGRAM BOT                         │
│  /dorkon /scan /cookies /status /secrets /dumps       │
└──────────────┬───────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────┐
│              MedyDorkerPipeline (main_v3.py)          │
│  Orchestrates the full pipeline, concurrent scans     │
│  Semaphore-bounded, circuit breaker, soft-404         │
└──┬────┬────┬────┬────┬────┬────┬────┬────────────────┘
   │    │    │    │    │    │    │    │
   ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
 Dork  Search WAF  Secret SQLi  SQLi  Report Persist
 Gen   Engine Det  Extract Scan  Dump  er     ence
```

### Module Inventory (11,360 lines total)

| Module | Lines | Purpose |
|--------|-------|---------|
| `main_v3.py` | 1,942 | Pipeline orchestrator + Telegram bot handlers |
| `sqli_scanner.py` | 1,391 | SQL injection testing (URL + cookie + header + POST) |
| `secret_extractor.py` | 982 | 83-pattern secret/key scraper + deep site crawler |
| `waf_detector.py` | 809 | WAF/CDN/bot protection/CMS detection + bypass encoders |
| `sqli_dumper.py` | 755 | Database exploitation, DIOS extraction, card/cred/key dumping |
| `engines.py` | 656 | 8 search engines with health tracking, pagination, adaptive rate limiting |
| `dork_generator.py` | 566 | 35 pattern templates + 214 static dorks = 12,866+ unique dorks |
| `persistence.py` | 563 | SQLite database (13 tables), circuit breaker, content dedup |
| `reporter.py` | 455 | Telegram message formatting + delivery |
| `config_v3.py` | 187 | All configuration with dataclass defaults |

### Supporting Files

| File | Purpose |
|------|---------|
| `params/kw.txt` | 303 keyword values for dork generation |
| `params/pp.txt` | 135 payment provider strings |
| `params/de.txt` | 88 database error strings |
| `params/pf.txt` | 61 platform fingerprints |
| `params/pt.txt` | 17 payment terminology strings |
| `params/sf.txt` | 12 SQL fingerprint strings |
| `requirements_v3.txt` | Python dependencies |
| `seen_domains.txt` | Previously scanned domains (legacy, now in SQLite) |
| `gateway_keys.json` | Found gateway keys (legacy, now in SQLite) |

---

## What the Bot Does

### Telegram Commands

| Command | Function |
|---------|----------|
| `/dorkon` | Start the 24/7 autonomous dorking pipeline |
| `/dorkoff` | Stop the pipeline |
| `/scan <url>` | **Full domain scan** — crawls up to 100 pages, extracts all cookies, tests up to 50 endpoints for SQLi (URL + cookie + header + POST injection), dumps data if exploitable |
| `/deepscan <url>` | Alias for `/scan` |
| `/stopscan` | Cancel a running scan |
| `/status` | Stats: uptime, URLs scanned, findings, cookies, blocked domains |
| `/cookies` | Show ALL extracted cookies grouped by domain (b3, session, auth, other) |
| `/secrets` | Show found gateway keys and other secrets |
| `/dumps` | Show saved database dumps |
| `/sqlistats` | SQLi vulnerability stats |
| `/dorkstats` | Dork generator stats |
| `/categories` | Available dork categories |
| `/target <cat>` | Targeted scan for a specific category (cards, gateways, secrets, sqli, databases, cloud) |

### Autonomous Pipeline (`/dorkon`)

When started, the pipeline runs indefinitely in cycles:

1. **Dork Generation** — generates 12,866+ unique dorks from 35 templates × 616 keyword combinations + 214 static dorks
2. **Dork Scoring** — sorts dorks by past effectiveness (productive dorks first, with exploration interleaving)
3. **Search** — queries 8 search engines (DuckDuckGo, Bing, Startpage, Yahoo, Ecosia, Qwant, Brave, AOL) with health tracking, pagination (up to 3 pages per engine), and adaptive rate limiting
4. **URL Filtering** — skips seen domains, circuit-breaker blocked domains, and soft-404 pages
5. **Priority Queuing** — sorts discovered URLs by injection likelihood (id=, cat=, pid= params first)
6. **Concurrent Processing** — processes URLs concurrently (semaphore-bounded, default 5)
7. **Per-URL Pipeline**:
   - Soft-404 detection (similarity threshold 0.85)
   - Content deduplication (MD5 hash)
   - WAF detection (60+ signatures) + risk assessment
   - Cookie extraction (all cookies categorized: session, auth, b3, tracking)
   - Secret extraction (83 patterns, deep site crawl with payment page discovery)
   - SQLi testing:
     - URL parameter injection (smart ordering)
     - Cookie value injection
     - Header injection (10 injectable headers)
     - POST form parameter injection
     - WAF-specific bypass payloads (6 WAFs)
     - Technology-based DBMS targeting
   - Data dumping (if union/error-based SQLi found):
     - Targeted table discovery (cards, users, customers, orders, payments)
     - DIOS extraction
     - Card data extraction
     - Credential extraction
     - Gateway key extraction
8. **Real-time Reporting** — every finding goes to Telegram immediately
9. **SQLite Persistence** — all state saved to `dorker.db`

### Manual Scan (`/scan <url>`)

The most comprehensive scanner — 5 phases:

1. **Phase 1: WAF + Cookies + Tech Detection**
   - WAF/CDN/CMS fingerprinting
   - Cookie extraction from main page (session, auth, b3, tracking)
   - Server technology detection

2. **Phase 2: Deep Secret Extraction**
   - Scans main page + discovers payment pages + checkout flows
   - 83-pattern regex matching for API keys, tokens, credentials
   - Endpoint discovery (AJAX, REST, forms, admin, login, file upload)

3. **Phase 3: Full Domain Crawl**
   - Follows all internal links (up to 100 pages)
   - Parses `<a>`, `<form>`, `<script>`, `<iframe>` tags
   - Collects cookies from every crawled page
   - Identifies all URLs with query parameters

4. **Phase 4: SQLi Testing**
   - Tests up to 50 discovered param URLs
   - All 4 injection points: URL params, cookies, headers, POST
   - WAF bypass payloads applied automatically
   - Smart parameter priority ordering

5. **Phase 5: Data Dumping**
   - Auto-exploits union/error-based SQLi
   - Dumps card data, credentials, gateway keys
   - Saves to disk and reports to Telegram

---

## Technical Features (v3.1)

### Search Engine Health Tracking
- Tracks success/failure rate per engine
- 3 consecutive failures → 300s cooldown
- Engines sorted by reliability for each query

### Adaptive Rate Limiting
- Exponential backoff on rate limits (429/403/captcha)
- Auto-tightens delay on success (0.9x factor)
- Per-engine delay tracking

### Dork Effectiveness Scoring
- Records URL yield per dork
- Sorts productive dorks first
- Interleaves 1 untried dork per 5 tried for exploration

### Cookie Extraction & Injection
- `aiohttp.CookieJar(unsafe=True)` for full cookie capture
- Categorizes cookies: session (PHPSESSID, JSESSIONID, etc.), auth (tokens, JWT, CSRF), b3 (distributed tracing), tracking
- B3 cookie names: `x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`, `x-b3-sampled`, `x-b3-flags`, `b3`
- Cookie injection: tests SQLi payloads in cookie values
- Collects `Set-Cookie` headers and redirect cookies

### Header Injection
- 10 injectable headers: `X-Forwarded-For`, `Referer`, `X-Real-IP`, `CF-Connecting-IP`, `X-Client-IP`, `True-Client-IP`, `X-Originating-IP`, `X-Custom-IP-Authorization`, `X-Forwarded-Host`, `Contact`
- Tests error-based + time-based payloads per header

### POST Parameter Discovery
- Parses `<form>` tags with BeautifulSoup
- Discovers all `<input>`, `<select>`, `<textarea>` including hidden fields
- Tests POST parameters for SQLi

### WAF Bypass Payloads
6 WAF-specific encoder sets:
- **Cloudflare** — double URL encoding, case variation, MySQL comments
- **ModSecurity** — comment injection, HPP, double encoding
- **Wordfence** — hex encoding, concat functions
- **Sucuri** — Unicode normalization, case manipulation
- **F5 BIG-IP ASM** — whitespace variation, comment tricks
- **AWS WAF** — JSON encoding, Unicode

### Technology-Based Payload Selection
Detects backend technology from URL extensions/headers/body → maps to likely DBMS:
- PHP → MySQL
- ASP/ASPX → MSSQL
- JSP → Oracle
- WordPress → MySQL
- Django → PostgreSQL
- Rails → PostgreSQL

### SQLite Persistence (13 tables)
- `seen_domains` — deduplicate scanning
- `vulnerable_urls` — all found SQLi vulns
- `gateway_keys` — extracted payment keys
- `found_secrets` — all discovered secrets
- `card_data` — dumped card data
- `dork_scores` — dork effectiveness history
- `engine_health` — search engine reliability
- `circuit_breaker` — per-domain failure tracking
- `content_hashes` — MD5 dedup
- `cookies` — all extracted cookies
- `b3_cookies` — distributed tracing cookies specifically
- `scan_history` — per-URL scan records
- Indexes on hot columns, WAL mode, NORMAL sync

### Per-Domain Circuit Breaker
- 3 consecutive failures → 30 minute block
- Prevents wasting time on unreachable/hostile domains
- Auto-resets on success

### Soft-404 Detection
- Fetches a known-bad path (`/thispagedoesnotexist_<rand>`)
- Fingerprints the response (title + heading)
- Future responses matching the fingerprint at ≥0.85 similarity are skipped

### Content Deduplication
- MD5 hash of response body
- Skips pages with identical content (mirrors, CDN duplicates)

---

## What Has Been Done

### Phase 1: Core Build (v3.0)
- [x] Full pipeline architecture: Dork Generator → Search → WAF → Secrets → SQLi → Dump → Report
- [x] Telegram bot with all base commands
- [x] DorkGenerator with 35 pattern templates, 6 parameter files, 6 categories
- [x] 8 search engines (DuckDuckGo, Bing, Startpage, Yahoo, Ecosia, Qwant, Brave, AOL)
- [x] WAF detector with 60+ signatures + CDN + CMS + bot protection detection
- [x] SecretExtractor with 83 regex patterns, deep site crawling, platform detection
- [x] SQLi scanner: heuristic, error-based, union-based, boolean-based, time-based
- [x] SQLi dumper: targeted dump, DIOS extraction, card/credential/gateway key extraction
- [x] Reporter: formatted Telegram messages for all finding types
- [x] Validator: URL validation and filtering

### Phase 2: Operational Fixes
- [x] Fixed dead proxies → `use_proxies = False` + fallback
- [x] Added live progress updates to Telegram during scanning
- [x] Added `/stopscan` command to cancel running scans
- [x] Made `/scan` run as background task so bot stays responsive
- [x] Fixed false positive platform detection with SDK-specific signatures

### Phase 3: v3.1 Improvements (16 enhancements)
- [x] **Engine health tracking** — 3-failure cooldown, sorted by reliability
- [x] **Search pagination** — queries pages 2-3 for more results
- [x] **Dork effectiveness scoring** — productive dorks prioritized
- [x] **Persistent sessions** — connection pooling (limit=20, TTL DNS=600s)
- [x] **Adaptive rate limiting** — exponential backoff on rate limits
- [x] **Concurrent URL processing** — semaphore-bounded (default 5)
- [x] **Smart parameter prioritization** — id/cat/pid scored highest
- [x] **POST parameter discovery** — form parsing + POST injection
- [x] **Cookie extraction + injection** — full category support, B3 tracing cookies
- [x] **WAF-specific bypass payloads** — 6 WAF encoder sets
- [x] **Technology-based DBMS targeting** — auto-detects backend
- [x] **Soft-404 detection** — fingerprint-based filtering
- [x] **SQLite persistence** — 13 tables replacing JSON files
- [x] **Priority queue** — URL scoring by injection likelihood
- [x] **Per-domain circuit breaker** — 3 failures → 30 min block
- [x] **Content hash deduplication** — MD5-based

### Phase 4: Scan Overhaul
- [x] `/scan` rewritten as comprehensive 5-phase full domain scanner
- [x] Crawls up to 100 pages per domain
- [x] Extracts cookies from every crawled page
- [x] Tests up to 50 param URLs with all 4 injection points
- [x] `/deepscan` aliased to `/scan`
- [x] `/cookies` shows all cookies grouped by domain with type tags
- [x] `/status` includes cookie count, B3 count, blocked domains

---

## What Still Needs To Be Done

### High Priority

- [ ] **Proxy rotation** — Need working proxy sources. Current proxies are dead. Options: residential proxy API, SOCKS5 rotation, Tor circuit rotation. Without proxies, search engines rate-limit aggressively.
- [ ] **Search engine resilience** — Some engines (especially DDG, Startpage) return 0 results due to rate limiting even with delays of 8-25s. Need: headless browser fallback (Playwright/Selenium), Google Custom Search API integration, or SearXNG self-hosted instance.
- [ ] **Anti-captcha integration** — When search engines serve captchas, currently just skipped. Could integrate 2captcha/anti-captcha API for automated solving.
- [ ] **B3 cookie usage pipeline** — B3 cookies are extracted and stored but not yet used for anything. Need a module that takes collected B3 cookies and uses them for trace ID spoofing, service mesh impersonation, or correlation with other tools.
- [ ] **Time-based SQLi dumping** — Currently only union/error-based injections trigger data dumping. Boolean and time-based confirmed vulnerabilities should also attempt blind data extraction (single-bit extraction).

### Medium Priority

- [ ] **Shopify/WooCommerce-specific checkers** — Dedicated payment flow checkers for Shopify checkout, WooCommerce AJAX endpoints, Magento payment processing.
- [ ] **JavaScript rendering** — Some targets serve JS-heavy SPAs where secrets/keys are only visible after rendering. Need headless browser (Playwright) for JS execution.
- [ ] **Recursive crawl depth control** — Currently crawls flat (all pages at same depth). Should implement BFS with configurable depth limit and smarter page prioritization.
- [ ] **Nmap/port scanning integration** — Discover additional services (MySQL port 3306 exposed, phpMyAdmin, etc.) on target domains.
- [ ] **Out-of-band SQLi (OOB)** — DNS/HTTP exfiltration for blind SQLi (using Burp Collaborator-style callback server or custom DNS server).
- [ ] **Multi-DBMS support in dumper** — Dumper is MySQL-focused. Need PostgreSQL, MSSQL, Oracle, SQLite-specific payloads and extraction queries.
- [ ] **Result export** — CSV/JSON export of all findings, cookies, gateway keys. Currently only in SQLite DB and Telegram messages.
- [ ] **Dashboard/web UI** — Simple Flask/FastAPI dashboard showing stats, cookies, gateway keys, with search/filter functionality.

### Low Priority

- [ ] **Distributed scanning** — Multiple bot instances sharing work via Redis/RabbitMQ queue. One coordinator, multiple workers.
- [ ] **Machine learning false positive filter** — Train a classifier on confirmed vs false positive SQLi results to reduce noise.
- [ ] **Automatic WAF evasion tuning** — Test multiple bypass techniques per WAF and learn which work, adapting over time.
- [ ] **Email notifications** — SMTP alerts for high-value findings (card data, gateway keys).
- [ ] **Rate limit learning** — Per-engine optimal delay discovery through binary search on rate limit thresholds.
- [ ] **API key validation** — Test extracted Stripe/Braintree/PayPal keys to confirm they're live.
- [ ] **Subdomain enumeration** — Discover subdomains before scanning (via crt.sh, DNS brute force, etc.).
- [ ] **Report deduplication in Telegram** — Avoid sending duplicate findings across cycles.
- [ ] **Scheduled scanning** — Cron-like scheduler for periodic rescans of previously found vulnerable domains.
- [ ] **OSINT enrichment** — Whois, DNS, SSL cert analysis on target domains for additional intel.

### Known Bugs / Issues

- Search engines return 0 URLs frequently due to rate limiting (no working proxies)
- Bot token is hardcoded in config (should be env-only)
- `engines_old.py` backup file still in directory (can be removed)
- Legacy JSON state files (`seen_domains.txt`, `gateway_keys.json`) still written alongside SQLite for backward compat
- Old `config.py`, `dorker.py`, `dorker_fast.py`, `validator.py`, `notifier.py` are legacy v1/v2 files — unused but still present
- `config.example.json` is from v1 — outdated

---

## How To Run

```bash
cd /home/null/Documents/dorker/dorker

# Install dependencies
pip3 install -r requirements_v3.txt

# Set bot token (or it uses the hardcoded default)
export DORKER_BOT_TOKEN="your-token-here"

# Start the bot
python3 main_v3.py

# Or run in background
nohup python3 main_v3.py > /tmp/dorker.log 2>&1 &
```

### Dependencies
- Python 3.10+
- `python-telegram-bot>=20.0`
- `aiohttp>=3.9.0`
- `beautifulsoup4>=4.12.0`
- `loguru>=0.7.0`
- SQLite3 (built into Python)

---

## File Map

```
dorker/
├── main_v3.py              ← ENTRY POINT: pipeline + telegram bot
├── config_v3.py            ← All configuration
├── engines.py              ← 8 search engines + health + rate limiting
├── dork_generator.py       ← 35 patterns × 616 keywords = 12,866+ dorks
├── waf_detector.py         ← WAF/CDN/CMS detection + bypass encoders
├── secret_extractor.py     ← 83-pattern secret scraper + deep crawler
├── sqli_scanner.py         ← SQLi testing (URL/cookie/header/POST)
├── sqli_dumper.py          ← Database exploitation + card/cred/key extraction
├── reporter.py             ← Telegram message formatting
├── persistence.py          ← SQLite DB (13 tables)
├── requirements_v3.txt     ← Python dependencies
├── params/                 ← Dork generation parameter files
│   ├── kw.txt (303)        ← Keywords
│   ├── pp.txt (135)        ← Payment providers
│   ├── de.txt (88)         ← Database errors
│   ├── pf.txt (61)         ← Platform fingerprints
│   ├── pt.txt (17)         ← Payment terms
│   └── sf.txt (12)         ← SQL fingerprints
├── dorker.db               ← SQLite database (created at runtime)
│
├── [LEGACY — unused]
│   ├── config.py           ← v1 config
│   ├── dorker.py           ← v1 dorker
│   ├── dorker_fast.py      ← v1 fast dorker
│   ├── validator.py        ← v1 URL validator
│   ├── notifier.py         ← v1 Telegram notifier
│   ├── engines_old.py      ← Pre-rewrite engines backup
│   ├── config.example.json ← v1 config example
│   └── proxies.txt         ← Dead proxy list
```

---

## Bot Token & Runtime

- **Bot Token:** `8187477232:AAEh3X22b1ddY9ZaVxc0x-j9MZQyTK9Wbp4`
- **Bot Username:** MedyDorker
- **Current PID:** Running as background process
- **Database:** `dorker.db` (SQLite, WAL mode)
- **Log:** `/tmp/dorker.log`
