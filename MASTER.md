# MedyDorker v3.14 — Master Documentation

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
│  /dorkon /scan /cookies /cookiehunt /status /secrets    │
│  /firecrawl /captcha /proxy /dumps                      │
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
              ▲
         Captcha
         Solver
         Proxy
         Manager
```

### Module Inventory (~21,000+ lines total)

| Module | Lines | Purpose |
|--------|-------|---------|
| `main_v3.py` | ~2,950 | Pipeline orchestrator + Telegram bot (27 commands) |
| `ecommerce_checker.py` | 1,262 | Shopify/WooCommerce/Magento/PrestaShop/OpenCart platform checker |
| `sqli_scanner.py` | 1,391 | SQL injection testing (URL + cookie + header + POST) |
| `secret_extractor.py` | 982 | 83-pattern secret/key scraper + deep site crawler |
| `captcha_solver.py` | 865 | Multi-provider captcha solving (2captcha/NopeCHA/AntiCaptcha) |
| `engines.py` | 1,001 | 9 search engines (incl. Firecrawl) + captcha + proxy + browser fallback |
| `waf_detector.py` | 809 | WAF/CDN/bot protection/CMS detection + bypass encoders |
| `cookie_hunter.py` | 807 | Active B3 + payment gateway cookie hunting (46 patterns, 9 gateways) |
| `browser_engine.py` | 641 | Playwright headless browser search (6 engines, stealth, human simulation) |
| `recursive_crawler.py` | 610 | BFS recursive crawler with depth control, priority queue, real-time callbacks |
| `ml_filter.py` | ~600 | ML false positive filter (gradient boosted trees, rule-based fallback) |
| `proxy_manager.py` | 580 | Smart proxy rotation, health checking, auto-ban, geo-filtering |
| `union_dumper.py` | ~550 | Multi-DBMS union dumper (MySQL/MSSQL/PostgreSQL/Oracle/SQLite) |
| `key_validator.py` | ~550 | API key validator (16 key types, 13 live validators) |
| `blind_dumper.py` | 530 | Blind SQLi data extraction (boolean + time-based, binary search, multi-DBMS) |
| `oob_sqli.py` | ~450 | OOB SQLi injector (DNS/HTTP exfiltration, interact.sh, 4 DBMS) |
| `sqli_dumper.py` | 830 | Database exploitation, DIOS extraction, card/cred/key dumping + blind delegation |
| `dork_generator.py` | 566 | 35 pattern templates + 214 static dorks = 12,866+ unique dorks |
| `persistence.py` | ~700 | SQLite database (16 tables), circuit breaker, content dedup |
| `reporter.py` | 455 | Telegram message formatting + delivery |
| `port_scanner.py` | ~400 | Port scanner (80+ ports, banner grabbing, service fingerprinting) |
| `config_v3.py` | ~310 | All configuration (incl. port scan, OOB, union dump, key validation, ML filter) |

### Supporting Files

| File | Purpose |
|------|---------|
| `params/kw.txt` | 303 keyword values for dork generation |
| `params/pp.txt` | 135 payment provider strings |
| `params/de.txt` | 88 database error strings |
| `params/pf.txt` | 61 platform fingerprints |
| `params/pt.txt` | 17 payment terminology strings |
| `params/sf.txt` | 12 SQL fingerprint strings |
| `requirements_v3.txt` | Python dependencies (incl. firecrawl-py, playwright) |
| `.vscode/mcp.json` | Firecrawl MCP server config for VS Code agent |
| `seen_domains.txt` | Previously scanned domains (legacy, now in SQLite) |
| `gateway_keys.json` | Found gateway keys (legacy, now in SQLite) |

---

## What the Bot Does

### Telegram Commands

| Command | Function |
|---------|----------|
| `/dorkon` | Start the 24/7 autonomous dorking pipeline |
| `/dorkoff` | Stop the pipeline |
| `/scan <url>` | **Full domain scan** — recursive BFS crawl (configurable depth, priority queue), extracts all cookies, tests up to 50 endpoints for SQLi (URL + cookie + header + POST injection), dumps data if exploitable |
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
| `/firecrawl` | Show Firecrawl engine status, mode, and stats |
| `/captcha` | Captcha solver status, balances, and stats |
| `/proxy` | Proxy pool status, health, rotation stats |
| `/ports` | Port scanner stats |
| `/oob` | OOB SQLi injector stats |
| `/unionstats` | Multi-DBMS union dumper stats |
| `/keys` | API key validator stats |
| `/mlfilter` | ML false positive filter stats |\n| `/crawlstats` | Recursive crawler stats (pages, depth, domains) |

### Autonomous Pipeline (`/dorkon`)

When started, the pipeline runs indefinitely in cycles:

1. **Dork Generation** — generates 12,866+ unique dorks from 35 templates × 616 keyword combinations + 214 static dorks
2. **Dork Scoring** — sorts dorks by past effectiveness (productive dorks first, with exploration interleaving)
3. **Search** — queries 9 search engines (Firecrawl, DuckDuckGo, Bing, Startpage, Yahoo, Ecosia, Qwant, Brave, AOL) with health tracking, pagination (up to 3 pages per engine), and adaptive rate limiting. Firecrawl can be primary or fallback engine. **Captcha auto-solving** intercepts search engine captchas (reCAPTCHA, hCaptcha, Turnstile) and solves them via 2captcha/NopeCHA/AntiCaptcha before retrying. **Smart proxy rotation** distributes requests across 1,150+ proxies with weighted selection, auto-ban on rate limits, per-domain stickiness, and background health checks.
4. **URL Filtering** — skips seen domains, circuit-breaker blocked domains, and soft-404 pages
5. **Priority Queuing** — sorts discovered URLs by injection likelihood (id=, cat=, pid= params first)
6. **Concurrent Processing** — processes URLs concurrently (semaphore-bounded, default 5)
7. **Per-URL Pipeline**:
   - Soft-404 detection (similarity threshold 0.85)
   - Content deduplication (MD5 hash)
   - WAF detection (60+ signatures) + risk assessment
   - Cookie extraction (all cookies categorized: session, auth, b3, tracking)
   - Secret extraction (83 patterns, deep site crawl with payment page discovery)
   - **Recursive BFS crawl** (v3.9): discovers additional pages with priority queue, extracts secrets in real-time via `on_page` callback, collects cookies + B3 traces, discovers param URLs for SQLi
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
   - **Firecrawl path** (primary): `map_urls()` for fast URL discovery → `crawl()` for JS-rendered content extraction → feeds HTML to secret extractor
   - **Recursive BFS fallback** (v3.9): Priority queue ordering (payment/checkout/admin/login pages first), configurable max depth (default 3) and max pages (default 50), concurrent fetching with semaphore, URL normalization + dedup, link extraction from `<a>`, `<form>`, `<script>`, `<iframe>`, meta refresh, JS redirects. Real-time `on_page` callback extracts secrets and collects cookies as pages are crawled.
   - Collects cookies from every crawled page (including B3 distributed tracing)
   - Discovers all URLs with query parameters (SQLi targets)
   - Discovers HTML forms with input names (POST SQLi targets)

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

## Technical Features (v3.10-v3.14)

### Port Scanner (v3.10)
- **PortScanner** class — async TCP port scanning with banner grabbing
- **80+ ports** quick scan, ~31 priority ports, extended scan option
- **Service fingerprinting** from banner analysis (60+ service patterns)
- **Risk assessment** per port (critical/high/medium/low/info)
- **Concurrent scanning** with configurable semaphore (default 50)
- Config: `port_scan_enabled`, `port_scan_timeout`, `port_scan_concurrent`, `port_scan_banner_timeout`, `port_scan_banners`, `port_scan_ports`
- `/ports` command shows scan stats

### OOB SQLi Injector (v3.11)
- **Out-of-band SQL injection** — DNS/HTTP exfiltration channels
- **4 DBMS support**: MySQL, MSSQL, PostgreSQL, Oracle
- **OOBCallbackServer** — async HTTP server for HTTP-channel callbacks
- **InteractShClient** — interact.sh / oast.fun DNS polling for DNS-channel
- **Two-phase approach**: Phase 1 detects OOB capability, Phase 2 extracts data (version, user, database, hostname, tables)
- Payload templates for both HTTP and DNS exfiltration per DBMS
- Config: `oob_sqli_enabled` (default False), `oob_callback_host/port`, `oob_callback_timeout`, `oob_use_interactsh`, `oob_max_extractions`
- `/oob` command shows injector stats

### Multi-DBMS Union Dumper (v3.12)
- **MultiUnionDumper** — full union-based extraction for 5 DBMS
- **MySQL, MSSQL, PostgreSQL, Oracle, SQLite** with per-DBMS query templates
- **Pipeline**: fingerprint DBMS → ORDER BY column count → NULL injectable columns → metadata extraction → table/column enumeration → data extraction
- **DBMS fingerprinting** via error patterns + version function fallback
- **Group concat** alternatives per DBMS (GROUP_CONCAT, STRING_AGG, XMLAGG, LIST, GROUP_CONCAT)
- Config: `union_dump_enabled`, `union_dump_max_tables` (30), `union_dump_max_rows` (500), `union_dump_timeout`, `union_dump_max_columns_per_table` (30)
- `/unionstats` command shows dumper stats

### API Key Validator (v3.13)
- **KeyValidator** — validates discovered API keys against live services
- **16 key types** detected via regex: Stripe (sk/pk/rk), AWS, PayPal, Square, Twilio, SendGrid, Mailgun, Slack, GitHub, Google, Telegram, Discord
- **13 live validators**: each makes real API calls to verify key validity
- **AWS SigV4 signing** for STS GetCallerIdentity (no boto3 dependency)
- Risk assessment: critical (Stripe secret, AWS), high (payment gateways), medium (messaging), low (public keys)
- Config: `key_validation_enabled`, `key_validation_timeout` (10s), `key_validation_concurrent` (5), `key_validation_report_dead`
- `/keys` command shows validation stats

### ML False Positive Filter (v3.14)
- **MLFilter** — machine learning filter for reducing false positives in SQLi + secret detection
- **Pure-Python gradient boosted trees** (no sklearn dependency)
- **FeatureExtractor**: 18 SQLi features (error keywords, HTML tags, response time, URL depth, entropy, etc.) + 10 secret features (entropy, length, charset, format patterns)
- **GradientBoostedClassifier**: 10-tree ensemble with Gini-based CART splits, sigmoid output
- **RuleBasedFilter**: weighted feature scoring fallback (13 SQLi weights, 8 secret weights)
- **Auto-bootstrap**: seeds 60 SQLi + 50 secret synthetic training samples on startup
- Feedback loop: `add_feedback()` for human correction, `add_sqli_feedback_auto()` for automated training from dump outcomes
- Config: `ml_filter_enabled`, `ml_filter_threshold` (0.5), `ml_filter_model_path`, `ml_filter_min_training_samples` (50), `ml_filter_auto_train`
- `/mlfilter` command shows filter stats

## Technical Features (v3.2-v3.9)

### Firecrawl Integration (v3.2)
- **FirecrawlSearch engine** — search, scrape, crawl, and map via Firecrawl API
- **Search**: replaces/augments traditional HTTP scraping engines, no captchas or rate limits
- **Scrape**: JS-rendered page content with markdown, HTML, and link extraction
- **Crawl**: full domain crawl with sitemap discovery, deduplication, JS rendering
- **Map**: fast URL discovery without content scraping (low credit cost)
- Configurable as primary engine or fallback-only mode
- 11 config fields: API key, enabled, search limit, scrape/crawl toggles, formats, timeout, proxy mode
- `/firecrawl` command shows engine status and stats

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

### Phase 5: Firecrawl Integration (v3.2)
- [x] `FirecrawlSearch` class in `engines.py` — search, scrape, crawl, map_urls methods
- [x] Firecrawl as primary or fallback search engine in `MultiSearch`
- [x] 11 config fields added to `config_v3.py` (API key, limits, toggles)
- [x] `/scan` Phase 3 rewritten: Firecrawl crawl-first with manual fallback
- [x] Map → Crawl → Secret Extract pipeline for JS-rendered content
- [x] `/firecrawl` command for status monitoring
- [x] `.vscode/mcp.json` for Firecrawl MCP server in VS Code
- [x] `firecrawl-py` added to dependencies
- [x] Tested: search (5 URLs), map (10 URLs), crawl (returns proper dicts with metadata)

### Captcha Solver Integration (v3.3)

New `captcha_solver.py` module (865 lines) providing multi-provider async captcha solving:

**Architecture:**
- `CaptchaSolver` — Main solver with provider fallback chain
- `SitekeyExtractor` — Auto-detects captcha type and extracts sitekeys from HTML
- `CaptchaType` — Constants for all supported captcha types
- 3 provider implementations: `TwoCaptchaProvider`, `NopeCHAProvider`, `AntiCaptchaProvider`
- `SolverStats` + `SolveResult` dataclasses for tracking

**Supported captcha types:**
- reCAPTCHA v2 / v3 (incl. Enterprise)
- hCaptcha
- Cloudflare Turnstile
- FunCaptcha (Arkose Labs)
- DataDome
- GeeTest v3 / v4
- Image captcha

**Sitekey extraction patterns:**
- `data-sitekey` attributes on reCAPTCHA/hCaptcha/Turnstile divs
- `grecaptcha.execute()` / `recaptcha/api.js?render=` for v3 detection
- `data-pkey` / arkoselabs URL for FunCaptcha
- `captcha-delivery.com` URLs for DataDome
- GeeTest `gt=` / `challenge=` parameters

**Integration points:**
1. `engines.py` — `CaptchaDetectedError` exception, `_detect_captcha_in_response()` method on SearchEngine, solve-and-retry loop in `MultiSearch.search()`
2. `main_v3.py` — Pipeline init creates `CaptchaSolver` and passes to searcher; autonomous pipeline solves target site captchas when `auto_solve_target=True`; `/captcha` command for stats/balance
3. `config_v3.py` — 10 captcha config fields

**Provider chain:**
Default order: NopeCHA (¢heap, AI-powered) → 2captcha (most versatile) → AntiCaptcha (mature fallback)

**Config fields (10):**
- `captcha_enabled`, `captcha_twocaptcha_key`, `captcha_nopecha_key`, `captcha_anticaptcha_key`
- `captcha_provider_order`, `captcha_max_solve_time`, `captcha_auto_solve_search`, `captcha_auto_solve_target`
- `captcha_budget_limit`, `captcha_max_per_domain`

**Completion checklist:**
- [x] `captcha_solver.py` — 3 providers, 8 captcha types, sitekey extraction, stats tracking
- [x] Config fields in `config_v3.py` (10 new fields)
- [x] Engine integration — `CaptchaDetectedError`, `_detect_captcha_in_response()`, solve-and-retry
- [x] Pipeline init wiring in `main_v3.py`
- [x] Autonomous pipeline — solve target site captchas before skipping
- [x] `/captcha` command with balance, stats, per-type/provider breakdown
- [x] `/start` updated to v3.3 with captcha feature listed
- [x] Dependencies: `2captcha-python>=2.0.0`, `nopecha>=2.0.0`, `anticaptchaofficial>=1.0.0`
- [x] All sitekey extractors tested: reCAPTCHA, hCaptcha, Turnstile, FunCaptcha, DataDome, GeeTest
- [x] Exception hierarchy tested: CaptchaDetectedError ⊂ RateLimitError
- [x] Syntax validation passes on all files

---

## What Still Needs To Be Done

### High Priority

- [ ] **Proxy rotation** — ~~Need working proxy sources. Current proxies are dead.~~ **✅ DONE (v3.4)** — Smart proxy rotation with 1,150 proxies from 2 CSV sources. Weighted selection (success rate + latency), auto-ban on rate limits, per-domain stickiness, country filtering, background health checks. See Proxy Manager section below.
- [ ] **Search engine resilience** — ~~Some engines (especially DDG, Startpage) return 0 results due to rate limiting. Firecrawl partially solves this (no rate limits), proxy rotation (v3.4) reduces rate limiting significantly. Headless browser fallback (Playwright/Selenium) still useful for free engines.~~ **✅ DONE (v3.7)** — Playwright headless browser fallback with stealth anti-fingerprinting, human simulation (typing/scrolling/delays), 6 browser engines (Google, Bing, DDG, Startpage, Yahoo, Brave), captcha detection + solving, semaphore-bounded concurrent tabs. Full fallback chain: HTTP → proxy rotation → captcha solving → Firecrawl → headless browser. See Headless Browser section below.
- [ ] **Anti-captcha integration** — ~~When search engines serve captchas, currently just skipped.~~ **✅ DONE (v3.3)** — Multi-provider captcha solving with 2captcha, NopeCHA, AntiCaptcha. Auto-solves search engine captchas + target site captchas. See Captcha Solver section below.
- [ ] **B3 cookie usage pipeline** — ~~B3 cookies are extracted and stored but not yet used for anything.~~ **✅ DONE (v3.5)** — Active B3 + payment gateway cookie hunting via `CookieHunter`. Probes every URL for B3 tracing headers, payment gateway cookies (Stripe, Braintree, PayPal, Square, Adyen, Shopify, WooCommerce, Klarna, Razorpay, Worldpay + 46 cookie patterns), detects gateway SDKs in HTML, probes checkout pages, reports all finds to Telegram immediately. See Cookie Hunter section below.
- [ ] **Time-based SQLi dumping** — ~~Currently only union/error-based injections trigger data dumping.~~ **✅ DONE (v3.6)** — Blind data extraction engine for boolean + time-based SQLi. Binary search on ASCII values (7 requests/char), multi-DBMS (MySQL, MSSQL, PostgreSQL, Oracle, SQLite), char-by-char table/column/data extraction, Luhn card validation, auto-categorization of cards/creds/keys. See Blind Dumper section below.

### Medium Priority

- [ ] **Shopify/WooCommerce-specific checkers** — ~~Dedicated payment flow checkers for Shopify checkout, WooCommerce AJAX endpoints, Magento payment processing.~~ **✅ DONE (v3.8)** — Dedicated e-commerce platform checker covering Shopify, WooCommerce, Magento, PrestaShop, and OpenCart. Platform fingerprinting (45+ signatures), API/config/admin/credential endpoint probing, payment gateway plugin detection, platform-specific secret scanning (Shopify tokens, WC keys, Magento encryption keys). All findings reported to Telegram. See E-commerce Checker section below.
- [x] **JavaScript rendering** — ~~Need headless browser.~~ Firecrawl handles JS rendering server-side for scrape/crawl operations.
- [ ] **Recursive crawl depth control** — ~~Currently crawls flat (all pages at same depth). Should implement BFS with configurable depth limit and smarter page prioritization.~~ **✅ DONE (v3.9)** — Full BFS recursive crawler with configurable depth (default 3), max pages (default 50), priority queue (payment/checkout/admin pages first), concurrent fetching (semaphore-bounded), URL normalization + dedup, form discovery, cookie collection (incl. B3), proxy rotation, real-time `on_page` callback for live secret extraction. Replaces inline BFS in `/scan` and adds recursive crawl to the main dorking pipeline. Crawler-discovered param URLs are fed to SQLi testing. See Recursive Crawler section below.
- [ ] **Nmap/port scanning integration** — Discover additional services (MySQL port 3306 exposed, phpMyAdmin, etc.) on target domains.
- [ ] **Out-of-band SQLi (OOB)** — DNS/HTTP exfiltration for blind SQLi (using Burp Collaborator-style callback server or custom DNS server).
- [ ] **Multi-DBMS support in dumper** — ~~Dumper is MySQL-focused.~~ Partially addressed in v3.6 blind dumper (MySQL, MSSQL, PostgreSQL, Oracle, SQLite). Union-based dumper still MySQL-focused.
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

- ~~Search engines return 0 URLs frequently due to rate limiting~~ — Addressed by multi-layer fallback: proxy rotation (v3.4) + captcha solving (v3.3) + Firecrawl API (v3.2) + headless browser (v3.7). If all 4 layers fail, engine is temporarily banned.
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
- `firecrawl-py>=1.0.0`
- `2captcha-python>=2.0.0`
- `nopecha>=2.0.0`
- `anticaptchaofficial>=1.0.0`
- SQLite3 (built into Python)

---

## Proxy Manager Integration (v3.4)

### Architecture

```
ProxyManager (top-level)
  └─ ProxyPool
       ├─ ProxyLoader.load_csv()   ← 2 CSV files (150 + 1000 proxies)
       ├─ ProxyLoader.load_text()  ← Legacy plain text support
       ├─ Health Checker            ← Background async ping loop
       ├─ Rotation Engine           ← round_robin / random / LRU / weighted
       ├─ Auto-Banner               ← Ban on consecutive failures or rate limits
       ├─ Country Filter            ← Geo-based proxy selection
       └─ Domain Stickiness         ← Same proxy for N requests to same domain
```

### Proxy Sources

| File | Count | Countries | Port | Status |
|------|-------|-----------|------|--------|
| `proxies.csv` (150) | 150 | US, CA | 8800 | Squid (mixed liveness) |
| `1000Proxies.csv` | 1,000 | US, CA, IN | 8800 | Squid (30/30 tested alive) |
| **Total (deduplicated)** | **1,150** | | | |

### Rotation Strategies

| Strategy | Description |
|----------|-------------|
| `round_robin` | Sequential cycling through proxy list |
| `random` | Random selection from available pool |
| `least_recently_used` | Pick proxy least recently used |
| `weighted` (default) | Score = 60% success rate + 20% latency + 20% trust, random weighted selection |

### Config Options

| Setting | Default | Description |
|---------|---------|-------------|
| `use_proxies` | `True` | Enable proxy rotation |
| `proxy_files` | 2 CSV files | List of proxy file paths |
| `proxy_rotation_strategy` | `weighted` | Selection algorithm |
| `proxy_ban_threshold` | `5` | Consecutive failures before ban |
| `proxy_ban_duration` | `600` | Ban duration in seconds |
| `proxy_health_check` | `True` | Test proxies on startup |
| `proxy_health_interval` | `300` | Background check interval (seconds) |
| `proxy_country_filter` | `[]` | Restrict to specific countries |
| `proxy_sticky_per_domain` | `3` | Same proxy for N requests per domain |
| `proxy_protocol` | `http` | http / https / socks5 |

### Integration Points

1. **engines.py** — `MultiSearch._get_smart_proxy()` fetches from `ProxyManager`, reports success/failure/rate-limit back. Auto-rotates on ban.
2. **main_v3.py** — Pipeline creates `ProxyManager` on init, starts it with health check, assigns to `searcher.proxy_manager`. `/proxy` command shows pool stats.
3. **config_v3.py** — 13 new proxy config fields.

### Completion Checklist

- [x] `proxy_manager.py` created (580 lines): ProxyInfo, ProxyLoader (CSV + text), ProxyPool, ProxyManager
- [x] CSV loading tested: 150 + 1000 = 1,150 unique proxies (dedup verified)
- [x] All 4 rotation strategies tested: round_robin, random, LRU, weighted
- [x] Country filtering tested (CA filter returns only CA proxies)
- [x] Auto-ban tested (3 failures → ban, excluded from selection)
- [x] Domain stickiness tested (same proxy for 3 requests, then rotates)
- [x] Rate limit reporting → immediate ban, fresh proxy on next request
- [x] Health check tested: 30/30 alive from 1000Proxies.csv (Squid, ~200ms latency)
- [x] Engine integration: `_get_smart_proxy()` → ProxyManager → fallback to legacy list
- [x] Proxy success/failure/rate-limit reported from search loop
- [x] `/proxy` Telegram command with pool stats, countries, sources, top/worst proxies
- [x] All files pass `py_compile`

---

## Cookie Hunter Integration (v3.5)

### Overview

The Cookie Hunter actively probes every URL in the pipeline for B3 distributed tracing cookies/headers and payment gateway cookies. Unlike the passive cookie extraction (Step 2 of the pipeline), the Cookie Hunter:

1. **Scans response headers** for B3/Zipkin/Jaeger/Datadog/AWS X-Ray tracing headers
2. **Matches all cookies** against 46 gateway-specific patterns (Stripe, Braintree, PayPal, Square, Adyen, Shopify, WooCommerce, Klarna, Razorpay, Worldpay, Authorize.net, 2Checkout)
3. **Scans HTML** for gateway SDK signatures (js.stripe.com, braintreegateway.com, paypal SDK, etc.)
4. **Discovers checkout pages** from links in the HTML (/checkout, /cart, /payment, /billing)
5. **Probes checkout pages** for additional cookies (up to 8 probes per domain)
6. **Reports each find immediately** to Telegram with full cookie details
7. **Persists** all finds to the SQLite database

### Hunt Strategy

```
hunt_url(url)
  ├── Phase 1: Fetch main page → collect Set-Cookie + response headers
  ├── Phase 2: Classify all cookies (B3 → gateway → commerce)
  ├── Phase 3: Check response headers for B3/tracing (15 header patterns)
  ├── Phase 4: Scan HTML for gateway SDK signatures (9 gateways)
  ├── Phase 5: Discover checkout/payment links from HTML
  ├── Phase 6: Probe discovered + common checkout paths
  └── Report findings → Telegram + SQLite
```

### B3 Tracing Headers Detected (15)

| Header | Source |
|--------|--------|
| `x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`, `x-b3-sampled`, `x-b3-flags`, `b3` | Zipkin/B3 |
| `traceparent`, `tracestate` | W3C Trace Context |
| `uber-trace-id` | Jaeger |
| `x-cloud-trace-context` | Google Cloud |
| `x-amzn-trace-id` | AWS X-Ray |
| `x-datadog-trace-id`, `x-datadog-parent-id` | Datadog |
| `x-request-id`, `x-trace-id` | Generic |

### Gateway Cookie Patterns (46)

| Gateway | Patterns | Example Cookies |
|---------|----------|-----------------|
| Stripe | 7 | `__stripe_mid`, `__stripe_sid`, `stripe.csrf`, `checkout-*session` |
| Braintree | 4 | `bt_bb_*`, `braintree*`, `__bt`, `bt_*token` |
| PayPal | 6 | `paypal*`, `pp_*`, `X-PP-*`, `PYPF`, `tsrce` |
| Square | 3 | `sq_*`, `squareup*`, `square_*session` |
| Adyen | 2 | `adyen*`, `__adyen*` |
| Shopify | 6 | `_shopify_s`, `_shopify_y`, `checkout_token`, `shopify_pay*` |
| WooCommerce | 4 | `wp_woocommerce_session_*`, `woocommerce_cart_hash`, `wc_cart_*` |
| Authorize.net | 2 | `authorizenet*`, `anet_*` |
| 2Checkout | 2 | `2co*`, `TWOCHECKOUT*` |
| Klarna | 2 | `klarna*`, `__klarna*` |
| Razorpay | 2 | `rzp_*`, `razorpay*` |
| Worldpay | 1 | `worldpay*` |
| Commerce (generic) | 5 | `payment_session*`, `checkout_session*`, `order_token*`, `cart_token*`, `billing_*` |

### HTML Gateway Detection (9 gateways)

Scans page source for SDK/JS includes: Stripe JS, Braintree gateway, PayPal SDK, Square payments, Adyen checkout, Shopify CDN, WooCommerce, Klarna, Razorpay.

### Telegram Reporting

Each find type gets its own Telegram message:

| Find Type | Icon | Message Contains |
|-----------|------|-----------------|
| B3 Tracing | 🔵 | Header/cookie name, value, domain, source, URL |
| Gateway Cookie | 🔥/🔑 | Gateway name, cookie name, value, domain, severity |
| Commerce Cookies | 🛒 | Batch of all commerce cookies for the domain |
| Gateway Detection | 🏦 | Detected gateway SDKs, checkout pages found |

### Commands

| Command | Description |
|---------|-------------|
| `/cookiehunt <url>` | Actively hunt a URL for B3 + gateway cookies |
| `/cookiehunt stats` | Show cookie hunter statistics |
| `/cookies` | Now also includes Cookie Hunter stats section |

### Config Options

| Setting | Default | Description |
|---------|---------|-------------|
| `cookie_hunter_enabled` | `True` | Enable active B3 + gateway cookie hunting |
| `cookie_hunt_probe_checkout` | `True` | Probe /checkout, /cart, /payment paths |
| `cookie_hunt_max_probes` | `8` | Max checkout pages to probe per domain |
| `cookie_hunt_report_commerce` | `True` | Also report generic commerce cookies |
| `cookie_hunt_report_html_gateways` | `True` | Report gateway SDK detections in HTML |

### Completion Checklist

- [x] `cookie_hunter.py` created (~550 lines): CookieHunter, CookieFind, HuntResult, HunterStats
- [x] 46 gateway cookie patterns with pre-compiled regexes
- [x] 15 B3/tracing header patterns (Zipkin, W3C, Jaeger, Datadog, AWS, Google Cloud)
- [x] 9 gateway HTML signature sets
- [x] 13 checkout path probing URLs
- [x] Cookie classification: B3 → gateway → commerce (with dedup)
- [x] Immediate Telegram reporting for each find (4 message types)
- [x] Rate limiting between Telegram messages
- [x] SQLite persistence via existing `cookies` and `b3_cookies` tables
- [x] New `get_gateway_cookies()` and `get_commerce_cookies()` DB methods
- [x] Pipeline integration: Cookie Hunter runs after Step 2 for every URL
- [x] Reporter updated: `b3_cookies_found`, `gateway_cookies_found`, `commerce_cookies_found` stats
- [x] Status report updated to v3.5 with cookie hunt section
- [x] `/cookiehunt` command added (hunt URL, view stats)
- [x] `/cookies` command updated with Cookie Hunter stats
- [x] Config: 5 new cookie hunter fields
- [x] Live tested: shopify.com → 2 Shopify cookies found, gateway detected in HTML, 3 checkout pages discovered
- [x] All files pass `py_compile`

---

## Blind SQLi Dumper Integration (v3.6)

### Overview

The Blind Dumper enables data extraction from **boolean-based** and **time-based** blind SQL injection vulnerabilities — which previously were detected but never exploited by the pipeline. Union/error-based SQLi uses bulk extraction (SELECT INTO columns), but blind SQLi requires extracting data **one character at a time** using conditional responses.

### How It Works

**Boolean-based extraction:**
1. Inject `AND (ASCII(SUBSTRING(database(),1,1))>=64)` 
2. Compare response body length to known true/false baselines
3. If response matches "true" baseline → condition is true
4. Binary search narrows each character in ~7 requests (log2(94) ≈ 7)

**Time-based extraction:**
1. Inject `AND IF((ASCII(SUBSTRING(database(),1,1))>=64), SLEEP(3), 0)`
2. If response takes ≥ 2.1s (70% of delay) → condition is true
3. Same binary search, but each request takes 3+ seconds when true

### Architecture

```
BlindExtractor (low-level engine)
├── check_condition(sql_cond)     → True/False via boolean or time analysis
├── extract_string(sql_expr)      → full string via char-by-char binary search
├── extract_int(sql_expr)         → integer via binary search
├── _extract_length(expr)         → string length via binary search
├── _extract_char(expr, pos)      → single char via ASCII binary search (32-126)
└── _boolean_check() / _time_check()  → injection-type-specific condition testing

BlindDumper (high-level orchestrator)
├── blind_dump(sqli, session)     → full extraction pipeline
├── _extract_database_name()      → database() / DB_NAME() / current_database()
├── _enumerate_tables()           → information_schema / sysobjects / user_tables
├── _enumerate_columns()          → information_schema.columns / user_tab_columns
├── _extract_rows()               → row-by-row, column-by-column extraction
├── _categorize_row()             → auto-categorize cards / creds / gateway keys
└── _luhn_check()                 → Validate card numbers with Luhn algorithm
```

### Multi-DBMS Support

| Feature | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|---------|-------|-------|------------|--------|--------|
| Sleep function | `SLEEP(n)` | `WAITFOR DELAY` | `pg_sleep(n)` | `DBMS_PIPE.RECEIVE_MESSAGE` | N/A |
| Substring | `SUBSTRING()` | `SUBSTRING()` | `SUBSTRING()` | `SUBSTR()` | `SUBSTRING()` |
| Length | `LENGTH()` | `LEN()` | `LENGTH()` | `LENGTH()` | `LENGTH()` |
| DB name | `database()` | `DB_NAME()` | `current_database()` | `ora_database_name` | `"main"` |
| Tables | `information_schema.tables` | `sysobjects` | `information_schema.tables` | `user_tables` | `sqlite_master` |
| Columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` | `user_tab_columns` | `pragma_table_info` |
| Pagination | `LIMIT n,1` | `ROW_NUMBER()` | `LIMIT 1 OFFSET n` | `ROWNUM` | `LIMIT 1 OFFSET n` |

### Data Categorization

Extracted rows are automatically categorized using regex pattern matching:

- **Card data:** Card numbers (13-19 digits, Luhn validated), CVV (3-4 digits in security columns), expiry dates, cardholder names
- **Credentials:** Passwords/hashes, emails, usernames in matching columns
- **Gateway keys:** Stripe (`sk_live_`/`pk_live_`), Braintree, PayPal, API keys, merchant secrets, access tokens

### Pipeline Integration

**Auto-pipeline (`process_url`):**
- Step 5: Union/error → `targeted_dump()` (existing)
- Step 5b: Boolean/time → `blind_targeted_dump()` (NEW)
- Results saved with `blind_` prefix, reported identically to Telegram

**`/scan` command:**
- Phase 5: Union/error → `targeted_dump()` (existing)
- Phase 5b: Boolean/time → `blind_targeted_dump()` (NEW) with progress messages
- User sees "🐢 Extracting data char-by-char (this is slow)..." notification

### Config Fields (5 new)

| Field | Default | Description |
|-------|---------|-------------|
| `dumper_blind_enabled` | `True` | Enable blind extraction |
| `dumper_blind_delay` | `3.0` | Sleep delay for time-based (seconds) |
| `dumper_blind_max_rows` | `50` | Max rows per table (blind is slow) |
| `dumper_blind_max_tables` | `15` | Max tables to enumerate |
| `dumper_blind_max_string` | `256` | Max chars per field extraction |

### Performance Characteristics

| Metric | Boolean-based | Time-based |
|--------|--------------|------------|
| Requests per char | ~7 (binary search) | ~7 (binary search) |
| Time per char | ~0.5-1s | ~3-5s per request × 7 = ~21-35s |
| DB name (8 chars) | ~56 requests / ~30s | ~56 requests / ~3 min |
| 10 table names (avg 10 chars) | ~700 requests / ~6 min | ~700 requests / ~35 min |
| 50 rows × 5 cols (avg 15 chars) | ~26,250 requests / ~4 hours | Very slow |

**Note:** Blind extraction is inherently slow. Boolean is ~5-10x faster than time-based. The engine caps tables at 15 and rows at 50 to keep runtime reasonable.

### Completion Checklist

- [x] `blind_dumper.py` — BlindExtractor (boolean + time check, binary search) + BlindDumper (5-DBMS extraction pipeline)
- [x] `sqli_dumper.py` — `blind_targeted_dump()` method, `_convert_blind_result()` helper, BlindDumper init in constructor
- [x] `main_v3.py` — Pipeline Step 5b for boolean/time, `/scan` Phase 5b with progress messages
- [x] `config_v3.py` — 5 new blind dumper fields
- [x] Data categorization — Luhn card validation, credential detection, gateway key pattern matching
- [x] Multi-DBMS — MySQL, MSSQL, PostgreSQL, Oracle, SQLite table/column/data queries
- [x] All files pass `py_compile`

---

## Headless Browser Engine (v3.7)

### Overview

The Browser Engine provides **Playwright-based headless Chromium** as the final fallback layer when all other search methods fail. It renders actual browser pages with full JavaScript, making requests indistinguishable from real user traffic. This solves the persistent problem of search engines (especially DDG, Startpage, Google) blocking HTTP-based scraping even with proxies and captcha solving.

### Fallback Chain (Complete)

```
Dork Query
│
├─ 1. HTTP scraping (9 engines) ─── uses proxies if available
│     ↓ rate limited / blocked / 0 results?
├─ 2. Captcha solving ─── if captcha detected (2captcha/NopeCHA/AntiCaptcha)
│     ↓ still 0 results?
├─ 3. Firecrawl API ─── server-side rendering, no rate limits
│     ↓ still 0 results?
└─ 4. Playwright headless browser ── stealth Chromium, human simulation
      ↓ tries up to 4 browser engines sequentially
      final result (or true 0 if all fail)
```

### Architecture

```
BrowserManager
├── start()                       → Launch Chromium with stealth config
├── stop()                        → Graceful shutdown + cleanup
├── search(query, engine, pages)  → Execute full search with human sim
├── _init_stealth(page)           → Navigator overrides, plugin spoofing
├── _human_type(page, sel, text)  → Realistic keystroke delays (50-150ms)
├── _human_scroll(page)           → Random smooth scrolling
├── _random_delay()               → 0.3-1.5s micro-delays
├── _check_captcha(page, engine)  → Captcha detection per engine
├── _solve_captcha(page, query)   → Screenshot + captcha_solver integration
├── _parse_results(html, engine)  → Delegate to SearchParser
└── stats                         → searches, results, errors, captchas_hit

SearchParser (static methods)
├── parse_google(html)            → div.g h3 a[href] + snippet extraction
├── parse_bing(html)              → li.b_algo h2 a + snippet
├── parse_duckduckgo(html)        → article[data-testid=result] a.result__a
├── parse_startpage(html)         → .w-gl__result a.w-gl__result-url
├── parse_yahoo(html)             → div.algo h3 a + snippet
└── parse_brave(html)             → div.snippet a.result-header

BrowserSearchEngine (SearchEngine-compatible wrapper)
└── search(dork, page)            → Delegates to BrowserManager.search()
```

### Stealth Anti-Detection

The browser is configured to evade bot detection systems:

| Technique | Implementation |
|-----------|---------------|
| WebDriver flag | `navigator.webdriver` set to `undefined` |
| Plugin spoofing | Fake `navigator.plugins` with Chrome PDF Plugin + Viewer |
| Language spoofing | `navigator.languages` → `['en-US', 'en']` |
| Touch spoofing | `navigator.maxTouchPoints` → `0` (desktop) |
| Chrome runtime | Fake `window.chrome.runtime` object |
| Random viewport | 1280×720 to 1920×1080, randomized per launch |
| Random User-Agent | Rotated from 10 modern Chrome UAs |
| Launch flags | `--disable-blink-features=AutomationControlled`, `--no-sandbox`, etc. |
| Persistent context | Uses `user_data_dir` to maintain cookies/state across sessions |

### Human Simulation

To avoid behavioral fingerprinting:

- **Typing:** 50-150ms random delay between keystrokes (realistic typing speed)
- **Scrolling:** 3-7 smooth scroll increments per page with random distances
- **Page delays:** 0.3-1.5s between actions, 2-5s after page load
- **Navigation:** Wait for `networkidle` + explicit waits for result selectors

### Browser Engines (6)

| Engine | Base URL | Wait Selector | Captcha Indicators |
|--------|----------|---------------|-------------------|
| Google | `google.com/search?q=` | `div.g` | `recaptcha`, `captcha`, `unusual traffic` |
| Bing | `bing.com/search?q=` | `li.b_algo` | `captcha`, `blocked` |
| DuckDuckGo | `duckduckgo.com/?q=` | `article[data-testid=result]` | `captcha`, `bot` |
| Startpage | `startpage.com/do/search?q=` | `.w-gl__result` | `captcha`, `verify` |
| Yahoo | `search.yahoo.com/search?p=` | `div.algo` | `captcha`, `robot` |
| Brave | `search.brave.com/search?q=` | `div.snippet` | `captcha`, `verify` |

### Config Fields (5 new)

| Field | Default | Description |
|-------|---------|-------------|
| `browser_enabled` | `True` | Enable headless browser fallback |
| `browser_headless` | `True` | Run in headless mode (set `False` for debugging) |
| `browser_max_concurrent` | `3` | Max concurrent browser tabs (semaphore-bounded) |
| `browser_page_timeout` | `30000` | Page load timeout in milliseconds |
| `browser_engines` | `["google","bing","duckduckgo","startpage"]` | Which engines to try in browser mode |

### Telegram Command

**`/browser`** — Shows browser engine status:
- Running / stopped / Playwright not installed
- Total searches, results found, errors, captchas hit

### Integration Points

- **`engines.py` MultiSearch.search()**:  After all HTTP engines + Firecrawl return 0 results, browser fallback kicks in. Tries each configured browser engine sequentially until results found.
- **`main_v3.py` pipeline init**: Creates `BrowserManager` after cookie_hunter, wires to `searcher.browser_manager` / `searcher.browser_fallback_enabled` / `searcher.browser_engines`.
- **`main_v3.py` close**: `BrowserManager.stop()` called via `MultiSearch.close()`.

### Performance Notes

- Browser search is **slower** than HTTP (~3-8s per page vs <1s) due to full page rendering + human simulation delays
- Semaphore limits concurrent tabs to prevent memory exhaustion (default: 3)
- Browser is started **lazily** — only when first browser search is needed
- Persistent context avoids re-creating browser for each search
- Auto-restarts if browser process crashes

### Completion Checklist

- [x] `browser_engine.py` — BrowserManager (stealth, human sim, captcha, parsing) + SearchParser (6 engines) + BrowserSearchEngine wrapper
- [x] `engines.py` — Browser import, MultiSearch attrs, browser fallback block in search(), stop in close()
- [x] `main_v3.py` — BrowserManager init, `/browser` command, features text updated to v3.7
- [x] `config_v3.py` — 5 new browser config fields
- [x] `requirements_v3.txt` — Added `playwright>=1.40.0`
- [x] All files pass `py_compile`
- [x] **Note:** Chromium browser binary must be installed separately: `playwright install chromium`

---

## E-commerce Platform Checker (v3.8)

### Overview

The E-commerce Checker provides **dedicated payment flow analysis** for sites running Shopify, WooCommerce, Magento, PrestaShop, or OpenCart. When the pipeline encounters a URL, the checker fingerprints the platform and runs targeted probes for exposed APIs, admin panels, config files, payment gateway plugins, and leaked credentials/API keys.

### Platform Detection

Detection uses a multi-signal fingerprinting system combining headers, HTML content, cookies, and URL patterns with confidence scoring:

| Platform | Fingerprint Count | High-Confidence Signals |
|----------|------------------|------------------------|
| Shopify | 11 | `X-ShopId` header, `cdn.shopify.com`, `_shopify_s` cookie, meta generator |
| WooCommerce | 9 | `woocommerce` class, `wp-content/plugins/woocommerce`, `wp_woocommerce_session` |
| Magento | 11 | `X-Magento-*` header, `Mage.Cookies` JS, `mage-cache-*` cookie, static versioning |
| PrestaShop | 6 | `PrestaShop` string, `/modules/ps_`, `PrestaShop-*` cookie |
| OpenCart | 6 | `catalog/view/theme`, `OCSESSID` cookie, `route=` URL |

Confidence scoring uses the highest-confidence match as base, with diminishing returns for additional signals. Minimum threshold: 40%.

### Endpoint Probes

**Shopify (8 probes):**
- `/products.json` — Product catalog (public API)
- `/collections.json` — Collection listing
- `/cart.json` — Cart token extraction
- `/meta.json` — Store metadata
- `/admin/auth/login` — Admin panel accessibility
- `/checkouts.json` — Checkout endpoint (usually protected)
- `/storefront-renderer/render` — Storefront renderer
- `/.well-known/shopify/monorail/...` — Analytics endpoint

**WooCommerce (10 probes):**
- `/wp-json/wc/v3/products` — Products API (may be open)
- `/wp-json/wc/v3/` — REST API root
- `/wp-json/wc/v3/system_status` — System info (often exposed)
- `/?wc-ajax=get_refreshed_fragments` — AJAX cart
- `/wp-content/debug.log` — Debug log (errors, paths)
- `/wp-json/wp/v2/users` — User enumeration
- `/wp-login.php` — Admin login
- `/xmlrpc.php` — XML-RPC (bruteforce/SSRF vector)
- `/.env` — Exposed environment file
- `/wp-config.php.bak` — Config backup (DB creds)

**Magento (10 probes):**
- `/rest/V1/store/storeConfigs` — Store configuration (public)
- `/rest/V1/directory/countries` — Directory API
- `/rest/V1/customers/me` — Customer auth check
- `/magento_version` — Version disclosure
- `/downloader/` — Magento Connect Manager (1.x)
- `/app/etc/local.xml` — Config (DB creds, encryption key) (1.x)
- `/app/etc/env.php` — Config (DB creds, encryption key) (2.x)
- `/admin` — Admin panel
- `/var/log/system.log` — System log
- `/.env` — Environment file

**PrestaShop (5 probes):**
- `/api/` — Web Service API root
- `/api/products` — Products API
- `/admin/` — Admin panel
- `/config/settings.inc.php` — Config file (DB creds)
- `/.env` — Environment file

**OpenCart (4 probes):**
- `/admin/` — Admin panel
- `/index.php?route=api/` — API endpoint
- `/config.php.bak` — Config backup (DB creds)
- `/system/storage/logs/error.log` — Error log

### Payment Gateway Plugin Detection

For each detected platform, HTML/JS is scanned for platform-specific payment gateway plugin signatures:

| Platform | Gateways Detected |
|----------|------------------|
| Shopify | Stripe, Shopify Payments, PayPal, Shop Pay, Afterpay, Klarna, Sezzle, Amazon Pay, Apple Pay, Google Pay |
| WooCommerce | Stripe, PayPal, Braintree, Square, Authorize.net, Checkout.com, Mollie, Razorpay, Klarna, Worldpay |
| Magento | PayPal, Stripe, Braintree, Adyen, Authorize.net, Amazon Pay, Klarna, Worldpay |
| PrestaShop | PayPal (Checkout), Stripe, Mollie, PayPlug, Adyen |
| OpenCart | PayPal, Stripe, SagePay, Worldpay |

### Secret / Credential Scanning

All fetched content (main page + probe responses) is scanned for platform-specific exposed secrets:

| Pattern | Platform | What |
|---------|----------|------|
| `shpat_[hex32]` | Shopify | Admin API token |
| `shpca_[hex32]` | Shopify | Custom App token |
| `shpss_[hex32]` | Shopify | Shared Secret |
| `Storefront-Access-Token` | Shopify | Storefront token |
| `ck_[hex40]` | WooCommerce | Consumer Key |
| `cs_[hex40]` | WooCommerce | Consumer Secret |
| `DB_PASSWORD` | WordPress | Database password |
| `'key' => '[hex32]'` | Magento | Encryption key |
| `_COOKIE_KEY_` | PrestaShop | Cookie encryption key |
| `_DB_PASSWD_` | PrestaShop | Database password |
| `sk_live_*` | Generic | Stripe Live Secret Key |
| `rk_live_*` | Generic | Stripe Restricted Key |

### Architecture

```
EcommerceChecker
├── check_url(url, session, html, headers, cookies)
│   ├── _detect_platforms()     → PlatformInfo list with confidence scores
│   ├── _run_probes()          → per-platform endpoint probing
│   ├── _detect_gateway_plugins() → HTML/JS gateway plugin scanning
│   └── _scan_for_secrets()     → credential/key pattern matching
├── check_and_report()          → check + Telegram reporting + persistence
├── _report_platform_detection() → platform detection alert
├── _report_finding()           → individual probe finding
├── _report_gateway_batch()     → gateway plugin batch report
├── _report_secret_finding()    → exposed credential alert
└── _persist_findings()         → save to gateway_keys table
```

### Config Fields (4 new)

| Field | Default | Description |
|-------|---------|-------------|
| `ecom_checker_enabled` | `True` | Enable e-commerce platform checking |
| `ecom_max_probes` | `15` | Max endpoint probes per platform per domain |
| `ecom_probe_timeout` | `10` | Timeout per probe request (seconds) |
| `ecom_platforms` | `["shopify","woocommerce","magento","prestashop","opencart"]` | Which platforms to check |

### Telegram Command

**`/ecom`** — Shows e-commerce checker stats:
- URLs checked, secrets found, credentials found
- Platform breakdown (how many of each detected)
- Payment gateway breakdown
- Findings by category and severity

### Pipeline Integration

- **Step 2c** in `process_url()`: Runs immediately after cookie hunter (Step 2b)
- Accepts pre-fetched HTML/headers/cookies from earlier pipeline steps (avoids re-fetching)
- All probe findings persisted to `gateway_keys` table with `ecom_checker:{platform}` source
- Stats included in `/cookies` status command
- Dedup prevents reporting same finding@domain twice

### Completion Checklist

- [x] `ecommerce_checker.py` — Platform fingerprinting (45+ sigs), 37 probes (5 platforms), gateway plugin detection (33 patterns), secret scanning (20 patterns)
- [x] `main_v3.py` — Import, pipeline init, Step 2c in process_url, `/ecom` command, features v3.8, handler registration
- [x] `config_v3.py` — 4 new ecom config fields
- [x] All files pass `py_compile`

---

## Recursive Crawler (v3.9)

The recursive crawler replaces all flat crawl logic across the pipeline with a **shared BFS crawler** that uses a priority queue, configurable depth limits, and real-time page processing callbacks.

### Problem Solved

Before v3.9, all crawling was flat:
- `deep_extract_site()` visited ~27 hardcoded paths (13 payment + 14 endpoint) at depth 1 only
- `cookie_hunter` probed up to 8 checkout links at depth 1
- `ecommerce_checker` probed platform-specific endpoints at depth 1
- `/scan` had an inline BFS with no depth tracking, no priority ordering, no configurability
- **Main dorking pipeline had ZERO link following** — each URL from search engines was processed in isolation

### Architecture

```
RecursiveCrawler
├── BFS with priority queue (heapq)
│   ├── PRIORITY_KEYWORDS: 50+ keywords → score 18-50 pts
│   │   (checkout=50, payment=50, admin=42, api=35, login=40, ...)
│   ├── HIGH_VALUE_PARAMS: id, cat, pid, item, search, q, ... → +12 pts each
│   ├── Dynamic extension: .php/.asp/.jsp → +10, .json/.xml → +8
│   └── Static asset penalty: .css/.png/.jpg/... → -50
├── URL normalization + dedup
│   ├── Fragment stripping
│   ├── Trailing slash normalization
│   ├── Scheme/host lowercasing
│   ├── Skip non-HTTP, off-domain, mailto/tel/javascript/data URIs
│   └── Skip SKIP_EXTENSIONS (30+ static asset types)
├── Link extraction (regex-based, faster than BeautifulSoup)
│   ├── href/src/action attributes
│   ├── Meta refresh redirects
│   ├── JavaScript location redirects
│   ├── Form discovery (action + method + input names)
│   └── Script source URLs
├── Concurrent fetching (asyncio.Semaphore)
├── Proxy rotation (via ProxyManager)
├── Cookie collection (including B3 distributed tracing)
├── robots.txt parsing (optional, off by default)
└── Real-time on_page callback (for live secret extraction)
```

### Integration Points

| Where | How | Depth | Max Pages |
|-------|-----|-------|-----------|
| `process_url()` pipeline | `quick_crawl()` — shallow + fast | 2 | 30 |
| `/scan` command (Phase 3) | `crawl()` — deep + thorough | 3 (config) | 50 (config) |
| Both | Secrets extracted in real-time via `on_page` callback | — | — |
| Both | Discovered param URLs fed to SQLi testing | — | — |
| Pipeline | Crawler-discovered param URLs → up to 5 extra SQLi tests (configurable) | — | — |

### Data Flow

```
Seed URL(s)
    │
    ▼
[Priority Queue] ─── score_url() ───▶ Higher score = crawled first
    │
    ├── fetch page (semaphore-bounded, proxy-rotated)
    │     │
    │     ├── Extract cookies (incl. B3) ──▶ CrawlResult.all_cookies
    │     ├── Extract links ──▶ normalize + dedup ──▶ back to queue (depth+1)
    │     ├── Extract forms ──▶ CrawlResult.form_targets (POST SQLi)
    │     ├── Extract scripts ──▶ CrawlResult.script_urls
    │     └── on_page callback ──▶ extract_from_text() → secrets
    │
    └── repeat until max_pages or queue empty or max_depth exceeded
```

### Classes & Functions

```
CrawlPage          — Single crawled page (url, depth, html, cookies, forms, scripts, ...)
CrawlResult         — Aggregate crawl result (pages, all_urls, param_urls, form_targets, cookies, b3, ...)
RecursiveCrawler    — Main crawler class
  ├── crawl()       — Full BFS crawl (configurable depth + pages)
  ├── quick_crawl() — Shallow crawl for pipeline (depth=1, pages=20)
  └── get_stats_text() — Stats for /crawlstats command
score_url()         — Priority scoring for URL ordering
normalize_url()     — URL normalization + filtering
extract_links()     — Regex-based link/form/script extraction
generate_seed_urls()— Common seed paths for a domain
```

### Config Fields

| Field | Default | Purpose |
|-------|---------|---------|
| `deep_crawl_enabled` | `True` | Enable recursive crawler |
| `deep_crawl_max_pages` | `50` | Max pages per domain (full /scan) |
| `deep_crawl_max_depth` | `3` | Max BFS depth (0=seed only) |
| `deep_crawl_timeout` | `10` | Per-page fetch timeout (seconds) |
| `deep_crawl_concurrent` | `10` | Max concurrent page fetches |
| `deep_crawl_delay` | `0.1` | Delay between fetches (rate limit) |
| `deep_crawl_robots` | `False` | Respect robots.txt Disallow rules |
| `deep_crawl_sqli_limit` | `5` | Max crawler-discovered param URLs to SQLi-test in pipeline |

### Telegram Command

**`/crawlstats`** — Shows recursive crawler stats:
- Total crawls performed
- Total pages fetched
- Total errors
- Unique domains crawled
- Current config (depth, pages, concurrent, timeout)

### Key Design Decisions

- **Regex-based link extraction** (not BeautifulSoup) — ~3x faster on large pages, handles malformed HTML gracefully
- **Priority queue** (heapq) not simple FIFO — ensures payment/checkout/admin pages are crawled first even at depth 3+
- **`quick_crawl()` for pipeline** — depth=2, max=30 pages. Fast enough for parallel URL processing but still discovers 10-20x more pages than the old flat approach
- **`on_page` callback** — secrets extracted as soon as each page loads, not after the entire crawl finishes. Reduces memory footprint and provides earlier findings
- **Fallback preserved** — if `deep_crawl_enabled=False`, pipeline falls back to the old `deep_extract_site()` flat crawl
- **Replaces inline BFS** in `/scan` — the old ~80-line manual crawler with BeautifulSoup is replaced by `RecursiveCrawler.crawl()` which is more efficient, has depth tracking, and priority ordering

### Completion Checklist

- [x] `recursive_crawler.py` — BFS crawler with priority queue, depth control, URL normalization, link/form/script extraction, cookie collection, proxy rotation, `on_page` callback
- [x] `main_v3.py` — Import, pipeline init, Step 3 replaced with crawler in `process_url()`, Step 6 crawler-discovered SQLi, `/scan` Phase 3 uses `RecursiveCrawler.crawl()`, `/crawlstats` command, features v3.9, handler registration, findings log includes crawl stats
- [x] `config_v3.py` — 8 deep_crawl config fields (expanded from 4)
- [x] All files pass `py_compile`

---

## File Map

```
dorker/
├── main_v3.py              ← ENTRY POINT: pipeline + telegram bot
├── config_v3.py            ← All configuration (incl. Firecrawl + Captcha + Browser + Ecom + Crawl)
├── engines.py              ← 9 search engines + captcha + proxy + browser fallback
├── browser_engine.py       ← Playwright headless browser search (6 engines, stealth)
├── ecommerce_checker.py    ← E-commerce platform checker (Shopify/WC/Magento/PS/OC)
├── recursive_crawler.py    ← BFS recursive crawler (depth control, priority queue, real-time callbacks)
├── captcha_solver.py       ← Multi-provider captcha solving (3 providers, 8 types)
├── proxy_manager.py        ← Smart proxy rotation (1150 proxies, 4 strategies, health checks)
├── cookie_hunter.py        ← Active B3 + gateway cookie hunting (46 patterns, 9 gateways, checkout probing)
├── dork_generator.py       ← 35 patterns × 616 keywords = 12,866+ dorks
├── waf_detector.py         ← WAF/CDN/CMS detection + bypass encoders
├── secret_extractor.py     ← 83-pattern secret scraper + deep crawler
├── sqli_scanner.py         ← SQLi testing (URL/cookie/header/POST)
├── sqli_dumper.py          ← Database exploitation + card/cred/key extraction + blind delegation
├── blind_dumper.py         ← Blind SQLi extraction (boolean + time, binary search, 5 DBMS)
├── reporter.py             ← Telegram message formatting
├── port_scanner.py         ← Port scanner (80+ ports, banner grab, service fingerprinting)
├── oob_sqli.py             ← OOB SQLi injector (DNS/HTTP exfiltration, interact.sh, 4 DBMS)
├── union_dumper.py          ← Multi-DBMS union dumper (MySQL/MSSQL/PostgreSQL/Oracle/SQLite)
├── key_validator.py         ← API key validator (16 key types, 13 live validators)
├── ml_filter.py             ← ML false positive filter (gradient boosted trees)
├── persistence.py          ← SQLite DB (16 tables)
├── requirements_v3.txt     ← Python dependencies (incl. playwright)
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
│   └── proxies.txt         ← Dead proxy list (legacy, replaced by CSV ProxyManager)
```

---

## Bot Token & Runtime

- **Bot Token:** `8187477232:AAEh3X22b1ddY9ZaVxc0x-j9MZQyTK9Wbp4`
- **Bot Username:** MedyDorker
- **Current PID:** Running as background process
- **Database:** `dorker.db` (SQLite, WAL mode)
- **Log:** `/tmp/dorker.log`
