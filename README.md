<p align="center">
  <img src="https://img.shields.io/badge/version-3.1-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-brightgreen?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platform-Telegram-2CA5E0?style=flat-square&logo=telegram" alt="Telegram">
  <img src="https://img.shields.io/badge/engines-23-orange?style=flat-square" alt="Engines">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

# MadyDorker v3.1

**Automated Reconnaissance & Vulnerability Scanner — Dual-Bot Telegram Framework**

MadyDorker is an all-in-one automated web reconnaissance framework controlled via Telegram. It combines multi-engine dorking, secret extraction, SQL injection scanning, cookie hunting, e-commerce detection, and data extraction into a continuous pipeline. v3.1 introduces 23-engine search, proxy rotation, headless browser fallback, and dual-bot deployment for maximum throughput.

---

## What's New in v3.1

- **23 Search Engines** — Added Exalead, Gigablast, Alexandria, Wiby, RightDao, Yep, MetaGer, Marginalia alongside the original 15
- **Proxy Rotation** — 250+ proxy support with weighted rotation, health checks, auto-ban, and IP-based auth
- **Dual-Bot Architecture** — Two independent bots splitting the dork pool for 2x throughput; Bot 2 commands use `2` suffix (`/status2`, `/dorkon2`, etc.)
- **Headless Browser Fallback** — Playwright/Chromium for JS-rendered pages (Google, Bing, DuckDuckGo, Startpage)
- **200K+ Payment-Focused Dorks** — v2 generator with 602 templates targeting e-commerce, checkout, and payment flows
- **E-commerce Detection** — Shopify, WooCommerce, Magento, PrestaShop, OpenCart fingerprinting
- **Cookie Hunter** — Session cookie extraction and analysis
- **ML False-Positive Filter** — Gradient boosted trees to reduce noise
- **API Key Validator** — 16 key types (Stripe, AWS, Twilio, SendGrid, etc.) with live validation
- **Extended Vuln Scanners** — XSS, SSTI, NoSQL injection, LFI, SSRF, CORS, Open Redirect, CRLF (8/8 enabled)
- **OOB SQLi Injector** — Out-of-band SQL injection detection
- **Auto Dumper Pipeline** — Inject → dump → parse → report automation
- **Noise Suppression** — B3 trace headers, commerce batch spam, and cloud trace noise filtered from reports

---

## Features

### Core Scanning Engine
- **Dynamic Dork Generation** — 602 pattern templates × 400+ keywords = 200,000+ payment-focused dorks per bot
- **23-Engine Search** — DuckDuckGo, Bing, Startpage, Yahoo, Ecosia, Qwant, Brave, AOL, Yandex, Ask, Dogpile, SearxNG, You.com, Mojeek, Naver, Exalead, Gigablast, Alexandria, Wiby, RightDao, Yep, MetaGer, Marginalia
- **Proxy Rotation** — Weighted round-robin with health checks, auto-ban after 5 consecutive failures, 250+ simultaneous proxies
- **Headless Browser** — Playwright/Chromium fallback for JS-heavy search engines with NoPeCHA captcha solving
- **WAF/CDN Detection** — Identifies Cloudflare, Akamai, AWS WAF, Sucuri, Imperva + 20 others
- **Deep Crawling** — Recursive link discovery up to depth 5, max 400 pages per site, JS onclick parsing

### Secret Extraction (210+ Patterns)
- **Payment Gateways** — Stripe (pk_live, sk_live), Braintree, PayPal, Square, Authorize.net, Adyen, NMI
- **Cloud Providers** — AWS (AKIA keys), GCP, Azure, DigitalOcean, Heroku, Firebase
- **Databases** — MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch connection strings
- **Card Data Detection** — Visa, Mastercard, Amex, Discover PAN detection with Luhn validation
- **Entropy-Based Detection** — Catches novel secrets via Shannon entropy analysis (>3.5 bits)
- **Sensitive File Exposure** — .env files, SQL dumps, phpinfo, git config, directory listings

### SQL Injection Scanner
- **5 DBMS Support** — MySQL, MSSQL, PostgreSQL, Oracle, SQLite
- **4 Techniques** — Error-based, UNION-based, Boolean-based, Time-based
- **47 Error Signatures** — Database-specific error pattern matching
- **Auto-Exploitation** — DIOS (Dump In One Shot), targeted table extraction, WAF bypass variants
- **OOB Injection** — Out-of-band detection for blind scenarios
- **Multi-DBMS Union Dumper** — Automated column enumeration and data extraction

### Extended Vulnerability Scanners
- **XSS** — Reflected/stored cross-site scripting detection
- **SSTI** — Server-side template injection (Jinja2, Twig, Freemarker, etc.)
- **NoSQL Injection** — MongoDB, CouchDB operator injection
- **LFI** — 206 file paths, 17 bypass techniques, sensitive data parsing
- **SSRF** — Server-side request forgery detection
- **CORS** — Misconfiguration detection (wildcard origins, credential leaks)
- **Open Redirect** — URL redirect chain analysis
- **CRLF Injection** — Header injection detection

### E-commerce & Cookie Hunting
- **Store Detection** — Shopify, WooCommerce, Magento, PrestaShop, OpenCart
- **Cookie Extraction** — Session cookies, auth tokens, payment-related cookies
- **Gateway Discovery** — Payment gateway endpoint identification

### Endpoint Discovery
- **AJAX Endpoints** — admin-ajax.php, wc-ajax, custom handlers
- **REST API** — wp-json, /api/v1, GraphQL
- **JS API URLs** — fetch(), axios, $.ajax, XMLHttpRequest targets
- **Hidden Form Fields** — CSRF tokens, debug flags, internal IDs
- **Internal Paths** — .php/.asp/.jsp with parameters

---

## Architecture

```
+---------------------------------------------------------------+
|                   Dual Telegram Bot Interface                  |
|         Bot 1: /dorkon /status /scan /export                   |
|         Bot 2: /dorkon2 /status2 /scan2 /export2               |
+-----------+-----------------------------+---------------------+
            |                             |
  +---------v---------+       +-----------v-----------+
  |  Dork Generator   |       |   Direct URL Scan     |
  | 602 templates     |       |   File / Reply input  |
  | 200K+ dorks/bot   |       |   Batch processing    |
  +---------+---------+       +-----------+-----------+
            |                             |
  +---------v-----------------------------v---------+
  |              23-Engine Multi-Search              |
  |   DDG - Bing - Startpage - Yahoo - Ecosia       |
  |   Qwant - Brave - AOL - Yandex - Ask - Dogpile  |
  |   SearxNG - You - Mojeek - Naver - Exalead      |
  |   Gigablast - Alexandria - Wiby - RightDao       |
  |   Yep - MetaGer - Marginalia                     |
  |        + Playwright/Chromium fallback             |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |             Proxy Rotation Layer                 |
  |   250+ proxies · weighted · health checks       |
  |   auto-ban · IP-based auth · per-engine         |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |          WAF/CDN Detection (20+ types)           |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |         Secret Extractor (210+ patterns)         |
  |  Gateways · Cloud · DB · Cards · Entropy · Files |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |           Vulnerability Scanners (8 types)       |
  | SQLi · XSS · SSTI · NoSQL · LFI · SSRF · CORS  |
  |              Open Redirect · CRLF                |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |        Auto Dumper · API Key Validator           |
  |   DIOS · Union · Error-based · 16 key types     |
  +---------------------+---------------------------+
                        |
  +---------------------v---------------------------+
  |       ML Filter · Reporter · Telegram Channel    |
  |   Gradient boosted trees · noise suppression     |
  +-----------------------------------------------------+
```

---

## Dual-Bot Deployment

MadyDorker supports running two independent bot instances splitting the dork pool for doubled throughput:

| | Bot 1 (Primary) | Bot 2 (Sister) |
|---|---|---|
| **Commands** | `/status`, `/dorkon`, `/export` | `/status2`, `/dorkon2`, `/export2` |
| **Dork Pool** | 286K dorks | 296K dorks |
| **Service** | `madydorker` | `madydorker2` |
| **Directory** | `~/NullIsADork/` | `~/NullIsADork2/` |

Both bots share the same Telegram channel for findings but have separate command namespaces.

---

## Installation

### Prerequisites
- Python 3.10+
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- (Optional) Proxy list for distributed searching
- (Optional) Playwright for headless browser fallback

### Setup

```bash
# Clone the repository
git clone git@github.com:NullMeDev/NullIsADork.git
cd NullIsADork

# Install dependencies
pip install -r requirements_v3.txt

# (Optional) Install Playwright for browser fallback
playwright install chromium

# Configure environment
cp .env.example .env
# Edit .env with your Telegram bot token and chat IDs
nano .env

# Run
python3 main_v3.py
```

### Docker

```bash
docker build -t madydorker .
docker run -d --env-file .env madydorker
```

### Systemd Service (Production)

```bash
# Copy service file
sudo cp madydorker.service /etc/systemd/system/
sudo systemctl enable madydorker
sudo systemctl start madydorker

# For dual-bot setup, create a second service for Bot 2
sudo cp madydorker.service /etc/systemd/system/madydorker2.service
# Edit ExecStart path and environment for Bot 2
sudo systemctl enable madydorker2
sudo systemctl start madydorker2
```

---

## Telegram Commands

### Bot 1 (Primary)

| Command | Description |
|---------|-------------|
| `/start` | Show help and available commands |
| `/dorkon` | Start continuous dork scanning cycle |
| `/dorkoff` | Stop the scanning cycle |
| `/status` | Show current pipeline status |
| `/export` | Export all findings to file |
| `/scan <url>` | Full deep scan (crawl + secrets + SQLi + LFI + XSS) |
| `/deepscan <url>` | Extended depth scan |
| `/mass` | Mass scan from URL list |
| `/target <domain>` | Focus dorking on specific domain |
| `/stopscan` | Stop current scan |
| `/cookies` | Cookie hunting stats |
| `/cookiehunt <url>` | Start cookie hunt on URL |
| `/dorkstats` | Dork effectiveness stats |
| `/sqlistats` | SQL injection scan stats |
| `/secrets` | Secret/API key findings |
| `/dumps` | Database dump results |
| `/keys` | API key validation stats |
| `/categories` | Finding categories breakdown |
| `/proxy` | Proxy status and config |
| `/browser` | Browser engine status |
| `/captcha` | Captcha solver status |
| `/ecom` | E-commerce detection stats |
| `/crawlstats` | Crawler statistics |
| `/ports` | Port scan results |
| `/oob` | OOB injection stats |
| `/unionstats` | Union dumper stats |
| `/stores` | Found online stores |
| `/mlfilter` | ML filter stats |
| `/hotreload` | Hot reload configuration |
| `/skip` | Skip current dork |

### Bot 2 (Sister) — Same commands with `2` suffix

All commands above are available with a `2` suffix: `/status2`, `/dorkon2`, `/export2`, `/scan2`, etc.

### Scan Options

```
/scan example.com                  Full maximum depth scan
/scan example.com quick            Fast scan (10 pages)
/scan example.com nosqli           Skip SQL injection testing
/scan example.com nodump           Don't auto-dump on SQLi
/scan example.com nolfi            Skip LFI testing
/scan quick nosqli (reply to file) Mass scan with options
```

---

## Search Engines

| Engine | Type | Rate Limiting |
|--------|------|--------------|
| Bing | Major | Moderate (proxy-mitigated) |
| Yahoo | Major | Light |
| DuckDuckGo | Privacy | Moderate |
| Startpage | Privacy proxy | Moderate |
| Ecosia | Green search | Light |
| Qwant | EU privacy | Moderate |
| Brave | Privacy | Moderate |
| AOL | Legacy | Light |
| Yandex | Russian | Moderate |
| Ask | Legacy | Light |
| Dogpile | Meta-search | Light |
| SearxNG | Open meta | Variable |
| You.com | AI search | Moderate |
| Mojeek | Independent | Light |
| Naver | Korean | Light |
| **Exalead** | French enterprise (Dassault) | Very light |
| **Gigablast** | Independent US, own crawler | None |
| **Alexandria** | Privacy, own index | None |
| **Wiby** | Retro/indie web | None |
| **RightDao** | Independent, own index | None |
| **Yep** | Ahrefs search | Light |
| **MetaGer** | German non-profit meta | Light |
| **Marginalia** | Indie, non-commercial focus | None |

Engines in **bold** were added in v3.1. All engines support proxy rotation and auto-failover.

---

## Configuration

All configuration is managed via environment variables (`.env` file):

| Variable | Description |
|----------|-------------|
| `DORKER_BOT_TOKEN` | Telegram bot token from @BotFather |
| `DORKER_CHAT_ID` | Your Telegram user ID for DM reports |
| `DORKER_GROUP_ID` | Telegram group ID for findings |
| `DORKER_OWNER_ID` | Authorized user ID (bot owner) |

Advanced settings in `config_v3.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `engines` | 23 engines | Active search engine list |
| `use_proxies` | `True` | Enable proxy rotation |
| `proxy_rotation_strategy` | `weighted` | Proxy selection algorithm |
| `search_delay_min/max` | `3/8` | Seconds between searches |
| `results_per_dork` | `50` | Max results per dork query |
| `browser_engines` | google, bing, ddg, startpage | Playwright fallback targets |
| `crawl_depth` | `5` | Recursive crawl depth |
| `crawl_max_pages` | `400` | Max pages per site |

---

## File Structure

```
├── main_v3.py              # Telegram bot + pipeline orchestration (5700+ lines)
├── config_v3.py            # Master configuration (23 engines, proxy, browser)
├── engines.py              # 23 search engine implementations + MultiSearch
├── secret_extractor.py     # Secret/key/card extraction (210+ patterns)
├── sqli_scanner.py         # SQL injection scanner (5 DBMS, 4 techniques)
├── sqli_dumper.py          # Multi-DBMS union data extraction
├── dork_generator.py       # Dynamic dork generator (602 templates)
├── cookie_hunter.py        # Cookie extraction and analysis
├── key_validator.py        # API key validation (16 types)
├── js_analyzer.py          # JavaScript endpoint analysis
├── waf_detector.py         # WAF/CDN fingerprinting (20+ types)
├── persistence.py          # SQLite state persistence
├── reporter.py             # Telegram report formatting
├── notifier.py             # Telegram notification helpers
├── validator.py            # Key validation (Stripe, etc.)
├── convert_dorks.py        # Dork format converter
├── generate_dorks_bot2.py  # Bot 2 dork generator
├── params/                 # Dork generation parameters
│   ├── kw.txt              # Keywords (400+)
│   ├── pp.txt              # URL parameter names (230+)
│   ├── pt.txt              # Page type extensions
│   ├── pf.txt              # Page filenames
│   ├── de.txt              # Domain extensions (88)
│   └── sf.txt              # Search operators
├── exports/                # Exported findings (JSON + TXT)
├── dumps/                  # Extracted data output
├── logs/                   # Runtime logs
├── .env.example            # Environment template
├── requirements_v3.txt     # Python dependencies
└── Dockerfile              # Container deployment
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built by <a href="https://github.com/NullMeDev">NullMeDev</a></sub>
</p>
