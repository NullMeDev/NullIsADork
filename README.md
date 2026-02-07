<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-brightgreen?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platform-Telegram-2CA5E0?style=flat-square&logo=telegram" alt="Telegram">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

# MedyDorker v3.0

**Automated Reconnaissance & Vulnerability Scanner — Telegram Bot Interface**

MedyDorker is an all-in-one automated web reconnaissance framework controlled via Telegram. It combines Google dorking, secret extraction, SQL injection scanning, LFI detection, admin panel discovery, and data extraction into a single pipeline that runs continuously in the background.

---

## Features

### Core Scanning Engine
- **Dynamic Dork Generation** — 45+ pattern templates x 400+ keywords = thousands of unique search queries
- **Multi-Engine Search** — DuckDuckGo, Bing, Startpage, Yahoo, Ecosia, Qwant, Brave with auto-rotation
- **WAF/CDN Detection** — Identifies Cloudflare, Akamai, AWS WAF, Sucuri, Imperva + 20 others
- **Deep Crawling** — Recursive internal link discovery, JS onclick parsing, up to 100+ pages per site

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
- **Error-Based Data Extraction** — EXTRACTVALUE/UPDATEXML (MySQL), CONVERT (MSSQL), CAST (PostgreSQL)

### LFI Scanner
- **206 File Paths** — Linux, Windows, macOS, web server configs, logs, credentials
- **17 Bypass Techniques** — Null byte, double encoding, path truncation, filter wrappers
- **Sensitive Data Extraction** — Parses /etc/passwd, wp-config.php, .env, shadow files

### Endpoint Discovery
- **AJAX Endpoints** — admin-ajax.php, wc-ajax, custom handlers
- **REST API** — wp-json, /api/v1, GraphQL
- **JS API URLs** — fetch(), axios, $.ajax, XMLHttpRequest targets
- **Hidden Form Fields** — CSRF tokens, debug flags, internal IDs
- **Internal Paths** — .php/.asp/.jsp with parameters

### Admin Panel Finder
- **100+ Common Paths** — WordPress, Joomla, Drupal, Laravel, Django, custom CMS
- **Smart Detection** — Login form recognition, CMS fingerprinting

---

## Architecture

```
+---------------------------------------------------------+
|                    Telegram Bot Interface                |
|  /dorkon /scan /adminfinder /lfi /cardhunt /masscheck   |
+---------------+-----------------------------+-----------+
                |                             |
     +----------v----------+       +----------v----------+
     |   Dork Generator    |       |   Direct URL Scan   |
     |  45 patterns x 400  |       |  File / Reply input |
     |    keyword combos   |       |  Batch processing   |
     +----------+----------+       +----------+----------+
                |                             |
     +----------v-----------------------------v----------+
     |              Multi-Engine Search                   |
     |     DuckDuckGo - Bing - Startpage - Yahoo         |
     |       Ecosia - Qwant - Brave (with rotation)      |
     +------------------------+---------------------------+
                              |
     +------------------------v--------------------------+
     |               WAF / CDN Detection                  |
     |  Cloudflare - Akamai - AWS - Sucuri - Imperva     |
     +------------------------+--------------------------+
                              |
     +------------------------v--------------------------+
     |             Secret Extractor (210+ patterns)       |
     |  Gateways - Cloud - DB - Cards - Entropy - Files  |
     +------------------------+--------------------------+
                              |
     +------------------------v--------------------------+
     |              SQL Injection Scanner                  |
     |  Error - UNION - Boolean - Time-based - 5 DBMS    |
     +------------------------+--------------------------+
                              |
     +------------------------v--------------------------+
     |              Data Dumper / Exploiter                |
     |   DIOS - Targeted - Error-based - WAF Bypass      |
     +------------------------+--------------------------+
                              |
     +------------------------v--------------------------+
     |               Telegram Reporter                    |
     |       Real-time alerts - Formatted reports         |
     +---------------------------------------------------+
```

---

## Installation

### Prerequisites
- Python 3.10+
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))

### Setup

```bash
# Clone the repository
git clone git@github.com:NullMeDev/NullIsADork.git
cd NullIsADork

# Install dependencies
pip install -r requirements_v3.txt

# Configure environment
cp .env.example .env
# Edit .env with your Telegram bot token and chat IDs
nano .env

# Run
python3 main_v3.py
```

### Docker

```bash
docker build -t medydorker .
docker run -d --env-file .env medydorker
```

---

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Show help and available commands |
| `/dorkon` | Start continuous dork scanning cycle |
| `/dorkoff` | Stop the scanning cycle |
| `/status` | Show current pipeline status |
| `/scan <url>` | Full deep scan (crawl + secrets + SQLi + LFI) |
| `/scan` (attach .txt) | Mass scan from file (one URL per line) |
| `/scan` (reply to file) | Mass scan from replied-to text file |
| `/adminfinder <url>` | Find admin panels on target |
| `/lfi <url>` | Test for Local File Inclusion |
| `/lfiextract <url>` | Extract sensitive files via LFI |
| `/cardhunt <url>` | Hunt for card data in database |
| `/masscheck` | Mass SQLi check from file or URL list |
| `/jobs` | Show running background jobs |
| `/dorkstats` | Dork generation statistics |
| `/sqlistats` | SQL injection scan statistics |
| `/secrets` | View found secrets summary |
| `/dumps` | View extracted data dumps |
| `/categories` | List dork categories |
| `/target <domain>` | Focus dorking on specific domain |

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

## Configuration

All configuration is managed via environment variables (`.env` file):

| Variable | Description |
|----------|-------------|
| `DORKER_BOT_TOKEN` | Telegram bot token from @BotFather |
| `DORKER_CHAT_ID` | Your Telegram user ID for DM reports |
| `DORKER_GROUP_ID` | Telegram group ID for findings |
| `DORKER_OWNER_ID` | Authorized user ID (bot owner) |

Advanced settings are in `config_v3.py` — search delays, proxy config, scan depth, DBMS selection, etc.

---

## File Structure

```
├── main_v3.py              # Telegram bot + pipeline orchestration
├── config_v3.py            # Master configuration
├── secret_extractor.py     # Secret/key/card extraction engine
├── sqli_scanner.py         # SQL injection scanner
├── sqli_dumper.py          # Data extraction/dumping
├── dork_generator.py       # Dynamic dork query generator
├── engines.py              # Search engine wrappers
├── waf_detector.py         # WAF/CDN fingerprinting
├── validator.py            # Key validation (Stripe, etc.)
├── notifier.py             # Telegram notification helpers
├── reporter.py             # Report formatting
├── params/                 # Dork generation parameters
│   ├── kw.txt              # Keywords (400+)
│   ├── pp.txt              # URL parameter names (230+)
│   ├── pt.txt              # Page type extensions
│   ├── pf.txt              # Page filenames
│   ├── de.txt              # Domain extensions (88)
│   └── sf.txt              # Search operators
├── dumps/                  # Extracted data output
├── logs/                   # Runtime logs
├── .env.example            # Environment template
├── requirements_v3.txt     # Python dependencies
└── Dockerfile              # Container deployment
```

---

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Use only on systems you own or have **explicit written permission** to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built by <a href="https://github.com/NullMeDev">NullMeDev</a></sub>
</p>
