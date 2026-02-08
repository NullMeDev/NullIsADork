# MadyDorker v4.0 — Improvement Roadmap

## Current State: v3.1 (~18,000 lines, 30+ modules)
**Strengths:** SQLi pipeline (9/10), secret detection (8/10), 9 search engines, WAF detection (30+), anti-bot evasion (9/10)  
**Weakness:** Vulnerability class coverage (3/10) — SQLi only. No XSS, SSTI, SSRF, NoSQL, LFI, CORS, cmd injection.

---

## TIER 1 — HIGH IMPACT, MODERATE EFFORT

### 1. XSS Scanner (`xss_scanner.py`) — NEW MODULE
**Why:** XSS is the #1 most common web vuln. Zero coverage currently.
- Reflected XSS detection (parameter reflection check → payload injection)
- DOM-based XSS via headless browser verification
- Stored XSS detection (input→check all pages for payload)
- Blind XSS callback (self-hosted Interactsh-style endpoint)
- Context-aware payloads (HTML tag, attribute, JS string, URL context)
- WAF bypass payloads (event handlers, encoding tricks, polyglots)
- **Pipeline integration:** After secret extraction, test reflected params for XSS
- **Research tools:** Dalfox techniques, XSStrike context analysis, kxss reflection testing
- **Bot command:** `/xss <url>` — scan URL for XSS

### 2. Subdomain Enumerator (`subdomain_enum.py`) — NEW MODULE
**Why:** Can't find vulns on subdomains you don't know about. Multiplies attack surface 10-100x.
- Certificate Transparency via crt.sh JSON API (free, no key needed)
- DNS brute-force with common subdomain wordlist
- Passive aggregation from SecurityTrails, VirusTotal, AlienVault OTX APIs
- Live host validation via HTTP probing
- Subdomain takeover detection (CNAME → dead service)
- **Bot command:** `/subs <domain>` — enumerate subdomains
- **Pipeline integration:** Optional pre-step before dorking — find all subdomains, then scan each

### 3. Directory Fuzzer (`dir_fuzzer.py`) — NEW MODULE
**Why:** Finds admin panels, backup files, config files, hidden endpoints that dorks miss.
- Wordlist-based path brute-force (SecLists common.txt, raft-medium)
- Extension fuzzing (.php, .bak, .old, .zip, .sql, .env, .git)
- Recursive discovery (configurable depth)
- Smart filtering (auto-calibrate on response size to filter custom 404s)
- Technology-specific wordlists (WordPress, Laravel, Django, Node.js)
- **Bot command:** `/fuzz <url>` — directory fuzz a target
- **Pipeline integration:** After initial URL discovery, fuzz for hidden paths

### 4. NoSQL Injection Scanner (`nosql_scanner.py`) — NEW MODULE
**Why:** MongoDB is everywhere. NoSQL injection is rampant and completely unscanned.
- MongoDB injection (`$gt`, `$ne`, `$regex`, `$where`)
- JSON body injection (replace string values with operator objects)
- Authentication bypass (`{"username": {"$ne": ""}, "password": {"$ne": ""}}`)
- Boolean-based blind NoSQL via `$regex` timing
- CouchDB `_all_docs` enumeration
- Redis command injection via SSRF
- **Bot command:** `/nosql <url>` — test for NoSQL injection

### 5. SSTI Scanner (`ssti_scanner.py`) — NEW MODULE
**Why:** SSTI → RCE in most cases. High-severity, easy to detect.
- Polyglot detection payload: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
- Engine fingerprinting (Jinja2, Twig, Freemarker, Velocity, ERB, Pug, Mako)
- RCE payload generation per engine after fingerprinting
- WAF bypass (Unicode normalization, string concatenation)
- **Pipeline integration:** Test same params as SQLi for template injection
- **Bot command:** `/ssti <url>` — test for SSTI

### 6. SSRF Scanner (`ssrf_scanner.py`) — NEW MODULE  
**Why:** 452% surge in SSRF attacks in 2025. Critical for cloud environments.
- Internal IP probing (169.254.169.254, 127.0.0.1, 10.x, 172.16.x, 192.168.x)
- Cloud metadata extraction (AWS/Azure/GCP endpoints)
- DNS rebinding detection
- Protocol smuggling (file://, gopher://, dict://)
- Blind SSRF via OOB callbacks (reuse OOB infrastructure from oob_sqli.py)
- **Bot command:** `/ssrf <url>` — test for SSRF

---

## TIER 2 — MEDIUM IMPACT, HIGH VALUE

### 7. Nuclei Integration (`nuclei_runner.py`) — NEW MODULE
**Why:** 11,997 templates, 3,587 CVEs, constantly updated. Force multiplier.
- Shell out to nuclei binary (install via `go install`)
- Template selection based on detected technology stack
- Severity filtering (critical + high by default)
- Parse nuclei JSON output → feed into reporter
- Custom templates for MadyDorker-specific findings
- **Bot command:** `/nuclei <url>` — run nuclei scan against target

### 8. Enhanced Secret Validation (`secret_extractor.py` upgrade)
**Why:** Finding secrets is useless without knowing if they're live. TruffleHog validates 800+ types.
- Add entropy-based detection for unknown key formats
- Expand validation to 30+ key types (add: Heroku, DigitalOcean, Datadog, New Relic, Sentry, PagerDuty, Zendesk, HubSpot, Notion, Airtable, etc.)
- Permission scope analysis after validation (what can this key access?)
- Automatic resource enumeration (S3 buckets, repos, channels, etc.)
- **Research source:** keyhacks repository validation commands

### 9. LFI/Path Traversal Scanner (`lfi_scanner.py`) — NEW MODULE
**Why:** Classic vuln, frequently found, leads to source code disclosure.
- `../` traversal payloads (Linux: /etc/passwd, Windows: C:\Windows\win.ini)
- PHP filter wrappers (`php://filter/convert.base64-encode/resource=`)
- Null byte injection (`%00`)
- Double encoding (`%252e%252e%252f`)
- WAF bypass variants (UTF-8 encoding, path normalization tricks)
- Log poisoning detection
- **Pipeline integration:** Test params with `file`, `path`, `page`, `include`, `template` names

### 10. Advanced Dork Generation with AI
**Why:** Static templates produce diminishing returns. AI dorks find novel patterns.
- LLM-powered dork generation (local Ollama or OpenAI API)
- Contextual dork suggestions based on target technology stack
- Dork mutation engine (combine, permute, extend successful dorks)
- Community dork database integration (DorkSearch 889K+ dorks)
- Google operator expansion: `AROUND(n)`, `before:`/`after:`, `allintitle:`
- **Config option:** Ollama endpoint or OpenAI API key

### 11. Camoufox/BrowserForge Integration
**Why:** Current Playwright stealth is good but Camoufox is next-gen (C++ level fingerprint injection).
- Replace Playwright stealth with Camoufox for browser-based operations
- BrowserForge for realistic header + fingerprint generation per request
- Rotate fingerprints per target (not just per session)
- Geolocation spoofing based on proxy region
- Human-like mouse movements and scroll patterns

---

## TIER 3 — SPECIALIZED / NICE-TO-HAVE

### 12. GraphQL Injection Scanner
**Why:** JS analyzer already finds GraphQL endpoints. Should test them.
- Introspection query abuse (`__schema`, `__type`)
- Query depth attacks (nested queries for DoS)
- Batch query exploitation
- Field suggestion abuse
- Authorization testing per field/mutation

### 13. CORS Misconfiguration Scanner
- Test `Origin` header reflection
- Null origin bypass
- Subdomain wildcard misconfiguration
- Credential inclusion testing

### 14. Open Redirect Scanner  
- Parameter-based redirect detection
- JavaScript redirect detection
- Meta refresh redirect detection
- Chained redirect abuse

### 15. CRLF Injection Scanner
- Header injection via `%0d%0a`
- Response splitting
- HTTP smuggling basics

### 16. JWT Attack Suite
- `alg: none` bypass
- Key confusion (RS256 → HS256)
- Weak secret brute-force (hashcat/john integration)
- Expired token reuse testing

### 17. WebSocket Security Scanner
- Cross-site WebSocket hijacking
- Message injection
- Authentication bypass
- Information disclosure

### 18. Enhanced Reporting
- HTML report generation (styled, with charts)
- JSON/SARIF export for tool integration
- Discord/Slack webhook notifications
- PDF report generation
- Severity scoring (CVSS-like)
- `/report <format>` command

### 19. Recon Pipeline (`recon_pipeline.py`)
- Full automated recon: subs → live hosts → port scan → tech detect → dir fuzz → vuln scan
- `/recon <domain>` — full domain reconnaissance
- Chained tool orchestration with progress tracking

### 20. Credential Stuffing Module
- Test found credentials against common services
- Multi-service login testing (with rate limiting)
- Breach database lookup integration (HaveIBeenPwned API)
- **Bot command:** `/credcheck <email>` — check if email is in breach databases

---

## IMPLEMENTATION PRIORITY ORDER

```
Phase 1 (v3.2): XSS Scanner + SSTI Scanner + NoSQL Scanner
Phase 2 (v3.3): Subdomain Enum + Directory Fuzzer + LFI Scanner
Phase 3 (v3.4): SSRF Scanner + CORS + Open Redirect + CRLF
Phase 4 (v3.5): Nuclei Integration + Enhanced Secrets + AI Dorks
Phase 5 (v4.0): Camoufox + GraphQL + JWT + WebSocket + Recon Pipeline + HTML Reports
```

## ESTIMATED LINES OF CODE PER MODULE

| Module | Est. Lines | Priority |
|---|---|---|
| xss_scanner.py | ~800-1000 | Phase 1 |
| ssti_scanner.py | ~400-500 | Phase 1 |
| nosql_scanner.py | ~500-600 | Phase 1 |
| subdomain_enum.py | ~600-700 | Phase 2 |
| dir_fuzzer.py | ~500-600 | Phase 2 |
| lfi_scanner.py | ~400-500 | Phase 2 |
| ssrf_scanner.py | ~500-600 | Phase 3 |
| cors_scanner.py | ~200-300 | Phase 3 |
| redirect_scanner.py | ~200-300 | Phase 3 |
| crlf_scanner.py | ~150-200 | Phase 3 |
| nuclei_runner.py | ~400-500 | Phase 4 |
| graphql_scanner.py | ~400-500 | Phase 5 |
| jwt_attacker.py | ~400-500 | Phase 5 |
| websocket_scanner.py | ~300-400 | Phase 5 |
| recon_pipeline.py | ~600-800 | Phase 5 |
| html_reporter.py | ~500-700 | Phase 5 |

**Total new code: ~6,500-8,500 lines across 16 new modules**
**Current codebase: ~18,000 lines**
**Projected v4.0: ~26,000+ lines**

---

## QUICK WINS (Can implement in 1 session each)

1. **CORS scanner** — ~200 lines, simple Origin header testing
2. **CRLF scanner** — ~150 lines, header injection testing
3. **Open redirect** — ~200 lines, redirect parameter testing
4. **Enhanced dork operators** — Add AROUND(n), before:/after: to existing dork_generator.py
5. **crt.sh subdomain lookup** — ~100 lines, simple HTTPS GET + JSON parse
6. **HaveIBeenPwned integration** — ~100 lines via API

---

*Research conducted: 2025-02-08*  
*Sources: Firecrawl deep search (3 research queries, ~5,000 lines of data)*  
*Tools analyzed: 50+ (sqlmap, ghauri, Nuclei v3, Dalfox, XSStrike, ffuf, feroxbuster, TruffleHog v3, GitLeaks, Camoufox, BrowserForge, subfinder, Amass, GoHunt, and more)*
