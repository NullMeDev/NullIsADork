"""
SQLite Persistence Layer — Replaces JSON files with proper database storage.

Stores: seen domains, vulnerable URLs, gateway keys, dork scores,
engine health stats, circuit breaker state, content hashes, cookies.
"""

import os
import json
import time
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from loguru import logger


class DorkerDB:
    """SQLite persistence for MedyDorker v3.0."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "dorker.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS seen_domains (
                domain TEXT PRIMARY KEY,
                first_seen REAL,
                last_seen REAL,
                scan_count INTEGER DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS vulnerable_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                parameter TEXT,
                injection_type TEXT,
                dbms TEXT,
                technique TEXT,
                confidence REAL,
                injection_point TEXT DEFAULT 'url',
                db_version TEXT,
                current_db TEXT,
                current_user TEXT,
                column_count INTEGER,
                payload_used TEXT,
                found_at REAL,
                UNIQUE(url, parameter, injection_type)
            );
            
            CREATE TABLE IF NOT EXISTS gateway_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                key_type TEXT NOT NULL,
                key_value TEXT NOT NULL,
                source TEXT,
                confidence REAL,
                found_at REAL,
                UNIQUE(key_type, key_value)
            );
            
            CREATE TABLE IF NOT EXISTS found_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                secret_type TEXT NOT NULL,
                key_name TEXT,
                value TEXT NOT NULL,
                category TEXT,
                confidence REAL,
                found_at REAL,
                UNIQUE(secret_type, value)
            );
            
            CREATE TABLE IF NOT EXISTS card_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                card_number TEXT,
                expiry TEXT,
                cvv TEXT,
                cardholder TEXT,
                source TEXT,
                found_at REAL
            );
            
            CREATE TABLE IF NOT EXISTS dork_scores (
                dork TEXT PRIMARY KEY,
                hits INTEGER DEFAULT 0,
                uses INTEGER DEFAULT 0,
                last_used REAL
            );
            
            CREATE TABLE IF NOT EXISTS engine_health (
                engine TEXT PRIMARY KEY,
                successes INTEGER DEFAULT 0,
                failures INTEGER DEFAULT 0,
                consecutive_failures INTEGER DEFAULT 0,
                cooldown_until REAL DEFAULT 0,
                last_used REAL
            );
            
            CREATE TABLE IF NOT EXISTS circuit_breaker (
                domain TEXT PRIMARY KEY,
                failures INTEGER DEFAULT 0,
                last_failure REAL,
                blocked_until REAL DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS content_hashes (
                hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                first_seen REAL
            );
            
            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                cookie_name TEXT NOT NULL,
                cookie_value TEXT NOT NULL,
                cookie_type TEXT,
                found_at REAL,
                UNIQUE(domain, cookie_name)
            );
            
            CREATE TABLE IF NOT EXISTS b3_cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT NOT NULL,
                found_at REAL
            );
            
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                scan_type TEXT,
                findings_count INTEGER DEFAULT 0,
                scanned_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_url ON vulnerable_urls(url);
            CREATE INDEX IF NOT EXISTS idx_gateway_type ON gateway_keys(key_type);
            CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies(domain);
            CREATE INDEX IF NOT EXISTS idx_b3_url ON b3_cookies(url);
        """)
        conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ═══════════════ DOMAIN TRACKING ═══════════════

    def add_seen_domain(self, domain: str):
        now = time.time()
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO seen_domains (domain, first_seen, last_seen, scan_count) 
            VALUES (?, ?, ?, 1)
            ON CONFLICT(domain) DO UPDATE SET 
                last_seen = ?, scan_count = scan_count + 1
        """, (domain, now, now, now))
        conn.commit()

    def is_domain_seen(self, domain: str) -> bool:
        conn = self._get_conn()
        row = conn.execute("SELECT 1 FROM seen_domains WHERE domain = ?", (domain,)).fetchone()
        return row is not None

    def get_seen_domains(self) -> set:
        conn = self._get_conn()
        rows = conn.execute("SELECT domain FROM seen_domains").fetchall()
        return {r["domain"] for r in rows}

    def get_seen_domain_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM seen_domains").fetchone()
        return row["cnt"]

    # ═══════════════ VULNERABLE URLS ═══════════════

    def add_vulnerable_url(self, vuln: Dict):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO vulnerable_urls 
                (url, parameter, injection_type, dbms, technique, confidence,
                 injection_point, db_version, current_db, current_user,
                 column_count, payload_used, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.get("url", ""), vuln.get("param", ""),
                vuln.get("type", ""), vuln.get("dbms", ""),
                vuln.get("technique", ""), vuln.get("confidence", 0),
                vuln.get("injection_point", "url"),
                vuln.get("db_version", ""), vuln.get("current_db", ""),
                vuln.get("current_user", ""), vuln.get("column_count", 0),
                vuln.get("payload_used", ""), time.time(),
            ))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert vuln error: {e}")

    def get_vulnerable_urls(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM vulnerable_urls ORDER BY found_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_vuln_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM vulnerable_urls").fetchone()
        return row["cnt"]

    # ═══════════════ GATEWAY KEYS ═══════════════

    def add_gateway_key(self, url: str, key_type: str, key_value: str,
                        source: str = "", confidence: float = 0.0):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO gateway_keys 
                (url, key_type, key_value, source, confidence, found_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (url, key_type, key_value, source, confidence, time.time()))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert gateway error: {e}")

    def get_gateway_keys(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM gateway_keys ORDER BY found_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_gateway_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM gateway_keys").fetchone()
        return row["cnt"]

    # ═══════════════ SECRETS ═══════════════

    def add_secret(self, url: str, secret_type: str, key_name: str,
                   value: str, category: str = "", confidence: float = 0.0):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO found_secrets 
                (url, secret_type, key_name, value, category, confidence, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (url, secret_type, key_name, value, category, confidence, time.time()))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert secret error: {e}")

    def get_secrets(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM found_secrets ORDER BY found_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_secret_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM found_secrets").fetchone()
        return row["cnt"]

    # ═══════════════ CARD DATA ═══════════════

    def add_card_data(self, url: str, card: Dict):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO card_data 
                (url, card_number, expiry, cvv, cardholder, source, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                url, card.get("card_number", ""), card.get("expiry", ""),
                card.get("cvv", ""), card.get("cardholder", ""),
                card.get("source", ""), time.time(),
            ))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert card error: {e}")

    def get_card_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM card_data").fetchone()
        return row["cnt"]

    # ═══════════════ DORK SCORES ═══════════════

    def update_dork_score(self, dork: str, url_count: int):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO dork_scores (dork, hits, uses, last_used)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(dork) DO UPDATE SET
                hits = hits + ?, uses = uses + 1, last_used = ?
        """, (dork, url_count, time.time(), url_count, time.time()))
        conn.commit()

    def get_top_dorks(self, limit: int = 50) -> List[Tuple[str, float]]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT dork, CAST(hits AS REAL) / CASE WHEN uses = 0 THEN 1 ELSE uses END as score
            FROM dork_scores ORDER BY score DESC LIMIT ?
        """, (limit,)).fetchall()
        return [(r["dork"], r["score"]) for r in rows]

    # ═══════════════ ENGINE HEALTH ═══════════════

    def update_engine_health(self, engine: str, success: bool):
        conn = self._get_conn()
        if success:
            conn.execute("""
                INSERT INTO engine_health (engine, successes, failures, consecutive_failures, last_used)
                VALUES (?, 1, 0, 0, ?)
                ON CONFLICT(engine) DO UPDATE SET
                    successes = successes + 1, consecutive_failures = 0, last_used = ?
            """, (engine, time.time(), time.time()))
        else:
            conn.execute("""
                INSERT INTO engine_health (engine, successes, failures, consecutive_failures, last_used)
                VALUES (?, 0, 1, 1, ?)
                ON CONFLICT(engine) DO UPDATE SET
                    failures = failures + 1, 
                    consecutive_failures = consecutive_failures + 1,
                    cooldown_until = CASE 
                        WHEN consecutive_failures + 1 >= 3 THEN ? 
                        ELSE cooldown_until 
                    END,
                    last_used = ?
            """, (engine, time.time(), time.time() + 300, time.time()))
        conn.commit()

    def get_engine_stats(self) -> Dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM engine_health").fetchall()
        return {r["engine"]: dict(r) for r in rows}

    # ═══════════════ CIRCUIT BREAKER ═══════════════

    def record_domain_failure(self, domain: str):
        now = time.time()
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO circuit_breaker (domain, failures, last_failure, blocked_until)
            VALUES (?, 1, ?, 0)
            ON CONFLICT(domain) DO UPDATE SET
                failures = failures + 1,
                last_failure = ?,
                blocked_until = CASE 
                    WHEN failures + 1 >= 3 THEN ?
                    ELSE blocked_until
                END
        """, (domain, now, now, now + 1800))  # Block for 30 minutes after 3 failures
        conn.commit()

    def reset_domain_failure(self, domain: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE circuit_breaker SET failures = 0, blocked_until = 0 WHERE domain = ?",
            (domain,)
        )
        conn.commit()

    def is_domain_blocked(self, domain: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT blocked_until FROM circuit_breaker WHERE domain = ?", (domain,)
        ).fetchone()
        if row and row["blocked_until"] > time.time():
            return True
        return False

    def get_blocked_domains(self) -> List[str]:
        now = time.time()
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT domain FROM circuit_breaker WHERE blocked_until > ?", (now,)
        ).fetchall()
        return [r["domain"] for r in rows]

    # ═══════════════ CONTENT HASH DEDUPLICATION ═══════════════

    def is_content_seen(self, content: str) -> bool:
        h = hashlib.md5(content.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        row = conn.execute("SELECT 1 FROM content_hashes WHERE hash = ?", (h,)).fetchone()
        return row is not None

    def add_content_hash(self, content: str, url: str):
        h = hashlib.md5(content.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO content_hashes (hash, url, first_seen) VALUES (?, ?, ?)",
                (h, url, time.time())
            )
            conn.commit()
        except Exception:
            pass

    def get_content_hash_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM content_hashes").fetchone()
        return row["cnt"]

    # ═══════════════ COOKIE STORAGE ═══════════════

    def add_cookie(self, url: str, name: str, value: str, cookie_type: str = ""):
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO cookies (url, domain, cookie_name, cookie_value, cookie_type, found_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, cookie_name) DO UPDATE SET
                    cookie_value = ?, found_at = ?
            """, (url, domain, name, value, cookie_type, time.time(), value, time.time()))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert cookie error: {e}")

    def add_b3_cookie(self, url: str, header_name: str, header_value: str):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO b3_cookies (url, header_name, header_value, found_at)
                VALUES (?, ?, ?, ?)
            """, (url, header_name, header_value, time.time()))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert b3 error: {e}")

    def get_all_cookies(self, domain: str = None) -> List[Dict]:
        conn = self._get_conn()
        if domain:
            rows = conn.execute(
                "SELECT * FROM cookies WHERE domain = ? ORDER BY found_at DESC", (domain,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cookies ORDER BY found_at DESC LIMIT 500"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_b3_cookies(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM b3_cookies ORDER BY found_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session_cookies(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM cookies 
            WHERE cookie_type IN ('session', 'auth') 
            ORDER BY found_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_cookie_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM cookies").fetchone()
        return row["cnt"]

    # ═══════════════ SCAN HISTORY ═══════════════

    def add_scan_record(self, url: str, scan_type: str = "auto", findings: int = 0):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO scan_history (url, scan_type, findings_count, scanned_at)
            VALUES (?, ?, ?, ?)
        """, (url, scan_type, findings, time.time()))
        conn.commit()

    # ═══════════════ SOFT-404 FINGERPRINTING ═══════════════

    _soft404_fingerprints: Dict[str, str] = {}

    def get_soft404_fingerprint(self, domain: str) -> Optional[str]:
        return self._soft404_fingerprints.get(domain)

    def set_soft404_fingerprint(self, domain: str, fingerprint: str):
        self._soft404_fingerprints[domain] = fingerprint

    # ═══════════════ MIGRATION FROM JSON FILES ═══════════════

    def import_from_json_files(self, seen_file: str = None, vuln_file: str = None,
                                gateway_file: str = None):
        """Import data from old JSON/text files into SQLite."""
        imported = 0
        
        if seen_file and os.path.exists(seen_file):
            with open(seen_file) as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        self.add_seen_domain(domain)
                        imported += 1
        
        if vuln_file and os.path.exists(vuln_file):
            try:
                with open(vuln_file) as f:
                    vulns = json.load(f)
                for v in vulns:
                    self.add_vulnerable_url(v)
                    imported += 1
            except Exception:
                pass
        
        if gateway_file and os.path.exists(gateway_file):
            try:
                with open(gateway_file) as f:
                    gateways = json.load(f)
                for g in gateways:
                    self.add_gateway_key(
                        g.get("url", ""), g.get("type", ""),
                        g.get("value", ""), g.get("source", "")
                    )
                    imported += 1
            except Exception:
                pass
        
        if imported > 0:
            logger.info(f"Imported {imported} records from JSON files")
        return imported

    # ═══════════════ STATS ═══════════════

    def get_stats(self) -> Dict:
        conn = self._get_conn()
        return {
            "domains_seen": self.get_seen_domain_count(),
            "vulns_found": self.get_vuln_count(),
            "gateways_found": self.get_gateway_count(),
            "secrets_found": self.get_secret_count(),
            "cards_found": self.get_card_count(),
            "cookies_collected": self.get_cookie_count(),
            "content_hashes": self.get_content_hash_count(),
            "blocked_domains": len(self.get_blocked_domains()),
        }
