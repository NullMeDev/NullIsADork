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
import threading
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from loguru import logger


class DorkerDB:
    """SQLite persistence for MadyDorker v3.0."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "dorker.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create the database connection (thread-safe via _lock)."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False,
                                         timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
        return self._conn

    def _init_db(self):
        with self._lock:
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
            
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT,
                ip TEXT,
                port INTEGER,
                service TEXT,
                banner TEXT,
                version TEXT,
                risk TEXT,
                notes TEXT,
                found_at REAL
            );
            
            CREATE TABLE IF NOT EXISTS oob_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                parameter TEXT,
                dbms TEXT,
                channel TEXT,
                extraction TEXT,
                callbacks INTEGER DEFAULT 0,
                payloads_sent INTEGER DEFAULT 0,
                found_at REAL,
                UNIQUE(url, parameter, dbms)
            );
            
            CREATE TABLE IF NOT EXISTS key_validations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                is_live INTEGER DEFAULT 0,
                confidence REAL,
                risk_level TEXT,
                account_info TEXT,
                permissions TEXT,
                source_url TEXT,
                found_at REAL,
                UNIQUE(key_type, key_hash)
            );
            
            CREATE TABLE IF NOT EXISTS processed_urls (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                processed_at REAL NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS dork_checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                cycle INTEGER NOT NULL DEFAULT 0,
                dork_index INTEGER NOT NULL DEFAULT 0,
                dork_hash TEXT,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS stripe_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                url TEXT NOT NULL,
                sk_live TEXT NOT NULL,
                pk_live TEXT,
                sk_test TEXT,
                pk_test TEXT,
                is_validated INTEGER DEFAULT 0,
                is_live INTEGER DEFAULT 0,
                account_id TEXT,
                account_email TEXT,
                business_name TEXT,
                country TEXT,
                balance_json TEXT,
                charges_count INTEGER DEFAULT 0,
                customers_count INTEGER DEFAULT 0,
                products_count INTEGER DEFAULT 0,
                subscriptions_count INTEGER DEFAULT 0,
                risk_level TEXT,
                permissions TEXT,
                found_at REAL,
                validated_at REAL,
                UNIQUE(sk_live)
            );

            CREATE TABLE IF NOT EXISTS shopify_stores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                url TEXT NOT NULL,
                store_name TEXT,
                payment_gateway TEXT,
                checkout_url TEXT,
                has_stripe_keys INTEGER DEFAULT 0,
                platform_confidence REAL,
                cookies_json TEXT,
                findings_json TEXT,
                found_at REAL,
                last_seen REAL,
                UNIQUE(domain)
            );

            CREATE INDEX IF NOT EXISTS idx_port_domain ON port_scans(domain);
            CREATE INDEX IF NOT EXISTS idx_oob_url ON oob_results(url);
            CREATE INDEX IF NOT EXISTS idx_key_type ON key_validations(key_type);
            CREATE TABLE IF NOT EXISTS failed_urls (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                fail_count INTEGER DEFAULT 1,
                last_error TEXT,
                first_failed REAL NOT NULL,
                last_failed REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_processed_domain ON processed_urls(domain);
            CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_urls(processed_at);
            CREATE INDEX IF NOT EXISTS idx_failed_domain ON failed_urls(domain);
            CREATE INDEX IF NOT EXISTS idx_stripe_keys_domain ON stripe_keys(domain);
            CREATE INDEX IF NOT EXISTS idx_shopify_domain ON shopify_stores(domain);

            CREATE TABLE IF NOT EXISTS registered_users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                activated INTEGER DEFAULT 0,
                role TEXT DEFAULT 'user',
                registered_at REAL,
                activated_at REAL,
                activated_by INTEGER
            );

            CREATE TABLE IF NOT EXISTS payment_sites (
                domain TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                gateway TEXT NOT NULL,
                method TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                has_params INTEGER DEFAULT 0,
                html_matches TEXT,
                discovered_at REAL NOT NULL,
                last_scanned REAL,
                scan_count INTEGER DEFAULT 0,
                sqli_found INTEGER DEFAULT 0,
                cards_found INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_payment_gateway ON payment_sites(gateway);
            CREATE INDEX IF NOT EXISTS idx_payment_active ON payment_sites(active);
            CREATE INDEX IF NOT EXISTS idx_payment_confidence ON payment_sites(confidence);
        """)
        conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ═══════════════ USER REGISTRATION ═══════════════

    def register_user(self, user_id: int, username: str = None,
                      first_name: str = None) -> bool:
        """Register a user (pending activation). Returns True if newly registered."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO registered_users
                       (user_id, username, first_name, activated, role, registered_at)
                       VALUES (?, ?, ?, 0, 'user', ?)""",
                    (user_id, username, first_name, now),
                )
                conn.commit()
                return True
            except Exception:
                # Already exists
                return False

    def activate_user(self, user_id: int, activated_by: int) -> bool:
        """Activate a registered user. Returns True if updated."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                """UPDATE registered_users
                   SET activated = 1, activated_at = ?, activated_by = ?
                   WHERE user_id = ?""",
                (now, activated_by, user_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate a user. Returns True if updated."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                "UPDATE registered_users SET activated = 0 WHERE user_id = ?",
                (user_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def is_user_activated(self, user_id: int) -> bool:
        """Check if a user is activated."""
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT activated FROM registered_users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return bool(row and row["activated"])

    def get_registered_users(self) -> list:
        """Get all registered users."""
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(
                """SELECT user_id, username, first_name, activated, role,
                          registered_at, activated_at
                   FROM registered_users ORDER BY registered_at"""
            ).fetchall()
            return [dict(r) for r in rows]

    def set_user_role(self, user_id: int, role: str) -> bool:
        """Set user role (owner/admin/user)."""
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                "UPDATE registered_users SET role = ? WHERE user_id = ?",
                (role, user_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def ensure_owner(self, owner_id: int):
        """Ensure the owner is registered and activated."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """INSERT INTO registered_users
                   (user_id, username, first_name, activated, role, registered_at, activated_at)
                   VALUES (?, 'owner', 'Owner', 1, 'owner', ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET activated = 1, role = 'owner'""",
                (owner_id, now, now),
            )
            conn.commit()

    # ═══════════════ PAYMENT SITE DISCOVERY ═══════════════

    def save_payment_site(self, domain: str, url: str, gateway: str, method: str,
                          confidence: float, has_params: bool, html_matches: list = None):
        """Save or update a discovered payment site."""
        now = time.time()
        matches_json = json.dumps(html_matches or [])
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO payment_sites
                    (domain, url, gateway, method, confidence, has_params, html_matches, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    confidence = MAX(confidence, excluded.confidence),
                    has_params = MAX(has_params, excluded.has_params),
                    url = CASE WHEN excluded.confidence > confidence THEN excluded.url ELSE url END,
                    gateway = CASE WHEN excluded.confidence > confidence THEN excluded.gateway ELSE gateway END
            """, (domain, url, gateway, method, confidence, int(has_params), matches_json, now))
            conn.commit()

    def get_payment_sites(self, active_only: bool = True, min_confidence: float = 0.0,
                          gateway: str = None, limit: int = 5000) -> list:
        """Get discovered payment sites. Returns list of dicts."""
        with self._lock:
            conn = self._get_conn()
            sql = "SELECT * FROM payment_sites WHERE 1=1"
            params = []
            if active_only:
                sql += " AND active = 1"
            if min_confidence > 0:
                sql += " AND confidence >= ?"
                params.append(min_confidence)
            if gateway:
                sql += " AND gateway = ?"
                params.append(gateway)
            sql += " ORDER BY confidence DESC, has_params DESC LIMIT ?"
            params.append(limit)
            cur = conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_payment_site_domains(self) -> set:
        """Get set of all known payment site domains (for fast lookup)."""
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute("SELECT domain FROM payment_sites WHERE active = 1").fetchall()
            return {r[0] for r in rows}

    def get_unscanned_payment_sites(self, max_age_hours: int = 48, limit: int = 200) -> list:
        """Get payment sites that haven't been scanned recently."""
        cutoff = time.time() - (max_age_hours * 3600)
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute("""
                SELECT * FROM payment_sites
                WHERE active = 1 AND (last_scanned IS NULL OR last_scanned < ?)
                ORDER BY confidence DESC, has_params DESC
                LIMIT ?
            """, (cutoff, limit))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def mark_payment_site_scanned(self, domain: str, sqli_found: bool = False,
                                   cards_found: bool = False):
        """Update scan timestamp and findings for a payment site."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                UPDATE payment_sites SET
                    last_scanned = ?,
                    scan_count = scan_count + 1,
                    sqli_found = sqli_found + ?,
                    cards_found = cards_found + ?
                WHERE domain = ?
            """, (now, int(sqli_found), int(cards_found), domain))
            conn.commit()

    def get_payment_stats(self) -> dict:
        """Get aggregate stats about payment sites."""
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN has_params = 1 THEN 1 ELSE 0 END) as injectable,
                    SUM(sqli_found) as total_sqli,
                    SUM(cards_found) as total_cards,
                    SUM(scan_count) as total_scans,
                    AVG(confidence) as avg_confidence
                FROM payment_sites
            """).fetchone()
            gw_rows = conn.execute("""
                SELECT gateway, COUNT(*) as cnt FROM payment_sites
                WHERE active = 1
                GROUP BY gateway ORDER BY cnt DESC
            """).fetchall()
            return {
                "total": row[0] or 0,
                "active": row[1] or 0,
                "injectable": row[2] or 0,
                "total_sqli": row[3] or 0,
                "total_cards": row[4] or 0,
                "total_scans": row[5] or 0,
                "avg_confidence": round(row[6] or 0, 2),
                "gateways": {r[0]: r[1] for r in gw_rows},
            }

    def payment_site_count(self) -> int:
        with self._lock:
            conn = self._get_conn()
            return conn.execute("SELECT COUNT(*) FROM payment_sites WHERE active = 1").fetchone()[0]

    # ═══════════════ DOMAIN TRACKING ═══════════════

    def add_seen_domain(self, domain: str):
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO seen_domains (domain, first_seen, last_seen, scan_count) 
            VALUES (?, ?, ?, 1)
            ON CONFLICT(domain) DO UPDATE SET 
                last_seen = ?, scan_count = scan_count + 1
        """,
            (domain, now, now, now),
        )
        conn.commit()

    def is_domain_seen(self, domain: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM seen_domains WHERE domain = ?", (domain,)
        ).fetchone()
        return row is not None

    def is_domain_on_cooldown(self, domain: str, cooldown_hours: int = 24) -> bool:
        """Check if domain was scanned within the cooldown period.

        Returns True if domain should be skipped (still on cooldown).
        Returns False if domain can be revisited (cooldown expired or never seen).
        If cooldown_hours == 0, acts as permanent block (old behavior).
        """
        if cooldown_hours == 0:
            return self.is_domain_seen(domain)
        conn = self._get_conn()
        cutoff = time.time() - (cooldown_hours * 3600)
        row = conn.execute(
            "SELECT last_seen FROM seen_domains WHERE domain = ? AND last_seen > ?",
            (domain, cutoff),
        ).fetchone()
        return row is not None

    def add_processed_url(self, url: str, domain: str):
        """Record a URL as processed (permanent URL-level dedup)."""
        import hashlib

        url_hash = hashlib.md5(url.encode(errors="ignore")).hexdigest()
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """
            INSERT OR IGNORE INTO processed_urls (url_hash, url, domain, processed_at)
            VALUES (?, ?, ?, ?)
        """,
            (url_hash, url[:2000], domain, now),
        )
        conn.commit()

    def is_url_processed(self, url: str) -> bool:
        """Check if this exact URL has been processed before."""
        import hashlib

        url_hash = hashlib.md5(url.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM processed_urls WHERE url_hash = ?", (url_hash,)
        ).fetchone()
        return row is not None

    def get_processed_url_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM processed_urls").fetchone()
        return row["cnt"]

    def cleanup_old_processed_urls(self, max_age_days: int = 30):
        """Remove processed URL entries older than max_age_days to keep DB lean."""
        cutoff = time.time() - (max_age_days * 86400)
        conn = self._get_conn()
        conn.execute("DELETE FROM processed_urls WHERE processed_at < ?", (cutoff,))
        conn.commit()

    # ═══════════════ FAILED URL TRACKING (retry logic) ═══════════════

    def record_url_failure(self, url: str, domain: str, error: str = ""):
        """Record a URL processing failure. Increments fail_count on each call."""
        import hashlib

        url_hash = hashlib.md5(url.encode(errors="ignore")).hexdigest()
        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO failed_urls (url_hash, url, domain, fail_count, last_error, first_failed, last_failed)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(url_hash) DO UPDATE SET
                    fail_count = fail_count + 1,
                    last_error = ?,
                    last_failed = ?
            """,
                (url_hash, url[:2000], domain, error, now, now, error, now),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB record_url_failure error: {e}")

    def get_url_fail_count(self, url: str) -> int:
        """Return the number of times this URL has failed processing."""
        import hashlib

        url_hash = hashlib.md5(url.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT fail_count FROM failed_urls WHERE url_hash = ?", (url_hash,)
        ).fetchone()
        return row["fail_count"] if row else 0

    def clear_url_failure(self, url: str):
        """Remove failure record for a URL (called on successful processing)."""
        import hashlib

        url_hash = hashlib.md5(url.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM failed_urls WHERE url_hash = ?", (url_hash,))
            conn.commit()
        except Exception as e:
            logger.debug(f"DB clear_url_failure error: {e}")

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
            conn.execute(
                """
                INSERT OR IGNORE INTO vulnerable_urls 
                (url, parameter, injection_type, dbms, technique, confidence,
                 injection_point, db_version, current_db, current_user,
                 column_count, payload_used, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    vuln.get("url", ""),
                    vuln.get("param", ""),
                    vuln.get("type", ""),
                    vuln.get("dbms", ""),
                    vuln.get("technique", ""),
                    vuln.get("confidence", 0),
                    vuln.get("injection_point", "url"),
                    vuln.get("db_version", ""),
                    vuln.get("current_db", ""),
                    vuln.get("current_user", ""),
                    vuln.get("column_count", 0),
                    vuln.get("payload_used", ""),
                    time.time(),
                ),
            )
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

    def add_gateway_key(
        self,
        url: str,
        key_type: str,
        key_value: str,
        source: str = "",
        confidence: float = 0.0,
    ):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO gateway_keys 
                (url, key_type, key_value, source, confidence, found_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (url, key_type, key_value, source, confidence, time.time()),
            )
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

    def add_secret(
        self,
        url: str,
        secret_type: str,
        key_name: str,
        value: str,
        category: str = "",
        confidence: float = 0.0,
    ):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO found_secrets 
                (url, secret_type, key_name, value, category, confidence, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (url, secret_type, key_name, value, category, confidence, time.time()),
            )
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
            conn.execute(
                """
                INSERT INTO card_data 
                (url, card_number, expiry, cvv, cardholder, source, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    url,
                    card.get("card_number", ""),
                    card.get("expiry", ""),
                    card.get("cvv", ""),
                    card.get("cardholder", ""),
                    card.get("source", ""),
                    time.time(),
                ),
            )
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
        conn.execute(
            """
            INSERT INTO dork_scores (dork, hits, uses, last_used)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(dork) DO UPDATE SET
                hits = hits + ?, uses = uses + 1, last_used = ?
        """,
            (dork, url_count, time.time(), url_count, time.time()),
        )
        conn.commit()

    def get_top_dorks(self, limit: int = 50) -> List[Tuple[str, float]]:
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT dork, CAST(hits AS REAL) / CASE WHEN uses = 0 THEN 1 ELSE uses END as score
            FROM dork_scores ORDER BY score DESC LIMIT ?
        """,
            (limit,),
        ).fetchall()
        return [(r["dork"], r["score"]) for r in rows]

    # ═══════════════ ENGINE HEALTH ═══════════════

    def update_engine_health(self, engine: str, success: bool):
        conn = self._get_conn()
        if success:
            conn.execute(
                """
                INSERT INTO engine_health (engine, successes, failures, consecutive_failures, last_used)
                VALUES (?, 1, 0, 0, ?)
                ON CONFLICT(engine) DO UPDATE SET
                    successes = successes + 1, consecutive_failures = 0, last_used = ?
            """,
                (engine, time.time(), time.time()),
            )
        else:
            conn.execute(
                """
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
            """,
                (engine, time.time(), time.time() + 300, time.time()),
            )
        conn.commit()

    def get_engine_stats(self) -> Dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM engine_health").fetchall()
        return {r["engine"]: dict(r) for r in rows}

    # ═══════════════ CIRCUIT BREAKER ═══════════════

    def record_domain_failure(self, domain: str):
        now = time.time()
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO circuit_breaker (domain, failures, last_failure, blocked_until)
            VALUES (?, 1, ?, 0)
            ON CONFLICT(domain) DO UPDATE SET
                failures = failures + 1,
                last_failure = ?,
                blocked_until = CASE 
                    WHEN failures + 1 >= 3 THEN ?
                    ELSE blocked_until
                END
        """,
            (domain, now, now, now + 1800),
        )  # Block for 30 minutes after 3 failures
        conn.commit()

    def reset_domain_failure(self, domain: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE circuit_breaker SET failures = 0, blocked_until = 0 WHERE domain = ?",
            (domain,),
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
        row = conn.execute(
            "SELECT 1 FROM content_hashes WHERE hash = ?", (h,)
        ).fetchone()
        return row is not None

    def add_content_hash(self, content: str, url: str):
        h = hashlib.md5(content.encode(errors="ignore")).hexdigest()
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO content_hashes (hash, url, first_seen) VALUES (?, ?, ?)",
                (h, url, time.time()),
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
            conn.execute(
                """
                INSERT INTO cookies (url, domain, cookie_name, cookie_value, cookie_type, found_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, cookie_name) DO UPDATE SET
                    cookie_value = ?, found_at = ?
            """,
                (
                    url,
                    domain,
                    name,
                    value,
                    cookie_type,
                    time.time(),
                    value,
                    time.time(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert cookie error: {e}")

    def add_b3_cookie(self, url: str, header_name: str, header_value: str):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO b3_cookies (url, header_name, header_value, found_at)
                VALUES (?, ?, ?, ?)
            """,
                (url, header_name, header_value, time.time()),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert b3 error: {e}")

    def get_all_cookies(self, domain: str = None) -> List[Dict]:
        conn = self._get_conn()
        if domain:
            rows = conn.execute(
                "SELECT * FROM cookies WHERE domain = ? ORDER BY found_at DESC",
                (domain,),
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

    def get_gateway_cookies(self) -> List[Dict]:
        """Get cookies identified as payment gateway cookies."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM cookies 
            WHERE cookie_type LIKE 'gateway:%' 
            ORDER BY found_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_commerce_cookies(self) -> List[Dict]:
        """Get cookies identified as commerce/checkout cookies."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM cookies 
            WHERE cookie_type = 'commerce' 
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
        conn.execute(
            """
            INSERT INTO scan_history (url, scan_type, findings_count, scanned_at)
            VALUES (?, ?, ?, ?)
        """,
            (url, scan_type, findings, time.time()),
        )
        conn.commit()

    # ═══════════════ SOFT-404 FINGERPRINTING ═══════════════

    _soft404_fingerprints: Dict[str, str] = {}

    def get_soft404_fingerprint(self, domain: str) -> Optional[str]:
        return self._soft404_fingerprints.get(domain)

    def set_soft404_fingerprint(self, domain: str, fingerprint: str):
        self._soft404_fingerprints[domain] = fingerprint

    # ═══════════════ MIGRATION FROM JSON FILES ═══════════════

    def import_from_json_files(
        self, seen_file: str = None, vuln_file: str = None, gateway_file: str = None
    ):
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
                        g.get("url", ""),
                        g.get("type", ""),
                        g.get("value", ""),
                        g.get("source", ""),
                    )
                    imported += 1
            except Exception:
                pass

        if imported > 0:
            logger.info(f"Imported {imported} records from JSON files")
        return imported

    # ═══════════════ PORT SCANS (v3.10) ═══════════════

    def add_port_scan(
        self,
        url: str,
        domain: str,
        ip: str,
        port: int,
        service: str = "",
        banner: str = "",
        version: str = "",
        risk: str = "",
        notes: str = "",
    ):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO port_scans 
                (url, domain, ip, port, service, banner, version, risk, notes, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    url,
                    domain,
                    ip,
                    port,
                    service,
                    banner,
                    version,
                    risk,
                    notes,
                    time.time(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert port scan error: {e}")

    def get_port_scans(self, domain: str = None, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        if domain:
            rows = conn.execute(
                "SELECT * FROM port_scans WHERE domain = ? ORDER BY found_at DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM port_scans ORDER BY found_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ═══════════════ OOB RESULTS (v3.11) ═══════════════

    def add_oob_result(self, result: Dict):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO oob_results 
                (url, parameter, dbms, channel, extraction, callbacks, payloads_sent, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    result.get("url", ""),
                    result.get("parameter", ""),
                    result.get("dbms", ""),
                    result.get("channel", ""),
                    json.dumps(result.get("extraction", {})),
                    result.get("callbacks", 0),
                    result.get("payloads_sent", 0),
                    time.time(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert OOB error: {e}")

    # ═══════════════ KEY VALIDATIONS (v3.13) ═══════════════

    def add_key_validation(self, validation: Dict):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO key_validations
                (key_type, key_hash, is_live, confidence, risk_level,
                 account_info, permissions, source_url, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    validation.get("key_type", ""),
                    validation.get("key_hash", ""),
                    1 if validation.get("is_live") else 0,
                    validation.get("confidence", 0),
                    validation.get("risk_level", ""),
                    validation.get("account_info", "{}"),
                    validation.get("permissions", "[]"),
                    validation.get("source_url", ""),
                    time.time(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB insert key validation error: {e}")

    def get_live_keys(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM key_validations WHERE is_live = 1 ORDER BY found_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ═══════════════ STRIPE KEYS ═══════════════

    def add_stripe_key(
        self,
        domain: str,
        url: str,
        sk_live: str,
        pk_live: str = None,
        sk_test: str = None,
        pk_test: str = None,
    ):
        """Insert or update a Stripe key pair. Deduplicates on sk_live."""
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO stripe_keys (domain, url, sk_live, pk_live, sk_test, pk_test, found_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sk_live) DO UPDATE SET
                    pk_live = COALESCE(excluded.pk_live, stripe_keys.pk_live),
                    sk_test = COALESCE(excluded.sk_test, stripe_keys.sk_test),
                    pk_test = COALESCE(excluded.pk_test, stripe_keys.pk_test)
            """,
                (domain, url, sk_live, pk_live, sk_test, pk_test, time.time()),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB add_stripe_key error: {e}")

    def update_stripe_key_validation(self, sk_live: str, data: Dict):
        """Update a Stripe key row with validation results."""
        conn = self._get_conn()
        try:
            conn.execute(
                """
                UPDATE stripe_keys SET
                    is_validated = 1,
                    is_live = ?,
                    account_id = ?,
                    account_email = ?,
                    business_name = ?,
                    country = ?,
                    balance_json = ?,
                    charges_count = ?,
                    customers_count = ?,
                    products_count = ?,
                    subscriptions_count = ?,
                    risk_level = ?,
                    permissions = ?,
                    validated_at = ?
                WHERE sk_live = ?
            """,
                (
                    1 if data.get("is_live") else 0,
                    data.get("account_id", ""),
                    data.get("account_email", ""),
                    data.get("business_name", ""),
                    data.get("country", ""),
                    data.get("balance_json", "{}"),
                    data.get("charges_count", 0),
                    data.get("customers_count", 0),
                    data.get("products_count", 0),
                    data.get("subscriptions_count", 0),
                    data.get("risk_level", ""),
                    data.get("permissions", "[]"),
                    time.time(),
                    sk_live,
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB update_stripe_key_validation error: {e}")

    def get_stripe_keys(self, limit: int = 500, live_only: bool = False) -> List[Dict]:
        conn = self._get_conn()
        if live_only:
            rows = conn.execute(
                "SELECT * FROM stripe_keys WHERE is_live = 1 ORDER BY validated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM stripe_keys ORDER BY found_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stripe_key_count(self, live_only: bool = False) -> int:
        conn = self._get_conn()
        if live_only:
            return conn.execute(
                "SELECT COUNT(*) FROM stripe_keys WHERE is_live = 1"
            ).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM stripe_keys").fetchone()[0]

    def get_stripe_key_by_domain(self, domain: str) -> Optional[Dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM stripe_keys WHERE domain = ? LIMIT 1", (domain,)
        ).fetchone()
        return dict(row) if row else None

    # ═══════════════ SHOPIFY STORES ═══════════════

    def add_shopify_store(
        self,
        domain: str,
        url: str,
        payment_gateway: str = "",
        checkout_url: str = "",
        confidence: float = 0.0,
        store_name: str = "",
        findings_json: str = "{}",
        cookies_json: str = "{}",
    ):
        """Insert or update a Shopify store. Deduplicates on domain."""
        conn = self._get_conn()
        # Check if stripe keys exist for this domain
        has_sk = (
            conn.execute(
                "SELECT COUNT(*) FROM stripe_keys WHERE domain = ?", (domain,)
            ).fetchone()[0]
            > 0
        )
        try:
            conn.execute(
                """
                INSERT INTO shopify_stores
                    (domain, url, store_name, payment_gateway, checkout_url,
                     has_stripe_keys, platform_confidence, cookies_json, findings_json,
                     found_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    payment_gateway = COALESCE(NULLIF(excluded.payment_gateway, ''), shopify_stores.payment_gateway),
                    checkout_url = COALESCE(NULLIF(excluded.checkout_url, ''), shopify_stores.checkout_url),
                    has_stripe_keys = MAX(shopify_stores.has_stripe_keys, excluded.has_stripe_keys),
                    platform_confidence = MAX(shopify_stores.platform_confidence, excluded.platform_confidence)
            """,
                (
                    domain,
                    url,
                    store_name,
                    payment_gateway,
                    checkout_url,
                    1 if has_sk else 0,
                    confidence,
                    cookies_json,
                    findings_json,
                    time.time(),
                    time.time(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.debug(f"DB add_shopify_store error: {e}")

    def get_shopify_stores(self, limit: int = 500) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM shopify_stores ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_shopify_store_count(self) -> int:
        conn = self._get_conn()
        return conn.execute("SELECT COUNT(*) FROM shopify_stores").fetchone()[0]

    # ═══════════════ SCAN HISTORY PURGE ═══════════════

    def purge_old_scan_history(self, max_age_days: int = 14):
        """Delete scan_history entries older than max_age_days."""
        conn = self._get_conn()
        cutoff = time.time() - (max_age_days * 86400)
        try:
            deleted = conn.execute(
                "DELETE FROM scan_history WHERE scanned_at < ?", (cutoff,)
            ).rowcount
            conn.commit()
            if deleted > 0:
                logger.info(
                    f"Purged {deleted} scan_history entries older than {max_age_days} days"
                )
        except Exception as e:
            logger.debug(f"DB purge_old_scan_history error: {e}")

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

    # ═══════════════ DORK CHECKPOINT ═══════════════

    def save_dork_checkpoint(self, cycle: int, dork_index: int, dork_hash: str = ""):
        """Save current dork progress so we can resume after restart."""
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO dork_checkpoint (id, cycle, dork_index, dork_hash, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cycle = ?, dork_index = ?, dork_hash = ?, updated_at = ?
        """,
            (
                cycle,
                dork_index,
                dork_hash,
                time.time(),
                cycle,
                dork_index,
                dork_hash,
                time.time(),
            ),
        )
        conn.commit()

    def get_dork_checkpoint(self) -> Optional[Dict]:
        """Get the last saved dork checkpoint, or None if no checkpoint."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM dork_checkpoint WHERE id = 1").fetchone()
        if row:
            return dict(row)
        return None

    def clear_dork_checkpoint(self):
        """Clear the checkpoint (e.g. after completing a full cycle)."""
        conn = self._get_conn()
        conn.execute("DELETE FROM dork_checkpoint WHERE id = 1")
        conn.commit()
