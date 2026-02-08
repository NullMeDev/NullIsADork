"""
MadyDorker v3.10 — Port Scanner & Service Discovery

Async TCP port scanner with:
- Configurable port lists (common, web, database, full)
- Banner grabbing for service fingerprinting
- Concurrent scanning with semaphore
- Service identification from banners
- Integration with WAF detector (augment ProtectionInfo)
- Exposed admin panel / database detection
- Reporting high-value open ports to Telegram
"""

import asyncio
import logging
import re
import socket
import ssl as _ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("port_scanner")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class OpenPort:
    """A single open port with service info."""
    port: int
    state: str = "open"          # open, filtered, closed
    service: str = ""            # http, mysql, ssh, etc.
    banner: str = ""             # Raw banner text
    version: str = ""            # Parsed version string
    tls: bool = False            # TLS/SSL detected
    risk: str = "info"           # info, low, medium, high, critical
    notes: List[str] = field(default_factory=list)


@dataclass
class PortScanResult:
    """Aggregate result of a port scan."""
    domain: str
    ip: str = ""
    open_ports: List[OpenPort] = field(default_factory=list)
    total_scanned: int = 0
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def high_value_ports(self) -> List[OpenPort]:
        """Ports that are interesting for exploitation."""
        return [p for p in self.open_ports if p.risk in ("high", "critical")]

    @property
    def database_ports(self) -> List[OpenPort]:
        """Exposed database ports."""
        db_ports = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 8529}
        return [p for p in self.open_ports if p.port in db_ports]

    @property
    def admin_ports(self) -> List[OpenPort]:
        """Admin / management ports."""
        admin = {8080, 8443, 9090, 2082, 2083, 2086, 2087, 8888, 10000}
        return [p for p in self.open_ports if p.port in admin]


# ═══════════════════════════════════════════════════════════════
#   PORT PROFILES
# ═══════════════════════════════════════════════════════════════

# Default: quick scan of high-value ports
PORTS_QUICK = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 2082, 2083, 2086, 2087,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
    8888, 9090, 9200, 10000, 27017,
]

# Extended: more services
PORTS_EXTENDED = PORTS_QUICK + [
    20, 69, 111, 135, 139, 161, 389, 465, 514, 587,
    636, 873, 1080, 1194, 1723, 2049, 2181, 3000,
    3128, 4443, 4848, 5000, 5001, 5432, 5601, 5672,
    5984, 6443, 6660, 6667, 7001, 7002, 7070, 7443,
    8000, 8001, 8008, 8009, 8081, 8082, 8180, 8181,
    8443, 8529, 8880, 8983, 9000, 9001, 9042, 9090,
    9200, 9300, 9418, 9443, 11211, 15672, 27018, 28017,
    50000, 50070,
]

# Service names by well-known port
PORT_SERVICE_MAP: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2181: "zookeeper", 3000: "grafana", 3128: "squid",
    3306: "mysql", 3389: "rdp", 4443: "https-alt",
    5000: "docker-registry", 5432: "postgresql", 5601: "kibana",
    5672: "rabbitmq", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 6660: "irc",
    6667: "irc", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8080: "http-proxy",
    8081: "http-alt", 8180: "http-alt", 8443: "https-alt",
    8529: "arangodb", 8880: "http-alt", 8888: "http-alt",
    8983: "solr", 9000: "php-fpm", 9042: "cassandra",
    9090: "prometheus", 9200: "elasticsearch", 9300: "es-transport",
    9418: "git", 9443: "https-alt", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 28017: "mongodb-web", 50000: "jenkins",
    50070: "hdfs",
}

# Risk levels by port
PORT_RISK: Dict[int, str] = {
    # Critical — exposed databases / admin
    3306: "critical", 5432: "critical", 1433: "critical",
    1521: "critical", 27017: "critical", 6379: "critical",
    9200: "critical", 5984: "critical", 8529: "critical",
    11211: "critical", 9042: "critical",
    # High — remote access / management
    22: "high", 23: "high", 3389: "high", 5900: "high",
    2082: "high", 2083: "high", 2086: "high", 2087: "high",
    10000: "high", 445: "high", 139: "high",
    # Medium — web admin / proxy
    8080: "medium", 8443: "medium", 9090: "medium",
    8888: "medium", 8983: "medium", 50000: "medium",
    7001: "medium", 5601: "medium", 15672: "medium",
    # Low — standard services
    21: "low", 25: "low", 110: "low", 143: "low",
    # Info — web/dns/mail
    80: "info", 443: "info", 53: "info", 587: "info",
    993: "info", 995: "info",
}

# Banner patterns for service + version extraction
BANNER_PATTERNS = [
    # SSH
    (re.compile(r"SSH-[\d.]+-(OpenSSH[_\s][\d.p]+)", re.I), "ssh"),
    (re.compile(r"SSH-[\d.]+-(.+)", re.I), "ssh"),
    # FTP
    (re.compile(r"220[- ].*?(?:vsftpd|ProFTPD|Pure-FTPd|FileZilla)\s*([\d.]+)?", re.I), "ftp"),
    (re.compile(r"220[- ](.+)", re.I), "ftp"),
    # SMTP
    (re.compile(r"220[- ].*?(?:Postfix|Exim|Sendmail|ESMTP)", re.I), "smtp"),
    # MySQL
    (re.compile(r"(\d+\.\d+\.\d+[-\w]*)\x00", re.I), "mysql"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    # PostgreSQL
    (re.compile(r"PostgreSQL", re.I), "postgresql"),
    # Redis
    (re.compile(r"-ERR|REDIS|\+PONG", re.I), "redis"),
    # MongoDB
    (re.compile(r"MongoDB|mongod|ismaster", re.I), "mongodb"),
    # HTTP
    (re.compile(r"HTTP/[\d.]+\s+\d+", re.I), "http"),
    (re.compile(r"Server:\s*(.+)", re.I), "http"),
    # Elasticsearch
    (re.compile(r"elasticsearch|\"cluster_name\"", re.I), "elasticsearch"),
]


# ═══════════════════════════════════════════════════════════════
#   PORT SCANNER
# ═══════════════════════════════════════════════════════════════

class PortScanner:
    """
    Async TCP port scanner with banner grabbing and service identification.
    """

    def __init__(
        self,
        config: Any = None,
        proxy_manager: Any = None,
        reporter: Any = None,
        db: Any = None,
    ):
        self.config = config
        self.proxy_manager = proxy_manager
        self.reporter = reporter
        self.db = db

        # Config
        self.enabled = True
        self.timeout: float = 2.0
        self.max_concurrent: int = 50
        self.banner_timeout: float = 3.0
        self.grab_banners: bool = True

        if config:
            self.enabled = getattr(config, "port_scan_enabled", False)
            self.timeout = getattr(config, "port_scan_timeout", 2.0)
            self.max_concurrent = getattr(config, "port_scan_concurrent", 50)
            self.banner_timeout = getattr(config, "port_scan_banner_timeout", 3.0)
            self.grab_banners = getattr(config, "port_scan_banners", True)

        # Parse port list from config
        self._ports: List[int] = PORTS_QUICK
        if config:
            ports_str = getattr(config, "port_scan_ports", "")
            if ports_str == "extended":
                self._ports = PORTS_EXTENDED
            elif ports_str == "quick" or not ports_str:
                self._ports = PORTS_QUICK
            elif isinstance(ports_str, str) and "," in ports_str:
                try:
                    self._ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
                except ValueError:
                    self._ports = PORTS_QUICK

        # Stats
        self.stats = {
            "total_scans": 0,
            "total_ports_scanned": 0,
            "total_open": 0,
            "total_critical": 0,
            "total_high": 0,
            "domains_scanned": set(),
        }

        # Dedup
        self._reported: Set[str] = set()

    # ─────────────────────────────────────────────
    #   PUBLIC API
    # ─────────────────────────────────────────────

    async def scan(
        self,
        url: str,
        ports: Optional[List[int]] = None,
    ) -> PortScanResult:
        """
        Scan a domain's ports.

        Args:
            url: Target URL (domain extracted from it)
            ports: Override port list (uses config default if None)

        Returns:
            PortScanResult with open ports and service info
        """
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            return PortScanResult(domain="", error="No domain")

        scan_ports = ports or self._ports
        result = PortScanResult(domain=domain)
        start = time.time()

        # Resolve IP
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            if infos:
                result.ip = infos[0][4][0]
        except Exception as e:
            result.error = f"DNS resolution failed: {e}"
            result.elapsed = time.time() - start
            return result

        # Scan ports concurrently
        sem = asyncio.Semaphore(self.max_concurrent)
        tasks = []
        for port in scan_ports:
            tasks.append(self._scan_port(result.ip, port, domain, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, OpenPort) and r.state == "open":
                result.open_ports.append(r)

        result.total_scanned = len(scan_ports)
        result.elapsed = time.time() - start

        # Sort by risk then port
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result.open_ports.sort(key=lambda p: (risk_order.get(p.risk, 5), p.port))

        # Update stats
        self.stats["total_scans"] += 1
        self.stats["total_ports_scanned"] += result.total_scanned
        self.stats["total_open"] += len(result.open_ports)
        self.stats["total_critical"] += len([p for p in result.open_ports if p.risk == "critical"])
        self.stats["total_high"] += len([p for p in result.open_ports if p.risk == "high"])
        self.stats["domains_scanned"].add(domain)

        logger.info(
            f"Port scan {domain} ({result.ip}): "
            f"{len(result.open_ports)}/{result.total_scanned} open | "
            f"critical={len(result.high_value_ports)} | "
            f"{result.elapsed:.1f}s"
        )

        return result

    async def scan_and_report(
        self,
        url: str,
        ports: Optional[List[int]] = None,
    ) -> PortScanResult:
        """Scan + report high-value findings to Telegram + persist."""
        result = await self.scan(url, ports)

        if result.error and not result.open_ports:
            return result

        domain = result.domain
        dedup_key = f"{domain}"

        # Persist
        if self.db:
            for port in result.open_ports:
                try:
                    self.db.add_port_scan(
                        url, domain, port.port,
                        service=port.service,
                        banner=port.banner[:500] if port.banner else None,
                    )
                except Exception:
                    pass

        # Report high-value ports
        if self.reporter and dedup_key not in self._reported:
            high_value = result.high_value_ports
            db_ports = result.database_ports
            admin_ports = result.admin_ports

            if high_value or db_ports:
                self._reported.add(dedup_key)
                lines = [
                    f"🔌 <b>Port Scan: {domain}</b>",
                    f"IP: <code>{result.ip}</code>",
                    f"Open: {len(result.open_ports)}/{result.total_scanned}",
                    "",
                ]

                if db_ports:
                    lines.append("🔴 <b>EXPOSED DATABASES:</b>")
                    for p in db_ports:
                        svc = p.service or PORT_SERVICE_MAP.get(p.port, "?")
                        ver = f" ({p.version})" if p.version else ""
                        lines.append(f"  • <code>{p.port}</code> {svc}{ver}")
                    lines.append("")

                if admin_ports:
                    lines.append("🟠 <b>Admin/Management:</b>")
                    for p in admin_ports:
                        svc = p.service or PORT_SERVICE_MAP.get(p.port, "?")
                        lines.append(f"  • <code>{p.port}</code> {svc}")
                    lines.append("")

                # Other high-value
                other_high = [p for p in high_value if p not in db_ports and p not in admin_ports]
                if other_high:
                    lines.append("🟡 <b>Other Notable:</b>")
                    for p in other_high:
                        svc = p.service or PORT_SERVICE_MAP.get(p.port, "?")
                        lines.append(f"  • <code>{p.port}</code> {svc}")

                text = "\n".join(lines)
                try:
                    await self.reporter.send_message(text)
                except Exception as e:
                    logger.debug(f"Port scan report failed: {e}")

        return result

    def get_stats_text(self) -> str:
        """Human-readable stats for Telegram."""
        s = self.stats
        return (
            "🔌 <b>Port Scanner Stats</b>\n"
            f"Scans: <b>{s['total_scans']}</b>\n"
            f"Ports probed: <b>{s['total_ports_scanned']}</b>\n"
            f"Open ports found: <b>{s['total_open']}</b>\n"
            f"Critical: <b>{s['total_critical']}</b> | High: <b>{s['total_high']}</b>\n"
            f"Domains: <b>{len(s['domains_scanned'])}</b>"
        )

    # ─────────────────────────────────────────────
    #   INTERNAL — PORT PROBING
    # ─────────────────────────────────────────────

    async def _scan_port(
        self,
        ip: str,
        port: int,
        domain: str,
        sem: asyncio.Semaphore,
    ) -> OpenPort:
        """Probe a single port."""
        result = OpenPort(port=port, state="closed")

        try:
            async with sem:
                # TCP connect
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout,
                    )
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return result

                result.state = "open"
                result.service = PORT_SERVICE_MAP.get(port, "")
                result.risk = PORT_RISK.get(port, "info")

                # Banner grabbing
                if self.grab_banners:
                    banner = await self._grab_banner(reader, writer, port, domain)
                    if banner:
                        result.banner = banner
                        svc, ver = self._parse_banner(banner, port)
                        if svc:
                            result.service = svc
                        if ver:
                            result.version = ver

                    # TLS check for non-standard TLS ports
                    if port not in (443, 8443, 993, 995, 465, 636, 2083, 2087):
                        # Already connected; just note it's not TLS
                        pass
                    else:
                        result.tls = True

                # Generate notes
                result.notes = self._generate_notes(result, domain)

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception:
            pass

        return result

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        domain: str,
    ) -> str:
        """Grab service banner from an open port."""
        banner = ""

        try:
            # Some services send banner immediately (SSH, FTP, SMTP)
            try:
                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=self.banner_timeout,
                )
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass

            # If no banner, try sending probes
            if not banner:
                probes = self._get_probes(port, domain)
                for probe in probes:
                    try:
                        writer.write(probe)
                        await writer.drain()
                        data = await asyncio.wait_for(
                            reader.read(2048),
                            timeout=self.banner_timeout,
                        )
                        if data:
                            banner = data.decode("utf-8", errors="replace").strip()
                            break
                    except Exception:
                        break

        except Exception:
            pass

        return banner[:1024]  # Cap banner length

    def _get_probes(self, port: int, domain: str) -> List[bytes]:
        """Get protocol-specific probes for a port."""
        probes: List[bytes] = []

        if port in (80, 8080, 8000, 8008, 8081, 8180, 8888, 3000, 5000, 9090):
            # HTTP probe
            probes.append(
                f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
            )
        elif port == 6379:
            # Redis PING
            probes.append(b"PING\r\n")
        elif port == 11211:
            # Memcached stats
            probes.append(b"stats\r\n")
        elif port == 27017:
            # MongoDB ismaster (legacy wire protocol)
            probes.append(b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff"
                          b"\xd4\x07\x00\x00\x00\x00\x00\x00"
                          b"admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                          b"\x15\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00")
        elif port == 9200:
            # Elasticsearch
            probes.append(
                f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
            )
        elif port in (3306,):
            # MySQL — server sends greeting on connect, already captured
            pass
        elif port in (5432,):
            # PostgreSQL startup
            # Send SSLRequest
            probes.append(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        else:
            # Generic: send newline
            probes.append(b"\r\n")

        return probes

    def _parse_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Parse banner to extract service name and version."""
        service = ""
        version = ""

        for pattern, svc in BANNER_PATTERNS:
            m = pattern.search(banner)
            if m:
                service = svc
                if m.lastindex and m.lastindex >= 1:
                    version = m.group(1).strip()[:100]
                break

        # Fallback to port-based service
        if not service:
            service = PORT_SERVICE_MAP.get(port, "")

        return service, version

    def _generate_notes(self, port: OpenPort, domain: str) -> List[str]:
        """Generate contextual notes for an open port."""
        notes = []

        if port.port == 3306:
            notes.append("MySQL exposed — try default creds / SQLi dump directly")
            if "MariaDB" in port.banner:
                notes.append("MariaDB detected")
        elif port.port == 5432:
            notes.append("PostgreSQL exposed — try default creds (postgres:postgres)")
        elif port.port == 6379:
            if "-NOAUTH" not in port.banner and "ERR" not in port.banner:
                notes.append("Redis may be unauthenticated!")
            else:
                notes.append("Redis requires auth")
        elif port.port == 27017:
            notes.append("MongoDB exposed — check for auth bypass")
        elif port.port == 9200:
            notes.append("Elasticsearch exposed — try /_cat/indices, /_search")
        elif port.port == 11211:
            notes.append("Memcached exposed — try 'stats items' for cache dumping")
        elif port.port == 8080:
            notes.append("HTTP proxy/alt — may bypass WAF on port 443")
        elif port.port in (2082, 2083):
            notes.append("cPanel detected")
        elif port.port in (2086, 2087):
            notes.append("WHM detected")
        elif port.port == 10000:
            notes.append("Webmin detected")
        elif port.port == 22:
            notes.append("SSH — brute force / key auth")
        elif port.port == 23:
            notes.append("Telnet — cleartext credentials!")
        elif port.port == 3389:
            notes.append("RDP — try BlueKeep, default creds")
        elif port.port == 445:
            notes.append("SMB — check EternalBlue, shares")
        elif port.port == 5900:
            notes.append("VNC — may be unauthenticated")
        elif port.port == 50000:
            notes.append("Jenkins — check /script console (RCE)")

        return notes
