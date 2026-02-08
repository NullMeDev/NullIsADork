"""
Directory Fuzzer Module for MadyDorker

Lightweight directory/file discovery via brute-force probing.
Complements API bruteforcer by finding hidden paths, backups, configs,
source code leaks, and sensitive files.
"""

import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict
from urllib.parse import urlparse, urljoin
from loguru import logger


@dataclass
class DirFuzzHit:
    """A discovered path."""
    url: str
    status: int
    size: int
    content_type: str = ""
    reason: str = ""


@dataclass
class DirFuzzResult:
    """Result of directory fuzzing."""
    base_url: str
    hits: List[DirFuzzHit] = field(default_factory=list)
    sensitive_files: List[DirFuzzHit] = field(default_factory=list)
    backup_files: List[DirFuzzHit] = field(default_factory=list)
    config_files: List[DirFuzzHit] = field(default_factory=list)
    total_probed: int = 0
    total_found: int = 0
    error: Optional[str] = None


# High-value sensitive paths to probe
SENSITIVE_PATHS = [
    # Version control
    ".git/HEAD", ".git/config", ".svn/entries", ".hg/requires",
    ".gitignore", ".env", ".env.local", ".env.production", ".env.backup",
    
    # Config files
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "config.php", "config.inc.php", "configuration.php",
    "settings.php", "settings.py", "config.py", "config.yml", "config.yaml",
    "config.json", "config.xml", "config.ini", "config.toml",
    "database.yml", "database.php", "db.php", "db.conf",
    "application.properties", "application.yml",
    ".htaccess", ".htpasswd", "nginx.conf", "web.config",
    
    # Backup & source
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "db.sql", "dump.sql", "database.sql", "mysql.sql",
    "site.zip", "www.zip", "html.zip", "public.zip",
    "web.zip", "source.zip", "src.zip", "code.zip",
    "backup.tar", "backup.rar", "backup.7z",
    "index.php.bak", "index.php.old", "index.php~",
    
    # Info disclosure
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    
    # Package managers & build
    "package.json", "composer.json", "Gemfile", "Pipfile",
    "requirements.txt", "yarn.lock", "package-lock.json",
    "composer.lock", "Gemfile.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Rakefile", "Gruntfile.js", "gulpfile.js",
    "webpack.config.js", "tsconfig.json", "next.config.js",
    
    # Logs & errors
    "error.log", "errors.log", "debug.log", "access.log",
    "error_log", "php_errors.log", "laravel.log",
    "storage/logs/laravel.log",
    
    # Admin & management
    "admin/", "administrator/", "manager/", "manage/",
    "phpmyadmin/", "pma/", "myadmin/", "mysql/",
    "adminer.php", "adminer/",
    
    # API docs
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs/", "api/docs/", "api/swagger/",
    "graphql", "graphiql", "__graphql",
    
    # Cloud & CI
    ".aws/credentials", ".docker/config.json",
    ".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile",
    ".travis.yml", "circle.yml", "azure-pipelines.yml",
    
    # Misc
    "readme.md", "README.md", "CHANGELOG.md", "LICENSE",
    "TODO.md", "INSTALL.md", "CONTRIBUTING.md",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "crossfire/", "cgi-bin/", "cgi/",
]

# Status codes that indicate a real find (not error pages)
VALID_STATUS = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403}

# Sensitive file indicators
SENSITIVE_INDICATORS = {
    ".git/HEAD": "Git repository exposed",
    ".git/config": "Git config exposed",
    ".svn/entries": "SVN repository exposed",
    ".env": "Environment file exposed",
    ".env.local": "Local env file exposed",
    ".env.production": "Production env exposed",
    ".env.backup": "Env backup exposed",
    ".htpasswd": "Password file exposed",
    "phpinfo.php": "PHP info exposed",
    "info.php": "PHP info exposed",
    "wp-config.php": "WordPress config exposed",
    "wp-config.php.bak": "WordPress config backup",
    "config.json": "Config file exposed",
    "config.yml": "Config file exposed",
    "database.yml": "Database config exposed",
    "swagger.json": "API spec exposed",
    "openapi.json": "API spec exposed",
    ".aws/credentials": "AWS credentials exposed",
    "adminer.php": "DB admin tool exposed",
    "server-status": "Apache status exposed",
    "backup.sql": "SQL dump exposed",
    "db.sql": "SQL dump exposed",
    "dump.sql": "SQL dump exposed",
}


class DirectoryFuzzer:
    """Lightweight directory/file fuzzer for the pipeline."""
    
    def __init__(self, timeout: float = 5.0, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._sem = asyncio.Semaphore(max_concurrent)
    
    async def fuzz(self, url: str, session: Optional[aiohttp.ClientSession] = None) -> DirFuzzResult:
        """Fuzz directories and sensitive files on a target URL.
        
        Args:
            url: Target base URL 
            session: Optional existing aiohttp session
            
        Returns:
            DirFuzzResult with discovered paths
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        result = DirFuzzResult(base_url=base_url)
        
        # Get a reference 404 response to filter false positives
        fp_body_len = await self._get_404_fingerprint(base_url, session)
        
        own_session = session is None
        if own_session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            session = aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
        
        try:
            tasks = []
            for path in SENSITIVE_PATHS:
                tasks.append(self._probe(base_url, path, session, fp_body_len))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for r in results:
                if isinstance(r, DirFuzzHit):
                    result.hits.append(r)
                    
                    # Categorize
                    path = r.url.replace(base_url, "").lstrip("/")
                    if path in SENSITIVE_INDICATORS:
                        r.reason = SENSITIVE_INDICATORS[path]
                        result.sensitive_files.append(r)
                    elif any(ext in path for ext in (".bak", ".old", ".zip", ".tar", ".gz", ".rar", ".7z", ".sql", "~")):
                        r.reason = "Backup/archive file"
                        result.backup_files.append(r)
                    elif any(ext in path for ext in (".php", ".yml", ".yaml", ".json", ".xml", ".ini", ".toml", ".conf", ".config")):
                        if any(kw in path.lower() for kw in ("config", "database", "settings", "env", ".env")):
                            r.reason = "Configuration file"
                            result.config_files.append(r)
            
            result.total_probed = len(SENSITIVE_PATHS)
            result.total_found = len(result.hits)
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Dir fuzz error for {base_url}: {e}")
        finally:
            if own_session:
                await session.close()
        
        logger.info(
            f"[DirFuzz] {base_url}: {result.total_found}/{result.total_probed} hits "
            f"({len(result.sensitive_files)} sensitive, {len(result.backup_files)} backups)"
        )
        return result
    
    async def _get_404_fingerprint(self, base_url: str, session: Optional[aiohttp.ClientSession]) -> int:
        """Get the body length of a 404 page to filter soft-404s."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            own = session is None
            if own:
                session = aiohttp.ClientSession(timeout=timeout)
            try:
                async with session.get(
                    f"{base_url}/nonexistent_path_for_404_check_xyz123",
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.read()
                    return len(body)
            finally:
                if own:
                    await session.close()
        except Exception:
            return -1
    
    async def _probe(
        self, base_url: str, path: str,
        session: aiohttp.ClientSession, fp_body_len: int
    ) -> Optional[DirFuzzHit]:
        """Probe a single path."""
        async with self._sem:
            target_url = f"{base_url}/{path}"
            try:
                async with session.get(
                    target_url, ssl=False, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status not in VALID_STATUS:
                        return None
                    
                    body = await resp.read()
                    body_len = len(body)
                    
                    # Filter soft-404s (same body length as known 404)
                    if fp_body_len > 0 and abs(body_len - fp_body_len) < 50:
                        return None
                    
                    # Skip empty responses (except for redirects and 401/403)
                    if body_len == 0 and resp.status not in {301, 302, 307, 308, 401, 403}:
                        return None
                    
                    content_type = resp.headers.get("Content-Type", "")
                    
                    return DirFuzzHit(
                        url=target_url,
                        status=resp.status,
                        size=body_len,
                        content_type=content_type,
                    )
            except Exception:
                return None


# Convenience wrapper
async def fuzz_directories(
    url: str,
    session: Optional[aiohttp.ClientSession] = None,
    timeout: float = 5.0,
) -> DirFuzzResult:
    """Fuzz directories on a target URL."""
    fuzzer = DirectoryFuzzer(timeout=timeout)
    return await fuzzer.fuzz(url, session)
