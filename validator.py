"""
Site Validator Module - Validates found sites for Stripe integration
"""

import re
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp
from loguru import logger


@dataclass
class SiteInfo:
    """Information about a validated site."""
    url: str
    domain: str
    pk_key: Optional[str] = None
    platform: Optional[str] = None
    has_captcha: bool = False
    has_cloudflare: bool = False
    has_registration: bool = False
    registration_type: Optional[str] = None  # email_only, phone_required, etc.
    checkout_url: Optional[str] = None
    score: int = 0
    found_at: datetime = field(default_factory=datetime.now)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "domain": self.domain,
            "pk_key": self.pk_key,
            "platform": self.platform,
            "has_captcha": self.has_captcha,
            "has_cloudflare": self.has_cloudflare,
            "has_registration": self.has_registration,
            "registration_type": self.registration_type,
            "checkout_url": self.checkout_url,
            "score": self.score,
            "found_at": self.found_at.isoformat(),
        }
    
    def format_telegram(self) -> str:
        """Format for Telegram message."""
        status_emoji = "✅" if self.score >= 50 else "⚠️" if self.score >= 20 else "❌"
        
        msg = f"""
<b>{status_emoji} New Site Found</b>

<b>URL:</b> <code>{self.url}</code>
<b>Domain:</b> <code>{self.domain}</code>
<b>Score:</b> <code>{self.score}/100</code>

<b>Details:</b>
• PK Key: <code>{self.pk_key[:30] + '...' if self.pk_key else 'Not found'}</code>
• Platform: <code>{self.platform or 'Unknown'}</code>
• CAPTCHA: <code>{'Yes ❌' if self.has_captcha else 'No ✅'}</code>
• Cloudflare: <code>{'Yes ⚠️' if self.has_cloudflare else 'No ✅'}</code>
• Registration: <code>{self.registration_type or 'Unknown'}</code>
"""
        if self.checkout_url:
            msg += f"• Checkout: <code>{self.checkout_url}</code>\n"
        
        return msg.strip()


class SiteValidator:
    """Validates sites for Stripe integration."""
    
    def __init__(
        self,
        skip_domains: Optional[List[str]] = None,
        timeout: int = 15,
        proxy: Optional[str] = None
    ):
        self.skip_domains = skip_domains or []
        self.timeout = timeout
        self.proxy = proxy
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except:
            return ""
    
    def _should_skip(self, domain: str) -> bool:
        """Check if domain should be skipped."""
        for skip in self.skip_domains:
            if skip in domain:
                return True
        return False
    
    def _detect_platform(self, html: str) -> Optional[str]:
        """Detect the e-commerce platform."""
        html_lower = html.lower()
        
        if "woocommerce" in html_lower or "wc-" in html_lower:
            return "WooCommerce"
        if "shopify" in html_lower or "myshopify" in html_lower:
            return "Shopify"
        if "magento" in html_lower:
            return "Magento"
        if "prestashop" in html_lower:
            return "PrestaShop"
        if "bigcommerce" in html_lower:
            return "BigCommerce"
        if "squarespace" in html_lower:
            return "Squarespace"
        if "wix" in html_lower:
            return "Wix"
        if "wordpress" in html_lower or "wp-" in html_lower:
            return "WordPress"
        
        return None
    
    def _detect_captcha(self, html: str) -> bool:
        """Detect if site has CAPTCHA."""
        html_lower = html.lower()
        captcha_indicators = [
            "recaptcha",
            "hcaptcha",
            "captcha",
            "g-recaptcha",
            "h-captcha",
            "cf-turnstile",  # Cloudflare Turnstile
        ]
        return any(indicator in html_lower for indicator in captcha_indicators)
    
    def _detect_cloudflare(self, html: str, headers: Dict) -> bool:
        """Detect Cloudflare protection."""
        # Check headers
        if "cf-ray" in str(headers).lower():
            return True
        if "cloudflare" in str(headers).lower():
            return True
        
        # Check HTML
        html_lower = html.lower()
        cf_indicators = [
            "cloudflare",
            "cf-browser-verification",
            "checking your browser",
            "__cf_bm",
            "cf_clearance",
        ]
        return any(indicator in html_lower for indicator in cf_indicators)
    
    def _detect_registration(self, html: str) -> Tuple[bool, Optional[str]]:
        """Detect registration type."""
        html_lower = html.lower()
        
        has_registration = any([
            "register" in html_lower,
            "sign up" in html_lower,
            "signup" in html_lower,
            "create account" in html_lower,
        ])
        
        if not has_registration:
            return False, None
        
        # Check for phone requirement
        if any([
            "phone" in html_lower and "verify" in html_lower,
            "sms verification" in html_lower,
            "mobile number" in html_lower and "required" in html_lower,
        ]):
            return True, "phone_required"
        
        # Check for email-only
        if "email" in html_lower and "register" in html_lower:
            return True, "email_only"
        
        return True, "unknown"
    
    def _find_checkout_url(self, html: str, base_url: str) -> Optional[str]:
        """Try to find checkout URL in page."""
        patterns = [
            r'href=["\']([^"\']*checkout[^"\']*)["\']',
            r'href=["\']([^"\']*cart[^"\']*)["\']',
            r'href=["\']([^"\']*payment[^"\']*)["\']',
            r'href=["\']([^"\']*donate[^"\']*)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith("http"):
                    return match
                elif match.startswith("/"):
                    parsed = urlparse(base_url)
                    return f"{parsed.scheme}://{parsed.netloc}{match}"
        
        return None
    
    def _calculate_score(self, info: SiteInfo) -> int:
        """Calculate site viability score (0-100)."""
        score = 0
        
        # Must have Stripe PK (+40)
        if info.pk_key:
            score += 40
        else:
            return 0  # No point without Stripe
        
        # Platform detection (+15)
        if info.platform:
            if info.platform == "WooCommerce":
                score += 20  # Preferred platform
            elif info.platform in ["WordPress", "Shopify"]:
                score += 15
            else:
                score += 10
        
        # No CAPTCHA (+25)
        if not info.has_captcha:
            score += 25
        else:
            score -= 30  # Heavy penalty
        
        # No Cloudflare (+10)
        if not info.has_cloudflare:
            score += 10
        else:
            score -= 15  # Moderate penalty
        
        # Easy registration (+15)
        if info.registration_type == "email_only":
            score += 15
        elif info.registration_type == "phone_required":
            score -= 20  # Heavy penalty
        
        # Found checkout URL (+5)
        if info.checkout_url:
            score += 5
        
        return max(0, min(100, score))
    
    async def validate(self, url: str) -> Optional[SiteInfo]:
        """
        Validate a single URL.
        
        Returns:
            SiteInfo if valid, None if should be skipped
        """
        domain = self._extract_domain(url)
        
        if not domain:
            logger.debug(f"VALIDATE | Skip: Could not extract domain from {url}")
            return None
        
        if self._should_skip(domain):
            logger.debug(f"VALIDATE | Skip: {domain} is in skip list")
            return None
        
        info = SiteInfo(url=url, domain=domain)
        logger.debug(f"VALIDATE | Checking: {url}")
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    proxy=self.proxy,
                    ssl=False,
                    allow_redirects=True
                ) as response:
                    if response.status != 200:
                        info.errors.append(f"HTTP {response.status}")
                        logger.warning(f"VALIDATE | {domain}: HTTP {response.status}")
                        return info
                    
                    html = await response.text()
                    headers = dict(response.headers)
                    html_size = len(html)
                    logger.debug(f"VALIDATE | {domain}: Got {html_size} bytes")
                    
                    # Find Stripe PK
                    pk_match = re.search(r'pk_live_[a-zA-Z0-9]{20,}', html)
                    if pk_match:
                        info.pk_key = pk_match.group(0)
                        logger.info(f"VALIDATE | {domain}: Found Stripe PK: {info.pk_key[:30]}...")
                    else:
                        # Also check for pk_test
                        pk_test_match = re.search(r'pk_test_[a-zA-Z0-9]{20,}', html)
                        if pk_test_match:
                            logger.debug(f"VALIDATE | {domain}: Found pk_test only (no pk_live)")
                        else:
                            logger.debug(f"VALIDATE | {domain}: No Stripe PK found")
                    
                    # Check for Braintree
                    braintree_match = re.search(r'braintree|data-braintree|braintree\.client', html.lower())
                    if braintree_match:
                        logger.info(f"VALIDATE | {domain}: Found Braintree indicators")
                    
                    # Detect platform
                    info.platform = self._detect_platform(html)
                    if info.platform:
                        logger.debug(f"VALIDATE | {domain}: Platform = {info.platform}")
                    
                    # Detect CAPTCHA
                    info.has_captcha = self._detect_captcha(html)
                    if info.has_captcha:
                        logger.debug(f"VALIDATE | {domain}: CAPTCHA detected")
                    
                    # Detect Cloudflare
                    info.has_cloudflare = self._detect_cloudflare(html, headers)
                    if info.has_cloudflare:
                        logger.debug(f"VALIDATE | {domain}: Cloudflare detected")
                    
                    # Detect registration
                    info.has_registration, info.registration_type = self._detect_registration(html)
                    if info.has_registration:
                        logger.debug(f"VALIDATE | {domain}: Registration = {info.registration_type}")
                    
                    # Find checkout URL
                    info.checkout_url = self._find_checkout_url(html, url)
                    if info.checkout_url:
                        logger.debug(f"VALIDATE | {domain}: Checkout URL = {info.checkout_url[:50]}...")
                    
                    # Calculate score
                    info.score = self._calculate_score(info)
                    
                    # Log detailed result
                    logger.info(
                        f"VALIDATE | {domain}: "
                        f"Score={info.score} | "
                        f"PK={'YES' if info.pk_key else 'NO'} | "
                        f"Platform={info.platform or 'Unknown'} | "
                        f"Captcha={info.has_captcha} | "
                        f"CF={info.has_cloudflare}"
                    )
                    
                    return info
                    
        except asyncio.TimeoutError:
            info.errors.append("Timeout")
            logger.warning(f"VALIDATE | {domain}: Timeout after {self.timeout}s")
            return info
        except aiohttp.ClientError as e:
            info.errors.append(str(e)[:100])
            logger.error(f"VALIDATE | {domain}: Connection error: {e}")
            return info
        except Exception as e:
            info.errors.append(str(e)[:100])
            logger.error(f"VALIDATE | {domain}: Error: {e}")
            return info
    
    async def validate_many(
        self,
        urls: List[str],
        max_concurrent: int = 5
    ) -> List[SiteInfo]:
        """
        Validate multiple URLs concurrently.
        
        Args:
            urls: List of URLs to validate
            max_concurrent: Maximum concurrent validations
            
        Returns:
            List of SiteInfo for validated sites
        """
        logger.info(f"VALIDATE | Starting batch validation of {len(urls)} URLs (max {max_concurrent} concurrent)")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def validate_with_semaphore(url: str) -> Optional[SiteInfo]:
            async with semaphore:
                return await self.validate(url)
        
        tasks = [validate_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks)
        
        # Count results
        total = len(results)
        none_count = sum(1 for r in results if r is None)
        with_pk = sum(1 for r in results if r and r.pk_key)
        without_pk = sum(1 for r in results if r and not r.pk_key)
        with_errors = sum(1 for r in results if r and r.errors)
        
        logger.info(
            f"VALIDATE | Batch complete: "
            f"Total={total} | "
            f"Skipped={none_count} | "
            f"With PK={with_pk} | "
            f"No PK={without_pk} | "
            f"Errors={with_errors}"
        )
        
        # Filter out None results and sites without Stripe
        valid = [r for r in results if r and r.pk_key]
        
        # Log each valid site
        for site in valid:
            logger.info(f"VALIDATE | Valid site: {site.domain} (score: {site.score})")
        
        return valid
