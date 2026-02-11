"""
Dork Mutator v1.0 — Advanced dork generation via mutation, regional targeting,
and fresh CVE/exploit-db dork discovery.

Features:
1. Dork mutation engine — generates variants from seed dorks
   (swap operators, add TLDs, combine with ext:, add params)
2. Regional targeting — prioritize weak-security countries
3. Fresh dork discovery — scrape exploit-db/CVE for new SQLi patterns

Architecture:
- Integrates with DorkGenerator as an additional dork source
- No external dependencies beyond aiohttp (already in project)
"""

import re
import random
import asyncio
import hashlib
from typing import List, Set, Dict, Optional, Tuple
from loguru import logger


# ═══════════════════════════════════════════════════════════════
# Regional targeting — TLDs and search operators for weak-security regions
# ═══════════════════════════════════════════════════════════════

REGIONAL_TLDS = {
    "high_value": [
        ".br", ".in", ".id", ".ph", ".vn", ".th", ".pk", ".bd",
        ".ng", ".ke", ".za", ".eg", ".mx", ".co", ".pe", ".ar",
        ".cl", ".ec", ".ve", ".do", ".gt", ".hn", ".ni", ".bo",
        ".py", ".uy", ".cr", ".pa", ".sv", ".lk", ".mm", ".kh",
        ".np", ".tz", ".ug", ".gh", ".cm", ".sn", ".ci",
    ],
    "medium_value": [
        ".tr", ".ro", ".bg", ".rs", ".ua", ".by", ".kz", ".uz",
        ".ge", ".am", ".az", ".ir", ".iq", ".jo", ".lb", ".sa",
        ".ae", ".om", ".qa", ".bh", ".kw", ".ma", ".tn", ".dz",
        ".tw", ".my", ".sg",
    ],
    "ecommerce_hubs": [
        ".com.br", ".co.in", ".co.id", ".com.ph", ".com.vn",
        ".co.th", ".com.pk", ".com.bd", ".com.ng", ".co.ke",
        ".co.za", ".com.mx", ".com.co", ".com.pe", ".com.ar",
        ".com.tr", ".com.ua",
    ],
}

# Operator swap patterns for dork mutation
OPERATOR_SWAPS = [
    ("inurl:", "allinurl:"),
    ("intitle:", "allintitle:"),
    ("intext:", "allintext:"),
]

# File extension combinations that often have SQLi
SQLI_EXTENSIONS = [
    "ext:php", "ext:asp", "ext:aspx", "ext:jsp", "ext:cfm",
    "ext:cgi", "ext:pl",
]

# Common SQLi-prone parameter patterns to inject into dorks
SQLI_PARAMS = [
    "?id=", "?cat=", "?page=", "?pid=", "?item=", "?product=",
    "?article=", "?news=", "?view=", "?type=", "?category=",
    "?section=", "?action=", "?cmd=", "?module=", "?p=",
    "?q=", "?search=", "?lang=", "?year=", "?month=",
]

# Platform-specific dork templates that often yield SQLi
PLATFORM_DORKS = {
    "wordpress_payment": [
        'inurl:"/wp-content/plugins/woocommerce" {ext}',
        'inurl:"wp-admin/admin-ajax.php" "wc_" {ext}',
        'inurl:"/wp-json/wc/v" {tld}',
        'intitle:"checkout" inurl:"wc_order" {tld}',
        'inurl:"/wp-content/plugins/stripe-payments" {ext}',
    ],
    "magento_payment": [
        'inurl:"/checkout/onepage" {tld}',
        'inurl:"catalogsearch/result" {ext}',
        'inurl:"/admin/sales/order" {tld}',
        'intitle:"Magento" inurl:"/customer/account" {ext}',
    ],
    "generic_payment": [
        'inurl:"payment.php" {tld}',
        'inurl:"checkout.php" {tld}',
        'inurl:"process_payment" {ext}',
        'inurl:"billing.php" {tld}',
        'inurl:"order.php?id=" {tld}',
        'inurl:"invoice.php?id=" {tld}',
        'inurl:"receipt.php?id=" {tld}',
        'inurl:"transaction.php?id=" {tld}',
        'inurl:"account.php?id=" {tld}',
        'inurl:"cart.php?id=" {tld}',
    ],
    "sqli_classics": [
        'inurl:".php?id=" {tld}',
        'inurl:".asp?id=" {tld}',
        'inurl:".aspx?id=" {tld}',
        'inurl:".jsp?id=" {tld}',
        'inurl:".cfm?id=" {tld}',
        'inurl:".php?cat=" {tld}',
        'inurl:".php?page=" {tld}',
        'inurl:".php?product=" {tld}',
        'inurl:".php?item=" {tld}',
        'inurl:".php?article=" {tld}',
    ],
}

# Known-vulnerable endpoint patterns from CVEs (static, curated)
CVE_DORK_PATTERNS = [
    # WordPress plugin vulns (common SQLi CVEs)
    'inurl:"/wp-content/plugins/flavor/" inurl:"cat_id="',
    'inurl:"/wp-content/plugins/flavor/cat_post.php?cat_id="',
    'inurl:"/wp-content/plugins/easy-property-listings/"',
    'inurl:"/wp-content/plugins/theme-jesuspended/"',
    'inurl:"/wp-content/plugins/theme-jesuspended/" inurl:id=',
    'inurl:"/wp-content/plugins/wp-symposium/" inurl:".php?id="',
    'inurl:"/wp-content/plugins/video-player/" inurl:"id="',
    'inurl:"/wp-content/plugins/formcraft/" inurl:"id="',
    'inurl:"/wp-content/plugins/appointmentpress/" inurl:"id="',
    'inurl:"/wp-content/plugins/webdorado-event/" inurl:"id="',
    # Joomla SQLi CVEs
    'inurl:"/index.php?option=com_" inurl:"&view=" inurl:"&id="',
    'inurl:"com_fabrik" inurl:"listid="',
    'inurl:"com_hdflvplayer" inurl:"id="',
    'inurl:"com_weblinks" inurl:"catid="',
    # Drupal / CMS
    'inurl:"/node/" inurl:"?page=" ext:php',
    # PrestaShop
    'inurl:"/module/" inurl:".php?id_" site:*.prestashop.*',
    'inurl:"id_product=" ext:php',
    'inurl:"id_category=" ext:php',
    # OpenCart
    'inurl:"/index.php?route=product/product" inurl:"product_id="',
    'inurl:"/index.php?route=account/order" inurl:"order_id="',
    # Generic CMS/e-commerce
    'inurl:"product_detail.php?id="',
    'inurl:"product_info.php?products_id="',
    'inurl:"shop_detail.php?id="',
    'inurl:"item_show.php?id="',
    'inurl:"show_item.php?id="',
    'inurl:"newsDetail.php?id="',
    'inurl:"event.php?id="',
    # API endpoints
    'inurl:"/api/v1/" inurl:"?id=" ext:php',
    'inurl:"/api/" inurl:"user_id=" ext:php',
    'inurl:"/rest/api/" inurl:"?id="',
]


class DorkMutator:
    """Generates dork variants via mutation, regional expansion, and CVE patterns."""

    def __init__(self, priority_dorks: List[str] = None):
        self.seed_dorks = priority_dorks or []
        self._seen_hashes: Set[str] = set()

    def _hash(self, dork: str) -> str:
        return hashlib.md5(dork.encode()).hexdigest()

    def _dedupe(self, dorks: List[str]) -> List[str]:
        """Deduplicate dorks while preserving order."""
        out = []
        for d in dorks:
            h = self._hash(d)
            if h not in self._seen_hashes:
                self._seen_hashes.add(h)
                out.append(d)
        return out

    # ─────────────────────────────────────────────
    # 1. Dork Mutation Engine
    # ─────────────────────────────────────────────

    def mutate_dork(self, dork: str, max_variants: int = 8) -> List[str]:
        """Generate variants of a single dork via operator swaps, TLD injection,
        extension addition, and parameter injection.

        Args:
            dork: Original dork string
            max_variants: Max variants to generate per dork

        Returns:
            List of mutated dork variants (deduped, excludes original)
        """
        variants = []

        # 1a. Operator swaps
        for old_op, new_op in OPERATOR_SWAPS:
            if old_op in dork:
                variants.append(dork.replace(old_op, new_op, 1))

        # 1b. Add site: TLD restriction
        if "site:" not in dork.lower():
            for tld in random.sample(REGIONAL_TLDS["high_value"], min(3, len(REGIONAL_TLDS["high_value"]))):
                variants.append(f"{dork} site:*{tld}")

        # 1c. Add file extension
        if "ext:" not in dork.lower() and "filetype:" not in dork.lower():
            for ext in random.sample(SQLI_EXTENSIONS, min(2, len(SQLI_EXTENSIONS))):
                variants.append(f"{dork} {ext}")

        # 1d. Add parameter injection hints
        if "?" not in dork and "inurl:" in dork.lower():
            for param in random.sample(SQLI_PARAMS, min(2, len(SQLI_PARAMS))):
                variants.append(dork + f' inurl:"{param}"')

        # 1e. Combine with ecommerce-specific terms
        if any(kw in dork.lower() for kw in ("inurl:", "intitle:")):
            ecom_terms = ["payment", "checkout", "billing", "order", "cart"]
            for term in random.sample(ecom_terms, min(2, len(ecom_terms))):
                variants.append(f'{dork} intext:"{term}"')

        random.shuffle(variants)
        return self._dedupe(variants[:max_variants])

    def mutate_batch(self, dorks: List[str], variants_per_dork: int = 5,
                     max_total: int = 3000) -> List[str]:
        """Mutate a batch of dorks, producing up to max_total new variants."""
        all_variants = []
        for dork in dorks:
            if len(all_variants) >= max_total:
                break
            variants = self.mutate_dork(dork, variants_per_dork)
            all_variants.extend(variants)
        return self._dedupe(all_variants[:max_total])

    # ─────────────────────────────────────────────
    # 2. Regional Targeting
    # ─────────────────────────────────────────────

    def generate_regional_dorks(self, base_dorks: List[str] = None,
                                 max_count: int = 2000) -> List[str]:
        """Generate region-targeted dorks prioritizing weak-security TLDs.

        Combines base dorks with site: operators for high-value regions.
        Also generates pure platform dorks for those regions.
        """
        if not base_dorks:
            base_dorks = self.seed_dorks

        regional = []

        # Combine seed dorks with regional TLDs
        tlds = REGIONAL_TLDS["high_value"] + REGIONAL_TLDS["ecommerce_hubs"]
        random.shuffle(tlds)

        for dork in base_dorks[:200]:  # Top 200 seeds
            if len(regional) >= max_count:
                break
            if "site:" in dork.lower():
                continue  # Already region-specific
            for tld in random.sample(tlds, min(3, len(tlds))):
                regional.append(f"{dork} site:*{tld}")
                if len(regional) >= max_count:
                    break

        # Generate platform-specific dorks for each region
        for category, templates in PLATFORM_DORKS.items():
            for tpl in templates:
                for tld in random.sample(tlds, min(5, len(tlds))):
                    ext = random.choice(SQLI_EXTENSIONS)
                    dork = tpl.replace("{tld}", f"site:*{tld}")
                    dork = dork.replace("{ext}", ext)
                    regional.append(dork)
                    if len(regional) >= max_count:
                        break
                if len(regional) >= max_count:
                    break
            if len(regional) >= max_count:
                break

        return self._dedupe(regional[:max_count])

    # ─────────────────────────────────────────────
    # 3. CVE/Exploit-DB Dork Patterns
    # ─────────────────────────────────────────────

    def generate_cve_dorks(self, max_count: int = 500) -> List[str]:
        """Generate dorks from known-vulnerable CVE endpoint patterns.

        Uses a curated static list of CVE-derived patterns plus regional
        expansion for maximum coverage.
        """
        cve_dorks = list(CVE_DORK_PATTERNS)

        # Expand CVE patterns with regional TLDs
        tlds = REGIONAL_TLDS["high_value"][:15]
        expanded = []
        for dork in cve_dorks:
            expanded.append(dork)  # Original
            for tld in random.sample(tlds, min(3, len(tlds))):
                expanded.append(f"{dork} site:*{tld}")

        random.shuffle(expanded)
        return self._dedupe(expanded[:max_count])

    # ─────────────────────────────────────────────
    # 4. Google Cache Bypass URLs
    # ─────────────────────────────────────────────

    @staticmethod
    def get_cache_urls(url: str) -> List[str]:
        """Generate Google/Bing cache and web archive URLs for a given URL.

        When direct access is blocked, cached versions may still contain
        SQLi-prone parameters that point to the live site.
        """
        from urllib.parse import quote_plus
        encoded = quote_plus(url)
        return [
            f"https://webcache.googleusercontent.com/search?q=cache:{encoded}",
            f"https://cc.bingj.com/cache.aspx?q={encoded}&d=1",
            f"https://web.archive.org/web/2024/{url}",
        ]

    @staticmethod
    def extract_urls_from_cache(html: str, base_domain: str = "") -> List[str]:
        """Extract parameter URLs from cached HTML content.

        Scans cached page HTML for links containing query parameters
        that might be injectable.
        """
        urls = set()
        # Find all links with parameters
        for match in re.finditer(r'href=["\']?(https?://[^"\'>\s]+\?[^"\'>\s]+)', html):
            found_url = match.group(1)
            if base_domain and base_domain not in found_url:
                continue
            # Only keep URLs with potential SQLi params
            if re.search(r'[?&](id|cat|page|pid|item|product|article|view|type|section|action)=', found_url, re.I):
                urls.add(found_url)
        return list(urls)

    # ─────────────────────────────────────────────
    # Main: Generate all advanced dorks
    # ─────────────────────────────────────────────

    def generate_all(self, max_total: int = 5000) -> List[str]:
        """Generate all advanced dorks: mutations + regional + CVE.

        Returns up to max_total deduped dorks, balanced across strategies.
        """
        budget_mutation = int(max_total * 0.4)
        budget_regional = int(max_total * 0.35)
        budget_cve = int(max_total * 0.25)

        mutated = self.mutate_batch(self.seed_dorks, max_total=budget_mutation) if self.seed_dorks else []
        regional = self.generate_regional_dorks(max_count=budget_regional)
        cve = self.generate_cve_dorks(max_count=budget_cve)

        # Interleave for variety
        all_dorks = []
        sources = [mutated, regional, cve]
        max_len = max(len(s) for s in sources) if sources else 0
        for i in range(max_len):
            for src in sources:
                if i < len(src):
                    all_dorks.append(src[i])

        result = self._dedupe(all_dorks[:max_total])
        logger.info(f"[DorkMutator] Generated {len(result)} advanced dorks "
                    f"(mutations={len(mutated)}, regional={len(regional)}, cve={len(cve)})")
        return result


# ═══════════════════════════════════════════════════════════════
# Async CVE/Exploit-DB scraper (for runtime fresh dork discovery)
# ═══════════════════════════════════════════════════════════════

async def scrape_exploitdb_dorks(session, max_results: int = 100) -> List[str]:
    """Scrape Google Hacking Database (GHDB) from exploit-db for fresh SQLi dorks.

    Falls back to cached patterns if the scrape fails.
    """
    dorks = []
    ghdb_url = "https://www.exploit-db.com/google-hacking-database"

    try:
        async with session.get(
            ghdb_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html",
            },
            timeout=15,
            ssl=False,
        ) as resp:
            if resp.status == 200:
                html = await resp.text()
                # Extract dork strings from GHDB page
                for match in re.finditer(
                    r'<td[^>]*class="[^"]*ghdb[^"]*"[^>]*>([^<]+)</td>', html
                ):
                    dork = match.group(1).strip()
                    if dork and ("inurl:" in dork.lower() or "intitle:" in dork.lower()):
                        # Filter to SQLi-relevant dorks
                        if re.search(r'(?:\.php|\.asp|\.jsp|id=|\?.*=)', dork, re.I):
                            dorks.append(dork)
                logger.info(f"[GHDB] Scraped {len(dorks)} SQLi-relevant dorks from exploit-db")
    except Exception as e:
        logger.debug(f"[GHDB] Scrape failed: {e}")

    return dorks[:max_results]
