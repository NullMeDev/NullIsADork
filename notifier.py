"""
Telegram Notifier Module - Sends findings to Telegram
"""

import asyncio
from typing import Optional, List
import aiohttp
from loguru import logger

from validator import SiteInfo


class TelegramNotifier:
    """Sends notifications to Telegram."""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base = f"https://api.telegram.org/bot{bot_token}"
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create a reusable aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    async def close(self):
        """Close the reusable session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
    
    async def send_message(
        self,
        text: str,
        parse_mode: str = "HTML",
        disable_preview: bool = True
    ) -> bool:
        """
        Send a message to the configured chat.
        
        Args:
            text: Message text
            parse_mode: HTML or Markdown
            disable_preview: Disable link preview
            
        Returns:
            True if successful
        """
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        url = f"{self.api_base}/sendMessage"
        data = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": disable_preview,
        }
        
        try:
            session = await self._get_session()
            async with session.post(url, json=data) as response:
                if response.status == 200:
                    logger.debug("Telegram message sent successfully")
                    return True
                else:
                    error = await response.text()
                    logger.error(f"Telegram API error: {response.status} - {error}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    async def send_site_found(self, site: SiteInfo) -> bool:
        """
        Send notification about a found site.
        
        Args:
            site: SiteInfo object
            
        Returns:
            True if successful
        """
        return await self.send_message(site.format_telegram())
    
    async def send_sites_batch(self, sites: List[SiteInfo]) -> bool:
        """
        Send a batch summary of found sites.
        
        Args:
            sites: List of SiteInfo objects
            
        Returns:
            True if successful
        """
        if not sites:
            return True
        
        # Sort by score
        sites = sorted(sites, key=lambda x: x.score, reverse=True)
        
        # Build summary message
        msg = f"<b>🔍 Dorker Found {len(sites)} Sites</b>\n\n"
        
        for i, site in enumerate(sites[:10], 1):  # Top 10
            score_emoji = "✅" if site.score >= 50 else "⚠️" if site.score >= 20 else "❌"
            platform = site.platform or "Unknown"
            captcha = "❌" if site.has_captcha else "✅"
            
            msg += f"{i}. {score_emoji} <code>{site.domain}</code>\n"
            msg += f"   Score: {site.score} | {platform} | CAPTCHA: {captcha}\n"
        
        if len(sites) > 10:
            msg += f"\n... and {len(sites) - 10} more sites"
        
        return await self.send_message(msg)
    
    async def send_status(
        self,
        total_searched: int,
        total_found: int,
        current_dork: str,
        cycle: int
    ) -> bool:
        """
        Send status update.
        
        Args:
            total_searched: Total URLs searched
            total_found: Total valid sites found
            current_dork: Current dork being processed
            cycle: Current cycle number
            
        Returns:
            True if successful
        """
        msg = f"""
<b>📊 Dorker Status Update</b>

<b>Cycle:</b> #{cycle}
<b>URLs Searched:</b> {total_searched}
<b>Valid Sites Found:</b> {total_found}
<b>Current Dork:</b>
<code>{current_dork[:100]}...</code>
"""
        return await self.send_message(msg.strip())
    
    async def send_error(self, error: str) -> bool:
        """Send error notification."""
        msg = f"<b>❌ Dorker Error</b>\n\n<code>{error[:500]}</code>"
        return await self.send_message(msg)
    
    async def send_startup(self, dork_count: int, proxy_count: int) -> bool:
        """Send startup notification."""
        msg = f"""
<b>🚀 Dorker Started</b>

<b>Dorks Loaded:</b> {dork_count}
<b>Proxies Loaded:</b> {proxy_count}
<b>Status:</b> Running continuously

The dorker will notify you when viable sites are found.
"""
        return await self.send_message(msg.strip())
