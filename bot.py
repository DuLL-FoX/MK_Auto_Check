import logging
from typing import List, Dict, Any

import discord

from core.analyzer import PlayerAnalyzer
from core.scanner import Scanner
from services.admin_service import AdminService
from services.cache_service import CacheService
from services.discord_service import DiscordService
from services.report_service import ReportService


class BanCheckerBot:
    def __init__(self, token: str, admin_panel, config: Dict[str, Any]) -> None:
        self.token = token
        self.config = config
        intents = discord.Intents.default()
        self.client = discord.Client(intents=intents)
        self.discord_service = DiscordService(self.client)
        self.admin_service = AdminService(admin_panel)
        self.cache_service = CacheService()
        self.report_service = ReportService()
        self.player_analyzer = PlayerAnalyzer()
        self.scanner = Scanner(
            self.discord_service,
            self.admin_service,
            self.cache_service,
            self.report_service,
            self.player_analyzer
        )
        self.client.event(self.on_ready)

    async def on_ready(self):
        logging.info(f"Logged in as: {self.client.user} (ID: {self.client.user.id})")
        target_channel_id = self.config.get("TARGET_CHANNEL_ID")
        complaint_channel_ids = self.config.get("COMPLAINT_CHANNEL_IDS", [])
        if not await self.scanner.setup(target_channel_id, complaint_channel_ids):
            logging.error("Failed to set up scanner. Exiting.")
            await self.close()
            return
        try:
            report_data: List[Dict[str, Any]] = []
            original_checks = []
            if self.config.get("check_ban_bypass"):
                original_checks = await self.scanner.check_ban_bypasses_raw(
                    max_pages=self.config.get("ban_bypass_pages", 5)
                )
                report_data = self.report_service.generate_ban_bypass_report(original_checks)
            elif self.config.get("username"):
                report_data = await self.scanner.scan_nickname(self.config.get("username"))
            elif self.config.get("message_limit") is not None:
                report_data = await self.scanner.scan_messages(
                    message_limit=self.config.get("message_limit", 10)
                )
            else:
                logging.warning("No scan type specified or missing parameters.")
            if report_data:
                self.report_service.write_json_report(report_data)
        except Exception as e:
            logging.error(f"Error during scan: {e}", exc_info=True)
        logging.info("Scan complete. Disconnecting from Discord.")
        await self.close()

    async def close(self):
        if self.client:
            await self.client.close()

    def run(self):
        self.client.run(self.token, bot=False)
