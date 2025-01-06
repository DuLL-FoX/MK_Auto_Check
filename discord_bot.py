import json
import logging
from typing import List, Dict, Any, Optional

import discord

from admin_panel import AdminPanel
from config_backup_v2 import TARGET_CHANNEL_ID, COMPLAINT_CHANNEL_IDS
from utils import embed_contains_nickname, collect_unique_links_from_embed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(module)s - %(message)s"
)

MESSAGE_LINK_FORMAT = "https://discord.com/channels/{}/{}/{}"
SCAN_REPORT_FILENAME = "scan_report.json"
SHARED_HWID_INFO_FORMAT = "Shared HWID with: {}"
COMPLAINT_LINKS_SUMMARY_FORMAT = "\n      Found in complaint messages:\n{}"
COMPLAINT_LINK_ITEM_FORMAT = "      - {}"
NICKNAMES_FORMAT = ", ".join
BAN_REASONS_FORMAT = ", ".join
NO_BAN_REASONS = "None"
NO_COMPLAINTS_FOUND = "None found"
UNKNOWN_STATUS = "unknown"
BANNED_VERDICT = "POSSIBLE BYPASS / BANNED"
CLEAN_VERDICT = "CLEAN / NO BYPASS"
SUSPICIOUS_VERDICT = "SUSPICIOUS / CHECK SERVER BANS"
UNKNOWN_VERDICT = "UNKNOWN / NEED MANUAL CHECK"
N_A = "N/A"

class DiscordBot(discord.Client):

    def __init__(
            self,
            admin_panel: AdminPanel,
            message_limit: int = 10,
            complaint_message_history_limit: int = 200,
            *args,
            **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.admin_panel = admin_panel
        self.message_limit = message_limit
        self.complaint_message_history_limit = complaint_message_history_limit
        self.target_channel: Optional[discord.TextChannel] = None

    async def _login_to_admin_panel(self) -> bool:
        logging.info("Logging in to the admin panel...")
        if not self.admin_panel.login():
            logging.error("Could not log in to the admin site.")
            return False
        logging.info("Successfully logged in to the admin panel.")
        return True

    async def _fetch_target_channel(self) -> bool:
        logging.info(f"Fetching target channel with ID: {TARGET_CHANNEL_ID}")
        self.target_channel = self.get_channel(TARGET_CHANNEL_ID)
        if not self.target_channel:
            logging.error(f"Could not find the target channel with ID: {TARGET_CHANNEL_ID}")
            return False
        logging.info(f"Target channel found: '{self.target_channel.name}' ({TARGET_CHANNEL_ID})")
        return True

    async def setup(self) -> bool:
        logging.info("Setting up the bot...")

        if not await self._login_to_admin_panel():
            await self.close()
            return False

        if not await self._fetch_target_channel():
            await self.close()
            return False

        return True

    async def on_ready(self) -> None:
        logging.info(f"Logged in to Discord as: {self.user} (ID: {self.user.id})")

        if not await self.setup():
            return

        report_data = await self.process_messages()

        self.write_json_report(report_data, file_name=SCAN_REPORT_FILENAME)

        logging.info("Finished scanning messages. Disconnecting from Discord.")
        await self.close()

    async def process_messages(self) -> List[Dict[str, Any]]:
        if not self.target_channel:
            logging.warning("Target channel is not set. Cannot process messages.")
            return []

        logging.info(
            f"Checking last {self.message_limit} messages in "
            f"'{self.target_channel.name}' ({TARGET_CHANNEL_ID}) for embed links."
        )

        report_data: List[Dict[str, Any]] = []

        async for message in self.target_channel.history(
                limit=self.message_limit, oldest_first=False
        ):
            if not message.embeds:
                continue

            message_info = await self._process_message(message)
            if message_info:
                report_data.append(message_info)
                self.log_message_summary(message_info)

        return report_data

    async def _process_message(
            self, message: discord.Message
    ) -> Optional[Dict[str, Any]]:
        partial_results_for_message: List[Dict[str, Any]] = []

        for embed in message.embeds:
            unique_links_dict = collect_unique_links_from_embed(embed)
            if not unique_links_dict:
                continue

            for link in unique_links_dict.values():
                try:
                    account_info = self.admin_panel.check_account_on_site(link)
                    partial_results_for_message.append(account_info)
                except Exception as e:
                    logging.error(f"Error checking account on admin site for link {link}: {e}")

        merged_player_results = self.admin_panel.aggregate_player_info(
            partial_results_for_message
        )
        if not merged_player_results:
            return None

        message_info: Dict[str, Any] = {
            "message_id": str(message.id),
            "message_link": MESSAGE_LINK_FORMAT.format(
                message.guild.id, message.channel.id, message.id
            ),
            "author_name": str(message.author),
            "author_id": str(message.author.id),
            "results": []
        }

        for player_res in merged_player_results:
            await self._enrich_player_results(player_res)
            message_info["results"].append(player_res)

        return message_info

    async def _enrich_player_results(self, player_res: Dict[str, Any]) -> None:
        if not player_res.get("suspected_vpn") and player_res.get("nicknames"):
            all_complaint_links: List[str] = []
            for nickname in player_res["nicknames"]:
                found_links = await self.check_name_in_channels(nickname)
                all_complaint_links.extend(found_links)

            player_res["complaint_links"] = list(set(all_complaint_links))
        else:
            player_res["complaint_links"] = []

    async def check_name_in_channels(self, nickname: str) -> List[str]:
        lower_nick = nickname.lower()
        found_links: List[str] = []

        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel = self.get_channel(ch_id)
            if not channel:
                logging.warning(f"Could not find complaint channel with ID: {ch_id}")
                continue

            try:
                async for msg in channel.history(limit=self.complaint_message_history_limit):
                    if lower_nick in msg.content.lower():
                        jump_link = MESSAGE_LINK_FORMAT.format(msg.guild.id, channel.id, msg.id)
                        found_links.append(jump_link)
                        continue

                    for embed in msg.embeds:
                        if embed_contains_nickname(embed, nickname):
                            jump_link = MESSAGE_LINK_FORMAT.format(msg.guild.id, channel.id, msg.id)
                            found_links.append(jump_link)
                            break

            except discord.Forbidden:
                logging.warning(
                    f"Could not read channel {channel.name} ({ch_id}). "
                    "Insufficient permissions."
                )
            except discord.HTTPException as e:
                logging.error(
                    f"Discord API error while reading channel {channel.name} "
                    f"({ch_id}): {e}"
                )
            except Exception as e:
                logging.error(
                    f"Unexpected error reading channel {channel.name} ({ch_id}): {e}",
                    exc_info=True,
                )

        return found_links

    def _get_player_verdict(self, status: str) -> str:
        if status == "banned":
            return BANNED_VERDICT
        elif status == "clean":
            return CLEAN_VERDICT
        elif status == "suspicious":
            return SUSPICIOUS_VERDICT
        else:
            return UNKNOWN_VERDICT

    def log_message_summary(self, message_info: Dict[str, Any]) -> None:
        results = message_info["results"]
        logging.info("=" * 60)
        logging.info(
            f"Message ID {message_info['message_id']} by {message_info['author_name']} "
            f"had {len(results)} merged result(s)."
        )
        logging.info(f"Message link: {message_info['message_link']}")

        for idx, result in enumerate(results, start=1):
            status = result.get("status", UNKNOWN_STATUS)
            verdict = self._get_player_verdict(status)

            shared_info = ""
            if result.get("shared_hwid_nicknames"):
                shared_names = NICKNAMES_FORMAT(result["shared_hwid_nicknames"])
                shared_info = SHARED_HWID_INFO_FORMAT.format(shared_names)

            complaint_summary = NO_COMPLAINTS_FOUND
            if result.get("complaint_links"):
                complaint_links = "\n".join(
                    COMPLAINT_LINK_ITEM_FORMAT.format(link) for link in result["complaint_links"]
                )
                complaint_summary = COMPLAINT_LINKS_SUMMARY_FORMAT.format(complaint_links)

            ban_reasons = BAN_REASONS_FORMAT(result.get("ban_reasons", [])) or NO_BAN_REASONS

            logging.info(
                f"{idx}) Nicknames: {NICKNAMES_FORMAT(result.get('nicknames', [N_A]))}\n"
                f"   Status: {status} (Ban count: {result.get('ban_counts', 0)})\n"
                f"   Suspected VPN: {result.get('suspected_vpn', False)}\n"
                f"   Ban reasons: {ban_reasons}\n"
                f"   Verdict: {verdict}\n"
                f"   {shared_info}\n"
                f"   Found in complaint messages: {complaint_summary}"
            )
        logging.info("=" * 60)

    def write_json_report(
            self,
            report_data: List[Dict[str, Any]],
            file_name: str = SCAN_REPORT_FILENAME
    ) -> None:
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            logging.info(
                f"JSON report saved to '{file_name}' with {len(report_data)} messages."
            )
        except Exception as e:
            logging.error(f"Could not write JSON report to '{file_name}': {e}")