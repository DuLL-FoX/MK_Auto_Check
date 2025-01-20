import json
import logging
import os
from typing import List, Dict, Any, Optional

import discord

from admin_panel import AdminPanel
from config_backup_v2 import (
    TARGET_CHANNEL_ID,
    COMPLAINT_CHANNEL_IDS,
    COMPLAINT_MESSAGE_HISTORY_LIMIT
)
from utils import embed_contains_nickname, collect_unique_links_from_embed

MESSAGE_LINK_FORMAT = "https://discord.com/channels/{}/{}/{}"
SCAN_REPORT_FILENAME = "scan_report.json"
COMPLAINT_CACHE_FILENAME = "complaint_message_cache.json"

# Format strings for logs and text
SHARED_HWID_INFO_FORMAT = "Shared HWID with: {}"
COMPLAINT_LINKS_SUMMARY_FORMAT = "\n      Found in complaint messages:\n{}"
COMPLAINT_LINK_ITEM_FORMAT = "      - {}"

# Various “verdict” constants
UNKNOWN_STATUS = "unknown"
BANNED_VERDICT = "POSSIBLE BYPASS / BANNED"
CLEAN_VERDICT = "CLEAN / NO BYPASS"
SUSPICIOUS_VERDICT = "SUSPICIOUS / SHARED HWID - MANUAL CHECK REQUIRED"
UNKNOWN_VERDICT = "UNKNOWN / NEED MANUAL CHECK"

# Misc constants
NO_BAN_REASONS = "None"
NO_COMPLAINTS_FOUND = "None found"
NICKNAMES_FORMAT = ", ".join
BAN_REASONS_FORMAT = ", ".join
N_A = "N/A"

EMBED_FIELDS_TO_CACHE = ["title", "description", "fields"]


class DiscordBot(discord.Client):
    def __init__(
        self,
        admin_panel: AdminPanel,
        message_limit: Optional[int] = 10,
        username: Optional[str] = None,
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.admin_panel = admin_panel
        self.message_limit = message_limit
        self.username = username

        self.target_channel: Optional[discord.TextChannel] = None
        self.complaint_channels: Dict[int, discord.TextChannel] = {}

        # complaint_message_cache[ch_id] = {
        #   "messages": [{ "id": int, "content": str, "embeds": [...] }, ...],
        #   "last_cached_id": Optional[int]
        # }
        self.complaint_message_cache: Dict[int, Dict[str, Any]] = {}

    async def on_ready(self) -> None:
        logging.info(f"Logged in to Discord as: {self.user} (ID: {self.user.id})")
        if not await self.setup():
            return

        if self.username and self.message_limit is None:
            report_data = await self.process_nickname_search(self.username)
        else:
            report_data = await self.process_messages()

        self.write_json_report(report_data, file_name=SCAN_REPORT_FILENAME)
        self.save_complaint_cache()

        logging.info("Finished scanning. Disconnecting from Discord.")
        await self.close()

    async def setup(self) -> bool:
        logging.info("Setting up the bot...")
        if not self.login_to_admin_panel():
            await self.close()
            return False

        if self.username is None and self.message_limit is not None:
            if not self.fetch_target_channel():
                await self.close()
                return False

        if not self.fetch_complaint_channels():
            await self.close()
            return False

        self.load_complaint_cache()
        return True

    def login_to_admin_panel(self) -> bool:
        logging.info("Logging in to the admin panel...")
        if not self.admin_panel.login():
            logging.error("Could not log in to the admin site.")
            return False
        logging.info("Successfully logged in to the admin panel.")
        return True

    def fetch_target_channel(self) -> bool:
        logging.info(f"Fetching target channel with ID: {TARGET_CHANNEL_ID}")
        self.target_channel = self.get_channel(TARGET_CHANNEL_ID)
        if not self.target_channel:
            logging.error(f"Could not find the target channel with ID: {TARGET_CHANNEL_ID}")
            return False
        logging.info(f"Target channel found: '{self.target_channel.name}' ({TARGET_CHANNEL_ID})")
        return True

    def fetch_complaint_channels(self) -> bool:
        logging.info("Fetching complaint channels...")
        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel = self.get_channel(ch_id)
            if not channel:
                logging.warning(f"Could not find complaint channel with ID: {ch_id}")
                continue
            self.complaint_channels[ch_id] = channel
            logging.info(f"Complaint channel found: '{channel.name}' ({ch_id})")
        return True

    def load_complaint_cache(self) -> None:
        logging.info("Loading complaint message cache...")
        if not os.path.exists(COMPLAINT_CACHE_FILENAME):
            logging.info("Complaint message cache file not found.")
            return

        try:
            with open(COMPLAINT_CACHE_FILENAME, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            for ch_str_id, ch_data in raw_data.items():
                ch_id = int(ch_str_id)
                self.complaint_message_cache[ch_id] = {
                    "messages": ch_data.get("messages", []),
                    "last_cached_id": ch_data.get("last_cached_id", None)
                }
            logging.info(
                f"Loaded cache for {len(self.complaint_message_cache)} channel(s) "
                f"from '{COMPLAINT_CACHE_FILENAME}'."
            )
        except Exception as e:
            logging.error(f"Error loading complaint cache: {e}")

    def save_complaint_cache(self) -> None:
        logging.info("Saving complaint message cache...")
        cache_data: Dict[str, Any] = {}

        for ch_id, ch_cache in self.complaint_message_cache.items():
            saved_messages = []
            for msg in ch_cache["messages"]:
                saved_messages.append({
                    "id": msg['id'],
                    "content": msg['content'],
                    "embeds": [
                        {
                            k: embed_data[k]
                            for k in EMBED_FIELDS_TO_CACHE
                            if k in embed_data
                        }
                        for embed_data in msg.get('embeds', [])
                    ]
                })
            cache_data[str(ch_id)] = {
                "messages": saved_messages,
                "last_cached_id": ch_cache.get("last_cached_id")
            }

        try:
            with open(COMPLAINT_CACHE_FILENAME, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=4)
            logging.info(f"Saved complaint message cache to '{COMPLAINT_CACHE_FILENAME}'.")
        except IOError as e:
            logging.error(f"Error saving complaint cache: {e}")

    async def process_nickname_search(self, username: str) -> List[Dict[str, Any]]:
        logging.info(f"** Nickname-search mode ** Searching for nickname: {username}")

        base_link = (
            "https://admin.deadspace14.net/Connections"
            "?showSet=true&search={}&showAccepted=true&showBanned=true"
            "&showWhitelist=true&showFull=true&showPanic=true"
        )
        nickname_link = base_link.format(username)

        def try_check(link: str):
            try:
                return self.admin_panel.check_account_on_site(link)
            except Exception as e:
                logging.error(f"Error checking account on site for {link}: {e}")
                return {}

        # 1) Search by nickname
        single_result = try_check(nickname_link)
        if not single_result:
            return []

        results_to_merge = [single_result]
        last_ip = single_result.get("last_used_ip")
        if last_ip:
            ip_result = try_check(base_link.format(last_ip))
            if ip_result:
                results_to_merge.append(ip_result)

        last_hwid = single_result.get("last_used_hwid")
        if last_hwid:
            hwid_result = try_check(base_link.format(last_hwid))
            if hwid_result:
                results_to_merge.append(hwid_result)

        merged_player_results = self.admin_panel.aggregate_player_info(results_to_merge)
        if not merged_player_results:
            return []

        for player_res in merged_player_results:
            await self.enrich_player_results(player_res)

        message_info = {
            "message_id": "N/A",
            "message_link": "N/A",
            "author_name": f"NicknameSearch({username})",
            "author_id": "N/A",
            "results": merged_player_results
        }

        self.log_message_summary(message_info)
        return [message_info]

    async def process_messages(self) -> List[Dict[str, Any]]:
        if not self.target_channel:
            logging.warning("Target channel is not set. Cannot process messages.")
            return []

        logging.info(
            f"Checking last {self.message_limit} messages in "
            f"'{self.target_channel.name}' ({TARGET_CHANNEL_ID}) for embed links."
        )

        report_data: List[Dict[str, Any]] = []
        processed_message_ids = set()

        async for message in self.target_channel.history(
            limit=self.message_limit,
            oldest_first=False
        ):
            if message.id in processed_message_ids:
                continue
            processed_message_ids.add(message.id)

            if not message.embeds:
                continue

            message_info = await self.process_message(message)
            if message_info:
                report_data.append(message_info)
                self.log_message_summary(message_info)

        return report_data

    async def process_message(self, message: discord.Message) -> Optional[Dict[str, Any]]:
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

        merged_player_results = self.admin_panel.aggregate_player_info(partial_results_for_message)
        if not merged_player_results:
            return None

        message_info: Dict[str, Any] = {
            "message_id": str(message.id),
            "message_link": MESSAGE_LINK_FORMAT.format(message.guild.id, message.channel.id, message.id),
            "author_name": str(message.author),
            "author_id": str(message.author.id),
            "results": []
        }

        for player_res in merged_player_results:
            await self.enrich_player_results(player_res)
            message_info["results"].append(player_res)

        return message_info

    async def enrich_player_results(self, player_res: Dict[str, Any]) -> None:
        if not player_res.get("suspected_vpn") and player_res.get("nicknames"):
            all_complaint_links = await self.check_name_in_channels(player_res["nicknames"])
            player_res["complaint_links"] = list(set(all_complaint_links))
        else:
            player_res["complaint_links"] = []

    async def check_name_in_channels(self, nicknames: List[str]) -> List[str]:
        found_links: List[str] = []
        lower_nicknames = [n.lower() for n in nicknames]

        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel = self.complaint_channels.get(ch_id)
            if not channel:
                logging.warning(f"Could not find pre-fetched complaint channel with ID: {ch_id}")
                continue

            channel_cache = self.complaint_message_cache.get(ch_id, {"messages": [], "last_cached_id": None})
            cached_message_ids = {msg["id"] for msg in channel_cache["messages"]}
            last_cached_id = channel_cache["last_cached_id"]

            history_kwargs = {}
            if last_cached_id:
                history_kwargs["after"] = discord.Object(id=last_cached_id)
                history_kwargs["oldest_first"] = False
            else:
                history_kwargs["limit"] = COMPLAINT_MESSAGE_HISTORY_LIMIT
                history_kwargs["oldest_first"] = False

            new_messages = []
            try:
                async for msg in channel.history(**history_kwargs):
                    if msg.id not in cached_message_ids:
                        new_messages.append(msg)

                if new_messages:
                    logging.info(f"Fetched {len(new_messages)} new messages for channel {channel.name} ({ch_id}).")
                    for m in new_messages:
                        channel_cache["messages"].append({
                            "id": m.id,
                            "content": m.content,
                            "embeds": [
                                {
                                    k: e.to_dict()[k]
                                    for k in EMBED_FIELDS_TO_CACHE
                                    if k in e.to_dict()
                                }
                                for e in m.embeds
                            ]
                        })
                    channel_cache["messages"].sort(key=lambda x: x["id"], reverse=True)
                    max_new_id = max(m.id for m in new_messages)
                    if not last_cached_id or max_new_id > last_cached_id:
                        channel_cache["last_cached_id"] = max_new_id

                    channel_cache["messages"] = channel_cache["messages"][:COMPLAINT_MESSAGE_HISTORY_LIMIT]

                else:
                    logging.info(f"No new messages found in channel {channel.name} ({ch_id}). Using cached messages.")

                for cached_msg_data in channel_cache["messages"]:
                    content_lower = cached_msg_data['content'].lower()
                    if any(nick in content_lower for nick in lower_nicknames):
                        jump_link = MESSAGE_LINK_FORMAT.format(
                            channel.guild.id, channel.id, cached_msg_data['id']
                        )
                        found_links.append(jump_link)

                    for embed_data in cached_msg_data.get('embeds', []):
                        embed = discord.Embed.from_dict(embed_data)
                        if any(embed_contains_nickname(embed, nick) for nick in nicknames):
                            jump_link = MESSAGE_LINK_FORMAT.format(
                                channel.guild.id, channel.id, cached_msg_data['id']
                            )
                            found_links.append(jump_link)
                            break

            except discord.Forbidden:
                logging.warning(f"Could not read channel {channel.name} ({ch_id}). Insufficient permissions.")
            except discord.HTTPException as e:
                logging.error(f"Discord API error while reading channel {channel.name} ({ch_id}): {e}")
            except Exception as e:
                logging.error(f"Unexpected error reading channel {channel.name} ({ch_id}): {e}", exc_info=True)

            self.complaint_message_cache[ch_id] = channel_cache

        return found_links

    def get_player_verdict(self, status: str, shared_hwid: bool) -> str:
        if shared_hwid:
            return SUSPICIOUS_VERDICT
        if status == "banned":
            return BANNED_VERDICT
        if status == "clean":
            return CLEAN_VERDICT
        if status == "suspicious":
            return SUSPICIOUS_VERDICT
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
            shared_hwid = bool(result.get("shared_hwid_nicknames"))
            verdict = self.get_player_verdict(status, shared_hwid)

            shared_info = ""
            if result.get("shared_hwid_nicknames"):
                shared_names = NICKNAMES_FORMAT(result["shared_hwid_nicknames"])
                shared_info = SHARED_HWID_INFO_FORMAT.format(shared_names)

            complaint_links = result.get("complaint_links", [])
            if complaint_links:
                complaint_list = "\n".join(COMPLAINT_LINK_ITEM_FORMAT.format(link) for link in complaint_links)
                complaint_summary = COMPLAINT_LINKS_SUMMARY_FORMAT.format(complaint_list)
            else:
                complaint_summary = NO_COMPLAINTS_FOUND

            ban_reasons = result.get("ban_reasons", [])
            ban_reasons_str = BAN_REASONS_FORMAT(ban_reasons) if ban_reasons else NO_BAN_REASONS
            ban_counts = result.get("ban_counts", 0)

            logging.info(
                f"{idx}) Nicknames: {NICKNAMES_FORMAT(result.get('nicknames', [N_A]))}\n"
                f"   Status: {status} (Ban count: {ban_counts})\n"
                f"   Suspected VPN: {result.get('suspected_vpn', False)}\n"
                f"   Ban reasons: {ban_reasons_str}\n"
                f"   Verdict: {verdict}\n"
                f"   {shared_info}\n"
                f"   {complaint_summary}"
            )
        logging.info("=" * 60)

    def write_json_report(self, report_data: List[Dict[str, Any]], file_name: str = SCAN_REPORT_FILENAME) -> None:
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            logging.info(f"JSON report saved to '{file_name}' with {len(report_data)} message(s).")
        except IOError as e:
            logging.error(f"Could not write JSON report to '{file_name}': {e}")
