import asyncio
import functools
import json
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus

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

SHARED_HWID_INFO_FORMAT = "Shared HWID with: {}"
COMPLAINT_LINKS_SUMMARY_FORMAT = "\n      Found in complaint messages:\n{}"
ASSOCIATED_IPS_FORMAT = "   Associated IPs:\n{}"
ASSOCIATED_HWIDS_FORMAT = "   Associated HWIDs:\n{}"
BAN_HIT_INFO_FORMAT = "   Ban Hit Match: {}"
COMPLAINT_LINK_ITEM_FORMAT = "      - {}"
UNKNOWN_STATUS = "unknown"
BANNED_VERDICT = "POSSIBLE BYPASS / BANNED"
CLEAN_VERDICT = "CLEAN / NO BYPASS"
SUSPICIOUS_VERDICT = "SUSPICIOUS / SHARED HWID - MANUAL CHECK REQUIRED"
POTENTIAL_BYPASS_VERDICT = "POTENTIAL BAN BYPASS - CHECK HWID/IP + TIME"
UNKNOWN_VERDICT = "UNKNOWN / NEED MANUAL CHECK"
NO_BAN_REASONS = "None"
NO_COMPLAINTS_FOUND = "None found"
NICKNAMES_FORMAT = ", ".join
BAN_REASONS_FORMAT = ", ".join
N_A = "N/A"
EMBED_FIELDS_TO_CACHE = ["title", "description", "fields"]
HWID_MATCH_CONFIDENCE = "100% (HWID Match)"
IP_TIME_MATCH_CONFIDENCE = "20-30% (IP + Time Match)"
NO_MATCH_CONFIDENCE = "No Match Found"
DEFAULT_BAN_BYPASS_PAGES = 5


class DiscordBot(discord.Client):
    def __init__(
        self,
        admin_panel: AdminPanel,
        message_limit: Optional[int] = 10,
        username: Optional[str] = None,
            check_ban_bypass: bool = False,
            ban_bypass_pages: int = DEFAULT_BAN_BYPASS_PAGES,
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.admin_panel = admin_panel
        self.message_limit = message_limit
        self.username = username
        self.target_channel: Optional[discord.TextChannel] = None
        self.complaint_channels: Dict[int, discord.TextChannel] = {}
        self.complaint_message_cache: Dict[int, Dict[str, Any]] = {}
        self.check_ban_bypass = check_ban_bypass
        self.ban_bypass_pages = ban_bypass_pages


    async def on_ready(self) -> None:
        logging.info(f"Logged in as: {self.user} (ID: {self.user.id})")
        if not await self.setup():
            return

        report_data = []
        if self.check_ban_bypass:
            report_data = await self.process_ban_bypass_check()
        elif self.username and self.message_limit is None:
            report_data = await self.process_nickname_search(self.username)
        else:
            report_data = await self.process_messages()


        self.write_json_report(report_data, SCAN_REPORT_FILENAME)
        self.save_complaint_cache()

        logging.info("Scan complete. Disconnecting from Discord.")
        await self.close()

    async def setup(self) -> bool:
        logging.info("Setting up the bot...")
        if not self.login_to_admin_panel():
            await self.close()
            return False

        if self.username is None and self.message_limit is not None and not self.fetch_target_channel():
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
        logging.info("Logged in to the admin panel.")
        return True

    def fetch_target_channel(self) -> bool:
        logging.info(f"Fetching target channel with ID: {TARGET_CHANNEL_ID}")
        self.target_channel = self.get_channel(TARGET_CHANNEL_ID)
        if not self.target_channel:
            logging.error(f"Could not find target channel: {TARGET_CHANNEL_ID}")
            return False
        logging.info(f"Target channel found: '{self.target_channel.name}' ({TARGET_CHANNEL_ID})")
        return True

    def fetch_complaint_channels(self) -> bool:
        logging.info("Fetching complaint channels...")
        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel = self.get_channel(ch_id)
            if not channel:
                logging.warning(f"Could not find complaint channel: {ch_id}")
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
                self.complaint_message_cache[ch_id] = ch_data
            logging.info(f"Loaded cache for {len(self.complaint_message_cache)} channel(s).")
        except Exception as e:
            logging.error(f"Error loading complaint cache: {e}")

    def save_complaint_cache(self) -> None:
        logging.info("Saving complaint message cache...")
        cache_data = {
            str(ch_id): {
                "messages": [
                    {
                        "id": msg['id'],
                        "content": msg['content'],
                        "embeds": [
                            {k: embed_data[k] for k in EMBED_FIELDS_TO_CACHE if k in embed_data}
                            for embed_data in msg.get('embeds', [])
                        ]
                    }
                    for msg in ch_cache["messages"]
                ],
                "last_cached_id": ch_cache.get("last_cached_id")
            }
            for ch_id, ch_cache in self.complaint_message_cache.items()
        }

        try:
            with open(COMPLAINT_CACHE_FILENAME, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=4)
            logging.info(f"Saved complaint message cache to '{COMPLAINT_CACHE_FILENAME}'.")
        except IOError as e:
            logging.error(f"Error saving complaint cache: {e}")

    async def process_nickname_search(self, username: str) -> List[Dict[str, Any]]:
        logging.info(f"Searching for nickname: {username}")

        base_link = "https://admin.deadspace14.net/Connections?showSet=true&search={}&showAccepted=true&showBanned=true&showWhitelist=true&showFull=true&showPanic=true&perPage=2000"
        nickname_link = base_link.format(username)
        try_check_partial = functools.partial(self._try_check, base_link=base_link)

        single_result = await asyncio.to_thread(try_check_partial, link=nickname_link)
        if not single_result:
            return []

        results_to_merge = [single_result]
        processed_ips = set()
        processed_hwids = set()
        check_tasks = []

        for ip in single_result.get("associated_ips", set()):
            if ip and ip not in processed_ips:
                check_tasks.append(asyncio.to_thread(try_check_partial, link=base_link.format(quote_plus(ip))))
                processed_ips.add(ip)

        for hwid in single_result.get("associated_hwids", set()):
            if hwid and hwid not in processed_hwids:
                check_tasks.append(asyncio.to_thread(try_check_partial, link=base_link.format(quote_plus(hwid))))
                processed_hwids.add(hwid)

        concurrent_results = await asyncio.gather(*check_tasks)

        for res in concurrent_results:
            if res:
                results_to_merge.append(res)

        merged_player_results = self.admin_panel.aggregate_player_info(results_to_merge)
        if not merged_player_results:
            return []

        final_results = merged_player_results[:1]
        for player_res in final_results:
            player_res.setdefault("nicknames", [username])
            await self.enrich_player_results(player_res)

        message_info = {
            "message_id": "N/A",
            "message_link": "N/A",
            "author_name": f"NicknameSearch({username})",
            "author_id": "N/A",
            "results": final_results
        }

        self.log_message_summary(message_info)
        return [message_info]

    def _try_check(self, link: str, base_link: str):
        try:
            return self.admin_panel.check_account_on_site(link)
        except Exception as e:
            logging.error(f"Error checking account on site for {link}: {e}")
            return {}

    async def process_messages(self) -> List[Dict[str, Any]]:
        if not self.target_channel:
            logging.warning("Target channel is not set. Cannot process messages.")
            return []

        logging.info(f"Checking last {self.message_limit} messages in '{self.target_channel.name}' ({TARGET_CHANNEL_ID}) for embed links.")

        report_data = []
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
        partial_results_for_message = []

        for embed in message.embeds:
            unique_links_dict = collect_unique_links_from_embed(embed)
            if not unique_links_dict:
                continue

            check_tasks = [asyncio.to_thread(self.admin_panel.check_account_on_site, link) for link in unique_links_dict.values()]
            concurrent_results = await asyncio.gather(*check_tasks, return_exceptions=True)

            for res in concurrent_results:
                if isinstance(res, Exception):
                    logging.error(f"Error checking account on admin site: {res}")
                elif res:
                    partial_results_for_message.append(res)

        merged_player_results = self.admin_panel.aggregate_player_info(partial_results_for_message)
        if not merged_player_results:
            return None

        message_info = {
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
            all_complaint_info = await self.check_name_in_channels(player_res["nicknames"])
            player_res["complaint_links"] = all_complaint_info
        else:
            player_res["complaint_links"] = []

    async def check_name_in_channels(self, nicknames: List[str]) -> List[Dict[str, Any]]:
        found_complaints_info = []
        lower_nicknames = [n.lower() for n in nicknames]

        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel_complaint_info = []

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
                                {k: e.to_dict()[k] for k in EMBED_FIELDS_TO_CACHE if k in e.to_dict()}
                                for e in m.embeds
                            ]
                        })
                    channel_cache["messages"].sort(key=lambda x: x["id"], reverse=True)
                    max_new_id = max(m.id for m in new_messages) if new_messages else last_cached_id
                    if not last_cached_id or (max_new_id and max_new_id > last_cached_id):
                        channel_cache["last_cached_id"] = max_new_id

                    channel_cache["messages"] = channel_cache["messages"][:COMPLAINT_MESSAGE_HISTORY_LIMIT]

                else:
                    logging.info(f"No new messages found in channel {channel.name} ({ch_id}). Using cached messages.")

                for cached_msg_data in channel_cache["messages"]:
                    content_lower = cached_msg_data['content'].lower()
                    found_nicks_in_content = [original_nick for original_nick, lower_nick in zip(nicknames, lower_nicknames) if lower_nick in content_lower]

                    if found_nicks_in_content:
                        jump_link = MESSAGE_LINK_FORMAT.format(channel.guild.id, channel.id, cached_msg_data['id'])
                        channel_complaint_info.append({"link": jump_link, "nicknames": found_nicks_in_content})

                    for embed_data in cached_msg_data.get('embeds', []):
                        embed = discord.Embed.from_dict(embed_data)
                        found_nicks_in_embed = [original_nick for original_nick in nicknames if embed_contains_nickname(embed, original_nick)]

                        if found_nicks_in_embed:
                            jump_link = MESSAGE_LINK_FORMAT.format(channel.guild.id, channel.id, cached_msg_data['id'])
                            channel_complaint_info.append({"link": jump_link, "nicknames": found_nicks_in_embed})
                            break

            except discord.Forbidden:
                logging.warning(f"Could not read channel {channel.name} ({ch_id}). Insufficient permissions.")
            except discord.HTTPException as e:
                logging.error(f"Discord API error reading channel {channel.name} ({ch_id}): {e}")
            except Exception as e:
                logging.error(f"Unexpected error reading channel {channel.name} ({ch_id}): {e}", exc_info=True)
            self.complaint_message_cache[ch_id] = channel_cache
            found_complaints_info.extend(channel_complaint_info)

        return found_complaints_info

    def get_player_verdict(self, status: str, shared_hwid: bool, ban_bypass_confidence: str) -> str:
        if ban_bypass_confidence == HWID_MATCH_CONFIDENCE or ban_bypass_confidence == IP_TIME_MATCH_CONFIDENCE:
            return POTENTIAL_BYPASS_VERDICT
        if shared_hwid:
            return SUSPICIOUS_VERDICT
        if status == "banned":
            return BANNED_VERDICT
        if status == "clean":
            return CLEAN_VERDICT
        if status == "suspicious":
            return SUSPICIOUS_VERDICT
        return UNKNOWN_VERDICT

    async def process_ban_bypass_check(self) -> List[Dict[str, Any]]:
        logging.info(f"Starting Ban Bypass Check, fetching max {self.ban_bypass_pages} pages of ban hits...")
        ban_hit_connections = await asyncio.to_thread(self.admin_panel.fetch_ban_hit_connections,
                                                      max_pages=self.ban_bypass_pages)
        if not ban_hit_connections:
            logging.info("No ban hit connections found.")
            return []

        report_data = []
        processed_hwids = set()
        processed_ips = set()

        for ban_hit in ban_hit_connections:
            logging.info(
                f"Processing ban hit for user: {ban_hit.get('user_name')}, connection link: {ban_hit.get('ban_hits_link')}")

            ban_hit_time = datetime.strptime(ban_hit['time'], "%Y-%m-%d %H:%M:%S")

            bypass_reason = NO_MATCH_CONFIDENCE

            if ban_hit['hwid'] and ban_hit['hwid'] != N_A and ban_hit['hwid'] not in processed_hwids:
                hwid_search_link = f"{self.admin_panel.CONNECTIONS_URL}?showSet=true&search={quote_plus(ban_hit['hwid'])}&showAccepted=true&showBanned=false&showWhitelist=false&showFull=false&showPanic=false"
                hwid_connections_result = await asyncio.to_thread(self.admin_panel.check_account_on_site,
                                                                  hwid_search_link)
                if hwid_connections_result and hwid_connections_result['status'] == 'clean':
                    bypass_reason = HWID_MATCH_CONFIDENCE
                    processed_hwids.add(ban_hit['hwid'])

            if bypass_reason == NO_MATCH_CONFIDENCE and ban_hit['ip_address'] and ban_hit['ip_address'] != N_A and \
                    ban_hit['ip_address'] not in processed_ips:
                ip_search_link = f"{self.admin_panel.CONNECTIONS_URL}?showSet=true&search={quote_plus(ban_hit['ip_address'])}&showAccepted=true&showBanned=false&showWhitelist=false&showFull=false&showPanic=false"
                ip_connections_result = await asyncio.to_thread(self.admin_panel.check_account_on_site, ip_search_link)

                if ip_connections_result and ip_connections_result['status'] == 'clean':
                    for recent_connection_time_str in [row['time'] for row in
                                                       ip_connections_result.get('raw_html_snippet', '')]:
                        try:
                            recent_connection_time = datetime.strptime(recent_connection_time_str, "%Y-%m-%d %H:%M:%S")
                            time_difference = abs(ban_hit_time - recent_connection_time)
                            if time_difference <= timedelta(minutes=10):
                                bypass_reason = IP_TIME_MATCH_CONFIDENCE
                                break
                        except ValueError:
                            continue

                    if bypass_reason == IP_TIME_MATCH_CONFIDENCE:
                        processed_ips.add(ban_hit['ip_address'])

            ban_hit_enriched = ban_hit.copy()
            ban_hit_enriched['ban_bypass_confidence'] = bypass_reason
            await self.enrich_player_results(ban_hit_enriched)
            report_data.append({
                "message_id": "N/A",
                "message_link": ban_hit['ban_hits_link'] if ban_hit['ban_hits_link'] else "N/A",
                "author_name": "BanBypassCheck",
                "author_id": "N/A",
                "results": [ban_hit_enriched]
            })
            self.log_message_summary(report_data[-1])

        logging.info("Ban Bypass Check Complete.")
        return report_data


    def log_message_summary(self, message_info: Dict[str, Any]) -> None:
        results = message_info["results"]
        logging.info("=" * 60)
        logging.info(f"Message ID {message_info['message_id']} by {message_info['author_name']} had {len(results)} result(s).")
        logging.info(f"Message link: {message_info['message_link']}")

        for idx, result in enumerate(results, start=1):
            status = result.get("status", UNKNOWN_STATUS)
            shared_hwid = bool(result.get("shared_hwid_nicknames"))
            ban_bypass_confidence = result.get("ban_bypass_confidence", NO_MATCH_CONFIDENCE)
            verdict = self.get_player_verdict(status, shared_hwid, ban_bypass_confidence)


            shared_info = ""
            if result.get("shared_hwid_nicknames"):
                shared_names = NICKNAMES_FORMAT(sorted(result["shared_hwid_nicknames"]))
                shared_info = SHARED_HWID_INFO_FORMAT.format(shared_names)

            associated_ips = result.get("associated_ips", {})
            ip_summary = ASSOCIATED_IPS_FORMAT.format("\n".join(
                [f"      - {ip}: {NICKNAMES_FORMAT(sorted(nicknames))}" for ip, nicknames in
                 sorted(associated_ips.items())])) if associated_ips else "      No associated IPs found."

            associated_hwids = result.get("associated_hwids", {})
            hwid_summary = ASSOCIATED_HWIDS_FORMAT.format("\n".join(
                [f"      - {hwid}: {NICKNAMES_FORMAT(sorted(nicknames))}" for hwid, nicknames in
                 sorted(associated_hwids.items())])) if associated_hwids else "      No associated HWIDs found."
            ban_hit_info = ""
            if ban_bypass_confidence != NO_MATCH_CONFIDENCE:
                ban_hit_info = BAN_HIT_INFO_FORMAT.format(ban_bypass_confidence)

            complaint_info = result.get("complaint_links", [])
            complaint_summary = COMPLAINT_LINKS_SUMMARY_FORMAT.format("\n".join([COMPLAINT_LINK_ITEM_FORMAT.format(f"{complaint['link']} - {NICKNAMES_FORMAT(sorted(complaint['nicknames']))}") for complaint in complaint_info])) if complaint_info else NO_COMPLAINTS_FOUND

            ban_reasons = result.get("ban_reasons", [])
            ban_reasons_str = BAN_REASONS_FORMAT(ban_reasons) if ban_reasons else NO_BAN_REASONS
            ban_counts = result.get("ban_counts", 0)

            logging.info(
                f"{idx}) Nicknames: {NICKNAMES_FORMAT(sorted(result.get('nicknames', [N_A])))}\n"
                f"   Status: {status} (Bans: {ban_counts})\n"
                f"   Suspected VPN: {result.get('suspected_vpn', False)}\n"
                f"   Ban reasons: {ban_reasons_str}\n"
                f"   Verdict: {verdict}\n"
                f"   {ban_hit_info}\n"
                f"   {shared_info}\n"
                f"   {ip_summary}\n"
                f"   {hwid_summary}\n"
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