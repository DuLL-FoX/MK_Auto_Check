import asyncio
import functools
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from urllib.parse import quote_plus, unquote_plus

import discord

from admin_panel import AdminPanel
from config_backup_v2 import TARGET_CHANNEL_ID, COMPLAINT_CHANNEL_IDS, COMPLAINT_MESSAGE_HISTORY_LIMIT
from utils import embed_contains_nickname, collect_unique_links_from_embed, extract_effective_search_term

MESSAGE_LINK_FORMAT = "https://discord.com/channels/{}/{}/{}"
SCAN_REPORT_FILENAME = "scan_report_1.json"
COMPLAINT_CACHE_FILENAME = "complaint_message_cache.json"
SHARED_HWID_INFO_FORMAT = "Shared HWID with: {}"
COMPLAINT_LINKS_SUMMARY_FORMAT = "\n      Found in complaint messages:\n{}"
ASSOCIATED_IPS_FORMAT = "   Associated IPs:\n{}"
ASSOCIATED_HWIDS_FORMAT = "   Associated HWIDs:\n{}"
BAN_HIT_INFO_FORMAT = "   Ban Hit Match: {} ({})"
COMPLAINT_LINK_ITEM_FORMAT = "      - {}"
UNKNOWN_STATUS = "unknown"
BANNED_VERDICT = "BANNED"
CLEAN_VERDICT = "CLEAN"
SUSPICIOUS_VERDICT = "SUSPICIOUS"
POTENTIAL_BYPASS_VERDICT = "POTENTIAL BYPASS"
UNKNOWN_VERDICT = "UNKNOWN"
NO_BAN_REASONS = "None"
NO_COMPLAINTS_FOUND = "None"
NICKNAMES_FORMAT = ", ".join
BAN_REASONS_FORMAT = ", ".join
N_A = "N/A"
EMBED_FIELDS_TO_CACHE = ["title", "description", "fields"]
HWID_MATCH_CONFIDENCE = "100% (HWID Match)"
IP_TIME_MATCH_CONFIDENCE = "20-30% (IP + Time Match)"
NO_MATCH_CONFIDENCE = "No Match Found"
DEFAULT_BAN_BYPASS_PAGES = 5
IP_MATCH_TIMEDELTA_MINUTES = 30
SUSPICIOUS_TIMEDELTA_MINUTES = 60


class DiscordBot(discord.Client):
    def __init__(self, admin_panel: AdminPanel, message_limit: Optional[int] = 10, username: Optional[str] = None,
                 check_ban_bypass: bool = False, ban_bypass_pages: int = DEFAULT_BAN_BYPASS_PAGES, *args,
                 **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.admin_panel = admin_panel
        self.message_limit = message_limit
        self.username = username
        self.target_channel: Optional[discord.TextChannel] = None
        self.complaint_channels: Dict[int, discord.TextChannel] = {}
        self.complaint_message_cache: Dict[int, Dict[str, Any]] = {}
        self.check_ban_bypass = check_ban_bypass
        self.ban_bypass_pages = ban_bypass_pages
        self.hwid_cache: Dict[str, Dict[str, Any]] = {}
        self.ip_cache: Dict[str, Dict[str, Any]] = {}

        self.base_admin_connections_url = "https://admin.deadspace14.net/Connections?showSet=true&showAccepted=true&showBanned=true&showWhitelist=true&showFull=true&showPanic=true&perPage=2000"
        self.try_check_partial = functools.partial(self._try_check, base_link=self.base_admin_connections_url)


    async def on_ready(self) -> None:
        logging.info(f"Logged in as: {self.user} (ID: {self.user.id})")
        if not await self.setup():
            return

        report_data = []
        if self.check_ban_bypass:
            report_data = await self.process_ban_bypass_check()
        elif self.username:
            report_data = await self.process_nickname_search(self.username)
        elif self.message_limit is not None and self.target_channel:
            report_data = await self.process_messages()
        else:
            logging.warning("No scan type specified or missing parameters. Doing nothing.")

        self.write_json_report(report_data, SCAN_REPORT_FILENAME)
        self.save_complaint_cache()
        logging.info("Scan complete. Disconnecting from Discord.")
        await self.close()

    async def setup(self) -> bool:
        logging.info("Setting up the bot...")
        if not await self.login_to_admin_panel():
            return False
        if self.username is None and self.message_limit is not None and not self.fetch_target_channel():
            return False
        if not self.fetch_complaint_channels():
            return False
        self.load_complaint_cache()
        return True

    async def login_to_admin_panel(self) -> bool:
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
        self.complaint_channels = {}
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
                try:
                    ch_id = int(ch_str_id)
                    self.complaint_message_cache[ch_id] = {
                        "messages": [
                            {
                                "id": msg['id'],
                                "content": msg['content'],
                                "embeds": [
                                    {k: embed_data[k] for k in EMBED_FIELDS_TO_CACHE if k in embed_data}
                                    for embed_data in msg.get('embeds', [])
                                ]
                            }
                            for msg in ch_data.get("messages", [])
                        ],
                        "last_cached_id": ch_data.get("last_cached_id")
                    }
                except (ValueError, TypeError, KeyError) as e:
                    logging.warning(f"Error loading cache for channel ID {ch_str_id}: {e}. Skipping channel cache.")

            logging.info(f"Loaded cache for {len(self.complaint_message_cache)} channel(s).")
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error loading complaint cache: {e}. Cache file might be corrupted.")
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
                    for msg in ch_cache.get("messages", [])
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
        clean_username = quote_plus(unquote_plus(username))
        search_url = f"{self.base_admin_connections_url}&search={clean_username}"
        logging.info(f"Processing nickname search for: {username} with URL: {search_url}")

        initial_account_result = await asyncio.to_thread(self.try_check_partial, link=search_url, single_user=True)
        if not initial_account_result:
            logging.info(f"No account info found for nickname: {username}")
            return []

        player_result = {
            "initial_account": initial_account_result,
            "ip_nicks": {},
            "hwid_nicks": {},
            "nicknames": [username]
        }

        initial_ips = initial_account_result.get("associated_ips", {})
        initial_hwids = initial_account_result.get("associated_hwids", {})

        player_result["ip_nicks"] = await self._get_associated_nicks(initial_ips, 'ip')
        player_result["hwid_nicks"] = await self._get_associated_nicks(initial_hwids, 'hwid')

        merged_player_results = self.admin_panel.aggregate_player_info([player_result["initial_account"]])
        if merged_player_results:
            player_result["initial_account"].update(merged_player_results[0])
            complaint_links = await self.enrich_player_results(player_result["initial_account"].get("nicknames", []))
            player_result["complaint_links"] = complaint_links
            message_info = self._create_message_info(f"NicknameSearch({username})", "N/A", "N/A", [player_result])
            self.log_message_summary(message_info)
            return [message_info]
        else:
            logging.warning(f"No aggregated player info found for nickname: {username}")
            return []

    async def _get_associated_nicks(self, ids: Dict[str, Any], id_type: str) -> Dict[str, List[str]]:
        associated_nicks = {}
        for id_val in ids.keys():
            search_url = f"{self.base_admin_connections_url}&search={quote_plus(id_val)}"
            id_result = await asyncio.to_thread(self.try_check_partial, link=search_url, single_user=True)
            if id_result and "nicknames" in id_result:
                associated_nicks[id_val] = id_result["nicknames"]
        return associated_nicks


    def _try_check(self, link: str, base_link: str, single_user: bool):
        try:
            return self.admin_panel.check_account_on_site(link, single_user)
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
        async for message in self.target_channel.history(limit=self.message_limit, oldest_first=False):
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

            for term_url in unique_links_dict.values():
                effective_term = extract_effective_search_term(term_url)
                search_url = f"{self.base_admin_connections_url}&search={quote_plus(unquote_plus(effective_term))}"
                logging.info(
                    f"Processing initial search term: {effective_term} from message {message.id} with URL: {search_url}")

                initial_account_result = await asyncio.to_thread(self.try_check_partial, link=search_url,
                                                                 single_user=True)
                if not initial_account_result:
                    logging.warning(
                        f"No account info found for initial term: {effective_term} from message {message.id}")
                    continue

                player_result = {
                    "initial_account": initial_account_result,
                    "ip_nicks": {},
                    "hwid_nicks": {},
                    "nicknames": initial_account_result.get("nicknames", [])
                }

                initial_ips = initial_account_result.get("associated_ips", {})
                initial_hwids = initial_account_result.get("associated_hwids", {})

                player_result["ip_nicks"] = await self._get_associated_nicks(initial_ips, 'ip')
                player_result["hwid_nicks"] = await self._get_associated_nicks(initial_hwids, 'hwid')


                partial_results_for_message.append(player_result)

        if not partial_results_for_message:
            return None

        message_info = self._create_message_info(str(message.author), str(message.author.id),
                                                 MESSAGE_LINK_FORMAT.format(message.guild.id, message.channel.id,
                                                                            message.id), partial_results_for_message)

        for player_res in message_info["results"]:
            complaint_links = await self.enrich_player_results(player_res["initial_account"].get("nicknames", []))
            player_res["complaint_links"] = complaint_links

        return message_info

    def _create_message_info(self, author_name: str, author_id: str, message_link: str,
                             results: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "message_id": "N/A" if message_link == "N/A" else message_link.split('/')[-1],
            "message_link": message_link,
            "author_name": author_name,
            "author_id": author_id,
            "results": results
        }

    async def enrich_player_results(self, nicknames: List[str]) -> List[Dict[str, Any]]:
        if not nicknames:
            return []
        complaint_links = await self.check_name_in_channels(nicknames)
        return complaint_links


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
                    channel_cache["messages"].extend([{
                        "id": m.id,
                        "content": m.content,
                        "embeds": [
                            {k: e.to_dict()[k] for k in EMBED_FIELDS_TO_CACHE if k in e.to_dict()}
                            for e in m.embeds
                        ]
                    } for m in new_messages])

                    channel_cache["messages"].sort(key=lambda x: x["id"], reverse=True)
                    channel_cache["messages"] = channel_cache["messages"][:COMPLAINT_MESSAGE_HISTORY_LIMIT]
                    channel_cache["last_cached_id"] = channel_cache["messages"][0]["id"] if channel_cache[
                        "messages"] else last_cached_id

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

        unique_complaints = []
        seen_links: Set[str] = set()
        for complaint in found_complaints_info:
            if complaint["link"] not in seen_links:
                unique_complaints.append(complaint)
                seen_links.add(complaint["link"])
        return unique_complaints


    def get_player_verdict(self, result: Dict[str, Any]) -> str:
        confidence = result.get("ban_bypass_confidence", "")
        if confidence in (HWID_MATCH_CONFIDENCE, IP_TIME_MATCH_CONFIDENCE, "IP+Time Match (5-10 min)"):
            return f"{POTENTIAL_BYPASS_VERDICT} - {confidence}"
        if result.get("aggregated_account", {}).get("ban_counts", 0) >= 5:
            return f"{SUSPICIOUS_VERDICT} - multiple bans"
        status = result.get("aggregated_account", {}).get("status", "unknown")
        if status == "banned":
            return BANNED_VERDICT
        if status == "clean":
            return CLEAN_VERDICT
        if status == "suspicious":
            return SUSPICIOUS_VERDICT
        return UNKNOWN_VERDICT


    async def process_ban_bypass_check(self) -> List[Dict[str, Any]]:
        logging.info(f"Starting Ban Bypass Check, fetching max {self.ban_bypass_pages} pages of ban hits...")
        ban_hit_connections = await asyncio.to_thread(
            self.admin_panel.fetch_ban_hit_connections,
            max_pages=self.ban_bypass_pages
        )
        if not ban_hit_connections:
            logging.info("No ban hit connections found.")
            return []
        report_data = []
        for ban_hit in ban_hit_connections:
            try:
                ban_hit_time = datetime.strptime(ban_hit['time'], "%Y-%m-%d %H:%M:%S")
                user_id = ban_hit.get('user_id')
                if not user_id or user_id == N_A:
                    continue
                ban_hits_link = ban_hit.get("ban_hits_link")
                ban_info = await asyncio.to_thread(self.admin_panel.fetch_ban_info, ban_hits_link)
                banned_user_name = ban_info.get("banned_user_name") or ban_hit.get("user_name", "")
                user_id = ban_info.get("user_id") or user_id
                ip_address = ban_info.get("ip_address") or ban_hit.get("ip_address", "")
                hwid = ban_info.get("hwid") or ban_hit.get("hwid", "")

                ban_time_str = ban_info.get("ban_time", ban_hit['time'])
                ban_expires_str = ban_info.get("expires", ban_hit['time'])


                con_tasks = [
                    asyncio.to_thread(self.admin_panel.fetch_connections_for_user, user_id),
                    asyncio.to_thread(self.admin_panel.fetch_connections_for_user, hwid),
                    asyncio.to_thread(self.admin_panel.fetch_connections_for_user, ip_address)
                ]
                connections_results = await asyncio.gather(*con_tasks, return_exceptions=True)
                connections = []
                for res in connections_results:
                    if isinstance(res, BaseException):
                        logging.error(f"Error fetching connections: {res}", exc_info=res)
                    else:
                        connections.extend(res)

                account_info = self.admin_panel.aggregate_single_user_info(connections)

                bypass_reason = NO_MATCH_CONFIDENCE
                bypass_user_names = []

                if hwid != N_A and hwid in account_info.get("associated_hwids", {}):
                    hwid_nicks = account_info["associated_hwids"][hwid]
                    if len(set(hwid_nicks)) > 1:
                        bypass_reason = HWID_MATCH_CONFIDENCE
                        bypass_user_names = sorted(set(hwid_nicks) - {banned_user_name})

                if bypass_reason == NO_MATCH_CONFIDENCE and ip_address != N_A and ip_address in account_info.get(
                        "associated_ips", {}):
                    ip_nicks = account_info["associated_ips"][ip_address]
                    if len(set(ip_nicks)) > 1:
                        bypass_reason = IP_TIME_MATCH_CONFIDENCE
                        bypass_user_names = sorted(set(ip_nicks) - {banned_user_name})

                    time_suspected_users = self._check_time_based_bypass(ban_hit_time, ip_address, banned_user_name,
                                                                         connections)
                    if time_suspected_users:
                        bypass_reason = "IP+Time Match (5-10 min)"
                        bypass_user_names = sorted(set(bypass_user_names).union(set(time_suspected_users)))


                ban_hit_enriched = ban_hit.copy()
                ban_hit_enriched.update({
                    "connection_link": self.admin_panel.get_connections_url(user_id=user_id),
                    "ban_hit_link": ban_hits_link,
                    "ban_time": ban_time_str,
                    "ban_expires": ban_expires_str,
                    "aggregated_account": account_info,
                    "ban_bypass_confidence": bypass_reason,
                    "bypass_user_names": bypass_user_names,
                    "banned_user_name": banned_user_name,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "hwid": hwid,
                    "complaint_links": []
                })
                enriched_complaint_links = await self.enrich_player_results([ban_hit_enriched['banned_user_name']])
                ban_hit_enriched["complaint_links"] = enriched_complaint_links

                message_data = self._create_message_info("BanBypassCheck", "N/A",
                                                         ban_hit_enriched.get("ban_hit_link", "N/A"),
                                                         [ban_hit_enriched])
                report_data.append(message_data)
                self.log_message_summary(message_data)

            except Exception as e:
                logging.error(f"Error processing ban hit {ban_hit.get('ban_hits_link')}: {e}", exc_info=True)
        logging.info("Ban Bypass Check Complete.")
        return report_data

    def _check_time_based_bypass(self, ban_hit_time: datetime, ip_address: str, banned_user_name: str,
                                 connections: List[Dict]) -> List[str]:
        time_suspected_users = []
        if ip_address != N_A:
            try:
                ban_hit_dt = ban_hit_time
                for conn in connections:
                    if conn.get("ip_address") == ip_address and conn.get("user_name") != banned_user_name:
                        conn_dt = datetime.strptime(conn["time"], "%Y-%m-%d %H:%M:%S")
                        diff_minutes = abs((conn_dt - ban_hit_dt).total_seconds() / 60.0)
                        if 5 <= diff_minutes <= 10:
                            time_suspected_users.append(conn.get("user_name"))
            except Exception as ex:
                logging.error(f"Error processing time difference for ban hit : {ex}", exc_info=True)
        return time_suspected_users


    def log_message_summary(self, message_info: Dict[str, Any]) -> None:
        results = message_info["results"]
        logging.info("=" * 60)
        log_header = f"Message ID {message_info['message_id']} by {message_info['author_name']} had {len(results)} result(s)."
        if message_info['message_link'] != "N/A":
            log_header += f" Message link: {message_info['message_link']}"
        logging.info(log_header)

        for idx, result_data in enumerate(results, start=1):
            result = result_data.get('initial_account', {})
            verdict = self.get_player_verdict(result)
            shared_info = ""
            if result.get("shared_hwid_nicknames"):
                shared_names = ", ".join(sorted(result["shared_hwid_nicknames"]))
                shared_info = SHARED_HWID_INFO_FORMAT.format(shared_names)

            ip_nicks_to_display = result_data.get("ip_nicks", {})
            ip_summary = (ASSOCIATED_IPS_FORMAT.format("\n".join(
                [f"      - {ip}: {', '.join(sorted(nicks))}" for ip, nicks in sorted(ip_nicks_to_display.items())]
            )) if ip_nicks_to_display else "      No associated IPs found.")

            hwid_nicks_to_display = result_data.get("hwid_nicks", {})
            hwid_summary = (ASSOCIATED_HWIDS_FORMAT.format("\n".join(
                [f"      - {hwid}: {', '.join(sorted(nicks))}" for hwid, nicks in sorted(hwid_nicks_to_display.items())]
            )) if hwid_nicks_to_display else "      No associated HWIDs found.")

            complaint_info = result_data.get("complaint_links", [])
            complaint_summary = (COMPLAINT_LINKS_SUMMARY_FORMAT.format("\n".join(
                [COMPLAINT_LINK_ITEM_FORMAT.format(f"{complaint['link']} - {', '.join(sorted(complaint['nicknames']))}")
                 for complaint in complaint_info]
            )) if complaint_info else NO_COMPLAINTS_FOUND)

            ban_reasons = result.get("ban_reasons", [])
            ban_reasons_str = ", ".join(ban_reasons) if ban_reasons else NO_BAN_REASONS
            ban_counts = result.get("ban_counts", 0)
            connection_link = result.get("connection_link", "N/A")

            if "ban_hit_link" in result_data:
                ban_time = result_data.get("ban_time", "N/A")
                ban_expires = result_data.get("ban_expires", "N/A")
                banned_user = result_data.get('banned_user_name', N_A)
                bypass_users = ", ".join(sorted(result_data.get('bypass_user_names', [N_A])))

                log_output = f"""{idx}) Banned User: {banned_user}
   Ban Time: {ban_time}   Expires: {ban_expires}
   Status: {result.get('status', UNKNOWN_STATUS)} (Bans: {ban_counts})
   Suspected VPN: {result.get('suspected_vpn', False)}
   Ban reasons: {ban_reasons_str}
   Verdict: {verdict}
   Connection Link: {connection_link}
   Ban Hit Link: {result_data.get('ban_hit_link')}
   IP: {result_data.get('ip_address', 'N/A')}
   HWID: {result_data.get('hwid', 'N/A')}
   Potential Bypassers: {bypass_users}
   {shared_info}
   {ip_summary}
   {hwid_summary}
   Complaint Links: {complaint_summary}"""
            else:
                log_output = f"""{idx}) Searched Nickname: {message_info['author_name']}
   Status: {result.get('status', UNKNOWN_STATUS)} (Bans: {ban_counts})
   Suspected VPN: {result.get('suspected_vpn', False)}
   Ban reasons: {ban_reasons_str}
   Verdict: {verdict}
   Connection Link: {connection_link}
   {shared_info}
   {ip_summary}
   {hwid_summary}
   Complaint Links: {complaint_summary}"""

            logging.info(log_output.strip())

        logging.info("=" * 60)

    def write_json_report(self, report_data: List[Dict[str, Any]], file_name: str = SCAN_REPORT_FILENAME) -> None:
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            logging.info(f"JSON report saved to '{file_name}' with {len(report_data)} message(s).")
        except IOError as e:
            logging.error(f"Could not write JSON report to '{file_name}': {e}")