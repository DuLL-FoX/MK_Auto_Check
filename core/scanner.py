import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict

from core.analyzer import PlayerAnalyzer
from models.ban_hit import BanBypassCheck
from models.complaint import ComplaintChannel
from models.message import DiscordMessage, ScanResult
from models.player import Player
from models.verdict import ConfidenceLevel
from services.admin_service import AdminService
from services.cache_service import CacheService
from services.discord_service import DiscordService
from services.report_service import ReportService
from utils.async_utils import gather_with_concurrency
from utils.url_utils import extract_effective_search_term

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, discord_service: DiscordService, admin_service: AdminService, cache_service: CacheService,
                 report_service: ReportService, player_analyzer: PlayerAnalyzer) -> None:
        self.discord_service = discord_service
        self.admin_service = admin_service
        self.admin_panel = admin_service.admin_panel
        self.cache_service = cache_service
        self.report_service = report_service
        self.player_analyzer = player_analyzer
        self.complaint_channels: Dict[int, ComplaintChannel] = {}
        self.searched_terms: Set[str] = set()
        self.term_results: Dict[str, Dict[str, Any]] = {}
        self.max_concurrent_requests = 15
        self.connection_cache = {}
        self._create_loggers()

    def _create_loggers(self):
        self.logger = logger
        self.perf_logger = logging.getLogger(f"{__name__}.performance")
        if not self.perf_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.perf_logger.addHandler(handler)
            self.perf_logger.setLevel(logging.INFO)

    async def setup(self, target_channel_id: int, complaint_channel_ids: List[int]) -> bool:
        self.logger.info("Setting up scanner...")
        self.searched_terms = set()
        self.term_results = {}
        if not await self.discord_service.setup_channels(target_channel_id, complaint_channel_ids):
            return False
        if not await self.admin_service.login():
            self.logger.error("Failed to log in to the admin panel")
            return False
        self.complaint_channels = self.cache_service.load_complaint_cache()
        self.logger.debug("Scanner setup complete")
        return True

    async def scan_messages(self, message_limit: int) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting message scan with limit {message_limit}")
        self.complaint_channels = await self.discord_service.update_complaint_cache(self.complaint_channels,
                                                                                    history_limit=2000)
        messages = await self.discord_service.scan_target_channel(
            message_limit,
            lambda m: any(embed.title == 'Arrived new player' for embed in m.embeds)
        )
        if not messages:
            self.logger.info("No matching messages found")
            return []
        self.logger.info(f"Found {len(messages)} messages to process")
        tasks = [self.process_message(message) for message in messages]
        results = await gather_with_concurrency(self.max_concurrent_requests, *tasks)
        scan_results = [result for result in results if result]
        report_data = self.report_service.generate_message_scan_report(scan_results)
        self.cache_service.save_complaint_cache(self.complaint_channels)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.perf_logger.info(
            f"Message scan completed in {duration:.2f}s: processed {len(messages)} messages, found {len(scan_results)} results")
        return report_data

    async def process_message(self, message: DiscordMessage) -> Optional[ScanResult]:
        message_id = message.id
        if 'Arrived new player' not in message.embed_titles:
            return None
        unique_links = message.embed_links
        if not unique_links:
            return None
        self.logger.debug(f"Processing message {message_id} with {len(unique_links)} links")
        processed_terms = set()
        unique_terms = []
        for term_type, term_url in unique_links.items():
            effective_term = extract_effective_search_term(term_url)
            if effective_term and effective_term not in processed_terms:
                processed_terms.add(effective_term)
                unique_terms.append(effective_term)
        if not unique_terms:
            return None
        tasks = [self.process_term(term) for term in unique_terms]
        players_results = await asyncio.gather(*tasks)
        players = [player for player in players_results if player]
        if not players:
            return None
        grouped_players = self.player_analyzer.group_players_by_nicknames(players)
        complaint_tasks = [self.discord_service.find_nickname_mentions(player.nicknames, self.complaint_channels)
                           for player in grouped_players]
        complaint_results = await asyncio.gather(*complaint_tasks)
        for player, complaint_links in zip(grouped_players, complaint_results):
            player.complaint_links = complaint_links
        self.logger.debug(f"Completed processing message {message_id}, found {len(grouped_players)} players")
        return ScanResult(message=message, players=grouped_players, scan_time=datetime.now())

    async def process_term(self, term: str) -> Optional[Player]:
        """
        Process a search term to find player information and associated data.
        Ensures all first-order data (direct connections) is thoroughly gathered and processed.
        """
        if term in self.searched_terms:
            if term in self.term_results:
                return self.admin_service.convert_to_player(self.term_results[term])
            return None
        self.searched_terms.add(term)
        term_start_time = datetime.now()
        account_info = await self.admin_service.search_player(term)
        if not account_info:
            return None
        associated_accounts = await self.fetch_new_associated_players(account_info)
        all_accounts = [account_info] + associated_accounts
        aggregated = self.admin_panel.aggregate_player_info(all_accounts)
        if not aggregated:
            self.logger.warning(f"No aggregated player info found for term: {term}")
            return None
        self.term_results[term] = aggregated[0]
        player = self.admin_service.convert_to_player(aggregated[0])
        identifiers = []
        if player.user_id and player.user_id != "N/A":
            identifiers.append(player.user_id)
        for nickname in player.nicknames:
            identifiers.append(nickname)
        if hasattr(player, 'associated_ips') and player.associated_ips:
            for ip in player.associated_ips:
                if ip != "N/A":
                    identifiers.append(ip)
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            for hwid in player.associated_hwids:
                if hwid != "N/A":
                    identifiers.append(hwid)
        unique_identifiers = list(set(id for id in identifiers if id))
        connections = []
        if unique_identifiers:
            max_identifiers = min(10, len(unique_identifiers))
            selected_identifiers = unique_identifiers[:max_identifiers]
            connection_tasks = [
                self.admin_service.fetch_with_rate_limit(self.admin_panel.fetch_connections_for_user, identifier)
                for identifier in selected_identifiers]
            connections_results = await asyncio.gather(*connection_tasks)
            for result in connections_results:
                connections.extend(result)
        nickname_connections = defaultdict(list)
        for conn in connections:
            user_name = conn.get("user_name", "")
            if user_name:
                nickname_connections[user_name].append(conn)
        denied_logins = []
        for conn in connections:
            if "Denied: Banned" in conn.get("status", ""):
                user_name = conn.get("user_name", "")
                denied_logins.append({
                    "user_name": user_name,
                    "time": conn.get("time", ""),
                    "ip_address": conn.get("ip_address", ""),
                    "hwid": conn.get("hwid", ""),
                    "server": conn.get("server", "")
                })
        player.denied_logins = denied_logins
        if denied_logins and player.status not in ["banned", "suspicious"]:
            player.status = "suspicious"
            player.ban_counts = max(player.ban_counts, 1)
        if hasattr(player, 'associated_ips'):
            for ip, nicknames in player.associated_ips.items():
                for conn in connections:
                    if conn.get("ip_address") == ip:
                        user_name = conn.get("user_name")
                        if user_name and user_name not in nicknames:
                            nicknames.append(user_name)
        if hasattr(player, 'associated_hwids'):
            for hwid, nicknames in player.associated_hwids.items():
                for conn in connections:
                    if conn.get("hwid") == hwid:
                        user_name = conn.get("user_name")
                        if user_name and user_name not in nicknames:
                            nicknames.append(user_name)
        processing_time = (datetime.now() - term_start_time).total_seconds()
        self.perf_logger.debug(f"Term '{term}' processed in {processing_time:.3f}s, status: {player.status}")
        return player

    async def fetch_new_associated_players(self, player_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        unique_search_terms = set()
        for ip in player_info.get("associated_ips", {}):
            if ip not in self.searched_terms and ip != "N/A":
                unique_search_terms.add(ip)
                self.searched_terms.add(ip)
        for hwid in player_info.get("associated_hwids", {}):
            if hwid not in self.searched_terms and hwid != "N/A":
                unique_search_terms.add(hwid)
                self.searched_terms.add(hwid)
        if not unique_search_terms:
            return []
        limited_terms = list(unique_search_terms)[:10]
        results = await gather_with_concurrency(
            self.max_concurrent_requests,
            *[self.admin_service.search_player(term) for term in limited_terms]
        )
        valid_results = [r for r in results if r]
        return valid_results

    async def scan_nickname(self, nickname: str) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting nickname search for: {nickname}")
        self.complaint_channels = await self.discord_service.update_complaint_cache(self.complaint_channels,
                                                                                    history_limit=2000)
        player = await self.process_term(nickname)
        if not player:
            self.logger.info(f"No player found for nickname: {nickname}")
            return []
        complaint_links = await self.discord_service.find_nickname_mentions(player.nicknames, self.complaint_channels)
        player.complaint_links = complaint_links
        report_data = self.report_service.generate_nickname_search_report(nickname, player)
        self.cache_service.save_complaint_cache(self.complaint_channels)
        duration = (datetime.now() - start_time).total_seconds()
        self.perf_logger.info(f"Nickname search for '{nickname}' completed in {duration:.2f}s")
        return report_data

    async def check_ban_bypasses_raw(self, max_pages: int = 5) -> List[BanBypassCheck]:
        start_time = datetime.now()
        self.logger.info(f"Starting ban bypass check (max {max_pages} pages)")
        connection_cache = {}
        ban_info_cache = {}
        identity_graph = defaultdict(set)
        cache_stats = {
            "connection_hits": 0,
            "connection_misses": 0,
            "ban_info_hits": 0,
            "ban_info_misses": 0
        }
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        complaint_task = asyncio.create_task(
            self.discord_service.update_complaint_cache(self.complaint_channels, history_limit=2000))
        ban_hits_task = asyncio.create_task(self.admin_service.fetch_ban_hits(max_pages))
        await asyncio.wait([complaint_task, ban_hits_task])
        self.complaint_channels = complaint_task.result()
        ban_hits = ban_hits_task.result()
        if not ban_hits:
            self.logger.info("No ban hits found")
            self.cache_service.save_complaint_cache(self.complaint_channels)
            return []
        unique_ban_hits = {}
        for hit in ban_hits:
            hit_key = f"{hit.user_id}|{hit.user_name}|{hit.ip_address}|{hit.hwid}"
            if hit_key not in unique_ban_hits:
                unique_ban_hits[hit_key] = hit
        unique_ban_hits_list = list(unique_ban_hits.values())
        self.logger.info(f"Processing {len(unique_ban_hits_list)} unique ban hits (from {len(ban_hits)} total)")
        all_user_ids = {hit.user_id for hit in unique_ban_hits_list if hit.user_id != "N/A"}
        all_hwids = {hit.hwid for hit in unique_ban_hits_list if hit.hwid != "N/A" and not hit.hwid_erased}
        all_ips = {hit.ip_address for hit in unique_ban_hits_list if hit.ip_address != "N/A"}
        self.logger.debug("Pre-fetching ban info for all unique ban hits")
        ban_info_fetch_tasks = []
        for hit in unique_ban_hits_list:
            if hit.ban_hit_link not in ban_info_cache:
                ban_info_fetch_tasks.append(self.admin_service.fetch_ban_info(hit))
        if ban_info_fetch_tasks:
            ban_info_results = await asyncio.gather(*ban_info_fetch_tasks)
            for hit, result in zip(unique_ban_hits_list, ban_info_results):
                if result:
                    ban_info_cache[hit.ban_hit_link] = result
                    hit.banned_user_name = result.get("banned_user_name") or hit.user_name
                    hit.user_id = result.get("user_id") or hit.user_id
                    hit.ip_address = result.get("ip_address") or hit.ip_address
                    hit.hwid = result.get("hwid") or hit.hwid
                    if "ban_time" in result:
                        hit.ban_time = datetime.strptime(result.get("ban_time"), "%Y-%m-%d %H:%M:%S")
                    expires_str = result.get("expires", "1970-01-01 00:00:00")
                    try:
                        if "PERMANENT" in expires_str:
                            hit.ban_expires = datetime(2099, 12, 31)
                        else:
                            hit.ban_expires = datetime.strptime(expires_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        hit.ban_expires = datetime(2099, 12, 31)

        async def fetch_connections_cached(term):
            if term == "N/A" or not term:
                return []
            if term in connection_cache:
                cache_stats["connection_hits"] += 1
                return connection_cache[term]
            cache_stats["connection_misses"] += 1
            async with semaphore:
                result = await self.admin_service.fetch_with_rate_limit(self.admin_panel.fetch_connections_for_user,
                                                                        term)
                if result:
                    connection_cache[term] = result
                    for conn in result:
                        user_name = conn.get("user_name")
                        user_id = conn.get("user_id")
                        ip = conn.get("ip_address")
                        hwid = conn.get("hwid")
                        if user_name and user_name != "N/A":
                            if user_id and user_id != "N/A":
                                identity_graph[f"uid:{user_id}"].add(f"name:{user_name}")
                                identity_graph[f"name:{user_name}"].add(f"uid:{user_id}")
                            if ip and ip != "N/A":
                                identity_graph[f"ip:{ip}"].add(f"name:{user_name}")
                                identity_graph[f"name:{user_name}"].add(f"ip:{ip}")
                            if hwid and hwid != "N/A":
                                identity_graph[f"hwid:{hwid}"].add(f"name:{user_name}")
                                identity_graph[f"name:{user_name}"].add(f"hwid:{hwid}")
                        if ip and ip != "N/A" and hwid and hwid != "N/A":
                            identity_graph[f"ip:{ip}"].add(f"hwid:{hwid}")
                            identity_graph[f"hwid:{hwid}"].add(f"ip:{ip}")
                        if user_id and user_id != "N/A":
                            if ip and ip != "N/A":
                                identity_graph[f"uid:{user_id}"].add(f"ip:{ip}")
                                identity_graph[f"ip:{ip}"].add(f"uid:{user_id}")
                            if hwid and hwid != "N/A":
                                identity_graph[f"uid:{user_id}"].add(f"hwid:{hwid}")
                                identity_graph[f"hwid:{hwid}"].add(f"uid:{user_id}")
                else:
                    connection_cache[term] = []
                return connection_cache[term]

        self.logger.debug(f"Stage 1: Pre-fetching connections for primary identifiers")
        primary_fetch_tasks = []
        for user_id in all_user_ids:
            primary_fetch_tasks.append(fetch_connections_cached(user_id))
        for hwid in all_hwids:
            primary_fetch_tasks.append(fetch_connections_cached(hwid))
        for ip in all_ips:
            primary_fetch_tasks.append(fetch_connections_cached(ip))
        if primary_fetch_tasks:
            await asyncio.gather(*primary_fetch_tasks)
        secondary_ips = set()
        secondary_hwids = set()
        secondary_user_ids = set()
        for identifier_type, identifiers in [("uid:", all_user_ids), ("hwid:", all_hwids), ("ip:", all_ips)]:
            for id_value in identifiers:
                full_id = f"{identifier_type}{id_value}"
                for connected_id in identity_graph.get(full_id, set()):
                    if connected_id.startswith("ip:") and connected_id[3:] not in all_ips:
                        secondary_ips.add(connected_id[3:])
                    elif connected_id.startswith("hwid:") and connected_id[5:] not in all_hwids:
                        secondary_hwids.add(connected_id[5:])
                    elif connected_id.startswith("uid:") and connected_id[4:] not in all_user_ids:
                        secondary_user_ids.add(connected_id[4:])
        if secondary_ips or secondary_hwids or secondary_user_ids:
            self.logger.debug(
                f"Stage 2: Pre-fetching {len(secondary_ips)} secondary IPs, {len(secondary_hwids)} secondary HWIDs, and {len(secondary_user_ids)} secondary user IDs")
            limited_ips = list(secondary_ips)[:20]
            limited_hwids = list(secondary_hwids)[:20]
            limited_user_ids = list(secondary_user_ids)[:20]
            secondary_fetch_tasks = []
            for ip in limited_ips:
                secondary_fetch_tasks.append(fetch_connections_cached(ip))
            for hwid in limited_hwids:
                secondary_fetch_tasks.append(fetch_connections_cached(hwid))
            for user_id in limited_user_ids:
                secondary_fetch_tasks.append(fetch_connections_cached(user_id))
            if secondary_fetch_tasks:
                await asyncio.gather(*secondary_fetch_tasks)
        global_processed_identifiers = set()

        async def process_ban_hit(hit, idx, total) -> Optional[BanBypassCheck]:
            try:
                log_prefix = f"Ban hit {idx + 1}/{total}"
                if hit.user_id == "N/A":
                    return None
                hit_identifiers = set()
                if hit.user_id != "N/A":
                    hit_identifiers.add(f"user_id:{hit.user_id}")
                if hit.hwid != "N/A" and not hit.hwid_erased:
                    hit_identifiers.add(f"hwid:{hit.hwid}")
                if hit.ip_address != "N/A":
                    hit_identifiers.add(f"ip:{hit.ip_address}")
                if hit_identifiers and hit_identifiers.issubset(global_processed_identifiers):
                    return None
                global_processed_identifiers.update(hit_identifiers)
                related_identifiers = set()
                if hit.user_id != "N/A":
                    related_identifiers.add(hit.user_id)
                    full_id = f"uid:{hit.user_id}"
                    for connected_id in identity_graph.get(full_id, set()):
                        if ":" in connected_id:
                            conn_type, conn_value = connected_id.split(":", 1)
                            if conn_value != "N/A":
                                if conn_type in ("ip", "hwid", "uid"):
                                    related_identifiers.add(conn_value)
                if hit.hwid != "N/A" and not hit.hwid_erased:
                    related_identifiers.add(hit.hwid)
                    full_id = f"hwid:{hit.hwid}"
                    for connected_id in identity_graph.get(full_id, set()):
                        if ":" in connected_id:
                            conn_type, conn_value = connected_id.split(":", 1)
                            if conn_value != "N/A":
                                if conn_type in ("ip", "uid"):
                                    related_identifiers.add(conn_value)
                if hit.ip_address != "N/A":
                    related_identifiers.add(hit.ip_address)
                    full_id = f"ip:{hit.ip_address}"
                    for connected_id in identity_graph.get(full_id, set()):
                        if ":" in connected_id:
                            conn_type, conn_value = connected_id.split(":", 1)
                            if conn_value != "N/A":
                                if conn_type in ("hwid", "uid"):
                                    related_identifiers.add(conn_value)
                initial_connections = []
                seen_connection_ids = set()
                banned_user_name = hit.banned_user_name or hit.user_name
                for identifier in related_identifiers:
                    for conn in connection_cache.get(identifier, []):
                        conn_id = f"{conn.get('user_id', '')}-{conn.get('time', '')}-{conn.get('ip_address', '')}-{conn.get('hwid', '')}"
                        if conn_id not in seen_connection_ids:
                            seen_connection_ids.add(conn_id)
                            initial_connections.append(conn)
                all_ips = {hit.ip_address} if hit.ip_address != "N/A" else set()
                all_hwids = {hit.hwid} if hit.hwid != "N/A" and not hit.hwid_erased else set()
                for conn in initial_connections:
                    if conn.get("user_name") == banned_user_name:
                        ip = conn.get("ip_address")
                        hwid = conn.get("hwid")
                        if ip and ip != "N/A":
                            all_ips.add(ip)
                        if hwid and hwid != "N/A":
                            all_hwids.add(hwid)
                for ip in all_ips:
                    if ip != hit.ip_address:
                        for conn in connection_cache.get(ip, []):
                            conn_id = f"{conn.get('user_id', '')}-{conn.get('time', '')}-{conn.get('ip_address', '')}-{conn.get('hwid', '')}"
                            if conn_id not in seen_connection_ids:
                                seen_connection_ids.add(conn_id)
                                initial_connections.append(conn)
                for hwid in all_hwids:
                    if hwid != hit.hwid:
                        for conn in connection_cache.get(hwid, []):
                            conn_id = f"{conn.get('user_id', '')}-{conn.get('time', '')}-{conn.get('ip_address', '')}-{conn.get('hwid', '')}"
                            if conn_id not in seen_connection_ids:
                                seen_connection_ids.add(conn_id)
                                initial_connections.append(conn)
                account_info = self.admin_panel.aggregate_single_user_info(initial_connections)
                banned_player = self.admin_service.convert_to_player(account_info)
                if hit.user_name and hit.user_name != "N/A":
                    if hit.user_name in banned_player.nicknames:
                        banned_player.nicknames.remove(hit.user_name)
                    banned_player.nicknames.insert(0, hit.user_name)
                bypass_confidence, potential_bypassers = self.player_analyzer.find_potential_bypassers(hit,
                                                                                                       banned_player,
                                                                                                       initial_connections)
                nickname_to_search = hit.banned_user_name or hit.user_name
                complaint_links = await self.discord_service.find_nickname_mentions([nickname_to_search],
                                                                                    self.complaint_channels)
                return BanBypassCheck(
                    ban_hit=hit,
                    banned_player=banned_player,
                    potential_bypassers=potential_bypassers,
                    bypass_confidence=bypass_confidence,
                    complaint_links=complaint_links
                )
            except Exception as e:
                self.logger.error(f"Error processing ban hit {hit.ban_hit_link}: {str(e)}", exc_info=True)
                return None

        self.logger.info(f"Starting parallel processing of {len(unique_ban_hits_list)} ban hits")
        processing_tasks = []
        for idx, hit in enumerate(unique_ban_hits_list):
            processing_tasks.append(process_ban_hit(hit, idx, len(unique_ban_hits_list)))
        results = await gather_with_concurrency(self.max_concurrent_requests, *processing_tasks)
        ban_bypass_checks = [result for result in results if result]
        self.logger.debug(
            f"Connection cache stats: {cache_stats['connection_hits']} hits, {cache_stats['connection_misses']} misses")
        self.cache_service.save_complaint_cache(self.complaint_channels)
        counts = {
            "no_match": 0,
            "ip_match": 0,
            "ip_time_match": 0,
            "ip_time_close_match": 0,
            "hwid_match": 0
        }
        for check in ban_bypass_checks:
            if check.bypass_confidence == ConfidenceLevel.NO_MATCH.value:
                counts["no_match"] += 1
            elif check.bypass_confidence == ConfidenceLevel.IP_MATCH.value:
                counts["ip_match"] += 1
            elif check.bypass_confidence == ConfidenceLevel.IP_TIME_MATCH.value:
                counts["ip_time_match"] += 1
            elif check.bypass_confidence == ConfidenceLevel.IP_TIME_CLOSE_MATCH.value:
                counts["ip_time_close_match"] += 1
            elif check.bypass_confidence == ConfidenceLevel.HWID_MATCH.value:
                counts["hwid_match"] += 1
        duration = (datetime.now() - start_time).total_seconds()
        self.perf_logger.info(
            f"Ban bypass check completed in {duration:.2f}s with {len(ban_bypass_checks)} potential bypasses found")
        self.logger.info(
            f"HWID Matches: {counts['hwid_match']} | IP+Close Time: {counts['ip_time_close_match']} | IP+Time: {counts['ip_time_match']} | IP: {counts['ip_match']} | No Match: {counts['no_match']}")
        return ban_bypass_checks
