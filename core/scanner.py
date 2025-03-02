import asyncio
import functools
import hashlib
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple

from config_system import get_config
from core.analyzer import PlayerAnalyzer
from models.ban_hit import BanBypassCheck
from models.complaint import ComplaintChannel
from models.message import ScanResult
from models.player import Player
from models.verdict import ConfidenceLevel
from services.admin_service import AdminService
from services.cache_service import CacheService
from services.discord_service import DiscordService
from services.report_service import ReportService
from utils.async_utils import gather_with_concurrency
from utils.url_utils import extract_effective_search_term


class PerformanceStats:
    def __init__(self):
        self.operation_stats = defaultdict(list)
        self.operation_counts = defaultdict(int)
        self.last_summary_time = time.time()
        self.summary_interval = 60

    def record(self, operation: str, duration: float):
        self.operation_stats[operation].append(duration)
        self.operation_counts[operation] += 1

    def should_log_summary(self) -> bool:
        return (time.time() - self.last_summary_time) > self.summary_interval

    def get_summary(self) -> List[str]:
        summary = []
        for op, durations in sorted(self.operation_stats.items()):
            if durations:
                count = len(durations)
                avg = sum(durations) / count
                summary.append(f"  {op}: {count} calls, avg {avg:.2f}s")
        self.operation_stats.clear()
        self.operation_counts.clear()
        self.last_summary_time = time.time()
        return ["Performance summary:"] + summary


def monitor_performance(func):
    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        start_time = time.time()
        try:
            return await func(self, *args, **kwargs)
        finally:
            elapsed = time.time() - start_time
            self.perf_stats.record(func.__name__, elapsed)
            if elapsed > self.slow_operation_threshold:
                args_str = str(args)
                if len(args_str) > 40:
                    args_str = args_str[:37] + "..."
                self.perf_logger.debug(f"{func.__name__} took {elapsed:.2f}s: {args_str}")

    return wrapper


def cached_operation(cache_attr_name, key_func=None, ttl=300):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            cache = getattr(self, cache_attr_name, {})
            if not hasattr(self, cache_attr_name):
                setattr(self, cache_attr_name, cache)
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = str(args[0]) if args else "default"
            if cache_key in cache:
                timestamp, value = cache[cache_key]
                if time.time() - timestamp < ttl:
                    return value
            result = await func(self, *args, **kwargs)
            cache[cache_key] = (time.time(), result)
            return result

        return wrapper

    return decorator

class Scanner:
    def __init__(self, discord_service: DiscordService, admin_service: AdminService,
                 cache_service: CacheService, report_service: ReportService,
                 player_analyzer: PlayerAnalyzer) -> None:
        self.discord_service = discord_service
        self.admin_service = admin_service
        self.admin_panel = admin_service.admin_panel
        self.cache_service = cache_service
        self.report_service = report_service
        self.player_analyzer = player_analyzer
        self.complaint_channels: Dict[int, ComplaintChannel] = {}
        self.cfg = get_config()
        self.max_concurrent_requests = self.cfg.api.max_concurrent_requests
        self.connection_cache = {}
        self.ban_info_cache = {}
        self.player_cache = {}
        self.identity_graph = defaultdict(set)
        self._create_loggers()
        self.slow_operation_threshold = 10.0
        self.perf_stats = PerformanceStats()
        self.status_priority = {'banned': 3, 'suspicious': 2, 'clean': 1, 'unknown': 0}

    def _create_loggers(self):
        from utils.logging_utils import get_logger
        self.logger = logging.getLogger(__name__)
        self.perf_logger = get_logger(f"{__name__}.performance")

    async def setup(self, target_channel_id: int, complaint_channel_ids: List[int]) -> bool:
        self.logger.info("Setting up scanner...")
        if not await self.discord_service.setup_channels(target_channel_id, complaint_channel_ids):
            return False
        if not await self.admin_service.login():
            self.logger.error("Failed to log in to the admin panel")
            return False
        self.complaint_channels = self.cache_service.load_complaint_cache()
        self.logger.info("Scanner setup complete")
        return True

    @monitor_performance
    async def scan_messages(self, message_limit: int) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting message scan with limit {message_limit}")
        message_scan_cache = set()
        cache_lock = asyncio.Lock()
        try:
            self.complaint_channels = await self.discord_service.update_complaint_cache(
                self.complaint_channels, history_limit=self.cfg.discord.message_history_limit
            )
            messages = await self.discord_service.scan_target_channel(
                message_limit,
                lambda m: any(embed.title == 'Arrived new player' for embed in m.embeds)
            )
            if not messages:
                self.logger.info("No matching messages found")
                return []
            self.logger.info(f"Found {len(messages)} messages to process")
            all_terms = set()
            message_terms = {}
            term_is_login_event = {}
            for message in messages:
                if 'Arrived new player' not in message.embed_titles:
                    continue
                unique_terms = {
                    extract_effective_search_term(url)
                    for url in message.embed_links.values()
                    if extract_effective_search_term(url)
                }
                if unique_terms:
                    message_terms[message.id] = unique_terms
                    all_terms.update(unique_terms)
                    for term in unique_terms:
                        term_is_login_event[term] = True
            self.logger.info(f"Processing {len(all_terms)} unique terms across all messages")
            term_processing_tasks = [
                self.process_term(
                    term,
                    use_cache=True,
                    shared_cache=message_scan_cache,
                    cache_lock=cache_lock,
                    is_login_event=term_is_login_event.get(term, False)
                )
                for term in all_terms
            ]
            term_results = await gather_with_concurrency(
                self.max_concurrent_requests,
                *term_processing_tasks
            )
            term_to_player = {
                term: player for term, player in zip(all_terms, term_results) if player
            }
            scan_results = []
            for message in messages:
                if message.id not in message_terms:
                    continue
                players = [term_to_player[term] for term in message_terms[message.id]
                           if term in term_to_player]
                if players:
                    for player in players:
                        if message.embed_titles and 'Arrived new player' in message.embed_titles:
                            player.raw_message = "Arrived new player"
                            if player.nicknames:
                                primary_nick = player.nicknames[0]
                                if not hasattr(player, 'login_priorities'):
                                    player.login_priorities = {}
                                player.login_priorities[primary_nick] = 1
                                if not hasattr(player, 'login_timestamps'):
                                    player.login_timestamps = {}
                                timestamp = message.created_at if hasattr(message,
                                                                          'created_at') else datetime.now().isoformat()
                                player.login_timestamps[primary_nick] = str(timestamp)
                    grouped_players = self.player_analyzer.group_players_by_nicknames(players)
                    all_nicknames = {nickname for player in grouped_players for nickname in player.nicknames}
                    complaint_links = await self.discord_service.find_nickname_mentions(
                        list(all_nicknames), self.complaint_channels
                    )
                    for player in grouped_players:
                        player.complaint_links = [
                            link for link in complaint_links
                            if any(nickname in link.get('content', '') for nickname in player.nicknames)
                        ]
                    scan_results.append(
                        ScanResult(message=message, players=grouped_players, scan_time=datetime.now())
                    )
            consolidated = self.consolidate_players_across_messages(scan_results)
            report_data = self.report_service.generate_message_scan_report(consolidated)
            duration = (datetime.now() - start_time).total_seconds()
            hit_rate = (len(consolidated) / len(messages)) * 100 if messages else 0
            self.perf_logger.info(
                f"Message scan completed in {duration:.2f}s: processed {len(messages)} messages, "
                f"found {len(consolidated)} results ({hit_rate:.1f}% hit rate)"
            )
            if self.perf_stats.should_log_summary():
                for line in self.perf_stats.get_summary():
                    self.perf_logger.info(line)
            return report_data
        except Exception as e:
            self.logger.error(f"Error during message scan: {str(e)}", exc_info=True)
            return []
        finally:
            self.cache_service.save_complaint_cache(self.complaint_channels)

    @monitor_performance
    async def process_term(self, term: str, use_cache: bool = False,
                           shared_cache: Optional[Set[str]] = None,
                           cache_lock: Optional[asyncio.Lock] = None,
                           is_login_event: bool = False) -> Optional[Player]:
        term_start = datetime.now()
        try:
            if use_cache and shared_cache is not None and cache_lock is not None:
                async with cache_lock:
                    if term in shared_cache:
                        return None
                    shared_cache.add(term)
            if term in self.player_cache:
                player = self.player_cache[term]
                if is_login_event and player:
                    player.raw_message = "Arrived new player"
                    if player.nicknames:
                        primary_nick = player.nicknames[0]
                        if not hasattr(player, 'login_priorities'):
                            player.login_priorities = {}
                        player.login_priorities[primary_nick] = 1
                        if not hasattr(player, 'login_timestamps'):
                            player.login_timestamps = {}
                        current_time = datetime.now().isoformat()
                        player.login_timestamps[primary_nick] = current_time
                return player
            account_info = await self.admin_service.search_player(term)
            if not account_info:
                return None
            associated_accounts = []
            unique_search_terms = set()
            for ip in account_info.get("associated_ips", {}):
                if ip != "N/A":
                    unique_search_terms.add(ip)
            for hwid in account_info.get("associated_hwids", {}):
                if hwid != "N/A":
                    unique_search_terms.add(hwid)
            if unique_search_terms:
                limited_terms = list(unique_search_terms)[:10]
                terms_to_process = []
                if use_cache and shared_cache is not None and cache_lock is not None:
                    async with cache_lock:
                        for search_term in limited_terms:
                            if search_term not in shared_cache:
                                shared_cache.add(search_term)
                                terms_to_process.append(search_term)
                else:
                    terms_to_process = limited_terms
                if terms_to_process:
                    search_tasks = [
                        self.admin_service.search_player(search_term)
                        for search_term in terms_to_process
                    ]
                    results = await gather_with_concurrency(
                        self.max_concurrent_requests,
                        *search_tasks
                    )
                    associated_accounts = [result for result in results if result]
            all_accounts = [account_info] + associated_accounts
            aggregated = self.admin_panel.aggregate_player_info(all_accounts)
            if not aggregated:
                return None
            player = self.admin_service.convert_to_player(aggregated[0])
            if is_login_event:
                player.raw_message = "Arrived new player"
                if player.nicknames:
                    primary_nick = player.nicknames[0]
                    if not hasattr(player, 'login_priorities'):
                        player.login_priorities = {}
                    player.login_priorities[primary_nick] = 1
                    if not hasattr(player, 'login_timestamps'):
                        player.login_timestamps = {}
                    current_time = datetime.now().isoformat()
                    player.login_timestamps[primary_nick] = current_time
            await self._batch_fetch_connections(player)
            processing_duration = (datetime.now() - term_start).total_seconds()
            self.perf_stats.record("process_term", processing_duration)
            self.player_cache[term] = player
            return player
        except Exception as e:
            self.logger.error(f"Error in process_term for '{term}': {str(e)}", exc_info=True)
            return None

    async def _batch_fetch_connections(self, player: Player) -> None:
        identifiers = self._collect_player_identifiers(player)
        unique_identifiers = list({id for id in identifiers if id and id != "N/A"})
        if not unique_identifiers:
            return
        max_identifiers = min(10, len(unique_identifiers))
        selected_identifiers = unique_identifiers[:max_identifiers]
        connection_tasks = []
        for identifier in selected_identifiers:
            if identifier in self.connection_cache:
                continue
            connection_tasks.append(
                self.admin_service.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user, identifier
                )
            )
        if connection_tasks:
            connection_results = await gather_with_concurrency(
                self.max_concurrent_requests,
                *connection_tasks
            )
            all_connections = []
            for i, result in enumerate(connection_results):
                identifier = selected_identifiers[i]
                self.connection_cache[identifier] = result
                all_connections.extend(result)
                self._update_identity_graph(result)
            self._process_connections(all_connections, player)
            denied_logins = self._process_denied_logins(all_connections)
            player.denied_logins = denied_logins
            if denied_logins and self.status_priority.get(player.status.lower(), 0) < self.status_priority[
                'suspicious']:
                player.status = "suspicious"
                player.ban_counts = max(player.ban_counts, 1)

    def _collect_player_identifiers(self, player: Player) -> List[str]:
        identifiers = set()
        if player.user_id and player.user_id != "N/A":
            identifiers.add(player.user_id)
        identifiers.update(player.nicknames)
        if hasattr(player, 'associated_ips') and player.associated_ips:
            for ip in player.associated_ips:
                if ip != "N/A":
                    identifiers.add(ip)
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            for hwid in player.associated_hwids:
                if hwid != "N/A":
                    identifiers.add(hwid)
        return list(identifiers)

    def _update_identity_graph(self, connections: List[Dict[str, Any]]) -> None:
        for conn in connections:
            user_name = conn.get("user_name")
            user_id = conn.get("user_id")
            ip = conn.get("ip_address")
            hwid = conn.get("hwid")
            if not user_name or user_name == "N/A":
                continue
            if user_id and user_id != "N/A":
                self.identity_graph[f"uid:{user_id}"].add(f"name:{user_name}")
                self.identity_graph[f"name:{user_name}"].add(f"uid:{user_id}")
            if ip and ip != "N/A":
                self.identity_graph[f"ip:{ip}"].add(f"name:{user_name}")
                self.identity_graph[f"name:{user_name}"].add(f"ip:{ip}")
            if hwid and hwid != "N/A":
                self.identity_graph[f"hwid:{hwid}"].add(f"name:{user_name}")
                self.identity_graph[f"name:{user_name}"].add(f"hwid:{hwid}")
            if ip and ip != "N/A" and hwid and hwid != "N/A":
                self.identity_graph[f"ip:{ip}"].add(f"hwid:{hwid}")
                self.identity_graph[f"hwid:{hwid}"].add(f"ip:{ip}")
            if user_id and user_id != "N/A":
                if ip and ip != "N/A":
                    self.identity_graph[f"uid:{user_id}"].add(f"ip:{ip}")
                    self.identity_graph[f"ip:{ip}"].add(f"uid:{user_id}")
                if hwid and hwid != "N/A":
                    self.identity_graph[f"uid:{user_id}"].add(f"hwid:{hwid}")
                    self.identity_graph[f"hwid:{hwid}"].add(f"uid:{user_id}")

    def _process_connections(self, connections: List[Dict[str, Any]], player: Player) -> Dict[
        str, List[Dict[str, Any]]]:
        nickname_connections = defaultdict(list)
        for conn in connections:
            user_name = conn.get("user_name", "")
            if user_name:
                nickname_connections[user_name].append(conn)
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
        return nickname_connections

    def _process_denied_logins(self, connections: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        denied_logins = []
        for conn in connections:
            if "Denied: Banned" in conn.get("status", ""):
                denied_logins.append({
                    "user_name": conn.get("user_name", ""),
                    "time": conn.get("time", ""),
                    "ip_address": conn.get("ip_address", ""),
                    "hwid": conn.get("hwid", ""),
                    "server": conn.get("server", "")
                })
        return denied_logins

    @monitor_performance
    async def scan_nickname(self, nickname: str) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting nickname search for: {nickname}")
        try:
            self.complaint_channels = await self.discord_service.update_complaint_cache(
                self.complaint_channels, history_limit=self.cfg.discord.message_history_limit
            )
            player = await self.process_term(nickname)
            if not player:
                self.logger.info(f"No player found for nickname: {nickname}")
                return []
            complaint_links = await self.discord_service.find_nickname_mentions(
                player.nicknames, self.complaint_channels
            )
            player.complaint_links = complaint_links
            report_data = self.report_service.generate_nickname_search_report(nickname, player)
            duration = (datetime.now() - start_time).total_seconds()
            self.perf_logger.info(f"Nickname search for '{nickname}' completed in {duration:.2f}s")
            return report_data
        except Exception as e:
            self.logger.error(f"Error in scan_nickname for '{nickname}': {str(e)}", exc_info=True)
            return []
        finally:
            self.cache_service.save_complaint_cache(self.complaint_channels)

    @monitor_performance
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
            self.discord_service.update_complaint_cache(
                self.complaint_channels, history_limit=self.cfg.discord.message_history_limit
            )
        )
        ban_hits_task = asyncio.create_task(
            self.admin_service.fetch_ban_hits(max_pages)
        )
        await asyncio.wait([complaint_task, ban_hits_task])
        self.complaint_channels = complaint_task.result()
        ban_hits = ban_hits_task.result()
        if not ban_hits:
            self.logger.info("No ban hits found")
            self.cache_service.save_complaint_cache(self.complaint_channels)
            return []
        unique_ban_hits = self._deduplicate_ban_hits(ban_hits)
        unique_ban_hits_list = list(unique_ban_hits.values())
        self.logger.info(
            f"Processing {len(unique_ban_hits_list)} unique ban hits (from {len(ban_hits)} total)"
        )
        all_identifiers = self._extract_identifiers_from_ban_hits(unique_ban_hits_list)
        all_user_ids = all_identifiers['user_ids']
        all_hwids = all_identifiers['hwids']
        all_ips = all_identifiers['ips']
        await self._prefetch_ban_info(unique_ban_hits_list, ban_info_cache)
        async def fetch_connections_cached(term):
            if term == "N/A" or not term:
                return []
            if term in connection_cache:
                cache_stats["connection_hits"] += 1
                return connection_cache[term]
            cache_stats["connection_misses"] += 1
            async with semaphore:
                result = await self.admin_service.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user, term
                )
                if result:
                    connection_cache[term] = result
                    self._update_identity_graph(result)
                else:
                    connection_cache[term] = []
                return connection_cache[term]

        self.logger.info(f"Stage 1: Pre-fetching connections for primary identifiers")
        primary_fetch_tasks = []
        for user_id in all_user_ids:
            primary_fetch_tasks.append(fetch_connections_cached(user_id))
        for hwid in all_hwids:
            primary_fetch_tasks.append(fetch_connections_cached(hwid))
        for ip in all_ips:
            primary_fetch_tasks.append(fetch_connections_cached(ip))
        if primary_fetch_tasks:
            await asyncio.gather(*primary_fetch_tasks)
        secondary_identifiers = self._find_secondary_identifiers(
            identity_graph, all_user_ids, all_hwids, all_ips
        )
        secondary_ips = secondary_identifiers['ips']
        secondary_hwids = secondary_identifiers['hwids']
        secondary_user_ids = secondary_identifiers['user_ids']
        if secondary_ips or secondary_hwids or secondary_user_ids:
            self.logger.info(
                f"Stage 2: Pre-fetching {len(secondary_ips)} secondary IPs, "
                f"{len(secondary_hwids)} secondary HWIDs, and {len(secondary_user_ids)} secondary user IDs"
            )
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
        processed_identifiers_lock = asyncio.Lock()
        global_processed_identifiers = set()
        async def process_ban_hit(hit, idx, total) -> Optional[BanBypassCheck]:
            try:
                if hit.user_id == "N/A":
                    return None
                hit_identifiers = set()
                if hit.user_id != "N/A":
                    hit_identifiers.add(f"user_id:{hit.user_id}")
                if hit.hwid != "N/A" and not hit.hwid_erased:
                    hit_identifiers.add(f"hwid:{hit.hwid}")
                if hit.ip_address != "N/A":
                    hit_identifiers.add(f"ip:{hit.ip_address}")
                async with processed_identifiers_lock:
                    if hit_identifiers and hit_identifiers.issubset(global_processed_identifiers):
                        return None
                    global_processed_identifiers.update(hit_identifiers)
                related_identifiers = await self._find_related_identifiers(hit, identity_graph)
                initial_connections, seen_connection_ids = await self._fetch_connections_for_ban_hit(
                    hit, related_identifiers, connection_cache
                )
                all_ips, all_hwids = self._extract_connection_identifiers(hit, initial_connections)
                for ip in all_ips:
                    if ip != hit.ip_address:
                        for conn in connection_cache.get(ip, []):
                            conn_id = self._create_connection_id(conn)
                            if conn_id not in seen_connection_ids:
                                seen_connection_ids.add(conn_id)
                                initial_connections.append(conn)
                for hwid in all_hwids:
                    if hwid != hit.hwid:
                        for conn in connection_cache.get(hwid, []):
                            conn_id = self._create_connection_id(conn)
                            if conn_id not in seen_connection_ids:
                                seen_connection_ids.add(conn_id)
                                initial_connections.append(conn)
                account_info = self.admin_panel.aggregate_single_user_info(initial_connections)
                banned_player = self.admin_service.convert_to_player(account_info)
                if hit.user_name and hit.user_name != "N/A":
                    if hit.user_name in banned_player.nicknames:
                        banned_player.nicknames.remove(hit.user_name)
                    banned_player.nicknames.insert(0, hit.user_name)
                bypass_confidence, potential_bypassers = self.player_analyzer.find_potential_bypassers(
                    hit, banned_player, initial_connections
                )
                nickname_to_search = hit.banned_user_name or hit.user_name
                complaint_links = await self.discord_service.find_nickname_mentions(
                    [nickname_to_search], self.complaint_channels
                )
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
        self.logger.info(
            f"Connection cache stats: {cache_stats['connection_hits']} hits, "
            f"{cache_stats['connection_misses']} misses"
        )
        self.cache_service.save_complaint_cache(self.complaint_channels)
        confidence_counts = self._count_confidence_levels(ban_bypass_checks)
        duration = (datetime.now() - start_time).total_seconds()
        self.perf_logger.info(
            f"Ban bypass check completed in {duration:.2f}s with {len(ban_bypass_checks)} potential bypasses found"
        )
        self.logger.info(
            f"HWID Matches: {confidence_counts['hwid_match']} | "
            f"IP+Close Time: {confidence_counts['ip_time_close_match']} | "
            f"IP+Time: {confidence_counts['ip_time_match']} | "
            f"IP: {confidence_counts['ip_match']} | "
            f"No Match: {confidence_counts['no_match']}"
        )
        return ban_bypass_checks

    def _deduplicate_ban_hits(self, ban_hits: List[Any]) -> Dict[str, Any]:
        unique_ban_hits = {}
        for hit in ban_hits:
            hit_key = f"{hit.user_id}|{hit.user_name}|{hit.ip_address}|{hit.hwid}"
            if hit_key not in unique_ban_hits:
                unique_ban_hits[hit_key] = hit
        return unique_ban_hits

    def _extract_identifiers_from_ban_hits(self, ban_hits: List[Any]) -> Dict[str, Set[str]]:
        all_user_ids = {hit.user_id for hit in ban_hits if hit.user_id != "N/A"}
        all_hwids = {hit.hwid for hit in ban_hits if hit.hwid != "N/A" and not hit.hwid_erased}
        all_ips = {hit.ip_address for hit in ban_hits if hit.ip_address != "N/A"}
        return {
            'user_ids': all_user_ids,
            'hwids': all_hwids,
            'ips': all_ips
        }

    async def _prefetch_ban_info(self, ban_hits: List[Any], ban_info_cache: Dict[str, Any]) -> None:
        self.logger.info("Pre-fetching ban info for all unique ban hits")
        ban_info_fetch_tasks = []
        hits_to_process = []
        for hit in ban_hits:
            if hit.ban_hit_link not in ban_info_cache:
                ban_info_fetch_tasks.append(self.admin_service.fetch_ban_info(hit))
                hits_to_process.append(hit)
        if ban_info_fetch_tasks:
            ban_info_results = await gather_with_concurrency(
                self.max_concurrent_requests,
                *ban_info_fetch_tasks
            )
            for hit, result in zip(hits_to_process, ban_info_results):
                if result:
                    ban_info_cache[hit.ban_hit_link] = result
                    hit.banned_user_name = result.get("banned_user_name") or hit.user_name
                    hit.user_id = result.get("user_id") or hit.user_id
                    hit.ip_address = result.get("ip_address") or hit.ip_address
                    hit.hwid = result.get("hwid") or hit.hwid
                    if "ban_time" in result:
                        hit.ban_time = datetime.strptime(
                            result.get("ban_time"), "%Y-%m-%d %H:%M:%S"
                        )
                    expires_str = result.get("expires", "1970-01-01 00:00:00")
                    try:
                        if "PERMANENT" in expires_str:
                            hit.ban_expires = datetime(2099, 12, 31)
                        else:
                            hit.ban_expires = datetime.strptime(
                                expires_str, "%Y-%m-%d %H:%M:%S"
                            )
                    except ValueError:
                        hit.ban_expires = datetime(2099, 12, 31)

    def _find_secondary_identifiers(
            self,
            identity_graph: Dict[str, Set[str]],
            all_user_ids: Set[str],
            all_hwids: Set[str],
            all_ips: Set[str]
    ) -> Dict[str, Set[str]]:
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
        return {
            'ips': secondary_ips,
            'hwids': secondary_hwids,
            'user_ids': secondary_user_ids
        }

    async def _find_related_identifiers(
            self, hit: Any, identity_graph: Dict[str, Set[str]]
    ) -> Set[str]:
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
        return related_identifiers

    async def _fetch_connections_for_ban_hit(
            self, hit: Any, related_identifiers: Set[str], connection_cache: Dict[str, List[Dict[str, Any]]]
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        initial_connections = []
        seen_connection_ids = set()
        for identifier in related_identifiers:
            for conn in connection_cache.get(identifier, []):
                conn_id = self._create_connection_id(conn)
                if conn_id not in seen_connection_ids:
                    seen_connection_ids.add(conn_id)
                    initial_connections.append(conn)
        return initial_connections, seen_connection_ids

    def _create_connection_id(self, conn: Dict[str, Any]) -> str:
        key_parts = [
            str(conn.get('user_id', '')),
            str(conn.get('time', '')),
            str(conn.get('ip_address', '')),
            str(conn.get('hwid', ''))
        ]
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()

    def _extract_connection_identifiers(
            self, hit: Any, connections: List[Dict[str, Any]]
    ) -> Tuple[Set[str], Set[str]]:
        all_ips = {hit.ip_address} if hit.ip_address != "N/A" else set()
        all_hwids = {hit.hwid} if hit.hwid != "N/A" and not hit.hwid_erased else set()
        banned_user_name = hit.banned_user_name or hit.user_name
        for conn in connections:
            if conn.get("user_name") == banned_user_name:
                ip = conn.get("ip_address")
                hwid = conn.get("hwid")
                if ip and ip != "N/A":
                    all_ips.add(ip)
                if hwid and hwid != "N/A":
                    all_hwids.add(hwid)
        return all_ips, all_hwids

    def _count_confidence_levels(self, ban_bypass_checks: List[BanBypassCheck]) -> Dict[str, int]:
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
        return counts

    def consolidate_players_across_messages(self, scan_results: List[ScanResult]) -> List[ScanResult]:
        if not scan_results:
            return []
        player_registry = {}
        message_to_players = defaultdict(set)
        for result in scan_results:
            message_id = result.message.id
            for player in result.players:
                identifier = self._create_player_identifier(player)
                if identifier not in player_registry:
                    player_registry[identifier] = player
                else:
                    self._merge_player_info(player_registry[identifier], player)
                message_to_players[message_id].add(identifier)
        consolidated_results = []
        processed_messages = set()
        for result in scan_results:
            message_id = result.message.id
            if message_id in processed_messages:
                continue
            processed_messages.add(message_id)
            message_player_ids = message_to_players[message_id]
            consolidated_players = [player_registry[pid] for pid in message_player_ids]
            consolidated_result = ScanResult(
                message=result.message,
                players=consolidated_players,
                scan_time=result.scan_time
            )
            consolidated_results.append(consolidated_result)
        self.logger.info(
            f"Consolidated {len(scan_results)} scan results into {len(consolidated_results)} unique message results")
        return consolidated_results

    def _create_player_identifier(self, player: Player) -> str:
        key_parts = []
        if player.user_id and player.user_id != "N/A":
            key_parts.append(f"uid:{player.user_id}")
        primary_nickname = player.primary_nickname if hasattr(player, 'primary_nickname') else (
            player.nicknames[0] if player.nicknames else "")
        if primary_nickname:
            key_parts.append(f"name:{primary_nickname}")
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            first_hwid = next(iter(player.associated_hwids.keys()), "")
            if first_hwid and first_hwid != "N/A":
                key_parts.append(f"hwid:{first_hwid}")
        if hasattr(player, 'associated_ips') and player.associated_ips:
            first_ip = next(iter(player.associated_ips.keys()), "")
            if first_ip and first_ip != "N/A":
                key_parts.append(f"ip:{first_ip}")
        if not key_parts and player.nicknames:
            for nick in player.nicknames:
                key_parts.append(f"name:{nick}")
        identifier_string = '|'.join(key_parts)
        return hashlib.md5(identifier_string.encode()).hexdigest()

    def _merge_player_info(self, target_player: Player, source_player: Player) -> None:
        if not hasattr(target_player, 'nicknames_sources'):
            target_player.nicknames_sources = {}
        if not hasattr(target_player, 'login_priorities'):
            target_player.login_priorities = {}
        if not hasattr(target_player, 'login_timestamps'):
            target_player.login_timestamps = {}
        source_is_login_event = False
        if hasattr(source_player, 'raw_message') and source_player.raw_message:
            source_is_login_event = "Arrived new player" in source_player.raw_message
            if source_is_login_event and (not hasattr(target_player, 'raw_message') or not target_player.raw_message):
                target_player.raw_message = source_player.raw_message
        for nickname in source_player.nicknames:
            is_login_event = source_is_login_event
            if hasattr(source_player, 'login_priorities') and nickname in source_player.login_priorities:
                if source_player.login_priorities[nickname] == 1:
                    is_login_event = True
            if is_login_event:
                target_player.nicknames_sources[nickname] = "login"
                target_player.login_priorities[nickname] = 1
                if hasattr(source_player, 'login_timestamps') and nickname in source_player.login_timestamps:
                    target_player.login_timestamps[nickname] = source_player.login_timestamps[nickname]
                if nickname in target_player.nicknames:
                    target_player.nicknames.remove(nickname)
                target_player.nicknames.insert(0, nickname)
            elif nickname not in target_player.nicknames:
                target_player.nicknames_sources[nickname] = "other"
                if nickname not in target_player.login_priorities:
                    target_player.login_priorities[nickname] = 2
                target_player.nicknames.append(nickname)
        if hasattr(source_player, 'login_timestamps'):
            for nick, timestamp in source_player.login_timestamps.items():
                if nick not in target_player.login_timestamps or timestamp > target_player.login_timestamps[nick]:
                    target_player.login_timestamps[nick] = timestamp
        source_status = source_player.status.lower()
        target_status = target_player.status.lower()
        if self.status_priority.get(source_status, 0) > self.status_priority.get(target_status, 0):
            target_player.status = source_player.status
        target_player.ban_counts = max(target_player.ban_counts, source_player.ban_counts)
        if hasattr(source_player, 'associated_ips') and hasattr(target_player, 'associated_ips'):
            for ip, nicks in source_player.associated_ips.items():
                if ip in target_player.associated_ips:
                    combined_nicks = set(target_player.associated_ips[ip])
                    combined_nicks.update(nicks)
                    target_player.associated_ips[ip] = list(combined_nicks)
                else:
                    target_player.associated_ips[ip] = nicks
        if hasattr(source_player, 'associated_hwids') and hasattr(target_player, 'associated_hwids'):
            for hwid, nicks in source_player.associated_hwids.items():
                if hwid in target_player.associated_hwids:
                    combined_nicks = set(target_player.associated_hwids[hwid])
                    combined_nicks.update(nicks)
                    target_player.associated_hwids[hwid] = list(combined_nicks)
                else:
                    target_player.associated_hwids[hwid] = nicks
        if hasattr(source_player, 'complaint_links') and source_player.complaint_links:
            if not hasattr(target_player, 'complaint_links'):
                target_player.complaint_links = []
            existing_links = {
                tuple(sorted((k, str(v)) for k, v in link.items()))
                for link in target_player.complaint_links
            } if target_player.complaint_links else set()
            for link in source_player.complaint_links:
                link_tuple = tuple(sorted((k, str(v)) for k, v in link.items()))
                if link_tuple not in existing_links:
                    target_player.complaint_links.append(link)
                    existing_links.add(link_tuple)
        if hasattr(source_player, 'ban_reasons') and source_player.ban_reasons:
            if not hasattr(target_player, 'ban_reasons'):
                target_player.ban_reasons = []
            target_reasons = set(target_player.ban_reasons)
            target_reasons.update(source_player.ban_reasons)
            target_player.ban_reasons = list(target_reasons)
