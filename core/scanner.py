import asyncio
import functools
import hashlib
import logging
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Set

from config_system import get_config
from core.analyzer import PlayerAnalyzer
from models.ban_hit import BanBypassCheck
from models.message import ScanResult
from models.player import Player
from models.verdict import ConfidenceLevel
from services.admin_service import AdminService
from services.cache_service import CacheService
from services.discord_service import DiscordService
from services.report_service import ReportService
from utils.async_utils import gather_with_concurrency
from utils.url_utils import extract_effective_search_term


class PerformanceTracker:
    def __init__(self, log_interval=60):
        self.stats = defaultdict(list)
        self.counts = defaultdict(int)
        self.last_summary_time = time.time()
        self.summary_interval = log_interval
        self.logger = logging.getLogger(__name__ + ".performance")

    def record(self, operation: str, duration: float):
        self.stats[operation].append(duration)
        self.counts[operation] += 1

    def log_summary_if_needed(self):
        if (time.time() - self.last_summary_time) > self.summary_interval:
            summary = ["Performance summary:"]
            for op, durations in sorted(self.stats.items()):
                if durations:
                    avg = sum(durations) / len(durations)
                    summary.append(f"  {op}: {len(durations)} calls, avg {avg:.2f}s")
            for line in summary:
                self.logger.info(line)
            self.stats.clear()
            self.counts.clear()
            self.last_summary_time = time.time()
            return True
        return False


def monitor_performance(slow_threshold=10.0):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            start_time = time.time()
            try:
                return await func(self, *args, **kwargs)
            finally:
                elapsed = time.time() - start_time
                self.perf.record(func.__name__, elapsed)
                if elapsed > slow_threshold:
                    args_str = str(args)[:40] + "..." if len(str(args)) > 40 else str(args)
                    self.perf.logger.debug(f"{func.__name__} took {elapsed:.2f}s: {args_str}")

        return wrapper

    return decorator


def cached(ttl=300):
    def decorator(func):
        cache = {}
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
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
        self.discord = discord_service
        self.admin = admin_service
        self.admin_panel = admin_service.admin_panel
        self.cache = cache_service
        self.report = report_service
        self.analyzer = player_analyzer
        self.cfg = get_config()
        self.max_concurrent = self.cfg.api.max_concurrent_requests
        self.complaint_channels = {}
        self.cache_data = {
            "connections": {},
            "ban_info": {},
            "players": {},
        }
        self.identity_graph = defaultdict(set)
        self.logger = logging.getLogger(__name__)
        self.perf = PerformanceTracker()
        self.status_priority = {
            'banned': 3,
            'suspicious': 2,
            'clean': 1,
            'unknown': 0
        }

    async def setup(self, target_channel_id: int, complaint_channel_ids: List[int]) -> bool:
        self.logger.info("Setting up scanner...")
        if not await self.discord.setup_channels(target_channel_id, complaint_channel_ids):
            return False
        if not await self.admin.login():
            self.logger.error("Failed to log in to the admin panel")
            return False
        self.complaint_channels = self.cache.load_complaint_cache()
        self.logger.info("Scanner setup complete")
        return True

    @monitor_performance()
    async def scan_messages(self, message_limit: int) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting message scan with limit {message_limit}")
        processed_terms = set()
        try:
            self.complaint_channels = await self.discord.update_complaint_cache(
                self.complaint_channels,
                history_limit=self.cfg.discord.message_history_limit
            )
            messages = await self.discord.scan_target_channel(
                message_limit,
                lambda m: any(embed.title == 'Arrived new player' for embed in m.embeds)
            )
            if not messages:
                self.logger.info("No matching messages found")
                return []
            self.logger.info(f"Found {len(messages)} messages to process")
            message_data = self._extract_message_data(messages)
            all_terms = message_data['all_terms']
            self.logger.info(f"Processing {len(all_terms)} unique terms")
            term_results = await self._process_all_terms(
                all_terms,
                message_data['term_is_login_event'],
                message_data['user_id_terms'],
                processed_terms,
                message_data
            )
            scan_results = await self._create_scan_results(
                messages,
                message_data,
                term_results
            )
            consolidated_results = self._consolidate_results(scan_results)
            report_data = self.report.generate_message_scan_report(consolidated_results)
            duration = (datetime.now() - start_time).total_seconds()
            hit_rate = (len(consolidated_results) / len(messages)) * 100 if messages else 0
            self.perf.logger.info(
                f"Message scan completed in {duration:.2f}s: processed {len(messages)} messages, "
                f"found {len(consolidated_results)} results ({hit_rate:.1f}% hit rate)"
            )
            self.perf.log_summary_if_needed()
            return report_data
        except Exception as e:
            self.logger.error(f"Error during message scan: {str(e)}", exc_info=True)
            return []
        finally:
            self.cache.save_complaint_cache(self.complaint_channels)

    def _extract_message_data(self, messages):
        all_terms = set()
        message_terms = {}
        term_is_login_event = {}
        user_id_terms = {}
        message_nicknames = {}
        term_to_message_id = {}
        for message in messages:
            if 'Arrived new player' not in message.embed_titles:
                continue
            nickname = None
            candidate_nicknames = []
            for key, url in message.embed_links.items():
                if key.startswith('search:'):
                    term = key[7:]
                    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', term, re.I):
                        continue
                    elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', term):
                        continue
                    elif term.startswith('V2-'):
                        continue
                    else:
                        candidate_nicknames.append(term)
            if candidate_nicknames:
                nickname = candidate_nicknames[0]
                message_nicknames[message.id] = nickname
            if not nickname and hasattr(message, 'embeds'):
                for embed in message.embeds:
                    if embed.title == 'Arrived new player':
                        for field in embed.fields:
                            if field.name.lower() == 'name':
                                nickname = field.value.strip()
                                message_nicknames[message.id] = nickname
                                break
            unique_terms = {
                extract_effective_search_term(url)
                for url in message.embed_links.values()
                if extract_effective_search_term(url)
            }
            if not unique_terms:
                continue
            message_terms[message.id] = unique_terms
            all_terms.update(unique_terms)
            for term in unique_terms:
                term_is_login_event[term] = True
                term_to_message_id[term] = message.id
            for url in message.embed_links.values():
                term = extract_effective_search_term(url)
                if term and re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', term, re.I):
                    user_id_terms[message.id] = term
                    break
        return {
            'all_terms': all_terms,
            'message_terms': message_terms,
            'term_is_login_event': term_is_login_event,
            'user_id_terms': user_id_terms,
            'message_nicknames': message_nicknames,
            'term_to_message_id': term_to_message_id
        }

    async def _process_all_terms(self, all_terms, term_is_login_event, user_id_terms, processed_terms, message_data):
        cache_lock = asyncio.Lock()
        term_tasks = []
        message_nicknames = message_data.get('message_nicknames', {})
        term_to_message_id = message_data.get('term_to_message_id', {})
        for term in all_terms:
            message_id = term_to_message_id.get(term)
            nickname = message_nicknames.get(message_id) if message_id else None
            term_tasks.append(
                self.process_term(
                    term,
                    use_cache=True,
                    shared_cache=processed_terms,
                    cache_lock=cache_lock,
                    is_login_event=term_is_login_event.get(term, False),
                    is_user_id=(term in user_id_terms.values()),
                    message_nickname=nickname
                )
            )
        term_results = await gather_with_concurrency(
            self.max_concurrent,
            *term_tasks
        )
        return {
            term: player
            for term, player in zip(all_terms, term_results)
            if player
        }

    async def _create_scan_results(self, messages, message_data, term_to_player):
        scan_results = []
        for message in messages:
            if message.id not in message_data['message_terms']:
                continue
            message_terms = message_data['message_terms'][message.id]
            players = [term_to_player[term] for term in message_terms if term in term_to_player]
            if not players:
                continue
            message_nickname = message_data.get('message_nicknames', {}).get(message.id)
            user_id_term = message_data['user_id_terms'].get(message.id)
            user_id_player = term_to_player.get(user_id_term) if user_id_term else None
            self._annotate_players_with_login_info(players, user_id_player, message, message_nickname)
            grouped_players = self.analyzer.group_players_by_nicknames(players)
            all_nicknames = {nickname for player in grouped_players for nickname in player.nicknames}
            complaint_links = await self.discord.find_nickname_mentions(
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
        return scan_results

    def _annotate_players_with_login_info(self, players, user_id_player, message, message_nickname=None):
        for player in players:
            if message.embed_titles and 'Arrived new player' in message.embed_titles:
                player.raw_message = "Arrived new player"
                if not hasattr(player, 'nicknames_sources'):
                    player.nicknames_sources = {}
                if message_nickname and message_nickname in player.nicknames:
                    player.is_primary = True
                    player.nicknames.remove(message_nickname)
                    player.nicknames.insert(0, message_nickname)
                    player.nicknames_sources[message_nickname] = "login"
                    player.primary_nickname = message_nickname
                elif user_id_player and player is user_id_player and player.nicknames:
                    player.is_primary = True
                    primary_nick = player.nicknames[0]
                    player.nicknames_sources[primary_nick] = "login"
                    player.primary_nickname = primary_nick
                elif player.nicknames:
                    player.is_primary = False
                    primary_nick = player.nicknames[0]
                    player.nicknames_sources[primary_nick] = "login"

    @monitor_performance()
    async def process_term(self, term: str, use_cache: bool = False,
                           shared_cache: Optional[Set[str]] = None,
                           cache_lock: Optional[asyncio.Lock] = None,
                           is_login_event: bool = False,
                           is_user_id: bool = False,
                           message_nickname: Optional[str] = None) -> Optional[Player]:
        term_start = datetime.now()
        try:
            if use_cache and shared_cache is not None and cache_lock is not None:
                async with cache_lock:
                    if term in shared_cache:
                        return None
                    shared_cache.add(term)
            if term in self.cache_data["players"]:
                player = self.cache_data["players"][term]
                if message_nickname and message_nickname in player.nicknames:
                    player.nicknames.remove(message_nickname)
                    player.nicknames.insert(0, message_nickname)
                    if not hasattr(player, 'nicknames_sources'):
                        player.nicknames_sources = {}
                    player.nicknames_sources[message_nickname] = "login"
                    player.is_primary = True
                    player.primary_nickname = message_nickname
                elif is_login_event:
                    self._update_player_login_info(player, is_user_id)
                return player
            self.logger.info(f"Searching for player with term: '{term}'")
            account_info = await self.admin.search_player(term)
            if not account_info:
                self.logger.info(f"No account found for term: '{term}'")
                return None
            player = self.admin.convert_to_player(account_info)
            player.is_from_user_id = is_user_id
            player.search_term = term
            if message_nickname and message_nickname in player.nicknames:
                player.nicknames.remove(message_nickname)
                player.nicknames.insert(0, message_nickname)
                if not hasattr(player, 'nicknames_sources'):
                    player.nicknames_sources = {}
                player.nicknames_sources[message_nickname] = "login"
                player.is_primary = True
                player.primary_nickname = message_nickname
            elif is_login_event:
                self._update_player_login_info(player, is_user_id)
            await self._fetch_player_connections(player)
            if not getattr(player, 'is_primary', False):
                self._identify_primary_nickname_from_search_term(player)
            self.cache_data["players"][term] = player
            processing_duration = (datetime.now() - term_start).total_seconds()
            self.perf.record("process_term", processing_duration)
            self.logger.info(f"Processed term '{term}' in {processing_duration:.2f}s")
            return player
        except Exception as e:
            self.logger.error(f"Error processing term '{term}': {str(e)}", exc_info=True)
            return None

    def _identify_primary_nickname_from_search_term(self, player: Player) -> None:
        search_term = getattr(player, 'search_term', None)
        if not search_term or not player.nicknames or getattr(player, 'is_primary', False):
            return
        if hasattr(player, 'associated_ips') and search_term in player.associated_ips:
            nicks = player.associated_ips[search_term]
            if nicks:
                primary_nick = nicks[0]
                if primary_nick in player.nicknames:
                    player.nicknames.remove(primary_nick)
                    player.nicknames.insert(0, primary_nick)
                    if not hasattr(player, 'nicknames_sources'):
                        player.nicknames_sources = {}
                    player.nicknames_sources[primary_nick] = "login"
                    player.is_primary = True
                    player.primary_nickname = primary_nick
        elif hasattr(player, 'associated_hwids') and search_term in player.associated_hwids:
            nicks = player.associated_hwids[search_term]
            if nicks:
                primary_nick = nicks[0]
                if primary_nick in player.nicknames:
                    player.nicknames.remove(primary_nick)
                    player.nicknames.insert(0, primary_nick)
                    if not hasattr(player, 'nicknames_sources'):
                        player.nicknames_sources = {}
                    player.nicknames_sources[primary_nick] = "login"
                    player.is_primary = True
                    player.primary_nickname = primary_nick

    def _update_player_login_info(self, player, is_user_id):
        player.raw_message = "Arrived new player"
        if not player.nicknames:
            return
        primary_nick = player.nicknames[0]
        if not hasattr(player, 'nicknames_sources'):
            player.nicknames_sources = {}
        player.nicknames_sources[primary_nick] = "login"
        if is_user_id:
            player.is_primary = True
            player.primary_nickname = primary_nick

    async def _fetch_player_connections(self, player: Player) -> None:
        identifiers = self._get_player_identifiers(player)
        if not identifiers:
            return
        max_identifiers = min(10, len(identifiers))
        selected_identifiers = identifiers[:max_identifiers]
        connection_tasks = []
        for identifier in selected_identifiers:
            if identifier in self.cache_data["connections"]:
                continue
            connection_tasks.append(
                self.admin.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user, identifier
                )
            )
        if connection_tasks:
            connection_results = await gather_with_concurrency(
                self.max_concurrent,
                *connection_tasks
            )
            all_connections = []
            for i, result in enumerate(connection_results):
                identifier = selected_identifiers[i]
                self.cache_data["connections"][identifier] = result
                all_connections.extend(result)
                self._update_identity_graph(result)
            self._process_player_connections(player, all_connections)

    def _get_player_identifiers(self, player: Player) -> List[str]:
        identifiers = set()
        if player.user_id and player.user_id != "N/A":
            identifiers.add(player.user_id)
        identifiers.update(player.nicknames)
        if hasattr(player, 'associated_ips') and player.associated_ips:
            identifiers.update(ip for ip in player.associated_ips if ip != "N/A")
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            identifiers.update(hwid for hwid in player.associated_hwids if hwid != "N/A")
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

    def _process_player_connections(self, player: Player, connections: List[Dict[str, Any]]) -> None:
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
        player.denied_logins = denied_logins
        if denied_logins and self.status_priority.get(player.status.lower(), 0) < self.status_priority['suspicious']:
            player.status = "suspicious"
            player.ban_counts = max(player.ban_counts, 1)

    @monitor_performance()
    async def scan_nickname(self, nickname: str, complaint_search_term: Optional[str] = None) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting nickname search for: {nickname}")
        try:
            self.complaint_channels = await self.discord.update_complaint_cache(
                self.complaint_channels,
                history_limit=self.cfg.discord.message_history_limit
            )
            player = await self.process_term(nickname)
            if not player:
                self.logger.info(f"No player found for nickname: {nickname}")
                return []
            complaint_links = await self.discord.find_nickname_mentions(
                player.nicknames,
                self.complaint_channels,
                search_term=complaint_search_term
            )
            player.complaint_links = complaint_links
            if complaint_search_term:
                self.logger.info(f"Found {len(complaint_links)} complaints with '{complaint_search_term}'")
            report_data = self.report.generate_nickname_search_report(nickname, player)
            duration = (datetime.now() - start_time).total_seconds()
            self.perf.logger.info(f"Nickname search for '{nickname}' completed in {duration:.2f}s")
            return report_data
        except Exception as e:
            self.logger.error(f"Error in scan_nickname for '{nickname}': {str(e)}", exc_info=True)
            return []
        finally:
            self.cache.save_complaint_cache(self.complaint_channels)

    @monitor_performance()
    async def check_ban_bypasses_raw(self, max_pages: int = 5) -> List[BanBypassCheck]:
        start_time = datetime.now()
        self.logger.info(f"Starting ban bypass check (max {max_pages} pages)")
        connection_cache = {}
        ban_info_cache = {}
        identity_graph = defaultdict(set)
        semaphore = asyncio.Semaphore(self.max_concurrent)
        try:
            complaint_task = asyncio.create_task(
                self.discord.update_complaint_cache(
                    self.complaint_channels,
                    history_limit=self.cfg.discord.message_history_limit
                )
            )
            ban_hits_task = asyncio.create_task(
                self.admin.fetch_ban_hits(max_pages)
            )
            await asyncio.wait([complaint_task, ban_hits_task])
            self.complaint_channels = complaint_task.result()
            ban_hits = ban_hits_task.result()
            if not ban_hits:
                self.logger.info("No ban hits found")
                return []
            unique_ban_hits = self._deduplicate_ban_hits(ban_hits)
            unique_ban_hits_list = list(unique_ban_hits.values())
            self.logger.info(f"Processing {len(unique_ban_hits_list)} unique ban hits (from {len(ban_hits)} total)")
            await self._prefetch_ban_info(unique_ban_hits_list, ban_info_cache)
            identifiers = self._extract_and_fetch_identifiers(
                unique_ban_hits_list,
                connection_cache,
                identity_graph,
                semaphore
            )
            processed_identifiers_lock = asyncio.Lock()
            global_processed_identifiers = set()
            processing_tasks = []
            for hit in unique_ban_hits_list:
                processing_tasks.append(
                    self._process_ban_hit(
                        hit,
                        connection_cache,
                        identity_graph,
                        processed_identifiers_lock,
                        global_processed_identifiers
                    )
                )
            results = await gather_with_concurrency(
                self.max_concurrent,
                *processing_tasks
            )
            ban_bypass_checks = [result for result in results if result]
            refined_checks = self._refine_ban_bypass_checks(ban_bypass_checks)
            duration = (datetime.now() - start_time).total_seconds()
            self.perf.logger.info(
                f"Ban bypass check completed in {duration:.2f}s with {len(refined_checks)} potential bypasses found"
            )
            return refined_checks
        except Exception as e:
            self.logger.error(f"Error in check_ban_bypasses_raw: {str(e)}", exc_info=True)
            return []
        finally:
            self.cache.save_complaint_cache(self.complaint_channels)

    def _deduplicate_ban_hits(self, ban_hits):
        unique_ban_hits = {}
        for hit in ban_hits:
            hit_key = f"{hit.user_id}|{hit.user_name}|{hit.ip_address}|{hit.hwid}"
            if hit_key not in unique_ban_hits:
                unique_ban_hits[hit_key] = hit
        return unique_ban_hits

    async def _prefetch_ban_info(self, ban_hits, ban_info_cache):
        self.logger.info("Pre-fetching ban info for all unique ban hits")
        ban_info_tasks = []
        hits_to_process = []
        for hit in ban_hits:
            if hit.ban_hit_link not in ban_info_cache:
                ban_info_tasks.append(self.admin.fetch_ban_info(hit))
                hits_to_process.append(hit)
        if ban_info_tasks:
            ban_info_results = await gather_with_concurrency(
                self.max_concurrent,
                *ban_info_tasks
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

    async def _extract_and_fetch_identifiers(self, ban_hits, connection_cache, identity_graph, semaphore):
        all_user_ids = {hit.user_id for hit in ban_hits if hit.user_id != "N/A"}
        all_hwids = {hit.hwid for hit in ban_hits if hit.hwid != "N/A" and not hit.hwid_erased}
        all_ips = {hit.ip_address for hit in ban_hits if hit.ip_address != "N/A"}
        self.logger.info(f"Found {len(all_user_ids)} unique user IDs, {len(all_hwids)} HWIDs, {len(all_ips)} IPs")
        async def fetch_connections_cached(term):
            if term == "N/A" or not term:
                return []
            if term in connection_cache:
                return connection_cache[term]
            async with semaphore:
                result = await self.admin.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user, term
                )
                if result:
                    connection_cache[term] = result
                    self._update_identity_graph_local(result, identity_graph)
                else:
                    connection_cache[term] = []
                return connection_cache[term]

        self.logger.info("Pre-fetching connections for primary identifiers")
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
        return {
            'primary': {
                'user_ids': all_user_ids,
                'hwids': all_hwids,
                'ips': all_ips
            },
            'secondary': secondary_identifiers
        }

    def _update_identity_graph_local(self, connections, graph):
        for conn in connections:
            user_name = conn.get("user_name")
            user_id = conn.get("user_id")
            ip = conn.get("ip_address")
            hwid = conn.get("hwid")
            if not user_name or user_name == "N/A":
                continue
            if user_id and user_id != "N/A":
                graph[f"uid:{user_id}"].add(f"name:{user_name}")
                graph[f"name:{user_name}"].add(f"uid:{user_id}")
            if ip and ip != "N/A":
                graph[f"ip:{ip}"].add(f"name:{user_name}")
                graph[f"name:{user_name}"].add(f"ip:{ip}")
            if hwid and hwid != "N/A":
                graph[f"hwid:{hwid}"].add(f"name:{user_name}")
                graph[f"name:{user_name}"].add(f"hwid:{hwid}")
            if ip and ip != "N/A" and hwid and hwid != "N/A":
                graph[f"ip:{ip}"].add(f"hwid:{hwid}")
                graph[f"hwid:{hwid}"].add(f"ip:{ip}")
            if user_id and user_id != "N/A":
                if ip and ip != "N/A":
                    graph[f"uid:{user_id}"].add(f"ip:{ip}")
                    graph[f"ip:{ip}"].add(f"uid:{user_id}")
                if hwid and hwid != "N/A":
                    graph[f"uid:{user_id}"].add(f"hwid:{hwid}")
                    graph[f"hwid:{hwid}"].add(f"uid:{user_id}")

    def _find_secondary_identifiers(self, identity_graph, user_ids, hwids, ips):
        secondary_ips = set()
        secondary_hwids = set()
        secondary_user_ids = set()
        for id_type, ids, prefix in [
            ("user_ids", user_ids, "uid:"),
            ("hwids", hwids, "hwid:"),
            ("ips", ips, "ip:")
        ]:
            for id_value in ids:
                full_id = f"{prefix}{id_value}"
                for connected_id in identity_graph.get(full_id, set()):
                    if connected_id.startswith("ip:") and connected_id[3:] not in ips:
                        secondary_ips.add(connected_id[3:])
                    elif connected_id.startswith("hwid:") and connected_id[5:] not in hwids:
                        secondary_hwids.add(connected_id[5:])
                    elif connected_id.startswith("uid:") and connected_id[4:] not in user_ids:
                        secondary_user_ids.add(connected_id[4:])
        return {
            'ips': secondary_ips,
            'hwids': secondary_hwids,
            'user_ids': secondary_user_ids
        }

    async def _process_ban_hit(self, hit, connection_cache, identity_graph,
                               processed_identifiers_lock, global_processed_identifiers):
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
            related_identifiers = await self._find_hit_related_identifiers(hit, identity_graph)
            seen_connection_ids = set()
            initial_connections = []
            for identifier in related_identifiers:
                for conn in connection_cache.get(identifier, []):
                    conn_id = self._create_connection_id(conn)
                    if conn_id not in seen_connection_ids:
                        seen_connection_ids.add(conn_id)
                        initial_connections.append(conn)
            all_ips, all_hwids = self._extract_hit_identifiers(hit, initial_connections)
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
            banned_player = self.admin.convert_to_player(account_info)
            if hit.banned_user_name and hit.banned_user_name != "N/A":
                banned_user_name = hit.banned_user_name
            else:
                banned_user_name = hit.user_name
            if banned_user_name and banned_user_name != "N/A":
                if banned_user_name in banned_player.nicknames:
                    banned_player.nicknames.remove(banned_user_name)
                banned_player.nicknames.insert(0, banned_user_name)
                banned_player.primary_nickname = banned_user_name
                banned_player.is_primary = True
            bypass_confidence, potential_bypassers = self.analyzer.find_potential_bypassers(
                hit, banned_player, initial_connections
            )
            nickname_to_search = banned_user_name or hit.user_name
            complaint_links = await self.discord.find_nickname_mentions(
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

    async def _find_hit_related_identifiers(self, hit, identity_graph):
        related_identifiers = set()
        if hit.user_id != "N/A":
            related_identifiers.add(hit.user_id)
            for connected_id in identity_graph.get(f"uid:{hit.user_id}", set()):
                if ":" in connected_id:
                    id_type, id_value = connected_id.split(":", 1)
                    if id_value != "N/A" and id_type in ("ip", "hwid", "uid"):
                        related_identifiers.add(id_value)
        if hit.hwid != "N/A" and not hit.hwid_erased:
            related_identifiers.add(hit.hwid)
            for connected_id in identity_graph.get(f"hwid:{hit.hwid}", set()):
                if ":" in connected_id:
                    id_type, id_value = connected_id.split(":", 1)
                    if id_value != "N/A" and id_type in ("ip", "uid"):
                        related_identifiers.add(id_value)
        if hit.ip_address != "N/A":
            related_identifiers.add(hit.ip_address)
            for connected_id in identity_graph.get(f"ip:{hit.ip_address}", set()):
                if ":" in connected_id:
                    id_type, id_value = connected_id.split(":", 1)
                    if id_value != "N/A" and id_type in ("hwid", "uid"):
                        related_identifiers.add(id_value)
        return related_identifiers

    def _create_connection_id(self, conn):
        key_parts = [
            str(conn.get('user_id', '')),
            str(conn.get('time', '')),
            str(conn.get('ip_address', '')),
            str(conn.get('hwid', ''))
        ]
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()

    def _extract_hit_identifiers(self, hit, connections):
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

    def _refine_ban_bypass_checks(self, ban_bypass_checks):
        refined_checks = []
        for check in ban_bypass_checks:
            filtered_bypassers = []
            banned_user_name = check.banned_player.nicknames[0] if check.banned_player.nicknames else ""
            banned_user_id = check.banned_player.user_id if check.banned_player.user_id != "UNKNOWN" else ""
            for bypasser in check.potential_bypassers:
                bypasser_name = bypasser.nicknames[0] if bypasser.nicknames else ""
                bypasser_id = bypasser.user_id if bypasser.user_id != "UNKNOWN" else ""
                if (not bypasser_name or bypasser_name != banned_user_name) and (
                        not bypasser_id or not banned_user_id or bypasser_id != banned_user_id):
                    filtered_bypassers.append(bypasser)
            if filtered_bypassers:
                check.potential_bypassers = filtered_bypassers
                refined_checks.append(check)
            elif check.bypass_confidence in [
                ConfidenceLevel.HWID_MATCH.value,
                ConfidenceLevel.IP_VERY_CLOSE_TIME.value,
                ConfidenceLevel.IP_CLOSE_TIME.value
            ]:
                check.bypass_confidence = ConfidenceLevel.NO_MATCH.value
                check.potential_bypassers = []
                refined_checks.append(check)
        return refined_checks

    def _consolidate_results(self, scan_results):
        if not scan_results:
            return []
        user_id_groups = {}
        no_user_id_players = []
        for result in scan_results:
            message_id = result.message.id
            for player in result.players:
                if player.user_id and player.user_id != "N/A":
                    if player.user_id not in user_id_groups:
                        user_id_groups[player.user_id] = {"players": [], "messages": set()}
                    user_id_groups[player.user_id]["players"].append(player)
                    user_id_groups[player.user_id]["messages"].add(message_id)
                else:
                    no_user_id_players.append((player, message_id))
        player_registry = {}
        message_to_players = defaultdict(set)
        for user_id, data in user_id_groups.items():
            players = data["players"]
            message_ids = data["messages"]
            merged_player = players[0]
            for i in range(1, len(players)):
                self._merge_player_info(merged_player, players[i])
            player_id = f"uid:{user_id}"
            player_registry[player_id] = merged_player
            for message_id in message_ids:
                message_to_players[message_id].add(player_id)
        for player, message_id in no_user_id_players:
            key_parts = []
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
            player_id = hashlib.md5(identifier_string.encode()).hexdigest()
            if player_id not in player_registry:
                player_registry[player_id] = player
            else:
                self._merge_player_info(player_registry[player_id], player)
            message_to_players[message_id].add(player_id)
        consolidated_results = []
        processed_messages = set()
        for result in scan_results:
            message_id = result.message.id
            if message_id in processed_messages:
                continue
            processed_messages.add(message_id)
            message_player_ids = message_to_players[message_id]
            consolidated_players = [player_registry[pid] for pid in message_player_ids]
            consolidated_results.append(
                ScanResult(
                    message=result.message,
                    players=consolidated_players,
                    scan_time=result.scan_time
                )
            )
        self.logger.info(
            f"Consolidated {len(scan_results)} results into {len(consolidated_results)} unique message results"
        )
        return consolidated_results

    def _create_player_identifier(self, player):
        if player.user_id and player.user_id != "N/A":
            return f"uid:{player.user_id}"
        key_parts = []
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

    def _merge_player_info(self, target_player, source_player):
        if not hasattr(target_player, 'nicknames_sources'):
            target_player.nicknames_sources = {}
        if not hasattr(target_player, 'is_from_user_id'):
            target_player.is_from_user_id = False
        if hasattr(source_player, 'is_from_user_id') and source_player.is_from_user_id:
            target_player.is_from_user_id = True
        source_is_primary = hasattr(source_player, 'is_primary') and source_player.is_primary
        target_is_primary = hasattr(target_player, 'is_primary') and target_player.is_primary
        source_primary = source_player.primary_nickname if source_player.nicknames else None
        if source_is_primary and source_primary and source_primary in source_player.nicknames:
            if source_primary not in target_player.nicknames:
                target_player.nicknames.append(source_primary)
            target_player.nicknames.remove(source_primary)
            target_player.nicknames.insert(0, source_primary)
            target_player.nicknames_sources[source_primary] = "login"
            target_player.is_primary = True
            target_player.primary_nickname = source_primary
            if hasattr(source_player, 'search_term'):
                target_player.search_term = source_player.search_term
        source_is_login_event = False
        if hasattr(source_player, 'raw_message') and source_player.raw_message:
            source_is_login_event = "Arrived new player" in source_player.raw_message
            if source_is_login_event and (not hasattr(target_player, 'raw_message') or not target_player.raw_message):
                target_player.raw_message = source_player.raw_message
        for nickname in source_player.nicknames:
            if source_is_primary and source_primary and nickname == source_primary:
                continue
            is_login_event = source_is_login_event
            if hasattr(source_player, 'is_from_user_id') and source_player.is_from_user_id and nickname == \
                    source_player.nicknames[0]:
                is_login_event = True
            if is_login_event:
                target_player.nicknames_sources[nickname] = "login"
                if nickname in target_player.nicknames:
                    target_player.nicknames.remove(nickname)
                if target_is_primary and hasattr(target_player, 'primary_nickname'):
                    target_player.nicknames.insert(1, nickname)
                else:
                    target_player.nicknames.insert(0, nickname)
            elif nickname not in target_player.nicknames:
                target_player.nicknames_sources[nickname] = "other"
                target_player.nicknames.append(nickname)
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
