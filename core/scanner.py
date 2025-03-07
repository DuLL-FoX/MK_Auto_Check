import asyncio
import functools
import logging
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Set

from config_system import get_config
from core.analyzer import PlayerAnalyzer
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
    async def scan_ban_bypasses(self, max_pages: int = 5) -> List[Dict[str, Any]]:
        start_time = datetime.now()
        self.logger.info(f"Starting Ban Bypass Check, fetching up to {max_pages} pages...")

        try:
            self.complaint_channels = await self.discord.update_complaint_cache(
                self.complaint_channels,
                history_limit=self.cfg.discord.message_history_limit
            )

            ban_hit_connections = await asyncio.to_thread(
                self.admin_panel.fetch_ban_hit_connections,
                max_pages=max_pages
            )

            if not ban_hit_connections:
                self.logger.info("No ban hit connections found.")
                return []

            self.logger.info(f"Processing {len(ban_hit_connections)} ban hits")

            tasks = []
            for ban_hit in ban_hit_connections:
                tasks.append(self._process_ban_hit(ban_hit))

            ban_hit_results = await gather_with_concurrency(
                self.max_concurrent,
                *tasks
            )

            report_data = [result for result in ban_hit_results if result]

            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(
                f"Ban Bypass Check completed in {duration:.2f}s: processed {len(ban_hit_connections)} ban hits, "
                f"found {len(report_data)} results"
            )

            return report_data
        except Exception as e:
            self.logger.error(f"Error during ban bypass check: {str(e)}", exc_info=True)
            return []
        finally:
            self.cache.save_complaint_cache(self.complaint_channels)

    async def _process_ban_hit(self, ban_hit: Dict[str, str]) -> Optional[Dict[str, Any]]:
        try:
            ban_hit_time = datetime.strptime(ban_hit["time"], "%Y-%m-%d %H:%M:%S")
            user_id = ban_hit.get("user_id")
            if not user_id or user_id == "N/A":
                return None

            ban_hits_link = ban_hit.get("ban_hits_link")

            ban_info = await self.admin.fetch_with_rate_limit(
                self.admin_panel.fetch_ban_info,
                ban_hits_link
            )

            banned_user_name = ban_info.get("banned_user_name") or ban_hit.get("user_name", "")
            user_id = ban_info.get("user_id") or user_id
            ip_address = ban_info.get("ip_address") or ban_hit.get("ip_address", "")
            hwid = ban_info.get("hwid") or ban_hit.get("hwid", "")
            hwid_erased = not hwid or hwid.strip() == ""

            ban_time_str = ban_info.get("ban_time", ban_hit["time"])
            ban_expires_str = ban_info.get("expires", ban_hit["time"])

            tasks = []
            if user_id and user_id != "N/A":
                tasks.append(self.admin.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user,
                    user_id
                ))
            if hwid and hwid != "N/A":
                tasks.append(self.admin.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user,
                    hwid
                ))
            if ip_address and ip_address != "N/A":
                tasks.append(self.admin.fetch_with_rate_limit(
                    self.admin_panel.fetch_connections_for_user,
                    ip_address
                ))

            connections_results = await gather_with_concurrency(
                self.max_concurrent,
                *tasks
            )

            connections = []
            for res in connections_results:
                if res:
                    connections.extend(res)

            account_info = self.admin_panel.aggregate_single_user_info(connections)

            bypass_reason = ConfidenceLevel.NO_MATCH.value
            bypass_user_names = []

            if hwid and hwid != "N/A" and hwid in account_info.get("associated_hwids", {}):
                hwid_nicks = account_info["associated_hwids"][hwid]
                if len(set(hwid_nicks)) > 1:
                    bypass_reason = ConfidenceLevel.HWID_MATCH.value
                    bypass_user_names = sorted(set(hwid_nicks) - {banned_user_name})

            if bypass_reason == ConfidenceLevel.NO_MATCH.value and ip_address and ip_address != "N/A" and ip_address in account_info.get(
                    "associated_ips", {}):
                time_suspected_users = self._check_time_based_bypass(ban_hit_time, ip_address, banned_user_name,
                                                                     connections)

                if time_suspected_users:
                    bypass_reason = ConfidenceLevel.IP_CLOSE_TIME.value
                    bypass_user_names = sorted(set(time_suspected_users))
                else:
                    ip_nicks = account_info["associated_ips"][ip_address]
                    if len(set(ip_nicks)) > 1:
                        bypass_reason = ConfidenceLevel.IP_MATCH.value
                        bypass_user_names = sorted(set(ip_nicks) - {banned_user_name})

            player = self.admin.convert_to_player(account_info)
            player.hwid_erased = hwid_erased

            complaint_links = await self.discord.find_nickname_mentions(
                [banned_user_name] + bypass_user_names,
                self.complaint_channels
            )

            report = {
                "message_id": "BanBypassCheck",
                "message_link": ban_hits_link,
                "author_name": banned_user_name,
                "author_id": user_id,
                "scan_time": datetime.now().isoformat(),
                "ban_time": ban_time_str,
                "ban_expires": ban_expires_str,
                "ban_bypass_confidence": bypass_reason,
                "bypass_user_names": bypass_user_names,
                "hwid_erased": hwid_erased,
                "results": [{
                    "initial_account": account_info,
                    "complaint_links": complaint_links,
                    "nicknames": player.nicknames,
                    "hwid_erased": hwid_erased,
                    "banned_user_name": banned_user_name,
                    "ip_address": ip_address,
                    "hwid": hwid
                }]
            }

            self.logger.info(
                f"Ban hit for {banned_user_name}: Confidence: {bypass_reason}, "
                f"Potential bypassers: {', '.join(bypass_user_names) if bypass_user_names else 'None'}"
            )

            return report
        except Exception as e:
            self.logger.error(f"Error processing ban hit {ban_hit.get('ban_hits_link')}: {str(e)}", exc_info=True)
            return None

    def _check_time_based_bypass(self, ban_hit_time: datetime, ip_address: str, banned_user_name: str,
                                 connections: List[Dict]) -> List[str]:
        time_suspected_users = []
        if ip_address == "N/A":
            return time_suspected_users

        try:
            for conn in connections:
                if conn.get("ip_address") == ip_address and conn.get("user_name") != banned_user_name:
                    conn_time = conn.get("time", "")
                    if not conn_time:
                        continue

                    try:
                        conn_dt = datetime.strptime(conn_time, "%Y-%m-%d %H:%M:%S")
                        diff_minutes = abs((conn_dt - ban_hit_time).total_seconds() / 60.0)

                        if 5 <= diff_minutes <= 10:
                            time_suspected_users.append(conn.get("user_name"))
                    except ValueError:
                        self.logger.warning(f"Invalid time format: {conn_time}")
        except Exception as ex:
            self.logger.error(f"Error processing time difference for ban hit: {str(ex)}", exc_info=True)

        return time_suspected_users
