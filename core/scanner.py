import asyncio
import functools
import hashlib
import heapq
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
        self.connections_cache = {}

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

            existing_ban_reasons = set()
            for ban_info in target_player.ban_reasons:
                if isinstance(ban_info, dict) and "reason" in ban_info and "username" in ban_info:
                    existing_ban_reasons.add((ban_info["reason"], ban_info["username"]))
                elif isinstance(ban_info, str):
                    existing_ban_reasons.add((ban_info, "Unknown"))

            # Add new ban reasons
            for ban_info in source_player.ban_reasons:
                if isinstance(ban_info, dict) and "reason" in ban_info and "username" in ban_info:
                    key = (ban_info["reason"], ban_info["username"])
                    if key not in existing_ban_reasons:
                        target_player.ban_reasons.append(ban_info)
                        existing_ban_reasons.add(key)
                elif isinstance(ban_info, str):
                    key = (ban_info, "Unknown")
                    if key not in existing_ban_reasons:
                        target_player.ban_reasons.append({
                            "reason": ban_info,
                            "username": "Unknown"
                        })
                        existing_ban_reasons.add(key)

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
        max_depth = getattr(self.cfg.scan, 'bypass_search_max_depth', 2)
        self.logger.info(f"Starting Ban Bypass Check, fetching up to {max_pages} pages with max depth {max_depth}...")
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
            self.logger.info(f"Processing {len(ban_hit_connections)} ban hits with max depth {max_depth}")
            processed_terms = set()
            self.connections_cache = {}
            ban_hit_connections.sort(key=lambda x: x.get("time", ""), reverse=True)
            batch_size = min(self.max_concurrent // 2, 10)
            results = []
            for i in range(0, len(ban_hit_connections), batch_size):
                batch = ban_hit_connections[i:i + batch_size]
                self.logger.info(
                    f"Processing batch {i // batch_size + 1}/{(len(ban_hit_connections) + batch_size - 1) // batch_size}")
                progress_stats = defaultdict(int)
                batch_tasks = []
                for ban_hit in batch:
                    task = asyncio.create_task(self._process_ban_hit(
                        ban_hit,
                        max_depth,
                        processed_terms,
                        progress_stats
                    ))
                    batch_tasks.append(task)
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                valid_results = []
                for result in batch_results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Error in batch processing: {str(result)}")
                        continue
                    if result:
                        valid_results.append(result)
                results.extend(valid_results)
                self.logger.info(f"Batch {i // batch_size + 1} stats: " +
                                 f"processed={progress_stats['processed']}, " +
                                 f"hwid_matches={progress_stats.get('hwid_matches', 0)}, " +
                                 f"ip_matches={progress_stats.get('ip_matches', 0)}")
                if i + batch_size < len(ban_hit_connections):
                    await asyncio.sleep(0.5)
            cache_hits = sum(1 for term in processed_terms if term in self.connections_cache)
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(
                f"Ban Bypass Check completed in {duration:.2f}s: processed {len(ban_hit_connections)} ban hits, "
                f"found {len(results)} results with depth {max_depth}, "
                f"processed {len(processed_terms)} unique terms, cache hits: {cache_hits}"
            )
            self.connections_cache.clear()
            return results
        except Exception as e:
            self.logger.error(f"Error during ban bypass check: {str(e)}", exc_info=True)
            return []
        finally:
            self.cache.save_complaint_cache(self.complaint_channels)

    async def _process_ban_hit(self, ban_hit, max_depth, processed_terms, progress_stats):
        try:
            progress_stats['processed'] += 1
            ban_id = ban_hit.get("connection_id", "") or ban_hit.get("ban_hits_link", "")
            ban_hit_time = datetime.strptime(ban_hit["time"], "%Y-%m-%d %H:%M:%S")
            user_id = ban_hit.get("user_id")
            if not user_id or user_id == "N/A":
                return None
            ban_hits_link = ban_hit.get("ban_hits_link")
            async with asyncio.Lock():
                if ban_id and ban_id in processed_terms:
                    return None
                if ban_id:
                    processed_terms.add(ban_id)
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
            self.logger.info(f"Processing ban hit for user '{banned_user_name}' (ID: {user_id})")
            connections = await self._gather_connections(
                user_id,
                hwid,
                ip_address,
                max_depth,
                processed_terms,
                banned_user_name
            )
            hwid_match_users = set()
            if hwid and hwid != "N/A":
                for conn in connections:
                    if conn.get("hwid") == hwid and conn.get("user_name") != banned_user_name:
                        hwid_match_users.add(conn.get("user_name"))
                if hwid_match_users:
                    progress_stats['hwid_matches'] = progress_stats.get('hwid_matches', 0) + 1
                    self.logger.info(f"HWID match found for {banned_user_name}: {', '.join(sorted(hwid_match_users))}")
            account_info = self.admin_panel.aggregate_single_user_info(connections)
            bypass_reason = self.analyzer.confidence_levels['no_match']
            bypass_user_names = []
            if hwid_match_users:
                bypass_reason = self.analyzer.confidence_levels['hwid_match']
                bypass_user_names = sorted(hwid_match_users)
            elif ip_address and ip_address != "N/A":
                time_suspected_users = self._check_time_based_bypass(ban_hit_time, ip_address, banned_user_name,
                                                                     connections)
                if time_suspected_users:
                    time_diff_minutes = self._get_minimum_time_difference(ban_hit_time, time_suspected_users,
                                                                          connections)
                    if time_diff_minutes <= self.analyzer.very_close_time_threshold_minutes:
                        bypass_reason = self.analyzer.confidence_levels['ip_very_close_time']
                    elif time_diff_minutes <= self.analyzer.close_time_threshold_minutes:
                        bypass_reason = self.analyzer.confidence_levels['ip_close_time']
                    elif time_diff_minutes <= self.analyzer.moderate_time_threshold_minutes:
                        bypass_reason = self.analyzer.confidence_levels['ip_moderate_time']
                    elif time_diff_minutes <= self.analyzer.distant_time_threshold_minutes:
                        bypass_reason = self.analyzer.confidence_levels['ip_distant_time']
                    else:
                        bypass_reason = self.analyzer.confidence_levels['ip_match']
                    bypass_user_names = sorted(set(time_suspected_users))
                    progress_stats['ip_matches'] = progress_stats.get('ip_matches', 0) + 1
                elif ip_address in account_info.get("associated_ips", {}):
                    ip_nicks = set(account_info["associated_ips"][ip_address]) - {banned_user_name}
                    if ip_nicks:
                        bypass_reason = self.analyzer.confidence_levels['ip_match']
                        bypass_user_names = sorted(ip_nicks)
                        progress_stats['ip_matches'] = progress_stats.get('ip_matches', 0) + 1
            bypass_success_status = self._determine_bypass_success(connections, bypass_user_names, ban_time_str, hwid,
                                                                   ip_address)
            player = self.admin.convert_to_player(account_info)
            player.hwid_erased = hwid_erased
            complaint_task = asyncio.create_task(self.discord.find_nickname_mentions(
                [banned_user_name] + bypass_user_names,
                self.complaint_channels
            ))
            complaint_links = await complaint_task
            has_meaningful_result = (
                    bypass_reason != self.analyzer.confidence_levels['no_match'] or
                    bypass_user_names or
                    hwid_erased or
                    complaint_links
            )
            if not has_meaningful_result:
                self.logger.info(f"No meaningful bypass detected for {banned_user_name}")
                return None
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
                "bypass_success_status": bypass_success_status,
                "hwid_erased": hwid_erased,
                "search_depth": max_depth,
                "connections_analyzed": len(connections),
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
                f"Ban hit for {banned_user_name}: Confidence: {bypass_reason}, " +
                f"Bypass status: {bypass_success_status}, " +
                f"Potential bypassers: {', '.join(bypass_user_names) if bypass_user_names else 'None'}, " +
                f"Analyzed {len(connections)} connections"
            )
            return report
        except Exception as e:
            self.logger.error(f"Error processing ban hit {ban_hit.get('ban_hits_link')}: {str(e)}", exc_info=True)
            return None

    async def _gather_connections(self, user_id, hwid, ip_address, max_depth, processed_terms,
                                  banned_user_name):
        search_processed = set()
        priority_queue = []
        if user_id and user_id != "N/A":
            heapq.heappush(priority_queue, (0, 1, "user_id", user_id))
            search_processed.add(user_id)
        if hwid and hwid != "N/A":
            heapq.heappush(priority_queue, (0, 2, "hwid", hwid))
            search_processed.add(hwid)
        if ip_address and ip_address != "N/A":
            heapq.heappush(priority_queue, (0, 3, "ip", ip_address))
            search_processed.add(ip_address)
        all_connections = []
        max_by_type_depth = {
            "user_id": {0: 100, 1: 50, 2: 30, 3: 20},
            "hwid": {0: 100, 1: 40, 2: 20, 3: 10},
            "ip": {0: 50, 1: 30, 2: 15, 3: 5},
            "username": {0: 30, 1: 20, 2: 10, 3: 5}
        }
        active_tasks = {}
        while priority_queue:
            batch = []
            batch_size = min(5, len(priority_queue))
            for _ in range(batch_size):
                if not priority_queue:
                    break
                item = heapq.heappop(priority_queue)
                depth, type_priority, id_type, identifier = item
                if depth > max_depth:
                    continue
                batch.append((depth, type_priority, id_type, identifier))
            fetch_tasks = []
            for depth, type_priority, id_type, identifier in batch:
                if identifier in active_tasks:
                    continue
                if identifier in self.connections_cache:
                    connections = self.connections_cache[identifier]
                    await self._process_connections_for_queue(
                        connections, identifier, depth, priority_queue,
                        search_processed, processed_terms, all_connections,
                        max_by_type_depth
                    )
                else:
                    task = self._fetch_and_process_connections(
                        identifier, depth, priority_queue, search_processed,
                        processed_terms, all_connections, max_by_type_depth,
                        banned_user_name
                    )
                    active_tasks[identifier] = asyncio.create_task(task)
                    fetch_tasks.append(active_tasks[identifier])
            if fetch_tasks:
                await asyncio.gather(*fetch_tasks, return_exceptions=True)
                for depth, _, _, identifier in batch:
                    if identifier in active_tasks:
                        del active_tasks[identifier]
            await asyncio.sleep(0)
        if active_tasks:
            await asyncio.gather(*active_tasks.values(), return_exceptions=True)
        return all_connections

    async def _fetch_and_process_connections(self, identifier, depth, priority_queue, search_processed,
                                             processed_terms, all_connections, max_by_type_depth,
                                             banned_user_name):
        try:
            connections = await self.admin.fetch_with_rate_limit(
                self.admin_panel.fetch_connections_for_user,
                identifier
            )
            self.connections_cache[identifier] = connections or []
            await self._process_connections_for_queue(
                connections, identifier, depth, priority_queue,
                search_processed, processed_terms, all_connections,
                max_by_type_depth
            )
            return connections or []
        except Exception as e:
            self.logger.error(f"Error fetching connections for {identifier}: {e}")
            return []

    async def _process_connections_for_queue(self, connections, identifier, depth, priority_queue,
                                             search_processed, processed_terms, all_connections,
                                             max_by_type_depth):
        if not connections:
            return
        depth_limit = max_by_type_depth.get(identifier, {}).get(depth, 10)
        limited_connections = connections[:depth_limit]
        all_connections.extend(limited_connections)
        if depth >= self.cfg.scan.bypass_search_max_depth:
            return
        next_depth = depth + 1
        new_identifiers = []
        banned_identifiers = []
        for conn in limited_connections:
            status = conn.get("status", "")
            if "Banned" in status or "Denied" in status:
                user_name = conn.get("user_name")
                user_id = conn.get("user_id")
                conn_hwid = conn.get("hwid")
                conn_ip = conn.get("ip_address")
                if user_id and user_id != "N/A" and user_id not in search_processed:
                    banned_identifiers.append((1, "user_id", user_id))
                if conn_hwid and conn_hwid != "N/A" and conn_hwid not in search_processed:
                    banned_identifiers.append((2, "hwid", conn_hwid))
                if conn_ip and conn_ip != "N/A" and conn_ip not in search_processed:
                    banned_identifiers.append((3, "ip", conn_ip))
                if user_name and user_name != "N/A" and user_name not in search_processed:
                    banned_identifiers.append((4, "username", user_name))
        for conn in limited_connections:
            user_name = conn.get("user_name")
            user_id = conn.get("user_id")
            conn_hwid = conn.get("hwid")
            conn_ip = conn.get("ip_address")
            if user_id and user_id != "N/A" and user_id not in search_processed:
                new_identifiers.append((1, "user_id", user_id))
            if conn_hwid and conn_hwid != "N/A" and conn_hwid not in search_processed:
                new_identifiers.append((2, "hwid", conn_hwid))
            if conn_ip and conn_ip != "N/A" and conn_ip not in search_processed:
                new_identifiers.append((3, "ip", conn_ip))
            if user_name and user_name != "N/A" and user_name not in search_processed:
                new_identifiers.append((4, "username", user_name))
        for type_priority, id_type, new_id in banned_identifiers:
            async with asyncio.Lock():
                if new_id not in processed_terms:
                    processed_terms.add(new_id)
            if new_id not in search_processed:
                search_processed.add(new_id)
                effective_depth = max(0, next_depth - 0.5)
                heapq.heappush(priority_queue, (effective_depth, type_priority, id_type, new_id))
        for type_priority, id_type, new_id in new_identifiers:
            async with asyncio.Lock():
                if new_id not in processed_terms:
                    processed_terms.add(new_id)
            if new_id not in search_processed:
                search_processed.add(new_id)
                heapq.heappush(priority_queue, (next_depth, type_priority, id_type, new_id))

    def _get_minimum_time_difference(self, ban_hit_time, suspected_users, connections):
        min_diff = float('inf')
        for conn in connections:
            if conn.get("user_name") in suspected_users:
                try:
                    conn_time = datetime.strptime(conn.get("time", ""), "%Y-%m-%d %H:%M:%S")
                    diff_minutes = abs((conn_time - ban_hit_time).total_seconds() / 60.0)
                    min_diff = min(min_diff, diff_minutes)
                except (ValueError, TypeError):
                    pass
        return min_diff if min_diff != float('inf') else 60

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

    def _determine_bypass_success(self, connections, bypass_user_names, ban_time_str, banned_hwid, banned_ip):
        if not bypass_user_names or not connections:
            return "Unknown"
        try:
            ban_time = datetime.strptime(ban_time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "Unknown"
        successful_logins = []
        unsuccessful_logins = []
        for conn in connections:
            user_name = conn.get("user_name", "")
            if user_name not in bypass_user_names:
                continue
            conn_time_str = conn.get("time", "")
            if not conn_time_str:
                continue
            try:
                conn_time = datetime.strptime(conn_time_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if conn_time <= ban_time:
                continue
            status = conn.get("status", "")
            if "Denied: Banned" in status:
                unsuccessful_logins.append(conn)
            elif "Accepted" in status:
                successful_logins.append(conn)
        if successful_logins:
            hwid_changed = any(conn.get("hwid", "") != banned_hwid for conn in successful_logins)
            ip_changed = any(conn.get("ip_address", "") != banned_ip for conn in successful_logins)
            if hwid_changed:
                return "Successful Bypass"
            elif ip_changed:
                return "Possibly Successful Bypass"
            else:
                return "Unknown"
        elif unsuccessful_logins:
            return "Unsuccessful Bypass"
        else:
            return "Unknown"
