from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple, Set

from config_system import get_config
from models.ban_hit import BanHit
from models.player import Player
from models.verdict import ConfidenceLevel


class PlayerAnalyzer:
    def __init__(self) -> None:
        cfg = get_config()
        self.confidence_levels = {
            'hwid_match': ConfidenceLevel.HWID_MATCH.value,
            'ip_very_close_time': ConfidenceLevel.IP_VERY_CLOSE_TIME.value,
            'ip_close_time': ConfidenceLevel.IP_CLOSE_TIME.value,
            'ip_moderate_time': ConfidenceLevel.IP_MODERATE_TIME.value,
            'ip_distant_time': ConfidenceLevel.IP_DISTANT_TIME.value,
            'ip_match': ConfidenceLevel.IP_MATCH.value,
            'no_match': ConfidenceLevel.NO_MATCH.value
        }
        self.very_close_time_threshold_minutes = 5
        self.close_time_threshold_minutes = 10
        self.moderate_time_threshold_minutes = 30
        self.distant_time_threshold_minutes = 60

    def group_players_by_nicknames(self, players: List[Player]) -> List[Player]:
        if not players:
            return []
        nickname_to_player_indices = defaultdict(list)
        for i, player in enumerate(players):
            for nickname in player.nicknames:
                nickname_to_player_indices[nickname].append(i)
        visited = set()
        groups = []
        for i, player in enumerate(players):
            if i in visited:
                continue
            group = [i]
            visited.add(i)
            queue = set(player.nicknames)
            processed = set()
            while queue:
                nickname = queue.pop()
                processed.add(nickname)
                for player_idx in nickname_to_player_indices.get(nickname, []):
                    if player_idx not in visited:
                        visited.add(player_idx)
                        group.append(player_idx)
                        new_nicknames = set(players[player_idx].nicknames) - processed
                        queue.update(new_nicknames)
            groups.append(group)
        merged_players = []
        for group in groups:
            if len(group) == 1:
                merged_players.append(players[group[0]])
            else:
                merged_players.append(self._merge_player_group([players[idx] for idx in group]))
        return merged_players

    def _merge_player_group(self, player_group: List[Player]) -> Player:
        if not player_group:
            return None
        base_player = player_group[0]
        all_nicknames = set(base_player.nicknames)
        all_hwids = dict(base_player.associated_hwids)
        all_ips = dict(base_player.associated_ips)
        all_shared_hwid_nicks = set(base_player.shared_hwid_nicknames)
        max_ban_count = base_player.ban_counts
        all_ban_reasons = set(base_player.ban_reasons)
        all_login_priorities = dict(getattr(base_player, 'login_priorities', {}))
        all_login_timestamps = dict(getattr(base_player, 'login_timestamps', {}))
        raw_message = getattr(base_player, 'raw_message', None)
        status_priority = {'banned': 3, 'suspicious': 2, 'clean': 1, 'unknown': 0}
        current_status_priority = status_priority.get(base_player.status.lower(), 0)
        for other_player in player_group[1:]:
            all_nicknames.update(other_player.nicknames)
            for hwid, nicks in other_player.associated_hwids.items():
                if hwid in all_hwids:
                    combined_nicks = set(all_hwids[hwid])
                    combined_nicks.update(nicks)
                    all_hwids[hwid] = list(combined_nicks)
                else:
                    all_hwids[hwid] = nicks
            for ip, nicks in other_player.associated_ips.items():
                if ip in all_ips:
                    combined_nicks = set(all_ips[ip])
                    combined_nicks.update(nicks)
                    all_ips[ip] = list(combined_nicks)
                else:
                    all_ips[ip] = nicks
            all_shared_hwid_nicks.update(other_player.shared_hwid_nicknames)
            max_ban_count = max(max_ban_count, other_player.ban_counts)
            all_ban_reasons.update(other_player.ban_reasons)
            other_status_priority = status_priority.get(other_player.status.lower(), 0)
            if other_status_priority > current_status_priority:
                base_player.status = other_player.status
                current_status_priority = other_status_priority
            other_login_priorities = getattr(other_player, 'login_priorities', {})
            for nick, priority in other_login_priorities.items():
                if nick not in all_login_priorities or priority < all_login_priorities[nick]:
                    all_login_priorities[nick] = priority
            other_login_timestamps = getattr(other_player, 'login_timestamps', {})
            for nick, timestamp in other_login_timestamps.items():
                if nick not in all_login_timestamps or timestamp > all_login_timestamps[nick]:
                    all_login_timestamps[nick] = timestamp
            other_raw_message = getattr(other_player, 'raw_message', None)
            if other_raw_message and "Arrived new player" in other_raw_message:
                raw_message = other_raw_message
        base_player.nicknames = list(all_nicknames)
        base_player.associated_hwids = all_hwids
        base_player.associated_ips = all_ips
        base_player.shared_hwid_nicknames = list(all_shared_hwid_nicks)
        base_player.ban_counts = max_ban_count
        base_player.ban_reasons = list(all_ban_reasons)
        base_player.login_priorities = all_login_priorities
        base_player.login_timestamps = all_login_timestamps
        base_player.raw_message = raw_message
        login_nicks = [nick for nick, priority in all_login_priorities.items() if
                       priority == 1 and nick in all_nicknames]
        other_nicks = [nick for nick in base_player.nicknames if nick not in login_nicks]
        if login_nicks and all_login_timestamps:
            login_nicks.sort(key=lambda n: all_login_timestamps.get(n, ""), reverse=True)
        base_player.nicknames = login_nicks + other_nicks
        return base_player

    def find_potential_bypassers(self, ban_hit: BanHit, banned_player: Player, connections: List[Dict[str, Any]]) -> \
            Tuple[str, List[Player]]:
        potential_bypassers: List[Player] = []
        bypasser_nicknames: Set[str] = set()
        highest_confidence = self.confidence_levels['no_match']

        banned_user_name = ban_hit.user_name
        all_banned_hwids, all_banned_ips = self._extract_banned_identifiers(ban_hit, banned_player)

        connection_maps = self._build_connection_maps(connections, banned_user_name)
        hwid_to_users = connection_maps['hwid_to_users']
        ip_to_users = connection_maps['ip_to_users']
        user_hwids = connection_maps['user_hwids']
        user_ips = connection_maps['user_ips']
        user_status = connection_maps['user_status']
        user_connections = connection_maps['user_connections']

        hwid_matched_users = self._find_hwid_matched_users(all_banned_hwids, hwid_to_users)

        ban_time = ban_hit.time if ban_hit.time else ban_hit.ban_time

        very_close_time_matches = set()
        close_time_matches = set()
        moderate_time_matches = set()
        distant_time_matches = set()

        if ban_time:
            user_times = self._build_user_time_map(user_connections)

            very_close_time_matches = self._find_time_based_matches(
                ban_time, all_banned_ips, ip_to_users, user_times, 0, self.very_close_time_threshold_minutes
            )

            close_time_matches = self._find_time_based_matches(
                ban_time, all_banned_ips, ip_to_users, user_times,
                self.very_close_time_threshold_minutes, self.close_time_threshold_minutes
            )

            moderate_time_matches = self._find_time_based_matches(
                ban_time, all_banned_ips, ip_to_users, user_times,
                self.close_time_threshold_minutes, self.moderate_time_threshold_minutes
            )

            distant_time_matches = self._find_time_based_matches(
                ban_time, all_banned_ips, ip_to_users, user_times,
                self.moderate_time_threshold_minutes, self.distant_time_threshold_minutes
            )

        ip_matched_users = self._find_ip_matched_users(all_banned_ips, ip_to_users)

        # HWID matches (100% confidence)
        for nick in hwid_matched_users:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                highest_confidence = self.confidence_levels['hwid_match']

        # Very close time IP matches (80-90% confidence)
        for nick in very_close_time_matches:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                if highest_confidence == self.confidence_levels['no_match']:
                    highest_confidence = self.confidence_levels['ip_very_close_time']

        # Close time IP matches (60-70% confidence)
        for nick in close_time_matches:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                if highest_confidence in [self.confidence_levels['no_match'], self.confidence_levels['ip_match']]:
                    highest_confidence = self.confidence_levels['ip_close_time']

        # Moderate time IP matches (40-50% confidence)
        for nick in moderate_time_matches:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                if highest_confidence in [self.confidence_levels['no_match'], self.confidence_levels['ip_match']]:
                    highest_confidence = self.confidence_levels['ip_moderate_time']

        # Distant time IP matches (20-30% confidence)
        for nick in distant_time_matches:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                if highest_confidence in [self.confidence_levels['no_match'], self.confidence_levels['ip_match']]:
                    highest_confidence = self.confidence_levels['ip_distant_time']

        # Simple IP matches (10-20% confidence)
        for nick in ip_matched_users:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser = self._create_bypasser_player(nick, user_status.get(nick) == "banned")
                potential_bypassers.append(bypasser)
                bypasser_nicknames.add(nick)
                if highest_confidence == self.confidence_levels['no_match']:
                    highest_confidence = self.confidence_levels['ip_match']

        for bypasser in potential_bypassers:
            self._enrich_bypasser_player(bypasser, user_connections, hwid_to_users, ip_to_users)

        return highest_confidence, potential_bypassers

    def _extract_banned_identifiers(self, ban_hit: BanHit, banned_player: Player) -> Tuple[Set[str], Set[str]]:
        all_banned_hwids = {hwid for hwid in banned_player.associated_hwids if hwid != "N/A"}
        if ban_hit.hwid != "N/A" and not ban_hit.hwid_erased:
            all_banned_hwids.add(ban_hit.hwid)
        all_banned_ips = {ip for ip in banned_player.associated_ips if ip != "N/A"}
        if ban_hit.ip_address != "N/A":
            all_banned_ips.add(ban_hit.ip_address)
        return all_banned_hwids, all_banned_ips

    def _build_connection_maps(self, connections: List[Dict[str, Any]], banned_user_name: str) -> Dict[str, Any]:
        hwid_to_users = defaultdict(set)
        ip_to_users = defaultdict(set)
        user_hwids = defaultdict(set)
        user_ips = defaultdict(set)
        user_status = {}
        user_connections = defaultdict(list)

        for conn in connections:
            user_name = conn.get("user_name", "")
            conn_hwid = conn.get("hwid", "N/A")
            conn_ip = conn.get("ip_address", "N/A")
            conn_status = conn.get("status", "")

            if not user_name or user_name == banned_user_name:
                continue

            user_connections[user_name].append(conn)

            if conn_hwid != "N/A":
                hwid_to_users[conn_hwid].add(user_name)
                user_hwids[user_name].add(conn_hwid)

            if conn_ip != "N/A":
                ip_to_users[conn_ip].add(user_name)
                user_ips[user_name].add(conn_ip)

            if "Denied: Banned" in conn_status:
                user_status[user_name] = "banned"

        return {
            'hwid_to_users': hwid_to_users,
            'ip_to_users': ip_to_users,
            'user_hwids': user_hwids,
            'user_ips': user_ips,
            'user_status': user_status,
            'user_connections': user_connections
        }

    def _find_hwid_matched_users(self, all_banned_hwids: Set[str], hwid_to_users: Dict[str, Set[str]]) -> Set[str]:
        hwid_matched_users = set()
        for hwid in all_banned_hwids:
            hwid_matched_users.update(hwid_to_users.get(hwid, set()))
        return hwid_matched_users

    def _find_ip_matched_users(self, all_banned_ips: Set[str], ip_to_users: Dict[str, Set[str]]) -> Set[str]:
        ip_matched_users = set()
        for ip in all_banned_ips:
            ip_matched_users.update(ip_to_users.get(ip, set()))
        return ip_matched_users

    def _build_user_time_map(self, user_connections: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[datetime]]:
        user_times = {}
        for user, conn_list in user_connections.items():
            times = []
            for conn in conn_list:
                time_str = conn.get("time", "")
                if time_str:
                    try:
                        conn_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                        times.append(conn_time)
                    except ValueError:
                        pass
            if times:
                user_times[user] = times
        return user_times

    def _find_time_based_matches(self, ban_time: datetime, all_ips: Set[str],
                                 ip_to_users: Dict[str, Set[str]], time_cache: Dict[str, List[datetime]],
                                 min_minutes: int, max_minutes: int) -> Set[str]:
        time_matches = set()
        min_seconds = min_minutes * 60
        max_seconds = max_minutes * 60

        for ip in all_ips:
            if ip == "N/A" or ip not in ip_to_users:
                continue

            for username in ip_to_users[ip]:
                if username not in time_cache:
                    continue

                for conn_time in time_cache[username]:
                    diff_seconds = abs((conn_time - ban_time).total_seconds())
                    if min_seconds <= diff_seconds <= max_seconds:
                        time_matches.add(username)
                        break

        return time_matches

    def _create_bypasser_player(self, nickname: str, is_denied_banned: bool) -> Player:
        return Player(
            user_id="UNKNOWN",
            nicknames=[nickname],
            status="banned" if is_denied_banned else "suspicious",
            ban_counts=1 if is_denied_banned else 0
        )

    def _enrich_bypasser_player(self, bypasser: Player, user_connections: Dict[str, List[Dict[str, Any]]],
                                hwid_to_users: Dict[str, Set[str]], ip_to_users: Dict[str, Set[str]]) -> None:
        nick = bypasser.nicknames[0] if bypasser.nicknames else "Unknown"
        bypasser_hwids = {}
        bypasser_ips = {}
        denied_logins = []

        for conn in user_connections.get(nick, []):
            if "Denied: Banned" in conn.get("status", ""):
                denied_logins.append({
                    "user_name": nick,
                    "time": conn.get("time", ""),
                    "ip_address": conn.get("ip_address", ""),
                    "hwid": conn.get("hwid", ""),
                    "server": conn.get("server", "")
                })

            hwid = conn.get("hwid")
            if hwid and hwid != "N/A" and hwid in hwid_to_users:
                shared_users = list(hwid_to_users[hwid] - {nick})
                if shared_users:
                    bypasser_hwids[hwid] = shared_users

            ip = conn.get("ip_address")
            if ip and ip != "N/A" and ip in ip_to_users:
                shared_users = list(ip_to_users[ip] - {nick})
                if shared_users:
                    bypasser_ips[ip] = shared_users

        bypasser.associated_hwids = bypasser_hwids
        bypasser.associated_ips = bypasser_ips
        bypasser.denied_logins = denied_logins

        shared_hwid_users = set()
        for users in bypasser_hwids.values():
            shared_hwid_users.update(users)
        bypasser.shared_hwid_nicknames = list(shared_hwid_users)