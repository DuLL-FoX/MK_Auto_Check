import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict

from models.ban_hit import BanHit
from models.player import Player
from models.verdict import Verdict, VerdictCategory, ConfidenceLevel


class PlayerAnalyzer:
    def __init__(self) -> None:
        self.hwid_match_confidence = ConfidenceLevel.HWID_MATCH.value
        self.ip_time_close_match_confidence = ConfidenceLevel.IP_TIME_CLOSE_MATCH.value
        self.ip_time_match_confidence = ConfidenceLevel.IP_TIME_MATCH.value
        self.ip_match_confidence = ConfidenceLevel.IP_MATCH.value
        self.no_match_confidence = ConfidenceLevel.NO_MATCH.value
        self.close_time_threshold_minutes = 10
        self.time_threshold_minutes = 30
        self.suspicious_time_threshold_minutes = 60

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
                        queue.update(nick for nick in players[player_idx].nicknames if nick not in processed)
            groups.append(group)

        merged_players = []
        for group in groups:
            if len(group) == 1:
                merged_players.append(players[group[0]])
            else:
                base_player = players[group[0]]
                all_nicknames = set(base_player.nicknames)
                all_hwids = dict(base_player.associated_hwids)
                all_ips = dict(base_player.associated_ips)
                all_shared_hwid_nicks = set(base_player.shared_hwid_nicknames)
                max_ban_count = base_player.ban_counts
                all_ban_reasons = set(base_player.ban_reasons)
                for idx in group[1:]:
                    other_player = players[idx]
                    all_nicknames.update(other_player.nicknames)
                    for hwid, nicks in other_player.associated_hwids.items():
                        if hwid in all_hwids:
                            all_hwids[hwid] = list(set(all_hwids[hwid] + nicks))
                        else:
                            all_hwids[hwid] = nicks
                    for ip, nicks in other_player.associated_ips.items():
                        if ip in all_ips:
                            all_ips[ip] = list(set(all_ips[ip] + nicks))
                        else:
                            all_ips[ip] = nicks
                    all_shared_hwid_nicks.update(other_player.shared_hwid_nicknames)
                    max_ban_count = max(max_ban_count, other_player.ban_counts)
                    all_ban_reasons.update(other_player.ban_reasons)
                    if other_player.status == "banned" or (
                            other_player.status == "suspicious" and base_player.status == "clean"):
                        base_player.status = other_player.status
                base_player.nicknames = list(all_nicknames)
                base_player.associated_hwids = all_hwids
                base_player.associated_ips = all_ips
                base_player.shared_hwid_nicknames = list(all_shared_hwid_nicks)
                base_player.ban_counts = max_ban_count
                base_player.ban_reasons = list(all_ban_reasons)
                merged_players.append(base_player)
        return merged_players

    def find_potential_bypassers(self, ban_hit: BanHit, banned_player: Player, connections: List[Dict[str, Any]]) -> \
    Tuple[str, List[Player]]:
        potential_bypassers: List[Player] = []
        bypasser_nicknames: Set[str] = set()
        highest_confidence = self.no_match_confidence
        banned_user_name = ban_hit.user_name
        all_banned_hwids = {hwid for hwid in banned_player.associated_hwids if hwid != "N/A"}
        all_banned_ips = {ip for ip in banned_player.associated_ips if ip != "N/A"}
        if ban_hit.hwid != "N/A" and not ban_hit.hwid_erased:
            all_banned_hwids.add(ban_hit.hwid)
        if ban_hit.ip_address != "N/A":
            all_banned_ips.add(ban_hit.ip_address)
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
        hwid_matched_users = set()
        for hwid in all_banned_hwids:
            hwid_matched_users.update(hwid_to_users.get(hwid, set()))
        ip_matched_users = set()
        for ip in all_banned_ips:
            ip_matched_users.update(ip_to_users.get(ip, set()))
        second_order_hwid_users = set()
        for user in hwid_matched_users:
            for hwid in user_hwids.get(user, set()):
                second_order_hwid_users.update(hwid_to_users.get(hwid, set()))
        second_order_ip_users = set()
        for user in ip_matched_users:
            for ip in user_ips.get(user, set()):
                second_order_ip_users.update(ip_to_users.get(ip, set()))
        all_linked_users = hwid_matched_users | ip_matched_users | second_order_hwid_users | second_order_ip_users
        all_linked_users.discard(banned_user_name)
        for nick in hwid_matched_users:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser_nicknames.add(nick)
                is_denied_banned = user_status.get(nick) == "banned"
                bypasser = Player(
                    user_id="UNKNOWN",
                    nicknames=[nick],
                    status="banned" if is_denied_banned else "suspicious",
                    ban_counts=1 if is_denied_banned else 0
                )
                potential_bypassers.append(bypasser)
                highest_confidence = max(highest_confidence, self.hwid_match_confidence)
        ban_time = ban_hit.time if ban_hit.time else ban_hit.ban_time
        if ban_time:
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
            close_time_matches = self._find_time_based_matches(ban_time, all_banned_ips, ip_to_users, user_times, 0,
                                                               self.close_time_threshold_minutes)
            normal_time_matches = self._find_time_based_matches(ban_time, all_banned_ips, ip_to_users, user_times,
                                                                self.close_time_threshold_minutes,
                                                                self.time_threshold_minutes)
            for nick in close_time_matches:
                if nick not in bypasser_nicknames and nick != banned_user_name:
                    bypasser_nicknames.add(nick)
                    is_denied_banned = user_status.get(nick) == "banned"
                    bypasser = Player(
                        user_id="UNKNOWN",
                        nicknames=[nick],
                        status="banned" if is_denied_banned else "suspicious",
                        ban_counts=1 if is_denied_banned else 0
                    )
                    potential_bypassers.append(bypasser)
                    if highest_confidence in [self.no_match_confidence, self.ip_match_confidence,
                                              self.ip_time_match_confidence]:
                        highest_confidence = self.ip_time_close_match_confidence
            for nick in normal_time_matches:
                if nick not in bypasser_nicknames and nick != banned_user_name:
                    bypasser_nicknames.add(nick)
                    is_denied_banned = user_status.get(nick) == "banned"
                    bypasser = Player(
                        user_id="UNKNOWN",
                        nicknames=[nick],
                        status="banned" if is_denied_banned else "suspicious",
                        ban_counts=1 if is_denied_banned else 0
                    )
                    potential_bypassers.append(bypasser)
                    if highest_confidence in [self.no_match_confidence, self.ip_match_confidence]:
                        highest_confidence = self.ip_time_match_confidence
        for nick in all_linked_users:
            if nick not in bypasser_nicknames and nick != banned_user_name:
                bypasser_nicknames.add(nick)
                is_denied_banned = user_status.get(nick) == "banned"
                bypasser = Player(
                    user_id="UNKNOWN",
                    nicknames=[nick],
                    status="banned" if is_denied_banned else "suspicious",
                    ban_counts=1 if is_denied_banned else 0
                )
                potential_bypassers.append(bypasser)
                if highest_confidence == self.no_match_confidence:
                    highest_confidence = self.ip_match_confidence
        for bypasser in potential_bypassers:
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
        return highest_confidence, potential_bypassers

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

    def _check_time_based_bypass(self, ban_time: datetime, ip_address: str, banned_user_name: str,
                                 connections: List[Dict], min_minutes: int, max_minutes: int) -> List[str]:
        if ip_address == "N/A":
            return []
        min_seconds = min_minutes * 60
        max_seconds = max_minutes * 60
        time_suspected_users = []
        ip_connections = [conn for conn in connections if
                          conn.get("ip_address") == ip_address and conn.get("user_name") != banned_user_name]
        for conn in ip_connections:
            try:
                conn_time_str = conn.get("time", "")
                if not conn_time_str:
                    continue
                conn_time = datetime.strptime(conn_time_str, "%Y-%m-%d %H:%M:%S")
                diff_seconds = abs((conn_time - ban_time).total_seconds())
                if min_seconds <= diff_seconds <= max_seconds:
                    username = conn.get("user_name")
                    if username and username not in time_suspected_users:
                        time_suspected_users.append(username)
            except ValueError:
                pass
        return time_suspected_users
