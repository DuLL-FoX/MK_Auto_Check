from collections import defaultdict
from typing import List

from config_system import get_config
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