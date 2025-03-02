import logging
from datetime import datetime
from functools import lru_cache
from typing import Optional, List, Dict, Any, Tuple, Set

from models.ban_hit import BanHit
from models.player import Player
from models.verdict import Verdict, VerdictCategory, ConfidenceLevel

logger = logging.getLogger(__name__)

class VerdictEngine:
    def __init__(self):
        self.IP_MATCH_TIMEDELTA_MINUTES = 30
        self.SUSPICIOUS_TIMEDELTA_MINUTES = 60
        self.status_mapping = {
            "banned": VerdictCategory.BANNED,
            "clean": VerdictCategory.CLEAN,
            "suspicious": VerdictCategory.SUSPICIOUS,
            "unknown": VerdictCategory.UNKNOWN
        }
        self.confidence_mapping = {
            ConfidenceLevel.HWID_MATCH.value: ConfidenceLevel.HWID_MATCH,
            ConfidenceLevel.IP_TIME_CLOSE_MATCH.value: ConfidenceLevel.IP_TIME_CLOSE_MATCH,
            ConfidenceLevel.IP_TIME_MATCH.value: ConfidenceLevel.IP_TIME_MATCH,
            ConfidenceLevel.IP_MATCH.value: ConfidenceLevel.IP_MATCH,
            ConfidenceLevel.NO_MATCH.value: ConfidenceLevel.NO_MATCH
        }
        self.high_confidence_bypasses = {
            ConfidenceLevel.HWID_MATCH.value,
            ConfidenceLevel.IP_TIME_MATCH.value,
            ConfidenceLevel.IP_TIME_CLOSE_MATCH.value
        }

    def determine_verdict(self, player: Player, bypass_confidence: Optional[str] = None) -> Verdict:
        if bypass_confidence in self.high_confidence_bypasses:
            return Verdict(
                category=VerdictCategory.POTENTIAL_BYPASS,
                confidence=self.confidence_mapping[bypass_confidence],
                hwid_erased=player.hwid_erased
            )
        if bypass_confidence == ConfidenceLevel.IP_MATCH.value:
            return Verdict(
                category=VerdictCategory.SUSPICIOUS,
                reason="shares IP with banned player",
                hwid_erased=player.hwid_erased
            )
        if player.ban_counts >= 5:
            return Verdict(
                category=VerdictCategory.SUSPICIOUS,
                reason="multiple bans",
                hwid_erased=player.hwid_erased
            )
        if player.hwid_erased and player.ban_counts > 0:
            return Verdict(
                category=VerdictCategory.SUSPICIOUS,
                reason="HWID erased with previous bans",
                hwid_erased=True
            )
        if player.has_complaints and player.ban_counts > 0:
            return Verdict(
                category=VerdictCategory.SUSPICIOUS,
                reason="previous complaints and bans",
                hwid_erased=player.hwid_erased
            )
        category = self.status_mapping.get(player.status.lower(), VerdictCategory.UNKNOWN)
        return Verdict(
            category=category,
            hwid_erased=player.hwid_erased
        )

    def analyze_ban_bypass(self, ban_hit: BanHit, connections: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
        if not connections:
            return ConfidenceLevel.NO_MATCH.value, []
        start_time = datetime.now()
        banned_user_name = ban_hit.user_name
        user_connections = self._group_connections_by_user(connections, banned_user_name)
        if ban_hit.hwid != "N/A" and not ban_hit.hwid_erased:
            hwid_denied_matches = self._find_hwid_denied_banned_matches(user_connections, ban_hit.hwid)
            if hwid_denied_matches:
                return ConfidenceLevel.HWID_MATCH.value, list(hwid_denied_matches)
            hwid_users = self._find_users_with_hwid(user_connections, ban_hit.hwid)
            if hwid_users:
                return ConfidenceLevel.HWID_MATCH.value, list(hwid_users)
        if ban_hit.ip_address != "N/A":
            denied_banned_ip_matches = self._find_ip_denied_banned_matches(user_connections, ban_hit.ip_address)
            if denied_banned_ip_matches:
                return ConfidenceLevel.IP_TIME_CLOSE_MATCH.value, list(denied_banned_ip_matches)
            if ban_hit.time:
                close_time_users = self._find_time_based_bypasses(user_connections, ban_hit.ip_address, ban_hit.time, 0,
                                                                  10)
                if close_time_users:
                    return ConfidenceLevel.IP_TIME_CLOSE_MATCH.value, close_time_users
                time_users = self._find_time_based_bypasses(user_connections, ban_hit.ip_address, ban_hit.time, 0,
                                                            self.IP_MATCH_TIMEDELTA_MINUTES)
                if time_users:
                    return ConfidenceLevel.IP_TIME_MATCH.value, time_users
            ip_users = self._find_users_with_ip(user_connections, ban_hit.ip_address)
            if ip_users:
                return ConfidenceLevel.IP_MATCH.value, list(ip_users)
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed > 0.1:
            logger.debug(f"Ban bypass analysis took {elapsed:.3f}s for user {banned_user_name}")
        return ConfidenceLevel.NO_MATCH.value, []

    def _group_connections_by_user(self, connections: List[Dict[str, Any]], banned_user_name: str) -> Dict[
        str, List[Dict[str, Any]]]:
        user_connections = {}
        for conn in connections:
            user = conn.get("user_name")
            if user and user != banned_user_name:
                if user not in user_connections:
                    user_connections[user] = []
                user_connections[user].append(conn)
        return user_connections

    def _find_hwid_denied_banned_matches(self, user_connections: Dict[str, List[Dict[str, Any]]], hwid: str) -> Set[
        str]:
        matches = set()
        for user, conns in user_connections.items():
            for conn in conns:
                if (conn.get("hwid") == hwid and "Denied: Banned" in conn.get("status", "")):
                    matches.add(user)
                    break
        return matches

    def _find_users_with_hwid(self, user_connections: Dict[str, List[Dict[str, Any]]], hwid: str) -> Set[str]:
        matches = set()
        for user, conns in user_connections.items():
            for conn in conns:
                if conn.get("hwid") == hwid:
                    matches.add(user)
                    break
        return matches

    def _find_ip_denied_banned_matches(self, user_connections: Dict[str, List[Dict[str, Any]]], ip: str) -> Set[str]:
        matches = set()
        for user, conns in user_connections.items():
            for conn in conns:
                if (conn.get("ip_address") == ip and "Denied: Banned" in conn.get("status", "")):
                    matches.add(user)
                    break
        return matches

    def _find_users_with_ip(self, user_connections: Dict[str, List[Dict[str, Any]]], ip: str) -> Set[str]:
        matches = set()
        for user, conns in user_connections.items():
            for conn in conns:
                if conn.get("ip_address") == ip:
                    matches.add(user)
                    break
        return matches

    @lru_cache(maxsize=128)
    def _get_connection_time(self, time_str: str) -> Optional[datetime]:
        if not time_str:
            return None
        try:
            return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    def _find_time_based_bypasses(self, user_connections: Dict[str, List[Dict[str, Any]]], ip_address: str,
                                  ban_time: datetime, min_minutes: int, max_minutes: int) -> List[str]:
        if not ban_time or ip_address == "N/A":
            return []
        min_seconds = min_minutes * 60
        max_seconds = max_minutes * 60
        matches = set()
        for user, conns in user_connections.items():
            for conn in conns:
                if conn.get("ip_address") != ip_address:
                    continue
                time_str = conn.get("time", "")
                conn_time = self._get_connection_time(time_str)
                if not conn_time:
                    continue
                diff_seconds = abs((conn_time - ban_time).total_seconds())
                if min_seconds <= diff_seconds <= max_seconds:
                    matches.add(user)
                    break
        return list(matches)
