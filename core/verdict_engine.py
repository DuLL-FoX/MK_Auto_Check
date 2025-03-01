import logging
from datetime import datetime
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
        }

    def determine_verdict(self, player: Player, bypass_confidence: Optional[str] = None) -> Verdict:
        if bypass_confidence in {
            ConfidenceLevel.HWID_MATCH.value,
            ConfidenceLevel.IP_TIME_MATCH.value,
            ConfidenceLevel.IP_TIME_CLOSE_MATCH.value
        }:
            confidence_map = {
                ConfidenceLevel.HWID_MATCH.value: ConfidenceLevel.HWID_MATCH,
                ConfidenceLevel.IP_TIME_CLOSE_MATCH.value: ConfidenceLevel.IP_TIME_CLOSE_MATCH,
                ConfidenceLevel.IP_TIME_MATCH.value: ConfidenceLevel.IP_TIME_MATCH
            }
            return Verdict(
                category=VerdictCategory.POTENTIAL_BYPASS,
                confidence=confidence_map[bypass_confidence],
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
        user_connections = {}
        for conn in connections:
            user = conn.get("user_name")
            if user and user != banned_user_name:
                user_connections.setdefault(user, []).append(conn)
        hwid_matches = set()
        if ban_hit.hwid != "N/A" and not ban_hit.hwid_erased:
            for user, conns in user_connections.items():
                for conn in conns:
                    if conn.get("hwid") == ban_hit.hwid and "Denied: Banned" in conn.get("status", ""):
                        hwid_matches.add(user)
                        break
        if hwid_matches:
            return ConfidenceLevel.HWID_MATCH.value, list(hwid_matches)
        if ban_hit.hwid != "N/A" and not ban_hit.hwid_erased:
            hwid_users = set()
            for user, conns in user_connections.items():
                for conn in conns:
                    if conn.get("hwid") == ban_hit.hwid:
                        hwid_users.add(user)
                        break
            if len(hwid_users) > 0:
                return ConfidenceLevel.HWID_MATCH.value, list(hwid_users)
        denied_banned_ip_matches = set()
        if ban_hit.ip_address != "N/A":
            for user, conns in user_connections.items():
                for conn in conns:
                    if conn.get("ip_address") == ban_hit.ip_address and "Denied: Banned" in conn.get("status", ""):
                        denied_banned_ip_matches.add(user)
                        break
            if denied_banned_ip_matches:
                return ConfidenceLevel.IP_TIME_CLOSE_MATCH.value, list(denied_banned_ip_matches)
        if ban_hit.ip_address != "N/A" and ban_hit.time:
            close_time_users = self._find_time_based_bypasses(user_connections, ban_hit.ip_address, ban_hit.time, 0, 10)
            if close_time_users:
                return ConfidenceLevel.IP_TIME_CLOSE_MATCH.value, close_time_users
            time_users = self._find_time_based_bypasses(user_connections, ban_hit.ip_address, ban_hit.time, 0,
                                                        self.IP_MATCH_TIMEDELTA_MINUTES)
            if time_users:
                return ConfidenceLevel.IP_TIME_MATCH.value, time_users
        if ban_hit.ip_address != "N/A":
            ip_users = set()
            for user, conns in user_connections.items():
                for conn in conns:
                    if conn.get("ip_address") == ban_hit.ip_address:
                        ip_users.add(user)
                        break
            if ip_users:
                return ConfidenceLevel.IP_MATCH.value, list(ip_users)
        elapsed = (datetime.now() - start_time).total_seconds()
        if elapsed > 0.1:
            logger.debug(f"Ban bypass analysis took {elapsed:.3f}s for user {banned_user_name}")
        return ConfidenceLevel.NO_MATCH.value, []

    def _find_time_based_bypasses(self, user_connections: Dict[str, List[Dict[str, Any]]],
                                  ip_address: str, ban_time: datetime,
                                  min_minutes: int, max_minutes: int) -> List[str]:
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
                if not time_str:
                    continue
                try:
                    conn_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    diff_seconds = abs((conn_time - ban_time).total_seconds())
                    if min_seconds <= diff_seconds <= max_seconds:
                        matches.add(user)
                        break
                except ValueError:
                    pass
        return list(matches)
