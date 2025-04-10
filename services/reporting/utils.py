from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple

from models.player import Player
from services.reporting.config import TIME_ANALYSIS_THRESHOLDS, ANALYSIS_CONFIG


def determine_owner(primary_nickname: str, nicknames: List[str], shared_with: List[str],
                    cache: Dict = None) -> str:
    cache = cache or {}
    cache_key = (primary_nickname, tuple(nicknames), tuple(shared_with))

    if cache_key in cache:
        return cache[cache_key]

    if primary_nickname in shared_with:
        owner = primary_nickname
    else:
        for nick in nicknames:
            if nick in shared_with:
                owner = nick
                break
        else:
            owner = shared_with[0] if shared_with else "Unknown"

    cache[cache_key] = owner
    return owner


def categorize_associated_nicknames(player: Player, primary_nickname: str) -> Dict[str, Any]:
    categories = {
        "confirmed_alts": {
            "accounts": set(),
            "direct_hwid": {},
        },
        "alt_to_alt": {
            "connections": {},
            "hwids": set(),
        },
        "likely_connections": [],
        "possible_connections": {
            "ip": {},
            "login": set(),
        },
        "other": set(),
        "time_based": {"recent": set(), "historical": set()}
    }

    categorized = {primary_nickname}

    for hwid, nicks in player.associated_hwids.items():
        if primary_nickname in nicks:
            others = [n for n in nicks if n != primary_nickname]
            if others:
                categories["confirmed_alts"]["accounts"].update(others)
                categories["confirmed_alts"]["direct_hwid"][hwid] = others
                categorized.update(others)

    for hwid, nicks in player.associated_hwids.items():
        if primary_nickname not in nicks:
            alt_nicks = [n for n in nicks if n in player.nicknames and n != primary_nickname]
            if len(alt_nicks) >= 2:
                categories["alt_to_alt"]["hwids"].add(hwid)
                for alt in alt_nicks:
                    if alt not in categories["alt_to_alt"]["connections"]:
                        categories["alt_to_alt"]["connections"][alt] = 0
                    categories["alt_to_alt"]["connections"][alt] += 1
                categorized.update(alt_nicks)

    account_connection_strength = defaultdict(lambda: {"strength": 0, "identifiers": 0})

    for hwid, nicks in player.associated_hwids.items():
        if primary_nickname in nicks or not any(alt in categories["confirmed_alts"]["accounts"] for alt in nicks):
            continue

        for nick in nicks:
            if nick != primary_nickname and nick not in categorized:
                connected_alts = sum(1 for alt in categories["confirmed_alts"]["accounts"] if alt in nicks)
                account_connection_strength[nick]["identifiers"] += 1

                if connected_alts > 1:
                    account_connection_strength[nick]["strength"] += ANALYSIS_CONFIG['DIRECT_CONNECTION_STRENGTH']
                else:
                    account_connection_strength[nick]["strength"] += ANALYSIS_CONFIG['SINGLE_CONNECTION_STRENGTH']

    for ip, nicks in player.associated_ips.items():
        if primary_nickname in nicks or not any(alt in categories["confirmed_alts"]["accounts"] for alt in nicks):
            continue

        for nick in nicks:
            if nick != primary_nickname and nick not in categorized:
                account_connection_strength[nick]["identifiers"] += 1
                account_connection_strength[nick]["strength"] += ANALYSIS_CONFIG['IP_CONNECTION_STRENGTH']

    for nick, data in account_connection_strength.items():
        categories["likely_connections"].append({
            "nickname": nick,
            "strength": "Strong" if data["strength"] > ANALYSIS_CONFIG['STRONG_CONNECTION_THRESHOLD'] else "Moderate",
            "strength_value": data["strength"],
            "identifiers": data["identifiers"]
        })
        categorized.add(nick)

    for ip, nicks in player.associated_ips.items():
        if primary_nickname in nicks:
            for nick in nicks:
                if nick != primary_nickname and nick not in categorized:
                    if nick not in categories["possible_connections"]["ip"]:
                        categories["possible_connections"]["ip"][nick] = 0
                    categories["possible_connections"]["ip"][nick] += 1
                    categorized.add(nick)

    if hasattr(player, 'nicknames_sources'):
        for nick, source in player.nicknames_sources.items():
            if source == "login" and nick != primary_nickname and nick not in categorized:
                categories["possible_connections"]["login"].add(nick)
                categorized.add(nick)

    if hasattr(player, 'denied_logins') and player.denied_logins:
        recent_threshold = datetime.now() - timedelta(days=TIME_ANALYSIS_THRESHOLDS['RECENT_LOGIN_DAYS'])
        historical_threshold = datetime.now() - timedelta(days=TIME_ANALYSIS_THRESHOLDS['HISTORICAL_LOGIN_DAYS'])

        for login in player.denied_logins:
            try:
                user_name = login.get('user_name', '')
                if not user_name or user_name == primary_nickname or user_name in categorized:
                    continue

                login_time = datetime.strptime(login['time'], "%Y-%m-%d %H:%M:%S")
                if login_time > recent_threshold:
                    categories["time_based"]["recent"].add(user_name)
                elif login_time > historical_threshold:
                    categories["time_based"]["historical"].add(user_name)
                categorized.add(user_name)
            except Exception:
                pass

    categories["other"] = {nick for nick in player.nicknames if
                           nick != primary_nickname and nick not in categorized}

    return categories


def analyze_hwids(player: Player, primary_nickname: str) -> Tuple[List, List, List]:
    nicknames_set = set(player.nicknames)

    owned_hwids = []
    alt_hwids = []
    other_hwids = []

    for hwid, shared_with in player.associated_hwids.items():
        if primary_nickname in shared_with:
            owned_hwids.append((hwid, shared_with))
        elif any(nick in nicknames_set for nick in shared_with):
            alt_hwids.append((hwid, shared_with))
        else:
            other_hwids.append((hwid, shared_with))

    owned_hwids.sort(key=lambda x: len(x[1]), reverse=True)
    alt_hwids.sort(key=lambda x: len(x[1]), reverse=True)
    other_hwids.sort(key=lambda x: len(x[1]), reverse=True)

    return owned_hwids, alt_hwids, other_hwids


def analyze_ips(player: Player, primary_nickname: str) -> Tuple[List, List, List, List]:
    nicknames_set = set(player.nicknames)

    original_ips = []
    shared_ips = []
    alt_shared_ips = []
    multi_user_ips = []

    for ip, shared_with in player.associated_ips.items():
        if primary_nickname in shared_with:
            if len(shared_with) == 1:
                original_ips.append(ip)
            else:
                shared_ips.append((ip, shared_with))
        elif any(nick in nicknames_set for nick in shared_with):
            alt_shared_ips.append((ip, shared_with))
        elif len(shared_with) > 1:
            multi_user_ips.append((ip, shared_with))

    shared_ips.sort(key=lambda x: len(x[1]), reverse=True)
    alt_shared_ips.sort(key=lambda x: len(x[1]), reverse=True)
    multi_user_ips.sort(key=lambda x: len(x[1]), reverse=True)

    return original_ips, shared_ips, alt_shared_ips, multi_user_ips


def analyze_complaints(player: Player, nickname: str) -> Tuple[List, List]:
    if not hasattr(player, 'complaint_links') or not player.complaint_links:
        return [], []

    direct_connections = {nickname}

    for hwid, nicks in player.associated_hwids.items():
        if nickname in nicks:
            direct_connections.update([n for n in nicks if n != nickname])

    for ip, nicks in player.associated_ips.items():
        if nickname in nicks:
            direct_connections.update([n for n in nicks if n != nickname])

    direct_complaints = []
    indirect_complaints = []

    for complaint in player.complaint_links:
        mentioned_nicks = complaint.get("mentioned_nicknames", [nickname])

        is_direct = any(nick in direct_connections for nick in mentioned_nicks)

        if not is_direct and "content" in complaint:
            content = complaint.get("content", "").lower()
            is_direct = any(nick.lower() in content for nick in direct_connections)

        if is_direct:
            direct_complaints.append(complaint)
        else:
            indirect_complaints.append(complaint)

    return direct_complaints, indirect_complaints


def find_connection_paths(player: Player, nickname: str) -> Dict[str, Any]:
    if not player.nicknames or len(player.nicknames) <= 1:
        return None

    nicknames_set = set(player.nicknames)

    primary_hwids = set()
    primary_ips = set()

    for hwid, nicks in player.associated_hwids.items():
        if nickname in nicks:
            primary_hwids.add(hwid)

    for ip, nicks in player.associated_ips.items():
        if nickname in nicks:
            primary_ips.add(ip)

    direct_connections = {}
    for hwid in primary_hwids:
        shared_with = player.associated_hwids.get(hwid, [])
        for nick in shared_with:
            if nick != nickname and nick in nicknames_set:
                direct_connections[nick] = {
                    "type": "hwid",
                    "identifier": hwid,
                    "confidence": "High",
                    "path": f"{nickname} → {hwid} → {nick}"
                }

    for ip in primary_ips:
        shared_with = player.associated_ips.get(ip, [])
        for nick in shared_with:
            if nick != nickname and nick in nicknames_set and nick not in direct_connections:
                direct_connections[nick] = {
                    "type": "ip",
                    "identifier": ip,
                    "confidence": "Medium",
                    "path": f"{nickname} → {ip} → {nick}"
                }

    indirect_connections = {}
    indirect_by_via = {}
    directly_connected_nicks = set(direct_connections.keys())

    for middle_nick in directly_connected_nicks:
        for hwid, nicks in player.associated_hwids.items():
            if middle_nick in nicks and nickname not in nicks:
                for nick in nicks:
                    if (nick != middle_nick and nick != nickname and
                            nick in nicknames_set and nick not in direct_connections):

                        if middle_nick not in indirect_by_via:
                            indirect_by_via[middle_nick] = {"hwid": [], "ip": []}

                        indirect_by_via[middle_nick]["hwid"].append({
                            "nick": nick,
                            "identifier": hwid
                        })

                        indirect_connections[nick] = {
                            "type": "hwid-indirect",
                            "identifier": hwid,
                            "via": middle_nick,
                            "confidence": "Medium"
                        }

        for ip, nicks in player.associated_ips.items():
            if middle_nick in nicks and nickname not in nicks:
                for nick in nicks:
                    if (nick != middle_nick and nick != nickname and
                            nick in nicknames_set and nick not in direct_connections and
                            nick not in indirect_connections):

                        if middle_nick not in indirect_by_via:
                            indirect_by_via[middle_nick] = {"hwid": [], "ip": []}

                        indirect_by_via[middle_nick]["ip"].append({
                            "nick": nick,
                            "identifier": ip
                        })

                        indirect_connections[nick] = {
                            "type": "ip-indirect",
                            "identifier": ip,
                            "via": middle_nick,
                            "confidence": "Low"
                        }

    return {
        "direct_connections": direct_connections,
        "indirect_connections": indirect_connections,
        "indirect_by_via": indirect_by_via
    }