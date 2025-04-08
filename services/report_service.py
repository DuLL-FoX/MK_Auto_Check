import json
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from models.message import ScanResult
from models.player import Player
from utils.logging_utils import get_logger

logger = get_logger(__name__)


class ReportFormatter:

    def __init__(self):
        self.fmt = self._setup_terminal_formatting()
        self.box = self._setup_box_chars()

    def _setup_terminal_formatting(self):
        if sys.stdout.isatty():
            return {
                'HEADER': '\033[95m',
                'BLUE': '\033[94m',
                'CYAN': '\033[96m',
                'GREEN': '\033[92m',
                'YELLOW': '\033[93m',
                'RED': '\033[91m',
                'BOLD': '\033[1m',
                'UNDERLINE': '\033[4m',
                'END': '\033[0m'
            }
        else:
            return {
                'HEADER': '', 'BLUE': '', 'CYAN': '', 'GREEN': '',
                'YELLOW': '', 'RED': '', 'BOLD': '', 'UNDERLINE': '', 'END': ''
            }

    def _setup_box_chars(self):
        return {
            'H': '─',
            'V': '│',
            'TL': '┌',
            'TR': '┐',
            'BL': '└',
            'BR': '┘',
            'VL': '┤',
            'VR': '├',
            'HU': '┴',
            'HD': '┬',
            'CROSS': '┼'
        }

    def print_header(self, title: str, width: int = 100):
        self._print_boxed(title, width, style='header')

    def print_section(self, title: str, width: int = 100):
        self._print_boxed(title, width, style='section')

    def _print_boxed(self, title: str, width: int = 100, style: str = 'header'):
        is_header = style == 'header'
        fmt = self.fmt
        box = self.box

        color_prefix = fmt['HEADER'] if is_header else ''
        color_prefix += fmt['BOLD']

        print(f"\n{color_prefix}{box['TL']}{box['H'] * (width - 2)}{box['TR']}{fmt['END']}")

        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(f"{color_prefix}{box['V']}{' ' * padding} {title} {' ' * right_padding}{box['V']}{fmt['END']}")

        print(f"{color_prefix}{box['BL']}{box['H'] * (width - 2)}{box['BR']}{fmt['END']}")

    def print_player_header(self, name: str, width: int = 76):
        box = self.box
        fmt = self.fmt

        player_header = f"PLAYER: {name}"
        print(f"\n  {fmt['BOLD']}{fmt['CYAN']}{box['TL']}{box['H'] * (width - 2)}{box['TR']}{fmt['END']}")

        padding = (width - len(player_header) - 4) // 2
        right_padding = width - padding - len(player_header) - 4
        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['V']}{' ' * padding} {player_header} {' ' * right_padding}{box['V']}{fmt['END']}")

        print(f"  {fmt['BOLD']}{fmt['CYAN']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

    def print_section_header(self, title: str, width: int = 76):
        box = self.box
        fmt = self.fmt

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(
            f"  {fmt['BOLD']}{box['V']}{' ' * padding} {title} {' ' * right_padding}{box['V']}{fmt['END']}")

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

    def print_content_box(self, width: int = 96, indent: str = "  "):
        box = self.box
        fmt = self.fmt

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")

        def end_box():
            print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

        return end_box

    def print_wrapped_content(self, content, indent="", line_width=85):
        box = self.box

        content_lines = content.split('\n')
        for line in content_lines:
            if len(line) > line_width:
                chunks = [line[i:i + line_width] for i in range(0, len(line), line_width)]
                for chunk in chunks:
                    print(f"  {box['V']}   {box['V']}{indent}{chunk}")
            else:
                print(f"  {box['V']}   {box['V']}{indent}{line}")

    def format_status(self, status: str, hwid_erased: bool = False) -> str:
        fmt = self.fmt
        status = status.upper()

        if status.lower() == "banned":
            status_str = f"{fmt['RED']}{fmt['BOLD']}{status}{fmt['END']}"
        elif status.lower() == "suspicious":
            status_str = f"{fmt['YELLOW']}{fmt['BOLD']}{status}{fmt['END']}"
        elif status.lower() == "clean":
            status_str = f"{fmt['GREEN']}{status}{fmt['END']}"
        else:
            status_str = status

        if hwid_erased:
            status_str += f" {fmt['YELLOW']}(HWID ERASED){fmt['END']}"

        return status_str

    def format_hwid(self, hwid: str) -> str:
        fmt = self.fmt

        if hwid.startswith("V2-"):
            prefix = f"{fmt['BOLD']}{fmt['CYAN']}V2-{fmt['END']}"
            base = hwid[3:]
            return f"{prefix}{fmt['CYAN']}{base}{fmt['END']}"

        return f"{fmt['CYAN']}{hwid}{fmt['END']}"

    def truncate_list(self, items, limit=5, joiner=", "):
        if not items:
            return ""

        if len(items) <= limit:
            return joiner.join(items)

        return joiner.join(items[:limit]) + f", and {len(items) - limit} more"

    def truncate_text(self, text, max_length=70):
        if text and len(text) > max_length:
            return text[:max_length - 3] + "..."

        return text

    def print_color_legend(self):
        fmt = self.fmt

        print(f"\n{fmt['BOLD']}COLOR LEGEND:{fmt['END']}")
        print(f"  {fmt['GREEN']}Green{fmt['END']}: Clean status or primary user")
        print(f"  {fmt['YELLOW']}Yellow{fmt['END']}: Suspicious status or shared resources")
        print(f"  {fmt['RED']}Red{fmt['END']}: Banned status or critical issues")
        print(f"  {fmt['CYAN']}Cyan{fmt['END']}: IPs and HWIDs")
        print(f"  {fmt['BLUE']}Blue{fmt['END']}: Links and references")


class ReportService:

    def __init__(self) -> None:
        self.report_filename = "scan_report.json"
        self.formatter = ReportFormatter()
        self.cache = {}

    def write_json_report(self, data: List[Dict[str, Any]], filename: Optional[str] = None) -> bool:
        report_file = filename or self.report_filename

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

            logger.info(f"Report saved to '{report_file}' ({len(data)} items)")
            return True

        except IOError as e:
            logger.error(f"Could not write report to '{report_file}': {e}")
            return False

    def _player_to_dict(self, player: Player) -> Dict[str, Any]:
        primary_nickname = getattr(player, 'primary_nickname', None) or (
            player.nicknames[0] if player.nicknames else "Unknown")

        enhanced_ips = {}
        for ip, shared_with in player.associated_ips.items():
            owner = self._determine_owner(primary_nickname, player.nicknames, shared_with)
            enhanced_ips[ip] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }

        enhanced_hwids = {}
        for hwid, shared_with in player.associated_hwids.items():
            owner = self._determine_owner(primary_nickname, player.nicknames, shared_with)
            enhanced_hwids[hwid] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }

        return {
            "initial_account": {
                "user_id": player.user_id,
                "nicknames": player.nicknames,
                "primary_nickname": primary_nickname,
                "status": player.status,
                "ban_counts": player.ban_counts,
                "ban_reasons": getattr(player, 'ban_reasons', []),
                "connection_link": getattr(player, 'connection_link', ""),
                "associated_ips": player.associated_ips,
                "associated_hwids": player.associated_hwids,
                "shared_hwid_nicknames": getattr(player, 'shared_hwid_nicknames', [])
            },
            "ip_data": enhanced_ips,
            "hwid_data": enhanced_hwids,
            "raw_ip_nicks": player.associated_ips,
            "raw_hwid_nicks": player.associated_hwids,
            "nicknames": player.nicknames,
            "hwid_erased": getattr(player, 'hwid_erased', False),
            "complaint_links": getattr(player, 'complaint_links', [])
        }

    def _determine_owner(self, primary_nickname: str, nicknames: List[str], shared_with: List[str]) -> str:
        cache_key = (primary_nickname, tuple(nicknames), tuple(shared_with))
        if cache_key in self.cache:
            return self.cache[cache_key]

        if primary_nickname in shared_with:
            owner = primary_nickname
        else:
            for nick in nicknames:
                if nick in shared_with:
                    owner = nick
                    break
            else:
                owner = shared_with[0] if shared_with else "Unknown"

        self.cache[cache_key] = owner
        return owner

    def generate_message_scan_report(self, scan_results: List[ScanResult]) -> List[Dict[str, Any]]:
        report_data = []

        for result in scan_results:
            message = result.message
            players_data = [self._player_to_dict(player) for player in result.players]

            message_data = {
                "message_id": message.id,
                "message_link": message.link,
                "author_name": message.author_name,
                "author_id": message.author_id,
                "scan_time": result.scan_time.isoformat(),
                "results": players_data
            }

            report_data.append(message_data)

            banned_count = sum(1 for p in result.players if p.status == 'banned')
            suspicious_count = sum(1 for p in result.players if p.status == 'suspicious')

            logger.info(f"Report item: Message {message.id} by {message.author_name}: " +
                        f"Found {len(players_data)} players with " +
                        f"{banned_count} banned, {suspicious_count} suspicious")

        self.print_message_scan_results(scan_results)

        return report_data

    def generate_nickname_search_report(self, nickname: str, player: Player) -> List[Dict[str, Any]]:
        report_data = []

        player_info = {
            "type": "player_info",
            "nickname": nickname,
            "status": player.status,
            "ban_counts": player.ban_counts,
            "ban_reasons": getattr(player, 'ban_reasons', []),
            "hwid_erased": getattr(player, 'hwid_erased', False)
        }
        report_data.append(player_info)

        if player.nicknames and len(player.nicknames) > 1:
            associated_accounts = {
                "type": "associated_accounts",
                "nicknames": player.nicknames
            }
            report_data.append(associated_accounts)

        if hasattr(player, 'denied_logins') and player.denied_logins:
            denied_logins_data = {
                "type": "denied_login_attempts",
                "attempts": player.denied_logins
            }
            report_data.append(denied_logins_data)

        if hasattr(player, 'associated_ips') and player.associated_ips:
            ip_data = self._generate_ip_data(nickname, player)
            report_data.append(ip_data)

        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            hwid_data = self._generate_hwid_data(nickname, player)
            report_data.append(hwid_data)

        if hasattr(player, 'complaint_links') and player.complaint_links:
            complaints_data = {
                "type": "complaints",
                "links": player.complaint_links
            }
            report_data.append(complaints_data)

        self._print_nickname_search_results(nickname, player)

        return report_data

    def _generate_ip_data(self, nickname: str, player: Player) -> Dict[str, Any]:
        ip_data = {
            "type": "associated_ips",
            "ips": []
        }

        denied_logins_by_ip = {}
        if hasattr(player, 'denied_logins'):
            for login in player.denied_logins:
                ip = login.get("ip_address")
                if ip:
                    if ip not in denied_logins_by_ip:
                        denied_logins_by_ip[ip] = []
                    denied_logins_by_ip[ip].append(login)

        for ip, shared_with in player.associated_ips.items():
            denied_logins_for_ip = denied_logins_by_ip.get(ip, [])

            owner = self._determine_owner(nickname, player.nicknames, shared_with)
            others = [nick for nick in shared_with if nick != owner]

            ip_entry = {
                "direct_ip_connections": ip,
                "owner": owner,
                "owned_by_primary": owner == nickname,
                "owned_by_alt": owner in player.nicknames and owner != nickname,
                "shared_with": others,
                "raw_users": shared_with
            }

            if denied_logins_for_ip:
                ip_entry["denied_logins"] = denied_logins_for_ip

            ip_data["ips"].append(ip_entry)

        return ip_data

    def _generate_hwid_data(self, nickname: str, player: Player) -> Dict[str, Any]:
        hwid_data = {
            "type": "associated_hwids",
            "hwids": []
        }

        denied_logins_by_hwid = {}
        if hasattr(player, 'denied_logins'):
            for login in player.denied_logins:
                hwid = login.get("hwid")
                if hwid:
                    if hwid not in denied_logins_by_hwid:
                        denied_logins_by_hwid[hwid] = []
                    denied_logins_by_hwid[hwid].append(login)

        for hwid, shared_with in player.associated_hwids.items():
            denied_logins_for_hwid = denied_logins_by_hwid.get(hwid, [])

            owner = self._determine_owner(nickname, player.nicknames, shared_with)
            others = [nick for nick in shared_with if nick != owner]

            hwid_entry = {
                "hwid": hwid,
                "owner": owner,
                "owned_by_primary": owner == nickname,
                "owned_by_alt": owner in player.nicknames and owner != nickname,
                "shared_with": others,
                "raw_users": shared_with
            }

            if denied_logins_for_hwid:
                hwid_entry["denied_logins"] = denied_logins_for_hwid

            hwid_data["hwids"].append(hwid_entry)

        return hwid_data

    def _categorize_associated_nicknames(self, player: Player, primary_nickname: str):
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
                        account_connection_strength[nick]["strength"] += 2
                    else:
                        account_connection_strength[nick]["strength"] += 1

        for ip, nicks in player.associated_ips.items():
            if primary_nickname in nicks or not any(alt in categories["confirmed_alts"]["accounts"] for alt in nicks):
                continue

            for nick in nicks:
                if nick != primary_nickname and nick not in categorized:
                    account_connection_strength[nick]["identifiers"] += 1
                    account_connection_strength[nick]["strength"] += 0.5

        for nick, data in account_connection_strength.items():
            categories["likely_connections"].append({
                "nickname": nick,
                "strength": "Strong" if data["strength"] > 1 else "Moderate",
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
            recent_threshold = datetime.now() - timedelta(days=180)
            for login in player.denied_logins:
                try:
                    user_name = login.get('user_name', '')
                    if not user_name or user_name == primary_nickname or user_name in categorized:
                        continue

                    login_time = datetime.strptime(login['time'], "%Y-%m-%d %H:%M:%S")
                    if login_time > recent_threshold:
                        categories["time_based"]["recent"].add(user_name)
                    else:
                        categories["time_based"]["historical"].add(user_name)
                    categorized.add(user_name)
                except Exception:
                    pass

        categories["other"] = {nick for nick in player.nicknames if
                               nick != primary_nickname and nick not in categorized}

        return categories

    def _print_connection_paths_section(self, player: Player, nickname: str) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        if not player.nicknames or len(player.nicknames) <= 1:
            return

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

        if not direct_connections and not indirect_connections:
            return

        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} CONNECTION EVIDENCE:{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

        total_connections = len(direct_connections) + len(indirect_connections)
        high_confidence = sum(1 for info in direct_connections.values() if info["confidence"] == "High")
        medium_confidence = sum(1 for info in direct_connections.values() if info["confidence"] == "Medium") + \
                            sum(1 for info in indirect_connections.values() if info["confidence"] == "Medium")
        low_confidence = sum(1 for info in indirect_connections.values() if info["confidence"] == "Low")

        print(f"  {box['V']} {fmt['BOLD']}Overview:{fmt['END']} {total_connections} connected accounts detected")
        print(f"  {box['V']}   • {fmt['RED']}{high_confidence} high confidence{fmt['END']} | "
              f"{fmt['YELLOW']}{medium_confidence} medium confidence{fmt['END']} | "
              f"{fmt['GREEN']}{low_confidence} low confidence{fmt['END']}")
        print(f"  {box['V']}")

        if direct_connections:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['RED']}■ DIRECT CONNECTIONS ({len(direct_connections)}):{fmt['END']}")

            hwid_direct = [(nick, info) for nick, info in direct_connections.items() if info["type"] == "hwid"]
            ip_direct = [(nick, info) for nick, info in direct_connections.items() if info["type"] == "ip"]

            if hwid_direct:
                print(f"  {box['V']}   {fmt['BOLD']}HWID-linked accounts:{fmt['END']}")

                by_hwid = defaultdict(list)
                for nick, info in hwid_direct:
                    hwid = info["identifier"]
                    by_hwid[hwid].append(nick)

                for hwid, nicks in by_hwid.items():
                    print(f"  {box['V']}     • {self.formatter.format_hwid(hwid)}: {', '.join(nicks)}")
                    print(f"  {box['V']}       {fmt['RED']}High confidence{fmt['END']} (direct HWID sharing)")

                if ip_direct:
                    print(f"  {box['V']}")

            if ip_direct:
                print(f"  {box['V']}   {fmt['BOLD']}IP-linked accounts:{fmt['END']}")

                by_ip = defaultdict(list)
                for nick, info in ip_direct:
                    ip = info["identifier"]
                    by_ip[ip].append(nick)

                for ip, nicks in by_ip.items():
                    print(f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']}: {', '.join(nicks)}")
                    print(f"  {box['V']}       {fmt['YELLOW']}Medium confidence{fmt['END']} (direct IP sharing)")

            if indirect_connections:
                print(f"  {box['V']}")

        if indirect_connections:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ INDIRECT CONNECTIONS ({len(indirect_connections)}):{fmt['END']}")

            for via_nick, connections in indirect_by_via.items():
                if connections["hwid"] or connections["ip"]:
                    print(f"  {box['V']}   {fmt['BOLD']}Through {via_nick}:{fmt['END']}")

                if connections["hwid"]:
                    by_hwid = defaultdict(list)
                    for conn in connections["hwid"]:
                        hwid = conn["identifier"]
                        by_hwid[hwid].append(conn["nick"])

                    for hwid, nicks in by_hwid.items():
                        print(f"  {box['V']}     • HWID {self.formatter.format_hwid(hwid)}: {', '.join(nicks)}")
                        print(
                            f"  {box['V']}       {fmt['YELLOW']}Medium confidence{fmt['END']} | Path: {nickname} → {via_nick} → [accounts]")

                if connections["ip"]:
                    by_ip = defaultdict(list)
                    for conn in connections["ip"]:
                        ip = conn["identifier"]
                        by_ip[ip].append(conn["nick"])

                    for ip, nicks in by_ip.items():
                        print(f"  {box['V']}     • IP {fmt['CYAN']}{ip}{fmt['END']}: {', '.join(nicks)}")
                        print(
                            f"  {box['V']}       {fmt['GREEN']}Low confidence{fmt['END']} | Path: {nickname} → {via_nick} → [accounts]")

                print(f"  {box['V']}")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

    def _print_nickname_search_results(self, nickname: str, player: Player) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box
        status_str = self.formatter.format_status(player.status, getattr(player, 'hwid_erased', False))

        self.formatter.print_header(f"SCAN RESULTS FOR: {nickname}", 100)

        print(f"  {fmt['BOLD']}STATUS:{fmt['END']} {status_str} | {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")

        if hasattr(player, 'ban_reasons') and player.ban_reasons:
            self._print_ban_reasons(player)

        if len(player.nicknames) > 1:
            print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
            print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED NICKNAMES:{fmt['END']}")

            categorized_nicks = self._categorize_associated_nicknames(player, nickname)
            has_categories = False

            if categorized_nicks["confirmed_alts"]["accounts"]:
                has_categories = True
                print(f"  {box['V']}")
                print(f"  {box['V']}   {fmt['BOLD']}{fmt['RED']}■ CONFIRMED ALTS:{fmt['END']}")

                confirmed_alts = sorted(list(categorized_nicks['confirmed_alts']['accounts']))
                if confirmed_alts:
                    print(f"  {box['V']}     {fmt['BOLD']}Accounts:{fmt['END']} {', '.join(confirmed_alts)}")

                if categorized_nicks["confirmed_alts"]["direct_hwid"]:
                    hwid_count = len(categorized_nicks["confirmed_alts"]["direct_hwid"])
                    print(f"  {box['V']}     {fmt['BOLD']}Directly shared HWIDs:{fmt['END']} {hwid_count}")

                    for hwid, connected_alts in categorized_nicks["confirmed_alts"]["direct_hwid"].items():
                        print(f"  {box['V']}       • {self.formatter.format_hwid(hwid)}: {', '.join(connected_alts)}")

            if categorized_nicks["alt_to_alt"]["connections"]:
                has_categories = True
                print(f"  {box['V']}")
                print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ ALT-TO-ALT CONNECTIONS:{fmt['END']}")

                hwid_to_accounts = {}
                for hwid in categorized_nicks["alt_to_alt"]["hwids"]:
                    if hwid in player.associated_hwids:
                        connected_accounts = [nick for nick in player.associated_hwids[hwid]
                                              if nick in categorized_nicks["alt_to_alt"][
                                                  "connections"] and nick != nickname]
                        if connected_accounts:
                            hwid_to_accounts[hwid] = connected_accounts

                total_hwids = len(hwid_to_accounts)
                total_accounts = len(categorized_nicks["alt_to_alt"]["connections"])

                print(
                    f"  {box['V']}     {fmt['BOLD']}Network Summary:{fmt['END']} {total_accounts} accounts connected through {total_hwids} HWIDs")

                alt_connections = sorted(
                    categorized_nicks["alt_to_alt"]["connections"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )

                top_connected = [alt for alt, _ in alt_connections[:10]]
                remaining = len(alt_connections) - 10 if len(alt_connections) > 10 else 0

                print(f"  {box['V']}     {fmt['BOLD']}Connected Alt Accounts:{fmt['END']} {', '.join(top_connected)}")
                if remaining > 0:
                    print(f"  {box['V']}       (and {remaining} more accounts)")

                print(f"  {box['V']}")
                print(f"  {box['V']}     {fmt['BOLD']}HWID Connections:{fmt['END']}")

                sorted_hwids = sorted(hwid_to_accounts.items(), key=lambda x: len(x[1]), reverse=True)

                for i, (hwid, accounts) in enumerate(sorted_hwids, 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['V']}       {i}. {formatted_hwid}")
                    print(f"  {box['V']}          {fmt['BOLD']}Connected accounts:{fmt['END']} {', '.join(accounts)}")

                    if hasattr(player, 'hwid_sources') and hwid in getattr(player, 'hwid_sources', {}):
                        source_info = player.hwid_sources[hwid]
                        print(f"  {box['V']}          {fmt['BOLD']}Origin:{fmt['END']} {source_info}")

                    if i < min(5, len(sorted_hwids)):
                        print(f"  {box['V']}")

                if len(sorted_hwids) > 5:
                    print(f"  {box['V']}       ...and {len(sorted_hwids) - 5} more shared HWIDs")

                print(
                    f"  {box['V']}     {fmt['BOLD']}Note:{fmt['END']} These accounts share HWIDs with each other, but not directly with {nickname}")

            if categorized_nicks["likely_connections"]:
                has_categories = True
                print(f"  {box['V']}")
                print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ LIKELY CONNECTIONS:{fmt['END']}")

                sorted_connections = sorted(
                    categorized_nicks["likely_connections"],
                    key=lambda x: (x["strength_value"], x["identifiers"]),
                    reverse=True
                )

                for i, connection in enumerate(sorted_connections[:10]):
                    nick = connection["nickname"]
                    strength = connection["strength"]
                    identifiers = connection["identifiers"]

                    strength_fmt = fmt['YELLOW'] if strength == "Strong" else fmt['CYAN']
                    print(
                        f"  {box['V']}     • {nick}: {strength_fmt}{strength}{fmt['END']} ({identifiers} shared identifiers)")

                if len(sorted_connections) > 10:
                    print(
                        f"  {box['V']}     • ...and {len(sorted_connections) - 10} more accounts with likely connections")

            ip_connections = categorized_nicks["possible_connections"]["ip"]
            login_matches = categorized_nicks["possible_connections"]["login"]

            if ip_connections or login_matches:
                has_categories = True
                print(f"  {box['V']}")
                print(f"  {box['V']}   {fmt['BOLD']}{fmt['CYAN']}■ POSSIBLE CONNECTIONS:{fmt['END']}")

                if login_matches:
                    login_list = sorted(list(login_matches))
                    print(f"  {box['V']}     {fmt['BOLD']}Login Event Matches:{fmt['END']} {', '.join(login_list)}")

                if ip_connections:
                    sorted_ip_connections = sorted(ip_connections.items(), key=lambda x: x[1], reverse=True)

                    print(f"  {box['V']}     {fmt['BOLD']}IP Matches ({len(sorted_ip_connections)}):{fmt['END']}")
                    for nick, count in sorted_ip_connections[:5]:
                        print(f"  {box['V']}       • {nick} ({count} shared IPs)")

                    if len(sorted_ip_connections) > 5:
                        print(
                            f"  {box['V']}       • ...and {len(sorted_ip_connections) - 5} more IP-connected accounts")

            other_nicks = list(categorized_nicks["other"])
            time_based_nicks = list(
                categorized_nicks["time_based"]["recent"] | categorized_nicks["time_based"]["historical"])

            if other_nicks or time_based_nicks:
                has_categories = True
                print(f"  {box['V']}")

                if time_based_nicks:
                    print(
                        f"  {box['V']}   {fmt['BOLD']}■ TIME-BASED CONNECTIONS:{fmt['END']} {', '.join(sorted(time_based_nicks))}")

                if other_nicks:
                    if len(other_nicks) <= 10:
                        print(
                            f"  {box['V']}   {fmt['BOLD']}■ OTHER ASSOCIATED NICKNAMES:{fmt['END']} {', '.join(sorted(other_nicks))}")
                    else:
                        print(
                            f"  {box['V']}   {fmt['BOLD']}■ OTHER ASSOCIATED NICKNAMES ({len(other_nicks)}):{fmt['END']} {', '.join(sorted(other_nicks)[:7])}, and {len(other_nicks) - 7} more")

            if not has_categories:
                other_nicks = [nick for nick in player.nicknames if nick != nickname]
                if other_nicks:
                    print(f"  {box['V']}   {', '.join(sorted(other_nicks))}")

            print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

        self._print_connection_paths_section(player, nickname)
        self._print_complaints_section(player, nickname)
        self._print_ip_section(player, nickname)
        self._print_hwid_section(player, nickname)
        self._print_denied_logins_section(player, nickname)

        print(f"\n{'=' * 100}")

        self.formatter.print_color_legend()

    def _print_ban_reasons(self, player, indent="  "):
        fmt = self.formatter.fmt

        if not hasattr(player, 'ban_reasons') or not player.ban_reasons:
            return

        print(f"{indent}{fmt['BOLD']}BAN REASONS ({len(player.ban_reasons)}):{fmt['END']}")

        for i, reason in enumerate(player.ban_reasons, 1):
            if len(reason) > 200:
                print(f"{indent}  {fmt['RED']}{i}.{fmt['END']} {reason[:200]}")
                remaining = reason[200:]
                chunks = [remaining[j:j + 200] for j in range(0, len(remaining), 200)]
                for chunk in chunks:
                    print(f"{indent}     {chunk}")
            else:
                print(f"{indent}  {fmt['RED']}{i}.{fmt['END']} {reason}")

    def _print_complaints_section(self, player: Player, nickname: str) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        if not hasattr(player, 'complaint_links') or not player.complaint_links:
            return

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

        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} COMPLAINTS ({len(player.complaint_links)}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

        if direct_complaints:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['GREEN']}■ DIRECT CONNECTIONS ({len(direct_complaints)}):{fmt['END']}")
            for i, complaint in enumerate(direct_complaints, 1):
                link = complaint.get("link", "No link")
                channel = complaint.get("channel", "Unknown channel")
                content = complaint.get("content", "No content available")
                author = complaint.get("author", "Unknown")

                print(f"  {box['V']}   {box['TL']}{box['H'] * 92}{box['TR']}")
                print(f"  {box['V']}   {box['V']} {i}. {fmt['BLUE']}{fmt['UNDERLINE']}{link}{fmt['END']}")
                print(
                    f"  {box['V']}   {box['V']} {fmt['BOLD']}Channel:{fmt['END']} {channel} | {fmt['BOLD']}Author:{fmt['END']} {author}")

                if content:
                    print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']}")
                    self.formatter.print_wrapped_content(content, indent="          ")
                else:
                    print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")

                mentioned_nicks = complaint.get("mentioned_nicknames", [nickname])
                if len(mentioned_nicks) > 1:
                    print(
                        f"  {box['V']}   {box['V']} {fmt['BOLD']}Associated with:{fmt['END']} {', '.join(mentioned_nicks)}")

                print(f"  {box['V']}   {box['BL']}{box['H'] * 92}{box['BR']}")

        if indirect_complaints:
            if direct_complaints:
                print(f"  {box['V']}")

            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ INDIRECT CONNECTIONS ({len(indirect_complaints)}):{fmt['END']}")

            channels = Counter(complaint.get("channel", "Unknown channel") for complaint in indirect_complaints)

            if channels:
                for channel, count in channels.items():
                    print(f"  {box['V']}     • {channel}: {count} complaints")

            if indirect_complaints:
                links = [complaint.get("link", "No link") for complaint in indirect_complaints[:3]]
                print(f"  {box['V']}     • Sample links: {', '.join(links)}")

                if len(indirect_complaints) > 3:
                    print(f"  {box['V']}     • ... and {len(indirect_complaints) - 3} more complaints not shown")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

    def _print_ip_section(self, player: Player, nickname: str) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        if not hasattr(player, 'associated_ips') or not player.associated_ips:
            return

        original_ips = []
        shared_ips = []
        alt_shared_ips = []
        multi_user_ips = []

        nicknames_set = set(player.nicknames)

        for ip, shared_with in player.associated_ips.items():
            if nickname in shared_with:
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

        total_relevant_ips = len(original_ips) + len(shared_ips) + len(alt_shared_ips) + len(multi_user_ips)

        width = 96
        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED IPs ({total_relevant_ips} total):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * width}{box['VL']}{fmt['END']}")

        if original_ips:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY IPs ({len(original_ips)}) - Used only by {nickname}:{fmt['END']}")

            if len(original_ips) == 1:
                print(
                    f"  {box['V']}   {fmt['BOLD']}1.{fmt['END']} {fmt['CYAN']}{original_ips[0]}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
            else:
                print(
                    f"  {box['V']}   {fmt['BOLD']}1.{fmt['END']} {fmt['CYAN']}{original_ips[0]}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                print(
                    f"  {box['V']}   {fmt['BOLD']}+ {len(original_ips) - 1} additional IPs used only by {nickname}{fmt['END']}")

            if shared_ips or alt_shared_ips or multi_user_ips:
                print(f"  {box['V']}")

        if shared_ips:
            display_limit = min(10, len(shared_ips))
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED IPs ({len(shared_ips)}) - Used by {nickname} and others:{fmt['END']}")
            for i, (ip, users) in enumerate(shared_ips[:display_limit], 1):
                others = [user for user in users if user != nickname]
                others_str = self.formatter.truncate_list(others, 5)

                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                print(f"  {box['V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")
                print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")

                if i < display_limit:
                    print(f"  {box['V']}")

            if len(shared_ips) > display_limit:
                print(
                    f"  {box['V']}   {fmt['BOLD']}+ {len(shared_ips) - display_limit} more shared IPs not shown{fmt['END']}")

            if alt_shared_ips or multi_user_ips:
                print(f"  {box['V']}")

        if alt_shared_ips:
            multi_alt_ips = []
            solo_alt_ips = []

            for ip, users in alt_shared_ips:
                alt_owners = [user for user in users if user in nicknames_set]
                others = [user for user in users if user not in nicknames_set]

                if len(alt_owners) > 1 or others:
                    multi_alt_ips.append((ip, alt_owners, others))
                else:
                    solo_alt_ips.append((ip, alt_owners[0]))

            print(f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT IPs ({len(alt_shared_ips)}):{fmt['END']}")

            if len(alt_shared_ips) > 50:
                alt_ip_counts = {}
                for ip, users in alt_shared_ips:
                    for user in users:
                        if user in nicknames_set:
                            if user not in alt_ip_counts:
                                alt_ip_counts[user] = 0
                            alt_ip_counts[user] += 1

                print(f"  {box['V']}   {fmt['BOLD']}Summary by alt account:{fmt['END']}")
                for alt, count in sorted(alt_ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
                    print(f"  {box['V']}     • {alt}: {count} IPs")

                if len(alt_ip_counts) > 20:
                    print(f"  {box['V']}     • ... and {len(alt_ip_counts) - 20} more accounts")

                ip_prefixes = {}
                for ip, _ in alt_shared_ips:
                    prefix = '.'.join(ip.split('.')[:2])
                    if prefix not in ip_prefixes:
                        ip_prefixes[prefix] = 0
                    ip_prefixes[prefix] += 1

                print(f"  {box['V']}   {fmt['BOLD']}IP range distribution:{fmt['END']}")
                for prefix, count in sorted(ip_prefixes.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {box['V']}     • {prefix}.x.x: {count} IPs")

                if len(ip_prefixes) > 10:
                    print(f"  {box['V']}     • ... and {len(ip_prefixes) - 10} more IP ranges")

                print(f"  {box['V']}   {fmt['BOLD']}Sample IPs ({min(5, len(alt_shared_ips))}):{fmt['END']}")
                for i, (ip, users) in enumerate(alt_shared_ips[:5], 1):
                    alt_owners = [user for user in users if user in nicknames_set]
                    print(f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - Used by: {', '.join(alt_owners[:3])}" +
                          (f" and {len(alt_owners) - 3} more" if len(alt_owners) > 3 else ""))
            else:
                display_limit = min(10, len(multi_alt_ips))

                for i, (ip, alt_owners, others) in enumerate(multi_alt_ips[:display_limit], 1):
                    print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                    print(f"  {box['V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")

                    if others:
                        others_str = self.formatter.truncate_list(others, 5)
                        print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")

                    if i < display_limit and i < len(multi_alt_ips):
                        print(f"  {box['V']}")

                if len(multi_alt_ips) > display_limit:
                    print(
                        f"  {box['V']}   {fmt['BOLD']}+ {len(multi_alt_ips) - display_limit} additional shared alt IPs not shown{fmt['END']}")

                if solo_alt_ips:
                    print(
                        f"  {box['V']}   {fmt['BOLD']}+ {len(solo_alt_ips)} additional IPs used by single alt accounts{fmt['END']}")

            if multi_user_ips:
                print(f"  {box['V']}")

        if multi_user_ips:
            display_limit = min(20, len(multi_user_ips))
            print(f"  {box['V']} {fmt['BOLD']}■ OTHER SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")

            if len(multi_user_ips) <= display_limit:
                for i, (ip, users) in enumerate(multi_user_ips, 1):
                    users_str = self.formatter.truncate_list(users, 5)
                    print(
                        f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} - Used by: {users_str}")

                    if i % 5 == 0 and i < len(multi_user_ips):
                        print(f"  {box['V']}")
            else:
                ip_ranges = defaultdict(list)
                for ip, _ in multi_user_ips:
                    prefix = '.'.join(ip.split('.')[:2])
                    ip_ranges[prefix].append(ip)

                print(f"  {box['V']}   {fmt['BOLD']}IP Range Distribution:{fmt['END']}")
                sorted_ranges = sorted(ip_ranges.items(), key=lambda x: len(x[1]), reverse=True)

                for prefix, ips in sorted_ranges[:5]:
                    print(f"  {box['V']}      {prefix}.x.x: {len(ips)} IPs")

                    for sample_ip in ips[:3]:
                        users = player.associated_ips[sample_ip]
                        users_str = self.formatter.truncate_list(users, 3)
                        print(f"  {box['V']}        - {fmt['CYAN']}{sample_ip}{fmt['END']} (Used by: {users_str})")

                    if len(ips) > 3:
                        print(f"  {box['V']}        - ... and {len(ips) - 3} more IPs in this range")

                    print(f"  {box['V']}")

                if len(sorted_ranges) > 5:
                    remaining_ranges = len(sorted_ranges) - 5
                    remaining_ips = sum(len(ips) for prefix, ips in sorted_ranges[5:])
                    print(f"  {box['V']}      Other {remaining_ranges} ranges: {remaining_ips} IPs")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

    def _print_hwid_section(self, player: Player, nickname: str) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        if not hasattr(player, 'associated_hwids') or not player.associated_hwids:
            return

        hwid_count = len(player.associated_hwids)
        width = 96

        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED HWIDs ({hwid_count}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * width}{box['VL']}{fmt['END']}")

        original_hwids = []
        shared_hwids = []
        alt_hwids = []
        other_hwids = []

        nicknames_set = set(player.nicknames)

        for hwid, shared_with in player.associated_hwids.items():
            if nickname in shared_with:
                if len(shared_with) == 1:
                    original_hwids.append((hwid, shared_with))
                else:
                    shared_hwids.append((hwid, shared_with))
            elif any(nick in nicknames_set for nick in shared_with):
                alt_hwids.append((hwid, shared_with))
            else:
                other_hwids.append((hwid, shared_with))

        if original_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY HWIDs ({len(original_hwids)}) - Used only by {nickname}:{fmt['END']}")
            if len(original_hwids) <= 5:
                for i, (hwid, _) in enumerate(original_hwids, 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(f"  {box['V']}      {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                    if i < len(original_hwids):
                        print(f"  {box['V']}")
            else:
                for i, (hwid, _) in enumerate(original_hwids[:3], 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(f"  {box['V']}      {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                    if i < 3:
                        print(f"  {box['V']}")
                print(
                    f"  {box['V']}   {fmt['BOLD']}+ {len(original_hwids) - 3} more HWIDs used only by {nickname}{fmt['END']}")

            if shared_hwids or alt_hwids or other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if shared_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED HWIDs ({len(shared_hwids)}) - Used by {nickname} and others:{fmt['END']}")
            for i, (hwid, shared_with) in enumerate(shared_hwids, 1):
                formatted_hwid = self.formatter.format_hwid(hwid)
                others = [nick for nick in shared_with if nick != nickname]

                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")

                if others:
                    shared_str = self.formatter.truncate_list(others, 10)
                    shared_str = self.formatter.truncate_text(shared_str, 70)
                    print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")

                if i < len(shared_hwids):
                    print(f"  {box['V']}")

            if alt_hwids or other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if alt_hwids:
            multi_alt_hwids = []
            single_alt_hwids = defaultdict(list)

            for hwid, shared_with in alt_hwids:
                alt_owners = [nick for nick in shared_with if nick in nicknames_set]
                others = [nick for nick in shared_with if nick not in nicknames_set]

                if len(alt_owners) > 1 or others:
                    multi_alt_hwids.append((hwid, alt_owners, others))
                else:
                    alt_name = alt_owners[0]
                    single_alt_hwids[alt_name].append(hwid)

            alt_hwid_counts = {alt: len(hwids) for alt, hwids in single_alt_hwids.items()}

            sorted_alts = sorted(alt_hwid_counts.items(), key=lambda x: x[1], reverse=True)

            multi_hwid_alts = [alt for alt, count in sorted_alts if count > 1]
            single_hwid_alts = [alt for alt, count in sorted_alts if count == 1]

            total_alts_with_hwids = len(single_alt_hwids)

            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT HWIDs ({len(alt_hwids)}) - Used by alts but not by {nickname}:{fmt['END']}")

            if multi_alt_hwids:
                print(
                    f"  {box['V']}   {fmt['BOLD']}HWIDs shared between multiple accounts ({len(multi_alt_hwids)}):{fmt['END']}")

                for i, (hwid, alt_owners, others) in enumerate(multi_alt_hwids, 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(f"  {box['V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")

                    if others:
                        shared_str = self.formatter.truncate_list(others, 10)
                        shared_str = self.formatter.truncate_text(shared_str, 70)
                        print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")

                    if i < len(multi_alt_hwids) and i < 10:
                        print(f"  {box['V']}")

                    if i >= 10 and len(multi_alt_hwids) > 10:
                        print(
                            f"  {box['V']}      {fmt['BOLD']}+ {len(multi_alt_hwids) - 10} more shared HWIDs{fmt['END']}")
                        break

                print(f"  {box['V']}")

            if multi_hwid_alts:
                print(f"  {box['V']}   {fmt['BOLD']}Alts with multiple HWIDs ({len(multi_hwid_alts)}):{fmt['END']}")

                for i, (alt, count) in enumerate(sorted_alts[:10], 1):
                    if count > 1:
                        print(f"  {box['V']}      • {alt}: {count} HWIDs")

                if len(multi_hwid_alts) > 10:
                    print(f"  {box['V']}      • ...and {len(multi_hwid_alts) - 10} more alts with multiple HWIDs")

                print(f"  {box['V']}")

            if single_hwid_alts:
                print(f"  {box['V']}   {fmt['BOLD']}Alts with single HWID ({len(single_hwid_alts)}):{fmt['END']}")

                v2_hwids = 0
                legacy_hwids = 0

                for alt in single_hwid_alts:
                    hwid = single_alt_hwids[alt][0]
                    if hwid.startswith("V2-"):
                        v2_hwids += 1
                    else:
                        legacy_hwids += 1

                print(f"  {box['V']}      • {v2_hwids} V2 HWIDs, {legacy_hwids} legacy HWIDs")

                if single_hwid_alts:
                    print(f"  {box['V']}      • Sample: {', '.join(single_hwid_alts[:5])}" +
                          (f", and {len(single_hwid_alts) - 5} more" if len(single_hwid_alts) > 5 else ""))

                print(f"  {box['V']}")

            if other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if other_hwids:
            other_users = defaultdict(int)
            for hwid, shared_with in other_hwids:
                for user in shared_with:
                    other_users[user] += 1

            top_other_users = sorted(other_users.items(), key=lambda x: x[1], reverse=True)

            print(
                f"  {box['V']} {fmt['BOLD']}■ OTHER HWIDs ({len(other_hwids)}) - Not associated with {nickname} or alts:{fmt['END']}")

            print(f"  {box['V']}   {fmt['BOLD']}Summary:{fmt['END']}")
            print(f"  {box['V']}      • Total unique users: {len(other_users)}")

            if top_other_users:
                print(f"  {box['V']}      • Top users by HWID count:")
                for user, count in top_other_users[:5]:
                    print(f"  {box['V']}        - {user}: {count} HWIDs")

                if len(top_other_users) > 5:
                    print(f"  {box['V']}        - ...and {len(top_other_users) - 5} more users")

            print(f"  {box['V']}   {fmt['BOLD']}Sample HWIDs:{fmt['END']}")
            for i, (hwid, shared_with) in enumerate(other_hwids[:3], 1):
                formatted_hwid = self.formatter.format_hwid(hwid)
                users_str = self.formatter.truncate_list(shared_with, 5)
                users_str = self.formatter.truncate_text(users_str, 70)

                print(f"  {box['V']}      {i}. {formatted_hwid}")
                print(f"  {box['V']}         Used by: {users_str}")

                if i < min(3, len(other_hwids)):
                    print(f"  {box['V']}")

            if len(other_hwids) > 3:
                print(f"  {box['V']}      ...and {len(other_hwids) - 3} more HWIDs")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

    def _print_denied_logins_section(self, player: Player, nickname: str) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        if not hasattr(player, 'denied_logins') or not player.denied_logins:
            return

        login_count = len(player.denied_logins)

        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} {fmt['RED']}DENIED LOGIN ATTEMPTS ({login_count}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

        for i, login in enumerate(player.denied_logins[:5], 1):
            time_str = login.get("time", "N/A")
            ip = login.get("ip_address", "N/A")
            server = login.get("server", "N/A")
            user_name = login.get("user_name", nickname)

            print(
                f"  {box['V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

            if user_name != nickname:
                print(f"  {box['V']}      {fmt['BOLD']}Attempted with name:{fmt['END']} {user_name}")

        if len(player.denied_logins) > 5:
            print(f"  {box['V']}   ... and {len(player.denied_logins) - 5} more")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

    def print_message_scan_results(self, scan_results: List[ScanResult]) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        total_players = 0
        total_banned = 0
        total_suspicious = 0
        total_clean = 0
        total_unknown = 0
        total_complaints = 0
        total_hwids = 0
        total_ips = 0
        unique_hwids = set()
        unique_ips = set()
        problematic_players = []

        self.formatter.print_header(f"SCAN RESULTS - {len(scan_results)} messages processed", 100)

        for result in scan_results:
            message = result.message
            players = result.players
            real_players = [p for p in players if getattr(p, 'primary_nickname', '') != "Unknown"]

            total_players += len(real_players)

            self.formatter.print_section(f"MESSAGE: {fmt['BLUE']}{message.link}{fmt['END']}", 100)
            print(f"  {fmt['BOLD']}AUTHOR:{fmt['END']} {message.author_name}")

            for player in real_players:
                if player.status.lower() == "banned":
                    status_str = f"{fmt['RED']}{fmt['BOLD']}BANNED{fmt['END']}"
                    total_banned += 1
                    problematic_players.append((player.primary_nickname, "BANNED", player.ban_counts))
                elif player.status.lower() == "suspicious":
                    status_str = f"{fmt['YELLOW']}{fmt['BOLD']}SUSPICIOUS{fmt['END']}"
                    total_suspicious += 1
                    problematic_players.append((player.primary_nickname, "SUSPICIOUS", player.ban_counts))
                elif player.status.lower() == "clean":
                    status_str = f"{fmt['GREEN']}CLEAN{fmt['END']}"
                    total_clean += 1
                else:
                    status_str = "UNKNOWN"
                    total_unknown += 1

                hwid_erased = ""
                if hasattr(player, 'hwid_erased') and player.hwid_erased:
                    hwid_erased = f" {fmt['YELLOW']}(HWID ERASED){fmt['END']}"

                self.formatter.print_player_header(player.primary_nickname)

                print(
                    f"  {box['V']} {fmt['BOLD']}STATUS:{fmt['END']} {status_str}{hwid_erased} {box['V']} {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")

                if hasattr(player, 'ban_reasons') and player.ban_reasons:
                    print(f"  {box['V']} ", end="")
                    self._print_ban_reasons(player, indent=f"  {box['V']} ")

                if len(player.nicknames) > 1:
                    alt_nicks = [n for n in player.nicknames if n != player.primary_nickname]
                    if alt_nicks:
                        alt_names_text = f"{fmt['BOLD']}ALT NAMES:{fmt['END']} {', '.join(alt_nicks)}"
                        print(f"  {box['V']} {alt_names_text}")

                if hasattr(player, 'complaint_links') and player.complaint_links:
                    total_complaints += len(player.complaint_links)
                    self.formatter.print_section_header("COMPLAINTS")
                    print(
                        f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}FOUND ({len(player.complaint_links)}):{fmt['END']}")

                    for i, complaint in enumerate(player.complaint_links, 1):
                        link = complaint.get("link", "No link")
                        channel = complaint.get("channel", "Unknown channel")
                        content = complaint.get("content", "No content available")

                        print(f"  {box['V']}   {box['TL']}{box['H'] * 70}{box['TR']}")
                        print(f"  {box['V']}   {box['V']} {i}. {fmt['BLUE']}{fmt['UNDERLINE']}{link}{fmt['END']}")
                        print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Channel:{fmt['END']} {channel}")

                        if content:
                            print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']}")
                            content_lines = content.split('\n')
                            for line_idx, line in enumerate(content_lines):
                                if len(line) > 65:
                                    print(f"  {box['V']}   {box['V']}          {line[:65]}")
                                    remaining = line[65:]
                                    chunks = [remaining[i:i + 65] for i in range(0, len(remaining), 65)]
                                    for chunk in chunks:
                                        print(f"  {box['V']}   {box['V']}          {chunk}")
                                else:
                                    print(f"  {box['V']}   {box['V']}          {line}")
                        else:
                            print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")

                        mentioned_nicks = complaint.get("mentioned_nicknames", [player.primary_nickname])
                        if len(mentioned_nicks) > 1:
                            print(
                                f"  {box['V']}   {box['V']} {fmt['BOLD']}Associated with:{fmt['END']} {', '.join(mentioned_nicks)}")

                        print(f"  {box['V']}   {box['BL']}{box['H'] * 70}{box['BR']}")

                has_indirect = False
                if (hasattr(player, 'associated_ips') and player.associated_ips or
                        hasattr(player, 'associated_hwids') and player.associated_hwids or
                        hasattr(player, 'denied_logins') and player.denied_logins):
                    self.formatter.print_section_header("CONNECTION INFORMATION")
                    has_indirect = True

                multi_user_ips = {}
                single_user_ips = {}
                single_user_count = 0

                if hasattr(player, 'associated_ips') and player.associated_ips:
                    for ip, shared_with in player.associated_ips.items():
                        if len(shared_with) > 1:
                            multi_user_ips[ip] = shared_with
                        else:
                            single_user_ips[ip] = shared_with
                            single_user_count += 1

                    ip_count = len(player.associated_ips)
                    total_ips += ip_count

                    if multi_user_ips:
                        print(f"  {box['V']} {fmt['BOLD']}SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")

                        owned_ips = []
                        alt_ips = []
                        other_ips = []

                        nicknames_set = set(player.nicknames)

                        for ip, shared_with in multi_user_ips.items():
                            if player.primary_nickname in shared_with:
                                owned_ips.append((ip, shared_with))
                            elif any(nick in nicknames_set for nick in shared_with):
                                alt_ips.append((ip, shared_with))
                            else:
                                other_ips.append((ip, shared_with))

                        if owned_ips:
                            print(
                                f"  {box['V']}   {fmt['BOLD']}{fmt['GREEN']}■ Owned by {player.primary_nickname}:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(owned_ips):
                                unique_ips.add(ip)
                                others = [nick for nick in shared_with if nick != player.primary_nickname]

                                if others:
                                    shared_str = self.formatter.truncate_list(others, 5)
                                    print(
                                        f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                                else:
                                    print(f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']}")

                            print(f"  {box['V']}")

                        if alt_ips:
                            print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(alt_ips):
                                unique_ips.add(ip)
                                alt_owners = [nick for nick in shared_with if nick in nicknames_set]
                                others = [nick for nick in shared_with if nick not in nicknames_set]

                                print(
                                    f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")

                                if others:
                                    shared_str = self.formatter.truncate_list(others, 5)
                                    print(f"  {box['V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")

                            print(f"  {box['V']}")

                        if other_ips:
                            print(f"  {box['V']}   {fmt['BOLD']}■ Other associated IPs:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(other_ips):
                                unique_ips.add(ip)
                                users_str = self.formatter.truncate_list(shared_with, 5)
                                print(
                                    f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - {fmt['BOLD']}Users:{fmt['END']} {users_str}")

                            print(f"  {box['V']}")

                    if single_user_count > 0:
                        print(
                            f"  {box['V']} {fmt['BOLD']}SINGLE-USER IPs:{fmt['END']} {single_user_count} IPs with only one user")
                        print(f"  {box['V']}")

                if hasattr(player, 'associated_hwids') and player.associated_hwids:
                    hwid_count = len(player.associated_hwids)
                    total_hwids += hwid_count

                    print(f"  {box['V']} {fmt['BOLD']}HWIDs ({hwid_count}):{fmt['END']}")

                    owned_hwids = []
                    alt_hwids = []
                    other_hwids = []

                    nicknames_set = set(player.nicknames)

                    for hwid, shared_with in player.associated_hwids.items():
                        if player.primary_nickname in shared_with:
                            owned_hwids.append((hwid, shared_with))
                        elif any(nick in nicknames_set for nick in shared_with):
                            alt_hwids.append((hwid, shared_with))
                        else:
                            other_hwids.append((hwid, shared_with))

                    if owned_hwids:
                        print(
                            f"  {box['V']}   {fmt['BOLD']}{fmt['GREEN']}■ Owned by {player.primary_nickname}:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(owned_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            others = [nick for nick in shared_with if nick != player.primary_nickname]

                            if others:
                                shared_str = self.formatter.truncate_list(others, 5)
                                print(
                                    f"  {box['V']}     • {formatted_hwid} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                            else:
                                print(f"  {box['V']}     • {formatted_hwid} - {fmt['GREEN']}Only user{fmt['END']}")

                        print(f"  {box['V']}")

                    if alt_hwids:
                        print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(alt_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            alt_owners = [nick for nick in shared_with if nick in nicknames_set]
                            others = [nick for nick in shared_with if nick not in nicknames_set]

                            print(
                                f"  {box['V']}     • {formatted_hwid} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")

                            if others:
                                shared_str = self.formatter.truncate_list(others, 5)
                                print(f"  {box['V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")

                        print(f"  {box['V']}")

                    if other_hwids:
                        print(f"  {box['V']}   {fmt['BOLD']}■ Other associated HWIDs:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(other_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            users_str = self.formatter.truncate_list(shared_with, 5)

                            print(f"  {box['V']}     • {formatted_hwid} - {fmt['BOLD']}Users:{fmt['END']} {users_str}")

                        print(f"  {box['V']}")

                if hasattr(player, 'denied_logins') and player.denied_logins:
                    login_count = len(player.denied_logins)
                    print(f"  {box['V']} {fmt['BOLD']}{fmt['RED']}DENIED LOGINS ({login_count}):{fmt['END']}")

                    for i, login in enumerate(player.denied_logins[:3], 1):
                        time_str = login.get("time", "N/A")
                        ip = login.get("ip_address", "N/A")
                        hwid = login.get("hwid", "N/A")
                        server = login.get("server", "N/A")
                        user_name = login.get("user_name", player.primary_nickname)

                        print(
                            f"  {box['V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

                        if user_name != player.primary_nickname:
                            print(f"  {box['V']}      {fmt['BOLD']}Used name:{fmt['END']} {user_name}")

                    if len(player.denied_logins) > 3:
                        print(f"  {box['V']}   ... and {len(player.denied_logins) - 3} more")

                print(f"  {box['BL']}{box['H'] * 74}{box['BR']}")

        self.formatter.print_header(" SCAN SUMMARY ", 100)
        print(f"  {box['V']} {fmt['BOLD']}Messages processed:{fmt['END']} {len(scan_results)}")
        print(f"  {box['V']} {fmt['BOLD']}Players found:{fmt['END']} {total_players}")
        print(f"  {box['V']} {fmt['BOLD']}Status breakdown:{fmt['END']}")

        if total_players:
            banned_pct = total_banned / total_players * 100
            suspicious_pct = total_suspicious / total_players * 100
            clean_pct = total_clean / total_players * 100
            unknown_pct = total_unknown / total_players * 100 if total_unknown else 0
        else:
            banned_pct = suspicious_pct = clean_pct = unknown_pct = 0

        print(
            f"  {box['V']}    • {fmt['RED']}{fmt['BOLD']}Banned:{fmt['END']} {total_banned} ({banned_pct:.1f}% of total)")
        print(
            f"  {box['V']}    • {fmt['YELLOW']}{fmt['BOLD']}Suspicious:{fmt['END']} {total_suspicious} ({suspicious_pct:.1f}% of total)")
        print(f"  {box['V']}    • {fmt['GREEN']}Clean:{fmt['END']} {total_clean} ({clean_pct:.1f}% of total)")

        if total_unknown:
            print(f"  {box['V']}    • Unknown: {total_unknown} ({unknown_pct:.1f}% of total)")
        else:
            print(f"  {box['V']}    • Unknown: 0")

        print(f"  {box['V']} {fmt['BOLD']}Complaints found:{fmt['END']} {total_complaints}")
        print(f"  {box['V']} {fmt['BOLD']}Unique HWIDs detected:{fmt['END']} {len(unique_hwids)}")
        print(f"  {box['V']} {fmt['BOLD']}Unique IPs detected:{fmt['END']} {len(unique_ips)}")

        if problematic_players:
            print(f"  {box['VR']}{box['H'] * 96}{box['VL']}")
            print(f"  {box['V']} {fmt['BOLD']}PROBLEMATIC PLAYERS DETECTED:{fmt['END']}")

            for nickname, status, bans in problematic_players:
                status_color = fmt['RED'] if status == "BANNED" else fmt['YELLOW']
                print(f"  {box['V']}   • {nickname}: {status_color}{status}{fmt['END']} (Bans: {bans})")

        print(f"\n{'=' * 100}")
        self.formatter.print_color_legend()

    def print_ban_bypass_results(self, ban_bypass_results: List[Dict[str, Any]]) -> None:
        fmt = self.formatter.fmt
        box = self.formatter.box

        total_players = 0
        total_banned = 0
        total_bypasses = 0
        total_hwid_matches = 0
        total_ip_matches = 0
        total_no_matches = 0

        self.formatter.print_header(f"BAN BYPASS CHECK RESULTS - {len(ban_bypass_results)} ban hits processed", 100)

        for result in ban_bypass_results:
            banned_user = result.get("author_name", "Unknown")
            bypass_users = result.get("bypass_user_names", [])
            confidence = result.get("ban_bypass_confidence", "Unknown")
            ban_time = result.get("ban_time", "Unknown")
            ban_expires = result.get("ban_expires", "Unknown")
            message_link = result.get("message_link", "")
            bypass_success_status = result.get("bypass_success_status", "Unknown")

            total_players += 1

            self.formatter.print_section(f"BAN HIT: {fmt['BLUE']}{message_link}{fmt['END']}", 100)
            print(f"  {fmt['BOLD']}BANNED USER:{fmt['END']} {banned_user}")
            print(f"  {fmt['BOLD']}BAN TIME:{fmt['END']} {ban_time} {fmt['BOLD']}EXPIRES:{fmt['END']} {ban_expires}")
            print(f"  {fmt['BOLD']}CONFIDENCE:{fmt['END']} {confidence}")

            if "Successful Bypass" == bypass_success_status:
                status_str = f"{fmt['RED']}{fmt['BOLD']}{bypass_success_status}{fmt['END']}"
            elif "Possibly Successful Bypass" == bypass_success_status:
                status_str = f"{fmt['YELLOW']}{fmt['BOLD']}{bypass_success_status}{fmt['END']}"
            elif "Unsuccessful Bypass" == bypass_success_status:
                status_str = f"{fmt['GREEN']}{bypass_success_status}{fmt['END']}"
            else:
                status_str = bypass_success_status

            print(f"  {fmt['BOLD']}BYPASS STATUS:{fmt['END']} {status_str}")

            if bypass_users:
                print(
                    f"  {fmt['BOLD']}POTENTIAL BYPASSERS ({len(bypass_users)}):{fmt['END']} {', '.join(bypass_users)}")
                total_bypasses += len(bypass_users)
            else:
                print(f"  {fmt['BOLD']}POTENTIAL BYPASSERS:{fmt['END']} None")

            if "HWID Match" in confidence:
                total_hwid_matches += 1
            elif "IP Match" in confidence or "Time" in confidence:
                total_ip_matches += 1
            else:
                total_no_matches += 1

            player_results = result.get("results", [])
            if player_results:
                player_data = player_results[0]

                complaint_links = player_data.get("complaint_links", [])
                if complaint_links:
                    print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['V']} {fmt['YELLOW']}COMPLAINTS ({len(complaint_links)}):{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

                    for i, complaint in enumerate(complaint_links, 1):
                        link = complaint.get("link", "No link")
                        content = complaint.get("content", "No content available")

                        print(f"  {box['V']}   {box['TL']}{box['H'] * 92}{box['TR']}")
                        print(f"  {box['V']}   {box['V']} {i}. {fmt['BLUE']}{fmt['UNDERLINE']}{link}{fmt['END']}")

                        if content:
                            print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']}")
                            content_lines = content.split('\n')
                            for line in content_lines:
                                if len(line) > 85:
                                    chunks = [line[i:i + 85] for i in range(0, len(line), 85)]
                                    for chunk in chunks:
                                        print(f"  {box['V']}   {box['V']}          {chunk}")
                                else:
                                    print(f"  {box['V']}   {box['V']}          {line}")
                        else:
                            print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")

                        print(f"  {box['V']}   {box['BL']}{box['H'] * 92}{box['BR']}")

                    print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

                initial_account = player_data.get("initial_account", {})
                associated_ips = initial_account.get("associated_ips", {})

                if associated_ips:
                    print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED IPs ({len(associated_ips)}):{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

                    for i, (ip, nicknames) in enumerate(associated_ips.items()):
                        print(f"  {box['V']}   {fmt['BOLD']}{i + 1}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")

                        if banned_user in nicknames:
                            others = [n for n in nicknames if n != banned_user]
                            print(f"  {box['V']}      {fmt['GREEN']}Used by {banned_user}{fmt['END']}")

                            if others:
                                print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {', '.join(others)}")
                        else:
                            print(f"  {box['V']}      {fmt['BOLD']}Used by:{fmt['END']} {', '.join(nicknames)}")

                        if i < len(associated_ips) - 1:
                            print(f"  {box['V']}")

                    print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

                associated_hwids = initial_account.get("associated_hwids", {})

                if associated_hwids:
                    print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED HWIDs ({len(associated_hwids)}):{fmt['END']}")
                    print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")

                    for i, (hwid, nicknames) in enumerate(associated_hwids.items()):
                        formatted_hwid = self.formatter.format_hwid(hwid)
                        print(f"  {box['V']}   {fmt['BOLD']}{i + 1}.{fmt['END']} {formatted_hwid}")

                        if banned_user in nicknames:
                            others = [n for n in nicknames if n != banned_user]
                            print(f"  {box['V']}      {fmt['GREEN']}Used by {banned_user}{fmt['END']}")

                            if others:
                                print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {', '.join(others)}")
                        else:
                            print(f"  {box['V']}      {fmt['BOLD']}Used by:{fmt['END']} {', '.join(nicknames)}")

                        if i < len(associated_hwids) - 1:
                            print(f"  {box['V']}")

                    print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

        total_successful_bypass = sum(
            1 for r in ban_bypass_results if r.get("bypass_success_status") == "Successful Bypass")
        total_possibly_successful = sum(
            1 for r in ban_bypass_results if r.get("bypass_success_status") == "Possibly Successful Bypass")
        total_unsuccessful = sum(
            1 for r in ban_bypass_results if r.get("bypass_success_status") == "Unsuccessful Bypass")

        self.formatter.print_header(" BAN BYPASS SUMMARY ", 100)
        print(f"  {box['V']} {fmt['BOLD']}Ban Hits processed:{fmt['END']} {len(ban_bypass_results)}")
        print(f"  {box['V']} {fmt['BOLD']}Players analyzed:{fmt['END']} {total_players}")
        print(f"  {box['V']} {fmt['BOLD']}Potential bypassers found:{fmt['END']} {total_bypasses}")
        print(f"  {box['V']} {fmt['BOLD']}Confidence breakdown:{fmt['END']}")
        print(f"  {box['V']}    • {fmt['RED']}{fmt['BOLD']}HWID Matches:{fmt['END']} {total_hwid_matches}")
        print(f"  {box['V']}    • {fmt['YELLOW']}{fmt['BOLD']}IP Matches:{fmt['END']} {total_ip_matches}")
        print(f"  {box['V']}    • No Matches: {total_no_matches}")
        print(f"  {box['V']} {fmt['BOLD']}Bypass status breakdown:{fmt['END']}")
        print(f"  {box['V']}    • {fmt['RED']}{fmt['BOLD']}Successful Bypasses:{fmt['END']} {total_successful_bypass}")
        print(
            f"  {box['V']}    • {fmt['YELLOW']}{fmt['BOLD']}Possibly Successful Bypasses:{fmt['END']} {total_possibly_successful}")
        print(f"  {box['V']}    • {fmt['GREEN']}Unsuccessful Bypasses:{fmt['END']} {total_unsuccessful}")
        print(
            f"  {box['V']}    • Unknown Status: {len(ban_bypass_results) - total_successful_bypass - total_possibly_successful - total_unsuccessful}")

        print(f"\n{'=' * 100}")
        self.formatter.print_color_legend()
