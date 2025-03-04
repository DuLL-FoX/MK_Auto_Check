import json
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional

from models.ban_hit import BanBypassCheck
from models.message import ScanResult
from models.player import Player
from utils.logging_utils import get_logger

logger = get_logger(__name__)


class ReportService:
    def __init__(self) -> None:
        self.report_filename = "scan_report.json"
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

    def _print_box(self, title, width=100, style='header'):
        is_header = style == 'header'
        color_prefix = self.fmt['HEADER'] if is_header else ''
        color_prefix += self.fmt['BOLD']
        print(f"\n{color_prefix}{self.box['TL']}{self.box['H'] * (width - 2)}{self.box['TR']}{self.fmt['END']}")
        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(
            f"{color_prefix}{self.box['V']}{' ' * padding} {title} {' ' * right_padding}{self.box['V']}{self.fmt['END']}")
        print(f"{color_prefix}{self.box['BL']}{self.box['H'] * (width - 2)}{self.box['BR']}{self.fmt['END']}")

    def _print_header(self, title, width=100):
        self._print_box(title, width, 'header')

    def _print_section(self, title, width=100):
        self._print_box(title, width, 'section')

    def _format_status(self, status, hwid_erased=False):
        status = status.upper()
        if status.lower() == "banned":
            status_str = f"{self.fmt['RED']}{self.fmt['BOLD']}{status}{self.fmt['END']}"
        elif status.lower() == "suspicious":
            status_str = f"{self.fmt['YELLOW']}{self.fmt['BOLD']}{status}{self.fmt['END']}"
        elif status.lower() == "clean":
            status_str = f"{self.fmt['GREEN']}{status}{self.fmt['END']}"
        else:
            status_str = status
        if hwid_erased:
            status_str += f" {self.fmt['YELLOW']}(HWID ERASED){self.fmt['END']}"
        return status_str

    def _format_hwid(self, hwid):
        fmt = self.fmt
        if hwid.startswith("V2-"):
            prefix = f"{fmt['BOLD']}{fmt['CYAN']}V2-{fmt['END']}"
            base = hwid[3:]
            return f"{prefix}{fmt['CYAN']}{base}{fmt['END']}"
        return f"{fmt['CYAN']}{hwid}{fmt['END']}"

    def _truncate_list(self, items, limit=5, joiner=", "):
        if not items:
            return ""
        if len(items) <= limit:
            return joiner.join(items)
        return joiner.join(items[:limit]) + f", and {len(items) - limit} more"

    def _truncate_text(self, text, max_length=70):
        if text and len(text) > max_length:
            return text[:max_length - 3] + "..."
        return text

    def _print_player_header(self, name, width=76):
        box = self.box
        fmt = self.fmt
        player_header = f"PLAYER: {name}"
        print(f"\n  {fmt['BOLD']}{fmt['CYAN']}{box['TL']}{box['H'] * (width - 2)}{box['TR']}{fmt['END']}")
        padding = (width - len(player_header) - 4) // 2
        right_padding = width - padding - len(player_header) - 4
        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['V']}{' ' * padding} {player_header} {' ' * right_padding}{box['V']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{fmt['CYAN']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

    def _print_section_header(self, title, width=76):
        box = self.box
        fmt = self.fmt
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")
        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(
            f"  {fmt['BOLD']}{box['V']}{' ' * padding} {title} {' ' * right_padding}{box['V']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

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
        self.print_nickname_search_results(nickname, player)
        return report_data

    def _generate_ip_data(self, nickname: str, player: Player) -> Dict[str, Any]:
        ip_data = {
            "type": "associated_ips",
            "ips": []
        }
        for ip, shared_with in player.associated_ips.items():
            denied_logins_for_ip = []
            if hasattr(player, 'denied_logins'):
                denied_logins_for_ip = [
                    login for login in player.denied_logins
                    if login.get("ip_address") == ip
                ]
            owner = self._determine_owner(nickname, player.nicknames, shared_with)
            others = [nick for nick in shared_with if nick != owner]
            ip_entry = {
                "ip": ip,
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
        for hwid, shared_with in player.associated_hwids.items():
            denied_logins_for_hwid = []
            if hasattr(player, 'denied_logins'):
                denied_logins_for_hwid = [
                    login for login in player.denied_logins
                    if login.get("hwid") == hwid
                ]
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

    def _determine_owner(self, primary_nickname: str, nicknames: List[str], shared_with: List[str]) -> str:
        if primary_nickname in shared_with:
            return primary_nickname
        for nick in nicknames:
            if nick in shared_with:
                return nick
        return shared_with[0] if shared_with else "Unknown"

    def print_nickname_search_results(self, nickname: str, player: Player) -> None:
        box = self.box
        fmt = self.fmt
        status_str = self._format_status(player.status, getattr(player, 'hwid_erased', False))
        self._print_header(f"SCAN RESULTS FOR: {nickname}", 100)

        print(f"  {fmt['BOLD']}STATUS:{fmt['END']} {status_str} | {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")
        if hasattr(player, 'ban_reasons') and player.ban_reasons:
            print(f"  {fmt['BOLD']}BAN REASONS:{fmt['END']} {', '.join(player.ban_reasons)}")

        if len(player.nicknames) > 1:
            print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
            print(f"  {fmt['BOLD']}{box['V']} ASSOCIATED NICKNAMES:{fmt['END']}")
            other_nicks = [nick for nick in player.nicknames if nick != nickname]
            if other_nicks:
                print(f"  {box['V']}   {', '.join(other_nicks)}")
            print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

        self._print_complaints_section(player, nickname)

        self._print_ip_section(player, nickname)

        self._print_hwid_section(player, nickname)

        self._print_denied_logins_section(player, nickname)

        print(f"\n{'=' * 100}")

    def _print_complaints_section(self, player: Player, nickname: str) -> None:
        box = self.box
        fmt = self.fmt
        if not hasattr(player, 'complaint_links') or not player.complaint_links:
            return
        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * 96}{box['TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['V']} {fmt['YELLOW']}COMPLAINTS ({len(player.complaint_links)}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * 96}{box['VL']}{fmt['END']}")
        for i, complaint in enumerate(player.complaint_links, 1):
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
                self._print_wrapped_content(content, box, indent="          ")
            else:
                print(f"  {box['V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")
            mentioned_nicks = complaint.get("mentioned_nicknames", [nickname])
            if len(mentioned_nicks) > 1:
                print(
                    f"  {box['V']}   {box['V']} {fmt['BOLD']}Associated with:{fmt['END']} {', '.join(mentioned_nicks)}")
            print(f"  {box['V']}   {box['BL']}{box['H'] * 92}{box['BR']}")
        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * 96}{box['BR']}{fmt['END']}")

    def _print_wrapped_content(self, content, box, indent="", line_width=85):
        content_lines = content.split('\n')
        for line in content_lines:
            if len(line) > line_width:
                chunks = [line[i:i + line_width] for i in range(0, len(line), line_width)]
                for j, chunk in enumerate(chunks):
                    print(f"  {box['V']}   {box['V']}{indent}{chunk}")
            else:
                print(f"  {box['V']}   {box['V']}{indent}{line}")

    def _print_ip_section(self, player: Player, nickname: str) -> None:
        box = self.box
        fmt = self.fmt

        if not hasattr(player, 'associated_ips') or not player.associated_ips:
            return

        original_ips = []
        shared_ips = []
        alt_shared_ips = []
        multi_user_ips = []

        # Count IPs by category
        solo_non_relevant_count = 0
        total_ips = 0

        for ip, shared_with in player.associated_ips.items():
            total_ips += 1

            if nickname in shared_with:
                if len(shared_with) == 1:
                    original_ips.append(ip)
                else:
                    shared_ips.append((ip, shared_with))
            elif any(nick in player.nicknames for nick in shared_with):
                if len(shared_with) > 1:
                    alt_shared_ips.append((ip, shared_with))
            elif len(shared_with) > 1:
                multi_user_ips.append((ip, shared_with))
            else:
                solo_non_relevant_count += 1

        shared_ips.sort(key=lambda x: len(x[1]), reverse=True)
        alt_shared_ips.sort(key=lambda x: len(x[1]), reverse=True)
        multi_user_ips.sort(key=lambda x: len(x[1]), reverse=True)

        meaningful_count = len(original_ips) + len(shared_ips) + len(alt_shared_ips) + len(multi_user_ips)

        if meaningful_count == 0:
            return

        width = 96
        print(f"\n  {fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")
        print(
            f"  {fmt['BOLD']}{box['V']} ASSOCIATED IPs ({total_ips} total, {meaningful_count} with intersections):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * width}{box['VL']}{fmt['END']}")

        if original_ips:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY IPs ({len(original_ips)}) - Used only by {nickname}:{fmt['END']}")
            for i, ip in enumerate(original_ips, 1):
                print(
                    f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")

            if shared_ips or alt_shared_ips or multi_user_ips:
                print(f"  {box['V']}")

        if shared_ips:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED IPs ({len(shared_ips)}) - Used by {nickname} and others:{fmt['END']}")
            for i, (ip, users) in enumerate(shared_ips, 1):
                others = [user for user in users if user != nickname]
                others_str = self._truncate_list(others, 5)
                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                print(f"  {box['V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")
                print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")
                if i < len(shared_ips):
                    print(f"  {box['V']}")

            if alt_shared_ips or multi_user_ips:
                print(f"  {box['V']}")

        if alt_shared_ips:
            section_added = False
            alt_section_header = (
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT SHARED IPs ({len(alt_shared_ips)}):{fmt['END']}"
            )

            for i, (ip, users) in enumerate(alt_shared_ips, 1):
                alt_owners = [user for user in users if user in player.nicknames]
                others = [user for user in users if user not in player.nicknames]

                if alt_owners and others:
                    if not section_added:
                        print(alt_section_header)
                        section_added = True

                    print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                    print(f"  {box['V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")
                    if others:
                        others_str = self._truncate_list(others, 5)
                        print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")
                    if i < len(alt_shared_ips) - 1:
                        print(f"  {box['V']}")

            if section_added and multi_user_ips:
                print(f"  {box['V']}")

        if multi_user_ips and len(multi_user_ips) <= 10:
            print(f"  {box['V']} {fmt['BOLD']}■ OTHER SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")
            for i, (ip, users) in enumerate(multi_user_ips, 1):
                users_str = self._truncate_list(users, 5)
                print(
                    f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} - Used by: {users_str}")
        elif multi_user_ips:
            print(f"  {box['V']} {fmt['BOLD']}■ OTHER SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")
            ip_ranges = {}
            for ip, _ in multi_user_ips:
                prefix = '.'.join(ip.split('.')[:2])
                if prefix not in ip_ranges:
                    ip_ranges[prefix] = []
                ip_ranges[prefix].append(ip)

            print(f"  {box['V']}   {fmt['BOLD']}IP Range Distribution:{fmt['END']}")
            sorted_ranges = sorted(ip_ranges.items(), key=lambda x: len(x[1]), reverse=True)
            for prefix, ips in sorted_ranges[:5]:
                print(f"  {box['V']}      {prefix}.x.x: {len(ips)} IPs")

            if len(sorted_ranges) > 5:
                remaining = sum(len(ips) for prefix, ips in sorted_ranges[5:])
                print(f"  {box['V']}      Other ranges: {remaining} IPs")

        if solo_non_relevant_count > 0:
            print(f"  {box['V']}")
            print(
                f"  {box['V']} {fmt['BOLD']}■ NOTE:{fmt['END']} {solo_non_relevant_count} additional IPs with single users not shown")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

    def _print_hwid_section(self, player: Player, nickname: str) -> None:
        box = self.box
        fmt = self.fmt

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

        for hwid, shared_with in player.associated_hwids.items():
            if nickname in shared_with:
                if len(shared_with) == 1:
                    original_hwids.append((hwid, shared_with))
                else:
                    shared_hwids.append((hwid, shared_with))
            elif any(nick in player.nicknames for nick in shared_with):
                alt_hwids.append((hwid, shared_with))
            else:
                other_hwids.append((hwid, shared_with))

        if original_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY HWIDs ({len(original_hwids)}) - Used only by {nickname}:{fmt['END']}")
            for i, (hwid, _) in enumerate(original_hwids, 1):
                formatted_hwid = self._format_hwid(hwid)
                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['V']}      {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                if i < len(original_hwids):
                    print(f"  {box['V']}")
            if shared_hwids or alt_hwids or other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if shared_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED HWIDs ({len(shared_hwids)}) - Used by {nickname} and others:{fmt['END']}")
            for i, (hwid, shared_with) in enumerate(shared_hwids, 1):
                formatted_hwid = self._format_hwid(hwid)
                others = [nick for nick in shared_with if nick != nickname]
                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")
                if others:
                    shared_str = self._truncate_list(others, 10)
                    shared_str = self._truncate_text(shared_str, 70)
                    print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")
                if i < len(shared_hwids):
                    print(f"  {box['V']}")
            if alt_hwids or other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if alt_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT HWIDs ({len(alt_hwids)}) - Used by alts but not by {nickname}:{fmt['END']}")
            for i, (hwid, shared_with) in enumerate(alt_hwids, 1):
                formatted_hwid = self._format_hwid(hwid)
                alt_owners = [nick for nick in shared_with if nick in player.nicknames]
                others = [nick for nick in shared_with if nick not in player.nicknames]
                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")
                if others:
                    shared_str = self._truncate_list(others, 10)
                    shared_str = self._truncate_text(shared_str, 70)
                    print(f"  {box['V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")
                if i < len(alt_hwids):
                    print(f"  {box['V']}")
            if other_hwids:
                print(f"  {box['V']}{box['H'] * width}")

        if other_hwids:
            print(
                f"  {box['V']} {fmt['BOLD']}■ OTHER HWIDs ({len(other_hwids)}) - Not associated with {nickname} or alts:{fmt['END']}")
            for i, (hwid, shared_with) in enumerate(other_hwids, 1):
                formatted_hwid = self._format_hwid(hwid)
                users_str = self._truncate_list(shared_with, 10)
                users_str = self._truncate_text(users_str, 70)
                print(f"  {box['V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['V']}      {fmt['BOLD']}Used by:{fmt['END']} {users_str}")
                if i < len(other_hwids):
                    print(f"  {box['V']}")

        print(f"  {fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

    def _print_denied_logins_section(self, player: Player, nickname: str) -> None:
        box = self.box
        fmt = self.fmt
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

    def generate_ban_bypass_report(self, ban_bypass_checks: List[BanBypassCheck]) -> List[Dict[str, Any]]:
        report_data = []
        confidence_counts = {
            "HWID_MATCH": 0,
            "IP_TIME_CLOSE_MATCH": 0,
            "IP_TIME_MATCH": 0,
            "IP_MATCH": 0,
            "NO_MATCH": 0
        }
        for check in ban_bypass_checks:
            ban_hit = check.ban_hit
            banned_player = check.banned_player
            potential_bypassers_data = []
            for bypasser in check.potential_bypassers:
                bypasser_data = self._player_to_dict(bypasser)
                shared_hwids = [{"hwid": hwid, "shared_with": nicks} for hwid, nicks in
                                bypasser.associated_hwids.items()]
                shared_ips = [{"ip": ip, "shared_with": nicks} for ip, nicks in bypasser.associated_ips.items()]
                bypasser_data["evidence"] = {
                    "shared_hwids": shared_hwids,
                    "shared_ips": shared_ips
                }
                potential_bypassers_data.append(bypasser_data)
            confidence = check.bypass_confidence
            if "HWID Match" in confidence:
                confidence_counts["HWID_MATCH"] += 1
            elif "Close Match" in confidence:
                confidence_counts["IP_TIME_CLOSE_MATCH"] += 1
            elif "Time Match" in confidence:
                confidence_counts["IP_TIME_MATCH"] += 1
            elif "IP Match" in confidence:
                confidence_counts["IP_MATCH"] += 1
            else:
                confidence_counts["NO_MATCH"] += 1
            bypass_data = {
                "ban_hit_id": ban_hit.ban_hit_id,
                "ban_hit_link": ban_hit.ban_hit_link,
                "banned_user_name": banned_player.primary_nickname,
                "banned_user_id": banned_player.user_id,
                "ban_time": ban_hit.ban_time.isoformat() if ban_hit.ban_time else "N/A",
                "ban_expires": ban_hit.ban_expires.isoformat() if ban_hit.ban_expires else "N/A",
                "ip_address": ban_hit.ip_address,
                "hwid": ban_hit.hwid,
                "hwid_erased": ban_hit.hwid_erased,
                "status": banned_player.status,
                "ban_counts": banned_player.ban_counts,
                "ban_reasons": banned_player.ban_reasons,
                "connection_link": banned_player.connection_link,
                "bypass_confidence": check.bypass_confidence,
                "potential_bypassers": potential_bypassers_data,
                "complaint_links": check.complaint_links,
                "all_associated_ips": banned_player.associated_ips,
                "all_associated_hwids": banned_player.associated_hwids
            }
            message_data = {
                "message_id": "BanBypassCheck",
                "message_link": ban_hit.ban_hit_link,
                "author_name": "BanBypassCheck",
                "author_id": "N/A",
                "scan_time": datetime.now().isoformat(),
                "results": [bypass_data]
            }
            report_data.append(message_data)
            logger.info(f"Ban bypass: {banned_player.primary_nickname} | " +
                        f"Confidence: {check.bypass_confidence} | " +
                        f"Potential bypassers: {len(potential_bypassers_data)}")
        if ban_bypass_checks:
            logger.info(f"Ban bypass check complete: {len(ban_bypass_checks)} checks | " +
                        f"HWID Matches: {confidence_counts['HWID_MATCH']} | " +
                        f"IP+Time Close Matches: {confidence_counts['IP_TIME_CLOSE_MATCH']} | " +
                        f"IP+Time Matches: {confidence_counts['IP_TIME_MATCH']} | " +
                        f"IP Matches: {confidence_counts['IP_MATCH']} | " +
                        f"No Matches: {confidence_counts['NO_MATCH']}")
        return report_data

    def _player_to_dict(self, player: Player) -> Dict[str, Any]:
        enhanced_ips = {}
        for ip, shared_with in player.associated_ips.items():
            owner = self._determine_owner(
                getattr(player, 'primary_nickname', player.nicknames[0] if player.nicknames else "Unknown"),
                player.nicknames, shared_with)
            enhanced_ips[ip] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }
        enhanced_hwids = {}
        for hwid, shared_with in player.associated_hwids.items():
            owner = self._determine_owner(
                getattr(player, 'primary_nickname', player.nicknames[0] if player.nicknames else "Unknown"),
                player.nicknames, shared_with)
            enhanced_hwids[hwid] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }
        primary_nickname = (getattr(player, 'primary_nickname', None) or (
            player.nicknames[0] if player.nicknames else "Unknown"))
        return {
            "initial_account": {
                "user_id": player.user_id,
                "nicknames": player.nicknames,
                "primary_nickname": primary_nickname,
                "status": player.status,
                "ban_counts": player.ban_counts,
                "ban_reasons": getattr(player, 'ban_reasons', []),
                "suspected_vpn": getattr(player, 'suspected_vpn', False),
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

    def _get_verdict_string(self, account: Dict[str, Any], hwid_erased: bool = False,
                            bypass_confidence: Optional[str] = None) -> str:
        if bypass_confidence in {"100% (HWID Match)", "20-30% (IP + Time Match)", "IP+Time Match (5-10 min, 30-50%)"}:
            verdict = f"POTENTIAL BYPASS - {bypass_confidence}"
        elif account.get("ban_counts", 0) >= 5:
            verdict = "SUSPICIOUS - multiple bans"
        else:
            status_mapping = {
                "banned": "BANNED",
                "clean": "CLEAN",
                "suspicious": "SUSPICIOUS",
            }
            status = account.get("status", "unknown").lower()
            verdict = status_mapping.get(status, "UNKNOWN")
        if hwid_erased:
            verdict += " / HWID Erased"
        return verdict

    def print_message_scan_results(self, scan_results: List[ScanResult]) -> None:
        fmt = self.fmt
        box = self.box
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
        self._print_header(f"SCAN RESULTS - {len(scan_results)} messages processed", 100)
        for result in scan_results:
            message = result.message
            players = result.players
            real_players = [p for p in players if getattr(p, 'primary_nickname', '') != "Unknown"]
            total_players += len(real_players)
            self._print_section(f"MESSAGE: {fmt['BLUE']}{message.link}{fmt['END']}", 100)
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
                self._print_player_header(player.primary_nickname)

                print(
                    f"  {box['V']} {fmt['BOLD']}STATUS:{fmt['END']} {status_str}{hwid_erased} {box['V']} {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")
                if hasattr(player, 'ban_reasons') and player.ban_reasons:
                    reason_text = f"{fmt['BOLD']}BAN REASONS:{fmt['END']} {', '.join(player.ban_reasons)}"
                    print(f"  {box['V']} {reason_text}")
                if len(player.nicknames) > 1:
                    alt_nicks = [n for n in player.nicknames if n != player.primary_nickname]
                    if alt_nicks:
                        alt_names_text = f"{fmt['BOLD']}ALT NAMES:{fmt['END']} {', '.join(alt_nicks)}"
                        print(f"  {box['V']} {alt_names_text}")

                if hasattr(player, 'complaint_links') and player.complaint_links:
                    total_complaints += len(player.complaint_links)
                    self._print_section_header("COMPLAINTS")
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
                if hasattr(player, 'associated_ips') and player.associated_ips or \
                        hasattr(player, 'associated_hwids') and player.associated_hwids or \
                        hasattr(player, 'denied_logins') and player.denied_logins:
                    self._print_section_header("CONNECTION INFORMATION")
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

                        for ip, shared_with in multi_user_ips.items():
                            if player.primary_nickname in shared_with:
                                owned_ips.append((ip, shared_with))
                            elif any(nick in player.nicknames for nick in shared_with):
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
                                    shared_str = self._truncate_list(others, 5)
                                    print(
                                        f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                                else:
                                    print(f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']}")
                            print(f"  {box['V']}")

                        if alt_ips:
                            print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(alt_ips):
                                unique_ips.add(ip)
                                alt_owners = [nick for nick in shared_with if nick in player.nicknames]
                                others = [nick for nick in shared_with if nick not in player.nicknames]
                                print(
                                    f"  {box['V']}     • {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")
                                if others:
                                    shared_str = self._truncate_list(others, 5)
                                    print(f"  {box['V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                            print(f"  {box['V']}")

                        if other_ips:
                            print(f"  {box['V']}   {fmt['BOLD']}■ Other associated IPs:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(other_ips):
                                unique_ips.add(ip)
                                users_str = self._truncate_list(shared_with, 5)
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

                    for hwid, shared_with in player.associated_hwids.items():
                        if player.primary_nickname in shared_with:
                            owned_hwids.append((hwid, shared_with))
                        elif any(nick in player.nicknames for nick in shared_with):
                            alt_hwids.append((hwid, shared_with))
                        else:
                            other_hwids.append((hwid, shared_with))

                    if owned_hwids:
                        print(
                            f"  {box['V']}   {fmt['BOLD']}{fmt['GREEN']}■ Owned by {player.primary_nickname}:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(owned_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self._format_hwid(hwid)
                            others = [nick for nick in shared_with if nick != player.primary_nickname]
                            if others:
                                shared_str = self._truncate_list(others, 5)
                                print(
                                    f"  {box['V']}     • {formatted_hwid} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                            else:
                                print(f"  {box['V']}     • {formatted_hwid} - {fmt['GREEN']}Only user{fmt['END']}")
                        print(f"  {box['V']}")

                    if alt_hwids:
                        print(f"  {box['V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(alt_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self._format_hwid(hwid)
                            alt_owners = [nick for nick in shared_with if nick in player.nicknames]
                            others = [nick for nick in shared_with if nick not in player.nicknames]
                            print(
                                f"  {box['V']}     • {formatted_hwid} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")
                            if others:
                                shared_str = self._truncate_list(others, 5)
                                print(f"  {box['V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                        print(f"  {box['V']}")

                    if other_hwids:
                        print(f"  {box['V']}   {fmt['BOLD']}■ Other associated HWIDs:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(other_hwids):
                            unique_hwids.add(hwid)
                            formatted_hwid = self._format_hwid(hwid)
                            users_str = self._truncate_list(shared_with, 5)
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

        self._print_header(" SCAN SUMMARY ", 100)
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