import json
import logging
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
            logger.info(
                f"Report item: Message {message.id} by {message.author_name}: " +
                f"Found {len(players_data)} players with " +
                f"{sum(1 for p in result.players if p.status == 'banned')} banned, " +
                f"{sum(1 for p in result.players if p.status == 'suspicious')} suspicious"
            )
            self.print_message_scan_results(scan_results)
            return report_data

    def generate_nickname_search_report(self, nickname: str, player: Player) -> List[Dict[str, Any]]:
        report_data = []
        player_dict = self._player_to_dict(player)
        player_info = {
            "type": "player_info",
            "nickname": nickname,
            "status": player.status,
            "ban_counts": player.ban_counts,
            "ban_reasons": player.ban_reasons if hasattr(player, 'ban_reasons') else [],
            "hwid_erased": player.hwid_erased if hasattr(player, 'hwid_erased') else False
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
                owner = ""
                if nickname in shared_with:
                    owner = nickname
                elif any(nick in player.nicknames for nick in shared_with):
                    for nick in player.nicknames:
                        if nick in shared_with:
                            owner = nick
                            break
                else:
                    owner = shared_with[0] if shared_with else "Unknown"
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
            report_data.append(ip_data)
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
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
                owner = ""
                if nickname in shared_with:
                    owner = nickname
                elif any(nick in player.nicknames for nick in shared_with):
                    for nick in player.nicknames:
                        if nick in shared_with:
                            owner = nick
                            break
                else:
                    owner = shared_with[0] if shared_with else "Unknown"
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
            report_data.append(hwid_data)
        if hasattr(player, 'complaint_links') and player.complaint_links:
            complaints_data = {
                "type": "complaints",
                "links": player.complaint_links
            }
            report_data.append(complaints_data)
        self.print_nickname_search_results(nickname, player)
        return report_data

    def print_nickname_search_results(self, nickname: str, player: Player) -> None:
        status_str = player.status.upper()
        if hasattr(player, 'hwid_erased') and player.hwid_erased:
            status_str += " (HWID ERASED)"
        logger.info(f"\n{'=' * 80}")
        logger.info(f"SCAN RESULTS FOR: {nickname}")
        logger.info(f"\n{'=' * 80}")
        logger.info(f"STATUS: {status_str} | BANS: {player.ban_counts}")
        if hasattr(player, 'ban_reasons') and player.ban_reasons:
            logger.info(f"BAN REASONS: {', '.join(player.ban_reasons)}")
        if len(player.nicknames) > 1:
            logger.info(f"\n{'-' * 40}")
            logger.info("ASSOCIATED NICKNAMES:")
            for other_nick in player.nicknames:
                if other_nick != nickname:
                    logger.info(f"  • {other_nick}")
        if hasattr(player, 'complaint_links') and player.complaint_links:
            logger.info(f"\n{'-' * 40}")
            logger.info(f"COMPLAINT LINKS ({len(player.complaint_links)}):")
            for i, complaint in enumerate(player.complaint_links, 1):
                link = complaint.get("link", "No link")
                channel = complaint.get("channel", "Unknown channel")
                content = complaint.get("content", "No content available")
                if content and len(content) > 60:
                    content = content[:57] + "..."
                logger.info(f"  {i}. {link}")
                logger.info(f"     Channel: {channel}")
                logger.info(f"     Content: {content}")
                mentioned_nicks = complaint.get("mentioned_nicknames", player.nicknames)
                logger.info(f"     Associated with nicknames: {', '.join(mentioned_nicks)}")
        if hasattr(player, 'associated_ips') and player.associated_ips:
            logger.info(f"\n{'-' * 40}")
            logger.info(f"ASSOCIATED IPs ({len(player.associated_ips)}):")
            for ip, shared_with in player.associated_ips.items():
                if nickname in shared_with:
                    logger.info(f"  • {ip} - Owner: {nickname}")
                    others = [nick for nick in shared_with if nick != nickname]
                    if others:
                        if len(others) > 10:
                            shared_str = ", ".join(others[:9]) + f", and {len(others) - 9} more"
                        else:
                            shared_str = ", ".join(others)
                        if len(shared_str) > 60:
                            shared_str = shared_str[:57] + "..."
                        logger.info(f"    Shared with: {shared_str}")
                else:
                    if len(shared_with) > 10:
                        users_str = ", ".join(shared_with[:9]) + f", and {len(shared_with) - 9} more"
                    else:
                        users_str = ", ".join(shared_with)
                    if len(users_str) > 60:
                        users_str = users_str[:57] + "..."
                    logger.info(f"  • {ip} - Owner/Users: {users_str}")
                    player_alts = [nick for nick in shared_with if nick in player.nicknames]
                    if player_alts:
                        logger.info(f"    Note: Used by alt account(s): {', '.join(player_alts)}")
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            logger.info(f"\n{'-' * 40}")
            logger.info(f"ASSOCIATED HWIDs ({len(player.associated_hwids)}):")
            for hwid, shared_with in player.associated_hwids.items():
                if nickname in shared_with:
                    logger.info(f"  • {hwid} - Owner: {nickname}")
                    others = [nick for nick in shared_with if nick != nickname]
                    if others:
                        if len(others) > 10:
                            shared_str = ", ".join(others[:9]) + f", and {len(others) - 9} more"
                        else:
                            shared_str = ", ".join(others)
                        if len(shared_str) > 60:
                            shared_str = shared_str[:57] + "..."
                        logger.info(f"    Shared with: {shared_str}")
                else:
                    if len(shared_with) > 10:
                        users_str = ", ".join(shared_with[:9]) + f", and {len(shared_with) - 9} more"
                    else:
                        users_str = ", ".join(shared_with)
                    if len(users_str) > 60:
                        users_str = users_str[:57] + "..."
                    logger.info(f"  • {hwid} - Owner/Users: {users_str}")
                    player_alts = [nick for nick in shared_with if nick in player.nicknames]
                    if player_alts:
                        logger.info(f"    Note: Used by alt account(s): {', '.join(player_alts)}")
        if hasattr(player, 'denied_logins') and player.denied_logins:
            logger.info(f"\n{'-' * 40}")
            logger.info(f"DENIED LOGIN ATTEMPTS ({len(player.denied_logins)}):")
            for i, login in enumerate(player.denied_logins[:5], 1):
                time_str = login.get("time", "N/A")
                ip = login.get("ip_address", "N/A")
                hwid = login.get("hwid", "N/A")
                server = login.get("server", "N/A")
                user_name = login.get("user_name", nickname)
                logger.info(f"  {i}. Time: {time_str} | IP: {ip} | HWID: {hwid} | Server: {server}")
                if user_name != nickname:
                    logger.info(f"     Attempted with nickname: {user_name}")
            if len(player.denied_logins) > 5:
                logger.info(f"  ... and {len(player.denied_logins) - 5} more")
        logger.info(f"\n{'=' * 80}")

    def _log_player_details_debug(self, player: Player) -> None:
        if not logger.isEnabledFor(logging.DEBUG):
            return
        if hasattr(player, 'denied_logins') and player.denied_logins:
            logger.debug("DENIED LOGINS:")
            for login in player.denied_logins[:5]:
                time_str = login.get("time", "N/A")
                ip = login.get("ip_address", "N/A")
                hwid = login.get("hwid", "N/A")
                logger.debug(f"  • {time_str} | IP: {ip} | HWID: {hwid}")
            if len(player.denied_logins) > 5:
                logger.debug(f"  • ... and {len(player.denied_logins) - 5} more")
        if hasattr(player, 'associated_ips') and player.associated_ips:
            logger.debug(f"ASSOCIATED IPs ({len(player.associated_ips)}):")
            for ip, shared_with in list(player.associated_ips.items())[:5]:
                if len(shared_with) > 1:
                    logger.debug(f"  • {ip} - Shared with: {len(shared_with) - 1} others")
                else:
                    logger.debug(f"  • {ip}")
            if len(player.associated_ips) > 5:
                logger.debug(f"  • ... and {len(player.associated_ips) - 5} more")
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            logger.debug(f"ASSOCIATED HWIDs ({len(player.associated_hwids)}):")
            for hwid, shared_with in list(player.associated_hwids.items())[:5]:
                if len(shared_with) > 1:
                    logger.debug(f"  • {hwid} - Shared with: {len(shared_with) - 1} others")
                else:
                    logger.debug(f"  • {hwid}")
            if len(player.associated_hwids) > 5:
                logger.debug(f"  • ... and {len(player.associated_hwids) - 5} more")

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
                shared_hwids = []
                for hwid, nicks in bypasser.associated_hwids.items():
                    shared_hwids.append({
                        "hwid": hwid,
                        "shared_with": nicks
                    })
                shared_ips = []
                for ip, nicks in bypasser.associated_ips.items():
                    shared_ips.append({
                        "ip": ip,
                        "shared_with": nicks
                    })
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
                "suspected_vpn": banned_player.suspected_vpn,
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
            logger.info(
                f"Ban bypass: {banned_player.primary_nickname} | " +
                f"Confidence: {check.bypass_confidence} | " +
                f"Potential bypassers: {len(potential_bypassers_data)}"
            )
        if ban_bypass_checks:
            logger.info(
                f"Ban bypass check complete: {len(ban_bypass_checks)} checks | " +
                f"HWID Matches: {confidence_counts['HWID_MATCH']} | " +
                f"IP+Time Close Matches: {confidence_counts['IP_TIME_CLOSE_MATCH']} | " +
                f"IP+Time Matches: {confidence_counts['IP_TIME_MATCH']} | " +
                f"IP Matches: {confidence_counts['IP_MATCH']} | " +
                f"No Matches: {confidence_counts['NO_MATCH']}"
            )
        return report_data

    def _player_to_dict(self, player: Player) -> Dict[str, Any]:
        enhanced_ips = {}
        for ip, shared_with in player.associated_ips.items():
            owner = ""
            if player.primary_nickname in shared_with:
                owner = player.primary_nickname
            elif any(nick in player.nicknames for nick in shared_with):
                for nick in player.nicknames:
                    if nick in shared_with:
                        owner = nick
                        break
            else:
                owner = shared_with[0] if shared_with else "Unknown"
            enhanced_ips[ip] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }
        enhanced_hwids = {}
        for hwid, shared_with in player.associated_hwids.items():
            owner = ""
            if player.primary_nickname in shared_with:
                owner = player.primary_nickname
            elif any(nick in player.nicknames for nick in shared_with):
                for nick in player.nicknames:
                    if nick in shared_with:
                        owner = nick
                        break
            else:
                owner = shared_with[0] if shared_with else "Unknown"
            enhanced_hwids[hwid] = {
                "owner": owner,
                "shared_with": [nick for nick in shared_with if nick != owner],
                "raw_users": shared_with
            }
        return {
            "initial_account": {
                "user_id": player.user_id,
                "nicknames": player.nicknames,
                "primary_nickname": player.primary_nickname if hasattr(player, 'primary_nickname') else (
                    player.nicknames[0] if player.nicknames else "Unknown"),
                "status": player.status,
                "ban_counts": player.ban_counts,
                "ban_reasons": player.ban_reasons,
                "suspected_vpn": player.suspected_vpn,
                "connection_link": player.connection_link,
                "associated_ips": player.associated_ips,
                "associated_hwids": player.associated_hwids,
                "shared_hwid_nicknames": player.shared_hwid_nicknames
            },
            "ip_data": enhanced_ips,
            "hwid_data": enhanced_hwids,
            "raw_ip_nicks": player.associated_ips,
            "raw_hwid_nicks": player.associated_hwids,
            "nicknames": player.nicknames,
            "hwid_erased": player.hwid_erased,
            "complaint_links": player.complaint_links
        }

    def _get_verdict_string(self, account: Dict[str, Any], hwid_erased: bool = False,
                            bypass_confidence: Optional[str] = None) -> str:
        if bypass_confidence in {
            "100% (HWID Match)",
            "20-30% (IP + Time Match)",
            "IP+Time Match (5-10 min, 30-50%)"
        }:
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
        if sys.stdout.isatty():
            HEADER = '\033[95m'
            BLUE = '\033[94m'
            CYAN = '\033[96m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            BOLD = '\033[1m'
            UNDERLINE = '\033[4m'
            END = '\033[0m'
        else:
            HEADER = BLUE = CYAN = GREEN = YELLOW = RED = BOLD = UNDERLINE = END = ''
        BOX_H = '─'
        BOX_V = '│'
        BOX_TL = '┌'
        BOX_TR = '┐'
        BOX_BL = '└'
        BOX_BR = '┘'
        BOX_VL = '┤'
        BOX_VR = '├'
        BOX_HU = '┴'
        BOX_HD = '┬'
        BOX_CROSS = '┼'
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

        def print_header(title, width=80):
            print(f"\n{HEADER}{BOLD}{BOX_TL}{BOX_H * (width - 2)}{BOX_TR}{END}")
            padding = (width - len(title) - 4) // 2
            print(
                f"{HEADER}{BOLD}{BOX_V}{' ' * padding} {title} {' ' * (width - padding - len(title) - 4)}{BOX_V}{END}")
            print(f"{HEADER}{BOLD}{BOX_BL}{BOX_H * (width - 2)}{BOX_BR}{END}")

        def print_section(title, width=80):
            print(f"\n{BOLD}{BOX_TL}{BOX_H * (width - 2)}{BOX_TR}{END}")
            padding = (width - len(title) - 4) // 2
            print(f"{BOLD}{BOX_V}{' ' * padding} {title} {' ' * (width - padding - len(title) - 4)}{BOX_V}{END}")
            print(f"{BOLD}{BOX_BL}{BOX_H * (width - 2)}{BOX_BR}{END}")

        def print_player_header(name, width=76):
            player_header = f"PLAYER: {name}"
            print(f"\n  {BOLD}{CYAN}{BOX_TL}{BOX_H * (width - 2)}{BOX_TR}{END}")
            padding = (width - len(player_header) - 4) // 2
            print(
                f"  {BOLD}{CYAN}{BOX_V}{' ' * padding} {player_header} {' ' * (width - padding - len(player_header) - 4)}{BOX_V}{END}")
            print(f"  {BOLD}{CYAN}{BOX_VR}{BOX_H * (width - 2)}{BOX_VL}{END}")

        def format_hwid(hwid):
            if len(hwid) <= 12:
                return hwid
            prefix = hwid[:5]
            middle = hwid[5:-5]
            suffix = hwid[-5:]
            return f"{CYAN}{prefix}{END}{middle}{CYAN}{suffix}{END}"

        print_header(f"SCAN RESULTS - {len(scan_results)} messages processed", 100)

        for result in scan_results:
            message = result.message
            players = result.players
            real_players = [p for p in players if p.primary_nickname != "Unknown"]
            total_players += len(real_players)
            print_section(f"MESSAGE: {BLUE}{message.link}{END}", 100)
            print(f"  {BOLD}AUTHOR:{END} {message.author_name}")
            for player in real_players:
                if player.status.lower() == "banned":
                    status_str = f"{RED}{BOLD}BANNED{END}"
                    total_banned += 1
                    problematic_players.append((player.primary_nickname, "BANNED", player.ban_counts))
                elif player.status.lower() == "suspicious":
                    status_str = f"{YELLOW}{BOLD}SUSPICIOUS{END}"
                    total_suspicious += 1
                    problematic_players.append((player.primary_nickname, "SUSPICIOUS", player.ban_counts))
                elif player.status.lower() == "clean":
                    status_str = f"{GREEN}CLEAN{END}"
                    total_clean += 1
                else:
                    status_str = "UNKNOWN"
                    total_unknown += 1
                hwid_erased = ""
                if hasattr(player, 'hwid_erased') and player.hwid_erased:
                    hwid_erased = f" {YELLOW}(HWID ERASED){END}"
                print_player_header(player.primary_nickname)
                print(
                    f"  {BOX_V} {BOLD}STATUS:{END} {status_str}{hwid_erased} {BOX_V} {BOLD}BANS:{END} {player.ban_counts}")
                if hasattr(player, 'ban_reasons') and player.ban_reasons:
                    reason_text = f"{BOLD}BAN REASONS:{END} {', '.join(player.ban_reasons)}"
                    print(f"  {BOX_V} {reason_text}")
                if len(player.nicknames) > 1:
                    alt_nicks = [n for n in player.nicknames if n != player.primary_nickname]
                    if alt_nicks:
                        alt_names_text = f"{BOLD}ALT NAMES:{END} {', '.join(alt_nicks)}"
                        print(f"  {BOX_V} {alt_names_text}")
                print(f"  {BOX_VR}{BOX_H * 74}{BOX_VL}")
                if hasattr(player, 'complaint_links') and player.complaint_links:
                    total_complaints += len(player.complaint_links)
                    print(f"  {BOX_V} {BOLD}{YELLOW}COMPLAINTS ({len(player.complaint_links)}):{END}")
                    for i, complaint in enumerate(player.complaint_links, 1):
                        link = complaint.get("link", "No link")
                        channel = complaint.get("channel", "Unknown channel")
                        content = complaint.get("content", "No content available")
                        print(f"  {BOX_V}   {BOX_TL}{BOX_H * 70}{BOX_TR}")
                        print(f"  {BOX_V}   {BOX_V} {i}. {BLUE}{UNDERLINE}{link}{END}")
                        print(f"  {BOX_V}   {BOX_V} {BOLD}Channel:{END} {channel}")
                        if content:
                            print(f"  {BOX_V}   {BOX_V} {BOLD}Content:{END}")
                            content_lines = content.split('\n')
                            for line_idx, line in enumerate(content_lines):
                                if len(line) > 65:
                                    print(f"  {BOX_V}   {BOX_V}          {line[:65]}")
                                    remaining = line[65:]
                                    chunks = [remaining[i:i + 65] for i in range(0, len(remaining), 65)]
                                    for chunk in chunks:
                                        print(f"  {BOX_V}   {BOX_V}          {chunk}")
                                else:
                                    print(f"  {BOX_V}   {BOX_V}          {line}")
                        else:
                            print(f"  {BOX_V}   {BOX_V} {BOLD}Content:{END} No content available")
                        mentioned_nicks = complaint.get("mentioned_nicknames", [player.primary_nickname])
                        if len(mentioned_nicks) > 1:
                            print(f"  {BOX_V}   {BOX_V} {BOLD}Associated with:{END} {', '.join(mentioned_nicks)}")
                        print(f"  {BOX_V}   {BOX_BL}{BOX_H * 70}{BOX_BR}")
                    print(f"  {BOX_VR}{BOX_H * 74}{BOX_VL}")
                has_details = False
                if hasattr(player, 'associated_ips') and player.associated_ips:
                    ip_count = len(player.associated_ips)
                    total_ips += ip_count
                    has_details = True
                    print(f"  {BOX_V} {BOLD}IPs ({ip_count}):{END}")
                    for ip, shared_with in player.associated_ips.items():
                        unique_ips.add(ip)
                        if player.primary_nickname in shared_with:
                            if len(shared_with) <= 1:
                                print(
                                    f"  {BOX_V}   • {CYAN}{ip}{END} - {GREEN}Owner/Only user:{END} {player.primary_nickname}")
                            else:
                                others = [nick for nick in shared_with if nick != player.primary_nickname]
                                if others:
                                    if len(others) > 5:
                                        shared_str = ", ".join(others[:5]) + f", and {len(others) - 5} more"
                                    else:
                                        shared_str = ", ".join(others)
                                    print(
                                        f"  {BOX_V}   • {CYAN}{ip}{END} - {GREEN}Owner:{END} {player.primary_nickname} | {YELLOW}Shared with:{END} {shared_str}")
                        else:
                            player_alts = [nick for nick in shared_with if nick in player.nicknames]
                            other_users = [nick for nick in shared_with if nick not in player.nicknames]
                            all_users = player_alts + other_users
                            if len(all_users) > 5:
                                users_str = ", ".join(all_users[:5]) + f", and {len(all_users) - 5} more"
                            else:
                                users_str = ", ".join(all_users)
                            print(f"  {BOX_V}   • {CYAN}{ip}{END} - {YELLOW}Owner/Users:{END} {users_str}")
                if hasattr(player, 'associated_hwids') and player.associated_hwids:
                    hwid_count = len(player.associated_hwids)
                    total_hwids += hwid_count
                    has_details = True
                    if hasattr(player, 'associated_ips') and player.associated_ips:
                        print(f"  {BOX_VR}{BOX_H * 74}{BOX_VL}")
                    print(f"  {BOX_V} {BOLD}HWIDs ({hwid_count}):{END}")
                    for hwid, shared_with in player.associated_hwids.items():
                        unique_hwids.add(hwid)
                        formatted_hwid = format_hwid(hwid)
                        if player.primary_nickname in shared_with:
                            if len(shared_with) <= 1:
                                print(
                                    f"  {BOX_V}   • {formatted_hwid} - {GREEN}Owner/Only user:{END} {player.primary_nickname}")
                            else:
                                others = [nick for nick in shared_with if nick != player.primary_nickname]
                                if others:
                                    if len(others) > 5:
                                        shared_str = ", ".join(others[:5]) + f", and {len(others) - 5} more"
                                    else:
                                        shared_str = ", ".join(others)
                                    print(
                                        f"  {BOX_V}   • {formatted_hwid} - {GREEN}Owner:{END} {player.primary_nickname} | {YELLOW}Shared with:{END} {shared_str}")
                        else:
                            player_alts = [nick for nick in shared_with if nick in player.nicknames]
                            other_users = [nick for nick in shared_with if nick not in player.nicknames]
                            all_users = player_alts + other_users
                            if len(all_users) > 5:
                                users_str = ", ".join(all_users[:5]) + f", and {len(all_users) - 5} more"
                            else:
                                users_str = ", ".join(all_users)
                            print(f"  {BOX_V}   • {formatted_hwid} - {YELLOW}Owner/Users:{END} {users_str}")
                    if hasattr(player, 'denied_logins') and player.denied_logins:
                        login_count = len(player.denied_logins)
                        if has_details:
                            print(f"  {BOX_VR}{BOX_H * 74}{BOX_VL}")
                        print(f"  {BOX_V} {BOLD}{RED}DENIED LOGINS ({login_count}):{END}")
                        for i, login in enumerate(player.denied_logins[:3], 1):
                            time_str = login.get("time", "N/A")
                            ip = login.get("ip_address", "N/A")
                            hwid = login.get("hwid", "N/A")
                            server = login.get("server", "N/A")
                            user_name = login.get("user_name", player.primary_nickname)
                            print(
                                f"  {BOX_V}   {i}. {BOLD}Time:{END} {time_str} {BOLD}IP:{END} {CYAN}{ip}{END} {BOLD}Server:{END} {server}")
                            if user_name != player.primary_nickname:
                                print(f"  {BOX_V}      {BOLD}Used name:{END} {user_name}")
                        if len(player.denied_logins) > 3:
                            print(f"  {BOX_V}   ... and {len(player.denied_logins) - 3} more")
                print(f"  {BOX_BL}{BOX_H * 74}{BOX_BR}")
        print_header(" SCAN SUMMARY ", 100)
        print(f"  {BOX_V} {BOLD}Messages processed:{END} {len(scan_results)}")
        print(f"  {BOX_V} {BOLD}Players found:{END} {total_players}")
        print(f"  {BOX_V} {BOLD}Status breakdown:{END}")
        if total_players:
            banned_pct = total_banned / total_players * 100
            suspicious_pct = total_suspicious / total_players * 100
            clean_pct = total_clean / total_players * 100
            unknown_pct = total_unknown / total_players * 100 if total_unknown else 0
        else:
            banned_pct = suspicious_pct = clean_pct = unknown_pct = 0
        print(f"  {BOX_V}    • {RED}{BOLD}Banned:{END} {total_banned} ({banned_pct:.1f}% of total)")
        print(f"  {BOX_V}    • {YELLOW}{BOLD}Suspicious:{END} {total_suspicious} ({suspicious_pct:.1f}% of total)")
        print(f"  {BOX_V}    • {GREEN}Clean:{END} {total_clean} ({clean_pct:.1f}% of total)")
        if total_unknown:
            print(f"  {BOX_V}    • Unknown: {total_unknown} ({unknown_pct:.1f}% of total)")
        else:
            print(f"  {BOX_V}    • Unknown: 0")
        print(f"  {BOX_V} {BOLD}Complaints found:{END} {total_complaints}")
        print(f"  {BOX_V} {BOLD}Unique HWIDs detected:{END} {len(unique_hwids)}")
        print(f"  {BOX_V} {BOLD}Unique IPs detected:{END} {len(unique_ips)}")
        if problematic_players:
            print(f"  {BOX_VR}{BOX_H * 96}{BOX_VL}")
            print(f"  {BOX_V} {BOLD}PROBLEMATIC PLAYERS DETECTED:{END}")
            for nickname, status, bans in problematic_players:
                status_color = RED if status == "BANNED" else YELLOW
                print(f"  {BOX_V}   • {nickname}: {status_color}{status}{END} (Bans: {bans})")
        print(f"  {BOX_BL}{BOX_H * 96}{BOX_VL}\n")
