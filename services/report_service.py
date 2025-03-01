import json
import logging
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
            for player in result.players:
                logger.debug(
                    f"Player: {player.primary_nickname} | " +
                    f"Status: {player.status} | " +
                    f"Bans: {player.ban_counts} | " +
                    f"IPs: {len(player.associated_ips)} | " +
                    f"HWIDs: {len(player.associated_hwids)}"
                )
        return report_data

    def generate_nickname_search_report(self, nickname: str, player: Player) -> List[Dict[str, Any]]:
        report_data = []
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
                ip_entry = {
                    "ip": ip,
                    "shared_with": shared_with,
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
                hwid_entry = {
                    "hwid": hwid,
                    "shared_with": shared_with,
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
                logger.info(f"  • {ip}")
                if shared_with:
                    if len(shared_with) > 10:
                        shared_str = ", ".join(shared_with[:9]) + f", and {len(shared_with) - 9} more"
                    else:
                        shared_str = ", ".join(shared_with)
                    if len(shared_str) > 60:
                        shared_str = shared_str[:57] + "..."
                    logger.info(f"    Associated with nicknames: {shared_str}")
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            logger.info(f"\n{'-' * 40}")
            logger.info(f"ASSOCIATED HWIDs ({len(player.associated_hwids)}):")
            for hwid, shared_with in player.associated_hwids.items():
                logger.info(f"  • {hwid}")
                if shared_with:
                    if len(shared_with) > 10:
                        shared_str = ", ".join(shared_with[:9]) + f", and {len(shared_with) - 9} more"
                    else:
                        shared_str = ", ".join(shared_with)
                    if len(shared_str) > 60:
                        shared_str = shared_str[:57] + "..."
                    logger.info(f"    Associated with nicknames: {shared_str}")
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
                logger.info(f"     Associated with nickname: {user_name}")
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
        return {
            "initial_account": {
                "user_id": player.user_id,
                "nicknames": player.nicknames,
                "status": player.status,
                "ban_counts": player.ban_counts,
                "ban_reasons": player.ban_reasons,
                "suspected_vpn": player.suspected_vpn,
                "connection_link": player.connection_link,
                "associated_ips": player.associated_ips,
                "associated_hwids": player.associated_hwids,
                "shared_hwid_nicknames": player.shared_hwid_nicknames
            },
            "ip_nicks": player.associated_ips,
            "hwid_nicks": player.associated_hwids,
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
