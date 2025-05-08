import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Callable

from models.message import ScanResult
from models.player import Player
from services.reporting.config import (
    ReportConfig, DISPLAY_LIMITS, LAYOUT_CONFIG,
    TIME_ANALYSIS_THRESHOLDS, BOX_CHARS, PLAYER_STATUS
)
from services.reporting.formatter import ReportFormatter
from services.reporting.utils import (
    determine_owner, categorize_associated_nicknames,
    analyze_hwids, analyze_ips, analyze_complaints, find_connection_paths
)
from utils.logging_utils import get_logger

logger = get_logger(__name__)


class ReportService:

    def __init__(self, config: Optional[ReportConfig] = None) -> None:
        self.config = config or ReportConfig()
        self.formatter = ReportFormatter(self.config)
        self.cache: Dict[Any, Any] = {}

        os.makedirs(self.config.report_output_dir, exist_ok=True)

    def write_json_report(self, data: List[Dict[str, Any]], filename: Optional[str] = None) -> bool:
        report_file = filename or os.path.join(self.config.report_output_dir, self.config.report_filename)
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            logger.info(f"Report saved to '{report_file}' ({len(data)} items)")
            return True
        except IOError as e:
            logger.error(f"Could not write report to '{report_file}': {e}")
            return False

    def _player_to_dict(self, player: Player) -> Dict[str, Any]:
        primary_nickname = getattr(player, 'primary_nickname', None) or \
                           (player.nicknames[0] if hasattr(player, 'nicknames') and player.nicknames else "Unknown")

        enhanced_ips = {}
        if hasattr(player, 'associated_ips'):
            for ip, shared_with in player.associated_ips.items():
                owner = determine_owner(primary_nickname, getattr(player, 'nicknames', []), shared_with, self.cache)
                enhanced_ips[ip] = {
                    "owner": owner, "shared_with": [nick for nick in shared_with if nick != owner], "raw_users": shared_with
                }

        enhanced_hwids = {}
        if hasattr(player, 'associated_hwids'):
            for hwid, shared_with in player.associated_hwids.items():
                owner = determine_owner(primary_nickname, getattr(player, 'nicknames', []), shared_with, self.cache)
                enhanced_hwids[hwid] = {
                    "owner": owner, "shared_with": [nick for nick in shared_with if nick != owner], "raw_users": shared_with
                }
        
        return {
            "initial_account": {
                "user_id": getattr(player, 'user_id', None),
                "nicknames": getattr(player, 'nicknames', []),
                "primary_nickname": primary_nickname,
                "status": getattr(player, 'status', 'unknown'),
                "ban_counts": getattr(player, 'ban_counts', 0),
                "ban_reasons": getattr(player, 'ban_reasons', []),
                "connection_link": getattr(player, 'connection_link', ""),
                "associated_ips": getattr(player, 'associated_ips', {}),
                "associated_hwids": getattr(player, 'associated_hwids', {}),
                "shared_hwid_nicknames": getattr(player, 'shared_hwid_nicknames', [])
            },
            "ip_data": enhanced_ips,
            "hwid_data": enhanced_hwids,
            "raw_ip_nicks": getattr(player, 'associated_ips', {}),
            "raw_hwid_nicks": getattr(player, 'associated_hwids', {}),
            "nicknames": getattr(player, 'nicknames', []),
            "hwid_erased": getattr(player, 'hwid_erased', False),
            "complaint_links": getattr(player, 'complaint_links', []),
            "timestamp": datetime.now().isoformat(),
            "scan_version": "2.1" 
        }

    def generate_message_scan_report(self, scan_results: List[ScanResult]) -> List[Dict[str, Any]]:
        report_data = []
        for result in scan_results:
            message = result.message
            players_data = [self._player_to_dict(player) for player in result.players if player] 

            message_data = {
                "message_id": message.id, "message_link": message.link,
                "author_name": message.author_name, "author_id": message.author_id,
                "scan_time": result.scan_time.isoformat(),
                "results": players_data, "scan_version": "2.1"
            }
            report_data.append(message_data)

            banned_count = sum(1 for p_data in players_data if p_data["initial_account"]["status"] == PLAYER_STATUS['BANNED'])
            suspicious_count = sum(1 for p_data in players_data if p_data["initial_account"]["status"] == PLAYER_STATUS['SUSPICIOUS'])
            logger.info(
                f"Report item: Message {message.id} by {message.author_name}: "
                f"Found {len(players_data)} players ({banned_count} banned, {suspicious_count} suspicious)"
            )
        self.print_message_scan_results(scan_results)
        return report_data

    def generate_nickname_search_report(self, nickname: str, player: Player) -> List[Dict[str, Any]]:
        report_data = []
        player_info = {
            "type": "player_info", "nickname": nickname,
            "status": getattr(player, 'status', 'unknown'),
            "ban_counts": getattr(player, 'ban_counts', 0),
            "ban_reasons": getattr(player, 'ban_reasons', []),
            "hwid_erased": getattr(player, 'hwid_erased', False),
            "timestamp": datetime.now().isoformat(), "scan_version": "2.1"
        }
        report_data.append(player_info)

        if hasattr(player, 'nicknames') and player.nicknames and len(player.nicknames) > 1:
            report_data.append({"type": "associated_accounts", "nicknames": player.nicknames})
        if hasattr(player, 'denied_logins') and player.denied_logins:
            report_data.append({"type": "denied_login_attempts", "attempts": player.denied_logins})
        if hasattr(player, 'associated_ips') and player.associated_ips:
            report_data.append(self._generate_ip_data(nickname, player))
        if hasattr(player, 'associated_hwids') and player.associated_hwids:
            report_data.append(self._generate_hwid_data(nickname, player))
        if hasattr(player, 'complaint_links') and player.complaint_links:
            report_data.append({"type": "complaints", "links": player.complaint_links})

        self._print_nickname_search_results(nickname, player)
        return report_data

    def _generate_ip_data(self, nickname: str, player: Player) -> Dict[str, Any]:
        ip_data = {"type": "associated_ips", "ips": []}
        denied_logins_by_ip = defaultdict(list)
        if hasattr(player, 'denied_logins'):
            for login in player.denied_logins:
                ip = login.get("ip_address")
                if ip: denied_logins_by_ip[ip].append(login)

        for ip, shared_with in getattr(player, 'associated_ips', {}).items():
            owner = determine_owner(nickname, getattr(player, 'nicknames', []), shared_with, self.cache)
            others = [n for n in shared_with if n != owner]
            ip_entry = {
                "direct_ip_connections": ip, "owner": owner,
                "owned_by_primary": owner == nickname,
                "owned_by_alt": owner in getattr(player, 'nicknames', []) and owner != nickname,
                "shared_with": others, "raw_users": shared_with
            }
            if denied_logins_by_ip.get(ip): ip_entry["denied_logins"] = denied_logins_by_ip[ip]
            ip_data["ips"].append(ip_entry)
        return ip_data

    def _generate_hwid_data(self, nickname: str, player: Player) -> Dict[str, Any]:
        hwid_data = {"type": "associated_hwids", "hwids": []}
        denied_logins_by_hwid = defaultdict(list)
        if hasattr(player, 'denied_logins'):
            for login in player.denied_logins:
                hwid = login.get("hwid")
                if hwid: denied_logins_by_hwid[hwid].append(login)

        for hwid, shared_with in getattr(player, 'associated_hwids', {}).items():
            owner = determine_owner(nickname, getattr(player, 'nicknames', []), shared_with, self.cache)
            others = [n for n in shared_with if n != owner]
            hwid_entry = {
                "hwid": hwid, "owner": owner,
                "owned_by_primary": owner == nickname,
                "owned_by_alt": owner in getattr(player, 'nicknames', []) and owner != nickname,
                "shared_with": others, "raw_users": shared_with
            }
            if denied_logins_by_hwid.get(hwid): hwid_entry["denied_logins"] = denied_logins_by_hwid[hwid]
            hwid_data["hwids"].append(hwid_entry)
        return hwid_data

    def _get_indent_str(self, level: int = 1) -> str:
        return LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] * level

    def _print_nickname_search_results(self, nickname: str, player: Player) -> None:
        fmt = self.formatter.fmt
        content_indent = self._get_indent_str(1)

        self.formatter.print_header(f"SCAN RESULTS FOR: {nickname}", width=self.config.box_width_large)

        status_str = self.formatter.format_status(getattr(player,'status', 'unknown'), getattr(player, 'hwid_erased', False))
        ban_counts = getattr(player, 'ban_counts', 0)
        print(f"{content_indent}{fmt['BOLD']}STATUS:{fmt['END']} {status_str} | {fmt['BOLD']}BANS:{fmt['END']} {self.formatter.format_count(ban_counts)}")


        if hasattr(player, 'ban_reasons') and player.ban_reasons:
            self._print_ban_reasons(player, base_indent_str=content_indent)

        if hasattr(player, 'nicknames') and player.nicknames and len(player.nicknames) > 1:
            self._print_associated_nicknames_section(player, nickname, base_indent_str=content_indent)
        
        self._print_connection_paths_section(player, nickname, base_indent_str=content_indent)
        self._print_complaints_section(player, nickname, base_indent_str=content_indent)
        self._print_ip_section(player, nickname, base_indent_str=content_indent)
        self._print_hwid_section(player, nickname, base_indent_str=content_indent)
        self._print_denied_logins_section(player, nickname, base_indent_str=content_indent)
        
        print()

    def _print_section_box_start(self, title: str, base_indent_str: str, box_width: int,
                                 title_color_keys: Tuple[str, ...] = ('BOLD',),
                                 box_char_set: str = 'SINGLE') -> Tuple[str, Callable[[], None]]:
        h_bar_len = box_width - 2
        if h_bar_len < 0: h_bar_len = 0
        
        box_color_outer = self.formatter._get_fmt('BOLD')
        title_str_colored = f"{self.formatter._get_fmt(*title_color_keys)}{title}{self.formatter.fmt['END']}"
        
        char_prefix = "DOUBLE_" if box_char_set == 'DOUBLE' else ""
        v_char = BOX_CHARS[f'{char_prefix}V']
        tl_char = BOX_CHARS[f'{char_prefix}TL']
        tr_char = BOX_CHARS[f'{char_prefix}TR']
        h_char = BOX_CHARS[f'{char_prefix}H']
        vr_char = BOX_CHARS[f'{char_prefix}VR']
        vl_char = BOX_CHARS[f'{char_prefix}VL']
        bl_char = BOX_CHARS[f'{char_prefix}BL']
        br_char = BOX_CHARS[f'{char_prefix}BR']

        print(f"\n{base_indent_str}{box_color_outer}{tl_char}{h_char * h_bar_len}{tr_char}{self.formatter.fmt['END']}")
        
        title_plain_len = len(title)
        space_for_title_and_padding = box_width - 2
        
        centering_padding_total = space_for_title_and_padding - title_plain_len
        if centering_padding_total < 0: centering_padding_total = 0
        
        left_padding_for_title = centering_padding_total // 2
        right_padding_for_title = centering_padding_total - left_padding_for_title
        
        print(f"{base_indent_str}{box_color_outer}{v_char}{self.formatter.fmt['END']}"
              f"{' ' * left_padding_for_title}{title_str_colored}{' ' * right_padding_for_title}"
              f"{box_color_outer}{v_char}{self.formatter.fmt['END']}")
        
        print(f"{base_indent_str}{box_color_outer}{vr_char}{h_char * h_bar_len}{vl_char}{self.formatter.fmt['END']}")

        def end_section_box():
            print(f"{base_indent_str}{box_color_outer}{bl_char}{h_char * h_bar_len}{br_char}{self.formatter.fmt['END']}")
        return v_char, end_section_box


    def _print_associated_nicknames_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        fmt = self.formatter.fmt
        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)
        
        categorized = categorize_associated_nicknames(player, nickname)
        total_associated_nicks = (
            len(categorized["confirmed_alts"]["accounts"]) +
            sum(len(alts) for alts in categorized["alt_to_alt"]["hwid_map"].values()) +
            len(categorized["likely_connections"]) +
            len(categorized["possible_connections"]["ip"]) +
            len(categorized["possible_connections"]["login"]) +
            len(categorized["time_based"]["recent"]) +
            len(categorized["time_based"]["historical"]) +
            len(categorized["other"])
        )
        if not total_associated_nicks and not categorized["confirmed_alts"]["accounts"] : return

        box_v_char_raw, end_box = self._print_section_box_start(
            f"ASSOCIATED NICKNAMES (Primary: {nickname})",
            base_indent_str, box_width, ('YELLOW', 'BOLD'), box_char_set='SINGLE'
        )
        
        line_padding_in_box = 1
        box_v_char_with_color = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{fmt['END']}"


        def print_cat_header(cat_title, color_keys=('BOLD',)):
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt(*color_keys)}■ {cat_title.upper()}:{fmt['END']}",
                                             box_v_char_with_color, base_indent_str, line_padding_in_box)
        
        sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        sub_sub_item_indent_str = sub_item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        list_display_limit = self.config.get_specific_display_limit('NICKNAME_DISPLAY_LIMIT')

        if categorized["confirmed_alts"]["accounts"]:
            print_cat_header(f"CONFIRMED ALTS (Linked directly to {nickname})", ('RED', 'BOLD'))
            self.formatter.print_line_in_box(
                f"{sub_item_indent_str}{fmt['BOLD']}Accounts ({len(categorized['confirmed_alts']['accounts'])}):{fmt['END']} "
                f"{self.formatter.truncate_list(categorized['confirmed_alts']['accounts'], list_display_limit)}",
                box_v_char_with_color, base_indent_str, line_padding_in_box
            )
            if categorized["confirmed_alts"]["direct_hwid"]:
                hwid_data = categorized["confirmed_alts"]["direct_hwid"]
                self.formatter.print_line_in_box(
                    f"{sub_item_indent_str}{fmt['BOLD']}Evidence (Shared HWIDs with {nickname} - {len(hwid_data)}):{fmt['END']}",
                    box_v_char_with_color, base_indent_str, line_padding_in_box
                )
                display_hwid_limit = self.config.get_specific_display_limit('HWID_OWNED_DISPLAY_LIMIT')
                count = 0
                for hwid_val, alts_on_hwid in hwid_data.items():
                    if count >= display_hwid_limit: break
                    self.formatter.print_line_in_box(
                        f"{sub_sub_item_indent_str}{BOX_CHARS['SUB_ARROW']} {self.formatter.format_hwid(hwid_val)} links to: "
                        f"{self.formatter.truncate_list(alts_on_hwid, list_display_limit)}",
                        box_v_char_with_color, base_indent_str, line_padding_in_box
                    )
                    count +=1
                if len(hwid_data) > count:
                     self.formatter.print_line_in_box(
                         f"{sub_sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(hwid_data) - count} more HWIDs",
                         box_v_char_with_color, base_indent_str, line_padding_in_box
                     )
            self.formatter.print_line_in_box("", box_v_char_with_color, base_indent_str, line_padding_in_box)

        if categorized["alt_to_alt"]["hwid_map"]:
            print_cat_header(f"ALT-TO-ALT CONNECTIONS (Between {nickname}'s alts)", ('YELLOW', 'BOLD'))
            hwid_map = categorized['alt_to_alt']['hwid_map']
            num_hwids_involved = len(hwid_map)
            unique_alts_in_map = set()
            for alts_list in hwid_map.values(): unique_alts_in_map.update(alts_list)


            summary = (f"{len(unique_alts_in_map)} alts interconnected by {num_hwids_involved} HWIDs "
                       f"(not directly involving {nickname})")
            self.formatter.print_line_in_box(f"{sub_item_indent_str}{summary}", box_v_char_with_color, base_indent_str, line_padding_in_box)
            
            display_alt_hwid_limit = self.config.get_specific_display_limit('MULTI_ALT_DISPLAY_LIMIT')
            count = 0
            for hwid_val, alts_list in hwid_map.items():
                if count >= display_alt_hwid_limit: break
                self.formatter.print_line_in_box(
                    f"{sub_sub_item_indent_str}{BOX_CHARS['SUB_ARROW']} {self.formatter.format_hwid(hwid_val)} links alts: "
                    f"{self.formatter.truncate_list(alts_list, list_display_limit)}",
                    box_v_char_with_color, base_indent_str, line_padding_in_box
                )
                count += 1
            if num_hwids_involved > count:
                self.formatter.print_line_in_box(
                    f"{sub_sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {num_hwids_involved - count} more HWIDs",
                    box_v_char_with_color, base_indent_str, line_padding_in_box
                )
            self.formatter.print_line_in_box("", box_v_char_with_color, base_indent_str, line_padding_in_box)

        if categorized["likely_connections"]:
            print_cat_header(f"LIKELY CONNECTIONS (Linked via alts of {nickname})", ('YELLOW',))
            for conn in categorized["likely_connections"][:list_display_limit]:
                evidence_parts = []
                if conn['id_details']['hwid'] > 0:
                    evidence_parts.append(f"{conn['id_details']['hwid']} HWID(s)")
                if conn['id_details']['ip'] > 0:
                    evidence_parts.append(f"{conn['id_details']['ip']} IP(s)")
                evidence_str = ", ".join(evidence_parts) if evidence_parts else "N/A"
                
                line = (f"{conn['nickname']}: {self.formatter.format_confidence(conn['strength_str'])} "
                        f"(Evidence: {evidence_str})")
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['RIGHT_ARROW']} {line}", box_v_char_with_color, base_indent_str, line_padding_in_box)
            if len(categorized["likely_connections"]) > list_display_limit:
                 self.formatter.print_line_in_box(
                     f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and "
                     f"{len(categorized['likely_connections']) - list_display_limit} more",
                     box_v_char_with_color, base_indent_str, line_padding_in_box
                 )
            self.formatter.print_line_in_box("", box_v_char_with_color, base_indent_str, line_padding_in_box)

        if categorized["possible_connections"]["ip"] or categorized["possible_connections"]["login"]:
            print_cat_header(f"POSSIBLE CONNECTIONS (Directly with {nickname})", ('CYAN',))
            if categorized["possible_connections"]["login"]:
                 logins = list(categorized['possible_connections']['login'])
                 self.formatter.print_line_in_box(
                     f"{sub_item_indent_str}{fmt['BOLD']}Via Login Data ({len(logins)}):{fmt['END']} "
                     f"{self.formatter.truncate_list(logins, list_display_limit)}",
                     box_v_char_with_color, base_indent_str, line_padding_in_box
                 )
            if categorized["possible_connections"]["ip"]:
                 ip_matches = categorized['possible_connections']['ip']
                 self.formatter.print_line_in_box(
                     f"{sub_item_indent_str}{fmt['BOLD']}Via Shared IPs with {nickname} ({len(ip_matches)}):{fmt['END']}",
                     box_v_char_with_color, base_indent_str, line_padding_in_box
                 )
                 count = 0
                 for nick_val, num_ips in ip_matches.items():
                     if count >= list_display_limit: break
                     self.formatter.print_line_in_box(
                         f"{sub_sub_item_indent_str}{BOX_CHARS['BULLET']} {nick_val} ({num_ips} shared IP(s) with {nickname})",
                         box_v_char_with_color, base_indent_str, line_padding_in_box
                     )
                     count +=1
                 if len(ip_matches) > count:
                     self.formatter.print_line_in_box(
                         f"{sub_sub_item_indent_str}{BOX_CHARS['BULLET']} ...and "
                         f"{len(ip_matches) - count} more IP-connected accounts",
                         box_v_char_with_color, base_indent_str, line_padding_in_box
                     )
            self.formatter.print_line_in_box("", box_v_char_with_color, base_indent_str, line_padding_in_box)
        
        time_based_nicks = categorized["time_based"]["recent"] + categorized["time_based"]["historical"]
        if time_based_nicks:
            print_cat_header("TIME-BASED ASSOCIATIONS (From Denied Logins)", ("GRAY",))
            if categorized["time_based"]["recent"]:
                 self.formatter.print_line_in_box(
                     f"{sub_item_indent_str}{fmt['BOLD']}Recent:{fmt['END']} "
                     f"{self.formatter.truncate_list(categorized['time_based']['recent'], list_display_limit)}",
                     box_v_char_with_color, base_indent_str, line_padding_in_box
                 )
            if categorized["time_based"]["historical"]:
                 self.formatter.print_line_in_box(
                     f"{sub_item_indent_str}{fmt['BOLD']}Historical:{fmt['END']} "
                     f"{self.formatter.truncate_list(categorized['time_based']['historical'], list_display_limit)}",
                     box_v_char_with_color, base_indent_str, line_padding_in_box
                 )
            self.formatter.print_line_in_box("", box_v_char_with_color, base_indent_str, line_padding_in_box)

        if categorized["other"]:
             print_cat_header("OTHER KNOWN NICKNAMES (Source unclear/weaker link)", ('GRAY',))
             self.formatter.print_line_in_box(
                 f"{sub_item_indent_str}{self.formatter.truncate_list(list(categorized['other']), list_display_limit)}",
                 box_v_char_with_color, base_indent_str, line_padding_in_box
             )

        end_box()

    def _print_ban_reasons(self, player: Player, base_indent_str: str) -> None:
        if not hasattr(player, 'ban_reasons') or not player.ban_reasons: return

        box_width = self.config.box_width_medium 
        item_indent_str = self._get_indent_str(1)
        
        self.formatter.print_section_header(
            f"BAN REASONS ({len(player.ban_reasons)})", 
            indent_str=base_indent_str, width=box_width, style='warning'
        )
        v_char_content_box = f"{self.formatter._get_fmt('BOLD')}{BOX_CHARS['V']}{self.formatter.fmt['END']}"
        self.formatter.print_content_box_start(width=box_width, indent_str=base_indent_str)
        
        limit = self.config.get_specific_display_limit('BAN_REASON_DISPLAY_LIMIT')
        
        line_padding_in_box = 1 
        content_area_width = box_width - 2 - (line_padding_in_box * 2)
        
        for i, ban_info in enumerate(player.ban_reasons[:limit]):
            reason_text, user_text = "", ""
            if isinstance(ban_info, dict) and "reason" in ban_info:
                reason_text = ban_info["reason"]
                user_text = f"User: {self.formatter._get_fmt('BLUE')}{ban_info.get('username', 'N/A')}{self.formatter.fmt['END']}"
            else:
                reason_text = str(ban_info)

            header_line = f"{self.formatter._get_fmt('BOLD')}{i+1}.{self.formatter.fmt['END']}"
            if user_text: header_line += f" {user_text}"
            
            self.formatter.print_line_in_box(f"{item_indent_str}{header_line}", v_char_content_box, base_indent_str, line_padding_in_box)
            
            reason_display_indent = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
            effective_text_width = content_area_width - len(LAYOUT_CONFIG['DEFAULT_INDENT_STRING'])
            
            wrapped_lines = self.formatter.get_wrapped_lines(reason_text, effective_text_width, 
                                                             initial_indent="", subsequent_indent="")
            for line_idx, line in enumerate(wrapped_lines):
                self.formatter.print_line_in_box(f"{reason_display_indent}{line}", v_char_content_box, base_indent_str, line_padding_in_box)


            if i < limit - 1 and i < len(player.ban_reasons) -1 :
                sep_len = content_area_width - len(item_indent_str)
                if sep_len < 0: sep_len = 0
                sep_line = BOX_CHARS['H'] * sep_len
                self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('GRAY')}{sep_line}{self.formatter.fmt['END']}", 
                                                 v_char_content_box, base_indent_str, line_padding_in_box)

        if len(player.ban_reasons) > limit:
            self.formatter.print_line_in_box(f"{item_indent_str}{BOX_CHARS['BULLET']} ... and {len(player.ban_reasons) - limit} more ban reasons",
                                            v_char_content_box, base_indent_str, line_padding_in_box)

        self.formatter.print_content_box_end(width=box_width, indent_str=base_indent_str)


    def _print_connection_paths_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        connection_data = find_connection_paths(player, nickname)
        if not connection_data or (not connection_data["direct_connections"] and not connection_data["indirect_connections"]):
            return

        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)
        sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        
        box_v_char_raw, end_box = self._print_section_box_start("CONNECTION EVIDENCE (Paths to Known Alts)", base_indent_str, box_width, ('YELLOW', 'BOLD'), box_char_set='SINGLE')
        box_v_char = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{self.formatter.fmt['END']}"
        line_padding_in_box = 1

        total_conn = len(connection_data["direct_connections"]) + len(connection_data["indirect_connections"])
        self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('BOLD')}Overview:{self.formatter.fmt['END']} {total_conn} alts connected via explicit paths", box_v_char, base_indent_str, line_padding_in_box)
        
        if connection_data["direct_connections"]:
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('RED', 'BOLD')}■ DIRECT CONNECTIONS ({len(connection_data['direct_connections'])}):{self.formatter.fmt['END']}",
                                             box_v_char, base_indent_str, line_padding_in_box)
            limit = self.config.get_specific_display_limit('CONNECTION_PATH_DISPLAY_LIMIT')
            count = 0
            for target_nick, info in connection_data["direct_connections"].items():
                if count >= limit: break
                path_line = f"{BOX_CHARS['SUB_ARROW']} {info['path']} ({self.formatter.format_confidence(info['confidence'])})"
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{path_line}", box_v_char, base_indent_str, line_padding_in_box)
                count +=1
            if len(connection_data["direct_connections"]) > count:
                 self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(connection_data['direct_connections'])-count} more", box_v_char, base_indent_str, line_padding_in_box)   
            self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)

        if connection_data["indirect_connections"]:
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('YELLOW', 'BOLD')}■ INDIRECT CONNECTIONS ({len(connection_data['indirect_connections'])}):{self.formatter.fmt['END']}",
                                             box_v_char, base_indent_str, line_padding_in_box)
            limit_via_groups = self.config.get_specific_display_limit('CONNECTION_PATH_DISPLAY_LIMIT') 
            paths_per_via_limit = DISPLAY_LIMITS['SMALL']
            
            displayed_via_groups = 0
            for via_nick, data in connection_data["indirect_by_via"].items():
                if displayed_via_groups >= limit_via_groups: break
                self.formatter.print_line_in_box(f"{sub_item_indent_str}Through {self.formatter._get_fmt('BOLD')}{via_nick}{self.formatter.fmt['END']}:",
                                                  box_v_char, base_indent_str, line_padding_in_box)
                displayed_paths_for_this_via = 0
                for conn_type in ["hwid", "ip"]: 
                    for conn_detail in data[conn_type]:
                        if displayed_paths_for_this_via >= paths_per_via_limit: break
                        target_nick = conn_detail["nick"]
                        full_info = connection_data["indirect_connections"].get(target_nick)
                        if full_info and full_info['via'] == via_nick : 
                            path_line = f"  {BOX_CHARS['SUB_ARROW']} {full_info['path']} ({self.formatter.format_confidence(full_info['confidence'])})"
                            self.formatter.print_line_in_box(f"{sub_item_indent_str}{path_line}", box_v_char, base_indent_str, line_padding_in_box)
                            displayed_paths_for_this_via +=1
                
                total_paths_for_this_via = sum(len(data[ct]) for ct in data)
                if total_paths_for_this_via > displayed_paths_for_this_via:
                    self.formatter.print_line_in_box(f"{sub_item_indent_str}    {BOX_CHARS['BULLET']} ...and {total_paths_for_this_via - displayed_paths_for_this_via} more paths via {via_nick}", box_v_char, base_indent_str, line_padding_in_box)
                
                displayed_via_groups +=1
                if displayed_via_groups < len(connection_data["indirect_by_via"]) and displayed_via_groups < limit_via_groups:
                    self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)

            if len(connection_data["indirect_by_via"]) > displayed_via_groups :
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and connections through {len(connection_data['indirect_by_via'])-displayed_via_groups} more accounts", box_v_char, base_indent_str, line_padding_in_box)   

        end_box()

    def _print_complaints_subsection(self, complaints: List[Dict[str, Any]], title_prefix: str,
                                    box_v_char: str, base_indent_str: str, item_indent_str: str,
                                    content_area_width: int,
                                    limit_key: str, title_color_keys: Tuple[str, ...] = ('GREEN', 'BOLD')) -> None:
        if not complaints:
            return
        
        line_padding_in_box = 1
        sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        content_display_indent_str = sub_item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] 
        content_snippet_extra_indent = content_display_indent_str + "  "


        self.formatter.print_line_in_box(
            f"{item_indent_str}{self.formatter._get_fmt(*title_color_keys)}■ {title_prefix} ({len(complaints)}):{self.formatter.fmt['END']}",
            box_v_char, base_indent_str, line_padding_in_box
        )
        limit = self.config.get_specific_display_limit(limit_key)
        for i, complaint in enumerate(complaints[:limit]):
            link_str = self.formatter.truncate_text(complaint.get('link', 'N/A'), 60)
            self.formatter.print_line_in_box(
                f"{sub_item_indent_str}{i+1}. {self.formatter._get_fmt('BLUE','UNDERLINE')}{link_str}{self.formatter.fmt['END']}",
                box_v_char, base_indent_str, line_padding_in_box
            )
            
            author_channel_info = []
            if complaint.get('channel'): author_channel_info.append(f"Channel: {complaint.get('channel')}")
            if complaint.get('author'): author_channel_info.append(f"Author: {complaint.get('author')}")
            if author_channel_info:
                self.formatter.print_line_in_box(
                    f"{content_display_indent_str}{' | '.join(author_channel_info)}", 
                    box_v_char, base_indent_str, line_padding_in_box
                )
            
            content = complaint.get("content", "")
            if content:
                self.formatter.print_line_in_box(f"{content_display_indent_str}{self.formatter._get_fmt('BOLD')}Content:{self.formatter.fmt['END']}", 
                                                 box_v_char, base_indent_str, line_padding_in_box)
                
                eff_text_width = content_area_width - len(content_display_indent_str) - len(LAYOUT_CONFIG['DEFAULT_INDENT_STRING'])
                if eff_text_width < 10: eff_text_width = 10

                wrapped_lines = self.formatter.get_wrapped_lines(content, eff_text_width, initial_indent="", subsequent_indent="")
                for line_idx, line in enumerate(wrapped_lines):
                    self.formatter.print_line_in_box(f"{content_display_indent_str}{LAYOUT_CONFIG['DEFAULT_INDENT_STRING']}{line}", 
                                                     box_v_char, base_indent_str, line_padding_in_box)
        if len(complaints) > limit:
            self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ... and {len(complaints) - limit} more", 
                                             box_v_char, base_indent_str, line_padding_in_box)
        self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)



    def _print_complaints_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        if not hasattr(player, 'complaint_links') or not player.complaint_links:
            return
        
        direct_complaints, sub_hwid_complaints, sub_ip_complaints, other_player_complaints = analyze_complaints(player, nickname)
        
        total_complaints_to_display = len(direct_complaints) + len(sub_hwid_complaints) + len(sub_ip_complaints) + len(other_player_complaints)
        if not total_complaints_to_display:
            return
            
        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)

        box_v_char_raw, end_box = self._print_section_box_start(f"COMPLAINTS ({total_complaints_to_display})", base_indent_str, box_width, box_char_set='SINGLE')
        box_v_char = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{self.formatter.fmt['END']}"

        line_padding_in_box = 1
        content_area_width = box_width - 2 - (line_padding_in_box * 2)

        self._print_complaints_subsection(
            direct_complaints, f"DIRECT COMPLAINTS (Targeting {nickname})",
            box_v_char, base_indent_str, item_indent_str, content_area_width,
            'COMPLAINT_LIMIT', ('RED', 'BOLD')
        )
        self._print_complaints_subsection(
            sub_hwid_complaints, "SUB-DIRECT COMPLAINTS (Via HWID-Linked Accounts)",
            box_v_char, base_indent_str, item_indent_str, content_area_width,
            'SUB-COMPLAINT_HWID_LIMIT', ('YELLOW', 'BOLD')
        )
        self._print_complaints_subsection(
            sub_ip_complaints, "SUB-DIRECT COMPLAINTS (Via IP-Linked Accounts)",
            box_v_char, base_indent_str, item_indent_str, content_area_width,
            'SUB-COMPLAINT_IP_LIMIT', ('YELLOW',)
        )
        self._print_complaints_subsection(
            other_player_complaints, "OTHER ASSOCIATED COMPLAINTS (Targeting Other Known Alts)",
            box_v_char, base_indent_str, item_indent_str, content_area_width,
            'COMPLAINT_SAMPLE_LIMIT', ('CYAN',)
        )
        end_box()

    def _print_ip_hwid_list(self, title: str, items: list, formatter_func: Callable, nickname_for_context: str,
                            box_v_char: str, base_indent_str: str, item_indent_str: str, 
                            limit_name: str, color_keys: Tuple[str, ...] = ('BOLD',), show_only_user_if_single: bool = False,
                            player_obj_for_nicks: Optional[Player] = None):
        if not items: return

        line_padding_in_box = 1
        sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        details_indent_str = sub_item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']

        self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt(*color_keys)}■ {title} ({len(items)}):{self.formatter.fmt['END']}",
                                         box_v_char, base_indent_str, line_padding_in_box)
        limit = self.config.get_specific_display_limit(limit_name)
        
        player_nicks_set = set(getattr(player_obj_for_nicks, 'nicknames', [nickname_for_context])) if player_obj_for_nicks else {nickname_for_context}


        for i, item_data in enumerate(items[:limit]):
            if isinstance(item_data, tuple) and len(item_data) == 2:
                identifier_val, users_list = item_data
            else:
                identifier_val, users_list = item_data, [nickname_for_context]

            self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} {formatter_func(identifier_val)}", 
                                             box_v_char, base_indent_str, line_padding_in_box)
            
            users_set = set(users_list)
            primary_user = nickname_for_context
            primary_present = primary_user in users_set
            alts_present = [u for u in users_list if u in player_nicks_set and u != primary_user]
            others_present = [u for u in users_list if u != primary_user and u not in player_nicks_set]

            user_list_trunc_limit = DISPLAY_LIMITS['SMALL'] 

            if show_only_user_if_single and len(users_set) == 1 and primary_present:
                self.formatter.print_line_in_box(
                    f"{details_indent_str}{BOX_CHARS['SUB_ARROW']} {self.formatter._get_fmt('GREEN')}Only user ({primary_user}){self.formatter.fmt['END']}",
                    box_v_char, base_indent_str, line_padding_in_box)
            else:
                if primary_present:
                    self.formatter.print_line_in_box(
                        f"{details_indent_str}{BOX_CHARS['SUB_ARROW']} {self.formatter._get_fmt('GREEN')}Used by {primary_user}{self.formatter.fmt['END']}",
                        box_v_char, base_indent_str, line_padding_in_box)
                if alts_present:
                    self.formatter.print_line_in_box(
                        f"{details_indent_str}{BOX_CHARS['SUB_ARROW']} {self.formatter._get_fmt('YELLOW')}Shared with Alt(s): {self.formatter.truncate_list(sorted(list(set(alts_present))), user_list_trunc_limit)}{self.formatter.fmt['END']}",
                        box_v_char, base_indent_str, line_padding_in_box)
                if others_present:
                    label = "Shared with Others" if (primary_present or alts_present) else "Users"
                    self.formatter.print_line_in_box(
                        f"{details_indent_str}{BOX_CHARS['SUB_ARROW']} {label}: {self.formatter.truncate_list(sorted(list(set(others_present))), user_list_trunc_limit)}",
                        box_v_char, base_indent_str, line_padding_in_box)


        if len(items) > limit:
            self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(items)-limit} more", 
                                             box_v_char, base_indent_str, line_padding_in_box)
        self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)


    def _print_ip_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        if not hasattr(player, 'associated_ips') or not player.associated_ips: return
        original_ips, shared_ips, alt_shared_ips, multi_user_ips = analyze_ips(player, nickname)
        total_ips = len(original_ips) + len(shared_ips) + len(alt_shared_ips) + len(multi_user_ips)
        if not total_ips: return

        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)
        box_v_char_raw, end_box = self._print_section_box_start(f"ASSOCIATED IPs ({total_ips})", base_indent_str, box_width, box_char_set='SINGLE')
        box_v_char = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{self.formatter.fmt['END']}"
        line_padding_in_box = 1
        
        if original_ips:
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('GREEN', 'BOLD')}■ PRIMARY IPs ({len(original_ips)}) - Used only by {nickname}:{self.formatter.fmt['END']}", 
                                             box_v_char, base_indent_str, line_padding_in_box)
            limit = self.config.get_specific_display_limit('IP_OWNED_DISPLAY_LIMIT')
            sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
            for i, ip_addr in enumerate(original_ips[:limit]):
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} {self.formatter._get_fmt('CYAN')}{ip_addr}{self.formatter.fmt['END']}", 
                                                 box_v_char, base_indent_str, line_padding_in_box)
            if len(original_ips) > limit:
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(original_ips)-limit} more primary IPs", 
                                                 box_v_char, base_indent_str, line_padding_in_box)
            self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)

        self._print_ip_hwid_list(f"SHARED IPs - Used by {nickname} and others", shared_ips, lambda x: self.formatter._get_fmt('CYAN') + x + self.formatter.fmt['END'], nickname, box_v_char, base_indent_str, item_indent_str, 'IP_OWNED_DISPLAY_LIMIT', ('YELLOW','BOLD'), player_obj_for_nicks=player)
        self._print_ip_hwid_list(f"ALT ACCOUNT IPs - Used by {nickname}'s alts", alt_shared_ips, lambda x: self.formatter._get_fmt('CYAN') + x + self.formatter.fmt['END'], nickname, box_v_char, base_indent_str, item_indent_str, 'IP_ALT_DISPLAY_LIMIT', ('YELLOW','BOLD'), player_obj_for_nicks=player)
        self._print_ip_hwid_list(f"OTHER SHARED IPs - Not {nickname} or alts", multi_user_ips, lambda x: self.formatter._get_fmt('CYAN') + x + self.formatter.fmt['END'], nickname, box_v_char, base_indent_str, item_indent_str, 'IP_OTHER_DISPLAY_LIMIT', ('GRAY','BOLD'), player_obj_for_nicks=player)
        end_box()

    def _print_hwid_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        if not hasattr(player, 'associated_hwids') or not player.associated_hwids: return
        owned_hwids, alt_hwids, other_hwids = analyze_hwids(player, nickname)
        total_hwids = len(owned_hwids) + len(alt_hwids) + len(other_hwids)
        if not total_hwids: return
            
        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)
        box_v_char_raw, end_box = self._print_section_box_start(f"ASSOCIATED HWIDs ({total_hwids})", base_indent_str, box_width, box_char_set='SINGLE')
        box_v_char = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{self.formatter.fmt['END']}"
        
        self._print_ip_hwid_list(f"PRIMARY HWIDs - Used by {nickname}", owned_hwids, self.formatter.format_hwid, nickname, box_v_char, base_indent_str, item_indent_str, 'HWID_OWNED_DISPLAY_LIMIT', ('GREEN','BOLD'), show_only_user_if_single=True, player_obj_for_nicks=player)
        self._print_ip_hwid_list(f"ALT ACCOUNT HWIDs - Used by {nickname}'s alts", alt_hwids, self.formatter.format_hwid, nickname, box_v_char, base_indent_str, item_indent_str, 'HWID_ALT_DISPLAY_LIMIT', ('YELLOW','BOLD'), player_obj_for_nicks=player)
        self._print_ip_hwid_list(f"OTHER HWIDs - Not {nickname} or alts", other_hwids, self.formatter.format_hwid, nickname, box_v_char, base_indent_str, item_indent_str, 'HWID_OTHER_DISPLAY_LIMIT', ('GRAY','BOLD'), player_obj_for_nicks=player)
        end_box()

    def _print_denied_logins_section(self, player: Player, nickname: str, base_indent_str: str) -> None:
        if not hasattr(player, 'denied_logins') or not player.denied_logins: return

        box_width = self.config.box_width_medium
        item_indent_str = self._get_indent_str(1)
        sub_item_indent_str = item_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        line_padding_in_box = 1

        box_v_char_raw, end_box = self._print_section_box_start(
            f"DENIED LOGIN ATTEMPTS ({len(player.denied_logins)})", 
            base_indent_str, box_width, title_color_keys=('RED', 'BOLD'), box_char_set='SINGLE'
        )
        box_v_char = f"{self.formatter._get_fmt('BOLD')}{box_v_char_raw}{self.formatter.fmt['END']}"
        
        limit = self.config.get_specific_display_limit('LOGIN_DISPLAY_LIMIT')
        now = datetime.now()
        recent_threshold_dt = now - timedelta(days=TIME_ANALYSIS_THRESHOLDS['RECENT_LOGIN_DAYS'])
        
        recent_logins, older_logins = [], []
        for l_entry in player.denied_logins: 
            try: 
                login_time_str = l_entry.get("time", "1970-01-01 00:00:00")
                login_dt = datetime.strptime(login_time_str, "%Y-%m-%d %H:%M:%S")
                (recent_logins if login_dt > recent_threshold_dt else older_logins).append(l_entry)
            except ValueError: older_logins.append(l_entry)

        displayed_count = 0
        if recent_logins:
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('BOLD')}Recent (last {TIME_ANALYSIS_THRESHOLDS['RECENT_LOGIN_DAYS']} days):{self.formatter.fmt['END']}",
                                             box_v_char, base_indent_str, line_padding_in_box)
            for i, login in enumerate(recent_logins):
                if displayed_count >= limit: break
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{i+1}. Time: {login.get('time','N/A')} | IP: {self.formatter._get_fmt('CYAN')}{login.get('ip_address','N/A')}{self.formatter.fmt['END']} | Server: {login.get('server','N/A')}", 
                                                 box_v_char, base_indent_str, line_padding_in_box)
                if login.get('user_name', nickname) != nickname:
                     self.formatter.print_line_in_box(f"{sub_item_indent_str}   {BOX_CHARS['SUB_ARROW']} Attempted as: {self.formatter._get_fmt('YELLOW')}{login.get('user_name')}{self.formatter.fmt['END']}", 
                                                      box_v_char, base_indent_str, line_padding_in_box)
                displayed_count += 1
            if len(recent_logins) > displayed_count and displayed_count >= limit :
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(recent_logins)-displayed_count} more recent logins", 
                                                 box_v_char, base_indent_str, line_padding_in_box)

            self.formatter.print_line_in_box("", box_v_char, base_indent_str, line_padding_in_box)


        if older_logins and displayed_count < limit:
            self.formatter.print_line_in_box(f"{item_indent_str}{self.formatter._get_fmt('BOLD')}Older logins:{self.formatter.fmt['END']}",
                                             box_v_char, base_indent_str, line_padding_in_box)
            older_to_show = limit - displayed_count
            for i, login in enumerate(older_logins[:older_to_show]):
                self.formatter.print_line_in_box(f"{sub_item_indent_str}{i+1}. Time: {login.get('time','N/A')} | IP: {self.formatter._get_fmt('CYAN')}{login.get('ip_address','N/A')}{self.formatter.fmt['END']} | Server: {login.get('server','N/A')}", 
                                                 box_v_char, base_indent_str, line_padding_in_box)
                if login.get('user_name', nickname) != nickname:
                     self.formatter.print_line_in_box(f"{sub_item_indent_str}   {BOX_CHARS['SUB_ARROW']} Attempted as: {self.formatter._get_fmt('YELLOW')}{login.get('user_name')}{self.formatter.fmt['END']}", 
                                                      box_v_char, base_indent_str, line_padding_in_box)
                displayed_count +=1 
            
            if len(older_logins) > older_to_show:
                 self.formatter.print_line_in_box(f"{sub_item_indent_str}{BOX_CHARS['BULLET']} ...and {len(older_logins)-older_to_show} more older logins", 
                                                  box_v_char, base_indent_str, line_padding_in_box)
        
        if len(player.denied_logins) > limit and displayed_count >= limit : 
             self.formatter.print_line_in_box(f"{item_indent_str}{BOX_CHARS['BULLET']} ...displaying {limit} of {len(player.denied_logins)} total logins.", 
                                              box_v_char, base_indent_str, line_padding_in_box)
        end_box()

    def _print_player_ban_summary_message_scan(self, player: Player, primary_nickname: str, indent_str: str) -> None:
        fmt = self.formatter.fmt
        if not hasattr(player, 'ban_reasons') or not player.ban_reasons:
            return

        total_ban_reasons = len(player.ban_reasons)
        print(f"{indent_str}{fmt['BOLD']}Ban Reasons Summary ({self.formatter.format_count(total_ban_reasons, threshold_medium=1, threshold_high=3)} total):{fmt['END']}")

        limit = self.config.get_specific_display_limit('COMPLAINT_SAMPLE_LIMIT') 
        
        sub_indent_str = indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']

        for i, ban_info in enumerate(player.ban_reasons[:limit]):
            reason_text_full = ""
            account_name_str = ""

            if isinstance(ban_info, dict):
                reason_text_full = ban_info.get("reason", str(ban_info))
                banned_username = ban_info.get('username')
                if banned_username:
                    if banned_username != primary_nickname:
                        account_name_str = f"({fmt['YELLOW']}Account: {banned_username}{fmt['END']})"
                    else:
                        account_name_str = f"({fmt['GREEN']}Account: {primary_nickname}{fmt['END']})"
            else:
                reason_text_full = str(ban_info)
            
            
            reason_lines = reason_text_full.splitlines()
            first_reason_line = reason_lines[0] if reason_lines else ""
            
            display_line_first = f"{sub_indent_str}{BOX_CHARS['SUB_ARROW']} {first_reason_line}"
            if account_name_str:
                display_line_first += f" {account_name_str}"
            print(display_line_first)

            additional_reason_indent = sub_indent_str + "  "
            for line_num in range(1, len(reason_lines)):
                print(f"{additional_reason_indent}{reason_lines[line_num]}")


        if total_ban_reasons > limit:
            print(f"{sub_indent_str}{BOX_CHARS['BULLET']} ...and {total_ban_reasons - limit} more ban reasons.")


    def _print_player_complaints_details_message_scan(self, player: Player, primary_nickname: str, indent_str: str) -> int:
        fmt = self.formatter.fmt
        if not hasattr(player, 'complaint_links') or not player.complaint_links:
            return 0
            
        direct, sub_hwid, sub_ip, other_assoc = analyze_complaints(player, primary_nickname)
        total_complaints_for_player = len(direct) + len(sub_hwid) + len(sub_ip) + len(other_assoc)

        if total_complaints_for_player == 0:
            return 0

        category_counts_parts = []
        if direct: category_counts_parts.append(f"Direct: {len(direct)}")
        if sub_hwid: category_counts_parts.append(f"Via HWID-Alts: {len(sub_hwid)}")
        if sub_ip: category_counts_parts.append(f"Via IP-Alts: {len(sub_ip)}")
        if other_assoc: category_counts_parts.append(f"Other Player Alts: {len(other_assoc)}")
        
        category_summary_str = ", ".join(category_counts_parts)
        print(f"{indent_str}{fmt['BOLD']}Complaints:{fmt['END']} Total {self.formatter.format_count(total_complaints_for_player)} ({category_summary_str})")

        sub_indent_str = indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
        content_link_indent_str = sub_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] 
        content_snippet_indent_str = content_link_indent_str + "  "

        def print_complaint_samples(complaints_list: List[Dict[str, Any]], 
                                    cat_name_str: str, 
                                    cat_color_keys: Tuple[str, ...], 
                                    display_limit: int,
                                    is_other_player_alts_category: bool): 
            if not complaints_list: return
            print(f"{sub_indent_str}{self.formatter._get_fmt(*cat_color_keys)}{BOX_CHARS['BULLET']} {cat_name_str} ({len(complaints_list)}):{fmt['END']}")
            
            num_complaints_to_show = len(complaints_list) if not is_other_player_alts_category else display_limit

            for c_idx, c in enumerate(complaints_list[:num_complaints_to_show]):
                link_str = c.get('link','N/A')
                print(f"{content_link_indent_str}{fmt['BLUE']}{BOX_CHARS['SUB_ARROW']} {link_str}{fmt['END']}")
                
                raw_content = c.get('content','No content')
                if raw_content and raw_content != "No content":
                    content_lines = raw_content.splitlines()
                    
                    for line_text in content_lines:
                        print(f"{content_snippet_indent_str}{line_text}")
            
            if is_other_player_alts_category and len(complaints_list) > display_limit:
                print(f"{content_snippet_indent_str}...and {len(complaints_list) - display_limit} more complaints in this category.")

        print_complaint_samples(direct, "Direct", ('RED', 'BOLD'), len(direct), is_other_player_alts_category=False)
        print_complaint_samples(sub_hwid, "Via HWID-Alts", ('YELLOW', 'BOLD'), len(sub_hwid), is_other_player_alts_category=False)
        print_complaint_samples(sub_ip, "Via IP-Alts", ('YELLOW',), len(sub_ip), is_other_player_alts_category=False)

        sample_complaint_limit_value = self.config.get_specific_display_limit('COMPLAINT_SAMPLE_LIMIT')
        print_complaint_samples(other_assoc, "Other Player Alts", ('CYAN',), sample_complaint_limit_value, is_other_player_alts_category=True)
        
        return total_complaints_for_player


    def _print_player_ip_details_message_scan(self, player: Player, primary_nickname: str, indent_str: str):
        fmt = self.formatter.fmt
        if not hasattr(player, 'associated_ips') or not player.associated_ips:
            print(f"{indent_str}{fmt['BOLD']}Associated IPs:{fmt['END']} {self.formatter.format_count(0)}")
            return

        original_ips, shared_ips, alt_shared_ips, multi_user_ips = analyze_ips(player, primary_nickname)
        total_ips = len(player.associated_ips) 
        
        print(f"{indent_str}{fmt['BOLD']}Associated IPs:{fmt['END']} {self.formatter.format_count(total_ips)}")

        is_any_ip_shared = any(len(users) > 1 for _, users in player.associated_ips.items())
        user_list_trunc_limit = DISPLAY_LIMITS['SMALL']

        if total_ips > 1 or is_any_ip_shared: 
            sub_indent_str = indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
            details_indent_str = sub_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] 
            
            if original_ips:
                print(f"{sub_indent_str}{fmt['GREEN']}{BOX_CHARS['BULLET']} Primary IPs ({len(original_ips)}):{fmt['END']} {self.formatter.truncate_list([self.formatter._get_fmt('CYAN') + ip + self.formatter.fmt['END'] for ip in original_ips], user_list_trunc_limit)}")
            
            if shared_ips:
                print(f"{sub_indent_str}{fmt['YELLOW']}{BOX_CHARS['BULLET']} Shared with {primary_nickname} ({len(shared_ips)}):{fmt['END']}")
                for i, (ip, users) in enumerate(shared_ips[:user_list_trunc_limit]):
                    others = [u for u in users if u != primary_nickname]
                    print(f"{details_indent_str}{self.formatter._get_fmt('CYAN')}{ip}{self.formatter.fmt['END']} (with: {self.formatter.truncate_list(others, user_list_trunc_limit)})")
                if len(shared_ips) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(shared_ips)-user_list_trunc_limit} more.")

            if alt_shared_ips:
                print(f"{sub_indent_str}{fmt['YELLOW']}{BOX_CHARS['BULLET']} Shared with Player's Alts ({len(alt_shared_ips)}):{fmt['END']}")
                player_nicks_set = set(getattr(player, 'nicknames', []))
                for i, (ip, users) in enumerate(alt_shared_ips[:user_list_trunc_limit]):
                    alt_users_on_ip = sorted(list(set(u for u in users if u in player_nicks_set and u != primary_nickname)))
                    other_users_on_ip = sorted(list(set(u for u in users if u not in player_nicks_set)))
                    shared_desc_parts = []
                    if alt_users_on_ip: shared_desc_parts.append(f"Alts: {self.formatter.truncate_list(alt_users_on_ip, user_list_trunc_limit)}")
                    if other_users_on_ip: shared_desc_parts.append(f"Others: {self.formatter.truncate_list(other_users_on_ip, user_list_trunc_limit)}")
                    print(f"{details_indent_str}{self.formatter._get_fmt('CYAN')}{ip}{self.formatter.fmt['END']} ({'; '.join(shared_desc_parts)})")
                if len(alt_shared_ips) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(alt_shared_ips)-user_list_trunc_limit} more.")
            
            if multi_user_ips:
                print(f"{sub_indent_str}{fmt['GRAY']}{BOX_CHARS['BULLET']} Other Multi-User IPs ({len(multi_user_ips)}):{fmt['END']}")
                for i, (ip, users) in enumerate(multi_user_ips[:user_list_trunc_limit]):
                     print(f"{details_indent_str}{self.formatter._get_fmt('CYAN')}{ip}{self.formatter.fmt['END']} (users: {self.formatter.truncate_list(sorted(list(set(users))), user_list_trunc_limit)})")
                if len(multi_user_ips) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(multi_user_ips)-user_list_trunc_limit} more.")


    def _print_player_hwid_details_message_scan(self, player: Player, primary_nickname: str, indent_str: str):
        fmt = self.formatter.fmt
        if not hasattr(player, 'associated_hwids') or not player.associated_hwids:
            print(f"{indent_str}{fmt['BOLD']}Associated HWIDs:{fmt['END']} {self.formatter.format_count(0)}")
            return

        owned_hwids, alt_hwids, other_hwids = analyze_hwids(player, primary_nickname)
        total_hwids = len(player.associated_hwids)

        print(f"{indent_str}{fmt['BOLD']}Associated HWIDs:{fmt['END']} {self.formatter.format_count(total_hwids)}")
        
        is_any_hwid_shared = any(len(users) > 1 for _, users in player.associated_hwids.items())
        user_list_trunc_limit = DISPLAY_LIMITS['SMALL']

        if total_hwids > 1 or is_any_hwid_shared: 
            sub_indent_str = indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
            details_indent_str = sub_indent_str + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']

            if owned_hwids: 
                print(f"{sub_indent_str}{fmt['GREEN']}{BOX_CHARS['BULLET']} Primary HWIDs ({len(owned_hwids)}):{fmt['END']}")
                for i, (hwid, users) in enumerate(owned_hwids[:user_list_trunc_limit]):
                    others = [u for u in users if u != primary_nickname]
                    if not others: 
                        print(f"{details_indent_str}{self.formatter.format_hwid(hwid)} (only {primary_nickname})")
                    else: 
                        print(f"{details_indent_str}{self.formatter.format_hwid(hwid)} (with: {self.formatter.truncate_list(sorted(list(set(others))), user_list_trunc_limit)})")
                if len(owned_hwids) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(owned_hwids)-user_list_trunc_limit} more.")
            
            if alt_hwids:
                print(f"{sub_indent_str}{fmt['YELLOW']}{BOX_CHARS['BULLET']} Player's Alt HWIDs ({len(alt_hwids)}):{fmt['END']}")
                player_nicks_set = set(getattr(player, 'nicknames', []))
                for i, (hwid, users) in enumerate(alt_hwids[:user_list_trunc_limit]):
                    alt_users_on_hwid = sorted(list(set(u for u in users if u in player_nicks_set and u != primary_nickname)))
                    other_users_on_hwid = sorted(list(set(u for u in users if u not in player_nicks_set)))
                    shared_desc_parts = []
                    if alt_users_on_hwid: shared_desc_parts.append(f"Alts: {self.formatter.truncate_list(alt_users_on_hwid, user_list_trunc_limit)}")
                    if other_users_on_hwid: shared_desc_parts.append(f"Others: {self.formatter.truncate_list(other_users_on_hwid, user_list_trunc_limit)}")
                    print(f"{details_indent_str}{self.formatter.format_hwid(hwid)} ({'; '.join(shared_desc_parts)})")
                if len(alt_hwids) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(alt_hwids)-user_list_trunc_limit} more.")

            if other_hwids:
                print(f"{sub_indent_str}{fmt['GRAY']}{BOX_CHARS['BULLET']} Other Shared HWIDs ({len(other_hwids)}):{fmt['END']}")
                for i, (hwid, users) in enumerate(other_hwids[:user_list_trunc_limit]):
                     print(f"{details_indent_str}{self.formatter.format_hwid(hwid)} (users: {self.formatter.truncate_list(sorted(list(set(users))), user_list_trunc_limit)})")
                if len(other_hwids) > user_list_trunc_limit: print(f"{details_indent_str}...and {len(other_hwids)-user_list_trunc_limit} more.")


    def print_message_scan_results(self, scan_results: List[ScanResult]) -> None:
        fmt = self.formatter.fmt
        overall_indent = self._get_indent_str(0) 
        message_content_indent = self._get_indent_str(1) 
        player_section_base_indent = self._get_indent_str(1) 
        player_content_indent = player_section_base_indent + LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] 

        self.formatter.print_header(f"SCAN RESULTS - {len(scan_results)} messages processed", self.config.box_width_large)
        
        summary_data = {
            "total_players": 0, "banned": 0, "suspicious": 0, "clean": 0, "unknown": 0,
            "total_complaints": 0, "unique_hwids": set(), "unique_ips": set(),
            "problematic_players": []
        }

        for idx, result in enumerate(scan_results):
            message = result.message
            self.formatter.print_section(
                f"MESSAGE ({idx+1}/{len(scan_results)}): {fmt['BLUE']}{message.link}{fmt['END']}",
                width=self.config.box_width_large
            )
            print(f"{message_content_indent}{fmt['BOLD']}AUTHOR:{fmt['END']} {message.author_name}")
            if hasattr(result, 'scan_time') and result.scan_time:
                scan_time_str = result.scan_time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"{message_content_indent}{fmt['BOLD']}SCANNED:{fmt['END']} {scan_time_str}")

            valid_players = [p for p in result.players if p and getattr(p, 'primary_nickname', None) and p.primary_nickname != "Unknown"]
            if not valid_players:
                print(f"{message_content_indent}{fmt['GRAY']}No valid players found in this message.{fmt['END']}")
            
            for player_idx, player in enumerate(valid_players):
                primary_nick = getattr(player, 'primary_nickname', 'Unknown')
                
                summary_data["total_players"] += 1
                status_lower = getattr(player, 'status', 'unknown').lower()
                summary_data[status_lower] = summary_data.get(status_lower, 0) + 1
                ban_count = getattr(player, 'ban_counts', 0)

                if status_lower in [PLAYER_STATUS['BANNED'], PLAYER_STATUS['SUSPICIOUS']]:
                     summary_data["problematic_players"].append((primary_nick, player.status.upper(), ban_count))

                print(f"\n{player_section_base_indent}{self.formatter._get_fmt('CYAN','BOLD')}PLAYER: {primary_nick}{fmt['END']}")
                
                status_str = self.formatter.format_status(player.status, getattr(player, 'hwid_erased', False))
                print(f"{player_content_indent}{fmt['BOLD']}STATUS:{fmt['END']} {status_str} | {fmt['BOLD']}BANS:{fmt['END']} {self.formatter.format_count(ban_count)}")


                if hasattr(player, 'ban_reasons') and player.ban_reasons:
                    self._print_player_ban_summary_message_scan(player, primary_nick, player_content_indent)
                
                player_total_complaints = self._print_player_complaints_details_message_scan(player, primary_nick, player_content_indent)
                
                self._print_player_ip_details_message_scan(player, primary_nick, player_content_indent)
                self._print_player_hwid_details_message_scan(player, primary_nick, player_content_indent)
                
                if hasattr(player, 'complaint_links'): 
                    summary_data["total_complaints"] += len(player.complaint_links) 
                if hasattr(player, 'associated_ips'): 
                    summary_data["unique_ips"].update(player.associated_ips.keys())
                if hasattr(player, 'associated_hwids'): 
                    summary_data["unique_hwids"].update(player.associated_hwids.keys())

            if idx < len(scan_results) - 1:
                print() 
                self.formatter.print_horizontal_line(self.config.box_width_large, indent_str=overall_indent, char_key='H', color_keys=('GRAY',))
        
        self.formatter.print_header("SCAN SUMMARY", self.config.box_width_large)
        stats = {
            "Messages Processed": len(scan_results),
            "Total Players Found": summary_data["total_players"],
            "Banned Players": summary_data["banned"],
            "Suspicious Players": summary_data["suspicious"],
            "Clean Players": summary_data["clean"],
            "Unknown Status": summary_data["unknown"],
            "Total Complaints Linked": summary_data["total_complaints"], 
            "Unique HWIDs Detected": len(summary_data["unique_hwids"]),
            "Unique IPs Detected": len(summary_data["unique_ips"]),
        }
        self.formatter.print_stats_box("Overall Statistics", stats, 
                                       base_indent_str=message_content_indent, 
                                       width=self.config.box_width_medium, 
                                       columns=2)

        if summary_data["problematic_players"]:
            print(f"\n{message_content_indent}{self.formatter._get_fmt('BOLD', 'YELLOW')}Problematic Players Summary ({len(summary_data['problematic_players'])}):{fmt['END']}")
            limit = self.config.get_specific_display_limit('SUMMARY_LIST_LIMIT')
            problematic_content_indent = message_content_indent + LAYOUT_CONFIG['DEFAULT_INDENT_STRING']
            for p_nick, p_status, p_bans in summary_data["problematic_players"][:limit]:
                p_status_fmt = self.formatter.format_status(p_status) 
                print(f"{problematic_content_indent}{BOX_CHARS['BULLET']} {p_nick}: {p_status_fmt} (Bans: {self.formatter.format_count(p_bans)})")
            if len(summary_data["problematic_players"]) > limit:
                print(f"{problematic_content_indent}{BOX_CHARS['BULLET']} ... and {len(summary_data['problematic_players']) - limit} more.")
        print()