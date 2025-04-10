import json
import os
import shutil
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable

from models.message import ScanResult
from models.player import Player
from utils.logging_utils import get_logger

logger = get_logger(__name__)


class ReportConfig:
    """Configuration class for report formatting settings."""

    def __init__(self, **kwargs):
        terminal_size = shutil.get_terminal_size((120, 40))
        terminal_width = terminal_size.columns

        self.box_width_large = min(kwargs.get('box_width_large', 120), terminal_width - 4)
        self.box_width_medium = min(kwargs.get('box_width_medium', 100), terminal_width - 8)
        self.box_width_small = min(kwargs.get('box_width_small', 80), terminal_width - 12)

        self.truncate_list_limit = kwargs.get('truncate_list_limit', 7)
        self.truncate_text_length = kwargs.get('truncate_text_length', 80)
        self.display_limit_small = kwargs.get('display_limit_small', 5)
        self.display_limit_medium = kwargs.get('display_limit_medium', 10)
        self.display_limit_large = kwargs.get('display_limit_large', 20)

        self.detail_level = kwargs.get('detail_level', 1)

        self.color_intensity = kwargs.get('color_intensity', 1)

        self.show_timestamps = kwargs.get('show_timestamps', True)


class ReportFormatter:
    """Enhanced formatter for report display with configurable appearance."""

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.fmt = self._setup_terminal_formatting()
        self.box = self._setup_box_chars()
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _setup_terminal_formatting(self) -> Dict[str, str]:
        """Setup terminal formatting codes based on output type and config."""
        if sys.stdout.isatty():
            base_fmt = {
                'HEADER': '\033[95m',
                'BLUE': '\033[94m',
                'CYAN': '\033[96m',
                'GREEN': '\033[92m',
                'YELLOW': '\033[93m',
                'RED': '\033[91m',
                'BOLD': '\033[1m',
                'UNDERLINE': '\033[4m',
                'END': '\033[0m',
                'GRAY': '\033[90m',
                'WHITE': '\033[97m',
                'BG_BLACK': '\033[40m',
                'BG_RED': '\033[41m',
                'BG_GREEN': '\033[42m',
                'BG_YELLOW': '\033[43m',
                'BG_BLUE': '\033[44m',
                'BG_MAGENTA': '\033[45m',
                'BG_CYAN': '\033[46m',
                'BG_WHITE': '\033[47m',
                'ITALIC': '\033[3m'
            }

            bright_colors = {
                'BRIGHT_BLACK': '\033[90m',
                'BRIGHT_RED': '\033[91m',
                'BRIGHT_GREEN': '\033[92m',
                'BRIGHT_YELLOW': '\033[93m',
                'BRIGHT_BLUE': '\033[94m',
                'BRIGHT_MAGENTA': '\033[95m',
                'BRIGHT_CYAN': '\033[96m',
                'BRIGHT_WHITE': '\033[97m',
            }

            if self.config.color_intensity >= 1:
                base_fmt.update(bright_colors)

            if self.config.color_intensity >= 2:
                for color in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'CYAN']:
                    base_fmt[f'{color}_BOLD'] = base_fmt[color] + base_fmt['BOLD']
                    base_fmt[f'{color}_UNDERLINE'] = base_fmt[color] + base_fmt['UNDERLINE']
                    base_fmt[f'{color}_ITALIC'] = base_fmt[color] + base_fmt['ITALIC']

            return base_fmt
        else:
            return {key: '' for key in [
                'HEADER', 'BLUE', 'CYAN', 'GREEN', 'YELLOW', 'RED', 'BOLD',
                'UNDERLINE', 'END', 'GRAY', 'WHITE', 'BG_BLACK', 'BG_RED',
                'BG_GREEN', 'BG_YELLOW', 'BG_BLUE', 'BG_MAGENTA', 'BG_CYAN',
                'BG_WHITE', 'ITALIC', 'BRIGHT_BLACK', 'BRIGHT_RED', 'BRIGHT_GREEN',
                'BRIGHT_YELLOW', 'BRIGHT_BLUE', 'BRIGHT_MAGENTA', 'BRIGHT_CYAN',
                'BRIGHT_WHITE', 'RED_BOLD', 'GREEN_BOLD', 'YELLOW_BOLD', 'BLUE_BOLD',
                'CYAN_BOLD', 'RED_UNDERLINE', 'GREEN_UNDERLINE', 'YELLOW_UNDERLINE',
                'BLUE_UNDERLINE', 'CYAN_UNDERLINE', 'RED_ITALIC', 'GREEN_ITALIC',
                'YELLOW_ITALIC', 'BLUE_ITALIC', 'CYAN_ITALIC'
            ]}

    def _setup_box_chars(self) -> Dict[str, str]:
        """Setup box drawing characters."""
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
            'CROSS': '┼',
            'DOUBLE_H': '═',
            'DOUBLE_V': '║',
            'DOUBLE_TL': '╔',
            'DOUBLE_TR': '╗',
            'DOUBLE_BL': '╚',
            'DOUBLE_BR': '╝',
            'DOUBLE_VL': '╣',
            'DOUBLE_VR': '╠',
            'DOUBLE_HU': '╩',
            'DOUBLE_HD': '╦',
            'DOUBLE_CROSS': '╬',
            'BULLET': '•',
            'ARROW': '→',
            'RIGHT_ARROW': '►',
            'DOWN_ARROW': '▼',
            'CHECK': '✓',
            'X_MARK': '✗',
            'WARNING': '⚠',
            'INFO': 'ℹ',
            'STAR': '★',
            'CIRCLE': '○',
            'FILLED_CIRCLE': '●'
        }

    def print_header(self, title: str, width: Optional[int] = None, style: str = 'header'):
        """Print a header box with the given title."""
        width = width or self.config.box_width_large
        self._print_boxed(title, width, style=style)

        if self.config.show_timestamps:
            timestamp_str = f"Report generated: {self.timestamp}"
            print(f"{self.fmt['GRAY']}{timestamp_str:>{width - 2}}{self.fmt['END']}")

    def print_section(self, title: str, width: Optional[int] = None, style: str = 'section'):
        """Print a section header with the given title."""
        width = width or self.config.box_width_medium
        self._print_boxed(title, width, style=style)

    def _print_boxed(self, title: str, width: int = 100, style: str = 'header'):
        """Print a boxed title with configurable style."""
        fmt = self.fmt
        box = self.box

        if style == 'header':
            color_prefix = fmt['HEADER'] + fmt['BOLD']
            box_chars = {
                'TL': box['DOUBLE_TL'], 'TR': box['DOUBLE_TR'],
                'BL': box['DOUBLE_BL'], 'BR': box['DOUBLE_BR'],
                'H': box['DOUBLE_H'], 'V': box['DOUBLE_V']
            }
        elif style == 'section':
            color_prefix = fmt['BRIGHT_CYAN'] + fmt['BOLD']
            box_chars = {
                'TL': box['TL'], 'TR': box['TR'],
                'BL': box['BL'], 'BR': box['BR'],
                'H': box['H'], 'V': box['V']
            }
        elif style == 'subsection':
            color_prefix = fmt['CYAN'] + fmt['BOLD']
            box_chars = {
                'TL': box['TL'], 'TR': box['TR'],
                'BL': box['BL'], 'BR': box['BR'],
                'H': box['H'], 'V': box['V']
            }
        elif style == 'warning':
            color_prefix = fmt['RED'] + fmt['BOLD']
            box_chars = {
                'TL': box['TL'], 'TR': box['TR'],
                'BL': box['BL'], 'BR': box['BR'],
                'H': box['H'], 'V': box['V']
            }
            title = f"{box['WARNING']} {title} {box['WARNING']}"
        elif style == 'success':
            color_prefix = fmt['GREEN'] + fmt['BOLD']
            box_chars = {
                'TL': box['TL'], 'TR': box['TR'],
                'BL': box['BL'], 'BR': box['BR'],
                'H': box['H'], 'V': box['V']
            }
            title = f"{box['CHECK']} {title} {box['CHECK']}"
        else:
            color_prefix = fmt['BOLD']
            box_chars = {
                'TL': box['TL'], 'TR': box['TR'],
                'BL': box['BL'], 'BR': box['BR'],
                'H': box['H'], 'V': box['V']
            }

        print(f"\n{color_prefix}{box_chars['TL']}{box_chars['H'] * (width - 2)}{box_chars['TR']}{fmt['END']}")

        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(
            f"{color_prefix}{box_chars['V']}{' ' * padding} {title} {' ' * right_padding}{box_chars['V']}{fmt['END']}")

        print(f"{color_prefix}{box_chars['BL']}{box_chars['H'] * (width - 2)}{box_chars['BR']}{fmt['END']}")

    def print_player_header(self, name: str, width: Optional[int] = None):
        """Print a player header with the given name."""
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        player_header = f"PLAYER: {name}"
        print(
            f"\n  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * (width - 2)}{box['DOUBLE_TR']}{fmt['END']}")

        padding = (width - len(player_header) - 4) // 2
        right_padding = width - padding - len(player_header) - 4
        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_V']}{' ' * padding} {player_header} {' ' * right_padding}{box['DOUBLE_V']}{fmt['END']}")

        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * (width - 2)}{box['DOUBLE_VL']}{fmt['END']}")

    def print_section_header(self, title: str, width: Optional[int] = None, style: str = 'normal'):
        """Print a section header with the given title and style."""
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        if style == 'warning':
            color = fmt['RED']
            title = f"{box['WARNING']} {title}"
        elif style == 'success':
            color = fmt['GREEN']
            title = f"{box['CHECK']} {title}"
        elif style == 'info':
            color = fmt['BLUE']
            title = f"{box['INFO']} {title}"
        elif style == 'important':
            color = fmt['YELLOW']
            title = f"{box['STAR']} {title}"
        else:
            color = fmt['BOLD']

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

        padding = (width - len(title) - 4) // 2
        right_padding = width - padding - len(title) - 4
        print(
            f"  {fmt['BOLD']}{box['V']}{' ' * padding} {color}{title}{fmt['END']}{fmt['BOLD']} {' ' * right_padding}{box['V']}{fmt['END']}")

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

    def print_content_box(self, width: Optional[int] = None, indent: str = "  ") -> Callable:
        """Print a content box with the given width and return a function to end it."""
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")

        def end_box():
            print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

        return end_box

    def print_wrapped_content(self, content: str, indent: str = "", line_width: Optional[int] = None):
        """Print wrapped content inside a box."""
        line_width = line_width or self.config.box_width_small - 10
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
        """Format a status string with appropriate colors and indicators."""
        fmt = self.fmt
        status = status.upper()

        if status.lower() == "banned":
            status_str = f"{fmt['RED_BOLD'] if 'RED_BOLD' in fmt else fmt['RED'] + fmt['BOLD']}{status}{fmt['END']}"
        elif status.lower() == "suspicious":
            status_str = f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{status}{fmt['END']}"
        elif status.lower() == "clean":
            status_str = f"{fmt['GREEN']}{status}{fmt['END']}"
        else:
            status_str = status

        if hwid_erased:
            status_str += f" {fmt['YELLOW']}(HWID ERASED){fmt['END']}"

        return status_str

    def format_hwid(self, hwid: str) -> str:
        """Format an HWID with appropriate colors and styling."""
        fmt = self.fmt

        if hwid.startswith("V2-"):
            prefix = f"{fmt['BOLD']}{fmt['CYAN']}V2-{fmt['END']}"
            base = hwid[3:]
            return f"{prefix}{fmt['CYAN']}{base}{fmt['END']}"

        return f"{fmt['CYAN']}{hwid}{fmt['END']}"

    def format_severity(self, severity: str) -> str:
        """Format a severity level with appropriate colors."""
        fmt = self.fmt
        severity = severity.upper()

        if severity in ["HIGH", "CRITICAL", "STRONG"]:
            return f"{fmt['RED_BOLD'] if 'RED_BOLD' in fmt else fmt['RED'] + fmt['BOLD']}{severity}{fmt['END']}"
        elif severity in ["MEDIUM", "MODERATE"]:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{severity}{fmt['END']}"
        elif severity in ["LOW", "MINIMAL"]:
            return f"{fmt['GREEN']}{severity}{fmt['END']}"
        else:
            return severity

    def format_confidence(self, confidence: str) -> str:
        """Format a confidence level with appropriate colors."""
        fmt = self.fmt
        confidence = confidence.upper()

        if confidence in ["HIGH", "CERTAIN"]:
            return f"{fmt['GREEN_BOLD'] if 'GREEN_BOLD' in fmt else fmt['GREEN'] + fmt['BOLD']}{confidence}{fmt['END']}"
        elif confidence in ["MEDIUM", "MODERATE", "LIKELY"]:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{confidence}{fmt['END']}"
        elif confidence in ["LOW", "UNCERTAIN", "UNLIKELY"]:
            return f"{fmt['RED']}{confidence}{fmt['END']}"
        else:
            return confidence

    def format_count(self, count: int, threshold_medium: int = 5, threshold_high: int = 20) -> str:
        """Format a count with color based on thresholds."""
        fmt = self.fmt

        if count >= threshold_high:
            return f"{fmt['RED_BOLD'] if 'RED_BOLD' in fmt else fmt['RED'] + fmt['BOLD']}{count}{fmt['END']}"
        elif count >= threshold_medium:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{count}{fmt['END']}"
        else:
            return f"{fmt['GREEN']}{count}{fmt['END']}"

    def truncate_list(self, items: List[str], limit: Optional[int] = None, joiner: str = ", ") -> str:
        """Truncate a list to the given limit and join with the given string."""
        if not items:
            return ""

        limit = limit or self.config.truncate_list_limit

        if len(items) <= limit:
            return joiner.join(items)

        return joiner.join(items[:limit]) + f", and {len(items) - limit} more"

    def truncate_text(self, text: str, max_length: Optional[int] = None) -> str:
        """Truncate text to the given maximum length."""
        if not text:
            return ""

        max_length = max_length or self.config.truncate_text_length

        if len(text) > max_length:
            return text[:max_length - 3] + "..."

        return text

    def print_list_items(self, items: List[str], prefix: str = "•", indent: str = "  ",
                         fmt_key: str = 'NORMAL', max_items: Optional[int] = None) -> None:
        """Print a list of items with the given prefix and formatting."""
        box = self.box
        fmt = self.fmt

        if not items:
            print(f"{indent}{box['V']}   None")
            return

        box_symbol = box.get(prefix.upper(), prefix)
        color_fmt = fmt.get(fmt_key, '')

        max_items = max_items or (
            self.config.display_limit_large if self.config.detail_level >= 2 else
            self.config.display_limit_medium
        )

        for i, item in enumerate(items[:max_items]):
            print(f"{indent}{box['V']}   {box_symbol} {color_fmt}{item}{fmt['END']}")

        if len(items) > max_items:
            print(f"{indent}{box['V']}   {box_symbol} ... and {len(items) - max_items} more")

    def print_table_row(self, columns: List[str], widths: List[int], indent: str = "  ",
                        fmt_keys: Optional[List[str]] = None) -> None:
        """Print a table row with the given columns, widths, and formatting."""
        box = self.box
        fmt = self.fmt

        if fmt_keys is None:
            fmt_keys = [''] * len(columns)

        row_parts = []
        for i, (col, width) in enumerate(zip(columns, widths)):
            fmt_key = fmt_keys[i] if i < len(fmt_keys) else ''
            color_fmt = fmt.get(fmt_key, '')

            if isinstance(col, int) or (isinstance(col, str) and col.isdigit()):
                col_str = f"{color_fmt}{col:>{width}}{fmt['END']}"
            else:
                col_str = f"{color_fmt}{col:<{width}}{fmt['END']}"

            row_parts.append(col_str)

        row_str = " │ ".join(row_parts)
        print(f"{indent}{box['V']} {row_str} {box['V']}")

    def print_table_header(self, headers: List[str], widths: List[int], indent: str = "  ",
                           width: Optional[int] = None) -> None:
        """Print a table header with the given headers and column widths."""
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"{indent}{fmt['BOLD']}{box['TL']}{box['H'] * (width - 2)}{box['TR']}{fmt['END']}")

        self.print_table_row(headers, widths, indent, ['BOLD'] * len(headers))

        divider = box['H'] * (width - 2)
        print(f"{indent}{fmt['BOLD']}{box['VR']}{divider}{box['VL']}{fmt['END']}")

    def print_stats_box(self, title: str, stats: Dict[str, Any], width: Optional[int] = None,
                        indent: str = "  ", columns: int = 1) -> None:
        """Print a statistics box with the given title and statistics."""
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * (width - 2)}{box['TR']}{fmt['END']}")

        title_padding = (width - len(title) - 4) // 2
        print(
            f"{indent}{fmt['BOLD']}{box['V']}{' ' * title_padding} {title} {' ' * title_padding}{box['V']}{fmt['END']}")

        print(f"{indent}{fmt['BOLD']}{box['VR']}{box['H'] * (width - 2)}{box['VL']}{fmt['END']}")

        col_width = (width - 2 - (columns + 1) * 2) // columns

        stats_items = list(stats.items())
        rows = (len(stats_items) + columns - 1) // columns

        for row in range(rows):
            row_str = []
            for col in range(columns):
                idx = row + col * rows
                if idx < len(stats_items):
                    key, value = stats_items[idx]

                    if isinstance(value, bool):
                        formatted_value = f"{fmt['GREEN']}{box['CHECK']}{fmt['END']}" if value else f"{fmt['RED']}{box['X_MARK']}{fmt['END']}"
                    elif isinstance(value, int):
                        formatted_value = self.format_count(value)
                    elif isinstance(value, float):
                        formatted_value = f"{value:.2f}"
                    elif isinstance(value, str):
                        formatted_value = value
                    else:
                        formatted_value = str(value)

                    item_str = f"{fmt['BOLD']}{key}:{fmt['END']} {formatted_value}"
                    row_str.append(item_str.ljust(col_width))
                else:
                    row_str.append("".ljust(col_width))

            print(f"{indent}{box['V']} {' | '.join(row_str)} {box['V']}")

        print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * (width - 2)}{box['BR']}{fmt['END']}")


class ReportService:
    """Enhanced service for generating and displaying reports with configurable formatting."""

    def __init__(self, config: Optional[ReportConfig] = None) -> None:
        self.config = config or ReportConfig()
        self.report_filename = "scan_report.json"
        self.report_output_dir = "reports"
        self.formatter = ReportFormatter(self.config)
        self.cache = {}

        os.makedirs(self.report_output_dir, exist_ok=True)

    def write_json_report(self, data: List[Dict[str, Any]], filename: Optional[str] = None) -> bool:
        """Write the report data to a JSON file."""
        report_file = filename or os.path.join(self.report_output_dir, self.report_filename)

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

            logger.info(f"Report saved to '{report_file}' ({len(data)} items)")
            return True

        except IOError as e:
            logger.error(f"Could not write report to '{report_file}': {e}")
            return False

    def _player_to_dict(self, player: Player) -> Dict[str, Any]:
        """Convert a Player object to a dictionary for reporting."""
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

        timestamp = datetime.now().isoformat()

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
            "complaint_links": getattr(player, 'complaint_links', []),
            "timestamp": timestamp,
            "scan_version": "2.0"
        }

    def _determine_owner(self, primary_nickname: str, nicknames: List[str], shared_with: List[str]) -> str:
        """Determine the owner of a resource (IP or HWID)."""
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
        """Generate a report from message scan results."""
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
                "results": players_data,
                "scan_version": "2.0"
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
        """Generate a report from a nickname search."""
        report_data = []

        player_info = {
            "type": "player_info",
            "nickname": nickname,
            "status": player.status,
            "ban_counts": player.ban_counts,
            "ban_reasons": getattr(player, 'ban_reasons', []),
            "hwid_erased": getattr(player, 'hwid_erased', False),
            "timestamp": datetime.now().isoformat(),
            "scan_version": "2.0"
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
        """Generate IP data for a player."""
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
        """Generate HWID data for a player."""
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
        """Categorize associated nicknames for a player."""
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
        """Print connection paths between accounts."""
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
                        "path": f"{nickname} {box['ARROW']} {hwid} {box['ARROW']} {nick}"
                    }

        for ip in primary_ips:
            shared_with = player.associated_ips.get(ip, [])
            for nick in shared_with:
                if nick != nickname and nick in nicknames_set and nick not in direct_connections:
                    direct_connections[nick] = {
                        "type": "ip",
                        "identifier": ip,
                        "confidence": "Medium",
                        "path": f"{nickname} {box['ARROW']} {ip} {box['ARROW']} {nick}"
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

        width = self.config.box_width_medium

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(
            f"  {fmt['BOLD']}{box['DOUBLE_V']} {fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}CONNECTION EVIDENCE:{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * width}{box['DOUBLE_VL']}{fmt['END']}")

        total_connections = len(direct_connections) + len(indirect_connections)
        high_confidence = sum(1 for info in direct_connections.values() if info["confidence"] == "High")
        medium_confidence = sum(1 for info in direct_connections.values() if info["confidence"] == "Medium") + \
                            sum(1 for info in indirect_connections.values() if info["confidence"] == "Medium")
        low_confidence = sum(1 for info in indirect_connections.values() if info["confidence"] == "Low")

        print(f"  {box['DOUBLE_V']} {fmt['BOLD']}Overview:{fmt['END']} {total_connections} connected accounts detected")
        print(f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['RED']}{high_confidence} high confidence{fmt['END']} | "
              f"{fmt['YELLOW']}{medium_confidence} medium confidence{fmt['END']} | "
              f"{fmt['GREEN']}{low_confidence} low confidence{fmt['END']}")
        print(f"  {box['DOUBLE_V']}")

        if direct_connections:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['RED']}■ DIRECT CONNECTIONS ({len(direct_connections)}):{fmt['END']}")

            hwid_direct = [(nick, info) for nick, info in direct_connections.items() if info["type"] == "hwid"]
            ip_direct = [(nick, info) for nick, info in direct_connections.items() if info["type"] == "ip"]

            if hwid_direct:
                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}HWID-linked accounts:{fmt['END']}")

                by_hwid = defaultdict(list)
                for nick, info in hwid_direct:
                    hwid = info["identifier"]
                    by_hwid[hwid].append(nick)

                for hwid, nicks in by_hwid.items():
                    print(
                        f"  {box['DOUBLE_V']}     {box['BULLET']} {self.formatter.format_hwid(hwid)}: {', '.join(nicks)}")
                    print(f"  {box['DOUBLE_V']}       {fmt['RED']}High confidence{fmt['END']} (direct HWID sharing)")

                if ip_direct:
                    print(f"  {box['DOUBLE_V']}")

            if ip_direct:
                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}IP-linked accounts:{fmt['END']}")

                by_ip = defaultdict(list)
                for nick, info in ip_direct:
                    ip = info["identifier"]
                    by_ip[ip].append(nick)

                for ip, nicks in by_ip.items():
                    print(f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']}: {', '.join(nicks)}")
                    print(f"  {box['DOUBLE_V']}       {fmt['YELLOW']}Medium confidence{fmt['END']} (direct IP sharing)")

            if indirect_connections:
                print(f"  {box['DOUBLE_V']}")

        if indirect_connections:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ INDIRECT CONNECTIONS ({len(indirect_connections)}):{fmt['END']}")

            for via_nick, connections in indirect_by_via.items():
                if connections["hwid"] or connections["ip"]:
                    print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}Through {via_nick}:{fmt['END']}")

                if connections["hwid"]:
                    by_hwid = defaultdict(list)
                    for conn in connections["hwid"]:
                        hwid = conn["identifier"]
                        by_hwid[hwid].append(conn["nick"])

                    for hwid, nicks in by_hwid.items():
                        print(
                            f"  {box['DOUBLE_V']}     {box['BULLET']} HWID {self.formatter.format_hwid(hwid)}: {', '.join(nicks)}")
                        print(
                            f"  {box['DOUBLE_V']}       {fmt['YELLOW']}Medium confidence{fmt['END']} | Path: {nickname} {box['ARROW']} {via_nick} {box['ARROW']} [accounts]")

                if connections["ip"]:
                    by_ip = defaultdict(list)
                    for conn in connections["ip"]:
                        ip = conn["identifier"]
                        by_ip[ip].append(conn["nick"])

                    for ip, nicks in by_ip.items():
                        print(
                            f"  {box['DOUBLE_V']}     {box['BULLET']} IP {fmt['CYAN']}{ip}{fmt['END']}: {', '.join(nicks)}")
                        print(
                            f"  {box['DOUBLE_V']}       {fmt['GREEN']}Low confidence{fmt['END']} | Path: {nickname} {box['ARROW']} {via_nick} {box['ARROW']} [accounts]")

                print(f"  {box['DOUBLE_V']}")

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def _print_nickname_search_results(self, nickname: str, player: Player) -> None:
        """Print nickname search results."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_large
        status_str = self.formatter.format_status(player.status, getattr(player, 'hwid_erased', False))

        self.formatter.print_header(f"SCAN RESULTS FOR: {nickname}", width)

        print(f"  {fmt['BOLD']}STATUS:{fmt['END']} {status_str} | {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")

        if hasattr(player, 'ban_reasons') and player.ban_reasons:
            self._print_ban_reasons(player)

        if len(player.nicknames) > 1:
            self._print_associated_nicknames_section(player, nickname)

        self._print_connection_paths_section(player, nickname)

        self._print_complaints_section(player, nickname)

        self._print_ip_section(player, nickname)

        self._print_hwid_section(player, nickname)

        self._print_denied_logins_section(player, nickname)

    def _print_associated_nicknames_section(self, player: Player, nickname: str) -> None:
        """Print associated nicknames section."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_V']} ASSOCIATED NICKNAMES:{fmt['END']}")

        categorized_nicks = self._categorize_associated_nicknames(player, nickname)
        has_categories = False

        if categorized_nicks["confirmed_alts"]["accounts"]:
            has_categories = True
            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['RED']}■ CONFIRMED ALTS:{fmt['END']}")

            confirmed_alts = sorted(list(categorized_nicks['confirmed_alts']['accounts']))
            if confirmed_alts:
                print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}Accounts:{fmt['END']} {', '.join(confirmed_alts)}")

            if categorized_nicks["confirmed_alts"]["direct_hwid"]:
                hwid_count = len(categorized_nicks["confirmed_alts"]["direct_hwid"])
                print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}Directly shared HWIDs:{fmt['END']} {hwid_count}")

                for hwid, connected_alts in categorized_nicks["confirmed_alts"]["direct_hwid"].items():
                    print(
                        f"  {box['DOUBLE_V']}       {box['BULLET']} {self.formatter.format_hwid(hwid)}: {', '.join(connected_alts)}")

        if categorized_nicks["alt_to_alt"]["connections"]:
            has_categories = True
            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['YELLOW']}■ ALT-TO-ALT CONNECTIONS:{fmt['END']}")

            hwid_to_accounts = {}
            for hwid in categorized_nicks["alt_to_alt"]["hwids"]:
                if hwid in player.associated_hwids:
                    connected_accounts = [nick for nick in player.associated_hwids[hwid]
                                          if
                                          nick in categorized_nicks["alt_to_alt"]["connections"] and nick != nickname]
                    if connected_accounts:
                        hwid_to_accounts[hwid] = connected_accounts

            total_hwids = len(hwid_to_accounts)
            total_accounts = len(categorized_nicks["alt_to_alt"]["connections"])

            print(
                f"  {box['DOUBLE_V']}     {fmt['BOLD']}Network Summary:{fmt['END']} {total_accounts} accounts connected through {total_hwids} HWIDs")

            alt_connections = sorted(
                categorized_nicks["alt_to_alt"]["connections"].items(),
                key=lambda x: x[1],
                reverse=True
            )

            display_limit = min(10, len(alt_connections))
            top_connected = [alt for alt, _ in alt_connections[:display_limit]]
            remaining = len(alt_connections) - display_limit if len(alt_connections) > display_limit else 0

            print(
                f"  {box['DOUBLE_V']}     {fmt['BOLD']}Connected Alt Accounts:{fmt['END']} {', '.join(top_connected)}")
            if remaining > 0:
                print(f"  {box['DOUBLE_V']}       (and {remaining} more accounts)")

            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}HWID Connections:{fmt['END']}")

            sorted_hwids = sorted(hwid_to_accounts.items(), key=lambda x: len(x[1]), reverse=True)

            display_hwids = self.config.display_limit_medium if self.config.detail_level >= 2 else min(5,
                                                                                                       len(sorted_hwids))

            for i, (hwid, accounts) in enumerate(sorted_hwids[:display_hwids], 1):
                formatted_hwid = self.formatter.format_hwid(hwid)
                print(f"  {box['DOUBLE_V']}       {i}. {formatted_hwid}")
                print(
                    f"  {box['DOUBLE_V']}          {fmt['BOLD']}Connected accounts:{fmt['END']} {', '.join(accounts)}")

                if hasattr(player, 'hwid_sources') and hwid in getattr(player, 'hwid_sources', {}):
                    source_info = player.hwid_sources[hwid]
                    print(f"  {box['DOUBLE_V']}          {fmt['BOLD']}Origin:{fmt['END']} {source_info}")

                if i < display_hwids and i < len(sorted_hwids):
                    print(f"  {box['DOUBLE_V']}")

            if len(sorted_hwids) > display_hwids:
                print(f"  {box['DOUBLE_V']}       ...and {len(sorted_hwids) - display_hwids} more shared HWIDs")

            print(
                f"  {box['DOUBLE_V']}     {fmt['BOLD']}Note:{fmt['END']} These accounts share HWIDs with each other, but not directly with {nickname}")

        if categorized_nicks["likely_connections"]:
            has_categories = True
            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['YELLOW']}■ LIKELY CONNECTIONS:{fmt['END']}")

            sorted_connections = sorted(
                categorized_nicks["likely_connections"],
                key=lambda x: (x["strength_value"], x["identifiers"]),
                reverse=True
            )

            display_limit = min(self.config.display_limit_medium, len(sorted_connections))

            for i, connection in enumerate(sorted_connections[:display_limit]):
                nick = connection["nickname"]
                strength = connection["strength"]
                identifiers = connection["identifiers"]

                strength_fmt = fmt['YELLOW'] if strength == "Strong" else fmt['CYAN']
                print(
                    f"  {box['DOUBLE_V']}     {box['BULLET']} {nick}: {strength_fmt}{strength}{fmt['END']} ({identifiers} shared identifiers)")

            if len(sorted_connections) > display_limit:
                print(
                    f"  {box['DOUBLE_V']}     {box['BULLET']} ...and {len(sorted_connections) - display_limit} more accounts with likely connections")

        ip_connections = categorized_nicks["possible_connections"]["ip"]
        login_matches = categorized_nicks["possible_connections"]["login"]

        if ip_connections or login_matches:
            has_categories = True
            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['CYAN']}■ POSSIBLE CONNECTIONS:{fmt['END']}")

            if login_matches:
                login_list = sorted(list(login_matches))
                print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}Login Event Matches:{fmt['END']} {', '.join(login_list)}")

            if ip_connections:
                sorted_ip_connections = sorted(ip_connections.items(), key=lambda x: x[1], reverse=True)

                display_limit = min(self.config.display_limit_medium, len(sorted_ip_connections))

                print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}IP Matches ({len(sorted_ip_connections)}):{fmt['END']}")
                for nick, count in sorted_ip_connections[:display_limit]:
                    print(f"  {box['DOUBLE_V']}       {box['BULLET']} {nick} ({count} shared IPs)")

                if len(sorted_ip_connections) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}       {box['BULLET']} ...and {len(sorted_ip_connections) - display_limit} more IP-connected accounts")

        other_nicks = list(categorized_nicks["other"])
        time_based_nicks = list(
            categorized_nicks["time_based"]["recent"] | categorized_nicks["time_based"]["historical"])

        if other_nicks or time_based_nicks:
            has_categories = True
            print(f"  {box['DOUBLE_V']}")

            if time_based_nicks:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}■ TIME-BASED CONNECTIONS:{fmt['END']} {', '.join(sorted(time_based_nicks))}")

            if other_nicks:
                if len(other_nicks) <= self.config.display_limit_medium:
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}■ OTHER ASSOCIATED NICKNAMES:{fmt['END']} {', '.join(sorted(other_nicks))}")
                else:
                    display_limit = min(7, len(other_nicks))
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}■ OTHER ASSOCIATED NICKNAMES ({len(other_nicks)}):{fmt['END']} {', '.join(sorted(other_nicks)[:display_limit])}, and {len(other_nicks) - display_limit} more")

        if not has_categories:
            other_nicks = [nick for nick in player.nicknames if nick != nickname]
            if other_nicks:
                print(f"  {box['DOUBLE_V']}   {', '.join(sorted(other_nicks))}")

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def _print_ban_reasons(self, player: Player, indent: str = "  ") -> None:
        """Print ban reasons for a player."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

        if not hasattr(player, 'ban_reasons') or not player.ban_reasons:
            return

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")
        print(f"{indent}{fmt['BOLD']}{box['V']} {fmt['RED']}BAN REASONS ({len(player.ban_reasons)}):{fmt['END']}")
        print(f"{indent}{fmt['BOLD']}{box['VR']}{box['H'] * width}{box['VL']}{fmt['END']}")

        display_limit = self.config.display_limit_large if self.config.detail_level >= 2 else self.config.display_limit_medium
        display_limit = min(display_limit, len(player.ban_reasons))

        for i, ban_info in enumerate(player.ban_reasons[:display_limit], 1):
            if isinstance(ban_info, dict) and "reason" in ban_info and "username" in ban_info:
                reason = ban_info["reason"]
                username = ban_info["username"]

                print(f"{indent}{box['V']}   {box['TL']}{box['H'] * (width - 6)}{box['TR']}")
                print(
                    f"{indent}{box['V']}   {box['V']} {fmt['BOLD']}{i}.{fmt['END']} {fmt['BOLD']}User:{fmt['END']} {fmt['BLUE']}[{username}]{fmt['END']}")

                print(f"{indent}{box['V']}   {box['V']} {fmt['BOLD']}Reason:{fmt['END']}")

                content_width = width - 12
                if len(reason) > content_width:
                    content_lines = reason.split('\n')
                    for line in content_lines:
                        if len(line) > content_width:
                            chunks = [line[j:j + content_width] for j in range(0, len(line), content_width)]
                            for chunk in chunks:
                                print(f"{indent}{box['V']}   {box['V']}   {chunk}")
                        else:
                            print(f"{indent}{box['V']}   {box['V']}   {line}")
                else:
                    print(f"{indent}{box['V']}   {box['V']}   {reason}")

                print(f"{indent}{box['V']}   {box['BL']}{box['H'] * (width - 6)}{box['BR']}")
            else:
                reason = ban_info if isinstance(ban_info, str) else str(ban_info)

                print(f"{indent}{box['V']}   {box['TL']}{box['H'] * (width - 6)}{box['TR']}")
                print(f"{indent}{box['V']}   {box['V']} {fmt['BOLD']}{i}.{fmt['END']}")

                print(f"{indent}{box['V']}   {box['V']} {fmt['BOLD']}Reason:{fmt['END']}")

                content_width = width - 12
                if len(reason) > content_width:
                    content_lines = reason.split('\n')
                    for line in content_lines:
                        if len(line) > content_width:
                            chunks = [line[j:j + content_width] for j in range(0, len(line), content_width)]
                            for chunk in chunks:
                                print(f"{indent}{box['V']}   {box['V']}   {chunk}")
                        else:
                            print(f"{indent}{box['V']}   {box['V']}   {line}")
                else:
                    print(f"{indent}{box['V']}   {box['V']}   {reason}")

                print(f"{indent}{box['V']}   {box['BL']}{box['H'] * (width - 6)}{box['BR']}")

        if len(player.ban_reasons) > display_limit:
            print(f"{indent}{box['V']}   ... and {len(player.ban_reasons) - display_limit} more ban reasons not shown")

        print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

    def _print_complaints_section(self, player: Player, nickname: str) -> None:
        """Print complaints section for a player."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

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

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_V']} COMPLAINTS ({len(player.complaint_links)}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * width}{box['DOUBLE_VL']}{fmt['END']}")

        direct_limit = self.config.display_limit_large if self.config.detail_level >= 2 else self.config.display_limit_medium

        if direct_complaints:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['GREEN']}■ DIRECT CONNECTIONS ({len(direct_complaints)}):{fmt['END']}")

            display_limit = min(direct_limit, len(direct_complaints))

            for i, complaint in enumerate(direct_complaints[:display_limit], 1):
                link = complaint.get("link", "No link")
                channel = complaint.get("channel", "Unknown channel")
                content = complaint.get("content", "No content available")
                author = complaint.get("author", "Unknown")

                print(f"  {box['DOUBLE_V']}   {box['TL']}{box['H'] * (width - 6)}{box['TR']}")
                print(f"  {box['DOUBLE_V']}   {box['V']} {i}. {fmt['BLUE']}{fmt['UNDERLINE']}{link}{fmt['END']}")
                print(
                    f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Channel:{fmt['END']} {channel} | {fmt['BOLD']}Author:{fmt['END']} {author}")

                if content:
                    print(f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']}")
                    self.formatter.print_wrapped_content(content, indent="          ", line_width=width - 20)
                else:
                    print(f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")

                mentioned_nicks = complaint.get("mentioned_nicknames", [nickname])
                if len(mentioned_nicks) > 1:
                    print(
                        f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Associated with:{fmt['END']} {', '.join(mentioned_nicks)}")

                print(f"  {box['DOUBLE_V']}   {box['BL']}{box['H'] * (width - 6)}{box['BR']}")

            if len(direct_complaints) > display_limit:
                print(
                    f"  {box['DOUBLE_V']}   ... and {len(direct_complaints) - display_limit} more direct complaints not shown")

        if indirect_complaints:
            if direct_complaints:
                print(f"  {box['DOUBLE_V']}")

            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ INDIRECT CONNECTIONS ({len(indirect_complaints)}):{fmt['END']}")

            channels = Counter(complaint.get("channel", "Unknown channel") for complaint in indirect_complaints)

            if channels:
                for channel, count in channels.items():
                    print(f"  {box['DOUBLE_V']}     {box['BULLET']} {channel}: {count} complaints")

            display_limit = min(3, len(indirect_complaints))

            if indirect_complaints:
                links = [complaint.get("link", "No link") for complaint in indirect_complaints[:display_limit]]
                print(f"  {box['DOUBLE_V']}     {box['BULLET']} Sample links: {', '.join(links)}")

                if len(indirect_complaints) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(indirect_complaints) - display_limit} more complaints not shown")

                if self.config.detail_level >= 2 and len(indirect_complaints) > display_limit:
                    print(f"  {box['DOUBLE_V']}")
                    print(f"  {box['DOUBLE_V']}     {fmt['BOLD']}Sample indirect complaints:{fmt['END']}")

                    for i, complaint in enumerate(indirect_complaints[:min(3, len(indirect_complaints))], 1):
                        link = complaint.get("link", "No link")
                        channel = complaint.get("channel", "Unknown channel")
                        content = complaint.get("content", "")

                        if content:
                            content_preview = self.formatter.truncate_text(content, max_length=width - 20)
                            print(f"  {box['DOUBLE_V']}       {i}. {fmt['BLUE']}{link}{fmt['END']} ({channel})")
                            print(f"  {box['DOUBLE_V']}          {content_preview}")
                        else:
                            print(f"  {box['DOUBLE_V']}       {i}. {fmt['BLUE']}{link}{fmt['END']} ({channel})")

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def _print_ip_section(self, player: Player, nickname: str) -> None:
        """Print IP address section for a player."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

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

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_V']} ASSOCIATED IPs ({total_relevant_ips} total):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * width}{box['DOUBLE_VL']}{fmt['END']}")

        primary_display_limit = self.config.display_limit_large if self.config.detail_level >= 2 else 10
        secondary_display_limit = self.config.display_limit_medium if self.config.detail_level >= 1 else 5

        if original_ips:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY IPs ({len(original_ips)}) - Used only by {nickname}:{fmt['END']}")

            display_limit = min(primary_display_limit, len(original_ips))

            if len(original_ips) == 1:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}1.{fmt['END']} {fmt['CYAN']}{original_ips[0]}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
            elif display_limit == 1:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}1.{fmt['END']} {fmt['CYAN']}{original_ips[0]}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(original_ips) - 1} additional IPs used only by {nickname}{fmt['END']}")
            else:
                for i, ip in enumerate(original_ips[:display_limit], 1):
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} - {fmt['GREEN']}Only used by {nickname}{fmt['END']}")

                if len(original_ips) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(original_ips) - display_limit} additional IPs used only by {nickname}{fmt['END']}")

            if shared_ips or alt_shared_ips or multi_user_ips:
                print(f"  {box['DOUBLE_V']}")

        if shared_ips:
            display_limit = min(primary_display_limit, len(shared_ips))
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED IPs ({len(shared_ips)}) - Used by {nickname} and others:{fmt['END']}")

            for i, (ip, users) in enumerate(shared_ips[:display_limit], 1):
                others = [user for user in users if user != nickname]
                others_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                print(f"  {box['DOUBLE_V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")
                print(f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")

                if i < display_limit:
                    print(f"  {box['DOUBLE_V']}")

            if len(shared_ips) > display_limit:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(shared_ips) - display_limit} more shared IPs not shown{fmt['END']}")

            if alt_shared_ips or multi_user_ips:
                print(f"  {box['DOUBLE_V']}")

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

            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT IPs ({len(alt_shared_ips)}):{fmt['END']}")

            if len(alt_shared_ips) > 50:
                alt_ip_counts = {}
                for ip, users in alt_shared_ips:
                    for user in users:
                        if user in nicknames_set:
                            if user not in alt_ip_counts:
                                alt_ip_counts[user] = 0
                            alt_ip_counts[user] += 1

                display_limit = min(secondary_display_limit, len(alt_ip_counts))

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}Summary by alt account:{fmt['END']}")
                for alt, count in sorted(alt_ip_counts.items(), key=lambda x: x[1], reverse=True)[:display_limit]:
                    print(f"  {box['DOUBLE_V']}     {box['BULLET']} {alt}: {self.formatter.format_count(count)} IPs")

                if len(alt_ip_counts) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(alt_ip_counts) - display_limit} more accounts")

                ip_prefixes = {}
                for ip, _ in alt_shared_ips:
                    prefix = '.'.join(ip.split('.')[:2])
                    if prefix not in ip_prefixes:
                        ip_prefixes[prefix] = 0
                    ip_prefixes[prefix] += 1

                display_limit = min(10, len(ip_prefixes))

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}IP range distribution:{fmt['END']}")
                for prefix, count in sorted(ip_prefixes.items(), key=lambda x: x[1], reverse=True)[:display_limit]:
                    print(f"  {box['DOUBLE_V']}     {box['BULLET']} {prefix}.x.x: {count} IPs")

                if len(ip_prefixes) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(ip_prefixes) - display_limit} more IP ranges")

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}Sample IPs ({min(5, len(alt_shared_ips))}):{fmt['END']}")
                for i, (ip, users) in enumerate(alt_shared_ips[:5], 1):
                    alt_owners = [user for user in users if user in nicknames_set]
                    print(
                        f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']} - Used by: {', '.join(alt_owners[:3])}" +
                        (f" and {len(alt_owners) - 3} more" if len(alt_owners) > 3 else ""))
            else:
                display_limit = min(secondary_display_limit, len(multi_alt_ips))

                for i, (ip, alt_owners, others) in enumerate(multi_alt_ips[:display_limit], 1):
                    print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']}")
                    print(
                        f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")

                    if others:
                        others_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)
                        print(f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {others_str}")

                    if i < display_limit and i < len(multi_alt_ips):
                        print(f"  {box['DOUBLE_V']}")

                if len(multi_alt_ips) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(multi_alt_ips) - display_limit} additional shared alt IPs not shown{fmt['END']}")

                if solo_alt_ips:
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(solo_alt_ips)} additional IPs used by single alt accounts{fmt['END']}")

            if multi_user_ips:
                print(f"  {box['DOUBLE_V']}")

        if multi_user_ips:
            display_limit = min(secondary_display_limit, len(multi_user_ips))
            print(f"  {box['DOUBLE_V']} {fmt['BOLD']}■ OTHER SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")

            if len(multi_user_ips) <= display_limit:
                for i, (ip, users) in enumerate(multi_user_ips[:display_limit], 1):
                    users_str = self.formatter.truncate_list(users, limit=self.config.truncate_list_limit)
                    print(
                        f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} - Used by: {users_str}")

                    if i % 5 == 0 and i < len(multi_user_ips):
                        print(f"  {box['DOUBLE_V']}")
            else:
                ip_ranges = defaultdict(list)
                for ip, _ in multi_user_ips:
                    prefix = '.'.join(ip.split('.')[:2])
                    ip_ranges[prefix].append(ip)

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}IP Range Distribution:{fmt['END']}")
                sorted_ranges = sorted(ip_ranges.items(), key=lambda x: len(x[1]), reverse=True)

                for prefix, ips in sorted_ranges[:5]:
                    print(f"  {box['DOUBLE_V']}      {prefix}.x.x: {len(ips)} IPs")

                    for sample_ip in ips[:3]:
                        users = player.associated_ips[sample_ip]
                        users_str = self.formatter.truncate_list(users, limit=3)
                        print(
                            f"  {box['DOUBLE_V']}        - {fmt['CYAN']}{sample_ip}{fmt['END']} (Used by: {users_str})")

                    if len(ips) > 3:
                        print(f"  {box['DOUBLE_V']}        - ... and {len(ips) - 3} more IPs in this range")

                    print(f"  {box['DOUBLE_V']}")

                if len(sorted_ranges) > 5:
                    remaining_ranges = len(sorted_ranges) - 5
                    remaining_ips = sum(len(ips) for prefix, ips in sorted_ranges[5:])
                    print(f"  {box['DOUBLE_V']}      Other {remaining_ranges} ranges: {remaining_ips} IPs")

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def _print_hwid_section(self, player: Player, nickname: str) -> None:
        """Print HWID section for a player."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

        if not hasattr(player, 'associated_hwids') or not player.associated_hwids:
            return

        hwid_count = len(player.associated_hwids)

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_V']} ASSOCIATED HWIDs ({hwid_count}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * width}{box['DOUBLE_VL']}{fmt['END']}")

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

        primary_display_limit = self.config.display_limit_large if self.config.detail_level >= 2 else 5
        secondary_display_limit = self.config.display_limit_medium if self.config.detail_level >= 1 else 3

        if original_hwids:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['GREEN']}■ PRIMARY HWIDs ({len(original_hwids)}) - Used only by {nickname}:{fmt['END']}")

            display_limit = min(primary_display_limit, len(original_hwids))

            if len(original_hwids) <= display_limit:
                for i, (hwid, _) in enumerate(original_hwids, 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(f"  {box['DOUBLE_V']}      {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                    if i < len(original_hwids):
                        print(f"  {box['DOUBLE_V']}")
            else:
                for i, (hwid, _) in enumerate(original_hwids[:3], 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(f"  {box['DOUBLE_V']}      {fmt['GREEN']}Only used by {nickname}{fmt['END']}")
                    if i < 3:
                        print(f"  {box['DOUBLE_V']}")
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(original_hwids) - 3} more HWIDs used only by {nickname}{fmt['END']}")

            if shared_hwids or alt_hwids or other_hwids:
                print(f"  {box['DOUBLE_V']}{box['H'] * width}")

        if shared_hwids:
            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ SHARED HWIDs ({len(shared_hwids)}) - Used by {nickname} and others:{fmt['END']}")

            display_limit = min(primary_display_limit, len(shared_hwids))

            for i, (hwid, shared_with) in enumerate(shared_hwids[:display_limit], 1):
                formatted_hwid = self.formatter.format_hwid(hwid)
                others = [nick for nick in shared_with if nick != nickname]

                print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                print(f"  {box['DOUBLE_V']}      {fmt['GREEN']}Used by {nickname}{fmt['END']}")

                if others:
                    shared_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)
                    shared_str = self.formatter.truncate_text(shared_str, max_length=width - 20)
                    print(f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")

                if i < display_limit and i < len(shared_hwids):
                    print(f"  {box['DOUBLE_V']}")

            if len(shared_hwids) > display_limit:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}+ {len(shared_hwids) - display_limit} more shared HWIDs not shown{fmt['END']}")

            if alt_hwids or other_hwids:
                print(f"  {box['DOUBLE_V']}{box['H'] * width}")

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
                f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}■ ALT ACCOUNT HWIDs ({len(alt_hwids)}) - Used by alts but not by {nickname}:{fmt['END']}")

            if multi_alt_hwids:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}HWIDs shared between multiple accounts ({len(multi_alt_hwids)}):{fmt['END']}")

                display_limit = min(secondary_display_limit, len(multi_alt_hwids))

                for i, (hwid, alt_owners, others) in enumerate(multi_alt_hwids[:display_limit], 1):
                    formatted_hwid = self.formatter.format_hwid(hwid)
                    print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{i}.{fmt['END']} {formatted_hwid}")
                    print(
                        f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Used by alt(s):{fmt['END']} {', '.join(alt_owners)}")

                    if others:
                        shared_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)
                        shared_str = self.formatter.truncate_text(shared_str, max_length=width - 20)
                        print(f"  {box['DOUBLE_V']}      {fmt['YELLOW']}Also used by:{fmt['END']} {shared_str}")

                    if i < display_limit and i < len(multi_alt_hwids):
                        print(f"  {box['DOUBLE_V']}")

                    if i >= 10 and len(multi_alt_hwids) > 10:
                        print(
                            f"  {box['DOUBLE_V']}      {fmt['BOLD']}+ {len(multi_alt_hwids) - 10} more shared HWIDs{fmt['END']}")
                        break

                print(f"  {box['DOUBLE_V']}")

            if multi_hwid_alts:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}Alts with multiple HWIDs ({len(multi_hwid_alts)}):{fmt['END']}")

                display_limit = min(secondary_display_limit, len(sorted_alts))

                for i, (alt, count) in enumerate(sorted_alts[:display_limit], 1):
                    if count > 1:
                        print(
                            f"  {box['DOUBLE_V']}      {box['BULLET']} {alt}: {self.formatter.format_count(count)} HWIDs")

                if len(multi_hwid_alts) > display_limit:
                    print(
                        f"  {box['DOUBLE_V']}      {box['BULLET']} ...and {len(multi_hwid_alts) - display_limit} more alts with multiple HWIDs")

                print(f"  {box['DOUBLE_V']}")

            if single_hwid_alts:
                print(
                    f"  {box['DOUBLE_V']}   {fmt['BOLD']}Alts with single HWID ({len(single_hwid_alts)}):{fmt['END']}")

                v2_hwids = 0
                legacy_hwids = 0

                for alt in single_hwid_alts:
                    hwid = single_alt_hwids[alt][0]
                    if hwid.startswith("V2-"):
                        v2_hwids += 1
                    else:
                        legacy_hwids += 1

                print(f"  {box['DOUBLE_V']}      {box['BULLET']} {v2_hwids} V2 HWIDs, {legacy_hwids} legacy HWIDs")

                if single_hwid_alts:
                    display_limit = min(5, len(single_hwid_alts))
                    print(
                        f"  {box['DOUBLE_V']}      {box['BULLET']} Sample: {', '.join(single_hwid_alts[:display_limit])}" +
                        (f", and {len(single_hwid_alts) - display_limit} more" if len(
                            single_hwid_alts) > display_limit else ""))

                print(f"  {box['DOUBLE_V']}")

            if other_hwids:
                print(f"  {box['DOUBLE_V']}{box['H'] * width}")

        if other_hwids:
            other_users = defaultdict(int)
            for hwid, shared_with in other_hwids:
                for user in shared_with:
                    other_users[user] += 1

            top_other_users = sorted(other_users.items(), key=lambda x: x[1], reverse=True)

            print(
                f"  {box['DOUBLE_V']} {fmt['BOLD']}■ OTHER HWIDs ({len(other_hwids)}) - Not associated with {nickname} or alts:{fmt['END']}")

            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}Summary:{fmt['END']}")
            print(f"  {box['DOUBLE_V']}      {box['BULLET']} Total unique users: {len(other_users)}")

            if top_other_users:
                display_limit = min(5, len(top_other_users))
                print(f"  {box['DOUBLE_V']}      {box['BULLET']} Top users by HWID count:")
                for user, count in top_other_users[:display_limit]:
                    print(f"  {box['DOUBLE_V']}        - {user}: {self.formatter.format_count(count)} HWIDs")

                if len(top_other_users) > display_limit:
                    print(f"  {box['DOUBLE_V']}        - ...and {len(top_other_users) - display_limit} more users")

            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}Sample HWIDs:{fmt['END']}")

            display_limit = min(3, len(other_hwids))

            for i, (hwid, shared_with) in enumerate(other_hwids[:display_limit], 1):
                formatted_hwid = self.formatter.format_hwid(hwid)
                users_str = self.formatter.truncate_list(shared_with, limit=self.config.truncate_list_limit)
                users_str = self.formatter.truncate_text(users_str, max_length=width - 20)

                print(f"  {box['DOUBLE_V']}      {i}. {formatted_hwid}")
                print(f"  {box['DOUBLE_V']}         Used by: {users_str}")

                if i < display_limit:
                    print(f"  {box['DOUBLE_V']}")

            if len(other_hwids) > display_limit:
                print(f"  {box['DOUBLE_V']}      ...and {len(other_hwids) - display_limit} more HWIDs")

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def _print_denied_logins_section(self, player: Player, nickname: str) -> None:
        """Print denied logins section for a player."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_medium

        if not hasattr(player, 'denied_logins') or not player.denied_logins:
            return

        login_count = len(player.denied_logins)

        print(f"\n  {fmt['BOLD']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * width}{box['DOUBLE_TR']}{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_V']} {fmt['RED']}DENIED LOGIN ATTEMPTS ({login_count}):{fmt['END']}")
        print(f"  {fmt['BOLD']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * width}{box['DOUBLE_VL']}{fmt['END']}")

        display_limit = self.config.display_limit_large if self.config.detail_level >= 2 else min(5, login_count)
        display_limit = min(display_limit, login_count)

        recent_logins = []
        older_logins = []

        recent_threshold = datetime.now() - timedelta(days=30)

        for login in player.denied_logins:
            try:
                time_str = login.get("time", "")
                if time_str:
                    login_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    if login_time > recent_threshold:
                        recent_logins.append(login)
                    else:
                        older_logins.append(login)
                else:
                    older_logins.append(login)
            except Exception:
                older_logins.append(login)

        if recent_logins:
            print(f"  {box['DOUBLE_V']} {fmt['BOLD']}Recent login attempts (last 30 days):{fmt['END']}")

            recent_display_limit = min(display_limit, len(recent_logins))

            for i, login in enumerate(recent_logins[:recent_display_limit], 1):
                time_str = login.get("time", "N/A")
                ip = login.get("ip_address", "N/A")
                server = login.get("server", "N/A")
                user_name = login.get("user_name", nickname)

                print(
                    f"  {box['DOUBLE_V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

                if user_name != nickname:
                    print(
                        f"  {box['DOUBLE_V']}      {fmt['BOLD']}Attempted with name:{fmt['END']} {fmt['YELLOW']}{user_name}{fmt['END']}")

                if i < recent_display_limit:
                    print(f"  {box['DOUBLE_V']}")

            if len(recent_logins) > recent_display_limit:
                print(
                    f"  {box['DOUBLE_V']}   ... and {len(recent_logins) - recent_display_limit} more recent login attempts")

            if older_logins and self.config.detail_level >= 1 and display_limit > recent_display_limit:
                print(f"  {box['DOUBLE_V']}")
                print(f"  {box['DOUBLE_V']} {fmt['BOLD']}Older login attempts:{fmt['END']}")

                older_display_limit = min(display_limit - recent_display_limit, len(older_logins))

                for i, login in enumerate(older_logins[:older_display_limit], 1):
                    time_str = login.get("time", "N/A")
                    ip = login.get("ip_address", "N/A")
                    server = login.get("server", "N/A")
                    user_name = login.get("user_name", nickname)

                    print(
                        f"  {box['DOUBLE_V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

                    if user_name != nickname:
                        print(
                            f"  {box['DOUBLE_V']}      {fmt['BOLD']}Attempted with name:{fmt['END']} {fmt['YELLOW']}{user_name}{fmt['END']}")

                if len(older_logins) > older_display_limit:
                    print(
                        f"  {box['DOUBLE_V']}   ... and {len(older_logins) - older_display_limit} more older login attempts")
        else:
            for i, login in enumerate(player.denied_logins[:display_limit], 1):
                time_str = login.get("time", "N/A")
                ip = login.get("ip_address", "N/A")
                server = login.get("server", "N/A")
                user_name = login.get("user_name", nickname)

                print(
                    f"  {box['DOUBLE_V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

                if user_name != nickname:
                    print(
                        f"  {box['DOUBLE_V']}      {fmt['BOLD']}Attempted with name:{fmt['END']} {fmt['YELLOW']}{user_name}{fmt['END']}")

            if len(player.denied_logins) > display_limit:
                print(f"  {box['DOUBLE_V']}   ... and {len(player.denied_logins) - display_limit} more login attempts")

        if login_count > display_limit and self.config.detail_level >= 1:
            unique_ips = set(login.get("ip_address", "N/A") for login in player.denied_logins)
            unique_servers = set(login.get("server", "N/A") for login in player.denied_logins)
            unique_usernames = set(login.get("user_name", nickname) for login in player.denied_logins)

            print(f"  {box['DOUBLE_V']}")
            print(f"  {box['DOUBLE_V']} {fmt['BOLD']}Summary:{fmt['END']}")
            print(
                f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['BOLD']}Total denied logins:{fmt['END']} {fmt['RED']}{login_count}{fmt['END']}")
            print(f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['BOLD']}Unique IPs:{fmt['END']} {len(unique_ips)}")
            print(
                f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['BOLD']}Unique servers:{fmt['END']} {len(unique_servers)}")

            if len(unique_usernames) > 1:
                print(
                    f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['BOLD']}Unique usernames:{fmt['END']} {len(unique_usernames)}")

                other_names = [name for name in unique_usernames if name != nickname]
                if other_names:
                    display_limit = min(5, len(other_names))
                    print(
                        f"  {box['DOUBLE_V']}   {box['BULLET']} {fmt['BOLD']}Attempted with names:{fmt['END']} {', '.join(other_names[:display_limit])}" +
                        (f", and {len(other_names) - display_limit} more" if len(other_names) > display_limit else ""))

        print(f"  {fmt['BOLD']}{box['DOUBLE_BL']}{box['DOUBLE_H'] * width}{box['DOUBLE_BR']}{fmt['END']}")

    def print_message_scan_results(self, scan_results: List[ScanResult]) -> None:
        """Print scan results from message scans."""
        fmt = self.formatter.fmt
        box = self.formatter.box
        width = self.config.box_width_large

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

        self.formatter.print_header(f"SCAN RESULTS - {len(scan_results)} messages processed", width)

        for result_idx, result in enumerate(scan_results):
            message = result.message
            players = result.players
            real_players = [p for p in players if getattr(p, 'primary_nickname', '') != "Unknown"]

            total_players += len(real_players)

            self.formatter.print_section(f"MESSAGE: {fmt['BLUE']}{message.link}{fmt['END']}", width)
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

                player_width = self.config.box_width_medium - 10
                self.formatter.print_player_header(player.primary_nickname, width=player_width)

                print(
                    f"  {box['DOUBLE_V']} {fmt['BOLD']}STATUS:{fmt['END']} {status_str}{hwid_erased} {box['DOUBLE_V']} {fmt['BOLD']}BANS:{fmt['END']} {player.ban_counts}")

                if hasattr(player, 'ban_reasons') and player.ban_reasons:
                    print(f"  {box['DOUBLE_V']} ", end="")
                    self._print_ban_reasons(player, indent=f"  {box['DOUBLE_V']} ")

                if len(player.nicknames) > 1:
                    alt_nicks = [n for n in player.nicknames if n != player.primary_nickname]
                    if alt_nicks:
                        if len(alt_nicks) <= self.config.truncate_list_limit:
                            alt_names_text = f"{fmt['BOLD']}ALT NAMES:{fmt['END']} {', '.join(alt_nicks)}"
                        else:
                            alt_names_text = (
                                    f"{fmt['BOLD']}ALT NAMES:{fmt['END']} {', '.join(alt_nicks[:self.config.truncate_list_limit])}" +
                                    f", and {len(alt_nicks) - self.config.truncate_list_limit} more")
                        print(f"  {box['DOUBLE_V']} {alt_names_text}")

                if hasattr(player, 'complaint_links') and player.complaint_links:
                    total_complaints += len(player.complaint_links)

                    complaint_limit = self.config.display_limit_medium if self.config.detail_level >= 1 else min(3,
                                                                                                                 len(player.complaint_links))

                    self.formatter.print_section_header("COMPLAINTS", width=player_width)
                    print(
                        f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['YELLOW']}FOUND ({len(player.complaint_links)}):{fmt['END']}")

                    for i, complaint in enumerate(player.complaint_links[:complaint_limit], 1):
                        link = complaint.get("link", "No link")
                        channel = complaint.get("channel", "Unknown channel")
                        content = complaint.get("content", "No content available")

                        print(f"  {box['DOUBLE_V']}   {box['TL']}{box['H'] * (player_width - 10)}{box['TR']}")
                        print(
                            f"  {box['DOUBLE_V']}   {box['V']} {i}. {fmt['BLUE']}{fmt['UNDERLINE']}{link}{fmt['END']}")
                        print(f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Channel:{fmt['END']} {channel}")

                        if content:
                            print(f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']}")

                            content_width = player_width - 22
                            content_lines = content.split('\n')
                            for line_idx, line in enumerate(content_lines):
                                if len(line) > content_width:
                                    chunks = [line[i:i + content_width] for i in range(0, len(line), content_width)]
                                    for chunk in chunks:
                                        print(f"  {box['DOUBLE_V']}   {box['V']}          {chunk}")
                                else:
                                    print(f"  {box['DOUBLE_V']}   {box['V']}          {line}")
                        else:
                            print(
                                f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Content:{fmt['END']} No content available")

                        mentioned_nicks = complaint.get("mentioned_nicknames", [player.primary_nickname])
                        if len(mentioned_nicks) > 1:
                            print(
                                f"  {box['DOUBLE_V']}   {box['V']} {fmt['BOLD']}Associated with:{fmt['END']} {', '.join(mentioned_nicks)}")

                        print(f"  {box['DOUBLE_V']}   {box['BL']}{box['H'] * (player_width - 10)}{box['BR']}")

                    if len(player.complaint_links) > complaint_limit:
                        print(
                            f"  {box['DOUBLE_V']}   ... and {len(player.complaint_links) - complaint_limit} more complaints not shown")

                has_indirect = False
                if (hasattr(player, 'associated_ips') and player.associated_ips or
                        hasattr(player, 'associated_hwids') and player.associated_hwids or
                        hasattr(player, 'denied_logins') and player.denied_logins):
                    self.formatter.print_section_header("CONNECTION INFORMATION", width=player_width)
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
                        print(f"  {box['DOUBLE_V']} {fmt['BOLD']}SHARED IPs ({len(multi_user_ips)}):{fmt['END']}")

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

                        owned_limit = min(5, len(owned_ips))
                        alt_limit = min(3, len(alt_ips))
                        other_limit = min(2, len(other_ips))

                        if owned_ips:
                            print(
                                f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['GREEN']}■ Owned by {player.primary_nickname}:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(owned_ips[:owned_limit]):
                                unique_ips.add(ip)
                                others = [nick for nick in shared_with if nick != player.primary_nickname]

                                if others:
                                    shared_str = self.formatter.truncate_list(others,
                                                                              limit=self.config.truncate_list_limit)
                                    print(
                                        f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                                else:
                                    print(f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']}")

                            if len(owned_ips) > owned_limit:
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(owned_ips) - owned_limit} more owned IPs")

                            print(f"  {box['DOUBLE_V']}")

                        if alt_ips:
                            print(
                                f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(alt_ips[:alt_limit]):
                                unique_ips.add(ip)
                                alt_owners = [nick for nick in shared_with if nick in nicknames_set]
                                others = [nick for nick in shared_with if nick not in nicknames_set]

                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")

                                if others:
                                    shared_str = self.formatter.truncate_list(others,
                                                                              limit=self.config.truncate_list_limit)
                                    print(
                                        f"  {box['DOUBLE_V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")

                            if len(alt_ips) > alt_limit:
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(alt_ips) - alt_limit} more alt-owned IPs")

                            print(f"  {box['DOUBLE_V']}")

                        if other_ips:
                            print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}■ Other associated IPs:{fmt['END']}")
                            for i, (ip, shared_with) in enumerate(other_ips[:other_limit]):
                                unique_ips.add(ip)
                                users_str = self.formatter.truncate_list(shared_with,
                                                                         limit=self.config.truncate_list_limit)
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} {fmt['CYAN']}{ip}{fmt['END']} - {fmt['BOLD']}Users:{fmt['END']} {users_str}")

                            if len(other_ips) > other_limit:
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(other_ips) - other_limit} more IPs")

                            print(f"  {box['DOUBLE_V']}")

                    if single_user_count > 0:
                        print(
                            f"  {box['DOUBLE_V']} {fmt['BOLD']}SINGLE-USER IPs:{fmt['END']} {single_user_count} IPs with only one user")
                        print(f"  {box['DOUBLE_V']}")

                if hasattr(player, 'associated_hwids') and player.associated_hwids:
                    hwid_count = len(player.associated_hwids)
                    total_hwids += hwid_count

                    print(f"  {box['DOUBLE_V']} {fmt['BOLD']}HWIDs ({hwid_count}):{fmt['END']}")

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

                    owned_limit = min(5, len(owned_hwids))
                    alt_limit = min(3, len(alt_hwids))
                    other_limit = min(2, len(other_hwids))

                    if owned_hwids:
                        print(
                            f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['GREEN']}■ Owned by {player.primary_nickname}:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(owned_hwids[:owned_limit]):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            others = [nick for nick in shared_with if nick != player.primary_nickname]

                            if others:
                                shared_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} {formatted_hwid} - {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")
                            else:
                                print(
                                    f"  {box['DOUBLE_V']}     {box['BULLET']} {formatted_hwid} - {fmt['GREEN']}Only user{fmt['END']}")

                        if len(owned_hwids) > owned_limit:
                            print(
                                f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(owned_hwids) - owned_limit} more owned HWIDs")

                        print(f"  {box['DOUBLE_V']}")

                    if alt_hwids:
                        print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}{fmt['YELLOW']}■ Owned by alt accounts:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(alt_hwids[:alt_limit]):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            alt_owners = [nick for nick in shared_with if nick in nicknames_set]
                            others = [nick for nick in shared_with if nick not in nicknames_set]

                            print(
                                f"  {box['DOUBLE_V']}     {box['BULLET']} {formatted_hwid} - {fmt['YELLOW']}Owner(s):{fmt['END']} {', '.join(alt_owners)}")

                            if others:
                                shared_str = self.formatter.truncate_list(others, limit=self.config.truncate_list_limit)
                                print(f"  {box['DOUBLE_V']}       {fmt['YELLOW']}Shared with:{fmt['END']} {shared_str}")

                        if len(alt_hwids) > alt_limit:
                            print(
                                f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(alt_hwids) - alt_limit} more alt-owned HWIDs")

                        print(f"  {box['DOUBLE_V']}")

                    if other_hwids:
                        print(f"  {box['DOUBLE_V']}   {fmt['BOLD']}■ Other associated HWIDs:{fmt['END']}")
                        for i, (hwid, shared_with) in enumerate(other_hwids[:other_limit]):
                            unique_hwids.add(hwid)
                            formatted_hwid = self.formatter.format_hwid(hwid)
                            users_str = self.formatter.truncate_list(shared_with, limit=self.config.truncate_list_limit)

                            print(
                                f"  {box['DOUBLE_V']}     {box['BULLET']} {formatted_hwid} - {fmt['BOLD']}Users:{fmt['END']} {users_str}")

                        if len(other_hwids) > other_limit:
                            print(
                                f"  {box['DOUBLE_V']}     {box['BULLET']} ... and {len(other_hwids) - other_limit} more HWIDs")

                        print(f"  {box['DOUBLE_V']}")

                if hasattr(player, 'denied_logins') and player.denied_logins:
                    login_count = len(player.denied_logins)
                    display_limit = min(3, login_count)

                    print(f"  {box['DOUBLE_V']} {fmt['BOLD']}{fmt['RED']}DENIED LOGINS ({login_count}):{fmt['END']}")

                    for i, login in enumerate(player.denied_logins[:display_limit], 1):
                        time_str = login.get("time", "N/A")
                        ip = login.get("ip_address", "N/A")
                        hwid = login.get("hwid", "N/A")
                        server = login.get("server", "N/A")
                        user_name = login.get("user_name", player.primary_nickname)

                        print(
                            f"  {box['DOUBLE_V']}   {i}. {fmt['BOLD']}Time:{fmt['END']} {time_str} {fmt['BOLD']}IP:{fmt['END']} {fmt['CYAN']}{ip}{fmt['END']} {fmt['BOLD']}Server:{fmt['END']} {server}")

                        if user_name != player.primary_nickname:
                            print(f"  {box['DOUBLE_V']}      {fmt['BOLD']}Used name:{fmt['END']} {user_name}")

                    if len(player.denied_logins) > display_limit:
                        print(f"  {box['DOUBLE_V']}   ... and {len(player.denied_logins) - display_limit} more")

                print(f"  {box['BL']}{box['H'] * player_width}{box['BR']}")

            if result_idx < len(scan_results) - 1:
                print(f"\n{'-' * width}")

        self.formatter.print_header(" SCAN SUMMARY ", width)

        if total_players:
            banned_pct = total_banned / total_players * 100
            suspicious_pct = total_suspicious / total_players * 100
            clean_pct = total_clean / total_players * 100
            unknown_pct = total_unknown / total_players * 100 if total_unknown else 0
        else:
            banned_pct = suspicious_pct = clean_pct = unknown_pct = 0

        summary_width = min(width, self.config.box_width_medium)

        print(f"  {box['V']} {fmt['BOLD']}Messages processed:{fmt['END']} {len(scan_results)}")
        print(f"  {box['V']} {fmt['BOLD']}Players found:{fmt['END']} {total_players}")
        print(f"  {box['V']} {fmt['BOLD']}Status breakdown:{fmt['END']}")

        print(
            f"  {box['V']}    {box['BULLET']} {fmt['RED']}{fmt['BOLD']}Banned:{fmt['END']} {total_banned} ({banned_pct:.1f}% of total)")
        print(
            f"  {box['V']}    {box['BULLET']} {fmt['YELLOW']}{fmt['BOLD']}Suspicious:{fmt['END']} {total_suspicious} ({suspicious_pct:.1f}% of total)")
        print(
            f"  {box['V']}    {box['BULLET']} {fmt['GREEN']}Clean:{fmt['END']} {total_clean} ({clean_pct:.1f}% of total)")

        if total_unknown:
            print(f"  {box['V']}    {box['BULLET']} Unknown: {total_unknown} ({unknown_pct:.1f}% of total)")
        else:
            print(f"  {box['V']}    {box['BULLET']} Unknown: 0")

        print(f"  {box['V']} {fmt['BOLD']}Complaints found:{fmt['END']} {total_complaints}")
        print(f"  {box['V']} {fmt['BOLD']}Unique HWIDs detected:{fmt['END']} {len(unique_hwids)}")
        print(f"  {box['V']} {fmt['BOLD']}Unique IPs detected:{fmt['END']} {len(unique_ips)}")

        if problematic_players:
            print(f"  {box['VR']}{box['H'] * summary_width}{box['VL']}")
            print(f"  {box['V']} {fmt['BOLD']}PROBLEMATIC PLAYERS DETECTED:{fmt['END']}")

            display_limit = min(10 if self.config.detail_level >= 1 else 5, len(problematic_players))

            for nickname, status, bans in problematic_players[:display_limit]:
                status_color = fmt['RED'] if status == "BANNED" else fmt['YELLOW']
                print(f"  {box['V']}   {box['BULLET']} {nickname}: {status_color}{status}{fmt['END']} (Bans: {bans})")

            if len(problematic_players) > display_limit:
                print(
                    f"  {box['V']}   {box['BULLET']} ... and {len(problematic_players) - display_limit} more problematic players")