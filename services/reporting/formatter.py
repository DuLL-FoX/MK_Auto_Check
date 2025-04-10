import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from services.reporting.config import (
    ReportConfig, TERMINAL_FORMATTING, BOX_CHARS,
    SEVERITY_LEVELS, CONFIDENCE_LEVELS, DEFAULT_REPORT_CONFIG,
    LAYOUT_CONFIG
)


class ReportFormatter:

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.fmt = self._setup_terminal_formatting()
        self.box = self._setup_box_chars()
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _setup_terminal_formatting(self) -> Dict[str, str]:
        if sys.stdout.isatty():
            base_fmt = TERMINAL_FORMATTING.copy()

            if self.config.color_intensity >= LAYOUT_CONFIG['COLOR_INTENSITY_THRESHOLD']:
                for color in ['RED', 'GREEN', 'YELLOW', 'BLUE', 'CYAN']:
                    base_fmt[f'{color}_BOLD'] = base_fmt[color] + base_fmt['BOLD']
                    base_fmt[f'{color}_UNDERLINE'] = base_fmt[color] + base_fmt['UNDERLINE']
                    base_fmt[f'{color}_ITALIC'] = base_fmt[color] + base_fmt['ITALIC']

            return base_fmt
        else:
            return {key: '' for key in TERMINAL_FORMATTING}

    def _setup_box_chars(self) -> Dict[str, str]:
        return BOX_CHARS.copy()

    def print_header(self, title: str, width: Optional[int] = None, style: str = 'header'):
        width = width or self.config.box_width_large
        self._print_boxed(title, width, style=style)

        if self.config.show_timestamps:
            timestamp_str = f"Report generated: {self.timestamp}"
            print(f"{self.fmt['GRAY']}{timestamp_str:>{width - LAYOUT_CONFIG['PADDING_SMALL']}}{self.fmt['END']}")

    def print_section(self, title: str, width: Optional[int] = None, style: str = 'section'):
        width = width or self.config.box_width_medium
        self._print_boxed(title, width, style=style)

    def _print_boxed(self, title: str, width: int = 100, style: str = 'header'):
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

        print(f"\n{color_prefix}{box_chars['TL']}{box_chars['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box_chars['TR']}{fmt['END']}")

        padding = (width - len(title) - LAYOUT_CONFIG['PADDING_MEDIUM']) // 2
        right_padding = width - padding - len(title) - LAYOUT_CONFIG['PADDING_MEDIUM']
        print(
            f"{color_prefix}{box_chars['V']}{' ' * padding} {title} {' ' * right_padding}{box_chars['V']}{fmt['END']}")

        print(f"{color_prefix}{box_chars['BL']}{box_chars['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box_chars['BR']}{fmt['END']}")

    def print_player_header(self, name: str, width: Optional[int] = None):
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        player_header = f"PLAYER: {name}"
        print(
            f"\n  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_TL']}{box['DOUBLE_H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['DOUBLE_TR']}{fmt['END']}")

        padding = (width - len(player_header) - LAYOUT_CONFIG['PADDING_MEDIUM']) // 2
        right_padding = width - padding - len(player_header) - LAYOUT_CONFIG['PADDING_MEDIUM']
        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_V']}{' ' * padding} {player_header} {' ' * right_padding}{box['DOUBLE_V']}{fmt['END']}")

        print(
            f"  {fmt['BOLD']}{fmt['CYAN']}{box['DOUBLE_VR']}{box['DOUBLE_H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['DOUBLE_VL']}{fmt['END']}")

    def print_section_header(self, title: str, width: Optional[int] = None, style: str = 'normal'):
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

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['VL']}{fmt['END']}")

        padding = (width - len(title) - LAYOUT_CONFIG['PADDING_MEDIUM']) // 2
        right_padding = width - padding - len(title) - LAYOUT_CONFIG['PADDING_MEDIUM']
        print(
            f"  {fmt['BOLD']}{box['V']}{' ' * padding} {color}{title}{fmt['END']}{fmt['BOLD']} {' ' * right_padding}{box['V']}{fmt['END']}")

        print(f"  {fmt['BOLD']}{box['VR']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['VL']}{fmt['END']}")

    def print_content_box(self, width: Optional[int] = None, indent: str = "  ") -> Callable:
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * width}{box['TR']}{fmt['END']}")

        def end_box():
            print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * width}{box['BR']}{fmt['END']}")

        return end_box

    def print_wrapped_content(self, content: str, indent: str = "", line_width: Optional[int] = None):
        line_width = line_width or self.config.box_width_small - LAYOUT_CONFIG['CONTENT_BOX_WIDTH_REDUCTION']
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
        fmt = self.fmt

        if hwid.startswith("V2-"):
            prefix = f"{fmt['BOLD']}{fmt['CYAN']}V2-{fmt['END']}"
            base = hwid[3:]
            return f"{prefix}{fmt['CYAN']}{base}{fmt['END']}"

        return f"{fmt['CYAN']}{hwid}{fmt['END']}"

    def format_severity(self, severity: str) -> str:
        fmt = self.fmt
        severity = severity.upper()

        if severity in SEVERITY_LEVELS['HIGH']:
            return f"{fmt['RED_BOLD'] if 'RED_BOLD' in fmt else fmt['RED'] + fmt['BOLD']}{severity}{fmt['END']}"
        elif severity in SEVERITY_LEVELS['MEDIUM']:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{severity}{fmt['END']}"
        elif severity in SEVERITY_LEVELS['LOW']:
            return f"{fmt['GREEN']}{severity}{fmt['END']}"
        else:
            return severity

    def format_confidence(self, confidence: str) -> str:
        fmt = self.fmt
        confidence = confidence.upper()

        if confidence in CONFIDENCE_LEVELS['HIGH']:
            return f"{fmt['GREEN_BOLD'] if 'GREEN_BOLD' in fmt else fmt['GREEN'] + fmt['BOLD']}{confidence}{fmt['END']}"
        elif confidence in CONFIDENCE_LEVELS['MEDIUM']:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{confidence}{fmt['END']}"
        elif confidence in CONFIDENCE_LEVELS['LOW']:
            return f"{fmt['RED']}{confidence}{fmt['END']}"
        else:
            return confidence

    def format_count(self, count: int, threshold_medium: int = None, threshold_high: int = None) -> str:
        fmt = self.fmt

        threshold_medium = threshold_medium or DEFAULT_REPORT_CONFIG['COUNT_THRESHOLD_MEDIUM']
        threshold_high = threshold_high or DEFAULT_REPORT_CONFIG['COUNT_THRESHOLD_HIGH']

        if count >= threshold_high:
            return f"{fmt['RED_BOLD'] if 'RED_BOLD' in fmt else fmt['RED'] + fmt['BOLD']}{count}{fmt['END']}"
        elif count >= threshold_medium:
            return f"{fmt['YELLOW_BOLD'] if 'YELLOW_BOLD' in fmt else fmt['YELLOW'] + fmt['BOLD']}{count}{fmt['END']}"
        else:
            return f"{fmt['GREEN']}{count}{fmt['END']}"

    def truncate_list(self, items: List[str], limit: Optional[int] = None, joiner: str = ", ") -> str:
        if not items:
            return ""

        limit = limit or self.config.truncate_list_limit

        if len(items) <= limit:
            return joiner.join(items)

        return joiner.join(items[:limit]) + f", and {len(items) - limit} more"

    def truncate_text(self, text: str, max_length: Optional[int] = None) -> str:
        if not text:
            return ""

        max_length = max_length or self.config.truncate_text_length

        if len(text) > max_length:
            return text[:max_length - 3] + "..."

        return text

    def print_list_items(self, items: List[str], prefix: str = "•", indent: str = "  ",
                         fmt_key: str = 'NORMAL', max_items: Optional[int] = None) -> None:
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
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"{indent}{fmt['BOLD']}{box['TL']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['TR']}{fmt['END']}")

        self.print_table_row(headers, widths, indent, ['BOLD'] * len(headers))

        divider = box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])
        print(f"{indent}{fmt['BOLD']}{box['VR']}{divider}{box['VL']}{fmt['END']}")

    def print_stats_box(self, title: str, stats: Dict[str, Any], width: Optional[int] = None,
                        indent: str = "  ", columns: int = 1) -> None:
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt

        print(f"\n{indent}{fmt['BOLD']}{box['TL']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['TR']}{fmt['END']}")

        title_padding = (width - len(title) - LAYOUT_CONFIG['PADDING_MEDIUM']) // 2
        print(
            f"{indent}{fmt['BOLD']}{box['V']}{' ' * title_padding} {title} {' ' * title_padding}{box['V']}{fmt['END']}")

        print(f"{indent}{fmt['BOLD']}{box['VR']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['VL']}{fmt['END']}")

        col_width = (width - LAYOUT_CONFIG['PADDING_SMALL'] - (columns + 1) * LAYOUT_CONFIG['STAT_BOX_COLUMN_PADDING']) // columns

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

        print(f"{indent}{fmt['BOLD']}{box['BL']}{box['H'] * (width - LAYOUT_CONFIG['PADDING_SMALL'])}{box['BR']}{fmt['END']}")