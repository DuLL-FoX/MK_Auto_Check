import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Tuple

from services.reporting.config import (
    ReportConfig, TERMINAL_FORMATTING, BOX_CHARS,
    SEVERITY_LEVELS, CONFIDENCE_LEVELS, DEFAULT_REPORT_CONFIG,
    LAYOUT_CONFIG
)


class ReportFormatter:

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.fmt = self._setup_terminal_formatting()
        self.box = BOX_CHARS.copy()
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _get_fmt(self, main_key: str, *modifier_keys: str, default: str = '') -> str:
        """
        Safely gets a format code, preferring combined keys if available
        (e.g., RED_BOLD over RED + BOLD).
        """
        main_key_upper = main_key.upper()
        mod_keys_upper = [mk.upper() for mk in modifier_keys]

        if mod_keys_upper:
            combined_key = f"{main_key_upper}_{'_'.join(mod_keys_upper)}"
            if combined_key in self.fmt:
                return self.fmt[combined_key]

        base_color = self.fmt.get(main_key_upper, '')
        modifiers_str = "".join(self.fmt.get(mod_key, '') for mod_key in mod_keys_upper)
        
        if base_color or modifiers_str:
            return base_color + modifiers_str
        return default

    def _setup_terminal_formatting(self) -> Dict[str, str]:
        if sys.stdout.isatty():
            base_fmt = TERMINAL_FORMATTING.copy()
            if self.config.color_intensity >= LAYOUT_CONFIG['COLOR_INTENSITY_THRESHOLD']:
                color_keys_to_combine = [
                    'HEADER', 'BLUE', 'CYAN', 'GREEN', 'YELLOW', 'RED', 'GRAY', 'WHITE',
                    'BRIGHT_BLACK', 'BRIGHT_RED', 'BRIGHT_GREEN', 'BRIGHT_YELLOW',
                    'BRIGHT_BLUE', 'BRIGHT_MAGENTA', 'BRIGHT_CYAN', 'BRIGHT_WHITE'
                ]
                style_modifiers = {
                    'BOLD': base_fmt.get('BOLD', ''),
                    'UNDERLINE': base_fmt.get('UNDERLINE', ''),
                    'ITALIC': base_fmt.get('ITALIC', '')
                }
                for color_key in color_keys_to_combine:
                    if color_key in base_fmt:
                        for style_name, style_code in style_modifiers.items():
                            if style_code:
                                base_fmt[f'{color_key}_{style_name}'] = base_fmt[color_key] + style_code
            return base_fmt
        else:
            return {key: '' for key in TERMINAL_FORMATTING}

    def print_header(self, title: str, width: Optional[int] = None, style: str = 'header'):
        width = width or self.config.box_width_large
        self._print_boxed(title, width, style=style)

        if self.config.show_timestamps:
            timestamp_str = f"Report generated: {self.timestamp}"
            print(f"{self._get_fmt('GRAY')}{timestamp_str:>{width}}{self.fmt['END']}")


    def print_section(self, title: str, width: Optional[int] = None, style: str = 'section'):
        width = width or self.config.box_width_medium
        self._print_boxed(title, width, style=style)

    def _print_boxed(self, title: str, width: int, style: str = 'default'):
        fmt = self.fmt
        box = self.box

        style_definitions = {
            'default':    {'color_keys': ('BOLD',), 'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V'), 'prefix': '', 'suffix': ''},
            'header':     {'color_keys': ('HEADER', 'BOLD'), 'chars': ('DOUBLE_TL', 'DOUBLE_TR', 'DOUBLE_BL', 'DOUBLE_BR', 'DOUBLE_H', 'DOUBLE_V'), 'prefix': '', 'suffix': ''},
            'section':    {'color_keys': ('BRIGHT_CYAN', 'BOLD'), 'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V'), 'prefix': '', 'suffix': ''},
            'subsection': {'color_keys': ('CYAN', 'BOLD'), 'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V'), 'prefix': '', 'suffix': ''},
            'warning':    {'color_keys': ('RED', 'BOLD'), 'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V'), 'prefix': f"{box['WARNING']} ", 'suffix': f" {box['WARNING']}"},
            'success':    {'color_keys': ('GREEN', 'BOLD'), 'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V'), 'prefix': f"{box['CHECK']} ", 'suffix': f" {box['CHECK']}"},
        }

        attrs = style_definitions.get(style, style_definitions['default'])
        
        color_prefix = self._get_fmt(*attrs['color_keys'])
        bc_keys = ('TL', 'TR', 'BL', 'BR', 'H', 'V')
        current_box_chars = {key: box[val_key] for key, val_key in zip(bc_keys, attrs['chars'])}
        
        effective_title = attrs['prefix'] + title + attrs['suffix']
        
        h_bar_len = width - 2 
        if h_bar_len < 0: h_bar_len = 0

        print(f"\n{color_prefix}{current_box_chars['TL']}{current_box_chars['H'] * h_bar_len}{current_box_chars['TR']}{fmt['END']}")

        space_for_title_and_padding = width - 2 
        min_side_padding = LAYOUT_CONFIG['HEADER_MIN_PADDING']
        
        plain_effective_title = attrs['prefix'] + title + attrs['suffix']
        max_title_len = space_for_title_and_padding - (min_side_padding * 2)

        if len(plain_effective_title) > max_title_len and max_title_len > 3:
            title_to_truncate = title
            available_for_title_text = max_title_len - (len(attrs['prefix']) + len(attrs['suffix']))
            if available_for_title_text > 3 :
                title_to_truncate = title[:available_for_title_text-3] + "..."
            else:
                title_to_truncate = title[:available_for_title_text]
            effective_title = attrs['prefix'] + title_to_truncate + attrs['suffix']
            plain_effective_title = attrs['prefix'] + title_to_truncate + attrs['suffix']
        elif len(plain_effective_title) > max_title_len:
            effective_title = plain_effective_title[:max_title_len]
            plain_effective_title = effective_title


        centering_padding_total = space_for_title_and_padding - len(plain_effective_title)
        if centering_padding_total < 0: centering_padding_total = 0
            
        left_centering_pad = centering_padding_total // 2
        right_centering_pad = centering_padding_total - left_centering_pad
        

        padded_title = f"{' ' * left_centering_pad}{effective_title}{' ' * right_centering_pad}"

        print(
            f"{color_prefix}{current_box_chars['V']}{fmt['END']}"
            f"{' ' * left_centering_pad}{color_prefix}{effective_title}{fmt['END']}{' ' * right_centering_pad}"
            f"{color_prefix}{current_box_chars['V']}{fmt['END']}")

        print(f"{color_prefix}{current_box_chars['BL']}{current_box_chars['H'] * h_bar_len}{current_box_chars['BR']}{fmt['END']}")

    def print_player_header(self, name: str, indent_str: str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING'], width: Optional[int] = None):
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt
        color = self._get_fmt('CYAN', 'BOLD')

        player_header_text = f"PLAYER: {name}"
        h_bar_len = width - 2 
        if h_bar_len < 0: h_bar_len = 0
        
        print(f"\n{indent_str}{color}{box['DOUBLE_TL']}{box['DOUBLE_H'] * h_bar_len}{box['DOUBLE_TR']}{fmt['END']}")
        
        space_for_title_and_padding = width - 2
        
        centering_padding_total = space_for_title_and_padding - len(player_header_text)
        if centering_padding_total < 0: centering_padding_total = 0
            
        left_pad_len = centering_padding_total // 2
        right_pad_len = centering_padding_total - left_pad_len

        print(
            f"{indent_str}{color}{box['DOUBLE_V']}{' ' * left_pad_len}"
            f"{player_header_text}{' ' * right_pad_len}{box['DOUBLE_V']}{fmt['END']}")
        print(f"{indent_str}{color}{box['DOUBLE_VR']}{box['DOUBLE_H'] * h_bar_len}{box['DOUBLE_VL']}{fmt['END']}")


    def print_section_header(self, title: str, indent_str: str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING'], width: Optional[int] = None, style: str = 'normal'):
        width = width or self.config.box_width_medium
        box = self.box
        fmt = self.fmt
        outer_color = self._get_fmt('BOLD') 

        style_map = {
            'warning': {'color_keys': ('RED', 'BOLD'), 'icon': box['WARNING']},
            'success': {'color_keys': ('GREEN', 'BOLD'), 'icon': box['CHECK']},
            'info': {'color_keys': ('BLUE', 'BOLD'), 'icon': box['INFO']},
            'important': {'color_keys': ('YELLOW', 'BOLD'), 'icon': box['STAR']},
            'normal': {'color_keys': ('BOLD',), 'icon': ''}, 
        }
        
        current_style = style_map.get(style, style_map['normal'])
        title_color_str = self._get_fmt(*current_style['color_keys'])
        icon_prefix = f"{current_style['icon']} " if current_style['icon'] else ""
        
        plain_title_with_icon = f"{icon_prefix}{title}"
        
        h_bar_len = width - 2
        if h_bar_len < 0: h_bar_len = 0


        print(f"{indent_str}{outer_color}{box['VR']}{box['H'] * h_bar_len}{box['VL']}{fmt['END']}")
        
        space_for_title_and_padding = width - 2
        min_side_padding = LAYOUT_CONFIG['HEADER_MIN_PADDING']
        
        max_plain_title_len = space_for_title_and_padding - (min_side_padding * 2)
        truncated_plain_title_with_icon = plain_title_with_icon
        
        if len(plain_title_with_icon) > max_plain_title_len:
            if max_plain_title_len > 3 + len(icon_prefix):
                 can_truncate_len = max_plain_title_len - len(icon_prefix) - 3
                 truncated_title_part = title[:can_truncate_len] + "..." if can_truncate_len > 0 else "..."
                 truncated_plain_title_with_icon = f"{icon_prefix}{truncated_title_part}"
            elif max_plain_title_len > len(icon_prefix):
                 truncated_plain_title_with_icon = plain_title_with_icon[:max_plain_title_len]
            else:
                 truncated_plain_title_with_icon = icon_prefix[:max_plain_title_len]


        formatted_title_colored = f"{title_color_str}{truncated_plain_title_with_icon}{fmt['END']}"


        centering_padding_total = space_for_title_and_padding - len(truncated_plain_title_with_icon)
        if centering_padding_total < 0: centering_padding_total = 0
            
        left_pad = centering_padding_total // 2
        right_pad = centering_padding_total - left_pad
        
        print(
            f"{indent_str}{outer_color}{box['V']}{fmt['END']}" 
            f"{' ' * left_pad}{formatted_title_colored}{' ' * right_pad}"
            f"{outer_color}{box['V']}{fmt['END']}")

        print(f"{indent_str}{outer_color}{box['VR']}{box['H'] * h_bar_len}{box['VL']}{fmt['END']}")

    def print_content_box_start(self, width: Optional[int] = None, indent_str: str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING']) -> None:
        width = width or self.config.box_width_medium
        box_h_len = width - 2 
        if box_h_len < 0: box_h_len = 0
        print(f"{indent_str}{self._get_fmt('BOLD')}{self.box['TL']}{self.box['H'] * box_h_len}{self.box['TR']}{self.fmt['END']}")

    def print_content_box_end(self, width: Optional[int] = None, indent_str: str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING']) -> None:
        width = width or self.config.box_width_medium
        box_h_len = width - 2
        if box_h_len < 0: box_h_len = 0
        print(f"{indent_str}{self._get_fmt('BOLD')}{self.box['BL']}{self.box['H'] * box_h_len}{self.box['BR']}{self.fmt['END']}")
        
    def get_wrapped_lines(self, text: str, width: int, initial_indent: str = "", subsequent_indent: str = "") -> List[str]:
        lines = []
        if not text: return [""]
        
        for paragraph_idx, paragraph in enumerate(text.splitlines()): 
            if not paragraph.strip() and paragraph_idx > 0 : 
                 lines.append(initial_indent if not lines and paragraph_idx == 0 else subsequent_indent)
                 continue

            current_paragraph_initial_indent = initial_indent if not lines and paragraph_idx == 0 else subsequent_indent
            
            import textwrap 
            
            check_indent = initial_indent if paragraph_idx == 0 and not lines else subsequent_indent
            if len(check_indent + paragraph) <= width :
                 lines.append(check_indent + paragraph)
                 continue

            wrapped_paragraph_lines = textwrap.wrap(
                paragraph, 
                width=max(1, width - len(subsequent_indent)),
                initial_indent="",
                subsequent_indent="",
                replace_whitespace=False, 
                drop_whitespace=True, 
                break_long_words=True,
                break_on_hyphens=True
            )
            
            if not wrapped_paragraph_lines and paragraph:
                lines.append(current_paragraph_initial_indent + paragraph[:max(0, width - len(current_paragraph_initial_indent))])
            else:
                for i, line_content in enumerate(wrapped_paragraph_lines):
                    prefix = current_paragraph_initial_indent if i == 0 else subsequent_indent
                    lines.append(prefix + line_content)
        return lines


    def print_line_in_box(self, text: str, box_v_char: str, indent_str: str, line_padding: int = 1, color_keys: Tuple[str, ...] = ()):
        padding_str = ' ' * line_padding
        line_color = self._get_fmt(*color_keys) if color_keys else ''
        print(f"{indent_str}{box_v_char}{padding_str}{line_color}{text}{self.fmt['END']}")


    def print_key_value_in_box(self, key: str, value: Any, box_v_char: str, indent_str: str,
                               key_width: int = 20, key_color_keys: Tuple[str, ...] = ('BOLD',),
                               value_color_keys: Tuple[str, ...] = (), line_padding: int = 1):
        key_str = f"{self._get_fmt(*key_color_keys)}{key + ':':<{key_width}}{self.fmt['END']}"
        
        if isinstance(value, bool):
            value_str = self.format_boolean(value)
        elif isinstance(value, int): 
            value_str = f"{self._get_fmt(*value_color_keys)}{value}{self.fmt['END']}"
        else:
            value_str = f"{self._get_fmt(*value_color_keys)}{str(value)}{self.fmt['END']}"
            
        self.print_line_in_box(f"{key_str} {value_str}", box_v_char, indent_str, line_padding)

    def format_boolean(self, value: bool) -> str:
        if value:
            return f"{self._get_fmt('GREEN')}{self.box['CHECK']}{self.fmt['END']}"
        else:
            return f"{self._get_fmt('RED')}{self.box['X_MARK']}{self.fmt['END']}"

    def format_status(self, status: str, hwid_erased: bool = False) -> str:
        status_upper = status.upper()
        status_str = status_upper 

        if status_upper == "BANNED":
            status_str = f"{self._get_fmt('RED', 'BOLD')}{status_upper}{self.fmt['END']}"
        elif status_upper == "SUSPICIOUS":
            status_str = f"{self._get_fmt('YELLOW', 'BOLD')}{status_upper}{self.fmt['END']}"
        elif status_upper == "CLEAN":
            status_str = f"{self._get_fmt('GREEN')}{status_upper}{self.fmt['END']}"
        
        if hwid_erased:
            status_str += f" {self._get_fmt('YELLOW')}(HWID ERASED){self.fmt['END']}"
        return status_str

    def format_hwid(self, hwid: str) -> str:
        if not isinstance(hwid, str): hwid = str(hwid)
        if hwid.startswith("V2-"):
            prefix = f"{self._get_fmt('CYAN', 'BOLD')}V2-{self.fmt['END']}"
            base = hwid[3:]
            return f"{prefix}{self._get_fmt('CYAN')}{base}{self.fmt['END']}"
        return f"{self._get_fmt('CYAN')}{hwid}{self.fmt['END']}"

    def format_severity(self, severity: str) -> str:
        severity_upper = severity.upper()
        if severity_upper in SEVERITY_LEVELS['HIGH']:
            return f"{self._get_fmt('RED', 'BOLD')}{severity_upper}{self.fmt['END']}"
        elif severity_upper in SEVERITY_LEVELS['MEDIUM']:
            return f"{self._get_fmt('YELLOW', 'BOLD')}{severity_upper}{self.fmt['END']}"
        elif severity_upper in SEVERITY_LEVELS['LOW']:
            return f"{self._get_fmt('GREEN')}{severity_upper}{self.fmt['END']}"
        return severity_upper

    def format_confidence(self, confidence: str) -> str:
        confidence_upper = confidence.upper()
        if confidence_upper in CONFIDENCE_LEVELS['HIGH']:
            return f"{self._get_fmt('GREEN', 'BOLD')}{confidence_upper}{self.fmt['END']}"
        elif confidence_upper in CONFIDENCE_LEVELS['MEDIUM']:
            return f"{self._get_fmt('YELLOW', 'BOLD')}{confidence_upper}{self.fmt['END']}"
        elif confidence_upper in CONFIDENCE_LEVELS['LOW']:
            return f"{self._get_fmt('RED')}{confidence_upper}{self.fmt['END']}"
        return confidence_upper

    def format_count(self, count: int, threshold_medium: Optional[int] = None, threshold_high: Optional[int] = None) -> str:
        cfg_medium = getattr(self.config, 'count_threshold_medium', DEFAULT_REPORT_CONFIG.get('COUNT_THRESHOLD_MEDIUM', 5))
        cfg_high = getattr(self.config, 'count_threshold_high', DEFAULT_REPORT_CONFIG.get('COUNT_THRESHOLD_HIGH', 20))
        
        threshold_medium = threshold_medium if threshold_medium is not None else cfg_medium
        threshold_high = threshold_high if threshold_high is not None else cfg_high


        if count >= threshold_high:
            return f"{self._get_fmt('RED', 'BOLD')}{count}{self.fmt['END']}"
        elif count >= threshold_medium:
            return f"{self._get_fmt('YELLOW', 'BOLD')}{count}{self.fmt['END']}"
        elif count > 0 :
             return f"{self._get_fmt('GREEN')}{count}{self.fmt['END']}"
        else: 
            return f"{self._get_fmt('GRAY')}{count}{self.fmt['END']}"


    def truncate_list(self, items: List[str], limit: Optional[int] = None, joiner: str = ", ") -> str:
        if not items:
            return self._get_fmt('GRAY') + "None" + self.fmt['END']

        limit = limit or self.config.truncate_list_limit

        if len(items) <= limit:
            return joiner.join(items)
        
        remaining_count = len(items) - limit
        str_items = [str(item) for item in items[:limit]]
        return joiner.join(str_items) + f"{self.fmt['END']}{joiner}{self._get_fmt('GRAY')}and {remaining_count} more...{self.fmt['END']}"


    def truncate_text(self, text: str, max_length: Optional[int] = None) -> str:
        if not text: return ""
        max_length = max_length or self.config.truncate_text_length
        if len(text) > max_length:
            return text[:max_length - 3] + "..."
        return text

    def print_list_items(self, items: List[str],
                         box_v_char: str, 
                         base_indent_str: str, 
                         item_indent_level: int = 1, 
                         prefix_char_key: str = 'BULLET',
                         fmt_key: Optional[str] = None, 
                         max_items: Optional[int] = None) -> None:

        if not items:
            line_indent = LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] * item_indent_level
            self.print_line_in_box(f"{line_indent}{self._get_fmt('GRAY')}None{self.fmt['END']}", box_v_char, base_indent_str)
            return

        bullet = self.box.get(prefix_char_key.upper(), prefix_char_key)
        item_color = self.fmt.get(fmt_key.upper(), '') if fmt_key else ''
        
        effective_max_items = max_items if max_items is not None else self.config.get_dynamic_limit('LARGE') 

        line_indent_str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING'] * item_indent_level

        for i, item_text in enumerate(items[:effective_max_items]):
            line_content = f"{line_indent_str}{bullet} {item_color}{item_text}{self.fmt['END']}"
            self.print_line_in_box(line_content, box_v_char, base_indent_str)

        if len(items) > effective_max_items:
            remaining_count = len(items) - effective_max_items
            line_content = f"{line_indent_str}{bullet} {self._get_fmt('GRAY')}... and {remaining_count} more{self.fmt['END']}"
            self.print_line_in_box(line_content, box_v_char, base_indent_str)

    def print_table_row(self, columns: List[Any], widths: List[int],
                        box_v_char: str, base_indent_str: str,
                        fmt_keys: Optional[List[Optional[Tuple[str, ...]]]] = None) -> None:
        
        if fmt_keys is None:
            fmt_keys_tuples: List[Optional[Tuple[str, ...]]] = [None] * len(columns)
        else:
            fmt_keys_tuples = [(fk,) if isinstance(fk, str) else fk for fk in fmt_keys]


        row_parts = []
        for i, (col_data, width) in enumerate(zip(columns, widths)):
            col_fmt_tuple = fmt_keys_tuples[i] if i < len(fmt_keys_tuples) and fmt_keys_tuples[i] is not None else ()
            color_prefix = self._get_fmt(*col_fmt_tuple)
            
            col_text = str(col_data) 
            if isinstance(col_data, (int, float)) or (isinstance(col_data, str) and col_data.replace('.', '', 1).isdigit()):
                ansi_len = len(color_prefix) + len(self.fmt['END']) if color_prefix else 0
                col_str = f"{color_prefix}{col_text:>{width - ansi_len if width > ansi_len else 0}}{self.fmt['END']}"
            else:
                ansi_len = len(color_prefix) + len(self.fmt['END']) if color_prefix else 0
                col_str = f"{color_prefix}{col_text:<{width - ansi_len if width > ansi_len else 0}}{self.fmt['END']}"
            row_parts.append(col_str)

        divider = f" {self.box['V']} " 
        row_str = divider.join(row_parts)
        self.print_line_in_box(row_str, box_v_char, base_indent_str, line_padding=1)


    def print_table_header(self, headers: List[str], widths: List[int],
                           base_indent_str: str, width: Optional[int] = None) -> None:
        box_width = width or self.config.box_width_medium
        h_bar_len = box_width - 2
        if h_bar_len < 0: h_bar_len = 0
        bold_fmt = self._get_fmt('BOLD')

        print(f"{base_indent_str}{bold_fmt}{self.box['TL']}{self.box['H'] * h_bar_len}{self.box['TR']}{self.fmt['END']}")
        self.print_table_row(headers, widths, self.box['V'], base_indent_str, [('BOLD',)] * len(headers))
        print(f"{base_indent_str}{bold_fmt}{self.box['VR']}{self.box['H'] * h_bar_len}{self.box['VL']}{self.fmt['END']}")


    def print_stats_box(self, title: str, stats: Dict[str, Any], 
                        base_indent_str: str = LAYOUT_CONFIG['DEFAULT_INDENT_STRING'], 
                        width: Optional[int] = None, columns: int = 1) -> None:
        box_width = width or self.config.box_width_medium
        
        style_attrs = { 
            'color_keys': ('CYAN', 'BOLD'), 
            'chars': ('TL', 'TR', 'BL', 'BR', 'H', 'V')
        }
        color_prefix = self._get_fmt(*style_attrs['color_keys'])
        bc_keys = ('TL', 'TR', 'BL', 'BR', 'H', 'V')
        current_box_chars = {key: self.box[val_key] for key, val_key in zip(bc_keys, style_attrs['chars'])}

        h_bar_len = box_width - 2
        if h_bar_len < 0: h_bar_len = 0
        
        print(f"\n{base_indent_str}{color_prefix}{current_box_chars['TL']}{current_box_chars['H'] * h_bar_len}{current_box_chars['TR']}{self.fmt['END']}")

        plain_title = title
        space_for_title_and_padding = box_width - 2
        
        centering_padding_total = space_for_title_and_padding - len(plain_title)
        if centering_padding_total < 0: centering_padding_total = 0
        left_pad = centering_padding_total // 2
        right_pad = centering_padding_total - left_pad
        
        print(
            f"{base_indent_str}{color_prefix}{current_box_chars['V']}{self.fmt['END']}"
            f"{' ' * left_pad}{color_prefix}{title}{self.fmt['END']}{' ' * right_pad}"
            f"{color_prefix}{current_box_chars['V']}{self.fmt['END']}")


        print(f"{base_indent_str}{color_prefix}{self.box['VR']}{current_box_chars['H'] * h_bar_len}{self.box['VL']}{self.fmt['END']}")
        
        content_padding = LAYOUT_CONFIG['STAT_BOX_COLUMN_PADDING'] 
        content_inner_width = box_width - 2 - (content_padding * 2) 
        
        divider_str = f"{self._get_fmt('GRAY')} | {self.fmt['END']}"
        plain_divider_len = len(" | ")
        
        col_width_estimate = content_inner_width
        if columns > 1:
             col_width_estimate = (content_inner_width - ((columns - 1) * plain_divider_len)) // columns
        if col_width_estimate <=0: col_width_estimate = 10

        stats_items = list(stats.items())
        rows = (len(stats_items) + columns - 1) // columns

        for row_idx in range(rows):
            row_str_parts_colored = []
            row_str_parts_plain_len = []

            for col_idx in range(columns):
                item_idx = row_idx + col_idx * rows
                if item_idx < len(stats_items):
                    key, value = stats_items[item_idx]

                    if isinstance(value, bool): formatted_value = self.format_boolean(value)
                    elif isinstance(value, int): formatted_value = self.format_count(value) 
                    elif isinstance(value, float): formatted_value = f"{value:.2f}"
                    else: formatted_value = str(value)
                    
                    item_str_colored = f"{self._get_fmt('BOLD')}{key}:{self.fmt['END']} {formatted_value}"
                    plain_key = key 
                    plain_value = str(value) if not isinstance(value, bool) else ("V" if value else "X")
                    item_str_plain_len = len(plain_key) + 2 + len(plain_value) 

                    row_str_parts_colored.append(item_str_colored)
                    row_str_parts_plain_len.append(item_str_plain_len)
                else:
                    row_str_parts_colored.append("") 
                    row_str_parts_plain_len.append(0)
            
            final_row_str_parts = []
            for i_col in range(columns):
                colored_part = row_str_parts_colored[i_col]
                plain_len = row_str_parts_plain_len[i_col]
                padding_needed = col_width_estimate - plain_len
                if padding_needed < 0: padding_needed = 0
                final_row_str_parts.append(colored_part + ' ' * padding_needed)
            
            full_row_str = divider_str.join(final_row_str_parts)
            self.print_line_in_box(full_row_str, current_box_chars['V'], base_indent_str, line_padding=content_padding)

        print(f"{base_indent_str}{color_prefix}{current_box_chars['BL']}{current_box_chars['H'] * h_bar_len}{current_box_chars['BR']}{self.fmt['END']}")

    def print_horizontal_line(self, width: int, indent_str: str = "", char_key: str = 'H', color_keys: Tuple[str, ...] = ('GRAY',)):
        color = self._get_fmt(*color_keys)
        line_char = self.box.get(char_key.upper(), char_key)
        actual_width = width
        if indent_str: 
             pass

        print(f"{indent_str}{color}{line_char * actual_width}{self.fmt['END']}")