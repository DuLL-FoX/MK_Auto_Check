import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from models.ban_hit import BanBypassCheck
from templates.html_template import HTMLTemplateGenerator
from utils.file_utils import ensure_directory_exists


class HTMLReportService:
    def __init__(self, report_service) -> None:
        self.report_service = report_service
        self.html_report_filename = "ban_bypass_report.html"
        self.static_dir = "static"
        self.css_file = "styles.css"
        self.js_file = "report.js"
        self.template_generator = HTMLTemplateGenerator()
        self.logger = logging.getLogger(__name__)

        self.VERDICT_THRESHOLDS = {
            "HWID Match": ("POTENTIAL BYPASS", "100% (HWID Match)"),
            "IP + Time Match": ("POTENTIAL BYPASS", "20-30% (IP + Time Match)"),
            "Close Time Match": ("POTENTIAL BYPASS", "40-50% (IP + Close Time Match)"),
            "IP Match": ("SUSPICIOUS", "1-10% (IP Match)"),
        }

        self.STATUS_VERDICTS = {
            "banned": "BANNED",
            "clean": "CLEAN",
            "suspicious": "SUSPICIOUS",
            "unknown": "UNKNOWN"
        }

    def generate_html_ban_bypass_report(self, ban_bypass_checks: List[BanBypassCheck]) -> str:
        report_data = self.report_service.generate_ban_bypass_report(ban_bypass_checks)
        self._enrich_report_data_with_verdicts(report_data)
        summary_stats = self._extract_summary_statistics(report_data)
        html_content = self.template_generator.get_html_header(summary_stats)
        html_content += self.template_generator.generate_side_navigation(report_data)
        html_content += '<div class="main-content">'
        html_content += self.template_generator.generate_summary_section(summary_stats)
        html_content += self.template_generator.generate_detailed_reports(report_data)
        html_content += '</div>'
        html_content += self.template_generator.get_html_footer(self.static_dir, self.js_file)
        self._create_static_files()
        return html_content

    def _enrich_report_data_with_verdicts(self, report_data: List[Dict[str, Any]]) -> None:
        for report in report_data:
            for result in report.get('results', []):
                self._add_verdict_to_result(result)
                for bypasser in result.get('potential_bypassers', []):
                    self._add_verdict_to_bypasser(bypasser, result)

    def _add_verdict_to_result(self, result: Dict[str, Any]) -> None:
        bypass_confidence = result.get('bypass_confidence', 'No Match Found')
        status = result.get('status', 'unknown').lower()
        hwid_erased = result.get('hwid_erased', False)
        verdict_category, verdict_confidence, verdict_reason = self._determine_verdict(
            bypass_confidence, status, hwid_erased
        )
        result['verdict_category'] = verdict_category
        if verdict_confidence:
            result['verdict_confidence'] = verdict_confidence
        if verdict_reason:
            result['verdict_reason'] = verdict_reason
        if hwid_erased:
            if 'verdict_reason' in result:
                result['verdict_reason'] += ' / HWID erased'
            else:
                result['verdict_reason'] = 'HWID erased'

    def _add_verdict_to_bypasser(self, bypasser: Dict[str, Any], result: Dict[str, Any]) -> None:
        status = bypasser.get('status', '')
        bypass_confidence = result.get('bypass_confidence', 'No Match Found')
        has_hwid_match = 'HWID Match' in bypass_confidence and len(bypasser.get('associated_hwids', {})) > 0
        has_time_match = ('Close Time Match' in bypass_confidence or 'Time Match' in bypass_confidence) and len(
            bypasser.get('associated_ips', {})) > 0
        has_ip_match = 'IP Match' in bypass_confidence and len(bypasser.get('associated_ips', {})) > 0
        if status == 'banned':
            bypasser['verdict_category'] = 'BANNED'
        elif has_hwid_match:
            bypasser['verdict_category'] = 'POTENTIAL BYPASS'
            bypasser['verdict_confidence'] = '100% (HWID Match)'
        elif has_time_match:
            bypasser['verdict_category'] = 'POTENTIAL BYPASS'
            bypasser['verdict_confidence'] = '40-50% (IP + Time Match)'
        elif has_ip_match:
            bypasser['verdict_category'] = 'SUSPICIOUS'
            bypasser['verdict_confidence'] = '1-10% (IP Match)'
        elif status == 'suspicious':
            bypasser['verdict_category'] = 'SUSPICIOUS'
        elif status == 'clean':
            bypasser['verdict_category'] = 'CLEAN'
        else:
            bypasser['verdict_category'] = 'UNKNOWN'

    def _determine_verdict(self, bypass_confidence: str, status: str, hwid_erased: bool) -> Tuple[
        str, Optional[str], Optional[str]]:
        for confidence_key, (category, confidence_value) in self.VERDICT_THRESHOLDS.items():
            if confidence_key in bypass_confidence:
                verdict_reason = 'shares IP with banned player' if confidence_key == 'IP Match' else None
                return category, confidence_value, verdict_reason
        verdict_category = self.STATUS_VERDICTS.get(status, 'UNKNOWN')
        return verdict_category, None, None

    def write_html_report(self, html_content: str, filename: Optional[str] = None) -> bool:
        html_file = filename or self.html_report_filename
        try:
            dir_path = os.path.dirname(html_file)
            if dir_path:
                ensure_directory_exists(dir_path)

            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            self.logger.info(f"HTML report saved to '{html_file}'.")
            return True
        except IOError as e:
            self.logger.error(f"Could not write HTML report to '{html_file}': {e}")
            return False

    def _extract_summary_statistics(self, report_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_reports = len(report_data)
        confidence_counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
        verdict_counts = {"potential_bypass": 0, "suspicious": 0, "banned": 0, "clean": 0, "unknown": 0}
        banned_players = set()
        potential_bypassers = set()
        ban_status_count = {"banned": 0, "suspicious": 0, "clean": 0, "unknown": 0}
        vpn_usage_count = {"vpn": 0, "no_vpn": 0}
        ban_reasons_count = {}
        for report in report_data:
            for result in report.get("results", []):
                self._count_confidence(result, confidence_counts)
                self._count_verdict(result, verdict_counts)
                banned_user = result.get("banned_user_name")
                if banned_user:
                    banned_players.add(banned_user)
                for bypasser in result.get("potential_bypassers", []):
                    nicknames = bypasser.get("nicknames", [])
                    if nicknames:
                        potential_bypassers.update(nicknames)
                for reason in result.get("ban_reasons", []):
                    ban_reasons_count[reason] = ban_reasons_count.get(reason, 0) + 1
                status = result.get("status", "unknown").lower()
                ban_status_count[status] = ban_status_count.get(status, 0) + 1
                vpn_key = "vpn" if result.get("suspected_vpn", False) else "no_vpn"
                vpn_usage_count[vpn_key] += 1
        return {
            "total_reports": total_reports,
            "banned_count": len(banned_players),
            "bypasser_count": len(potential_bypassers),
            "confidence_counts": confidence_counts,
            "verdict_counts": verdict_counts,
            "ban_reasons_count": ban_reasons_count,
            "ban_status_count": ban_status_count,
            "vpn_usage_count": vpn_usage_count,
            "banned_players": list(banned_players),
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _count_confidence(self, result: Dict[str, Any], confidence_counts: Dict[str, int]) -> None:
        confidence = result.get("bypass_confidence", "No Match Found")
        if "HWID Match" in confidence:
            confidence_counts["high"] += 1
        elif "IP + Time Match" in confidence or "Time Match" in confidence or "Close Time Match" in confidence:
            confidence_counts["medium"] += 1
        elif "IP Match" in confidence:
            confidence_counts["low"] += 1
        else:
            confidence_counts["none"] += 1

    def _count_verdict(self, result: Dict[str, Any], verdict_counts: Dict[str, int]) -> None:
        verdict_category = result.get("verdict_category", "UNKNOWN").lower()
        if verdict_category == "potential bypass" or verdict_category == "potential_bypass":
            verdict_counts["potential_bypass"] += 1
        elif verdict_category == "suspicious":
            verdict_counts["suspicious"] += 1
        elif verdict_category == "banned":
            verdict_counts["banned"] += 1
        elif verdict_category == "clean":
            verdict_counts["clean"] += 1
        else:
            verdict_counts["unknown"] += 1

    def _create_static_files(self) -> None:
        ensure_directory_exists(self.static_dir)
        self._create_css_file()
        self._create_js_file()

    def _create_css_file(self) -> None:
        from static.css_content import get_css_content
        css_path = os.path.join(self.static_dir, self.css_file)
        try:
            with open(css_path, "w", encoding="utf-8") as f:
                f.write(get_css_content())
            self.logger.debug(f"CSS file created at {css_path}")
        except IOError as e:
            self.logger.error(f"Could not create CSS file: {e}")

    def _create_js_file(self) -> None:
        from static.js_content import get_js_content
        js_path = os.path.join(self.static_dir, self.js_file)
        try:
            with open(js_path, "w", encoding="utf-8") as f:
                f.write(get_js_content())
            self.logger.debug(f"JS file created at {js_path}")
        except IOError as e:
            self.logger.error(f"Could not create JS file: {e}")