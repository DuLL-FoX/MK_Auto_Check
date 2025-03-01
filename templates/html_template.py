from typing import List, Dict, Any, Optional


class HTMLTemplateGenerator:
    VERDICT_ICONS = {
        'POTENTIAL_BYPASS': 'fa-user-secret',
        'POTENTIAL BYPASS': 'fa-user-secret',
        'SUSPICIOUS': 'fa-exclamation-triangle',
        'BANNED': 'fa-ban',
        'CLEAN': 'fa-check-circle',
        'UNKNOWN': 'fa-question-circle'
    }

    VERDICT_COLORS = {
        'POTENTIAL_BYPASS': '#ef4444',
        'POTENTIAL BYPASS': '#ef4444',
        'SUSPICIOUS': '#f59e0b',
        'BANNED': '#9333ea',
        'CLEAN': '#10b981',
        'UNKNOWN': '#6b7280'
    }

    STATUS_ICONS = {
        'banned': {'icon': 'fa-ban', 'class': 'text-danger'},
        'suspicious': {'icon': 'fa-exclamation-triangle', 'class': 'text-warning'},
        'clean': {'icon': 'fa-check-circle', 'class': 'text-success'},
        'unknown': {'icon': 'fa-question-circle', 'class': 'text-muted'}
    }

    def get_html_header(self, summary_stats: Dict[str, Any]) -> str:
        total_reports = summary_stats.get('total_reports', 0)
        gen_date = summary_stats.get('generation_date', 'Today')
        return f'''
        <!DOCTYPE html>
        <html lang="en" data-theme="dark">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Ban Bypass Report ({total_reports} Reports)</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            <link rel="stylesheet" href="static/styles.css">
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        </head>
        <body>
            <div class="app-container">
                <header class="header">
                    <div class="header-left">
                        <div class="menu-toggle">
                            <i class="fas fa-bars"></i>
                        </div>
                        <div class="header-title">
                            <h1><i class="fas fa-shield-alt"></i> Ban Bypass Report</h1>
                            <span class="header-date">Generated on {gen_date}</span>
                        </div>
                    </div>
                    <div class="header-actions">
                        <button id="theme-toggle" class="theme-toggle" title="Toggle Theme">
                            <i class="fas fa-sun"></i>
                        </button>
                    </div>
                </header>
        '''

    def get_html_footer(self, static_dir: str, js_file: str) -> str:
        return f'''
                <footer class="footer">
                    <div class="footer-content">
                        <div class="footer-logo">
                            <i class="fas fa-shield-alt"></i> Ban Bypass Detector
                        </div>
                        <div class="footer-info">
                            &copy; 2025 Ban Bypass Detector
                        </div>
                    </div>
                </footer>
                <div id="back-to-top">
                    <i class="fas fa-arrow-up"></i>
                </div>
            </div>
            <script src="{static_dir}/{js_file}"></script>
        </body>
        </html>
        '''

    def generate_side_navigation(self, report_data: List[Dict[str, Any]]) -> str:
        players = self._extract_players_for_sidebar(report_data)
        player_list_html = self._generate_player_list_html(players)
        return f'''
        <div class="sidebar">
            <div class="sidebar-header">
                <h3><i class="fas fa-filter"></i> <span>Filters</span></h3>
            </div>
            <div class="sidebar-nav">
                <ul>
                    <li class="active">
                        <a href="#" class="filter-link" data-filter="all">
                            <i class="fas fa-list"></i>
                            <span>All Reports</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="confidence-high">
                            <i class="fas fa-exclamation-circle"></i>
                            <span>High Confidence Bypass</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="confidence-medium">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>Medium Confidence Bypass</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="confidence-low">
                            <i class="fas fa-question-circle"></i>
                            <span>Low Confidence Bypass</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="verdict-potential-bypass">
                            <i class="fas fa-user-secret"></i>
                            <span>Potential Bypass</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="verdict-suspicious">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>Suspicious</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="verdict-banned">
                            <i class="fas fa-ban"></i>
                            <span>Banned</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="verdict-clean">
                            <i class="fas fa-check-circle"></i>
                            <span>Clean</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="vpn-detected">
                            <i class="fas fa-globe"></i>
                            <span>VPN Detected</span>
                        </a>
                    </li>
                    <li>
                        <a href="#" class="filter-link" data-filter="hwid-erased">
                            <i class="fas fa-eraser"></i>
                            <span>HWID Erased</span>
                        </a>
                    </li>
                </ul>
                <div class="nav-divider"></div>
                <ul>
                    <li class="sidebar-dropdown" data-id="sort-by">
                        <a href="#">
                            <i class="fas fa-sort"></i>
                            <span>Sort By</span>
                        </a>
                        <ul class="sidebar-submenu">
                            <li>
                                <a href="#" data-sort="name-asc" class="sort-link active">
                                    <i class="fas fa-sort-alpha-down"></i>
                                    <span>Name (A-Z)</span>
                                </a>
                            </li>
                            <li>
                                <a href="#" data-sort="name-desc" class="sort-link">
                                    <i class="fas fa-sort-alpha-up"></i>
                                    <span>Name (Z-A)</span>
                                </a>
                            </li>
                            <li>
                                <a href="#" data-sort="bans-desc" class="sort-link">
                                    <i class="fas fa-ban"></i>
                                    <span>Most Bans</span>
                                </a>
                            </li>
                            <li>
                                <a href="#" data-sort="confidence-desc" class="sort-link">
                                    <i class="fas fa-exclamation-circle"></i>
                                    <span>Highest Confidence</span>
                                </a>
                            </li>
                        </ul>
                    </li>
                </ul>
                <div class="nav-divider"></div>
                <ul>
                    <li class="sidebar-dropdown" data-id="players">
                        <a href="#">
                            <i class="fas fa-users"></i>
                            <span>Players</span>
                        </a>
                        <ul class="sidebar-submenu player-list">
                            {player_list_html}
                        </ul>
                    </li>
                </ul>
            </div>
            <div class="sidebar-footer">
                <span>Ban Bypass Detector v1.0</span>
            </div>
        </div>
        '''

    def _extract_players_for_sidebar(self, report_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        players = {}
        for report in report_data:
            for result in report.get('results', []):
                banned_user = result.get('banned_user_name')
                if banned_user and banned_user not in players:
                    players[banned_user] = {
                        'name': banned_user,
                        'status': result.get('status', 'unknown'),
                        'ban_count': result.get('ban_counts', 0),
                        'id': f"player-{banned_user.lower().replace(' ', '-')}"
                    }
                for bypasser in result.get('potential_bypassers', []):
                    for nickname in bypasser.get('nicknames', []):
                        if nickname and nickname not in players:
                            players[nickname] = {
                                'name': nickname,
                                'status': bypasser.get('status', 'unknown'),
                                'ban_count': bypasser.get('ban_counts', 0),
                                'id': f"player-{nickname.lower().replace(' ', '-')}"
                            }
        player_list = list(players.values())
        return sorted(player_list, key=lambda x: (
            0 if x['status'] == 'banned' else
            1 if x['status'] == 'suspicious' else
            2 if x['status'] == 'clean' else 3,
            x['name']
        ))

    def _generate_player_list_html(self, player_list: List[Dict[str, Any]]) -> str:
        html = ""
        for player in player_list:
            status_info = self.STATUS_ICONS.get(player['status'], self.STATUS_ICONS['unknown'])
            html += f'''
            <li>
                <a href="#{player['id']}" class="player-link" title="{player['name']}">
                    <i class="fas {status_info['icon']} {status_info['class']}"></i>
                    <span class="player-name">{player['name']}</span>
                </a>
            </li>
            '''
        return html

    def generate_summary_section(self, summary_stats: Dict[str, Any]) -> str:
        total_reports = summary_stats.get('total_reports', 0)
        banned_count = summary_stats.get('banned_count', 0)
        bypasser_count = summary_stats.get('bypasser_count', 0)
        verdict_counts = summary_stats.get('verdict_counts', {})
        potential_bypass = verdict_counts.get('potential_bypass', 0)
        suspicious = verdict_counts.get('suspicious', 0)
        banned_verdict = verdict_counts.get('banned', 0)
        clean = verdict_counts.get('clean', 0)
        confidence_counts = summary_stats.get('confidence_counts', {})
        high = confidence_counts.get('high', 0)
        medium = confidence_counts.get('medium', 0)
        low = confidence_counts.get('low', 0)
        dashboard_cards = [
            {'icon': 'fa-file-alt', 'title': 'Total Reports', 'value': total_reports, 'class': ''},
            {'icon': 'fa-ban', 'title': 'Banned Players', 'value': banned_count, 'class': ''},
            {'icon': 'fa-user-secret', 'title': 'Potential Bypassers', 'value': bypasser_count, 'class': ''},
            {'icon': 'fa-user-secret', 'title': 'Potential Bypass', 'value': potential_bypass,
             'class': 'verdict-potential-bypass'},
            {'icon': 'fa-exclamation-triangle', 'title': 'Suspicious', 'value': suspicious,
             'class': 'verdict-suspicious'},
            {'icon': 'fa-ban', 'title': 'Banned', 'value': banned_verdict, 'class': 'verdict-banned'},
            {'icon': 'fa-check-circle', 'title': 'Clean', 'value': clean, 'class': 'verdict-clean'},
            {'icon': 'fa-exclamation-circle', 'title': 'High Confidence', 'value': high, 'class': 'confidence-high'},
            {'icon': 'fa-exclamation-triangle', 'title': 'Medium Confidence', 'value': medium,
             'class': 'confidence-medium'},
            {'icon': 'fa-question-circle', 'title': 'Low Confidence', 'value': low, 'class': 'confidence-low'}
        ]
        cards_html = ""
        for card in dashboard_cards:
            cards_html += f'''
            <div class="dashboard-card {card['class']}">
                <div class="card-icon">
                    <i class="fas {card['icon']}"></i>
                </div>
                <div class="card-content">
                    <h3>{card['title']}</h3>
                    <div class="card-value">{card['value']}</div>
                </div>
            </div>
            '''
        return f'''
        <section class="summary-section">
            <h2><i class="fas fa-chart-pie"></i> Summary</h2>
            <div class="dashboard-cards">
                {cards_html}
            </div>
            <div class="search-section">
                <div id="active-filters" class="active-filter-tags">
                    <span class="filter-tag active" data-filter="all">All Reports <i class="fas fa-times-circle"></i></span>
                </div>
                <div class="search-container">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" id="search-input" class="search-input" placeholder="Search for player, HWID, IP...">
                    <button id="clear-search" class="clear-search">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="search-status">
                    Showing <span id="visible-count">0</span> of <span id="total-count">0</span> reports
                </div>
            </div>
        </section>
        '''

    def generate_detailed_reports(self, report_data: List[Dict[str, Any]]) -> str:
        processed_players = set()
        report_cards_html = ""
        for report in report_data:
            for result in report.get('results', []):
                banned_user_name = result.get('banned_user_name', 'Unknown')
                player_id = f"player-{banned_user_name.lower().replace(' ', '-')}"
                if player_id in processed_players:
                    continue
                processed_players.add(player_id)
                report_cards_html += self._generate_report_card(result, report)
        return f'''
        <section class="reports-section">
            <h2><i class="fas fa-clipboard-list"></i> Detailed Reports</h2>
            <div id="reports-container" class="reports-grid">
                {report_cards_html}
            </div>
        </section>
        '''

    def _generate_report_card(self, result: Dict[str, Any], report: Dict[str, Any]) -> str:
        banned_user_name = result.get('banned_user_name', 'Unknown')
        status = result.get('status', 'unknown')
        ban_counts = result.get('ban_counts', 0)
        bypass_confidence = result.get('bypass_confidence', 'No Match Found')
        verdict_category = result.get('verdict_category', 'UNKNOWN')
        verdict_reason = result.get('verdict_reason', '')
        suspected_vpn = result.get('suspected_vpn', False)
        hwid_erased = result.get('hwid_erased', False)
        confidence_class = self._get_confidence_class(bypass_confidence)
        player_id = f"player-{banned_user_name.lower().replace(' ', '-')}"
        special_classes = []
        if suspected_vpn:
            special_classes.append('vpn-detected')
        if hwid_erased:
            special_classes.append('hwid-erased')
        special_class_str = ' '.join(special_classes)
        verdict_class = f"verdict-{verdict_category.lower().replace(' ', '-')}"
        verdict_icon = self.VERDICT_ICONS.get(verdict_category, 'fa-question-circle')
        verdict_color = self.VERDICT_COLORS.get(verdict_category, '#6b7280')
        return f'''
        <div class="report-card {confidence_class} {verdict_class} {special_class_str}" id="{player_id}" 
             data-player-name="{banned_user_name}" 
             data-ban-count="{ban_counts}"
             data-verdict="{verdict_category}">
            <div class="report-header" style="background-color: {verdict_color}">
                <div class="report-title">
                    <i class="fas fa-user-shield"></i>
                    <h3>{banned_user_name}</h3>
                </div>
                <div class="report-badges">
                    <span class="badge badge-secondary">
                        <i class="fas fa-gavel"></i> {status.capitalize()}
                    </span>
                    <span class="badge badge-primary">
                        <i class="fas fa-ban"></i> Bans: {ban_counts}
                    </span>
                    <span class="badge badge-info">
                        <i class="fas fa-percentage"></i> {bypass_confidence}
                    </span>
                </div>
            </div>
            <div class="report-content">
                {self._generate_verdict_banner(verdict_category, verdict_reason)}
                <div class="tabs-container">
                    <div class="tabs">
                        <button class="tab active" data-tab="{player_id}-overview">
                            <i class="fas fa-info-circle"></i> Overview
                        </button>
                        <button class="tab" data-tab="{player_id}-bypassers">
                            <i class="fas fa-users"></i> Potential Bypassers
                        </button>
                        <button class="tab" data-tab="{player_id}-evidence">
                            <i class="fas fa-search"></i> Evidence
                        </button>
                        <button class="tab" data-tab="{player_id}-complaints">
                            <i class="fas fa-exclamation-triangle"></i> Complaints
                        </button>
                    </div>
                    <div id="{player_id}-overview" class="tab-content active">
                        {self._generate_overview_tab(result)}
                    </div>
                    <div id="{player_id}-bypassers" class="tab-content">
                        {self._generate_bypassers_tab(result)}
                    </div>
                    <div id="{player_id}-evidence" class="tab-content">
                        {self._generate_evidence_tab(result)}
                    </div>
                    <div id="{player_id}-complaints" class="tab-content">
                        {self._generate_complaints_tab(result)}
                    </div>
                </div>
            </div>
        </div>
        '''

    def _get_confidence_class(self, bypass_confidence: str) -> str:
        if 'HWID Match' in bypass_confidence:
            return 'confidence-high'
        elif any(match in bypass_confidence for match in ['IP + Time Match', 'Time Match', 'Close Time Match']):
            return 'confidence-medium'
        return 'confidence-low'

    def _generate_verdict_banner(self, verdict_category: str, verdict_reason: str) -> str:
        verdict_icon = self.VERDICT_ICONS.get(verdict_category, 'fa-question-circle')
        reason_html = f"<p>{verdict_reason}</p>" if verdict_reason else ""
        bg_color = f"rgba({self._hex_to_rgb(self.VERDICT_COLORS.get(verdict_category, '#6b7280'))}, 0.1)"
        return f'''
        <div class="verdict-banner" style="background-color: {bg_color}">
            <div class="verdict-icon">
                <i class="fas {verdict_icon}"></i>
            </div>
            <div class="verdict-text">
                <h4>Verdict: {verdict_category}</h4>
                {reason_html}
            </div>
        </div>
        '''

    def _hex_to_rgb(self, hex_color: str) -> str:
        hex_color = hex_color.lstrip('#')
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        return f"{r}, {g}, {b}"

    def _generate_overview_tab(self, result: Dict[str, Any]) -> str:
        banned_user_name = result.get('banned_user_name', 'Unknown')
        status = result.get('status', 'unknown')
        ban_counts = result.get('ban_counts', 0)
        user_id = result.get('banned_user_id', 'N/A')
        ban_time = result.get('ban_time', 'N/A')
        ban_expires = result.get('ban_expires', 'N/A')
        ip_address = result.get('ip_address', 'N/A')
        hwid = result.get('hwid', 'N/A')
        hwid_erased = result.get('hwid_erased', False)
        suspected_vpn = result.get('suspected_vpn', False)
        ban_hit_link = result.get('ban_hit_link', '#')
        connection_link = result.get('connection_link', '#')
        verdict_category = result.get('verdict_category', 'UNKNOWN')
        verdict_reason = result.get('verdict_reason', '')
        verdict_confidence = result.get('verdict_confidence', '')
        ban_reasons = result.get('ban_reasons', [])
        ban_reasons_html = self._generate_tag_container(ban_reasons) if ban_reasons else '''
        <div class="tag-container">
            <span class="tag">No ban reasons found</span>
        </div>
        '''
        verdict_html = self._generate_verdict_card(
            verdict_category,
            verdict_reason,
            verdict_confidence,
            hwid_erased
        )
        hwid_erased_text = "Yes" if hwid_erased else "No"
        suspected_vpn_text = "Yes" if suspected_vpn else "No"
        return f'''
        {verdict_html}
        <div class="info-card">
            <h4><i class="fas fa-user"></i> Player Information</h4>
            <div class="info-grid">
                {self._info_item("Username", banned_user_name, "fa-user")}
                {self._info_item("User ID", user_id, "fa-id-card")}
                {self._info_item("Status", status.capitalize(), "fa-gavel")}
                {self._info_item("Ban Count", ban_counts, "fa-ban")}
                {self._info_item("HWID Erased", hwid_erased_text, "fa-eraser")}
                {self._info_item("VPN Detected", suspected_vpn_text, "fa-globe")}
            </div>
        </div>
        <div class="info-card">
            <h4><i class="fas fa-gavel"></i> Ban Information</h4>
            <div class="info-grid">
                {self._info_item("Ban Time", ban_time, "fa-clock")}
                {self._info_item("Ban Expires", ban_expires, "fa-hourglass-end")}
                {self._link_item("Ban Hit Link", ban_hit_link, "fa-link", "View Ban Hit")}
                {self._link_item("Connection Link", connection_link, "fa-link", "View Connection")}
            </div>
        </div>
        <div class="info-card">
            <h4><i class="fas fa-exclamation-triangle"></i> Ban Reasons</h4>
            {ban_reasons_html}
        </div>
        <div class="info-card">
            <h4><i class="fas fa-network-wired"></i> Connection Information</h4>
            <div class="info-grid">
                {self._copyable_item("IP Address", ip_address, "fa-globe")}
                {self._copyable_item("HWID", hwid, "fa-fingerprint", "hwid-value")}
            </div>
        </div>
        '''

    def _generate_verdict_card(self, verdict_category: str, verdict_reason: str,
                               verdict_confidence: str, hwid_erased: bool) -> str:
        hwid_erased_text = "Yes" if hwid_erased else "No"
        verdict_class = f"verdict-{verdict_category.lower().replace(' ', '-')}"
        details = [
            self._verdict_detail_item("Category", verdict_category, "verdict-category"),
        ]
        if verdict_reason:
            details.append(self._verdict_detail_item("Reason", verdict_reason, "verdict-reason"))
        if verdict_confidence:
            details.append(self._verdict_detail_item("Confidence", verdict_confidence, "verdict-confidence"))
        details.append(self._verdict_detail_item("HWID Erased", hwid_erased_text, "verdict-hwid-erased"))
        details_html = "\n".join(details)
        return f'''
        <div class="info-card verdict-card {verdict_class}">
            <h4><i class="fas {self.VERDICT_ICONS.get(verdict_category, 'fa-question-circle')}"></i> Verdict Assessment</h4>
            <div class="verdict-details">
                {details_html}
            </div>
        </div>
        '''

    def _verdict_detail_item(self, label: str, value: str, class_name: str) -> str:
        return f'''
        <div class="{class_name}">
            <span class="label">{label}:</span>
            <span class="value">{value}</span>
        </div>
        '''

    def _info_item(self, label: str, value: Any, icon: str) -> str:
        return f'''
        <div class="info-item">
            <div class="label"><i class="fas {icon}"></i> {label}</div>
            <div class="value">{value}</div>
        </div>
        '''

    def _copyable_item(self, label: str, value: str, icon: str, extra_class: str = "") -> str:
        value_class = f"value {extra_class}" if extra_class else "value"
        return f'''
        <div class="info-item">
            <div class="label"><i class="fas {icon}"></i> {label}</div>
            <div class="{value_class}">{value}
                <button class="copy-btn" data-copy="{value}" title="Copy to Clipboard">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        </div>
        '''

    def _link_item(self, label: str, url: str, icon: str, link_text: str) -> str:
        return f'''
        <div class="info-item">
            <div class="label"><i class="fas {icon}"></i> {label}</div>
            <div class="value">
                <a href="{url}" target="_blank" class="link-item">
                    <i class="fas fa-external-link-alt"></i> {link_text}
                </a>
            </div>
        </div>
        '''

    def _generate_tag_container(self, tags: List[str]) -> str:
        if not tags:
            return '<div class="tag-container"></div>'
        tags_html = "\n".join([f'<span class="tag">{tag}</span>' for tag in tags])
        return f'''
        <div class="tag-container">
            {tags_html}
        </div>
        '''

    def _generate_bypassers_tab(self, result: Dict[str, Any]) -> str:
        potential_bypassers = result.get('potential_bypassers', [])
        if not potential_bypassers:
            return '''
            <div class="empty-state">
                <i class="fas fa-search"></i>
                <p>No potential bypassers found for this player.</p>
            </div>
            '''
        processed_bypassers = set()
        bypasser_rows = []
        for bypasser in potential_bypassers:
            nickname = bypasser.get('nicknames', ['Unknown'])[0]
            if nickname in processed_bypassers:
                continue
            processed_bypassers.add(nickname)
            status = bypasser.get('status', 'unknown')
            ban_counts = bypasser.get('ban_counts', 0)
            verdict_category = bypasser.get('verdict_category', 'UNKNOWN')
            shared_hwids_count = 0
            shared_ips_count = 0
            if 'evidence' in bypasser:
                shared_hwids_count = len(bypasser['evidence'].get('shared_hwids', []))
                shared_ips_count = len(bypasser['evidence'].get('shared_ips', []))
            status_info = self.STATUS_ICONS.get(status, self.STATUS_ICONS['unknown'])
            verdict_icon = self.VERDICT_ICONS.get(verdict_category, 'fa-question-circle')
            player_id = f"player-{nickname.lower().replace(' ', '-')}"
            bypasser_rows.append(f'''
            <tr>
                <td class="user-cell">
                    <div class="user-info">
                        <i class="fas {status_info['icon']} {status_info['class']}"></i>
                        <span class="nickname-cell" title="{nickname}">{nickname}</span>
                    </div>
                </td>
                <td>{status.capitalize()}</td>
                <td>
                    <div class="table-verdict">
                        <i class="fas {verdict_icon}"></i>
                        <span>{verdict_category}</span>
                    </div>
                </td>
                <td>{ban_counts}</td>
                <td>{shared_hwids_count}</td>
                <td>{shared_ips_count}</td>
                <td>
                    <div class="action-buttons">
                        <a href="#{player_id}" class="btn btn-sm btn-primary player-link">
                            <i class="fas fa-info-circle"></i>
                        </a>
                    </div>
                </td>
            </tr>
            ''')
        bypasser_rows_html = "\n".join(bypasser_rows)
        return f'''
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th class="sortable">Player</th>
                        <th class="sortable">Status</th>
                        <th class="sortable">Verdict</th>
                        <th class="sortable">Ban Count</th>
                        <th class="sortable">Shared HWIDs</th>
                        <th class="sortable">Shared IPs</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {bypasser_rows_html}
                </tbody>
            </table>
        </div>
        '''

    def _generate_evidence_tab(self, result: Dict[str, Any]) -> str:
        all_ips = result.get('all_associated_ips', {})
        all_hwids = result.get('all_associated_hwids', {})
        if not all_ips and not all_hwids:
            return '''
            <div class="empty-state">
                <i class="fas fa-search"></i>
                <p>No evidence information found for this player.</p>
            </div>
            '''
        ip_section = ""
        if all_ips:
            ip_rows = []
            for ip, nicknames in all_ips.items():
                shared_with, tooltip_text = self._format_shared_names(nicknames)
                ip_rows.append(f'''
                <tr>
                    <td class="ip-display">
                        {ip}
                        <button class="copy-btn" data-copy="{ip}" title="Copy to Clipboard">
                            <i class="fas fa-copy"></i>
                        </button>
                    </td>
                    <td class="shared-with-cell" title="{tooltip_text}">{shared_with}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-sm btn-info" onclick="filterByIP('{ip}')">
                                <i class="fas fa-filter"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                ''')
            ip_rows_html = "\n".join(ip_rows)
            ip_section = f'''
            <div class="info-card">
                <h4><i class="fas fa-globe"></i> Associated IP Addresses</h4>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th class="sortable">IP Address</th>
                                <th class="sortable">Shared With</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ip_rows_html}
                        </tbody>
                    </table>
                </div>
            </div>
            '''
        hwid_section = ""
        if all_hwids:
            hwid_rows = []
            for hwid, nicknames in all_hwids.items():
                shared_with, tooltip_text = self._format_shared_names(nicknames)
                hwid_rows.append(f'''
                <tr>
                    <td class="hwid-display">
                        <span class="hwid-value">{hwid}</span>
                        <button class="copy-btn" data-copy="{hwid}" title="Copy to Clipboard">
                            <i class="fas fa-copy"></i>
                        </button>
                    </td>
                    <td class="shared-with-cell" title="{tooltip_text}">{shared_with}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-sm btn-info" onclick="filterByHWID('{hwid}')">
                                <i class="fas fa-filter"></i>
                            </button>
                        </div>
                    </td>
                </tr>
                ''')
            hwid_rows_html = "\n".join(hwid_rows)
            hwid_section = f'''
            <div class="info-card">
                <h4><i class="fas fa-fingerprint"></i> Associated HWIDs</h4>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th class="sortable">HWID</th>
                                <th class="sortable">Shared With</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {hwid_rows_html}
                        </tbody>
                    </table>
                </div>
            </div>
            '''
        return ip_section + hwid_section

    def _format_shared_names(self, nicknames: List[str]) -> tuple:
        if len(nicknames) > 5:
            visible_nicknames = ", ".join(nicknames[:5])
            remaining_count = len(nicknames) - 5
            shared_with = f"{visible_nicknames} <span class='badge badge-secondary'>+{remaining_count} more</span>"
            tooltip_text = ", ".join(nicknames)
        else:
            shared_with = ", ".join(nicknames) if nicknames else "None"
            tooltip_text = shared_with
        return shared_with, tooltip_text

    def _generate_complaints_tab(self, result: Dict[str, Any]) -> str:
        complaint_links = result.get('complaint_links', [])
        if not complaint_links:
            return '''
            <div class="empty-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>No complaints found for this player.</p>
            </div>
            '''
        return f'''
        <div class="info-card">
            <h4><i class="fas fa-exclamation-triangle"></i> Complaint Messages</h4>
            {self._generate_complaint_links_section(complaint_links)}
        </div>
        '''

    def _generate_complaint_links_section(self, complaint_links: List[Any]) -> str:
        if not complaint_links:
            return '<p>No complaint links found.</p>'
        links_html = []
        processed_links = set()
        for complaint in complaint_links:
            if isinstance(complaint, str):
                if complaint not in processed_links:
                    processed_links.add(complaint)
                    links_html.append(f'''
                    <a href="{complaint}" target="_blank" class="link-item">
                        <i class="fas fa-external-link-alt"></i> View Complaint
                    </a>
                    ''')
            else:
                link = complaint.get('link', '#')
                if link not in processed_links:
                    processed_links.add(link)
                    nicknames = complaint.get('nicknames', [])
                    if len(nicknames) > 3:
                        display_nicknames = f"{', '.join(nicknames[:3])} +{len(nicknames) - 3} more"
                        tooltip_text = f"Complaint about {', '.join(nicknames)}"
                    else:
                        display_nicknames = ", ".join(nicknames)
                        tooltip_text = f"Complaint about {display_nicknames}" if nicknames else "View Complaint"
                    nickname_text = f"Complaint about {display_nicknames}" if nicknames else "View Complaint"
                    links_html.append(f'''
                    <a href="{link}" target="_blank" class="link-item" title="{tooltip_text}">
                        <i class="fas fa-external-link-alt"></i> {nickname_text}
                    </a>
                    ''')
        return f'''
        <div class="link-list">
            {"".join(links_html)}
        </div>
        '''
