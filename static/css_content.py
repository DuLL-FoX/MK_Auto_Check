def get_css_content() -> str:
    return """
:root {
  /* Theme colors */
  --primary: #4a6cf7;
  --primary-dark: #3a56d4;
  --primary-light: rgba(74, 108, 247, 0.1);
  --secondary: #6c757d;
  --accent: #f72585;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  --info: #3b82f6;
  --muted: #6b7280;

  /* Verdict colors */
  --verdict-bypass: #ef4444;
  --verdict-suspicious: #f59e0b;
  --verdict-banned: #9333ea;
  --verdict-clean: #10b981;
  --verdict-unknown: #6b7280;

  /* Confidence colors */
  --high-confidence: var(--verdict-bypass);
  --medium-confidence: var(--verdict-suspicious);
  --low-confidence: var(--info);

  /* UI colors */
  --bg: #f8f9fa;
  --card: #ffffff;
  --sidebar: #344054;
  --text: #212529;
  --text-light: #f8f9fa;
  --border: #e9ecef;

  /* Dimensions */
  --header-height: 60px;
  --sidebar-width: 250px;
  --sidebar-collapsed: 70px;

  /* Effects */
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.1);
  --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
  --transition: 0.3s ease;
}

/* Dark theme */
[data-theme="dark"] {
  --bg: #1a1d23;
  --card: #232830;
  --sidebar: #131720;
  --text: #e9ecef;
  --text-light: #e9ecef;
  --secondary: #adb5bd;
  --border: #343a40;
}

/* Base styles */
* { 
  margin: 0; 
  padding: 0; 
  box-sizing: border-box; 
}

body {
  font-family: 'Segoe UI', system-ui, sans-serif;
  line-height: 1.6;
  color: var(--text);
  background-color: var(--bg);
  transition: background-color var(--transition);
}

/* Simplified Layout */
.app-container {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.header {
  position: sticky;
  top: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: var(--header-height);
  background-color: var(--card);
  border-bottom: 1px solid var(--border);
  padding: 0 1.5rem;
  z-index: 100;
  box-shadow: var(--shadow-sm);
}

.main-content {
  margin-left: var(--sidebar-width);
  padding: 1.5rem;
  transition: margin-left var(--transition);
}

.sidebar {
  position: fixed;
  top: var(--header-height);
  left: 0;
  height: calc(100vh - var(--header-height));
  width: var(--sidebar-width);
  background-color: var(--sidebar);
  color: var(--text-light);
  overflow-y: auto;
  transition: width var(--transition), transform var(--transition);
  z-index: 90;
}

/* Header components */
.menu-toggle, .theme-toggle {
  font-size: 1.25rem;
  cursor: pointer;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  transition: background-color 0.2s;
  background: none;
  border: none;
  color: var(--text);
}

.menu-toggle:hover, .theme-toggle:hover {
  background-color: var(--border);
}

.header-title {
  display: flex;
  flex-direction: column;
}

.header-title h1 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.header-date {
  font-size: 0.8rem;
  color: var(--secondary);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 1rem;
}

/* Sidebar components */
.sidebar-header {
  padding: 1.5rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.sidebar-header h3 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
}

.sidebar-nav ul {
  list-style: none;
  padding: 0;
}

.sidebar-nav a {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1.5rem;
  color: var(--text-light);
  text-decoration: none;
  transition: background-color 0.2s;
}

.sidebar-nav a i {
  width: 1.25rem;
  text-align: center;
}

.sidebar-nav li.active a {
  background-color: var(--primary);
  font-weight: 500;
}

.sidebar-nav a:hover {
  background-color: rgba(255, 255, 255, 0.1);
}

.nav-divider {
  height: 1px;
  background-color: rgba(255, 255, 255, 0.1);
  margin: 0.5rem 0;
}

.sidebar-dropdown > a::after {
  content: '\\f107';
  font-family: 'Font Awesome 6 Free';
  font-weight: 900;
  margin-left: auto;
  transition: transform 0.3s;
}

.sidebar-dropdown.active > a::after {
  transform: rotate(180deg);
}

.sidebar-submenu {
  display: none;
  background-color: rgba(0, 0, 0, 0.1);
  max-height: 400px;
  overflow-y: auto;
}

.player-list {
  max-height: 300px;
  overflow-y: auto;
}

.sidebar-dropdown.active .sidebar-submenu {
  display: block;
}

.sidebar-submenu a {
  padding-left: 3rem;
}

.sidebar-footer {
  padding: 1rem 1.5rem;
  font-size: 0.8rem;
  color: var(--secondary);
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  margin-top: auto;
}

/* Consolidated player name styles */
.player-name, .nickname-cell {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 160px;
  display: inline-block;
}

.nickname-cell {
  max-width: 200px;
}

/* Dashboard cards */
.dashboard-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.dashboard-card {
  background-color: var(--card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: var(--shadow-sm);
  display: flex;
  align-items: center;
  gap: 1rem;
  border-left: 4px solid var(--primary);
  transition: transform 0.2s, box-shadow 0.2s;
}

.dashboard-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

/* Consolidated card icon styles */
.card-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 50px;
  height: 50px;
  border-radius: 50%;
  background-color: var(--primary-light);
  color: var(--primary);
  font-size: 1.25rem;
}

.card-content {
  flex: 1;
}

.card-content h3 {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--secondary);
  margin-bottom: 0.25rem;
}

.card-value {
  font-size: 1.5rem;
  font-weight: 600;
}

/* Search section */
.search-section {
  background-color: var(--card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: var(--shadow-sm);
  margin-bottom: 1.5rem;
}

.search-container {
  position: relative;
  margin-bottom: 0.5rem;
}

.search-icon {
  position: absolute;
  left: 1rem;
  top: 50%;
  transform: translateY(-50%);
  color: var(--secondary);
}

.search-input {
  width: 100%;
  padding: 0.75rem 1rem 0.75rem 2.5rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 1rem;
  background-color: var(--bg);
  color: var(--text);
  transition: border-color 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: var(--primary);
}

.clear-search {
  position: absolute;
  right: 1rem;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--secondary);
  cursor: pointer;
  display: none;
}

.search-input:not(:placeholder-shown) + .clear-search {
  display: block;
}

.search-status {
  color: var(--secondary);
  font-size: 0.875rem;
}

/* Reports section */
.reports-section h2, .summary-section h2 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  font-size: 1.5rem;
  font-weight: 600;
}

.reports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(600px, 1fr));
  gap: 1rem;
}

.report-card {
  background-color: var(--card);
  border-radius: 8px;
  box-shadow: var(--shadow-sm);
  overflow: hidden;
  transition: transform 0.2s, box-shadow 0.2s;
}

.report-card:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md);
}

/* Report header */
.report-header {
  background-color: var(--primary);
  color: white;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.report-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.report-title h3 {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
}

/* Badge styles */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.report-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

/* Badge variants */
.badge-primary { background-color: var(--primary); color: white; }
.badge-success { background-color: var(--success); color: white; }
.badge-warning { background-color: var(--warning); color: white; }
.badge-danger { background-color: var(--danger); color: white; }
.badge-info { background-color: var(--info); color: white; }
.badge-secondary { background-color: var(--secondary); color: white; }

/* Confidence classes */
.confidence-high .report-header { background-color: var(--high-confidence); }
.confidence-medium .report-header { background-color: var(--medium-confidence); }
.confidence-low .report-header { background-color: var(--low-confidence); }

.confidence-high .card-icon {
  background-color: rgba(239, 68, 68, 0.1);
  color: var(--high-confidence);
}

.confidence-medium .card-icon {
  background-color: rgba(245, 158, 11, 0.1);
  color: var(--medium-confidence);
}

.confidence-low .card-icon {
  background-color: rgba(59, 130, 246, 0.1);
  color: var(--low-confidence);
}

/* Dashboard confidence */
.dashboard-card.confidence-high { border-left-color: var(--high-confidence); }
.dashboard-card.confidence-medium { border-left-color: var(--medium-confidence); }
.dashboard-card.confidence-low { border-left-color: var(--low-confidence); }

/* Report content */
.report-content {
  padding: 1.25rem;
}

.report-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}

/* Info cards */
.info-card {
  background-color: var(--bg);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
}

.info-card h4 {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.75rem;
}

.info-item {
  margin-bottom: 0.5rem;
}

.info-item .label {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  font-weight: 500;
  color: var(--secondary);
  font-size: 0.875rem;
  margin-bottom: 0.25rem;
}

.info-item .value {
  font-size: 0.9375rem;
}

.hwid-value, .ip-display {
  font-family: monospace;
  word-break: break-all;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* Copy button */
.copy-btn {
  background: none;
  border: none;
  color: var(--primary);
  cursor: pointer;
  font-size: 0.875rem;
  padding: 0.25rem;
  border-radius: 4px;
  transition: background-color 0.2s;
}

.copy-btn:hover {
  background-color: var(--primary-light);
}

.copy-btn.copied {
  background-color: rgba(16, 185, 129, 0.1);
  color: var(--success);
}

/* Tags */
.tag-container {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.tag {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  background-color: var(--primary-light);
  color: var(--primary);
  border-radius: 4px;
  font-size: 0.875rem;
}

/* Links */
.link-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.link-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  border-radius: 4px;
  text-decoration: none;
  color: var(--primary);
  transition: background-color 0.2s;
}

.link-item:hover {
  background-color: var(--primary-light);
}

/* Tabs */
.tabs-container {
  margin-top: 1rem;
}

.tabs {
  display: flex;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1rem;
}

.tab {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.75rem 1rem;
  background: none;
  border: none;
  border-bottom: 3px solid transparent;
  font-size: 0.9375rem;
  color: var(--secondary);
  cursor: pointer;
  transition: all 0.2s;
}

.tab:hover {
  color: var(--primary);
}

.tab.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
  font-weight: 500;
}

.tab-content {
  display: none;
}

.tab-content.active {
  display: block;
  animation: fadeIn 0.3s;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* Tables */
.table-responsive {
  overflow-x: auto;
  margin-bottom: 1rem;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
}

.data-table th,
.data-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.data-table th {
  font-weight: 600;
  color: var(--secondary);
  background-color: var(--bg);
  position: sticky;
  top: 0;
}

.data-table th.sortable {
  cursor: pointer;
}

.data-table th.sortable::after {
  content: '\\f0dc';
  font-family: 'Font Awesome 6 Free';
  font-weight: 900;
  margin-left: 0.5rem;
  font-size: 0.875rem;
  color: var(--secondary);
}

.data-table th.th-sort-asc::after {
  content: '\\f0de';
  color: var(--primary);
}

.data-table th.th-sort-desc::after {
  content: '\\f0dd';
  color: var(--primary);
}

.data-table tr:hover {
  background-color: rgba(0, 0, 0, 0.02);
}

.user-cell {
  white-space: nowrap;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.shared-with-cell {
  max-width: 300px;
  white-space: normal;
  word-break: break-word;
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
}

/* Button styles */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.375rem 0.75rem;
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
}

.btn-sm {
  padding: 0.25rem 0.5rem;
  font-size: 0.875rem;
}

.btn-primary {
  background-color: var(--primary);
  color: white;
}

.btn-primary:hover {
  background-color: var(--primary-dark);
}

.btn-info {
  background-color: var(--info);
  color: white;
}

.btn-info:hover {
  background-color: #2563eb;
}

.btn-warning {
  background-color: var(--warning);
  color: white;
}

.btn-warning:hover {
  background-color: #d97706;
}

/* Empty state */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 1rem;
  color: var(--secondary);
}

.empty-state i {
  font-size: 2.5rem;
  margin-bottom: 1rem;
}

/* Back to top button */
#back-to-top {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  width: 40px;
  height: 40px;
  background-color: var(--primary);
  color: white;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  box-shadow: var(--shadow-md);
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.3s, visibility 0.3s;
  z-index: 99;
}

#back-to-top.visible {
  opacity: 1;
  visibility: visible;
}

/* Footer */
.footer {
  background-color: var(--card);
  border-top: 1px solid var(--border);
  padding: 1rem 0;
  margin-top: 2rem;
  margin-left: var(--sidebar-width);
  transition: margin-left var(--transition);
}

.footer-content {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 1.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.footer-logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
}

.footer-info {
  color: var(--secondary);
  font-size: 0.875rem;
}

/* Filter tags */
.active-filter-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.filter-tag {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background-color: var(--primary);
  color: white;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 500;
}

.filter-tag i {
  cursor: pointer;
  opacity: 0.8;
  transition: opacity 0.2s;
}

.filter-tag i:hover {
  opacity: 1;
}

/* Highlight animation */
.highlight-pulse {
  animation: highlight-pulse 2s ease-in-out;
}

@keyframes highlight-pulse {
  0% { box-shadow: 0 0 0 0 rgba(74, 108, 247, 0.5); }
  50% { box-shadow: 0 0 0 10px rgba(74, 108, 247, 0); }
  100% { box-shadow: 0 0 0 0 rgba(74, 108, 247, 0); }
}

/* Verdict styling */
.verdict-banner {
  display: flex;
  align-items: center;
  padding: 1rem;
  margin-bottom: 1rem;
  border-radius: 8px;
  gap: 1rem;
}

.verdict-icon {
  font-size: 1.5rem;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background-color: rgba(255, 255, 255, 0.2);
}

.verdict-text {
  flex: 1;
}

.verdict-text h4 {
  margin: 0 0 0.25rem 0;
  font-size: 1.1rem;
  font-weight: 600;
}

.verdict-text p {
  margin: 0;
  font-size: 0.9rem;
}

/* Verdict card styles */
.verdict-card {
  border-left-width: 4px;
  border-left-style: solid;
}

.verdict-details {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.75rem;
}

/* Verdict type styling */
.verdict-potential-bypass, 
.verdict-card.verdict-potential-bypass {
  --verdict-color: var(--verdict-bypass);
  --verdict-bg: rgba(239, 68, 68, 0.1);
}

.verdict-suspicious, 
.verdict-card.verdict-suspicious {
  --verdict-color: var(--verdict-suspicious);
  --verdict-bg: rgba(245, 158, 11, 0.1);
}

.verdict-banned, 
.verdict-card.verdict-banned {
  --verdict-color: var(--verdict-banned);
  --verdict-bg: rgba(147, 51, 234, 0.1);
}

.verdict-clean, 
.verdict-card.verdict-clean {
  --verdict-color: var(--verdict-clean);
  --verdict-bg: rgba(16, 185, 129, 0.1);
}

.verdict-unknown, 
.verdict-card.verdict-unknown {
  --verdict-color: var(--verdict-unknown);
  --verdict-bg: rgba(107, 114, 128, 0.1);
}

.verdict-card {
  border-left-color: var(--verdict-color);
}

.verdict-banner {
  background-color: var(--verdict-bg);
}

.verdict-card .card-icon {
  background-color: var(--verdict-bg);
  color: var(--verdict-color);
}

/* Table verdict icons */
.table-verdict {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.table-verdict i {
  font-size: 0.9rem;
}

.table-verdict i.fa-user-secret { color: var(--verdict-bypass); }
.table-verdict i.fa-exclamation-triangle { color: var(--verdict-suspicious); }
.table-verdict i.fa-ban { color: var(--verdict-banned); }
.table-verdict i.fa-check-circle { color: var(--verdict-clean); }
.table-verdict i.fa-question-circle { color: var(--verdict-unknown); }

/* Special classes */
.vpn-detected, .hwid-erased {
  position: relative;
}

.vpn-detected::before {
  content: 'VPN';
  position: absolute;
  top: -10px;
  right: -10px;
  background-color: var(--warning);
  color: white;
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border-radius: 4px;
  z-index: 10;
}

.hwid-erased::after {
  content: 'HWID Erased';
  position: absolute;
  top: -10px;
  left: -10px;
  background-color: var(--danger);
  color: white;
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border-radius: 4px;
  z-index: 10;
}

/* Responsive layout */
@media screen and (max-width: 1200px) {
  .reports-grid {
    grid-template-columns: 1fr;
  }
}

@media screen and (max-width: 768px) {
  .sidebar {
    transform: translateX(-100%);
  }

  .main-content,
  .footer {
    margin-left: 0;
  }

  .sidebar.active {
    transform: translateX(0);
  }

  .dashboard-cards {
    grid-template-columns: 1fr;
  }

  .info-grid {
    grid-template-columns: 1fr;
  }
}

/* Collapsed sidebar */
.collapsed-sidebar .sidebar {
  width: var(--sidebar-collapsed);
}

.collapsed-sidebar .main-content,
.collapsed-sidebar .footer {
  margin-left: var(--sidebar-collapsed);
}

.collapsed-sidebar .sidebar-nav span,
.collapsed-sidebar .sidebar-header h3 span,
.collapsed-sidebar .sidebar-dropdown > a::after,
.collapsed-sidebar .sidebar-footer {
  display: none;
}

.collapsed-sidebar .sidebar-nav a {
  justify-content: center;
  padding: 0.75rem 0;
}

.collapsed-sidebar .sidebar-submenu {
  position: absolute;
  left: var(--sidebar-collapsed);
  top: 0;
  width: 200px;
  z-index: 100;
}

.collapsed-sidebar .sidebar-submenu a {
  padding-left: 1.5rem;
  justify-content: flex-start;
}

.collapsed-sidebar .sidebar-dropdown:hover .sidebar-submenu {
  display: block;
}
"""
