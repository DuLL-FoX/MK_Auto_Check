import importlib.util
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TimeThresholds:
    close_time_threshold_minutes: int = 10
    time_threshold_minutes: int = 30
    suspicious_time_threshold_minutes: int = 60
    ip_match_timedelta_minutes: int = 30


@dataclass
class APIConfig:
    base_admin_url: str = "https://admin.deadspace14.net"
    account_url: str = "https://account.spacestation14.com"
    request_timeout: int = 60
    login_retry_limit: int = 3
    max_concurrent_requests: int = 15


@dataclass
class DiscordConfig:
    token: str = ""
    target_channel_id: int = 0
    complaint_channel_ids: List[int] = field(default_factory=list)
    message_history_limit: int = 70000


@dataclass
class AuthConfig:
    admin_username: str = ""
    admin_password: str = ""


@dataclass
class ScanConfig:
    message_limit: int = 10
    username: Optional[str] = None
    check_ban_bypass: bool = False
    ban_bypass_pages: int = 5
    search_max_depth: int = 4
    search_limit_root: int = 8
    search_limit_level1: int = 5
    search_limit_level2: int = 3
    search_limit_default: int = 2


@dataclass
class LoggingConfig:
    log_file: Optional[str] = None
    log_level: str = "INFO"
    log_dir: Optional[str] = None
    max_bytes: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    use_colors: bool = True


@dataclass
class ConfidenceLevelConfig:
    hwid_match: str = "HWID_MATCH"
    ip_time_close_match: str = "IP_TIME_CLOSE_MATCH"
    ip_time_match: str = "IP_TIME_MATCH"
    ip_match: str = "IP_MATCH"
    no_match: str = "NO_MATCH"


@dataclass
class ReportConfig:
    html_report_filename: str = "ban_bypass_report.html"
    json_report_filename: str = "scan_report.json"
    report_dir: Optional[str] = None


@dataclass
class Config:
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    api: APIConfig = field(default_factory=APIConfig)
    time_thresholds: TimeThresholds = field(default_factory=TimeThresholds)
    scan: ScanConfig = field(default_factory=ScanConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    confidence_levels: ConfidenceLevelConfig = field(default_factory=ConfidenceLevelConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


config = Config()


def load_from_env():
    if token := os.environ.get("DISCORD_TOKEN"):
        config.discord.token = token
    if channel_id := os.environ.get("TARGET_CHANNEL_ID"):
        try:
            config.discord.target_channel_id = int(channel_id)
        except ValueError:
            pass

    if username := os.environ.get("ADMIN_USERNAME"):
        config.auth.admin_username = username
    if password := os.environ.get("ADMIN_PASSWORD"):
        config.auth.admin_password = password

    if log_level := os.environ.get("LOG_LEVEL"):
        config.logging.log_level = log_level

    if check_bypass := os.environ.get("CHECK_BAN_BYPASS"):
        config.scan.check_ban_bypass = check_bypass.lower() in ('true', 'yes', '1')


def load_from_file(file_path: str):
    try:
        spec = importlib.util.spec_from_file_location("config_module", file_path)
        if not spec or not spec.loader:
            return

        config_module = importlib.util.module_from_spec(spec)
        sys.modules["config_module"] = config_module
        spec.loader.exec_module(config_module)

        if hasattr(config_module, "DISCORD_USER_TOKEN"):
            config.discord.token = config_module.DISCORD_USER_TOKEN
        if hasattr(config_module, "TARGET_CHANNEL_ID"):
            config.discord.target_channel_id = config_module.TARGET_CHANNEL_ID
        if hasattr(config_module, "COMPLAINT_CHANNEL_IDS"):
            config.discord.complaint_channel_ids = config_module.COMPLAINT_CHANNEL_IDS
        if hasattr(config_module, "COMPLAINT_MESSAGE_HISTORY_LIMIT"):
            config.discord.message_history_limit = config_module.COMPLAINT_MESSAGE_HISTORY_LIMIT

        if hasattr(config_module, "ADMIN_USERNAME"):
            config.auth.admin_username = config_module.ADMIN_USERNAME
        if hasattr(config_module, "ADMIN_PASSWORD"):
            config.auth.admin_password = config_module.ADMIN_PASSWORD

        if hasattr(config_module, "MESSAGE_LIMIT"):
            config.scan.message_limit = config_module.MESSAGE_LIMIT
        if hasattr(config_module, "USERNAME"):
            config.scan.username = config_module.USERNAME
        if hasattr(config_module, "CHECK_BAN_BYPASS"):
            config.scan.check_ban_bypass = config_module.CHECK_BAN_BYPASS
        if hasattr(config_module, "BAN_BYPASS_PAGES"):
            config.scan.ban_bypass_pages = config_module.BAN_BYPASS_PAGES

        if hasattr(config_module, "SEARCH_MAX_DEPTH"):
            config.scan.search_max_depth = config_module.SEARCH_MAX_DEPTH
        if hasattr(config_module, "SEARCH_LIMIT_ROOT"):
            config.scan.search_limit_root = config_module.SEARCH_LIMIT_ROOT
        if hasattr(config_module, "SEARCH_LIMIT_LEVEL1"):
            config.scan.search_limit_level1 = config_module.SEARCH_LIMIT_LEVEL1
        if hasattr(config_module, "SEARCH_LIMIT_LEVEL2"):
            config.scan.search_limit_level2 = config_module.SEARCH_LIMIT_LEVEL2
        if hasattr(config_module, "SEARCH_LIMIT_DEFAULT"):
            config.scan.search_limit_default = config_module.SEARCH_LIMIT_DEFAULT

        if hasattr(config_module, "CLOSE_TIME_THRESHOLD_MINUTES"):
            config.time_thresholds.close_time_threshold_minutes = config_module.CLOSE_TIME_THRESHOLD_MINUTES
        if hasattr(config_module, "TIME_THRESHOLD_MINUTES"):
            config.time_thresholds.time_threshold_minutes = config_module.TIME_THRESHOLD_MINUTES

        if hasattr(config_module, "MAX_CONCURRENT_REQUESTS"):
            config.api.max_concurrent_requests = config_module.MAX_CONCURRENT_REQUESTS
    except Exception as e:
        print(f"Error loading configuration file: {e}")


def validate():
    missing = []

    if not config.discord.token:
        missing.append("Discord token")
    if not config.discord.target_channel_id:
        missing.append("Target channel ID")
    if not config.auth.admin_username or not config.auth.admin_password:
        missing.append("Admin credentials")

    if missing:
        raise ValueError(f"Missing required configuration: {', '.join(missing)}")


def initialize(config_file: Optional[str] = None):
    load_from_env()
    if config_file:
        load_from_file(config_file)
    validate()


def get_config() -> Config:
    return config
