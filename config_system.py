import importlib.util
import json
import os
import sys
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Type, TypeVar, Optional, Dict

T = TypeVar('T')

def _convert_value(value: str, target_type: Type[Any]) -> Any:
    if target_type is bool:
        return value.lower() in ('1', 'true', 'yes', 'on')
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    return value


def _merge_data_into(instance: T, data: Dict[str, Any]) -> None:
    for f in fields(instance):
        if f.name in data:
            raw = data[f.name]
            if is_dataclass(f.type) and isinstance(raw, dict):
                _merge_data_into(getattr(instance, f.name), raw)
            else:
                setattr(instance, f.name, raw)
        elif is_dataclass(f.type):
            nested = getattr(instance, f.name)
            _merge_data_into(nested, data)


def load_env_into(instance: T, prefix: str = '') -> None:
    for f in fields(instance):
        env_key = (prefix + f.name).upper()
        if raw := os.getenv(env_key):
            try:
                converted = _convert_value(raw, f.type)
                setattr(instance, f.name, converted)
            except Exception:
                pass
        elif is_dataclass(f.type):
            load_env_into(getattr(instance, f.name), env_key + '_')


def load_file(path: str, instance: T) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML config files")
        loader = yaml.safe_load
    elif ext == '.json':
        loader = json.load
    elif ext == '.py':
        spec = importlib.util.spec_from_file_location('_config', path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules['_config'] = module
            spec.loader.exec_module(module)
            data = {k.lower(): getattr(module, k) for k in dir(module) if k.isupper()}
            _merge_data_into(instance, data)
        return
    else:
        raise ValueError(f"Unsupported config file type: {ext}")

    with open(path, 'r') as f:
        data = loader(f)
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a top-level mapping")
        _merge_data_into(instance, data)


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
    discord_user_token: str = ""
    target_channel_id: int = 0
    complaint_channel_ids: list[int] = field(default_factory=list)
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
    bypass_search_max_depth: int = 2
    search_max_depth: int = 3
    search_limit_root: int = 20
    search_limit_level1: int = 10
    search_limit_level2: int = 5
    search_limit_default: int = 3

@dataclass
class LoggingConfig:
    log_file: Optional[str] = None
    log_level: str = "INFO"
    log_dir: Optional[str] = None
    max_bytes: int = 10 * 1024 * 1024
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

    def validate(self) -> None:
        missing = []
        if not self.discord.discord_user_token:
            missing.append('discord.token')
        if not self.discord.target_channel_id:
            missing.append('discord.target_channel_id')
        if not self.auth.admin_username or not self.auth.admin_password:
            missing.append('auth.admin_username and auth.admin_password')
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")

config = Config()

def initialize(config_file: Optional[str] = None) -> Config:
    load_env_into(config)
    if config_file:
        load_file(config_file, config)
    config.validate()
    return config


def get_config() -> Config:
    return config
