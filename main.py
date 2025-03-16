import argparse
import logging
import sys

from admin_panel import AdminPanel
from bot import BanCheckerBot
from config_system import initialize, get_config
from utils.logging_utils import setup_logging


def parse_arguments():
    parser = argparse.ArgumentParser(description="Ban Checker Bot")

    parser.add_argument("--message-limit", type=int, help="Number of messages to scan")
    parser.add_argument("--username", help="Username to scan")
    parser.add_argument("--check-ban-bypass", action="store_true", help="Check for ban bypasses")
    parser.add_argument("--ban-bypass-pages", type=int, help="Number of ban bypass pages to check")

    parser.add_argument("--search-depth", type=int, help="Maximum search depth for player searches")
    parser.add_argument("--search-limit-root", type=int, help="Number of searches at root level")
    parser.add_argument("--search-limit-level1", type=int, help="Number of searches at level 1")
    parser.add_argument("--search-limit-level2", type=int, help="Number of searches at level 2")
    parser.add_argument("--search-limit-default", type=int, help="Number of searches at deeper levels")

    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging level")
    parser.add_argument("--config", help="Path to configuration file")

    return parser.parse_args()


def main():
    args = parse_arguments()

    # Параметры по умолчанию (будут использованы, если не указаны ни в конфиге, ни в аргументах)
    default_message_limit = 12
    default_username = None
    default_check_ban_bypass = False
    default_ban_bypass_pages = 1

    try:
        config_file = args.config if args.config else "config.py"
        initialize(config_file)
        cfg = get_config()
    except Exception as e:
        print(f"Configuration error: {e}")
        sys.exit(1)

    if not hasattr(cfg, 'scan'):
        cfg.scan = type('ScanConfig', (), {})

    if default_message_limit is not None:
        cfg.scan.message_limit = default_message_limit
    if default_username is not None:
        cfg.scan.username = default_username
    if default_check_ban_bypass is not None:
        cfg.scan.check_ban_bypass = default_check_ban_bypass
    if default_ban_bypass_pages is not None:
        cfg.scan.ban_bypass_pages = default_ban_bypass_pages

    if args.message_limit is not None:
        cfg.scan.message_limit = args.message_limit
    if args.username is not None:
        cfg.scan.username = args.username
    if args.check_ban_bypass:
        cfg.scan.check_ban_bypass = True
        if args.username is None and args.message_limit is None:
            cfg.scan.username = None
            cfg.scan.message_limit = None
    if args.ban_bypass_pages is not None:
        cfg.scan.ban_bypass_pages = args.ban_bypass_pages

    if args.search_depth is not None:
        cfg.scan.search_max_depth = args.search_depth
    if args.search_limit_root is not None:
        cfg.scan.search_limit_root = args.search_limit_root
    if args.search_limit_level1 is not None:
        cfg.scan.search_limit_level1 = args.search_limit_level1
    if args.search_limit_level2 is not None:
        cfg.scan.search_limit_level2 = args.search_limit_level2
    if args.search_limit_default is not None:
        cfg.scan.search_limit_default = args.search_limit_default

    if args.log_level is not None:
        cfg.logging.log_level = args.log_level

    setup_logging(
        log_file=cfg.logging.log_file,
        level=getattr(logging, cfg.logging.log_level),
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
        use_colors=cfg.logging.use_colors,
        log_dir=cfg.logging.log_dir
    )

    logging.info("Starting Ban Checker Bot")
    logging.info(
        f"Scan mode: {'Ban Bypass Check' if cfg.scan.check_ban_bypass else ('Username: ' + cfg.scan.username if cfg.scan.username else 'Messages: ' + str(cfg.scan.message_limit))}")

    admin_panel = AdminPanel(
        cfg.auth.admin_username,
        cfg.auth.admin_password
    )

    bot_config = {
        "TARGET_CHANNEL_ID": cfg.discord.target_channel_id,
        "COMPLAINT_CHANNEL_IDS": cfg.discord.complaint_channel_ids,
        "COMPLAINT_MESSAGE_HISTORY_LIMIT": cfg.discord.message_history_limit,
        "message_limit": cfg.scan.message_limit,
        "username": cfg.scan.username,
        "check_ban_bypass": cfg.scan.check_ban_bypass,
        "ban_bypass_pages": cfg.scan.ban_bypass_pages,
        "html_report_filename": cfg.report.html_report_filename
    }

    bot = BanCheckerBot(cfg.discord.token, admin_panel, bot_config)
    bot.run()


if __name__ == "__main__":
    main()