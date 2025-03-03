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
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging level")
    parser.add_argument("--config", help="Path to configuration file")

    return parser.parse_args()


def main():
    args = parse_arguments()

    try:
        config_file = args.config if args.config else "config_backup_v2.py"
        initialize(config_file)
        cfg = get_config()
    except Exception as e:
        print(f"Configuration error: {e}")
        sys.exit(1)

    if args.message_limit is not None:
        cfg.scan.message_limit = args.message_limit
    if args.username is not None:
        cfg.scan.username = args.username
    if args.check_ban_bypass:
        cfg.scan.check_ban_bypass = True
    if args.ban_bypass_pages is not None:
        cfg.scan.ban_bypass_pages = args.ban_bypass_pages
    if args.search_depth is not None:
        cfg.scan.search_max_depth = args.search_depth
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