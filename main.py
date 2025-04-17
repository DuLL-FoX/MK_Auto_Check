import logging
import sys

from admin_panel import AdminPanel
from bot import BanCheckerBot
from config_system import initialize, get_config
from utils.logging_utils import setup_logging

# ─── 1) MAIN-SPECIFIED VALUES (HIGHEST PRIORITY) ────────────────────────────────
MESSAGE_LIMIT = 1
USERNAME = None
CHECK_BAN_BYPASS = False
BAN_BYPASS_PAGES = 1

SEARCH_DEPTH = None
SEARCH_LIMIT_ROOT = None
SEARCH_LIMIT_LEVEL1 = None
SEARCH_LIMIT_LEVEL2 = None
SEARCH_LIMIT_DEFAULT = None

LOG_LEVEL = None
CONFIG_FILE = "config.py"
# ────────────────────────────────────────────────────────────────────────────────

def main():
    try:
        initialize(CONFIG_FILE)
        cfg = get_config()
    except Exception as e:
        print(f"Configuration error: {e}")
        sys.exit(1)

    # ─── 2) OVERRIDE WITH MAIN VARIABLES (if not None) ─────────────────────────────
    if MESSAGE_LIMIT is not None:
        cfg.scan.message_limit = MESSAGE_LIMIT
    if USERNAME is not None:
        cfg.scan.username = USERNAME
    if CHECK_BAN_BYPASS is not None:
        cfg.scan.check_ban_bypass = CHECK_BAN_BYPASS
    if BAN_BYPASS_PAGES is not None:
        cfg.scan.ban_bypass_pages = BAN_BYPASS_PAGES

    if SEARCH_DEPTH is not None:
        cfg.scan.search_max_depth = SEARCH_DEPTH
    if SEARCH_LIMIT_ROOT is not None:
        cfg.scan.search_limit_root = SEARCH_LIMIT_ROOT
    if SEARCH_LIMIT_LEVEL1 is not None:
        cfg.scan.search_limit_level1 = SEARCH_LIMIT_LEVEL1
    if SEARCH_LIMIT_LEVEL2 is not None:
        cfg.scan.search_limit_level2 = SEARCH_LIMIT_LEVEL2
    if SEARCH_LIMIT_DEFAULT is not None:
        cfg.scan.search_limit_default = SEARCH_LIMIT_DEFAULT

    if LOG_LEVEL is not None:
        cfg.logging.log_level = LOG_LEVEL
    # ────────────────────────────────────────────────────────────────────────────────

    setup_logging(
        log_file=cfg.logging.log_file,
        level=getattr(logging, cfg.logging.log_level),
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
        use_colors=cfg.logging.use_colors,
        log_dir=cfg.logging.log_dir
    )

    logging.info("Starting Ban Checker Bot")
    mode = ("Ban Bypass Check" if cfg.scan.check_ban_bypass
            else f"Username: {cfg.scan.username}" if cfg.scan.username
            else f"Messages: {cfg.scan.message_limit}")
    logging.info(f"Scan mode: {mode}")

    admin_panel = AdminPanel(cfg.auth.admin_username, cfg.auth.admin_password)

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

    bot = BanCheckerBot(cfg.discord.discord_user_token, admin_panel, bot_config)
    bot.run()

if __name__ == "__main__":
    main()
