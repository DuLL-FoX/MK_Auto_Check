import sys
import logging
from typing import Dict, Any

from admin_panel import AdminPanel
from bot import BanCheckerBot
from utils.logging_utils import setup_logging
from config_backup_v2 import (
    TARGET_CHANNEL_ID,
    COMPLAINT_CHANNEL_IDS,
    COMPLAINT_MESSAGE_HISTORY_LIMIT,
    DISCORD_USER_TOKEN,
    ADMIN_USERNAME,
    ADMIN_PASSWORD
)

def main():
    message_limit = 2
    username = "stetsspat"
    check_ban_bypass = False
    ban_bypass_pages = 3
    log_file = None
    log_level = "INFO"
    html_report_filename = "ban_bypass_report.html"
    setup_logging(log_file, getattr(logging, log_level))
    token = DISCORD_USER_TOKEN
    if not token:
        logging.error("Discord token not provided in config.")
        sys.exit(1)
    admin_panel = AdminPanel(ADMIN_USERNAME, ADMIN_PASSWORD)
    config: Dict[str, Any] = {
        "TARGET_CHANNEL_ID": TARGET_CHANNEL_ID,
        "COMPLAINT_CHANNEL_IDS": COMPLAINT_CHANNEL_IDS,
        "COMPLAINT_MESSAGE_HISTORY_LIMIT": COMPLAINT_MESSAGE_HISTORY_LIMIT,
        "message_limit": message_limit,
        "username": username,
        "check_ban_bypass": check_ban_bypass,
        "ban_bypass_pages": ban_bypass_pages,
        "html_report_filename": html_report_filename
    }
    bot = BanCheckerBot(token, admin_panel, config)
    bot.run()

if __name__ == "__main__":
    main()
