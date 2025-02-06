import logging
import traceback

import discord

from admin_panel import AdminPanel
from config_backup_v2 import DISCORD_USER_TOKEN, ADMIN_USERNAME, ADMIN_PASSWORD
from discord_bot import DiscordBot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
)


def main():
    intents = discord.Intents.default()

    username = "Lolkok32"
    message_limit = None
    check_ban_bypass = False
    ban_bypass_pages = 5
    admin_panel = AdminPanel(ADMIN_USERNAME, ADMIN_PASSWORD)
    bot = DiscordBot(
        admin_panel,
        message_limit=message_limit,
        username=username,
        intents=intents,
        check_ban_bypass=check_ban_bypass,
        ban_bypass_pages=ban_bypass_pages
    )

    try:
        bot.run(DISCORD_USER_TOKEN, bot=False)
    except discord.errors.LoginFailure:
        logging.error("Discord login failed. Ensure your token is correct.")
        traceback.print_exc()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()