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

    username = "Hero"
    message_limit = None
    check_ban_bypass = False  # Enable ban bypass check mode
    ban_bypass_pages = 1  # Specify the number of pages to fetch for ban bypass check
    admin_panel = AdminPanel(ADMIN_USERNAME, ADMIN_PASSWORD)
    bot = DiscordBot(
        admin_panel,
        message_limit=message_limit,
        username=username,
        intents=intents,
        check_ban_bypass=check_ban_bypass,  # Pass the flag to DiscordBot
        ban_bypass_pages=ban_bypass_pages  # Pass the page limit
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
