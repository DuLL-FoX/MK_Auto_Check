import discord
from config import DISCORD_USER_TOKEN, ADMIN_USERNAME, ADMIN_PASSWORD
from admin_panel import AdminPanel
from discord_bot import DiscordBot

def main():
    intents = discord.Intents.default()

    message_limit = 30

    admin_panel = AdminPanel(ADMIN_USERNAME, ADMIN_PASSWORD)
    bot = DiscordBot(admin_panel, message_limit=message_limit, intents=intents)

    try:
        bot.run(DISCORD_USER_TOKEN, bot=False)
    except discord.errors.LoginFailure:
        print("[-] Discord login failed. Ensure your token is correct.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
