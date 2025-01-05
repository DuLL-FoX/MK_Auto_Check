import discord
import json
from admin_panel import AdminPanel
from config_backup_v2 import TARGET_CHANNEL_ID, COMPLAINT_CHANNEL_IDS
from utils import embed_contains_nickname, collect_unique_links_from_embed

class DiscordBot(discord.Client):
    def __init__(self, admin_panel: AdminPanel, message_limit: int = 10, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.admin_panel = admin_panel
        self.message_limit = message_limit

    async def on_ready(self):
        print(f"[+] Logged in to Discord as: {self.user} (ID: {self.user.id})")

        if not self.admin_panel.login():
            print("[-] Could not log in to admin site.")
            await self.close()
            return

        channel = self.get_channel(TARGET_CHANNEL_ID)
        if not channel:
            print(f"[-] Could not find channel ID: {TARGET_CHANNEL_ID}")
            await self.close()
            return

        print(
            f"[+] Checking last {self.message_limit} messages in channel '{channel.name}' "
            f"({TARGET_CHANNEL_ID}) for embed links."
        )

        report_data = []

        async for message in channel.history(limit=self.message_limit, oldest_first=False):
            if not message.embeds:
                continue

            partial_results_for_message = []

            for embed in message.embeds:
                unique_links_dict = collect_unique_links_from_embed(embed)
                if not unique_links_dict:
                    continue

                for search_value, link in unique_links_dict.items():
                    account_info = self.admin_panel.check_account_on_site(link)
                    partial_results_for_message.append(account_info)

            merged_player_results = self.admin_panel.aggregate_player_info(partial_results_for_message)

            if not merged_player_results:
                continue

            message_info = {
                "message_id": str(message.id),
                "message_link": f"https://discord.com/channels/{message.guild.id}/{channel.id}/{message.id}",
                "author_name": str(message.author),
                "author_id": str(message.author.id),
                "results": []
            }

            for player_res in merged_player_results:
                if not player_res["suspected_vpn"] and player_res["nicknames"]:
                    all_complaint_links = []
                    for nick in player_res["nicknames"]:
                        found_links = await self.check_name_in_channels(nick)
                        all_complaint_links.extend(found_links)

                    player_res["complaint_links"] = list(set(all_complaint_links))
                else:
                    player_res["complaint_links"] = []

                message_info["results"].append(player_res)

            report_data.append(message_info)
            self.print_message_summary(message, message_info)

        self.write_json_report(report_data, file_name="scan_report.json")

        print("[+] Finished scanning messages. Disconnecting from Discord.")
        await self.close()

    def print_message_summary(self, message: discord.Message, message_info: dict):
        results = message_info["results"]
        print("=====================================================================")
        print(f"Message ID {message.id} by {message.author} had {len(results)} merged result(s).")
        print(f"Message link: {message_info['message_link']}\n")

        for idx, result in enumerate(results, start=1):
            # Decide a textual verdict
            status = result["status"]
            if status == "banned":
                verdict = "POSSIBLE BYPASS / BANNED"
            elif status == "clean":
                verdict = "CLEAN / NO BYPASS"
            elif status == "suspicious":
                verdict = "SUSPICIOUS / CHECK SERVER BANS"
            else:
                verdict = "UNKNOWN / NEED MANUAL CHECK"

            shared_info = ""
            if result["shared_hwid_nicknames"]:
                shared_info = "Shared HWID with: " + ", ".join(result["shared_hwid_nicknames"])

            if result["complaint_links"]:
                complaint_summary = "\n      Found in complaint messages:\n" + "\n".join(
                    [f"         - {link}" for link in result["complaint_links"]]
                )
            else:
                complaint_summary = "\n      Found in complaint messages: None"

            ban_reasons = ", ".join(result["ban_reasons"]) if result["ban_reasons"] else "None"

            print(
                f"{idx}) Nicknames: {', '.join(result['nicknames']) if result['nicknames'] else 'N/A'}\n"
                f"   Status: {status} (Ban count: {result['ban_counts']})\n"
                f"   Suspected VPN: {result['suspected_vpn']}\n"
                f"   Ban reasons: {ban_reasons}\n"
                f"   Verdict: {verdict}\n"
                f"   {shared_info}"
                f"{complaint_summary}\n"
            )
        print("=====================================================================\n")

    def write_json_report(self, report_data, file_name="scan_report.json"):
        try:
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=4)
            print(f"[+] JSON report saved to '{file_name}' with {len(report_data)} messages.")
        except Exception as e:
            print(f"[-] Could not write JSON report to '{file_name}': {e}")

    async def check_name_in_channels(self, nickname: str):
        lower_nick = nickname.lower()
        found_links = []

        for ch_id in COMPLAINT_CHANNEL_IDS:
            channel = self.get_channel(ch_id)
            if not channel:
                print(f"[-] Could not find channel with ID: {ch_id}")
                continue

            try:
                async for msg in channel.history(limit=200):
                    if lower_nick in msg.content.lower():
                        jump_link = f"https://discord.com/channels/{msg.guild.id}/{channel.id}/{msg.id}"
                        found_links.append(jump_link)
                        continue

                    for embed in msg.embeds:
                        if embed_contains_nickname(embed, nickname):
                            jump_link = f"https://discord.com/channels/{msg.guild.id}/{channel.id}/{msg.id}"
                            found_links.append(jump_link)
                            break

            except discord.errors.Forbidden:
                print(f"[-] Could not read channel {channel.name} ({ch_id}). Insufficient permissions.")
            except discord.errors.HTTPException as e:
                print(f"[-] Could not read channel {channel.name} ({ch_id}). Discord API error: {e}")
            except Exception as e:
                print(f"[-] Could not read channel {channel.name} ({ch_id}). Error: {e}")

        return found_links
