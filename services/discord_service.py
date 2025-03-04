import logging
import re
from typing import List, Dict, Any, Optional

import discord

from models.complaint import ComplaintChannel, ComplaintMessage
from models.message import DiscordMessage
from utils.embed_utils import collect_unique_links_from_embed


class DiscordService:
    def __init__(self, client: discord.Client) -> None:
        self.target_channel_id = None
        self.client = client
        self.target_channel: Optional[discord.TextChannel] = None
        self.complaint_channels: Dict[int, discord.TextChannel] = {}

    async def setup_channels(self, target_channel_id: int, complaint_channel_ids: List[int]) -> bool:
        success = True
        if target_channel_id:
            self.target_channel_id = target_channel_id
            self.target_channel = self.client.get_channel(target_channel_id)
            if not self.target_channel:
                logging.error(f"Target channel not found: {target_channel_id}")
                success = False
            else:
                logging.info(f"Found target channel: '{self.target_channel.name}' ({target_channel_id})")
        for ch_id in complaint_channel_ids:
            channel = self.client.get_channel(ch_id)
            if not channel:
                logging.warning(f"Complaint channel not found: {ch_id}")
                continue
            self.complaint_channels[ch_id] = channel
            logging.info(f"Found complaint channel: '{channel.name}' ({ch_id})")
        return success

    async def scan_target_channel(self, message_limit, filter_func):
        messages = []
        if not self.target_channel_id:
            logging.error("Target channel ID is not set")
            return messages
        channel = self.client.get_channel(int(self.target_channel_id))
        if not channel:
            logging.error(f"Could not find channel with ID {self.target_channel_id}")
            return messages
        scan_limit = max(100, message_limit * 10)
        scanned_count = 0
        async for msg in channel.history(limit=scan_limit):
            scanned_count += 1
            if filter_func(msg):
                embed_links = {}
                for embed in msg.embeds:
                    links = collect_unique_links_from_embed(embed)
                    embed_links.update(links)
                embed_titles = [embed.title for embed in msg.embeds if embed.title]
                message = DiscordMessage(
                    id=msg.id,
                    channel_id=msg.channel.id,
                    author_id=msg.author.id,
                    author_name=str(msg.author),
                    content=msg.content,
                    embed_titles=embed_titles,
                    embed_links=embed_links,
                    guild_id=msg.guild.id,
                    created_at=msg.created_at.isoformat()
                )
                messages.append(message)
                if len(messages) >= message_limit:
                    logging.info(f"Found {len(messages)} matching messages after scanning {scanned_count} messages")
                    return messages
        logging.info(f"Found {len(messages)} matching messages after scanning {scanned_count} messages")
        return messages

    async def update_complaint_cache(self, complaint_channels: Dict[int, ComplaintChannel],
                                     history_limit: int) -> Dict[int, ComplaintChannel]:
        logging.info("Updating complaint message cache for all complaint channels...")
        updated_channels = complaint_channels.copy()
        for ch_id, discord_channel in self.complaint_channels.items():
            channel_cache = updated_channels.get(ch_id, ComplaintChannel(
                id=str(ch_id),
                name=discord_channel.name,
                guild_id=str(discord_channel.guild.id)
            ))
            cached_message_ids = {msg.id for msg in channel_cache.messages}
            last_cached_id = channel_cache.last_cached_id
            history_kwargs = {"oldest_first": False}
            if last_cached_id:
                history_kwargs["after"] = discord.Object(id=int(last_cached_id))
            else:
                history_kwargs["limit"] = history_limit
            new_messages = []
            try:
                async for msg in discord_channel.history(**history_kwargs):
                    if str(msg.id) not in cached_message_ids:
                        complaint_msg = ComplaintMessage(
                            id=str(msg.id),
                            content=msg.content,
                            embeds=[
                                {k: e.to_dict()[k] for k in ["title", "description", "fields"]
                                 if k in e.to_dict()}
                                for e in msg.embeds
                            ],
                            channel_id=str(discord_channel.id),
                            guild_id=str(discord_channel.guild.id)
                        )
                        new_messages.append(complaint_msg)
                if new_messages:
                    logging.info(
                        f"Fetched {len(new_messages)} new messages for channel {discord_channel.name} ({ch_id}).")
                    channel_cache.messages.extend(new_messages)
                    channel_cache.messages.sort(key=lambda x: int(x.id), reverse=True)
                    channel_cache.messages = channel_cache.messages[:history_limit]
                    channel_cache.last_cached_id = channel_cache.messages[
                        0].id if channel_cache.messages else last_cached_id
                else:
                    logging.info(f"No new messages found in channel {discord_channel.name} ({ch_id}).")
            except discord.Forbidden:
                logging.warning(f"Insufficient permissions to read channel {discord_channel.name} ({ch_id}).")
            except discord.HTTPException as e:
                logging.error(f"Discord API error reading channel {discord_channel.name} ({ch_id}): {e}")
            except Exception as e:
                logging.error(f"Unexpected error reading channel {discord_channel.name} ({ch_id}): {e}", exc_info=True)
            updated_channels[ch_id] = channel_cache
        return updated_channels

    async def find_nickname_mentions(
            self,
            nicknames: List[str],
            complaint_channels: Dict[int, ComplaintChannel],
            search_term: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        import asyncio

        if not nicknames or not complaint_channels:
            return []

        result = []
        patterns = {}
        for nickname in nicknames:
            if not nickname or not isinstance(nickname, str):
                continue
            try:
                escaped_nick = re.escape(nickname)
                patterns[nickname] = re.compile(r'\b' + escaped_nick + r'\b', re.IGNORECASE)
            except Exception as e:
                logging.warning(f"Error compiling regex for nickname '{nickname}': {e}")
                continue

        search_pattern = None
        if search_term and isinstance(search_term, str):
            try:
                search_pattern = re.compile(re.escape(search_term), re.IGNORECASE)
                logging.info(f"Filtering complaints for search term: '{search_term}'")
            except Exception as e:
                logging.warning(f"Error compiling regex for search term '{search_term}': {e}")
                search_term = None

        message_count = 0
        for channel_id, channel_data in complaint_channels.items():
            if not channel_data.messages:
                continue

            guild_id = channel_data.guild_id
            if not guild_id or guild_id == "0":
                discord_channel = self.client.get_channel(int(channel_id))
                if discord_channel and hasattr(discord_channel, 'guild'):
                    guild_id = str(discord_channel.guild.id)
                    channel_data.guild_id = guild_id

            for message in channel_data.messages:
                message_count += 1
                if message_count % 20 == 0:
                    await asyncio.sleep(0)

                try:
                    searchable_text = message.content or ""

                    if hasattr(message, 'embeds') and message.embeds:
                        for embed in message.embeds:
                            if isinstance(embed, dict):
                                if 'description' in embed and embed['description']:
                                    searchable_text += " " + str(embed['description'])

                                if 'fields' in embed and isinstance(embed['fields'], list):
                                    for field in embed['fields']:
                                        if isinstance(field, dict):
                                            if 'name' in field and field['name']:
                                                searchable_text += " " + str(field['name'])
                                            if 'value' in field and field['value']:
                                                searchable_text += " " + str(field['value'])

                                if 'title' in embed and embed['title']:
                                    searchable_text += " " + str(embed['title'])

                    if not searchable_text:
                        continue

                    if search_term and search_term.lower() not in searchable_text.lower():
                        continue

                    mentioned_nicknames = []
                    for nickname, pattern in patterns.items():
                        if nickname.lower() in searchable_text.lower():
                            try:
                                if pattern.search(searchable_text):
                                    mentioned_nicknames.append(nickname)
                            except Exception as e:
                                logging.warning(f"Error searching for nickname '{nickname}': {e}")
                                mentioned_nicknames.append(nickname)

                    if mentioned_nicknames:
                        result.append({
                            "link": f"https://discord.com/channels/{guild_id}/{channel_id}/{message.id}",
                            "channel": channel_data.name,
                            "content": searchable_text,
                            "message_id": message.id,
                            "message_id_as_timestamp": int(message.id),
                            "author": message.author.name if hasattr(message, 'author') else "Unknown",
                            "mentioned_nicknames": mentioned_nicknames
                        })
                except Exception as e:
                    logging.warning(f"Error processing message {message.id}: {e}")
                    continue

                if len(result) % 10 == 0 and len(result) > 0:
                    await asyncio.sleep(0)

        result.sort(key=lambda x: x.get("message_id_as_timestamp", 0), reverse=True)

        if search_term:
            logging.info(f"Found {len(result)} complaints containing '{search_term}' that mention the player")

        return result