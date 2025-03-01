import json
import logging
import os
from typing import Dict
from models.complaint import ComplaintChannel, ComplaintMessage

COMPLAINT_CACHE_FILENAME = "complaint_message_cache.json"


class CacheService:
    def __init__(self, cache_filename: str = COMPLAINT_CACHE_FILENAME) -> None:
        self.cache_filename = cache_filename

    def load_complaint_cache(self) -> Dict[int, ComplaintChannel]:
        logging.info(f"Loading complaint message cache from {self.cache_filename}...")
        complaint_channels: Dict[int, ComplaintChannel] = {}
        if not os.path.exists(self.cache_filename):
            logging.info("Complaint message cache file not found.")
            return complaint_channels
        try:
            with open(self.cache_filename, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            for ch_str_id, ch_data in raw_data.items():
                try:
                    ch_id = int(ch_str_id)
                    messages = []
                    for msg in ch_data.get("messages", []):
                        complaint_msg = ComplaintMessage(
                            id=msg["id"],
                            content=msg["content"],
                            embeds=msg.get("embeds", []),
                            channel_id=ch_str_id,
                            guild_id=ch_data.get("guild_id", "0")
                        )
                        messages.append(complaint_msg)
                    complaint_channels[ch_id] = ComplaintChannel(
                        id=ch_str_id,
                        name=ch_data.get("name", f"Channel {ch_str_id}"),
                        guild_id=ch_data.get("guild_id", "0"),
                        messages=messages,
                        last_cached_id=ch_data.get("last_cached_id")
                    )
                except (ValueError, TypeError, KeyError) as e:
                    logging.warning(f"Error loading cache for channel {ch_str_id}: {e}. Skipping channel cache.")
            logging.info(f"Loaded cache for {len(complaint_channels)} channel(s).")
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error loading complaint cache: {e}. Cache file might be corrupted.")
        except Exception as e:
            logging.error(f"Error loading complaint cache: {e}", exc_info=True)
        return complaint_channels

    def save_complaint_cache(self, complaint_channels: Dict[int, ComplaintChannel]) -> bool:
        logging.info(f"Saving complaint message cache to {self.cache_filename}...")
        cache_data = {}
        for ch_id, channel in complaint_channels.items():
            cache_data[str(ch_id)] = {
                "name": channel.name,
                "guild_id": channel.guild_id,
                "messages": [
                    {
                        "id": msg.id,
                        "content": msg.content,
                        "embeds": msg.embeds
                    }
                    for msg in channel.messages
                ],
                "last_cached_id": channel.last_cached_id
            }
        try:
            with open(self.cache_filename, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=4)
            logging.info(f"Complaint message cache saved to '{self.cache_filename}'.")
            return True
        except IOError as e:
            logging.error(f"Error saving complaint cache: {e}")
            return False
