import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
import logging

import discord

def embed_contains_nickname(embed: discord.Embed, nickname: str) -> bool:
    lower_nick = nickname.lower()
    embed_text: List[str] = []

    if embed.title:
        embed_text.append(embed.title)
    if embed.description:
        embed_text.append(embed.description)
    if embed.footer and embed.footer.text:
        embed_text.append(embed.footer.text)
    if embed.author and embed.author.name:
        embed_text.append(embed.author.name)

    for field in embed.fields:
        if field.name:
            embed_text.append(field.name)
        if field.value:
            embed_text.append(field.value)

    contains = any(lower_nick in text.lower() for text in embed_text)
    logging.debug(f"Checking if embed contains nickname '{nickname}': {contains}")
    return contains

def extract_markdown_links(text: str) -> List[str]:
    pattern = r'\((https?://[^\)]+)\)'
    links = re.findall(pattern, text)
    logging.debug(f"Extracted markdown links from text: {links}")
    return links

def collect_unique_links_from_embed(embed: discord.Embed) -> Dict[str, str]:
    unique_links = {}
    for field in embed.fields:
        if field.name == "Name":
            continue

        links = extract_markdown_links(field.value)
        for link in links:
            if "admin.deadspace14.net/Connections" not in link:
                continue

            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            search_vals = qs.get('search', [])
            if not search_vals:
                continue

            search_value = search_vals[0]
            if search_value not in unique_links:
                unique_links[search_value] = link
                logging.debug(f"Collected unique link: {link} with search value: {search_value}")

    return unique_links
