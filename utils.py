import logging
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, quote_plus, urlencode, urlunparse

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
        for original_link in links:
            if "/Connections" not in original_link:
                continue

            parsed = urlparse(original_link)

            search_value = None
            query_parts = parsed.query.split('&')
            for part in query_parts:
                if part.startswith('search='):
                    search_value = part.split('=', 1)[1]
                    break

            if not search_value:
                continue

            encoded_search = quote_plus(search_value)

            new_query = []
            for part in query_parts:
                if part.startswith('search='):
                    new_query.append(f"search={encoded_search}")
                else:
                    new_query.append(part)

            new_parsed = parsed._replace(query="&".join(new_query))
            reconstructed_link = urlunparse(new_parsed)

            if search_value not in unique_links:
                unique_links[search_value] = reconstructed_link
                logging.debug(f"Collected corrected link: {reconstructed_link}")

    return unique_links