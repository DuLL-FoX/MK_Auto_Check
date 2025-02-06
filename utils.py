import logging
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, quote_plus, urlencode, urlunparse

import discord


def embed_contains_nickname(embed: discord.Embed, nickname: str) -> bool:
    """
    Checks if a Discord embed contains a specific nickname (case-insensitive).  Improved
    to handle more edge cases and be more robust.
    """
    lower_nick = nickname.lower()

    def check_text(text: Optional[str]) -> bool:
        # Handle _EmptyEmbed explicitly.
        if isinstance(text, discord.embeds._EmptyEmbed):  # Check for _EmptyEmbed
            return False
        return text is not None and lower_nick in text.lower()

    if check_text(embed.title) or check_text(embed.description):
        return True
    if embed.footer and check_text(embed.footer.text):
        return True
    if embed.author and check_text(embed.author.name):
        return True

    for field in embed.fields:
        if check_text(field.name) or check_text(field.value):
            return True

    logging.debug(f"Checking if embed contains nickname '{nickname}': False")  # Log the negative case
    return False


def extract_markdown_links(text: str) -> List[str]:
    """
    Extracts URLs from Markdown links within a string.  Handles more variations.
    """
    # More robust regex to handle different link formats and potential whitespace.
    pattern = r'\[.*?\]\(\s*(https?://[^\s\)]+)\s*\)'
    links = re.findall(pattern, text)
    logging.debug(f"Extracted markdown links from text: {links}")
    return links


def extract_plain_links(text: str) -> List[str]:
    """Extracts plain URLs (not in markdown) from a string."""
    # This regex is a bit more comprehensive, handling more URL variations.
    pattern = r'\bhttps?://\S+\b'
    links = re.findall(pattern, text)
    logging.debug(f"Extracted plain links from text: {links}")
    return links


def normalize_url(url_str: str) -> str:
    """
    Normalizes a URL by:
    1.  Ensuring it's properly encoded.
    2.  Removing redundant query parameters (keeping only essential ones).
    3.  Sorting query parameters for consistency.
    """
    parsed = urlparse(url_str)
    query_params = parse_qs(parsed.query)

    # Define the parameters we want to keep (adjust as needed).
    essential_params = ['search', 'connection', 'showSet', 'showAccepted', 'showBanned',
                        'showWhitelist', 'showFull', 'showPanic', 'perPage', 'sort', 'pageIndex']
    filtered_params = {k: v for k, v in query_params.items() if k in essential_params}

    # Encode the values and sort the parameters.
    encoded_params = {k: [quote_plus(vi) for vi in v] for k, v in filtered_params.items()}
    sorted_params = sorted(encoded_params.items())
    encoded_query = urlencode(sorted_params, doseq=True)  # doseq=True handles lists properly.

    # Reconstruct the URL.
    new_parsed = parsed._replace(query=encoded_query)
    normalized = urlunparse(new_parsed)
    logging.debug(f"Normalized URL: {normalized}")
    return normalized

def collect_unique_links_from_embed(embed: discord.Embed) -> Dict[str, str]:
    """
    Collects *unique* and *normalized* links from a Discord embed, handling:
    - Markdown links in fields.
    - Plain URLs in the description and fields.
    - Normalizes URLs to avoid duplicates due to different parameter order or encoding.
    - Prioritizes links from fields over the description.
    - Returns a dictionary where keys are the *search terms* (or other identifying parts of the URL)
      and values are the *normalized* URLs.  This helps in de-duplication.
    """
    unique_links: Dict[str, str] = {}

    # Helper function to process and add links
    def add_link(url: str):
        if "/Connections" not in url and "Players/Info" not in url and "Bans/Hits" not in url:
            return

        normalized = normalize_url(url)  # Normalize!
        parsed = urlparse(normalized)

        # Extract a unique key.  Prioritize 'search', then 'connection', then the whole path.
        if "search=" in parsed.query:
            search_value = parse_qs(parsed.query).get("search", [""])[0]
            key = f"search:{search_value}"
        elif "connection=" in parsed.query:
            connection_value = parse_qs(parsed.query).get("connection", [""])[0]
            key = f"connection:{connection_value}"
        else:
            key = parsed.path  # Fallback to using the path.

        if key not in unique_links:  # Only add if the *key* is new.
            unique_links[key] = normalized
            logging.debug(f"Collected link: {normalized} with key: {key}")

    # Process fields (prioritize these)
    for field in embed.fields:
        if field.name == "Name":  # Skip the "Name" field as instructed.
            continue

        if field.value:
            for url in extract_markdown_links(field.value):
                add_link(url)
            for url in extract_plain_links(field.value):  # Also get plain URLs from fields.
                add_link(url)

    # Process description (if no links found yet)
    if not unique_links and embed.description:
        for url in extract_plain_links(embed.description):
            add_link(url)


    return unique_links


def extract_effective_search_term(term: str) -> str:
    """
    Если term выглядит как URL и содержит параметр 'search', то возвращает его значение.
    Иначе – возвращает исходный term.
    """
    if term.startswith("http"):
        parsed = urlparse(term)
        qs = parse_qs(parsed.query)
        if "search" in qs and qs["search"]:
            # Берём первое значение параметра search.
            return qs["search"][0]
    return term
