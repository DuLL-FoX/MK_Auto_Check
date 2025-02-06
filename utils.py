import logging
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote

import discord


def embed_contains_nickname(embed: discord.Embed, nickname: str) -> bool:
    lower_nick = nickname.lower()

    def check_text(text: Optional[str]) -> bool:
        if isinstance(text, discord.embeds._EmptyEmbed):
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

    logging.debug(f"Checking if embed contains nickname '{nickname}': False")
    return False


def extract_markdown_links(text: str) -> List[str]:
    pattern = r'\[.*?\]\(\s*(https?://[^\s\)]+)\s*\)'
    links = re.findall(pattern, text)
    logging.debug(f"Extracted markdown links from text: {links}")
    return links


def extract_plain_links(text: str) -> List[str]:
    pattern = r'\bhttps?://\S+\b'
    links = re.findall(pattern, text)
    logging.debug(f"Extracted plain links from text: {links}")
    return links


def normalize_url(url_str: str) -> str:
    try:
        parsed = urlparse(url_str)
        query_params = parse_qs(parsed.query)

        essential_params = ['search', 'connection', 'showSet', 'showAccepted', 'showBanned',
                            'showWhitelist', 'showFull', 'showPanic', 'perPage', 'sort', 'pageIndex']
        filtered_params = {k: v for k, v in query_params.items() if k in essential_params}

        encoded_params = filtered_params
        sorted_params = sorted(encoded_params.items())
        encoded_query = urlencode(sorted_params, doseq=True)

        new_parsed = parsed._replace(query=encoded_query)
        normalized = urlunparse(new_parsed)
        logging.debug(f"Normalized URL: {normalized}")
        return normalized
    except Exception as e:
        logging.warning(f"URL normalization failed for '{url_str}': {e}. Returning original URL.")
        return url_str



def collect_unique_links_from_embed(embed: discord.Embed) -> Dict[str, str]:
    unique_links: Dict[str, str] = {}

    def add_link(url: str):
        if "/Connections" not in url and "Players/Info" not in url and "Bans/Hits" not in url:
            return

        normalized = normalize_url(url)
        parsed = urlparse(normalized)

        if "search=" in parsed.query:
            search_value = parse_qs(parsed.query).get("search", [""])[0]
            key = f"search:{search_value}"
        elif "connection=" in parsed.query:
            connection_value = parse_qs(parsed.query).get("connection", [""])[0]
            key = f"connection:{connection_value}"
        else:
            key = parsed.path

        if key not in unique_links:
            unique_links[key] = normalized
            logging.debug(f"Collected link: {normalized} with key: {key}")

    for field in embed.fields:
        if field.name == "Name":
            continue

        if field.value:
            for url in extract_markdown_links(field.value):
                add_link(url)
            for url in extract_plain_links(field.value):
                add_link(url)

    if not unique_links and embed.description:
        for url in extract_plain_links(embed.description):
            add_link(url)

    return unique_links


def extract_effective_search_term(term: str) -> str:
    if term.startswith("http"):
        try:
            parsed = urlparse(term)
            raw_query = parsed.query
            import re
            m = re.search(r'(?:^|&)search=([^&]+)', raw_query)
            if m:
                raw_value = m.group(1)
                decoded_value = unquote(raw_value)
                return decoded_value
        except Exception as e:
            logging.warning(f"Error parsing URL '{term}' to extract search term: {e}. Returning original term.")
            return term
    return term