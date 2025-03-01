import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, unquote_plus
from models.ban_hit import BanHit
from models.player import Player
from utils.async_utils import gather_with_concurrency, RateLimiter, AsyncCache

logger = logging.getLogger(__name__)


class AdminService:
    def __init__(self, admin_panel, max_concurrent_requests: int = 100) -> None:
        self.admin_panel = admin_panel
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.rate_limiter = RateLimiter(max_calls=150, period=1.0)
        self.cache = AsyncCache(max_size=10000)
        self.base_admin_connections_url = (
            "https://admin.deadspace14.net/Connections?showSet=true&showAccepted=true&showBanned=true"
            "&showWhitelist=true&showFull=true&showPanic=true&perPage=2000"
        )
        self._request_stats = {"total": 0, "cache_hits": 0, "cache_misses": 0}
        self.perf_logger = logging.getLogger(f"{__name__}.performance")
        if not self.perf_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.perf_logger.addHandler(handler)
            self.perf_logger.setLevel(logging.INFO)

    async def login(self) -> bool:
        start_time = time.time()
        result = await asyncio.to_thread(self.admin_panel.login)
        elapsed = time.time() - start_time
        logger.info(f"Login completed in {elapsed:.2f}s with result: {result}")
        return result

    async def fetch_with_rate_limit(self, func, *args, **kwargs):
        func_name = func.__name__
        args_str = ','.join(str(a) for a in args if len(str(a)) < 100)
        cache_key = f"{func_name}:{args_str}"
        self._request_stats["total"] += 1

        async def fetch_factory():
            self._request_stats["cache_misses"] += 1
            start_time = time.time()
            async with self.semaphore:
                await self.rate_limiter.acquire()
                result = await asyncio.to_thread(func, *args, **kwargs)
            elapsed = time.time() - start_time
            if elapsed > 1.0:
                self.perf_logger.info(f"Slow operation: {func_name} took {elapsed:.2f}s with args: {args_str[:100]}")
            return result

        result = await self.cache.get(cache_key, fetch_factory)
        self._request_stats["cache_hits"] += 1
        return result

    async def search_player(self, term: str, single_user: bool = True) -> Optional[Dict[str, Any]]:
        clean_term = quote_plus(unquote_plus(term))
        search_url = f"{self.base_admin_connections_url}&search={clean_term}"
        try:
            result = await self.fetch_with_rate_limit(
                self.admin_panel.check_account_on_site,
                search_url,
                single_user
            )
            return result
        except Exception as e:
            logger.error(f"Error searching for '{term}': {str(e)}")
            return None

    async def fetch_associated_players(self, player_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        search_terms = set()
        processed_terms = set()
        for ip in player_info.get("associated_ips", {}):
            if ip != "N/A" and ip not in processed_terms:
                search_terms.add(ip)
                processed_terms.add(ip)
        for hwid in player_info.get("associated_hwids", {}):
            if hwid != "N/A" and hwid not in processed_terms:
                search_terms.add(hwid)
                processed_terms.add(hwid)
        if not search_terms:
            return []
        limited_terms = list(search_terms)[:20]
        results = await gather_with_concurrency(
            100,
            *[self.search_player(term) for term in limited_terms]
        )
        return [r for r in results if r]

    async def fetch_ban_hits(self, max_pages: int = 5) -> List[BanHit]:
        start_time = time.time()
        logger.info(f"Fetching ban hits (max pages: {max_pages})")
        raw_ban_hits = await asyncio.to_thread(
            self.admin_panel.fetch_ban_hit_connections,
            max_pages=max_pages
        )
        if not raw_ban_hits:
            logger.info("No raw ban hits found")
            return []

        async def process_ban_hit(hit):
            try:
                return BanHit(
                    ban_hit_id=hit.get("connection_id", "N/A"),
                    ban_hit_link=hit.get("ban_hits_link", "N/A"),
                    user_id=hit.get("user_id", "N/A"),
                    user_name=hit.get("user_name", ""),
                    ip_address=hit.get("ip_address", "N/A"),
                    hwid=hit.get("hwid", "N/A"),
                    time=datetime.strptime(hit.get("time", "1970-01-01 00:00:00"), "%Y-%m-%d %H:%M:%S"),
                    hwid_erased=not hit.get("hwid") or hit.get("hwid").strip() == ""
                )
            except (ValueError, KeyError) as e:
                logger.error(f"Error creating BanHit: {str(e)}")
                return None

        ban_hits_results = await gather_with_concurrency(
            100,
            *[process_ban_hit(hit) for hit in raw_ban_hits]
        )
        valid_hits = [hit for hit in ban_hits_results if hit]
        elapsed = time.time() - start_time
        self.perf_logger.info(
            f"Processed {len(valid_hits)} ban hits (from {len(raw_ban_hits)} raw hits) in {elapsed:.2f}s"
        )
        return valid_hits

    async def fetch_ban_info(self, ban_hit: BanHit) -> Dict[str, Any]:
        if ban_hit.ban_hit_link == "N/A":
            return {}
        cache_key = f"ban_info:{ban_hit.ban_hit_link}"

        async def fetch_factory():
            async with self.semaphore:
                await self.rate_limiter.acquire()
                start_time = time.time()
                result = await asyncio.to_thread(
                    self.admin_panel.fetch_ban_info,
                    ban_hit.ban_hit_link
                )
                elapsed = time.time() - start_time
                if elapsed > 1.0:
                    self.perf_logger.info(f"Slow ban info fetch: {elapsed:.2f}s for {ban_hit.ban_hit_link}")
                return result

        return await self.cache.get(cache_key, fetch_factory)

    async def batch_fetch_connections(self, identifiers: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        results = {}
        valid_identifiers = [id for id in identifiers if id != "N/A"]
        if not valid_identifiers:
            return results
        start_time = time.time()
        self.perf_logger.info(f"Batch fetching connections for {len(valid_identifiers)} identifiers")

        async def fetch_for_identifier(identifier):
            connections = await self.fetch_with_rate_limit(
                self.admin_panel.fetch_connections_for_user,
                identifier
            )
            return identifier, connections

        fetch_results = await gather_with_concurrency(
            100,
            *[fetch_for_identifier(identifier) for identifier in valid_identifiers]
        )
        for identifier, connections in fetch_results:
            if connections:
                results[identifier] = connections
        elapsed = time.time() - start_time
        self.perf_logger.info(
            f"Batch fetch completed in {elapsed:.2f}s for {len(valid_identifiers)} identifiers, got data for {len(results)} identifiers"
        )
        return results

    def convert_to_player(self, account_info: Dict[str, Any]) -> Player:
        if not account_info:
            return Player(user_id="N/A", nicknames=[], status="unknown")
        player = Player(
            user_id=account_info.get("user_id", "N/A"),
            nicknames=account_info.get("nicknames", []),
            status=account_info.get("status", "unknown"),
            ban_counts=account_info.get("ban_counts", 0),
            ban_reasons=account_info.get("ban_reasons", []),
            suspected_vpn=account_info.get("suspected_vpn", False),
            connection_link=account_info.get("connection_link", "N/A"),
            associated_ips=account_info.get("associated_ips", {}),
            associated_hwids=account_info.get("associated_hwids", {}),
            shared_hwid_nicknames=account_info.get("shared_hwid_nicknames", []),
            hwid_erased=account_info.get("hwid_erased", False)
        )
        if "denied_banned_connections" in account_info:
            player.denied_logins = account_info["denied_banned_connections"]
        return player

    async def get_cache_stats(self) -> Dict[str, Any]:
        cache_stats = self.cache.get_stats()
        stats = {
            "rate_limiter_calls": len(self.rate_limiter.calls),
            "rate_limiter_max_calls": self.rate_limiter.max_calls,
            "request_stats": dict(self._request_stats),
            "cache_hit_ratio": (self._request_stats["cache_hits"] / self._request_stats["total"])
            if self._request_stats["total"] > 0 else 0,
            "cache_stats": cache_stats
        }
        return stats
