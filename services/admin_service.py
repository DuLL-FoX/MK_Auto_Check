import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, unquote_plus

from models.ban_hit import BanHit
from models.player import Player
from utils.async_utils import gather_with_concurrency, RateLimiter, AsyncCache


class PerformanceTracker:
    def __init__(self, logger):
        self.logger = logger
        self.ops_stats = {}
        self.last_summary_time = time.time()
        self.summary_interval = 60

    def record(self, operation, duration):
        if operation not in self.ops_stats:
            self.ops_stats[operation] = {'count': 0, 'total_time': 0, 'min_time': float('inf'), 'max_time': 0}
        stats = self.ops_stats[operation]
        stats['count'] += 1
        stats['total_time'] += duration
        stats['min_time'] = min(stats['min_time'], duration)
        stats['max_time'] = max(stats['max_time'], duration)

    def should_log_summary(self):
        return time.time() - self.last_summary_time >= self.summary_interval

    def get_summary(self):
        if not self.ops_stats:
            return []
        lines = ["Admin service performance summary:"]
        for op_name, stats in sorted(self.ops_stats.items()):
            count = stats['count']
            if count == 0:
                continue
            avg_time = stats['total_time'] / count
            lines.append(f"  {op_name}: {count} calls, avg {avg_time:.2f}s, "
                         f"min {stats['min_time']:.2f}s, max {stats['max_time']:.2f}s")
        self.ops_stats.clear()
        self.last_summary_time = time.time()
        return lines


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
        from utils.logging_utils import get_logger
        self.logger = logging.getLogger(__name__)
        self.perf_logger = get_logger(f"{__name__}.performance")
        self.slow_operation_threshold = 10.0
        self.perf_tracker = PerformanceTracker(self.perf_logger)

    async def login(self) -> bool:
        start_time = time.time()
        result = await asyncio.to_thread(self.admin_panel.login)
        elapsed = time.time() - start_time
        self.perf_tracker.record("login", elapsed)
        self.logger.info(f"Login completed in {elapsed:.2f}s with result: {result}")
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
            self.perf_tracker.record(func_name, elapsed)
            if elapsed > self.slow_operation_threshold:
                log_args = args_str
                if len(log_args) > 40:
                    log_args = log_args[:37] + "..."
                self.perf_logger.debug(f"Slow operation: {func_name} took {elapsed:.2f}s with args: {log_args}")
            return result

        result = await self.cache.get(cache_key, fetch_factory)
        self._request_stats["cache_hits"] += 1
        if self.perf_tracker.should_log_summary():
            for line in self.perf_tracker.get_summary():
                self.perf_logger.info(line)
        return result

    async def search_player(self, term: str, single_user: bool = True) -> Optional[Dict[str, Any]]:
        clean_term = quote_plus(unquote_plus(term))
        search_url = f"{self.base_admin_connections_url}&search={clean_term}"
        try:
            start_time = time.time()
            result = await self.fetch_with_rate_limit(
                self.admin_panel.check_account_on_site,
                search_url,
                single_user
            )
            elapsed = time.time() - start_time
            self.perf_tracker.record("search_player", elapsed)
            return result
        except Exception as e:
            self.logger.error(f"Error searching for '{term}': {str(e)}")
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
        start_time = time.time()
        results = await gather_with_concurrency(
            100,
            *[self.search_player(term) for term in limited_terms]
        )
        elapsed = time.time() - start_time
        self.perf_tracker.record("fetch_associated_players", elapsed)
        valid_results = [r for r in results if r]
        if len(valid_results) < len(limited_terms):
            self.logger.debug(f"Found {len(valid_results)} associated players from {len(limited_terms)} search terms")
        return valid_results

    async def fetch_ban_hits(self, max_pages: int = 5) -> List[BanHit]:
        start_time = time.time()
        self.logger.info(f"Fetching ban hits (max pages: {max_pages})")
        raw_ban_hits = await asyncio.to_thread(
            self.admin_panel.fetch_ban_hit_connections,
            max_pages=max_pages
        )
        if not raw_ban_hits:
            self.logger.info("No raw ban hits found")
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
                self.logger.error(f"Error creating BanHit: {str(e)}")
                return None
        ban_hits_results = await gather_with_concurrency(
            100,
            *[process_ban_hit(hit) for hit in raw_ban_hits]
        )
        valid_hits = [hit for hit in ban_hits_results if hit]
        elapsed = time.time() - start_time
        self.perf_tracker.record("fetch_ban_hits", elapsed)
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
                self.perf_tracker.record("fetch_ban_info", elapsed)
                if elapsed > self.slow_operation_threshold:
                    short_link = ban_hit.ban_hit_link.split('/')[-1]
                    self.perf_logger.debug(f"Slow ban info fetch: {elapsed:.2f}s for {short_link}")
                return result
        return await self.cache.get(cache_key, fetch_factory)

    async def batch_fetch_connections(self, identifiers: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        results = {}
        valid_identifiers = [id for id in identifiers if id != "N/A"]
        if not valid_identifiers:
            return results
        start_time = time.time()
        self.perf_logger.debug(f"Batch fetching connections for {len(valid_identifiers)} identifiers")
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
        self.perf_tracker.record("batch_fetch_connections", elapsed)
        self.perf_logger.debug(
            f"Batch fetch completed in {elapsed:.2f}s for {len(valid_identifiers)} identifiers, "
            f"got data for {len(results)} identifiers"
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
        total_requests = self._request_stats["total"]
        hit_ratio = 0
        if total_requests > 0:
            hit_ratio = self._request_stats["cache_hits"] / total_requests
        stats = {
            "rate_limiter_calls": len(self.rate_limiter.calls),
            "rate_limiter_max_calls": self.rate_limiter.max_calls,
            "request_stats": dict(self._request_stats),
            "cache_hit_ratio": hit_ratio,
            "cache_stats": cache_stats
        }
        return stats
