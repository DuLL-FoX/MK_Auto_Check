import asyncio
import logging
import time
from collections import deque
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, quote_plus

from config_system import get_config
from models.player import Player
from utils.async_utils import RateLimiter, AsyncCache


class PerformanceTracker:
    def __init__(self, logger):
        self.logger = logger
        self.ops_stats = {}
        self.last_summary_time = time.time()
        self.summary_interval = 60
        self.enabled = True

    def record(self, operation, duration):
        if not self.enabled:
            return

        if operation not in self.ops_stats:
            self.ops_stats[operation] = {'count': 0, 'total_time': 0, 'min_time': float('inf'), 'max_time': 0}
        stats = self.ops_stats[operation]
        stats['count'] += 1
        stats['total_time'] += duration
        stats['min_time'] = min(stats['min_time'], duration)
        stats['max_time'] = max(stats['max_time'], duration)

    def should_log_summary(self):
        return self.enabled and (time.time() - self.last_summary_time >= self.summary_interval)

    def get_summary(self):
        if not self.ops_stats:
            return []

        lines = ["Admin service performance summary:"]
        lines.extend([
            f"  {op_name}: {stats['count']} calls, avg {stats['total_time'] / stats['count']:.2f}s, "
            f"min {stats['min_time']:.2f}s, max {stats['max_time']:.2f}s"
            for op_name, stats in sorted(self.ops_stats.items())
            if stats['count'] > 0
        ])

        self.ops_stats.clear()
        self.last_summary_time = time.time()
        return lines


def monitor_performance(func):
    async def wrapper(self, *args, **kwargs):
        start_time = time.time()
        try:
            return await func(self, *args, **kwargs)
        finally:
            elapsed = time.time() - start_time
            self.perf_tracker.record(func.__name__, elapsed)
            if elapsed > self.slow_operation_threshold:
                args_repr = str(args[0]) if args else ""
                if len(args_repr) > 40:
                    args_repr = args_repr[:37] + "..."
                self.perf_logger.debug(f"Slow operation: {func.__name__} took {elapsed:.2f}s with args: {args_repr}")

    return wrapper


class AdminService:
    def __init__(self, admin_panel, max_concurrent_requests: int = 100) -> None:
        self.admin_panel = admin_panel
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.rate_limiter = RateLimiter(max_calls=150, period=1.0)
        self.cache = AsyncCache(max_size=20000, default_ttl=3600)
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
        self._search_cache = {}
        self._search_cache_ttl = 1800
        self._last_login_time = 0
        self._auth_ttl = 1800
        self.logger.info("AdminService initialized")

    @monitor_performance
    async def login(self) -> bool:
        current_time = time.time()
        if current_time - self._last_login_time < self._auth_ttl:
            return True

        start_time = time.time()
        result = await asyncio.to_thread(self.admin_panel.login)
        elapsed = time.time() - start_time
        self.perf_tracker.record("login", elapsed)

        if result:
            self._last_login_time = current_time

        self.logger.info(f"Login completed in {elapsed:.2f}s with result: {result}")
        return result

    @monitor_performance
    async def fetch_with_rate_limit(self, func, *args, **kwargs):
        func_name = func.__name__

        if func_name == "check_account_on_site" and args and isinstance(args[0], str) and "search=" in args[0]:
            parsed_url = urlparse(args[0])
            query_params = parse_qs(parsed_url.query)
            search_term = query_params.get('search', [''])[0]
            single_user = args[1] if len(args) > 1 else kwargs.get('single_user', False)
            cache_key = f"{func_name}:search={search_term}:single_user={single_user}"
        else:
            args_str = ','.join(str(a) for a in args if isinstance(a, (str, int, float, bool)) or len(str(a)) < 100)
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
                log_args = str(args[0]) if args else ""
                if len(log_args) > 40:
                    log_args = log_args[:37] + "..."
                self.perf_logger.debug(f"Slow operation: {func_name} took {elapsed:.2f}s with args: {log_args}")

            return result

        result = await self.cache.get(cache_key, fetch_factory)
        self._request_stats["cache_hits"] += 1

        if func_name == "check_account_on_site" and isinstance(result, dict):
            required_keys = ['status', 'nicknames', 'associated_ips', 'associated_hwids', 'user_id']
            missing_keys = [k for k in required_keys if k not in result]
            if missing_keys:
                self.logger.warning(f"Missing keys in check_account_on_site result: {missing_keys}")

        if self.perf_tracker.should_log_summary():
            for line in self.perf_tracker.get_summary():
                self.perf_logger.info(line)

        return result

    @monitor_performance
    async def search_player(self, term: str, single_user: bool = True, max_depth: int = None) -> Optional[
        Dict[str, Any]]:
        cfg = get_config()
        max_depth = max_depth if max_depth is not None else cfg.scan.search_max_depth
        start_time = time.time()
        self.logger.info(f"Searching for player with term: '{term}' (max depth: {max_depth})")

        cache_key = f"search_player:{term}:{single_user}:{max_depth}"
        current_time = time.time()
        if cache_key in self._search_cache:
            cached_result, timestamp = self._search_cache[cache_key]
            if current_time - timestamp < self._search_cache_ttl:
                self.logger.info(f"Using cached search result for '{term}'")
                return cached_result

        processed_terms = set()
        queued_terms = set([term])
        queue = deque([(term, 0)])
        merged_result = None
        stats = {"searches": 0, "depth_counts": {}}

        while queue:
            batch_size = min(5, len(queue))
            batch = []

            for _ in range(batch_size):
                if not queue:
                    break
                batch.append(queue.popleft())

            batch_tasks = []
            for current_term, current_depth in batch:
                if current_term in processed_terms:
                    continue

                processed_terms.add(current_term)
                stats["searches"] += 1
                stats["depth_counts"][current_depth] = stats["depth_counts"].get(current_depth, 0) + 1

                batch_tasks.append(self._process_search_term(
                    current_term,
                    current_depth,
                    single_user,
                    max_depth,
                    processed_terms,
                    queued_terms
                ))

            if not batch_tasks:
                continue

            batch_results = await asyncio.gather(*batch_tasks)

            for result in batch_results:
                if not result or not result.get('result'):
                    continue

                if merged_result is None:
                    merged_result = result['result']
                else:
                    self._merge_search_results(merged_result, result['result'])

                for new_term, new_depth in result.get('new_terms', []):
                    queue.append((new_term, new_depth))
                    queued_terms.add(new_term)

        elapsed = time.time() - start_time
        self.logger.info(
            f"Search completed in {elapsed:.2f}s: {stats['searches']} unique searches performed, "
            f"depth distribution: {stats['depth_counts']}"
        )

        self._search_cache[cache_key] = (merged_result, current_time)

        if len(self._search_cache) > 1000:
            self._clean_search_cache()

        return merged_result

    async def _process_search_term(self, current_term, current_depth, single_user, max_depth, processed_terms,
                                   queued_terms):
        try:
            clean_term = quote_plus(current_term)
            search_url = f"{self.base_admin_connections_url}&search={clean_term}"
            self.logger.info(f"Searching for player with term: '{current_term}' (depth: {current_depth})")

            result = await self.fetch_with_rate_limit(
                self.admin_panel.check_account_on_site,
                search_url,
                single_user
            )

            if not result:
                self.logger.info(f"No results found for term: '{current_term}'")
                return None

            if current_depth >= max_depth:
                return {'result': result, 'new_terms': []}

            identifiers = self._extract_prioritized_identifiers(
                result,
                current_term,
                processed_terms,
                queued_terms
            )

            limit = self._get_search_limit_for_depth(current_depth)
            limited_identifiers = identifiers[:limit]

            new_terms = [(identifier, current_depth + 1) for identifier in limited_identifiers]
            self.logger.info(f"Added {len(new_terms)} identifiers to search at depth {current_depth + 1}")

            return {'result': result, 'new_terms': new_terms}

        except Exception as e:
            self.logger.error(f"Error searching for '{current_term}': {str(e)}")
            return None

    def _clean_search_cache(self):
        current_time = time.time()
        to_remove = []

        for key, (_, timestamp) in self._search_cache.items():
            if current_time - timestamp > self._search_cache_ttl:
                to_remove.append(key)

        for key in to_remove:
            del self._search_cache[key]

        if len(self._search_cache) > 900:
            sorted_items = sorted(self._search_cache.items(), key=lambda x: x[1][1])
            for key, _ in sorted_items[:100]:
                del self._search_cache[key]

    def _extract_prioritized_identifiers(
            self,
            result: Dict[str, Any],
            current_term: str,
            processed_terms: Set[str],
            queued_terms: Set[str]
    ) -> List[str]:
        prioritized = []
        processed_set = processed_terms
        queued_set = queued_terms

        def add_if_new(identifier, priority):
            if (identifier and
                    identifier != "N/A" and
                    identifier != current_term and
                    identifier not in processed_set and
                    identifier not in queued_set):
                prioritized.append((priority, identifier))

        user_id = result.get("user_id")
        add_if_new(user_id, 0)

        associated_hwids = result.get("associated_hwids", {})
        for hwid in associated_hwids:
            add_if_new(hwid, 1)

        associated_ips = result.get("associated_ips", {})
        for ip in associated_ips:
            add_if_new(ip, 2)

        nicknames = result.get("nicknames", [])
        for nickname in nicknames:
            add_if_new(nickname, 3)

        prioritized.sort()
        return [identifier for _, identifier in prioritized]

    def _get_search_limit_for_depth(self, depth: int) -> int:
        cfg = get_config()
        if depth == 0:
            return cfg.scan.search_limit_root
        elif depth == 1:
            return cfg.scan.search_limit_level1
        elif depth == 2:
            return cfg.scan.search_limit_level2
        else:
            return cfg.scan.search_limit_default

    def _merge_search_results(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        if not target or not source:
            return

        for key in ['associated_ips', 'associated_hwids', 'nicknames', 'shared_hwid_nicknames']:
            if key not in target:
                target[key] = {} if key in ['associated_ips', 'associated_hwids'] else []

        source_ips = source.get('associated_ips', {})
        for ip, nicks in source_ips.items():
            if ip not in target['associated_ips']:
                target['associated_ips'][ip] = nicks
            else:
                existing_nicks = set(target['associated_ips'][ip])
                existing_nicks.update(nicks)
                target['associated_ips'][ip] = list(existing_nicks)

        source_hwids = source.get('associated_hwids', {})
        for hwid, nicks in source_hwids.items():
            if hwid not in target['associated_hwids']:
                target['associated_hwids'][hwid] = nicks
            else:
                existing_nicks = set(target['associated_hwids'][hwid])
                existing_nicks.update(nicks)
                target['associated_hwids'][hwid] = list(existing_nicks)

        for key in ['nicknames', 'shared_hwid_nicknames']:
            if key in source:
                target_items = set(target.get(key, []))
                source_items = source.get(key, [])
                target_items.update(source_items)
                target[key] = list(target_items)

        if 'ban_reasons' in source:
            if 'ban_reasons' not in target:
                target['ban_reasons'] = []

            existing_ban_reason_keys = set()
            for ban_info in target['ban_reasons']:
                if isinstance(ban_info, dict) and 'reason' in ban_info and 'username' in ban_info:
                    existing_ban_reason_keys.add((ban_info['reason'], ban_info['username']))
                elif isinstance(ban_info, str):
                    existing_ban_reason_keys.add((ban_info, "Unknown"))

            for ban_info in source.get('ban_reasons', []):
                if isinstance(ban_info, dict) and 'reason' in ban_info and 'username' in ban_info:
                    key = (ban_info['reason'], ban_info['username'])
                    if key not in existing_ban_reason_keys:
                        target['ban_reasons'].append(ban_info)
                        existing_ban_reason_keys.add(key)
                elif isinstance(ban_info, str):
                    key = (ban_info, "Unknown")
                    if key not in existing_ban_reason_keys:
                        target['ban_reasons'].append({
                            'reason': ban_info,
                            'username': "Unknown"
                        })
                        existing_ban_reason_keys.add(key)

        target['ban_counts'] = max(
            target.get('ban_counts', 0),
            source.get('ban_counts', 0)
        )

        status_priority = {
            'banned': 3,
            'suspicious': 2,
            'clean': 1,
            'unknown': 0
        }
        target_status = target.get('status', 'unknown').lower()
        source_status = source.get('status', 'unknown').lower()
        if status_priority.get(source_status, 0) > status_priority.get(target_status, 0):
            target['status'] = source.get('status')

        if 'denied_banned_connections' in source:
            target_denied = target.get('denied_banned_connections', [])
            source_denied = source.get('denied_banned_connections', [])
            denied_set = {
                (conn.get('user_name', ''), conn.get('time', ''), conn.get('ip_address', ''))
                for conn in target_denied
            }
            for conn in source_denied:
                conn_key = (conn.get('user_name', ''), conn.get('time', ''), conn.get('ip_address', ''))
                if conn_key not in denied_set:
                    target_denied.append(conn)
                    denied_set.add(conn_key)
            target['denied_banned_connections'] = target_denied

    def convert_to_player(self, account_info: Dict[str, Any]) -> Player:
        if not account_info:
            self.logger.warning("Empty account_info provided to convert_to_player")
            return Player(user_id="N/A", nicknames=[], status="unknown")

        required_fields = ['user_id', 'nicknames', 'status']
        missing_fields = [field for field in required_fields if field not in account_info]
        if missing_fields:
            self.logger.warning(f"Missing required fields in account_info: {missing_fields}")

        ban_reasons = account_info.get("ban_reasons", [])
        formatted_ban_reasons = []
        for reason in ban_reasons:
            if isinstance(reason, dict) and "reason" in reason and "username" in reason:
                formatted_ban_reasons.append(reason)
            elif isinstance(reason, str):
                formatted_ban_reasons.append({
                    "reason": reason,
                    "username": account_info.get("nicknames", ["Unknown"])[0] if account_info.get(
                        "nicknames") else "Unknown"
                })

        player = Player(
            user_id=account_info.get("user_id", "N/A"),
            nicknames=account_info.get("nicknames", []),
            status=account_info.get("status", "unknown"),
            ban_counts=account_info.get("ban_counts", 0),
            ban_reasons=formatted_ban_reasons,
            connection_link=account_info.get("connection_link", "N/A"),
            associated_ips=account_info.get("associated_ips", {}),
            associated_hwids=account_info.get("associated_hwids", {}),
            shared_hwid_nicknames=account_info.get("shared_hwid_nicknames", []),
            hwid_erased=account_info.get("hwid_erased", False)
        )

        if "denied_banned_connections" in account_info:
            player.denied_logins = account_info["denied_banned_connections"]

        return player
