import asyncio
import hashlib
import logging
import time
from collections import deque, OrderedDict
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import quote_plus

from admin_panel import N_A
from config_system import get_config
from models.player import Player
from utils.async_utils import RateLimiter, AsyncCache
from utils.performance_monitor import monitor_performance, PerformanceTracker


class AdminService:
    def __init__(self, admin_panel, max_concurrent_requests: int = 100) -> None:
        self.admin_panel = admin_panel
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.rate_limiter = RateLimiter(max_calls=150,
                                        period=1.0)
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

        self._search_cache: OrderedDict[
            str, Tuple[Optional[Dict[str, Any]], float]] = OrderedDict()
        cfg = get_config()
        self._search_cache_max_size = getattr(cfg.scan, 'search_cache_max_size', 1000)
        self._search_cache_ttl = getattr(cfg.scan, 'search_cache_ttl', 1800)

        self._login_lock = asyncio.Lock()
        self._last_login_time = 0
        self._auth_ttl = 1800
        self.logger.info("AdminService initialized")

    @monitor_performance
    async def login(self) -> bool:
        async with self._login_lock:
            current_time = time.time()
            if self.admin_panel._is_authenticated and (current_time - self._last_login_time < self._auth_ttl):
                self.logger.debug("Login token still considered valid by AdminService and panel likely still auth'd.")
                return True

            self.logger.info("Attempting AdminPanel login via AdminService.")
            start_time = time.time()
            result = await asyncio.to_thread(self.admin_panel.login)
            elapsed = time.time() - start_time
            self.perf_tracker.record("admin_panel_login", elapsed)

            if result:
                self._last_login_time = current_time
                self.logger.info(f"AdminPanel login successful in {elapsed:.2f}s.")
            else:
                self.logger.error(f"AdminPanel login failed after {elapsed:.2f}s.")
            return result

    @monitor_performance
    async def fetch_with_rate_limit(self, func, *args, **kwargs):
        func_name = func.__name__ if hasattr(func, '__name__') else str(func)
        arg_parts_str = ":".join(map(str, args))
        kwarg_parts_str = ":".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
        raw_cache_key = f"{func_name}:{arg_parts_str}:{kwarg_parts_str}"

        if len(raw_cache_key) > 256:
            cache_key = hashlib.sha256(raw_cache_key.encode('utf-8')).hexdigest()
        else:
            cache_key = raw_cache_key

        self._request_stats["total"] += 1

        async def factory_coro():
            self.logger.debug(
                f"Cache miss for key: {cache_key} (raw: {raw_cache_key[:100]}...). Executing: {func_name}")
            self._request_stats["cache_misses"] += 1

            if not await self.login():
                self.logger.error(f"Login failed for {func_name}, cannot proceed.")
                return None

            op_start_time = time.time()
            async with self.semaphore:
                await self.rate_limiter.acquire()
                call_result = await asyncio.to_thread(func, *args, **kwargs)

            op_elapsed_time = time.time() - op_start_time
            self.perf_tracker.record(func_name, op_elapsed_time)

            if op_elapsed_time > self.slow_operation_threshold:
                log_args_preview = raw_cache_key[:120] + "..." if len(raw_cache_key) > 120 else raw_cache_key
                self.perf_logger.warning(
                    f"Slow operation: {func_name} took {op_elapsed_time:.2f}s. Args preview: {log_args_preview}"
                )
            return call_result

        result = await self.cache.get(cache_key, factory_coro)

        if func_name == "check_account_on_site" and isinstance(result, dict) and kwargs.get('single_user'):
            required_keys = ['status', 'nicknames', 'associated_ips', 'associated_hwids', 'user_id']
            missing_or_none_keys = [k for k in required_keys if k not in result or result[k] is None]
            if missing_or_none_keys:
                self.logger.warning(
                    f"Missing or None essential keys in 'check_account_on_site' single_user result: {missing_or_none_keys} for key {cache_key}"
                )

        if self.perf_tracker.should_log_summary():
            summary_lines = self.perf_tracker.get_summary()
            for line in summary_lines:
                self.perf_logger.info(line)
        return result

    @monitor_performance
    async def search_player(self, term: str, single_user: bool = True, max_depth: int = None) -> Optional[
        Dict[str, Any]]:
        cfg = get_config()
        effective_max_depth = max_depth if max_depth is not None else getattr(cfg.scan, 'search_max_depth', 2)

        start_time_search = time.time()

        initial_search_term = term.lower().strip()

        self.logger.info(
            f"Initiating player search for term: '{term}' (searching as '{initial_search_term}'), single_user={single_user}, max_depth={effective_max_depth}")

        raw_search_cache_key = f"search_player_v2:{initial_search_term}:single_user={single_user}:max_depth={effective_max_depth}"
        if len(raw_search_cache_key) > 256:
            search_cache_key = hashlib.sha256(raw_search_cache_key.encode('utf-8')).hexdigest()
        else:
            search_cache_key = raw_search_cache_key

        current_time = time.time()

        if search_cache_key in self._search_cache:
            cached_data, timestamp = self._search_cache[search_cache_key]
            if current_time - timestamp < self._search_cache_ttl:
                self.logger.info(f"Returning cached search result for '{initial_search_term}' from _search_cache.")
                self._search_cache.move_to_end(search_cache_key)
                self._request_stats["cache_hits"] += 1
                return cached_data
            else:
                del self._search_cache[search_cache_key]

        self._request_stats["cache_misses"] += 1

        processed_terms: Set[str] = set()
        search_queue = deque([(initial_search_term, 0)])
        terms_in_flight: Set[str] = {initial_search_term}
        merged_result_data: Optional[Dict[str, Any]] = None
        search_stats = {"unique_api_calls": 0, "depth_distribution": {}}

        while search_queue:
            current_batch_size = min(getattr(cfg.scan, 'search_batch_size', 5), len(search_queue))
            batch_items_to_process = []
            for _ in range(current_batch_size):
                if not search_queue: break
                batch_items_to_process.append(search_queue.popleft())

            if not batch_items_to_process: continue

            batch_processing_tasks = []
            for current_search_term, current_search_depth in batch_items_to_process:
                if current_search_term in processed_terms:
                    continue
                processed_terms.add(current_search_term)
                search_stats["unique_api_calls"] += 1
                search_stats["depth_distribution"][current_search_depth] = search_stats["depth_distribution"].get(
                    current_search_depth, 0) + 1

                batch_processing_tasks.append(self._process_search_term(
                    current_search_term, current_search_depth, single_user, effective_max_depth,
                    processed_terms, terms_in_flight
                ))

            if not batch_processing_tasks: continue
            term_processing_results = await asyncio.gather(*batch_processing_tasks, return_exceptions=True)

            for item_from_gather in term_processing_results:
                if isinstance(item_from_gather, Exception):
                    self.logger.error(f"Error during batched search term processing: {item_from_gather}", exc_info=True)
                elif item_from_gather and isinstance(item_from_gather, dict):
                    individual_result: Optional[Dict[str, Any]] = item_from_gather
                    if not individual_result.get('result_data'):
                        continue
                    if merged_result_data is None:
                        merged_result_data = individual_result['result_data']
                    else:
                        self._merge_search_results(merged_result_data, individual_result['result_data'])

                    for new_term_to_search, new_depth_level in individual_result.get('new_terms_to_search', []):
                        if new_term_to_search not in terms_in_flight:
                            search_queue.append((new_term_to_search, new_depth_level))
                            terms_in_flight.add(new_term_to_search)

        search_elapsed_time = time.time() - start_time_search
        self.logger.info(
            f"Search for '{term}' (initially as '{initial_search_term}') completed in {search_elapsed_time:.2f}s. "
            f"Stats: API Calls={search_stats['unique_api_calls']}, Depth Dist={search_stats['depth_distribution']}"
        )

        if merged_result_data:
            self._search_cache[search_cache_key] = (merged_result_data, current_time)
            self._search_cache.move_to_end(search_cache_key)
            while len(self._search_cache) > self._search_cache_max_size:
                self._search_cache.popitem(last=False)

        return merged_result_data

    async def _process_search_term(
            self, current_term: str, current_depth: int,
            single_user_mode: bool, max_search_depth: int,
            glob_processed_terms: Set[str],
            glob_terms_in_flight: Set[str]
    ) -> Optional[Dict[str, Any]]:

        self.logger.debug(f"Processing search for term: '{current_term}' at depth {current_depth}")
        try:
            encoded_term = quote_plus(current_term)
            connections_search_url = f"{self.base_admin_connections_url}&search={encoded_term}"

            term_data = await self.fetch_with_rate_limit(
                self.admin_panel.check_account_on_site,
                connections_search_url,
                single_user=single_user_mode
            )

            if not term_data or (isinstance(term_data, list) and not term_data):
                self.logger.debug(f"No data returned for term '{current_term}'.")
                return None

            aggregated_data_for_term = term_data
            if single_user_mode and isinstance(term_data, list):
                self.logger.warning(
                    f"Expected aggregated dict for '{current_term}' in single_user_mode, but got list. Attempting aggregation."
                )
                if term_data and all(isinstance(d, dict) for d in term_data):
                    aggregated_data_for_term = self.admin_panel.aggregate_single_user_info(term_data)
                else:
                    return {'result_data': aggregated_data_for_term, 'new_terms_to_search': []}

            new_terms_to_add_to_queue: List[Tuple[str, int]] = []
            if current_depth < max_search_depth:
                if isinstance(aggregated_data_for_term, dict):
                    extracted_identifiers = self._extract_prioritized_identifiers(
                        aggregated_data_for_term, current_term,
                        glob_processed_terms,
                        glob_terms_in_flight
                    )
                    search_limit_for_this_depth = self._get_search_limit_for_depth(current_depth)
                    count_added = 0
                    for identifier in extracted_identifiers:
                        if count_added >= search_limit_for_this_depth:
                            break
                        new_terms_to_add_to_queue.append((identifier, current_depth + 1))
                        count_added += 1
                    if new_terms_to_add_to_queue:
                        self.logger.debug(
                            f"Identified {len(new_terms_to_add_to_queue)} new terms from '{current_term}' for further search.")
                else:
                    self.logger.debug(
                        f"Data for '{current_term}' is not a dict (type: {type(aggregated_data_for_term)}), cannot extract new identifiers.")

            return {'result_data': aggregated_data_for_term, 'new_terms_to_search': new_terms_to_add_to_queue}

        except Exception as e:
            self.logger.error(f"Error processing search term '{current_term}' at depth {current_depth}: {e}",
                              exc_info=True)
            return None

    def _clean_search_cache_lru(self, evict_count: int):
        pass

    def _extract_prioritized_identifiers(
            self,
            result_dict: Dict[str, Any],
            origin_term: str,
            glob_processed_terms: Set[str],
            glob_terms_in_flight: Set[str]
    ) -> List[str]:
        potential_new_identifiers: List[Tuple[int, str]] = []

        def add_if_valid_and_new(identifier_to_search: Optional[str], priority: int):
            if not identifier_to_search or identifier_to_search == N_A or not isinstance(identifier_to_search,
                                                                                         str) or not identifier_to_search.strip():
                return


            if identifier_to_search == origin_term:
                return
            if identifier_to_search.lower() == origin_term.lower():
                return

            if identifier_to_search not in glob_processed_terms and identifier_to_search not in glob_terms_in_flight:
                potential_new_identifiers.append((priority, identifier_to_search))

        user_id_orig = result_dict.get("user_id")
        if user_id_orig and isinstance(user_id_orig, str) and user_id_orig != N_A:
            add_if_valid_and_new(user_id_orig.lower().strip(), 0)

        for hwid_val_orig in result_dict.get("associated_hwids", {}).keys():
            if hwid_val_orig and isinstance(hwid_val_orig, str) and hwid_val_orig != N_A:
                hwid_val_stripped = hwid_val_orig.strip()
                if hwid_val_stripped:
                    add_if_valid_and_new(hwid_val_stripped, 1)

        for ip_val_orig in result_dict.get("associated_ips", {}).keys():
            if ip_val_orig and isinstance(ip_val_orig, str) and ip_val_orig != N_A:
                ip_val_stripped_lower = ip_val_orig.lower().strip()
                if ip_val_stripped_lower:
                    add_if_valid_and_new(ip_val_stripped_lower, 2)

        for nickname_val_orig in result_dict.get("nicknames", []):
            if nickname_val_orig and isinstance(nickname_val_orig, str) and nickname_val_orig != N_A:
                nickname_val_stripped_lower = nickname_val_orig.lower().strip()
                if nickname_val_stripped_lower:
                    add_if_valid_and_new(nickname_val_stripped_lower, 3)

        potential_new_identifiers.sort()
        return [id_str for _, id_str in potential_new_identifiers]

    def _get_search_limit_for_depth(self, depth: int) -> int:
        cfg = get_config()
        if depth == 0: return getattr(cfg.scan, 'search_limit_root', 5)
        if depth == 1: return getattr(cfg.scan, 'search_limit_level1', 3)
        if depth == 2: return getattr(cfg.scan, 'search_limit_level2', 2)
        return getattr(cfg.scan, 'search_limit_default', 1)

    def _merge_search_results(self, main_result: Dict[str, Any], new_data: Dict[str, Any]) -> None:
        if not isinstance(main_result, dict) or not isinstance(new_data, dict):
            self.logger.warning(
                f"Attempted to merge non-dict results. Main type: {type(main_result)}, New type: {type(new_data)}")
            return

        def merge_list_field(field_name: str, uniqueness_key_func=None):
            main_list = main_result.get(field_name, [])
            new_items = new_data.get(field_name, [])
            if not isinstance(main_list, list): main_list = []

            existing_keys_set = set()
            final_list = []

            for item in main_list:
                try:
                    key = uniqueness_key_func(item) if uniqueness_key_func else item
                    if isinstance(key, (list, dict)):
                        if item not in final_list: final_list.append(item)
                    elif key not in existing_keys_set:
                        existing_keys_set.add(key)
                        final_list.append(item)
                except TypeError:
                    if item not in final_list: final_list.append(item)

            for item in new_items:
                try:
                    key = uniqueness_key_func(item) if uniqueness_key_func else item
                    if isinstance(key, (list, dict)):
                        if item not in final_list: final_list.append(item)
                    elif key not in existing_keys_set:
                        existing_keys_set.add(key)
                        final_list.append(item)
                except TypeError:
                    if item not in final_list: final_list.append(item)
            main_result[field_name] = final_list

        def merge_dict_field_with_list_values(field_name: str):
            main_dict = main_result.get(field_name, {})
            new_items_dict = new_data.get(field_name, {})
            if not isinstance(main_dict, dict): main_dict = {}

            for key, new_val_list_candidate in new_items_dict.items():
                if not isinstance(new_val_list_candidate, list): continue

                current_val_set = set(main_dict.get(key, []))
                current_val_set.update(new_val_list_candidate)
                main_dict[key] = sorted(list(current_val_set))
            main_result[field_name] = main_dict

        merge_list_field("nicknames")
        merge_list_field("shared_hwid_nicknames")
        merge_list_field("ban_reasons", lambda br: tuple(sorted(br.items())) if isinstance(br, dict) else br)
        merge_list_field("denied_banned_connections",
                         lambda dbc: tuple(sorted(dbc.items())) if isinstance(dbc, dict) else dbc)

        merge_dict_field_with_list_values("associated_ips")
        merge_dict_field_with_list_values("associated_hwids")

        main_result["ban_counts"] = max(main_result.get("ban_counts", 0), new_data.get("ban_counts", 0))

        status_priority = {'suspicious': 4, 'banned': 3, 'clean': 1, 'unknown': 0, N_A: 0}
        current_status = str(main_result.get("status", "unknown")).lower()
        new_status = str(new_data.get("status", "unknown")).lower()
        if status_priority.get(new_status, 0) > status_priority.get(current_status, 0):
            main_result["status"] = new_data.get("status")

        if main_result.get("user_id", N_A) == N_A and new_data.get("user_id", N_A) != N_A:
            main_result["user_id"] = new_data.get("user_id")
        if main_result.get("connection_link", N_A) == N_A and new_data.get("connection_link", N_A) != N_A:
            main_result["connection_link"] = new_data.get("connection_link")

    def convert_to_player(self, account_info_dict: Optional[Dict[str, Any]]) -> Player:
        if not account_info_dict or not isinstance(account_info_dict, dict):
            self.logger.warning(
                "Empty, None, or non-dict account_info_dict provided to convert_to_player. Returning default Player.")
            return Player(user_id=N_A, nicknames=[], status="unknown")

        player_user_id = account_info_dict.get("user_id", N_A)
        player_nicknames = account_info_dict.get("nicknames", [])
        player_status = account_info_dict.get("status", "unknown")
        player_ban_counts = account_info_dict.get("ban_counts", 0)
        raw_ban_reasons = account_info_dict.get("ban_reasons", [])
        formatted_ban_reasons: List[Dict[str, str]] = []

        if isinstance(raw_ban_reasons, list):
            for reason_entry in raw_ban_reasons:
                if isinstance(reason_entry, dict) and "reason" in reason_entry and "username" in reason_entry:
                    formatted_ban_reasons.append({
                        "reason": str(reason_entry["reason"]),
                        "username": str(reason_entry["username"])
                    })

        player_instance = Player(
            user_id=str(player_user_id) if player_user_id is not None else N_A,
            nicknames=player_nicknames if isinstance(player_nicknames, list) else [],
            status=str(player_status) if player_status is not None else "unknown",
            ban_counts=int(player_ban_counts) if isinstance(player_ban_counts, (int, float)) else 0,
            ban_reasons=formatted_ban_reasons,
            connection_link=str(account_info_dict.get("connection_link", N_A)),
            associated_ips=account_info_dict.get("associated_ips", {}) if isinstance(
                account_info_dict.get("associated_ips"), dict) else {},
            associated_hwids=account_info_dict.get("associated_hwids", {}) if isinstance(
                account_info_dict.get("associated_hwids"), dict) else {},
            shared_hwid_nicknames=account_info_dict.get("shared_hwid_nicknames", []) if isinstance(
                account_info_dict.get("shared_hwid_nicknames"), list) else [],
            denied_logins=account_info_dict.get("denied_banned_connections", []) if isinstance(
                account_info_dict.get("denied_banned_connections"), list) else [],
            hwid_erased=bool(account_info_dict.get("hwid_erased", False))
        )
        return player_instance