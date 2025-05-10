import asyncio
import hashlib
import logging
import time
from collections import deque, OrderedDict
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from urllib.parse import quote_plus
from datetime import datetime, timedelta

from admin_panel import N_A, AdminPanel
from config_system import get_config
from models.player import Player
from utils.async_utils import AsyncCache
from aiolimiter import AsyncLimiter
from utils.performance_monitor import monitor_performance, PerformanceTracker


class AdminService:
    def __init__(self, admin_panel: AdminPanel, max_concurrent_requests: int = 100) -> None:
        self.admin_panel = admin_panel
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.rate_limiter = AsyncLimiter(150, 1.0)
        
        self.cache = AsyncCache(max_size=20000, default_ttl=3600)
        self.base_admin_connections_url = (
            f"{self.admin_panel.BASE_ADMIN_URL}/Connections?showSet=true&showAccepted=true&showBanned=true"
            "&showWhitelist=true&showFull=true&showPanic=true&perPage=200"
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
        self._search_cache_max_size = getattr(cfg.scan, 'search_cache_max_size', 5000)
        self._search_cache_ttl = getattr(cfg.scan, 'search_cache_ttl', 7200)

        self._login_lock = asyncio.Lock()
        self._last_login_time = 0
        self._auth_ttl = self.admin_panel._auth_token_ttl - 60
        
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("AdminService initialized")

    async def close(self):
        await self.admin_panel.close()
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info("AdminService closed.")

    @monitor_performance
    async def login(self) -> bool:
        async with self._login_lock:
            current_time = time.time()
            if self.admin_panel._is_authenticated and \
               (current_time - self.admin_panel._auth_token_timestamp < self.admin_panel._auth_token_ttl - 60):
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug("Login token likely still valid in AdminPanel.")
                return True

            if self.logger.isEnabledFor(logging.INFO):
                self.logger.info("Attempting AdminPanel login via AdminService.")
            start_time = time.time()
            result = await self.admin_panel.login()
            elapsed = time.time() - start_time
            self.perf_tracker.record("admin_panel_login", elapsed)

            if result:
                self._last_login_time = current_time
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info(f"AdminPanel login successful in {elapsed:.2f}s.")
            else:
                if self.logger.isEnabledFor(logging.ERROR):
                    self.logger.error(f"AdminPanel login failed after {elapsed:.2f}s.")
            return result

    @monitor_performance
    async def fetch_with_rate_limit(self, func: Callable, *args, **kwargs) -> Any:
        func_name = func.__name__ if hasattr(func, '__name__') else str(func)
        arg_parts_str = ":".join(map(str, args))
        kwarg_parts_str = ":".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
        raw_cache_key = f"{func_name}:{arg_parts_str}:{kwarg_parts_str}"
        cache_key = hashlib.sha256(raw_cache_key.encode('utf-8')).hexdigest() if len(raw_cache_key) > 256 else raw_cache_key

        self._request_stats["total"] += 1

        async def factory_coro():
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    f"Cache miss for key: {cache_key_preview(cache_key)} (raw: {raw_cache_key[:100]}...). Executing: {func_name}")
            self._request_stats["cache_misses"] += 1
            
            if not await self.login():
                self.logger.error(f"Login failed for {func_name}, cannot proceed.")
                raise Exception(f"Authentication failed, cannot execute {func_name}")

            op_start_time = time.time()
            call_result = None
            async with self.semaphore:
                async with self.rate_limiter:
                    if not asyncio.iscoroutinefunction(func):
                        if self.logger.isEnabledFor(logging.WARNING):
                            self.logger.warning(f"Function {func_name} is not a coroutine function. Running in thread.")
                        call_result = await asyncio.to_thread(func, *args, **kwargs)
                    else:
                        call_result = await func(*args, **kwargs)
            
            op_elapsed_time = time.time() - op_start_time
            self.perf_tracker.record(func_name, op_elapsed_time)

            if op_elapsed_time > self.slow_operation_threshold:
                log_args_preview = raw_cache_key[:120] + "..." if len(raw_cache_key) > 120 else raw_cache_key
                if self.perf_logger.isEnabledFor(logging.WARNING):
                    self.perf_logger.warning(
                        f"Slow operation: {func_name} took {op_elapsed_time:.2f}s. Args preview: {log_args_preview}"
                    )
            return call_result

        result = await self.cache.get(cache_key, factory_coro)
        
        if func_name == "check_account_on_site" and isinstance(result, dict) and kwargs.get('single_user'):
            required_keys = ['status', 'nicknames', 'associated_ips', 'associated_hwids', 'user_id']
            missing_or_none_keys = [k for k in required_keys if result.get(k) is None]
            if missing_or_none_keys:
                 if self.logger.isEnabledFor(logging.WARNING):
                    self.logger.warning(
                        f"Missing or None essential keys in 'check_account_on_site' single_user result: {missing_or_none_keys} for key {cache_key_preview(cache_key)}"
                    )
        
        if self.perf_tracker.should_log_summary():
            summary_lines = self.perf_tracker.get_summary()
            for line in summary_lines:
                if self.perf_logger.isEnabledFor(logging.INFO):
                    self.perf_logger.info(line)
        return result
    
    def _is_recent(self, time_str: str, days: int = 7) -> bool:
        if not time_str or time_str == N_A: return False
        try:
            conn_time = datetime.strptime(time_str, "%m/%d/%Y %I:%M:%S %p")
            if datetime.now() - conn_time < timedelta(days=days):
                return True
        except ValueError:
            if self.logger.isEnabledFor(logging.DEBUG):
                 self.logger.debug(f"Could not parse time_str '{time_str}' for recency check.")
            return False
        return False

    @monitor_performance
    async def search_player(self, term: str, single_user: bool = True, max_depth: Optional[int] = None) -> Optional[Dict[str, Any]]:
        cfg = get_config()
        effective_max_depth = max_depth if max_depth is not None else getattr(cfg.scan, 'search_max_depth', 2)
        start_time_search = time.time()
        
        initial_term_is_likely_hwid = len(term) > 20 and any(c.islower() for c in term) and any(c.isupper() for c in term) and ('/' in term or '+' in term or '=' in term)
        
        initial_search_term_str = term
        initial_term_canonical = term.strip() if initial_term_is_likely_hwid else term.lower().strip()

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"Initiating player search for term: '{initial_search_term_str}' (canonical: '{initial_term_canonical}'), single_user={single_user}, max_depth={effective_max_depth}")

        raw_search_cache_key = f"search_player_v4:{initial_term_canonical}:single_user={single_user}:max_depth={effective_max_depth}"
        search_cache_key = hashlib.sha256(raw_search_cache_key.encode('utf-8')).hexdigest() if len(raw_search_cache_key) > 256 else raw_search_cache_key
        
        current_time = time.time()
        if search_cache_key in self._search_cache:
            cached_data, timestamp = self._search_cache[search_cache_key]
            if current_time - timestamp < self._search_cache_ttl:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Returning cached search result for '{initial_term_canonical}' from _search_cache.")
                self._search_cache.move_to_end(search_cache_key)
                self._request_stats["cache_hits"] += 1
                return cached_data
            else:
                del self._search_cache[search_cache_key]

        processed_terms: Set[str] = set()
        search_queue = deque([((term.strip(), initial_term_is_likely_hwid), 0)])
        terms_in_flight: Set[str] = {initial_term_canonical}
        
        merged_result_data: Optional[Dict[str, Any]] = None
        search_stats = {"unique_api_calls": 0, "depth_distribution": {}}

        while search_queue:
            batch_size = min(getattr(cfg.scan, 'search_batch_size', 5), len(search_queue))
            items_to_process_this_batch = [search_queue.popleft() for _ in range(batch_size)]
            
            tasks, actual_items_for_api = [], []
            for (term_str_to_process, term_is_hwid_flag), depth in items_to_process_this_batch:
                canonical_term_to_process = term_str_to_process if term_is_hwid_flag else term_str_to_process.lower()
                if canonical_term_to_process in processed_terms: continue
                
                tasks.append(self._process_search_term(
                    term_str_to_process, term_is_hwid_flag, depth, single_user, effective_max_depth,
                    processed_terms, terms_in_flight
                ))
                actual_items_for_api.append(((term_str_to_process, term_is_hwid_flag), depth, canonical_term_to_process))

            if not tasks: continue
            results_from_batch = await asyncio.gather(*tasks, return_exceptions=True)

            for i, res_or_exc in enumerate(results_from_batch):
                (_original_term_tuple, original_depth, canonical_original_term) = actual_items_for_api[i]
                original_term_str, _ = _original_term_tuple

                if canonical_original_term not in processed_terms:
                     processed_terms.add(canonical_original_term)
                     search_stats["unique_api_calls"] += 1
                     search_stats["depth_distribution"][original_depth] = search_stats["depth_distribution"].get(original_depth, 0) + 1

                if isinstance(res_or_exc, Exception):
                    if self.logger.isEnabledFor(logging.ERROR):
                        self.logger.error(f"Error processing search term '{original_term_str}': {res_or_exc}", exc_info=False)
                    continue
                
                individual_result: Optional[Dict[str, Any]] = res_or_exc
                if not individual_result or not individual_result.get('result_data'): continue

                if merged_result_data is None: merged_result_data = individual_result['result_data']
                else: self._merge_search_results(merged_result_data, individual_result['result_data'])

                for new_term_str, new_term_is_hwid_flag in individual_result.get('new_terms_to_search', []):
                    canonical_new_term = new_term_str if new_term_is_hwid_flag else new_term_str.lower()
                    if canonical_new_term not in terms_in_flight:
                        search_queue.append(((new_term_str, new_term_is_hwid_flag), original_depth + 1))
                        terms_in_flight.add(canonical_new_term)

        search_elapsed_time = time.time() - start_time_search
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"Search for '{initial_search_term_str}' (canonical '{initial_term_canonical}') completed in {search_elapsed_time:.2f}s. "
                f"API Calls={search_stats['unique_api_calls']}, Depth Dist={search_stats['depth_distribution']}" )

        if merged_result_data:
            self._search_cache[search_cache_key] = (merged_result_data, current_time)
            if len(self._search_cache) > self._search_cache_max_size:
                self._search_cache.popitem(last=False)
        return merged_result_data

    async def _process_search_term(
            self, current_term_str: str, current_term_is_hwid: bool, current_depth: int,
            single_user_mode: bool, max_search_depth: int,
            glob_processed_terms: Set[str], glob_terms_in_flight: Set[str]
    ) -> Optional[Dict[str, Any]]:

        canonical_term_for_url = current_term_str
        if not current_term_is_hwid:
            canonical_term_for_url = current_term_str.lower()

        current_term_canonical_for_tracking = current_term_str if current_term_is_hwid else current_term_str.lower()

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                f"Processing search for term: '{current_term_str}' (using URL term: '{canonical_term_for_url}', "
                f"internal canonical: '{current_term_canonical_for_tracking}', is_hwid: {current_term_is_hwid}) at depth {current_depth}"
            )
        try:
            encoded_term = quote_plus(canonical_term_for_url)
            connections_search_url = f"{self.base_admin_connections_url}&search={encoded_term}"

            term_data = await self.fetch_with_rate_limit(
                self.admin_panel.check_account_on_site,
                connections_search_url,
                single_user=single_user_mode
            )

            if not term_data or (isinstance(term_data, list) and not term_data):
                if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(
                    f"No data returned for term '{current_term_str}'.")
                return None

            aggregated_data_for_term = term_data
            new_terms_to_queue: List[Tuple[str, bool]] = []

            if current_depth < max_search_depth:
                if isinstance(aggregated_data_for_term, dict):
                    all_connections_recent = False
                    if "raw_html_snippet" in aggregated_data_for_term and aggregated_data_for_term["raw_html_snippet"]:
                        all_connections_recent = all(
                            self._is_recent(conn_prev.get("time"), days=7)
                            for conn_prev in aggregated_data_for_term["raw_html_snippet"] if conn_prev.get("time")
                        ) if aggregated_data_for_term["raw_html_snippet"] else False

                    if all_connections_recent and aggregated_data_for_term["raw_html_snippet"]:
                        if self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(
                                f"Term '{current_term_str}' data appears very recent. Suppressing further expansion.")
                    else:
                        extracted_identifiers_with_type = self._extract_prioritized_identifiers(
                            aggregated_data_for_term, current_term_str, current_term_is_hwid,
                            glob_processed_terms, glob_terms_in_flight
                        )
                        search_limit_for_depth = self._get_search_limit_for_depth(current_depth)
                        new_terms_to_queue.extend(extracted_identifiers_with_type[:search_limit_for_depth])
                        if new_terms_to_queue and self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(
                                f"Identified {len(new_terms_to_queue)} new terms from '{current_term_str}' for depth {current_depth + 1}.")
                elif self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(
                        f"Data for '{current_term_str}' (type: {type(aggregated_data_for_term)}) not dict, cannot extract new ids.")
            return {'result_data': aggregated_data_for_term, 'new_terms_to_search': new_terms_to_queue}
        except Exception as e:
            if self.logger.isEnabledFor(logging.ERROR):
                self.logger.error(f"Error processing search term '{current_term_str}' at depth {current_depth}: {e}",
                                  exc_info=False)
            return None

    def _extract_prioritized_identifiers(
            self, result_dict: Dict[str, Any],
            origin_term_str: str, origin_term_is_hwid: bool,
            glob_processed_terms: Set[str], glob_terms_in_flight: Set[str]
    ) -> List[Tuple[str, bool]]:
        
        potential_new_ids: List[Tuple[int, str, bool]] = []

        def add_if_valid(identifier: Optional[str], priority: int, term_is_hwid: bool):
            if not identifier or identifier == N_A or not isinstance(identifier, str) or not identifier.strip(): return
            
            id_str_stripped = identifier.strip()

            comp_term = id_str_stripped if term_is_hwid else id_str_stripped.lower()
            origin_comp_term = origin_term_str.strip() if origin_term_is_hwid else origin_term_str.lower().strip()

            if comp_term == origin_comp_term: return

            if comp_term in glob_processed_terms or comp_term in glob_terms_in_flight: return

            if priority == 2:
                is_private = False
                try:
                    if (id_str_stripped.startswith("192.168.") or
                        id_str_stripped.startswith("10.") or
                        (id_str_stripped.startswith("172.") and 16 <= int(id_str_stripped.split('.')[1]) <= 31)):
                        is_private = True
                except (ValueError, IndexError): pass
                if is_private:
                    if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Skipping private IP for expansion: {id_str_stripped}")
                    return
            
            potential_new_ids.append((priority, id_str_stripped, term_is_hwid))

        add_if_valid(result_dict.get("user_id"), 0, False)
        for hwid_val in result_dict.get("associated_hwids", {}).keys(): add_if_valid(hwid_val, 1, True)
        for ip_val in result_dict.get("associated_ips", {}).keys(): add_if_valid(ip_val, 2, False)
        for nickname_val in result_dict.get("nicknames", []): add_if_valid(nickname_val, 3, False)
        
        potential_new_ids.sort(key=lambda x: (x[0], x[1]))
        
        return [(id_str, is_hwid) for _, id_str, is_hwid in potential_new_ids]

    def _get_search_limit_for_depth(self, depth: int) -> int:
        cfg = get_config()
        if depth == 0: return getattr(cfg.scan, 'search_limit_root', 5)
        if depth == 1: return getattr(cfg.scan, 'search_limit_level1', 3)
        if depth == 2: return getattr(cfg.scan, 'search_limit_level2', 2)
        return getattr(cfg.scan, 'search_limit_default', 1)

    def _merge_search_results(self, main_result: Dict[str, Any], new_data: Dict[str, Any]) -> None:
        if not isinstance(main_result, dict) or not isinstance(new_data, dict):
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning(f"Attempted to merge non-dict results. Main: {type(main_result)}, New: {type(new_data)}")
            return

        main_result["nicknames"] = sorted(list(set(main_result.get("nicknames", [])) | set(new_data.get("nicknames", []))))
        main_result["shared_hwid_nicknames"] = sorted(list(set(main_result.get("shared_hwid_nicknames", [])) | set(new_data.get("shared_hwid_nicknames", []))))

        def br_key(br): return frozenset(br.items())
        merged_brs = {br_key(br): br for br in main_result.get("ban_reasons", [])}
        for br_new in new_data.get("ban_reasons", []): merged_brs.setdefault(br_key(br_new), br_new)
        main_result["ban_reasons"] = sorted(list(merged_brs.values()), key=lambda x: (x.get("username", ""), x.get("reason", "")))

        def dc_key(dc): return frozenset(dc.items())
        merged_dcs = {dc_key(dc): dc for dc in main_result.get("denied_banned_connections", [])}
        for dc_new in new_data.get("denied_banned_connections", []): merged_dcs.setdefault(dc_key(dc_new), dc_new)
        main_result["denied_banned_connections"] = sorted(list(merged_dcs.values()), key=lambda x: x.get("time", ""))

        assoc_ips = main_result.get("associated_ips", {})
        for ip, nicks in new_data.get("associated_ips", {}).items():
            assoc_ips[ip] = sorted(list(set(assoc_ips.get(ip, [])) | set(nicks)))
        main_result["associated_ips"] = assoc_ips

        assoc_hwids = main_result.get("associated_hwids", {})
        for hwid, nicks in new_data.get("associated_hwids", {}).items():
            existing_nicks = set(assoc_hwids.get(hwid, []))
            existing_nicks.update(nicks)
            assoc_hwids[hwid] = sorted(list(existing_nicks))
        main_result["associated_hwids"] = assoc_hwids
        
        main_result["ban_counts"] = max(main_result.get("ban_counts", 0), new_data.get("ban_counts", 0))

        s_pri = {'suspicious': 4, 'banned': 3, 'clean': 1, 'unknown': 0, N_A: 0}
        cur_s, new_s = str(main_result.get("status", "u")).lower(), str(new_data.get("status", "u")).lower()
        if s_pri.get(new_s, 0) > s_pri.get(cur_s, 0): main_result["status"] = new_data.get("status")

        if main_result.get("user_id", N_A) == N_A and new_data.get("user_id", N_A) != N_A: main_result["user_id"] = new_data.get("user_id")
        if main_result.get("connection_link", N_A) == N_A and new_data.get("connection_link", N_A) != N_A: main_result["connection_link"] = new_data.get("connection_link")
        main_result["hwid_erased"] = bool(main_result.get("hwid_erased", False) or new_data.get("hwid_erased", False))
        if not main_result.get("raw_html_snippet") and new_data.get("raw_html_snippet"): main_result["raw_html_snippet"] = new_data.get("raw_html_snippet")

    def convert_to_player(self, account_info_dict: Optional[Dict[str, Any]]) -> Player:
        if not account_info_dict or not isinstance(account_info_dict, dict):
            if self.logger.isEnabledFor(logging.WARNING): self.logger.warning("Empty/None/non-dict account_info for convert_to_player. Default Player returned.")
            return Player(user_id=N_A, nicknames=[], status="unknown")

        p_uid = str(account_info_dict.get("user_id", N_A))
        nicks_list = account_info_dict.get("nicknames", []); p_nicks = nicks_list if isinstance(nicks_list, list) else []
        p_status = str(account_info_dict.get("status", "unknown"))
        p_ban_c = int(bc) if isinstance((bc:=account_info_dict.get("ban_counts",0)),(int,float)) else 0
        
        fmt_brs: List[Dict[str, str]] = []
        for r_entry in (raw_brs if isinstance((raw_brs:=account_info_dict.get("ban_reasons",[])),list) else []):
            if isinstance(r_entry, dict) and "reason" in r_entry and "username" in r_entry:
                fmt_brs.append({"reason": str(r_entry["reason"]), "username": str(r_entry["username"])})
        
        p_conn_link = str(account_info_dict.get("connection_link", N_A))
        p_assoc_ips = ips if isinstance((ips:=account_info_dict.get("associated_ips",{})),dict) else {}
        p_assoc_hwids = hwids if isinstance((hwids:=account_info_dict.get("associated_hwids",{})),dict) else {}
        p_shared_hwids = sh_hwids if isinstance((sh_hwids:=account_info_dict.get("shared_hwid_nicknames",[])),list) else []
        p_denied_logins = d_logins if isinstance((d_logins:=account_info_dict.get("denied_banned_connections",[])),list) else []
        p_hwid_erased = bool(account_info_dict.get("hwid_erased", False))

        return Player(user_id=p_uid, nicknames=p_nicks, status=p_status, ban_counts=p_ban_c,
                      ban_reasons=fmt_brs, connection_link=p_conn_link, associated_ips=p_assoc_ips,
                      associated_hwids=p_assoc_hwids, shared_hwid_nicknames=p_shared_hwids,
                      denied_logins=p_denied_logins, hwid_erased=p_hwid_erased)

def cache_key_preview(key: str, length: int = 60) -> str:
    return key[:length//2] + "..." + key[-(length//2):] if len(key) > length else key