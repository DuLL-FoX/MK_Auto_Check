import asyncio
import functools
import logging
import time
from collections import deque
from typing import Any, List, Coroutine, Dict, Callable, TypeVar, Tuple, Optional

T = TypeVar('T')

logger = logging.getLogger(__name__)

async def run_with_semaphore(semaphore: asyncio.Semaphore, coro: Coroutine) -> Any:
    async with semaphore:
        return await coro

async def gather_with_concurrency(n: int, *coros) -> List[Any]:
    if not coros:
        return []
    semaphore = asyncio.Semaphore(n)
    tasks = [run_with_semaphore(semaphore, c) for c in coros]
    return await asyncio.gather(*tasks)


class RateLimiter:
    def __init__(self, max_calls: int, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque(maxlen=max_calls + 5)
        self.lock = asyncio.Lock()
        self._last_acquire_time = 0
        self._min_interval = period / max_calls if max_calls > 0 else 0
        self._pending_tasks = 0

    async def acquire(self):
        now = time.time()
        if (len(self.calls) < self.max_calls and
                now - self._last_acquire_time >= self._min_interval and
                self._pending_tasks == 0):
            self.calls.append(now)
            self._last_acquire_time = now
            return

        async with self.lock:
            self._pending_tasks += 1
            try:
                now = time.time()

                while self.calls and now - self.calls[0] >= self.period:
                    self.calls.popleft()

                if len(self.calls) >= self.max_calls:
                    oldest = self.calls[0]
                    wait_time = self.period - (now - oldest)
                    if wait_time > 0:
                        await asyncio.sleep(wait_time)
                        now = time.time()
                        while self.calls and now - self.calls[0] >= self.period:
                            self.calls.popleft()

                self.calls.append(now)
                self._last_acquire_time = now
            finally:
                self._pending_tasks -= 1

    async def wrapped_call(self, coro):
        await self.acquire()
        return await coro

def to_thread(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)
    return wrapper


class AsyncCache:
    def __init__(self, max_size: int = 1000, default_ttl: float = 3600):
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self._key_access_times = {}
        self._last_cleanup_time = time.time()
        self._cleanup_interval = 1800
        self._ttl_overrides = {}

    def set_ttl_override(self, pattern: str, ttl: float):
        self._ttl_overrides[pattern] = ttl

    def _get_ttl_for_key(self, key: str) -> float:
        for pattern, ttl in self._ttl_overrides.items():
            if pattern in key:
                return ttl
        return self.default_ttl

    async def get(self, key: str, factory: Callable[[], Coroutine], ttl: Optional[float] = None) -> Any:
        current_time = time.time()
        effective_ttl = ttl if ttl is not None else self._get_ttl_for_key(key)


        async with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if current_time - timestamp < effective_ttl:
                    self.hits += 1
                    self._key_access_times[key] = current_time
                    return value
                else:
                    del self.cache[key]
                    if key in self._key_access_times:
                        del self._key_access_times[key]
                    self.evictions +=1


        self.misses += 1
        try:
            new_value = await factory()
        except Exception as e:
            logger.error(f"Cache factory error for key '{key}': {str(e)}")
            return None 

        async with self.lock:
            if len(self.cache) >= self.max_size and key not in self.cache:
                await self._evict_entries_locked()

            self.cache[key] = (new_value, current_time)
            self._key_access_times[key] = current_time

        if current_time - self._last_cleanup_time > self._cleanup_interval:
            asyncio.create_task(self._cleanup_expired())
            self._last_cleanup_time = current_time
            
        return new_value

    async def _evict_entries_locked(self):
        if len(self.cache) < self.max_size:
            return

        num_to_evict = max(1, (len(self.cache) - self.max_size) + (self.max_size // 10))
        
        sorted_keys_by_access = sorted(self._key_access_times.items(), key=lambda item: item[1])
        
        evicted_count = 0
        for key_to_evict, _ in sorted_keys_by_access:
            if evicted_count >= num_to_evict:
                break
            if key_to_evict in self.cache:
                del self.cache[key_to_evict]
                if key_to_evict in self._key_access_times:
                    del self._key_access_times[key_to_evict]
                self.evictions += 1
                evicted_count += 1
        logger.debug(f"Evicted {evicted_count} entries from cache due to size limit.")


    async def _cleanup_expired(self):
        async with self.lock:
            current_time = time.time()
            self._last_cleanup_time = current_time
            
            expired_keys_in_cache = [
                k for k, (_, timestamp) in self.cache.items()
                if current_time - timestamp > self._get_ttl_for_key(k)
            ]
            
            for key in expired_keys_in_cache:
                del self.cache[key]
                if key in self._key_access_times:
                    del self._key_access_times[key]
                self.evictions += 1
            
            if expired_keys_in_cache:
                logger.debug(f"Cleaned up {len(expired_keys_in_cache)} expired entries from cache.")

            access_keys_to_prune = [k for k in self._key_access_times if k not in self.cache]
            if access_keys_to_prune:
                for key in access_keys_to_prune:
                    del self._key_access_times[key]
                logger.debug(f"Pruned {len(access_keys_to_prune)} orphaned keys from _key_access_times.")


    async def clear(self):
        async with self.lock:
            self.cache.clear()
            self._key_access_times.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0
            logger.info("AsyncCache cleared.")