import asyncio
import functools
import logging
import time
from collections import deque, OrderedDict
from typing import Any, List, Coroutine, Callable, TypeVar, Tuple, Optional

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
                    oldest_call_in_window = self.calls[0]
                    wait_time = self.period - (now - oldest_call_in_window)
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
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
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
                    self.cache.move_to_end(key)
                    return value
                else:
                    del self.cache[key]
                    self.evictions += 1

        self.misses += 1
        try:
            new_value = await factory()
        except Exception as e:
            logger.error(f"Cache factory error for key '{key}': {str(e)}")
            return None

        async with self.lock:
            self.cache[key] = (new_value, current_time)
            self.cache.move_to_end(key)

            while len(self.cache) > self.max_size:
                popped_key, _ = self.cache.popitem(last=False)
                self.evictions += 1

        if current_time - self._last_cleanup_time > self._cleanup_interval:
            asyncio.create_task(self._cleanup_expired())
            self._last_cleanup_time = current_time

        return new_value

    async def _evict_entries_locked(self):
        pass

    async def _cleanup_expired(self):
        logger.debug("AsyncCache: Starting periodic cleanup of expired entries.")
        cleaned_count = 0
        async with self.lock:
            current_time = time.time()
            keys_to_check = list(self.cache.keys())

            for key in keys_to_check:
                if key not in self.cache:
                    continue

                _value, timestamp = self.cache[key]
                if current_time - timestamp > self._get_ttl_for_key(key):
                    del self.cache[key]
                    self.evictions += 1
                    cleaned_count += 1

            self._last_cleanup_time = current_time

        if cleaned_count > 0:
            logger.debug(f"AsyncCache: Cleaned up {cleaned_count} expired entries.")

    async def clear(self):
        async with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0
            logger.info("AsyncCache cleared.")