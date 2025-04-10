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
        ttl = ttl or self._get_ttl_for_key(key)

        if key in self.cache:
            value, timestamp = self.cache[key]
            if current_time - timestamp < ttl:
                self.hits += 1
                return value

        if current_time - self._last_cleanup_time > self._cleanup_interval:
            asyncio.create_task(self._cleanup_expired())
            self._last_cleanup_time = current_time

        self.misses += 1
        try:
            value = await factory()
        except Exception as e:
            logger.error(f"Cache fetch error for {key}: {str(e)}")
            return None

        async with self.lock:
            if len(self.cache) >= self.max_size:
                await self._evict_entries()
            self.cache[key] = (value, current_time)
            self._key_access_times[key] = current_time

        return value

    async def _evict_entries(self):
        current_time = time.time()
        expired_keys = [
            k for k, (_, timestamp) in self.cache.items()
            if current_time - timestamp > self.default_ttl
        ]
        for key in expired_keys:
            del self.cache[key]
            if key in self._key_access_times:
                del self._key_access_times[key]
            self.evictions += 1
        if len(self.cache) >= self.max_size:
            to_remove = sorted(
                self._key_access_times.items(),
                key=lambda x: x[1]
            )[:max(1, self.max_size // 10)]
            for key, _ in to_remove:
                if key in self.cache:
                    del self.cache[key]
                if key in self._key_access_times:
                    del self._key_access_times[key]
                self.evictions += 1

    async def _cleanup_expired(self):
        async with self.lock:
            current_time = time.time()
            self._last_cleanup_time = current_time
            expired_keys = [
                k for k, (_, timestamp) in self.cache.items()
                if current_time - timestamp > self.default_ttl
            ]
            for key in expired_keys:
                del self.cache[key]
                if key in self._key_access_times:
                    del self._key_access_times[key]
                self.evictions += 1
            access_keys_to_remove = [
                k for k in self._key_access_times
                if k not in self.cache
            ]
            for key in access_keys_to_remove:
                del self._key_access_times[key]

    async def clear(self):
        async with self.lock:
            self.cache.clear()
            self._key_access_times.clear()
