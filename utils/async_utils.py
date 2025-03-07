import asyncio
import functools
import logging
import time
from collections import deque
from typing import Any, List, Coroutine, Dict, Callable, TypeVar, Tuple

T = TypeVar('T')

logger = logging.getLogger(__name__)


async def run_with_semaphore(semaphore: asyncio.Semaphore, coro: Coroutine) -> Any:
    async with semaphore:
        return await coro


async def gather_with_concurrency(n: int, *coros) -> List[Any]:
    if not coros:
        return []
    semaphore = asyncio.Semaphore(n)
    return await asyncio.gather(*(run_with_semaphore(semaphore, c) for c in coros))


class RateLimiter:
    def __init__(self, max_calls: int, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque(maxlen=max_calls * 2)
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.time()
            while self.calls and now - self.calls[0] >= self.period:
                self.calls.popleft()
            if len(self.calls) >= self.max_calls:
                oldest = self.calls[0]
                wait_time = self.period - (now - oldest)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    now = time.time()
            self.calls.append(now)

    async def wrapped_call(self, coro):
        await self.acquire()
        return await coro


def to_thread(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return wrapper


class AsyncCache:
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.max_size = max_size
        self.lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    async def get(self, key: str, factory: Callable[[], Coroutine]) -> Any:
        async with self.lock:
            if key in self.cache:
                self.hits += 1
                value, _ = self.cache[key]
                self.cache[key] = (value, time.time())
                return value
            self.misses += 1
        value = await factory()
        async with self.lock:
            if len(self.cache) >= self.max_size:
                oldest_key = min(self.cache.items(), key=lambda x: x[1][1])[0]
                del self.cache[oldest_key]
                self.evictions += 1
            self.cache[key] = (value, time.time())
        return value

    async def clear(self):
        async with self.lock:
            self.cache.clear()
