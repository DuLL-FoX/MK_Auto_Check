import asyncio
import functools
import time
import logging
from typing import Any, List, Coroutine, Dict, Set, Callable, TypeVar, Optional, Tuple
from collections import deque

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


async def gather_with_progress(n: int, coros: List[Coroutine],
                               progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Any]:
    if not coros:
        return []
    semaphore = asyncio.Semaphore(n)
    total = len(coros)
    completed = 0
    results = []

    async def _run_with_progress(coro, idx):
        nonlocal completed
        try:
            async with semaphore:
                result = await coro
            results.append((idx, result))
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            return result
        except Exception as e:
            results.append((idx, None))
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            logger.error(f"Error in task {idx}: {str(e)}")
            return None

    tasks = [_run_with_progress(coro, i) for i, coro in enumerate(coros)]
    await asyncio.gather(*tasks, return_exceptions=True)
    results.sort(key=lambda x: x[0])
    return [r[1] for r in results]


async def batch_process(items: List[T], process_func: Callable[[T], Coroutine],
                        batch_size: int = 20, concurrency: int = 10,
                        progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Any]:
    if not items:
        return []
    results = []
    total_items = len(items)
    processed_items = 0
    for i in range(0, total_items, batch_size):
        batch = items[i:i + batch_size]
        batch_results = await gather_with_concurrency(
            concurrency,
            *[process_func(item) for item in batch]
        )
        results.extend(batch_results)
        processed_items += len(batch)
        if progress_callback:
            progress_callback(processed_items, total_items)
    return results


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

    def get_stats(self) -> Dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "size": len(self.cache),
            "max_size": self.max_size,
            "evictions": self.evictions,
            "hit_ratio": self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0
        }

    async def clear(self):
        async with self.lock:
            self.cache.clear()
