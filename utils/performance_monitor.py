import asyncio
import functools
import logging
import time
from collections import defaultdict


class PerformanceStats:

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.operations = {}
        self.last_summary_time = time.time()
        self.summary_interval = 60
        self.log_enabled = True

    def record(self, operation, duration):
        if not self.log_enabled:
            return

        if operation not in self.operations:
            self.operations[operation] = {
                'count': 0,
                'total_time': 0.0,
                'min_time': float('inf'),
                'max_time': 0.0,
                'slow_count': 0
            }

        stats = self.operations[operation]
        stats['count'] += 1
        stats['total_time'] += duration
        stats['min_time'] = min(stats['min_time'], duration)
        stats['max_time'] = max(stats['max_time'], duration)

    def should_log_summary(self):
        return self.log_enabled and (time.time() - self.last_summary_time >= self.summary_interval)

    def get_summary(self):
        if not self.operations:
            return []

        lines = ["Performance summary:"]

        for op_name, stats in sorted(self.operations.items()):
            count = stats['count']
            if count == 0:
                continue

            avg_time = stats['total_time'] / count

            lines.append(
                f"  {op_name}: {count} calls, avg {avg_time:.2f}s, "
                f"min {stats['min_time']:.2f}s, max {stats['max_time']:.2f}s"
            )

        self.operations.clear()
        self.last_summary_time = time.time()

        return lines


class PerformanceTracker:
    def __init__(self, logger=None, log_interval=60):
        self.logger = logger or logging.getLogger(__name__ + ".performance")
        self.stats = defaultdict(list)
        self.counts = defaultdict(int)
        self.last_summary_time = time.time()
        self.summary_interval = log_interval
        self.enabled = True
        self.ops_stats = {}

    def record(self, operation: str, duration: float):
        if not self.enabled:
            return

        self.stats[operation].append(duration)
        self.counts[operation] += 1

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
        if not self.stats:
            return []

        lines = ["Performance summary:"]

        for op, durations in sorted(self.stats.items()):
            if durations:
                avg = sum(durations) / len(durations)
                min_time = min(durations)
                max_time = max(durations)
                lines.append(
                    f"  {op}: {len(durations)} calls, avg {avg:.2f}s, "
                    f"min {min_time:.2f}s, max {max_time:.2f}s"
                )

        self.stats.clear()
        self.counts.clear()
        self.ops_stats.clear()
        self.last_summary_time = time.time()

        return lines

    def log_summary_if_needed(self):
        if not self.should_log_summary():
            return False

        summary = self.get_summary()

        for line in summary:
            self.logger.info(line)

        return bool(summary)


def monitor_performance(func=None):
    if func is None:
        return monitor_performance

    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                elapsed = time.time() - start_time
                # Log or store performance data here

        return async_wrapper
    else:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                elapsed = time.time() - start_time
                # Log or store performance data here

        return sync_wrapper


def monitor_admin_service(func):
    @functools.wraps(func)
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