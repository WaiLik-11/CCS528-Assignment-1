"""Timing helpers shared by the measurement experiments."""
import statistics
import time
from collections.abc import Callable

def sample_ms(fn: Callable[[], object], runs: int, warmup: int = 5) -> list[float]:
    """Call fn() `runs` times and return each wall-clock duration in milliseconds.

    A few warm-up calls run first so one-off costs (library loading, CPU cache misses) do not skew the first samples.
    """
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1e6)
    return samples

def sample_cpu_ms(fn: Callable[[], object], samples: int = 20, warmup: int = 5, min_batch_ms: float = 20.0) -> list[float]:
    """Per-call CPU time (user + system) in milliseconds, as `samples` batch averages.

    The OS process-CPU clock advances in coarse ticks (commonly ~15 ms on Windows), too
    coarse to resolve one sub-millisecond call directly: a single call usually reads as
    exactly 0, with an occasional tick producing a huge outlier. Each returned sample
    instead times a batch of calls large enough to clear min_batch_ms, then divides by
    the batch size, so the result stays meaningful however fast fn() is.
    """
    for _ in range(warmup):
        fn()
    batch = 1
    while True:
        start = time.process_time_ns()
        for _ in range(batch):
            fn()
        if (time.process_time_ns() - start) / 1e6 >= min_batch_ms:
            break
        batch *= 2
    result = []
    for _ in range(samples):
        start = time.process_time_ns()
        for _ in range(batch):
            fn()
        result.append((time.process_time_ns() - start) / 1e6 / batch)
    return result

def summarize(samples: list[float]) -> dict[str, float]:
    """Mean, standard deviation, median, min and max of a list of samples."""
    return {
        "mean": statistics.fmean(samples),
        "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }
