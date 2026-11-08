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

def summarize(samples: list[float]) -> dict[str, float]:
    """Mean, standard deviation, median, min and max of a list of samples."""
    return {
        "mean": statistics.fmean(samples),
        "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }
