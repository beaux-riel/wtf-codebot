"""
Performance optimization module for WTF CodeBot.

This module provides tools for profiling, caching, and parallel processing
to optimize performance on large codebases.
"""

from .profiler import PerformanceProfiler, ProfileResult
from .cache import AnalysisCache, CacheManager
from .parallel import ParallelScanner, ParallelAnalyzer
from .benchmarks import BenchmarkSuite, BenchmarkResult

__all__ = [
    'PerformanceProfiler',
    'ProfileResult',
    'AnalysisCache',
    'CacheManager',
    'ParallelScanner',
    'ParallelAnalyzer',
    'BenchmarkSuite',
    'BenchmarkResult',
]
