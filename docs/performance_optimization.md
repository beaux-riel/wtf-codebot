# Performance Optimization Guide

This guide covers the comprehensive performance optimization features implemented in WTF CodeBot, including profiling, caching, parallel processing, and benchmarking.

## Overview

The performance optimization system consists of four main components:

1. **Performance Profiler** - Memory and CPU profiling with timeline tracking
2. **Analysis Cache** - Multi-tier caching with intelligent invalidation
3. **Parallel Processing** - Multiprocessing for file parsing and analysis
4. **Benchmark Suite** - Comprehensive performance testing framework

## Quick Start

### Basic Profiling

```python
from wtf_codebot.performance.profiler import PerformanceProfiler

# Create a profiler
profiler = PerformanceProfiler(sample_interval=0.1)

# Profile a function
@profiler.profile_function
def my_analysis_function():
    # Your analysis code here
    pass

# Or use manual profiling
profiler.start_monitoring()
# ... your code ...
profile_result = profiler.stop_monitoring()

print(f"Duration: {profile_result.duration:.2f}s")
print(f"Peak Memory: {profile_result.peak_memory_mb:.1f}MB")
```

### Using Cache

```python
from wtf_codebot.performance.cache import CacheManager

# Create cache manager
cache = CacheManager()

# Cache analysis results
cache.set_analysis_result("key", result, file_path="file.py")

# Retrieve cached results
cached_result = cache.get_analysis_result("key")
```

### Parallel Processing

```python
from wtf_codebot.performance.parallel import ParallelScanner

# Use parallel scanner
scanner = ParallelScanner(num_processes=4)
codebase = scanner.scan_directory_parallel(project_path)
```

### Running Benchmarks

```bash
# Benchmark a specific project
python scripts/run_benchmarks.py --project /path/to/project --parallel 4 --cache

# Run full benchmark suite
python scripts/run_benchmarks.py --full-suite
```

## Detailed Features

### 1. Performance Profiler

The `PerformanceProfiler` provides comprehensive monitoring of memory usage, CPU consumption, and execution time.

#### Features:
- **Real-time monitoring** with configurable sampling intervals
- **Memory timeline tracking** with peak usage detection
- **CPU usage monitoring** with average and timeline data
- **Memory allocation tracing** using Python's tracemalloc
- **Function decorators** for easy integration
- **Profile management** for collecting and analyzing multiple runs

#### Example Usage:

```python
from wtf_codebot.performance.profiler import PerformanceProfiler, ProfileManager

# Initialize profiler
profiler = PerformanceProfiler(
    sample_interval=0.1,  # Sample every 100ms
    trace_memory=True     # Enable memory tracing
)

# Manual profiling
profiler.start_monitoring()

# Your code here
from wtf_codebot.discovery.scanner import CodebaseScanner
scanner = CodebaseScanner()
codebase = scanner.scan_directory("/path/to/project")

profile_result = profiler.stop_monitoring()

# Analyze results
print(f"Execution time: {profile_result.duration:.2f} seconds")
print(f"Peak memory: {profile_result.peak_memory_mb:.1f} MB")
print(f"Average CPU: {profile_result.avg_cpu_percent:.1f}%")
print(f"Memory samples: {len(profile_result.memory_timeline)}")

# Profile manager for multiple runs
manager = ProfileManager()
manager.add_profile("scan_test", profile_result)
summary = manager.get_summary()
```

#### Decorator Usage:

```python
from wtf_codebot.performance.profiler import profile_performance

@profile_performance(sample_interval=0.05, trace_memory=True)
def analyze_large_codebase(path):
    scanner = CodebaseScanner()
    return scanner.scan_directory(path)

# Function is automatically profiled
result = analyze_large_codebase("/large/project")

# Access profile results
profiles = analyze_large_codebase._profile_results
latest_profile = profiles[-1]
```

### 2. Analysis Cache

The caching system provides multi-tier caching with intelligent invalidation based on file changes.

#### Architecture:
- **Memory Cache**: Fast in-memory LRU cache for immediate access
- **Persistent Cache**: SQLite-based storage for cross-session persistence
- **File Change Detection**: Automatic invalidation when files are modified
- **Dependency Tracking**: Invalidate dependent analyses when dependencies change

#### Features:
- **TTL (Time-To-Live)** support for automatic expiration
- **File hash-based invalidation** for accurate change detection
- **Dependency tracking** for complex invalidation scenarios
- **LRU eviction** for memory management
- **Statistics and monitoring** for cache performance analysis

#### Example Usage:

```python
from wtf_codebot.performance.cache import CacheManager

# Initialize cache manager
cache_manager = CacheManager(cache_dir="./cache")

# Cache analysis results
file_path = "/path/to/file.py"
analysis_result = {"findings": [], "metrics": []}

cache_manager.set_analysis_result(
    key="python_analysis_file.py",
    result=analysis_result,
    file_path=file_path,
    dependencies=["config.py", "utils.py"],
    ttl=3600  # 1 hour
)

# Retrieve cached results
cached_result = cache_manager.get_analysis_result("python_analysis_file.py")

# Check for file changes and invalidate if needed
changed_files = cache_manager.check_file_changes([file_path])
if changed_files:
    print(f"Files changed: {changed_files}")

# Get cache statistics
stats = cache_manager.stats()
print(f"Memory cache hit rate: {stats['memory_cache']['hit_rate']:.2%}")
print(f"Persistent cache entries: {stats['persistent_cache']['total_entries']}")
```

#### Cache Configuration:

```python
from wtf_codebot.performance.cache import AnalysisCache, PersistentCache

# Configure memory cache
memory_cache = AnalysisCache(
    max_size=1000,      # Maximum entries
    default_ttl=3600    # Default TTL in seconds
)

# Configure persistent cache
persistent_cache = PersistentCache(
    db_path="./cache/analysis.db",
    default_ttl=24*3600  # 24 hours
)
```

### 3. Parallel Processing

The parallel processing system uses multiprocessing to distribute file parsing and analysis across multiple CPU cores.

#### Components:
- **ParallelScanner**: Parallel file scanning and parsing
- **ParallelAnalyzer**: Parallel code analysis
- **WorkerProcess**: Individual worker process handling
- **Task Queue**: Queue-based task distribution

#### Features:
- **Automatic CPU detection** for optimal process count
- **Chunked processing** for large file sets
- **Error isolation** preventing single file failures from affecting others
- **Progress monitoring** with detailed logging
- **Configurable process count** for different workloads

#### Example Usage:

```python
from wtf_codebot.performance.parallel import ParallelScanner, ParallelAnalyzer
from pathlib import Path

# Parallel file scanning
scanner = ParallelScanner(
    num_processes=4,  # Use 4 processes
    chunk_size=100    # Process 100 files per chunk
)

codebase = scanner.scan_directory_parallel(
    root_path=Path("/large/project"),
    include_content=True,
    parse_ast=True,
    max_file_size=10*1024*1024  # 10MB max file size
)

print(f"Scanned {codebase.total_files} files")
print(f"Errors: {len(codebase.scan_errors)}")

# Parallel analysis
from wtf_codebot.analyzers.registry import AnalyzerRegistry

registry = AnalyzerRegistry()
analyzers = {
    'python': registry.get_analyzer('python'),
    'javascript': registry.get_analyzer('javascript')
}

parallel_analyzer = ParallelAnalyzer(num_processes=4)
results = parallel_analyzer.analyze_codebase_parallel(codebase, analyzers)

for analyzer_name, result in results.items():
    print(f"{analyzer_name}: {len(result.findings)} findings")
```

#### Performance Considerations:

- **Optimal Process Count**: Usually CPU core count, but may vary based on I/O vs CPU intensity
- **Memory Usage**: Each process has its own memory space, so total memory usage scales linearly
- **Overhead**: Process creation and IPC overhead means parallel processing is beneficial mainly for larger codebases
- **File Size Distribution**: Works best when files are relatively uniform in size

### 4. Benchmark Suite

The benchmark suite provides comprehensive performance testing across different configurations and project sizes.

#### Features:
- **Multiple test scenarios**: Sequential, parallel, cached processing
- **Synthetic project generation** for consistent testing
- **Real project integration** with popular open-source repositories
- **Comprehensive reporting** with markdown and JSON output
- **Performance metrics** including throughput, memory usage, and CPU utilization
- **Recommendation system** based on benchmark results

#### Example Usage:

```python
from wtf_codebot.performance.benchmarks import BenchmarkSuite, run_performance_benchmarks

# Run full benchmark suite
results = run_performance_benchmarks(output_dir=Path("./benchmarks"))

# Custom benchmark suite
suite = BenchmarkSuite(output_dir=Path("./custom_benchmarks"))

# Benchmark specific project
project_results = suite.benchmark_sequential_scanning(
    project_dir=Path("/my/project"),
    project_name="my_project"
)

print(f"Duration: {project_results.duration:.2f}s")
print(f"Throughput: {project_results.throughput_files_per_sec:.1f} files/s")
print(f"Memory: {project_results.memory_peak_mb:.1f}MB")
```

#### Command Line Interface:

```bash
# Benchmark specific project with all optimizations
python scripts/run_benchmarks.py \
    --project /path/to/project \
    --parallel 4 \
    --cache \
    --verbose

# Run full benchmark suite
python scripts/run_benchmarks.py --full-suite --verbose

# Benchmark current project
python scripts/run_benchmarks.py --project . --parallel 2 --cache
```

## Performance Metrics

### Key Metrics Tracked:

1. **Execution Time**: Total time for operation completion
2. **Peak Memory Usage**: Maximum memory consumption during execution
3. **Average Memory Usage**: Average memory consumption over time
4. **CPU Utilization**: Average CPU usage during execution
5. **Throughput**: Files processed per second
6. **Cache Hit Rate**: Percentage of cache hits vs misses
7. **Error Rate**: Number of processing errors encountered

### Benchmark Results Interpretation:

#### Sequential vs Parallel Performance:
- **Small projects (<50 files)**: Parallel processing may be slower due to overhead
- **Medium projects (50-500 files)**: 1.5-3x speedup typical with 2-4 processes
- **Large projects (500+ files)**: 2-4x speedup possible with optimal process count

#### Cache Performance:
- **First run**: No cache benefit, establishes baseline
- **Subsequent runs**: 10-1000x speedup possible with high cache hit rates
- **File modification**: Automatic invalidation ensures accuracy

#### Memory Usage:
- **Sequential**: Memory usage scales with file size and complexity
- **Parallel**: ~2-4x memory usage due to multiple processes
- **Cache**: Additional memory for cache storage, but faster processing

## Sample Benchmark Results

Here's an example of the benchmark results from our test run:

```
=== Benchmark Results for wtf-codebot ===
Sequential scan: 2.13s, 176.6MB peak, 55.9 files/s
Parallel scan (2p): 0.77s, 289.9MB peak, 154.1 files/s (2.75x speedup)
Cached scan: 0.003s, 323.0MB peak, 43,781.9 files/s (399.4x speedup, 100% hit rate)
```

### Analysis:
- **Parallel processing** achieved 2.75x speedup with 2 processes
- **Memory usage** increased by ~64% for parallel processing
- **Caching** provided dramatic 399x speedup with perfect hit rate
- **Throughput** increased from 56 files/s to 154 files/s with parallelization

## Best Practices

### 1. Profiling
- Use appropriate sampling intervals (0.1s for most cases)
- Enable memory tracing only when needed (has overhead)
- Profile representative workloads
- Collect multiple samples for statistical significance

### 2. Caching
- Set appropriate TTL values based on file change frequency
- Monitor cache hit rates and adjust strategies accordingly
- Use dependency tracking for complex analysis relationships
- Regularly clean up expired entries

### 3. Parallel Processing
- Start with CPU core count for process number
- Monitor memory usage scaling
- Consider I/O vs CPU bound nature of workload
- Use progress monitoring for long-running operations

### 4. Benchmarking
- Test with realistic project sizes
- Include both synthetic and real projects
- Run multiple iterations for consistent results
- Document system specifications for result comparison

## Integration Guide

### Adding Performance Monitoring to Existing Code

1. **Identify bottlenecks** using the profiler
2. **Add caching** for expensive operations
3. **Implement parallel processing** for independent tasks
4. **Benchmark improvements** to validate optimizations

### Example Integration:

```python
from wtf_codebot.performance import (
    PerformanceProfiler, CacheManager, ParallelScanner
)

class OptimizedAnalyzer:
    def __init__(self):
        self.profiler = PerformanceProfiler()
        self.cache = CacheManager()
        self.parallel_scanner = ParallelScanner()
    
    def analyze_project(self, project_path):
        # Check cache first
        cache_key = f"analysis_{project_path.name}"
        cached_result = self.cache.get_analysis_result(cache_key)
        if cached_result:
            return cached_result
        
        # Profile the analysis
        self.profiler.start_monitoring()
        
        # Use parallel scanning for large projects
        if self._is_large_project(project_path):
            codebase = self.parallel_scanner.scan_directory_parallel(project_path)
        else:
            scanner = CodebaseScanner()
            codebase = scanner.scan_directory(project_path)
        
        # Perform analysis
        result = self._analyze_codebase(codebase)
        
        profile_result = self.profiler.stop_monitoring()
        
        # Cache the result
        self.cache.set_analysis_result(
            cache_key, result, file_path=project_path
        )
        
        # Log performance metrics
        print(f"Analysis completed in {profile_result.duration:.2f}s")
        print(f"Peak memory: {profile_result.peak_memory_mb:.1f}MB")
        
        return result
```

## Troubleshooting

### Common Issues:

1. **High Memory Usage in Parallel Processing**
   - Reduce number of processes
   - Implement chunked processing
   - Monitor individual process memory usage

2. **Low Cache Hit Rates**
   - Check file change detection logic
   - Verify cache key generation
   - Review TTL settings

3. **Slower Parallel Performance**
   - Verify sufficient file count for parallelization benefit
   - Check for I/O bottlenecks
   - Monitor process creation overhead

4. **Profile Data Collection Issues**
   - Ensure sufficient sampling time
   - Check for interference from system monitoring
   - Verify memory tracing compatibility

### Performance Debugging:

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Monitor cache statistics
stats = cache_manager.stats()
print(f"Cache statistics: {stats}")

# Profile with detailed memory tracing
profiler = PerformanceProfiler(trace_memory=True)
# ... run analysis ...
profile_result = profiler.stop_monitoring()

if profile_result.memory_traces:
    for trace in profile_result.memory_traces[:5]:
        print(f"Memory trace: {trace}")
```

## Future Enhancements

Planned improvements include:

1. **Distributed Processing**: Support for multi-machine processing
2. **Advanced Cache Strategies**: ML-based cache prediction
3. **GPU Acceleration**: CUDA support for compatible operations
4. **Real-time Monitoring**: Live performance dashboards
5. **Adaptive Optimization**: Automatic parameter tuning based on workload characteristics

---

For more detailed API documentation, see the individual module documentation in the `wtf_codebot.performance` package.
