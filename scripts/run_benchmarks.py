#!/usr/bin/env python3
"""
CLI tool for running performance benchmarks.
"""

import argparse
import logging
import sys
from pathlib import Path
import json
import time

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from wtf_codebot.performance.benchmarks import BenchmarkSuite, run_performance_benchmarks
from wtf_codebot.performance.profiler import PerformanceProfiler
from wtf_codebot.performance.cache import CacheManager
from wtf_codebot.performance.parallel import ParallelScanner
from wtf_codebot.discovery.scanner import CodebaseScanner


def setup_logging(level=logging.INFO):
    """Setup logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )


def benchmark_single_project(project_path: Path, output_dir: Path, 
                           num_processes: int = None, enable_cache: bool = False):
    """Benchmark a single project."""
    logger = logging.getLogger(__name__)
    
    if not project_path.exists():
        logger.error(f"Project path does not exist: {project_path}")
        return None
    
    output_dir.mkdir(exist_ok=True)
    project_name = project_path.name
    
    logger.info(f"Benchmarking project: {project_name}")
    logger.info(f"Project path: {project_path}")
    logger.info(f"Output directory: {output_dir}")
    
    results = []
    
    # Sequential scanning benchmark
    logger.info("Running sequential scanning benchmark...")
    try:
        profiler = PerformanceProfiler(sample_interval=0.1)
        
        profiler.start_monitoring()
        start_time = time.time()
        
        scanner = CodebaseScanner(include_content=True, parse_ast=True)
        codebase = scanner.scan_directory(project_path)
        
        end_time = time.time()
        profile_result = profiler.stop_monitoring()
        
        duration = end_time - start_time
        files_processed = codebase.total_files
        lines_of_code = sum(
            len(file_node.content.splitlines()) if file_node.content else 0
            for file_node in codebase.files.values()
        )
        
        sequential_result = {
            'name': f'{project_name}_sequential',
            'duration': duration,
            'peak_memory_mb': profile_result.peak_memory_mb,
            'avg_memory_mb': profile_result.avg_memory_mb,
            'cpu_avg_percent': profile_result.avg_cpu_percent,
            'files_processed': files_processed,
            'lines_of_code': lines_of_code,
            'throughput_files_per_sec': files_processed / duration if duration > 0 else 0,
            'throughput_loc_per_sec': lines_of_code / duration if duration > 0 else 0,
            'error_count': len(codebase.scan_errors),
            'mode': 'sequential'
        }
        results.append(sequential_result)
        
        logger.info(f"Sequential scan completed: {duration:.2f}s, "
                   f"{files_processed} files, {lines_of_code} LOC")
        
    except Exception as e:
        logger.error(f"Sequential scanning failed: {e}")
    
    # Parallel scanning benchmark
    if num_processes:
        logger.info(f"Running parallel scanning benchmark with {num_processes} processes...")
        try:
            profiler = PerformanceProfiler(sample_interval=0.1)
            
            profiler.start_monitoring()
            start_time = time.time()
            
            scanner = ParallelScanner(num_processes=num_processes)
            codebase = scanner.scan_directory_parallel(
                project_path, include_content=True, parse_ast=True
            )
            
            end_time = time.time()
            profile_result = profiler.stop_monitoring()
            
            duration = end_time - start_time
            files_processed = codebase.total_files
            lines_of_code = sum(
                len(file_node.content.splitlines()) if file_node.content else 0
                for file_node in codebase.files.values()
            )
            
            parallel_result = {
                'name': f'{project_name}_parallel_{num_processes}p',
                'duration': duration,
                'peak_memory_mb': profile_result.peak_memory_mb,
                'avg_memory_mb': profile_result.avg_memory_mb,
                'cpu_avg_percent': profile_result.avg_cpu_percent,
                'files_processed': files_processed,
                'lines_of_code': lines_of_code,
                'throughput_files_per_sec': files_processed / duration if duration > 0 else 0,
                'throughput_loc_per_sec': lines_of_code / duration if duration > 0 else 0,
                'error_count': len(codebase.scan_errors),
                'mode': 'parallel',
                'num_processes': num_processes
            }
            results.append(parallel_result)
            
            # Calculate speedup
            if len(results) >= 2:
                speedup = results[0]['duration'] / parallel_result['duration']
                logger.info(f"Parallel scan completed: {duration:.2f}s, "
                           f"speedup: {speedup:.2f}x")
            else:
                logger.info(f"Parallel scan completed: {duration:.2f}s")
                
        except Exception as e:
            logger.error(f"Parallel scanning failed: {e}")
    
    # Cache benchmark
    if enable_cache:
        logger.info("Running cache benchmark...")
        try:
            cache_manager = CacheManager(cache_dir=output_dir / "cache")
            cache_manager.clear_all()
            
            # First run (cold cache)
            scanner = CodebaseScanner(include_content=True, parse_ast=True)
            
            start_time = time.time()
            codebase = scanner.scan_directory(project_path)
            first_duration = time.time() - start_time
            
            # Cache results
            for file_path, file_node in codebase.files.items():
                cache_key = cache_manager.get_content_hash(file_node.content or "")
                cache_manager.set_analysis_result(
                    cache_key, file_node, file_path=file_path
                )
            
            # Second run (warm cache simulation)
            profiler = PerformanceProfiler(sample_interval=0.1)
            profiler.start_monitoring()
            start_time = time.time()
            
            cache_hits = 0
            cache_misses = 0
            
            for file_path, file_node in codebase.files.items():
                cache_key = cache_manager.get_content_hash(file_node.content or "")
                cached_result = cache_manager.get_analysis_result(cache_key)
                if cached_result:
                    cache_hits += 1
                else:
                    cache_misses += 1
            
            end_time = time.time()
            profile_result = profiler.stop_monitoring()
            
            duration = end_time - start_time
            cache_hit_rate = cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0
            
            cache_result = {
                'name': f'{project_name}_cached',
                'duration': duration,
                'peak_memory_mb': profile_result.peak_memory_mb,
                'avg_memory_mb': profile_result.avg_memory_mb,
                'cpu_avg_percent': profile_result.avg_cpu_percent,
                'files_processed': codebase.total_files,
                'lines_of_code': sum(
                    len(file_node.content.splitlines()) if file_node.content else 0
                    for file_node in codebase.files.values()
                ),
                'throughput_files_per_sec': codebase.total_files / duration if duration > 0 else 0,
                'cache_hit_rate': cache_hit_rate,
                'mode': 'cached',
                'cache_hits': cache_hits,
                'cache_misses': cache_misses,
                'first_run_duration': first_duration,
                'speedup': first_duration / duration if duration > 0 else 0
            }
            results.append(cache_result)
            
            logger.info(f"Cache benchmark completed: {duration:.2f}s, "
                       f"hit rate: {cache_hit_rate:.2%}, "
                       f"speedup: {cache_result['speedup']:.2f}x")
            
        except Exception as e:
            logger.error(f"Cache benchmark failed: {e}")
    
    # Save results
    results_file = output_dir / f"{project_name}_benchmark_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            'project_name': project_name,
            'project_path': str(project_path),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': results
        }, f, indent=2)
    
    logger.info(f"Results saved to: {results_file}")
    
    # Generate summary report
    generate_summary_report(results, output_dir / f"{project_name}_summary.md", project_name)
    
    return results


def generate_summary_report(results, report_file, project_name):
    """Generate a summary report."""
    with open(report_file, 'w') as f:
        f.write(f"# Performance Benchmark Report: {project_name}\n\n")
        f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Results Summary\n\n")
        f.write("| Test | Duration (s) | Peak Memory (MB) | Throughput (files/s) | Notes |\n")
        f.write("|------|--------------|------------------|----------------------|-------|\n")
        
        for result in results:
            notes = ""
            if 'speedup' in result:
                notes = f"Speedup: {result['speedup']:.2f}x"
            if 'cache_hit_rate' in result:
                notes += f", Hit rate: {result['cache_hit_rate']:.2%}"
            
            f.write(f"| {result['name']} | {result['duration']:.2f} | "
                   f"{result['peak_memory_mb']:.1f} | "
                   f"{result['throughput_files_per_sec']:.1f} | {notes} |\n")
        
        f.write("\n## Performance Analysis\n\n")
        
        # Find best performance
        if len(results) > 1:
            fastest = min(results, key=lambda r: r['duration'])
            f.write(f"**Fastest configuration**: {fastest['name']} "
                   f"({fastest['duration']:.2f}s)\n\n")
        
        # Memory usage
        avg_memory = sum(r['peak_memory_mb'] for r in results) / len(results)
        f.write(f"**Average peak memory usage**: {avg_memory:.1f} MB\n\n")
        
        # Recommendations
        f.write("## Recommendations\n\n")
        
        parallel_results = [r for r in results if 'parallel' in r['name']]
        if parallel_results:
            best_parallel = min(parallel_results, key=lambda r: r['duration'])
            sequential_results = [r for r in results if 'sequential' in r['name']]
            
            if sequential_results:
                speedup = sequential_results[0]['duration'] / best_parallel['duration']
                f.write(f"- **Parallel processing**: Use {best_parallel.get('num_processes', 'unknown')} processes "
                       f"for {speedup:.2f}x speedup\n")
        
        cache_results = [r for r in results if 'cached' in r['name']]
        if cache_results:
            cache_result = cache_results[0]
            if cache_result.get('cache_hit_rate', 0) > 0.5:
                f.write(f"- **Caching**: Highly effective with {cache_result['cache_hit_rate']:.2%} hit rate\n")
            else:
                f.write(f"- **Caching**: Limited benefit with {cache_result['cache_hit_rate']:.2%} hit rate\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='WTF CodeBot Performance Benchmarks')
    
    parser.add_argument('--project', type=Path, 
                       help='Path to project to benchmark (if not specified, runs full benchmark suite)')
    parser.add_argument('--output-dir', type=Path, default=Path.cwd() / 'benchmark_results',
                       help='Output directory for benchmark results')
    parser.add_argument('--parallel', type=int, metavar='N',
                       help='Enable parallel scanning with N processes')
    parser.add_argument('--cache', action='store_true',
                       help='Enable cache benchmarking')
    parser.add_argument('--full-suite', action='store_true',
                       help='Run full benchmark suite with sample projects')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    
    # Create output directory
    args.output_dir.mkdir(exist_ok=True)
    logger.info(f"Output directory: {args.output_dir}")
    
    if args.full_suite:
        # Run full benchmark suite
        logger.info("Running full benchmark suite...")
        try:
            results = run_performance_benchmarks(args.output_dir)
            
            print("\n=== Full Benchmark Suite Results ===")
            for project_name, project_results in results.items():
                print(f"\n{project_name}:")
                for result in project_results:
                    print(f"  {result.name}: {result.duration:.2f}s, "
                          f"{result.memory_peak_mb:.1f}MB, "
                          f"{result.throughput_files_per_sec:.1f} files/s")
            
            # Generate comprehensive report
            report_file = args.output_dir / "comprehensive_benchmark_report.md"
            logger.info(f"Comprehensive report available at: {report_file}")
            
        except Exception as e:
            logger.error(f"Full benchmark suite failed: {e}")
            return 1
    
    elif args.project:
        # Benchmark single project
        logger.info(f"Benchmarking single project: {args.project}")
        
        results = benchmark_single_project(
            args.project, 
            args.output_dir,
            num_processes=args.parallel,
            enable_cache=args.cache
        )
        
        if results:
            print(f"\n=== Benchmark Results for {args.project.name} ===")
            for result in results:
                print(f"{result['name']}: {result['duration']:.2f}s, "
                      f"{result['peak_memory_mb']:.1f}MB, "
                      f"{result['throughput_files_per_sec']:.1f} files/s")
        else:
            print("Benchmark failed!")
            return 1
    
    else:
        parser.print_help()
        return 1
    
    print(f"\nResults saved to: {args.output_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
