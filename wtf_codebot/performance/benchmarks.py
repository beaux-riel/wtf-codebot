"""
Benchmarking suite for performance testing on sample projects.
"""

import time
import json
import statistics
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
import tempfile
import shutil
import logging
import subprocess
import psutil

from .profiler import PerformanceProfiler, ProfileResult, ProfileManager
from .cache import CacheManager
from .parallel import ParallelScanner, ParallelAnalyzer
from ..discovery.scanner import CodebaseScanner
from ..analyzers.registry import AnalyzerRegistry

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""
    name: str
    duration: float
    memory_peak_mb: float
    memory_avg_mb: float
    cpu_avg_percent: float
    files_processed: int
    lines_of_code: int
    throughput_files_per_sec: float
    throughput_loc_per_sec: float
    cache_hit_rate: float = 0.0
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass
class BenchmarkSuite:
    """Comprehensive benchmarking suite."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the benchmark suite.
        
        Args:
            output_dir: Directory to store benchmark results
        """
        self.output_dir = output_dir or Path.cwd() / "benchmark_results"
        self.output_dir.mkdir(exist_ok=True)
        
        self.profiler = PerformanceProfiler()
        self.profile_manager = ProfileManager()
        self.cache_manager = CacheManager()
        
        # Sample projects for testing
        self.sample_projects = [
            {
                'name': 'small_python_project',
                'url': 'https://github.com/pallets/click.git',
                'expected_files': 50,
                'expected_loc': 5000,
            },
            {
                'name': 'medium_python_project', 
                'url': 'https://github.com/psf/requests.git',
                'expected_files': 200,
                'expected_loc': 25000,
            },
            {
                'name': 'large_python_project',
                'url': 'https://github.com/django/django.git',
                'expected_files': 2000,
                'expected_loc': 200000,
            }
        ]
    
    def run_full_benchmark_suite(self) -> Dict[str, List[BenchmarkResult]]:
        """Run the complete benchmark suite."""
        logger.info("Starting full benchmark suite")
        
        all_results = {}
        
        # Download sample projects
        sample_dirs = self._prepare_sample_projects()
        
        try:
            for project_info, project_dir in zip(self.sample_projects, sample_dirs):
                if project_dir is None:
                    continue
                
                logger.info(f"Benchmarking project: {project_info['name']}")
                
                # Run all benchmark scenarios for this project
                project_results = []
                
                # Sequential scanning benchmark
                result = self.benchmark_sequential_scanning(project_dir, project_info['name'])
                if result:
                    project_results.append(result)
                
                # Parallel scanning benchmark
                for num_processes in [2, 4, mp.cpu_count()]:
                    result = self.benchmark_parallel_scanning(
                        project_dir, project_info['name'], num_processes
                    )
                    if result:
                        project_results.append(result)
                
                # Caching benchmarks
                result = self.benchmark_with_cache(project_dir, project_info['name'])
                if result:
                    project_results.append(result)
                
                # Analysis benchmarks
                result = self.benchmark_analysis(project_dir, project_info['name'])
                if result:
                    project_results.append(result)
                
                all_results[project_info['name']] = project_results
                
        finally:
            # Cleanup
            self._cleanup_sample_projects(sample_dirs)
        
        # Save results
        self._save_benchmark_results(all_results)
        
        # Generate report
        self._generate_benchmark_report(all_results)
        
        return all_results
    
    def benchmark_sequential_scanning(self, project_dir: Path, project_name: str) -> Optional[BenchmarkResult]:
        """Benchmark sequential file scanning."""
        logger.info(f"Benchmarking sequential scanning for {project_name}")
        
        try:
            scanner = CodebaseScanner(
                include_content=True,
                parse_ast=True
            )
            
            # Profile the scanning operation
            self.profiler.start_monitoring()
            start_time = time.time()
            
            codebase = scanner.scan_directory(project_dir)
            
            end_time = time.time()
            profile_result = self.profiler.stop_monitoring()
            
            # Calculate metrics
            duration = end_time - start_time
            files_processed = codebase.total_files
            lines_of_code = sum(
                len(file_node.content.splitlines()) if file_node.content else 0
                for file_node in codebase.files.values()
            )
            
            result = BenchmarkResult(
                name=f"{project_name}_sequential_scan",
                duration=duration,
                memory_peak_mb=profile_result.peak_memory_mb,
                memory_avg_mb=profile_result.avg_memory_mb,
                cpu_avg_percent=profile_result.avg_cpu_percent,
                files_processed=files_processed,
                lines_of_code=lines_of_code,
                throughput_files_per_sec=files_processed / duration if duration > 0 else 0,
                throughput_loc_per_sec=lines_of_code / duration if duration > 0 else 0,
                error_count=len(codebase.scan_errors),
                metadata={
                    'mode': 'sequential',
                    'include_content': True,
                    'parse_ast': True,
                }
            )
            
            self.profile_manager.add_profile(f"{project_name}_sequential", profile_result)
            return result
            
        except Exception as e:
            logger.error(f"Sequential scanning benchmark failed for {project_name}: {e}")
            return None
    
    def benchmark_parallel_scanning(self, project_dir: Path, project_name: str, 
                                  num_processes: int) -> Optional[BenchmarkResult]:
        """Benchmark parallel file scanning."""
        logger.info(f"Benchmarking parallel scanning for {project_name} with {num_processes} processes")
        
        try:
            scanner = ParallelScanner(num_processes=num_processes)
            
            # Profile the scanning operation
            self.profiler.start_monitoring()
            start_time = time.time()
            
            codebase = scanner.scan_directory_parallel(
                project_dir,
                include_content=True,
                parse_ast=True
            )
            
            end_time = time.time()
            profile_result = self.profiler.stop_monitoring()
            
            # Calculate metrics
            duration = end_time - start_time
            files_processed = codebase.total_files
            lines_of_code = sum(
                len(file_node.content.splitlines()) if file_node.content else 0
                for file_node in codebase.files.values()
            )
            
            result = BenchmarkResult(
                name=f"{project_name}_parallel_scan_{num_processes}p",
                duration=duration,
                memory_peak_mb=profile_result.peak_memory_mb,
                memory_avg_mb=profile_result.avg_memory_mb,
                cpu_avg_percent=profile_result.avg_cpu_percent,
                files_processed=files_processed,
                lines_of_code=lines_of_code,
                throughput_files_per_sec=files_processed / duration if duration > 0 else 0,
                throughput_loc_per_sec=lines_of_code / duration if duration > 0 else 0,
                error_count=len(codebase.scan_errors),
                metadata={
                    'mode': 'parallel',
                    'num_processes': num_processes,
                    'include_content': True,
                    'parse_ast': True,
                }
            )
            
            self.profile_manager.add_profile(f"{project_name}_parallel_{num_processes}p", profile_result)
            return result
            
        except Exception as e:
            logger.error(f"Parallel scanning benchmark failed for {project_name}: {e}")
            return None
    
    def benchmark_with_cache(self, project_dir: Path, project_name: str) -> Optional[BenchmarkResult]:
        """Benchmark scanning with caching enabled."""
        logger.info(f"Benchmarking with cache for {project_name}")
        
        try:
            # Clear cache first
            self.cache_manager.clear_all()
            
            scanner = CodebaseScanner(
                include_content=True,
                parse_ast=True
            )
            
            # First run (cold cache)
            start_time = time.time()
            codebase = scanner.scan_directory(project_dir)
            first_duration = time.time() - start_time
            
            # Simulate caching by storing results
            for file_path, file_node in codebase.files.items():
                cache_key = self.cache_manager.get_content_hash(file_node.content or "")
                self.cache_manager.set_analysis_result(
                    cache_key, file_node, file_path=file_path
                )
            
            # Second run (warm cache)
            self.profiler.start_monitoring()
            start_time = time.time()
            
            # Simulate cache hits
            cache_hits = 0
            cache_misses = 0
            
            for file_path, file_node in codebase.files.items():
                cache_key = self.cache_manager.get_content_hash(file_node.content or "")
                cached_result = self.cache_manager.get_analysis_result(cache_key)
                if cached_result:
                    cache_hits += 1
                else:
                    cache_misses += 1
            
            end_time = time.time()
            profile_result = self.profiler.stop_monitoring()
            
            cache_hit_rate = cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0
            
            # Calculate metrics
            duration = end_time - start_time
            files_processed = codebase.total_files
            lines_of_code = sum(
                len(file_node.content.splitlines()) if file_node.content else 0
                for file_node in codebase.files.values()
            )
            
            result = BenchmarkResult(
                name=f"{project_name}_cached_scan",
                duration=duration,
                memory_peak_mb=profile_result.peak_memory_mb,
                memory_avg_mb=profile_result.avg_memory_mb,
                cpu_avg_percent=profile_result.avg_cpu_percent,
                files_processed=files_processed,
                lines_of_code=lines_of_code,
                throughput_files_per_sec=files_processed / duration if duration > 0 else 0,
                throughput_loc_per_sec=lines_of_code / duration if duration > 0 else 0,
                cache_hit_rate=cache_hit_rate,
                metadata={
                    'mode': 'cached',
                    'cache_hits': cache_hits,
                    'cache_misses': cache_misses,
                    'first_run_duration': first_duration,
                    'speedup': first_duration / duration if duration > 0 else 0,
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Cache benchmark failed for {project_name}: {e}")
            return None
    
    def benchmark_analysis(self, project_dir: Path, project_name: str) -> Optional[BenchmarkResult]:
        """Benchmark code analysis."""
        logger.info(f"Benchmarking analysis for {project_name}")
        
        try:
            # First scan the codebase
            scanner = CodebaseScanner()
            codebase = scanner.scan_directory(project_dir)
            
            # Get analyzers
            registry = AnalyzerRegistry()
            analyzers = {
                'python': registry.get_analyzer('python'),
                'javascript': registry.get_analyzer('javascript'),
            }
            
            # Filter out None analyzers
            analyzers = {k: v for k, v in analyzers.items() if v is not None}
            
            if not analyzers:
                logger.warning(f"No analyzers available for {project_name}")
                return None
            
            # Run analysis
            self.profiler.start_monitoring()
            start_time = time.time()
            
            all_results = {}
            for name, analyzer in analyzers.items():
                result = analyzer.analyze_codebase(codebase)
                all_results[name] = result
            
            end_time = time.time()
            profile_result = self.profiler.stop_monitoring()
            
            # Calculate metrics
            duration = end_time - start_time
            total_findings = sum(len(result.findings) for result in all_results.values())
            total_metrics = sum(len(result.metrics) for result in all_results.values())
            
            result = BenchmarkResult(
                name=f"{project_name}_analysis",
                duration=duration,
                memory_peak_mb=profile_result.peak_memory_mb,
                memory_avg_mb=profile_result.avg_memory_mb,
                cpu_avg_percent=profile_result.avg_cpu_percent,
                files_processed=codebase.total_files,
                lines_of_code=sum(
                    len(file_node.content.splitlines()) if file_node.content else 0
                    for file_node in codebase.files.values()
                ),
                throughput_files_per_sec=codebase.total_files / duration if duration > 0 else 0,
                throughput_loc_per_sec=0,  # Calculated below
                metadata={
                    'mode': 'analysis',
                    'analyzers_used': list(analyzers.keys()),
                    'total_findings': total_findings,
                    'total_metrics': total_metrics,
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis benchmark failed for {project_name}: {e}")
            return None
    
    def _prepare_sample_projects(self) -> List[Optional[Path]]:
        """Download and prepare sample projects for testing."""
        project_dirs = []
        
        for project_info in self.sample_projects:
            try:
                project_dir = self._download_project(project_info)
                project_dirs.append(project_dir)
                logger.info(f"Prepared project: {project_info['name']}")
            except Exception as e:
                logger.warning(f"Failed to prepare project {project_info['name']}: {e}")
                project_dirs.append(None)
        
        return project_dirs
    
    def _download_project(self, project_info: Dict[str, Any]) -> Path:
        """Download a sample project."""
        temp_dir = Path(tempfile.mkdtemp())
        project_dir = temp_dir / project_info['name']
        
        # Try to clone the repository
        try:
            result = subprocess.run([
                'git', 'clone', '--depth', '1', 
                project_info['url'], str(project_dir)
            ], check=True, capture_output=True, text=True)
            
            logger.info(f"Cloned {project_info['name']} to {project_dir}")
            return project_dir
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git clone failed for {project_info['name']}: {e}")
            
            # Fallback: create a synthetic project
            return self._create_synthetic_project(project_dir, project_info)
    
    def _create_synthetic_project(self, project_dir: Path, project_info: Dict[str, Any]) -> Path:
        """Create a synthetic project for testing when git clone fails."""
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Calculate approximate files and lines needed
        target_files = project_info.get('expected_files', 100)
        target_loc = project_info.get('expected_loc', 10000)
        lines_per_file = target_loc // target_files
        
        logger.info(f"Creating synthetic project with {target_files} files, ~{target_loc} LOC")
        
        # Create Python files
        for i in range(target_files):
            file_path = project_dir / f"module_{i:03d}.py"
            
            # Generate synthetic Python code
            content = self._generate_synthetic_python_code(lines_per_file, i)
            
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Create some JavaScript files
        js_files = min(10, target_files // 10)
        for i in range(js_files):
            file_path = project_dir / f"script_{i:03d}.js"
            content = self._generate_synthetic_js_code(lines_per_file // 2, i)
            
            with open(file_path, 'w') as f:
                f.write(content)
        
        logger.info(f"Created synthetic project at {project_dir}")
        return project_dir
    
    def _generate_synthetic_python_code(self, num_lines: int, module_id: int) -> str:
        """Generate synthetic Python code."""
        lines = [
            f'"""Module {module_id} for benchmarking."""',
            '',
            'import os',
            'import sys',
            'from typing import List, Dict, Any',
            '',
            f'class Module{module_id}Class:',
            '    """Sample class for benchmarking."""',
            '    ',
            '    def __init__(self, name: str):',
            '        self.name = name',
            '        self.data = []',
            '    ',
            '    def add_data(self, item: Any) -> None:',
            '        """Add data to the module."""',
            '        self.data.append(item)',
            '    ',
            '    def process_data(self) -> List[Any]:',
            '        """Process the stored data."""',
            '        result = []',
            '        for item in self.data:',
            '            if isinstance(item, str):',
            '                result.append(item.upper())',
            '            elif isinstance(item, int):',
            '                result.append(item * 2)',
            '            else:',
            '                result.append(str(item))',
            '        return result',
            '',
            f'def function_{module_id}(param1: str, param2: int = 0) -> Dict[str, Any]:',
            '    """Sample function for benchmarking."""',
            '    result = {',
            '        "param1": param1,',
            '        "param2": param2,',
            '        "computed": param1 * param2 if param2 > 0 else param1,',
            '    }',
            '    return result',
            '',
        ]
        
        # Add more lines to reach target
        additional_lines_needed = max(0, num_lines - len(lines))
        for i in range(additional_lines_needed):
            if i % 5 == 0:
                lines.append(f'# Comment line {i}')
            else:
                lines.append(f'variable_{i} = "value_{i}"')
        
        return '\n'.join(lines)
    
    def _generate_synthetic_js_code(self, num_lines: int, module_id: int) -> str:
        """Generate synthetic JavaScript code."""
        lines = [
            f'// Module {module_id} for benchmarking',
            '',
            f'class Module{module_id} {{',
            '    constructor(name) {',
            '        this.name = name;',
            '        this.data = [];',
            '    }',
            '',
            '    addData(item) {',
            '        this.data.push(item);',
            '    }',
            '',
            '    processData() {',
            '        return this.data.map(item => {',
            '            if (typeof item === "string") {',
            '                return item.toUpperCase();',
            '            } else if (typeof item === "number") {',
            '                return item * 2;',
            '            } else {',
            '                return String(item);',
            '            }',
            '        });',
            '    }',
            '}',
            '',
            f'function function{module_id}(param1, param2 = 0) {{',
            '    return {',
            '        param1: param1,',
            '        param2: param2,',
            '        computed: param2 > 0 ? param1 * param2 : param1',
            '    };',
            '}',
            '',
        ]
        
        # Add more lines to reach target
        additional_lines_needed = max(0, num_lines - len(lines))
        for i in range(additional_lines_needed):
            if i % 5 == 0:
                lines.append(f'// Comment line {i}')
            else:
                lines.append(f'const variable{i} = "value{i}";')
        
        return '\n'.join(lines)
    
    def _cleanup_sample_projects(self, project_dirs: List[Optional[Path]]) -> None:
        """Clean up downloaded sample projects."""
        for project_dir in project_dirs:
            if project_dir and project_dir.exists():
                try:
                    shutil.rmtree(project_dir.parent)  # Remove the temp dir
                    logger.debug(f"Cleaned up {project_dir}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup {project_dir}: {e}")
    
    def _save_benchmark_results(self, results: Dict[str, List[BenchmarkResult]]) -> None:
        """Save benchmark results to files."""
        # Save as JSON
        json_file = self.output_dir / "benchmark_results.json"
        json_data = {
            project: [result.to_dict() for result in project_results]
            for project, project_results in results.items()
        }
        
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        logger.info(f"Saved benchmark results to {json_file}")
        
        # Save profiles
        profile_file = self.output_dir / "profiles.json"
        self.profile_manager.export_profiles(str(profile_file))
        logger.info(f"Saved profiles to {profile_file}")
    
    def _generate_benchmark_report(self, results: Dict[str, List[BenchmarkResult]]) -> None:
        """Generate a comprehensive benchmark report."""
        report_file = self.output_dir / "benchmark_report.md"
        
        with open(report_file, 'w') as f:
            f.write("# WTF CodeBot Performance Benchmark Report\n\n")
            f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # System information
            f.write("## System Information\n\n")
            f.write(f"- CPU Count: {psutil.cpu_count()}\n")
            f.write(f"- CPU Count (Logical): {psutil.cpu_count(logical=True)}\n")
            f.write(f"- Memory Total: {psutil.virtual_memory().total / (1024**3):.2f} GB\n")
            f.write(f"- Memory Available: {psutil.virtual_memory().available / (1024**3):.2f} GB\n\n")
            
            # Results summary
            f.write("## Benchmark Results Summary\n\n")
            
            for project_name, project_results in results.items():
                f.write(f"### {project_name}\n\n")
                
                if not project_results:
                    f.write("No results available.\n\n")
                    continue
                
                f.write("| Test | Duration (s) | Peak Memory (MB) | Throughput (files/s) | Cache Hit Rate |\n")
                f.write("|------|--------------|------------------|----------------------|----------------|\n")
                
                for result in project_results:
                    f.write(f"| {result.name} | {result.duration:.2f} | {result.memory_peak_mb:.1f} | "
                           f"{result.throughput_files_per_sec:.1f} | {result.cache_hit_rate:.2%} |\n")
                
                f.write("\n")
                
                # Performance comparison
                sequential_results = [r for r in project_results if 'sequential' in r.name]
                parallel_results = [r for r in project_results if 'parallel' in r.name]
                
                if sequential_results and parallel_results:
                    seq_duration = sequential_results[0].duration
                    best_parallel = min(parallel_results, key=lambda r: r.duration)
                    speedup = seq_duration / best_parallel.duration
                    
                    f.write(f"**Best Parallel Speedup**: {speedup:.2f}x "
                           f"({best_parallel.name} vs sequential)\n\n")
                
                # Cache performance
                cached_results = [r for r in project_results if 'cached' in r.name]
                if cached_results and sequential_results:
                    cached = cached_results[0]
                    sequential = sequential_results[0]
                    cache_speedup = sequential.duration / cached.duration
                    
                    f.write(f"**Cache Speedup**: {cache_speedup:.2f}x "
                           f"(Cache hit rate: {cached.cache_hit_rate:.2%})\n\n")
            
            # Detailed analysis
            f.write("## Detailed Analysis\n\n")
            
            all_results = []
            for project_results in results.values():
                all_results.extend(project_results)
            
            if all_results:
                # Memory usage analysis
                memory_usage = [r.memory_peak_mb for r in all_results]
                f.write(f"### Memory Usage\n\n")
                f.write(f"- Average Peak Memory: {statistics.mean(memory_usage):.1f} MB\n")
                f.write(f"- Median Peak Memory: {statistics.median(memory_usage):.1f} MB\n")
                f.write(f"- Max Peak Memory: {max(memory_usage):.1f} MB\n")
                f.write(f"- Min Peak Memory: {min(memory_usage):.1f} MB\n\n")
                
                # Throughput analysis
                throughput = [r.throughput_files_per_sec for r in all_results if r.throughput_files_per_sec > 0]
                if throughput:
                    f.write(f"### Throughput\n\n")
                    f.write(f"- Average Throughput: {statistics.mean(throughput):.1f} files/sec\n")
                    f.write(f"- Median Throughput: {statistics.median(throughput):.1f} files/sec\n")
                    f.write(f"- Max Throughput: {max(throughput):.1f} files/sec\n")
                    f.write(f"- Min Throughput: {min(throughput):.1f} files/sec\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            f.write("Based on the benchmark results:\n\n")
            
            # Find best parallel configuration
            parallel_results = [r for r in all_results if 'parallel' in r.name]
            if parallel_results:
                best_parallel = min(parallel_results, key=lambda r: r.duration)
                processes = best_parallel.metadata.get('num_processes', 'unknown')
                f.write(f"- **Optimal parallel configuration**: {processes} processes\n")
            
            # Cache recommendations
            cached_results = [r for r in all_results if 'cached' in r.name]
            if cached_results:
                avg_hit_rate = statistics.mean(r.cache_hit_rate for r in cached_results)
                f.write(f"- **Caching effectiveness**: {avg_hit_rate:.1%} average hit rate\n")
                if avg_hit_rate > 0.8:
                    f.write("  - High cache hit rate suggests caching is very effective\n")
                elif avg_hit_rate > 0.5:
                    f.write("  - Moderate cache hit rate suggests caching provides some benefit\n")
                else:
                    f.write("  - Low cache hit rate suggests limited caching benefit\n")
            
            f.write("\n")
        
        logger.info(f"Generated benchmark report: {report_file}")


def run_performance_benchmarks(output_dir: Optional[Path] = None) -> Dict[str, List[BenchmarkResult]]:
    """Convenience function to run performance benchmarks."""
    suite = BenchmarkSuite(output_dir)
    return suite.run_full_benchmark_suite()


if __name__ == "__main__":
    import multiprocessing as mp
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run benchmarks
    results = run_performance_benchmarks()
    
    print("\n=== Benchmark Summary ===")
    for project_name, project_results in results.items():
        print(f"\n{project_name}:")
        for result in project_results:
            print(f"  {result.name}: {result.duration:.2f}s, "
                  f"{result.memory_peak_mb:.1f}MB, "
                  f"{result.throughput_files_per_sec:.1f} files/s")
