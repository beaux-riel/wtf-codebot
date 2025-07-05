"""
Unit tests for performance optimization components.
"""

import pytest
import time
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json
import pickle

from wtf_codebot.performance.profiler import (
    PerformanceProfiler, ProfileResult, ProfileManager, 
    profile_performance
)
from wtf_codebot.performance.cache import (
    AnalysisCache, PersistentCache, CacheManager, CacheEntry
)
from wtf_codebot.performance.parallel import (
    ParallelScanner, ParallelAnalyzer, ProcessingTask, 
    ProcessingResult, WorkerProcess
)
from wtf_codebot.performance.benchmarks import (
    BenchmarkSuite, BenchmarkResult, run_performance_benchmarks
)
from wtf_codebot.discovery.models import FileNode, FileType, CodebaseGraph


class TestPerformanceProfiler:
    """Test the performance profiler."""
    
    def test_profiler_initialization(self):
        """Test profiler initialization."""
        profiler = PerformanceProfiler(sample_interval=0.05, trace_memory=False)
        assert profiler.sample_interval == 0.05
        assert not profiler.trace_memory
        assert not profiler._monitoring
    
    def test_profiler_basic_monitoring(self):
        """Test basic monitoring functionality."""
        profiler = PerformanceProfiler(sample_interval=0.01, trace_memory=False)
        
        profiler.start_monitoring()
        assert profiler._monitoring
        
        # Do some work
        time.sleep(0.05)
        result = [i**2 for i in range(1000)]  # Some CPU work
        
        profile_result = profiler.stop_monitoring()
        
        assert isinstance(profile_result, ProfileResult)
        assert profile_result.duration > 0
        assert profile_result.peak_memory_mb >= 0
        assert len(profile_result.memory_timeline) > 0
        assert len(profile_result.cpu_timeline) > 0
    
    def test_profile_decorator(self):
        """Test the profile decorator."""
        @profile_performance(sample_interval=0.01, trace_memory=False)
        def test_function(n):
            return sum(i**2 for i in range(n))
        
        result = test_function(1000)
        assert result == sum(i**2 for i in range(1000))
        
        # Check that profile results were stored
        assert hasattr(test_function, '_profile_results')
        assert len(test_function._profile_results) > 0
        
        profile_result = test_function._profile_results[0]
        assert profile_result.function_name == 'test_function'
        assert profile_result.duration > 0
    
    def test_profile_manager(self):
        """Test the profile manager."""
        manager = ProfileManager()
        
        # Create some mock profile results
        result1 = ProfileResult(
            duration=1.0, peak_memory_mb=50.0, cpu_percent=25.0,
            function_name="test1"
        )
        result2 = ProfileResult(
            duration=2.0, peak_memory_mb=75.0, cpu_percent=50.0,
            function_name="test1"
        )
        
        manager.add_profile("test1", result1)
        manager.add_profile("test1", result2)
        
        summary = manager.get_summary()
        assert "test1" in summary
        assert summary["test1"]["count"] == 2
        assert summary["test1"]["duration"]["avg"] == 1.5
        assert summary["test1"]["peak_memory_mb"]["max"] == 75.0


class TestAnalysisCache:
    """Test the analysis cache."""
    
    def test_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = AnalysisCache(max_size=10, default_ttl=3600)
        
        # Test set and get
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Test non-existent key
        assert cache.get("nonexistent") is None
        
        # Test cache stats
        stats = cache.stats()
        assert stats["size"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
    
    def test_cache_ttl_expiration(self):
        """Test cache TTL expiration."""
        cache = AnalysisCache(default_ttl=0.1)  # 0.1 second TTL
        
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(0.2)
        assert cache.get("key1") is None
    
    def test_cache_eviction(self):
        """Test cache eviction with LRU."""
        cache = AnalysisCache(max_size=2)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")  # Should evict key1
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
    
    def test_cache_invalidation(self):
        """Test cache invalidation."""
        cache = AnalysisCache()
        
        cache.set("key1", "value1", file_hash="hash1")
        cache.set("key2", "value2", file_hash="hash2")
        cache.set("key3", "value3", dependencies=["file1.py"])
        
        # Test specific key invalidation
        assert cache.invalidate("key1")
        assert cache.get("key1") is None
        
        # Test file hash invalidation
        count = cache.invalidate_by_file_hash("hash2")
        assert count == 1
        assert cache.get("key2") is None
        
        # Test dependency invalidation
        count = cache.invalidate_by_dependency("file1.py")
        assert count == 1
        assert cache.get("key3") is None


class TestPersistentCache:
    """Test the persistent cache."""
    
    def test_persistent_cache_basic_operations(self):
        """Test basic persistent cache operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_cache.db"
            cache = PersistentCache(db_path, default_ttl=3600)
            
            # Test set and get
            cache.set("key1", {"data": "value1"})
            result = cache.get("key1")
            assert result == {"data": "value1"}
            
            # Test persistence - create new cache instance
            cache2 = PersistentCache(db_path)
            result = cache2.get("key1")
            assert result == {"data": "value1"}
    
    def test_persistent_cache_cleanup(self):
        """Test cleanup of expired entries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_cache.db"
            cache = PersistentCache(db_path, default_ttl=0.1)
            
            cache.set("key1", "value1")
            cache.set("key2", "value2", ttl=3600)  # Long TTL
            
            time.sleep(0.2)  # Wait for expiration
            
            cleaned = cache.cleanup_expired()
            assert cleaned == 1  # One expired entry
            
            assert cache.get("key1") is None
            assert cache.get("key2") == "value2"


class TestCacheManager:
    """Test the cache manager."""
    
    def test_cache_manager_initialization(self):
        """Test cache manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CacheManager(cache_dir=temp_dir)
            assert manager.cache_dir.exists()
            assert isinstance(manager.memory_cache, AnalysisCache)
            assert isinstance(manager.persistent_cache, PersistentCache)
    
    def test_cache_manager_operations(self):
        """Test cache manager operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CacheManager(cache_dir=temp_dir)
            
            # Test file hash generation
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("print('hello')")
            
            hash1 = manager.get_file_hash(test_file)
            hash2 = manager.get_file_hash(test_file)
            assert hash1 == hash2
            
            # Test analysis result caching
            manager.set_analysis_result("test_key", {"result": "data"}, file_path=test_file)
            result = manager.get_analysis_result("test_key")
            assert result == {"result": "data"}
    
    def test_file_change_detection(self):
        """Test file change detection."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = CacheManager(cache_dir=temp_dir)
            
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("print('hello')")
            
            # Cache something
            manager.set_analysis_result("test_key", "data", file_path=test_file)
            
            # Check no changes initially
            changed = manager.check_file_changes([test_file])
            assert len(changed) == 0
            
            # Modify file
            time.sleep(0.01)  # Ensure different timestamp
            test_file.write_text("print('hello world')")
            
            # Check for changes
            changed = manager.check_file_changes([test_file])
            assert len(changed) == 1
            assert str(test_file) in changed


class TestParallelProcessing:
    """Test parallel processing components."""
    
    def test_processing_task_creation(self):
        """Test processing task creation."""
        task = ProcessingTask(
            task_id="test_1",
            file_path=Path("test.py"),
            task_type="parse",
            config={"include_content": True}
        )
        
        assert task.task_id == "test_1"
        assert task.file_path == Path("test.py")
        assert task.task_type == "parse"
        assert task.config["include_content"] is True
    
    def test_worker_process_initialization(self):
        """Test worker process initialization."""
        worker = WorkerProcess(worker_id=1)
        
        success = worker.initialize({}, {})
        assert success
        assert worker.parser_factory is not None
    
    @patch('wtf_codebot.performance.parallel.subprocess.run')
    def test_parallel_scanner_synthetic_project(self, mock_subprocess):
        """Test parallel scanner with synthetic project."""
        # Mock git clone failure to use synthetic project
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'git')
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create some test files
            project_dir = Path(temp_dir) / "test_project"
            project_dir.mkdir()
            
            (project_dir / "test1.py").write_text("print('hello')")
            (project_dir / "test2.py").write_text("def func(): pass")
            (project_dir / "test3.js").write_text("console.log('hello');")
            
            scanner = ParallelScanner(num_processes=2)
            
            # This should work even with a small number of files
            codebase = scanner.scan_directory_parallel(
                project_dir,
                include_content=True,
                parse_ast=False  # Disable AST parsing for simplicity
            )
            
            assert isinstance(codebase, CodebaseGraph)
            assert len(codebase.files) >= 3


class TestBenchmarkSuite:
    """Test the benchmark suite."""
    
    def test_benchmark_result_creation(self):
        """Test benchmark result creation."""
        result = BenchmarkResult(
            name="test_benchmark",
            duration=1.5,
            memory_peak_mb=100.0,
            memory_avg_mb=80.0,
            cpu_avg_percent=25.0,
            files_processed=50,
            lines_of_code=1000,
            throughput_files_per_sec=33.33,
            throughput_loc_per_sec=666.67
        )
        
        assert result.name == "test_benchmark"
        assert result.duration == 1.5
        assert result.files_processed == 50
        
        # Test conversion to dict
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["name"] == "test_benchmark"
    
    def test_benchmark_suite_initialization(self):
        """Test benchmark suite initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            suite = BenchmarkSuite(output_dir=Path(temp_dir))
            
            assert suite.output_dir.exists()
            assert isinstance(suite.profiler, PerformanceProfiler)
            assert isinstance(suite.cache_manager, CacheManager)
            assert len(suite.sample_projects) > 0
    
    def test_synthetic_code_generation(self):
        """Test synthetic code generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            suite = BenchmarkSuite(output_dir=Path(temp_dir))
            
            # Test Python code generation
            python_code = suite._generate_synthetic_python_code(50, 1)
            assert "class Module1Class:" in python_code
            assert "def function_1(" in python_code
            assert len(python_code.splitlines()) >= 40
            
            # Test JavaScript code generation
            js_code = suite._generate_synthetic_js_code(30, 2)
            assert "class Module2 {" in js_code
            assert "function function2(" in js_code
            assert len(js_code.splitlines()) >= 25
    
    @patch('wtf_codebot.performance.benchmarks.subprocess.run')
    def test_synthetic_project_creation(self, mock_subprocess):
        """Test synthetic project creation."""
        # Mock git clone failure
        mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'git')
        
        with tempfile.TemporaryDirectory() as temp_dir:
            suite = BenchmarkSuite(output_dir=Path(temp_dir))
            
            project_info = {
                'name': 'test_project',
                'url': 'https://example.com/repo.git',
                'expected_files': 10,
                'expected_loc': 500
            }
            
            project_dir = suite._download_project(project_info)
            
            assert project_dir.exists()
            python_files = list(project_dir.glob("*.py"))
            js_files = list(project_dir.glob("*.js"))
            
            assert len(python_files) == 10
            assert len(js_files) >= 1
            
            # Verify content
            for py_file in python_files:
                content = py_file.read_text()
                assert len(content) > 0
                assert "class Module" in content
    
    def test_benchmark_sequential_scanning(self):
        """Test sequential scanning benchmark."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test project
            project_dir = Path(temp_dir) / "test_project"
            project_dir.mkdir()
            
            (project_dir / "test1.py").write_text("print('hello')\n# comment")
            (project_dir / "test2.py").write_text("def func():\n    return 42")
            
            suite = BenchmarkSuite(output_dir=Path(temp_dir))
            
            result = suite.benchmark_sequential_scanning(project_dir, "test_project")
            
            assert result is not None
            assert result.name == "test_project_sequential_scan"
            assert result.duration > 0
            assert result.files_processed >= 2
            assert result.throughput_files_per_sec > 0
            assert result.metadata["mode"] == "sequential"


class TestIntegration:
    """Integration tests for performance components."""
    
    def test_end_to_end_performance_optimization(self):
        """Test end-to-end performance optimization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test project
            project_dir = Path(temp_dir) / "test_project"
            project_dir.mkdir()
            
            # Create multiple Python files
            for i in range(5):
                file_path = project_dir / f"module_{i}.py"
                content = f"""
def function_{i}(x):
    '''Function {i} for testing.'''
    result = x * {i}
    return result

class Class{i}:
    '''Class {i} for testing.'''
    
    def __init__(self):
        self.value = {i}
    
    def process(self):
        return self.value * 2
"""
                file_path.write_text(content)
            
            # Test profiling
            profiler = PerformanceProfiler(sample_interval=0.01)
            
            @profiler.profile_function
            def scan_project():
                from wtf_codebot.discovery.scanner import CodebaseScanner
                scanner = CodebaseScanner()
                return scanner.scan_directory(project_dir)
            
            codebase = scan_project()
            
            # Verify scanning worked
            assert isinstance(codebase, CodebaseGraph)
            assert len(codebase.files) == 5
            
            # Verify profiling worked
            assert hasattr(scan_project, '_profile_results')
            profile_result = scan_project._profile_results[0]
            assert profile_result.duration > 0
            assert profile_result.peak_memory_mb > 0
            
            # Test caching
            cache_manager = CacheManager(cache_dir=temp_dir)
            
            # Cache some results
            for file_path, file_node in codebase.files.items():
                cache_key = f"analysis_{file_path}"
                cache_manager.set_analysis_result(
                    cache_key, {"analyzed": True}, file_path=file_path
                )
            
            # Verify caching worked
            stats = cache_manager.stats()
            assert stats['memory_cache']['size'] == 5
            
            # Test cache retrieval
            cached_result = cache_manager.get_analysis_result("analysis_module_0.py")
            assert cached_result == {"analyzed": True}
    
    def test_performance_comparison(self):
        """Test performance comparison between sequential and parallel processing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a larger test project
            project_dir = Path(temp_dir) / "large_project"
            project_dir.mkdir()
            
            # Create 20 Python files
            for i in range(20):
                file_path = project_dir / f"module_{i:02d}.py"
                content = f"""
# Module {i} for performance testing
import os
import sys
from typing import List, Dict

class TestClass{i}:
    '''Test class {i}.'''
    
    def __init__(self, name: str):
        self.name = name
        self.data = []
        
    def add_item(self, item):
        self.data.append(item)
        
    def process_items(self) -> List:
        return [str(item).upper() for item in self.data]

def test_function_{i}(param: int) -> Dict:
    '''Test function {i}.'''
    return {{
        'param': param,
        'result': param * {i},
        'module_id': {i}
    }}

# Some additional code to make files larger
for x in range(10):
    variable_{i}_{{}}_value = f"test_{{x}}_{{i}}"
""".format(i)
                file_path.write_text(content)
            
            # Test sequential scanning
            from wtf_codebot.discovery.scanner import CodebaseScanner
            
            profiler = PerformanceProfiler(sample_interval=0.01)
            
            profiler.start_monitoring()
            start_time = time.time()
            
            scanner = CodebaseScanner()
            codebase_sequential = scanner.scan_directory(project_dir)
            
            sequential_time = time.time() - start_time
            sequential_profile = profiler.stop_monitoring()
            
            # Test parallel scanning
            from wtf_codebot.performance.parallel import ParallelScanner
            
            profiler.start_monitoring()
            start_time = time.time()
            
            parallel_scanner = ParallelScanner(num_processes=2)
            codebase_parallel = parallel_scanner.scan_directory_parallel(
                project_dir, parse_ast=False  # Simplify for testing
            )
            
            parallel_time = time.time() - start_time
            parallel_profile = profiler.stop_monitoring()
            
            # Verify both approaches found the same files
            assert len(codebase_sequential.files) == len(codebase_parallel.files)
            assert len(codebase_sequential.files) == 20
            
            # Log performance comparison
            print(f"\nPerformance Comparison:")
            print(f"Sequential: {sequential_time:.3f}s, {sequential_profile.peak_memory_mb:.1f}MB")
            print(f"Parallel:   {parallel_time:.3f}s, {parallel_profile.peak_memory_mb:.1f}MB")
            
            # Note: Parallel may not always be faster for small projects due to overhead
            # but this test verifies that both approaches work correctly


if __name__ == "__main__":
    pytest.main([__file__])
