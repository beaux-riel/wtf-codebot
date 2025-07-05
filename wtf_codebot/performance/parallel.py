"""
Parallel processing module for multiprocessing file parsing and analysis.
"""

import multiprocessing as mp
from multiprocessing import Pool, Queue, Process, Manager
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Tuple, Iterator
from dataclasses import dataclass
import logging
import time
import queue
import os
from concurrent.futures import ProcessPoolExecutor, as_completed, Future
import pickle

from ..discovery.models import FileNode, CodebaseGraph, FileType
from ..discovery.parsers.factory import ParserFactory
from ..analyzers.base import BaseAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class ProcessingTask:
    """Represents a processing task for parallel execution."""
    task_id: str
    file_path: Path
    task_type: str  # 'parse' or 'analyze'
    config: Dict[str, Any]
    root_path: Optional[Path] = None


@dataclass
class ProcessingResult:
    """Result from parallel processing."""
    task_id: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    memory_usage: float = 0.0


class WorkerProcess:
    """Worker process for parallel execution."""
    
    def __init__(self, worker_id: int):
        self.worker_id = worker_id
        self.parser_factory = None
        self.analyzers = {}
        
    def initialize(self, parser_config: Dict[str, Any], analyzer_configs: Dict[str, Any]):
        """Initialize the worker process."""
        try:
            # Initialize parser factory
            self.parser_factory = ParserFactory()
            
            # Initialize analyzers
            for name, config in analyzer_configs.items():
                # Create analyzer from config
                analyzer_class = config.get('class')
                if analyzer_class:
                    self.analyzers[name] = analyzer_class(**config.get('args', {}))
            
            logger.info(f"Worker {self.worker_id} initialized")
            return True
        except Exception as e:
            logger.error(f"Worker {self.worker_id} initialization failed: {e}")
            return False
    
    def process_task(self, task: ProcessingTask) -> ProcessingResult:
        """Process a single task."""
        start_time = time.time()
        
        try:
            if task.task_type == 'parse':
                result = self._parse_file(task)
            elif task.task_type == 'analyze':
                result = self._analyze_file(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")
            
            duration = time.time() - start_time
            
            return ProcessingResult(
                task_id=task.task_id,
                success=True,
                result=result,
                duration=duration
            )
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"Task {task.task_id} failed: {str(e)}"
            logger.error(error_msg)
            
            return ProcessingResult(
                task_id=task.task_id,
                success=False,
                error=error_msg,
                duration=duration
            )
    
    def _parse_file(self, task: ProcessingTask) -> Optional[FileNode]:
        """Parse a single file."""
        file_path = task.file_path
        root_path = task.root_path or file_path.parent
        config = task.config
        
        try:
            # Get file stats
            stat = file_path.stat()
            
            # Determine file type
            extension = file_path.suffix.lower()
            file_type_map = {
                '.py': FileType.PYTHON,
                '.js': FileType.JAVASCRIPT,
                '.jsx': FileType.JAVASCRIPT,
                '.ts': FileType.TYPESCRIPT,
                '.tsx': FileType.TYPESCRIPT,
                '.html': FileType.HTML,
                '.htm': FileType.HTML,
                '.css': FileType.CSS,
                '.scss': FileType.CSS,
                '.sass': FileType.CSS,
                '.json': FileType.JSON,
                '.yaml': FileType.YAML,
                '.yml': FileType.YAML,
                '.md': FileType.MARKDOWN,
                '.markdown': FileType.MARKDOWN,
            }
            file_type = file_type_map.get(extension, FileType.UNKNOWN)
            
            # Create relative path
            try:
                relative_path = file_path.relative_to(root_path)
            except ValueError:
                relative_path = file_path
            
            # Create file node
            file_node = FileNode(
                path=relative_path,
                file_type=file_type,
                size=stat.st_size,
                last_modified=stat.st_mtime,
            )
            
            # Read content if requested
            if config.get('include_content', True):
                file_node.content = self._read_file_content(file_path)
            
            # Parse AST if requested and we have content
            if config.get('parse_ast', True) and file_node.content and file_type != FileType.UNKNOWN:
                parser = self.parser_factory.get_parser(file_type)
                if parser:
                    parser.parse(file_node)
            
            return file_node
            
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            return None
    
    def _analyze_file(self, task: ProcessingTask) -> Optional[AnalysisResult]:
        """Analyze a single file."""
        file_path = task.file_path
        config = task.config
        
        try:
            # Load file node from task config
            file_node_data = config.get('file_node')
            if not file_node_data:
                # Create minimal file node
                file_node = FileNode(
                    path=file_path,
                    file_type=FileType.UNKNOWN,
                    size=0,
                    last_modified=0,
                )
                file_node.content = self._read_file_content(file_path)
            else:
                # Deserialize file node
                file_node = pickle.loads(file_node_data)
            
            # Get analyzer name
            analyzer_name = config.get('analyzer')
            if analyzer_name not in self.analyzers:
                raise ValueError(f"Analyzer {analyzer_name} not available")
            
            analyzer = self.analyzers[analyzer_name]
            
            # Analyze the file
            result = analyzer.analyze_file(file_node)
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return None
    
    def _read_file_content(self, file_path: Path) -> str:
        """Read file content with encoding detection."""
        encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, UnicodeError):
                continue
        
        # If all encodings fail, read as binary and decode with errors='ignore'
        with open(file_path, 'rb') as f:
            return f.read().decode('utf-8', errors='ignore')


def process_task_worker(args: Tuple[ProcessingTask, Dict[str, Any], Dict[str, Any]]) -> ProcessingResult:
    """Worker function for processing tasks in separate processes."""
    task, parser_config, analyzer_configs = args
    
    # Create worker instance
    worker = WorkerProcess(os.getpid())
    
    # Initialize worker
    if not worker.initialize(parser_config, analyzer_configs):
        return ProcessingResult(
            task_id=task.task_id,
            success=False,
            error="Worker initialization failed"
        )
    
    # Process the task
    return worker.process_task(task)


class ParallelScanner:
    """Parallel file scanner using multiprocessing."""
    
    def __init__(self, num_processes: Optional[int] = None, chunk_size: int = 100):
        """
        Initialize the parallel scanner.
        
        Args:
            num_processes: Number of processes to use (default: CPU count)
            chunk_size: Number of files to process in each chunk
        """
        self.num_processes = num_processes or mp.cpu_count()
        self.chunk_size = chunk_size
        
    def scan_directory_parallel(self, root_path: Path, 
                               include_content: bool = True,
                               parse_ast: bool = True,
                               ignore_dirs: Optional[set] = None,
                               ignore_files: Optional[set] = None,
                               max_file_size: int = 10 * 1024 * 1024) -> CodebaseGraph:
        """
        Scan directory in parallel.
        
        Args:
            root_path: Root directory to scan
            include_content: Whether to read file content
            parse_ast: Whether to parse AST
            ignore_dirs: Directories to ignore
            ignore_files: File patterns to ignore
            max_file_size: Maximum file size to process
            
        Returns:
            CodebaseGraph: Complete codebase representation
        """
        if not root_path.exists():
            raise FileNotFoundError(f"Directory not found: {root_path}")
        
        if not root_path.is_dir():
            raise ValueError(f"Path is not a directory: {root_path}")
        
        logger.info(f"Starting parallel scan of {root_path} with {self.num_processes} processes")
        
        # Collect all file paths first
        file_paths = list(self._walk_directory(
            root_path, ignore_dirs, ignore_files, max_file_size
        ))
        
        logger.info(f"Found {len(file_paths)} files to process")
        
        # Create tasks
        tasks = []
        for i, file_path in enumerate(file_paths):
            task = ProcessingTask(
                task_id=f"parse_{i}",
                file_path=file_path,
                task_type='parse',
                config={
                    'include_content': include_content,
                    'parse_ast': parse_ast,
                },
                root_path=root_path
            )
            tasks.append(task)
        
        # Process tasks in parallel
        codebase_graph = CodebaseGraph(root_path=root_path)
        
        parser_config = {}
        analyzer_configs = {}
        
        with ProcessPoolExecutor(max_workers=self.num_processes) as executor:
            # Submit tasks
            task_args = [(task, parser_config, analyzer_configs) for task in tasks]
            futures = [executor.submit(process_task_worker, args) for args in task_args]
            
            # Collect results
            processed_count = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    processed_count += 1
                    
                    if result.success and result.result:
                        codebase_graph.add_file(result.result)
                    elif not result.success:
                        codebase_graph.scan_errors.append(result.error)
                    
                    if processed_count % 100 == 0:
                        logger.info(f"Processed {processed_count}/{len(tasks)} files")
                        
                except Exception as e:
                    logger.error(f"Error processing future: {e}")
                    codebase_graph.scan_errors.append(str(e))
        
        logger.info(f"Parallel scan complete. Processed {len(file_paths)} files")
        return codebase_graph
    
    def _walk_directory(self, root_path: Path, ignore_dirs: Optional[set] = None,
                       ignore_files: Optional[set] = None, max_file_size: int = 10 * 1024 * 1024) -> Iterator[Path]:
        """Walk directory tree and yield file paths."""
        ignore_dirs = ignore_dirs or {
            '__pycache__', '.git', '.hg', '.svn', 'node_modules',
            '.venv', 'venv', '.env', 'env', 'dist', 'build',
            '.tox', '.pytest_cache', '.coverage', '.mypy_cache',
            '.DS_Store', 'coverage', '.idea', '.vscode', 'target', 'bin', 'obj'
        }
        
        ignore_files = ignore_files or {
            '*.pyc', '*.pyo', '*.pyd', '*.so', '*.dylib', '*.dll',
            '*.exe', '*.log', '*.tmp', '*.bak', '*.swp', '*.swo',
            '*~', '.DS_Store', 'Thumbs.db'
        }
        
        import fnmatch
        
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Remove ignored directories
            dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
            
            current_dir = Path(dirpath)
            
            for filename in filenames:
                # Check ignore patterns
                should_ignore = False
                for pattern in ignore_files:
                    if fnmatch.fnmatch(filename, pattern):
                        should_ignore = True
                        break
                
                if should_ignore:
                    continue
                
                file_path = current_dir / filename
                
                # Check file size
                try:
                    if file_path.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue
                
                yield file_path


class ParallelAnalyzer:
    """Parallel analyzer using multiprocessing."""
    
    def __init__(self, num_processes: Optional[int] = None):
        """
        Initialize the parallel analyzer.
        
        Args:
            num_processes: Number of processes to use (default: CPU count)
        """
        self.num_processes = num_processes or mp.cpu_count()
    
    def analyze_codebase_parallel(self, codebase: CodebaseGraph, 
                                analyzers: Dict[str, BaseAnalyzer]) -> Dict[str, AnalysisResult]:
        """
        Analyze codebase in parallel using multiple analyzers.
        
        Args:
            codebase: Codebase to analyze
            analyzers: Dictionary of analyzers to use
            
        Returns:
            Dict[str, AnalysisResult]: Results from each analyzer
        """
        logger.info(f"Starting parallel analysis with {len(analyzers)} analyzers")
        
        # Prepare analyzer configurations
        analyzer_configs = {}
        for name, analyzer in analyzers.items():
            analyzer_configs[name] = {
                'class': analyzer.__class__,
                'args': {},  # Add any necessary initialization args
            }
        
        # Create tasks for each file-analyzer combination
        tasks = []
        task_id = 0
        
        for file_path, file_node in codebase.files.items():
            for analyzer_name, analyzer in analyzers.items():
                if analyzer.supports_file(file_node):
                    task = ProcessingTask(
                        task_id=f"analyze_{task_id}",
                        file_path=Path(file_path),
                        task_type='analyze',
                        config={
                            'analyzer': analyzer_name,
                            'file_node': pickle.dumps(file_node),  # Serialize file node
                        }
                    )
                    tasks.append(task)
                    task_id += 1
        
        logger.info(f"Created {len(tasks)} analysis tasks")
        
        # Process tasks in parallel
        results = {name: AnalysisResult() for name in analyzers.keys()}
        
        parser_config = {}
        
        with ProcessPoolExecutor(max_workers=self.num_processes) as executor:
            # Submit tasks
            task_args = [(task, parser_config, analyzer_configs) for task in tasks]
            futures = [executor.submit(process_task_worker, args) for args in task_args]
            
            # Collect results
            processed_count = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    processed_count += 1
                    
                    if result.success and result.result:
                        # Extract analyzer name from task config
                        task_config = [t for t in tasks if t.task_id == result.task_id][0].config
                        analyzer_name = task_config['analyzer']
                        
                        # Merge results
                        analysis_result = result.result
                        results[analyzer_name].findings.extend(analysis_result.findings)
                        results[analyzer_name].metrics.extend(analysis_result.metrics)
                    
                    if processed_count % 100 == 0:
                        logger.info(f"Analyzed {processed_count}/{len(tasks)} tasks")
                        
                except Exception as e:
                    logger.error(f"Error processing analysis future: {e}")
        
        logger.info(f"Parallel analysis complete. Processed {len(tasks)} tasks")
        return results


class ParallelTaskQueue:
    """Queue-based parallel task processor."""
    
    def __init__(self, num_workers: int = None, queue_size: int = 1000):
        """
        Initialize the task queue.
        
        Args:
            num_workers: Number of worker processes
            queue_size: Maximum queue size
        """
        self.num_workers = num_workers or mp.cpu_count()
        self.queue_size = queue_size
        self.input_queue = Queue(maxsize=queue_size)
        self.output_queue = Queue()
        self.workers = []
        self.running = False
    
    def start(self):
        """Start worker processes."""
        if self.running:
            return
        
        self.running = True
        
        for i in range(self.num_workers):
            worker = Process(target=self._worker_loop, args=(i,))
            worker.start()
            self.workers.append(worker)
    
    def stop(self, timeout: float = 10.0):
        """Stop worker processes."""
        if not self.running:
            return
        
        self.running = False
        
        # Send stop signals
        for _ in self.workers:
            try:
                self.input_queue.put(None, timeout=1.0)
            except queue.Full:
                pass
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=timeout)
            if worker.is_alive():
                worker.terminate()
        
        self.workers.clear()
    
    def submit_task(self, task: ProcessingTask, timeout: float = 1.0) -> bool:
        """
        Submit a task for processing.
        
        Args:
            task: Task to process
            timeout: Timeout for queue put
            
        Returns:
            bool: True if task was submitted successfully
        """
        try:
            self.input_queue.put(task, timeout=timeout)
            return True
        except queue.Full:
            return False
    
    def get_result(self, timeout: float = 1.0) -> Optional[ProcessingResult]:
        """
        Get a result from the output queue.
        
        Args:
            timeout: Timeout for queue get
            
        Returns:
            Optional[ProcessingResult]: Result if available
        """
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def _worker_loop(self, worker_id: int):
        """Main worker loop."""
        worker = WorkerProcess(worker_id)
        
        # Initialize worker (you may need to pass configs here)
        worker.initialize({}, {})
        
        while True:
            try:
                task = self.input_queue.get(timeout=1.0)
                
                if task is None:  # Stop signal
                    break
                
                result = worker.process_task(task)
                self.output_queue.put(result)
                
            except queue.Empty:
                if not self.running:
                    break
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                break
