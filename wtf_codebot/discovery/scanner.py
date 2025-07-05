"""
Codebase scanner for recursive directory traversal and file discovery.
"""

import os
from pathlib import Path
from typing import List, Set, Optional, Iterator, Dict
import logging

from .models import FileNode, FileType, CodebaseGraph
from .parsers import ParserFactory

logger = logging.getLogger(__name__)


class CodebaseScanner:
    """
    Recursively scans directories to discover and parse code files.
    
    Identifies file types by extension, builds in-memory representations,
    and creates AST paths and dependency graphs.
    """
    
    # File extension to type mapping
    FILE_TYPE_MAP = {
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
    
    # Default directories to ignore
    DEFAULT_IGNORE_DIRS = {
        '__pycache__',
        '.git',
        '.hg',
        '.svn',
        'node_modules',
        '.venv',
        'venv',
        '.env',
        'env',
        'dist',
        'build',
        '.tox',
        '.pytest_cache',
        '.coverage',
        '.mypy_cache',
        '.DS_Store',
        'coverage',
        '.idea',
        '.vscode',
        'target',
        'bin',
        'obj',
    }
    
    # Default file patterns to ignore
    DEFAULT_IGNORE_FILES = {
        '*.pyc',
        '*.pyo',
        '*.pyd',
        '*.so',
        '*.dylib',
        '*.dll',
        '*.exe',
        '*.log',
        '*.tmp',
        '*.bak',
        '*.swp',
        '*.swo',
        '*~',
        '.DS_Store',
        'Thumbs.db',
    }
    
    def __init__(
        self,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_files: Optional[Set[str]] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        include_content: bool = True,
        parse_ast: bool = True,
    ):
        """
        Initialize the codebase scanner.
        
        Args:
            ignore_dirs: Set of directory names to ignore
            ignore_files: Set of file patterns to ignore
            max_file_size: Maximum file size to process (in bytes)
            include_content: Whether to read file content
            parse_ast: Whether to parse AST for supported files
        """
        self.ignore_dirs = ignore_dirs or self.DEFAULT_IGNORE_DIRS
        self.ignore_files = ignore_files or self.DEFAULT_IGNORE_FILES
        self.max_file_size = max_file_size
        self.include_content = include_content
        self.parse_ast = parse_ast
        self.parser_factory = ParserFactory()
        
    def scan_directory(self, root_path: Path) -> CodebaseGraph:
        """
        Scan a directory recursively and build a codebase graph.
        
        Args:
            root_path: Root directory to scan
            
        Returns:
            CodebaseGraph: Complete representation of the codebase
        """
        if not root_path.exists():
            raise FileNotFoundError(f"Directory not found: {root_path}")
        
        if not root_path.is_dir():
            raise ValueError(f"Path is not a directory: {root_path}")
        
        logger.info(f"Starting codebase scan of {root_path}")
        
        codebase_graph = CodebaseGraph(root_path=root_path)
        
        for file_path in self._walk_directory(root_path):
            try:
                file_node = self._process_file(file_path, root_path)
                if file_node:
                    codebase_graph.add_file(file_node)
            except Exception as e:
                error_msg = f"Error processing {file_path}: {str(e)}"
                logger.error(error_msg)
                codebase_graph.scan_errors.append(error_msg)
        
        logger.info(f"Scan complete. Found {codebase_graph.total_files} files")
        return codebase_graph
    
    def _walk_directory(self, root_path: Path) -> Iterator[Path]:
        """
        Walk directory tree, yielding file paths while respecting ignore rules.
        
        Args:
            root_path: Root directory to walk
            
        Yields:
            Path: File paths to process
        """
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Remove ignored directories from the walk
            dirnames[:] = [d for d in dirnames if d not in self.ignore_dirs]
            
            current_dir = Path(dirpath)
            
            for filename in filenames:
                if self._should_ignore_file(filename):
                    continue
                
                file_path = current_dir / filename
                
                # Skip if file is too large
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        logger.warning(f"Skipping large file: {file_path}")
                        continue
                except OSError:
                    logger.warning(f"Could not stat file: {file_path}")
                    continue
                
                yield file_path
    
    def _should_ignore_file(self, filename: str) -> bool:
        """
        Check if a file should be ignored based on ignore patterns.
        
        Args:
            filename: Name of the file to check
            
        Returns:
            bool: True if file should be ignored
        """
        import fnmatch
        
        for pattern in self.ignore_files:
            if fnmatch.fnmatch(filename, pattern):
                return True
        
        return False
    
    def _process_file(self, file_path: Path, root_path: Path) -> Optional[FileNode]:
        """
        Process a single file and create a FileNode.
        
        Args:
            file_path: Path to the file to process
            root_path: Root directory of the scan
            
        Returns:
            Optional[FileNode]: FileNode if processing was successful
        """
        try:
            # Get file stats
            stat = file_path.stat()
            
            # Determine file type
            file_type = self._determine_file_type(file_path)
            
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
            if self.include_content:
                try:
                    file_node.content = self._read_file_content(file_path)
                except Exception as e:
                    logger.warning(f"Could not read content of {file_path}: {e}")
            
            # Parse file if AST parsing is enabled and we have content
            if self.parse_ast and file_node.content and file_type != FileType.UNKNOWN:
                try:
                    self._parse_file(file_node)
                except Exception as e:
                    error_msg = f"Parse error in {file_path}: {str(e)}"
                    logger.warning(error_msg)
                    file_node.parse_errors.append(error_msg)
            
            return file_node
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            return None
    
    def _determine_file_type(self, file_path: Path) -> FileType:
        """
        Determine the file type based on extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FileType: Determined file type
        """
        extension = file_path.suffix.lower()
        return self.FILE_TYPE_MAP.get(extension, FileType.UNKNOWN)
    
    def _read_file_content(self, file_path: Path) -> str:
        """
        Read file content with encoding detection.
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: File content
        """
        # Try common encodings
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
    
    def _parse_file(self, file_node: FileNode) -> None:
        """
        Parse a file to extract AST and dependencies.
        
        Args:
            file_node: FileNode to parse
        """
        parser = self.parser_factory.get_parser(file_node.file_type)
        
        if parser:
            try:
                parser.parse(file_node)
            except Exception as e:
                error_msg = f"Parser error: {str(e)}"
                file_node.parse_errors.append(error_msg)
                logger.warning(f"Parser error for {file_node.path}: {error_msg}")
    
    def get_file_type_statistics(self, codebase_graph: CodebaseGraph) -> Dict[str, int]:
        """
        Get statistics about file types in the codebase.
        
        Args:
            codebase_graph: CodebaseGraph to analyze
            
        Returns:
            Dict[str, int]: File type counts
        """
        stats = {}
        for file_type, files in codebase_graph.file_types.items():
            stats[file_type.value] = len(files)
        return stats
