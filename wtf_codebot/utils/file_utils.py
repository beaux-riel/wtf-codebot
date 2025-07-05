"""File utilities for WTF CodeBot."""

import fnmatch
import os
from pathlib import Path
from typing import Iterator, List, Set

from ..core.logging import LoggerMixin


class FileDiscovery(LoggerMixin):
    """Handles file discovery and filtering."""
    
    def __init__(self, supported_extensions: List[str], exclude_patterns: List[str], max_file_size: int):
        """Initialize file discovery.
        
        Args:
            supported_extensions: List of supported file extensions
            exclude_patterns: List of glob patterns to exclude
            max_file_size: Maximum file size in bytes
        """
        super().__init__()
        self.supported_extensions = {ext.lower() for ext in supported_extensions}
        self.exclude_patterns = exclude_patterns
        self.max_file_size = max_file_size
    
    def discover_files(self, root_path: Path) -> Iterator[Path]:
        """Discover files in the given path.
        
        Args:
            root_path: Root path to search
            
        Yields:
            Discovered file paths
        """
        if not root_path.exists():
            self.log_error("Path does not exist", path=str(root_path))
            return
        
        if root_path.is_file():
            if self._should_include_file(root_path):
                yield root_path
            return
        
        self.log_info("Starting file discovery", path=str(root_path))
        
        for root, dirs, files in os.walk(root_path):
            root_path_obj = Path(root)
            
            # Filter directories
            dirs[:] = [d for d in dirs if not self._should_exclude_path(root_path_obj / d)]
            
            for file in files:
                file_path = root_path_obj / file
                
                if self._should_include_file(file_path):
                    yield file_path
    
    def _should_include_file(self, file_path: Path) -> bool:
        """Check if a file should be included.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file should be included
        """
        # Check if file exists and is a regular file
        if not file_path.is_file():
            return False
        
        # Check extension
        if file_path.suffix.lower() not in self.supported_extensions:
            self.log_debug("Excluding file due to unsupported extension", file=str(file_path))
            return False
        
        # Check exclude patterns
        if self._should_exclude_path(file_path):
            return False
        
        # Check file size
        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                self.log_warning(
                    "Excluding file due to size limit",
                    file=str(file_path),
                    size=file_size,
                    limit=self.max_file_size
                )
                return False
        except OSError as e:
            self.log_error("Failed to get file stats", file=str(file_path), error=str(e))
            return False
        
        return True
    
    def _should_exclude_path(self, path: Path) -> bool:
        """Check if a path should be excluded.
        
        Args:
            path: Path to check
            
        Returns:
            True if path should be excluded
        """
        path_str = str(path)
        
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                self.log_debug("Excluding path due to pattern", path=path_str, pattern=pattern)
                return True
        
        return False
    
    def get_file_stats(self, files: List[Path]) -> dict:
        """Get statistics about discovered files.
        
        Args:
            files: List of file paths
            
        Returns:
            Dictionary with file statistics
        """
        stats = {
            "total_files": len(files),
            "total_size": 0,
            "extensions": {},
            "largest_file": None,
            "largest_size": 0
        }
        
        for file_path in files:
            try:
                file_size = file_path.stat().st_size
                stats["total_size"] += file_size
                
                # Track extensions
                ext = file_path.suffix.lower()
                stats["extensions"][ext] = stats["extensions"].get(ext, 0) + 1
                
                # Track largest file
                if file_size > stats["largest_size"]:
                    stats["largest_file"] = str(file_path)
                    stats["largest_size"] = file_size
                    
            except OSError:
                continue
        
        return stats


def read_file_content(file_path: Path, encoding: str = 'utf-8') -> str:
    """Read file content safely.
    
    Args:
        file_path: Path to file
        encoding: File encoding
        
    Returns:
        File content as string
        
    Raises:
        FileProcessingError: If file cannot be read
    """
    from ..core.exceptions import FileProcessingError
    
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        # Try with different encodings
        for fallback_encoding in ['latin-1', 'cp1252']:
            try:
                with open(file_path, 'r', encoding=fallback_encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        
        raise FileProcessingError(
            f"Unable to decode file with any supported encoding",
            file_path=str(file_path)
        )
    except OSError as e:
        raise FileProcessingError(
            f"Failed to read file: {e}",
            file_path=str(file_path)
        )


def is_test_file(file_path: Path) -> bool:
    """Check if a file is a test file.
    
    Args:
        file_path: Path to check
        
    Returns:
        True if file appears to be a test file
    """
    file_name = file_path.name.lower()
    parent_names = [p.name.lower() for p in file_path.parents]
    
    # Common test file patterns
    test_patterns = [
        'test_',
        '_test',
        'tests',
        'spec_',
        '_spec',
        'specs'
    ]
    
    # Check file name
    for pattern in test_patterns:
        if pattern in file_name:
            return True
    
    # Check parent directories
    for parent in parent_names:
        if parent in ['test', 'tests', 'spec', 'specs', '__tests__']:
            return True
    
    return False
