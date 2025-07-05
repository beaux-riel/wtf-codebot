"""
Data models for codebase representation.
"""

from typing import Dict, List, Optional, Set, Union, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class FileType(Enum):
    """Supported file types for parsing."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    CSS = "css"
    JSON = "json"
    YAML = "yaml"
    MARKDOWN = "markdown"
    UNKNOWN = "unknown"


@dataclass
class ASTNode:
    """Represents a node in the Abstract Syntax Tree."""
    node_type: str
    name: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    children: List["ASTNode"] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Dependency:
    """Represents a dependency relationship."""
    source: str
    target: str
    dependency_type: str  # import, require, include, etc.
    line_number: Optional[int] = None
    is_relative: bool = False
    is_external: bool = False


@dataclass
class FileNode:
    """Represents a file in the codebase."""
    path: Path
    file_type: FileType
    size: int
    last_modified: float
    content: Optional[str] = None
    ast_root: Optional[ASTNode] = None
    dependencies: List[Dependency] = field(default_factory=list)
    exports: Set[str] = field(default_factory=set)
    imports: Set[str] = field(default_factory=set)
    functions: Set[str] = field(default_factory=set)
    classes: Set[str] = field(default_factory=set)
    variables: Set[str] = field(default_factory=set)
    parse_errors: List[str] = field(default_factory=list)
    
    @property
    def relative_path(self) -> str:
        """Get the relative path as a string."""
        return str(self.path)
    
    @property
    def extension(self) -> str:
        """Get the file extension."""
        return self.path.suffix.lower()


@dataclass
class DependencyGraph:
    """Represents dependency relationships in the codebase."""
    nodes: Dict[str, FileNode] = field(default_factory=dict)
    edges: List[Dependency] = field(default_factory=list)
    
    def add_node(self, file_node: FileNode) -> None:
        """Add a file node to the graph."""
        self.nodes[str(file_node.path)] = file_node
    
    def add_dependency(self, dependency: Dependency) -> None:
        """Add a dependency edge to the graph."""
        self.edges.append(dependency)
    
    def get_dependencies(self, file_path: str) -> List[Dependency]:
        """Get all dependencies for a given file."""
        return [dep for dep in self.edges if dep.source == file_path]
    
    def get_dependents(self, file_path: str) -> List[Dependency]:
        """Get all files that depend on the given file."""
        return [dep for dep in self.edges if dep.target == file_path]


@dataclass
class CodebaseGraph:
    """Complete in-memory representation of the codebase."""
    root_path: Path
    files: Dict[str, FileNode] = field(default_factory=dict)
    dependency_graph: DependencyGraph = field(default_factory=DependencyGraph)
    file_types: Dict[FileType, List[str]] = field(default_factory=dict)
    total_files: int = 0
    total_size: int = 0
    scan_errors: List[str] = field(default_factory=list)
    
    def add_file(self, file_node: FileNode) -> None:
        """Add a file to the codebase graph."""
        file_path = str(file_node.path)
        self.files[file_path] = file_node
        self.dependency_graph.add_node(file_node)
        
        # Group by file type
        if file_node.file_type not in self.file_types:
            self.file_types[file_node.file_type] = []
        self.file_types[file_node.file_type].append(file_path)
        
        # Update statistics
        self.total_files += 1
        self.total_size += file_node.size
        
        # Add dependencies to graph
        for dep in file_node.dependencies:
            self.dependency_graph.add_dependency(dep)
    
    def get_files_by_type(self, file_type: FileType) -> List[FileNode]:
        """Get all files of a specific type."""
        return [self.files[path] for path in self.file_types.get(file_type, [])]
    
    def get_file_by_path(self, path: Union[str, Path]) -> Optional[FileNode]:
        """Get a file node by its path."""
        return self.files.get(str(path))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get codebase statistics."""
        return {
            "total_files": self.total_files,
            "total_size": self.total_size,
            "file_types": {ft.value: len(files) for ft, files in self.file_types.items()},
            "dependency_count": len(self.dependency_graph.edges),
            "scan_errors": len(self.scan_errors)
        }
