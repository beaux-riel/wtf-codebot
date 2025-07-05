"""
Base parser class for all language-specific parsers.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Set
import logging

from ..models import FileNode, ASTNode, Dependency

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for all language-specific parsers.
    
    Each parser is responsible for:
    - Parsing files to extract AST information
    - Identifying dependencies (imports, requires, includes)
    - Extracting symbols (functions, classes, variables)
    - Building structured representations of code
    """
    
    def __init__(self):
        """Initialize the parser."""
        self.supported_extensions: Set[str] = set()
        self.language_name: str = ""
    
    @abstractmethod
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a file and populate the FileNode with extracted information.
        
        This method should:
        1. Parse the file content to create an AST
        2. Extract dependencies 
        3. Identify functions, classes, and variables
        4. Populate the FileNode with the extracted information
        
        Args:
            file_node: FileNode to populate with parsed information
        """
        pass
    
    @abstractmethod
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract dependencies from file content.
        
        Args:
            content: Source code content
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        pass
    
    @abstractmethod
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols (functions, classes, variables) from content.
        
        Args:
            content: Source code content
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        pass
    
    def supports_file(self, file_node: FileNode) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_node: FileNode to check
            
        Returns:
            bool: True if parser supports this file type
        """
        return file_node.extension in self.supported_extensions
    
    def build_ast_node(
        self, 
        node_type: str, 
        name: Optional[str] = None,
        line_number: Optional[int] = None,
        column_number: Optional[int] = None,
        **attributes
    ) -> ASTNode:
        """
        Create an ASTNode with the given parameters.
        
        Args:
            node_type: Type of the AST node
            name: Optional name of the node
            line_number: Optional line number
            column_number: Optional column number
            **attributes: Additional attributes
            
        Returns:
            ASTNode: Created AST node
        """
        return ASTNode(
            node_type=node_type,
            name=name,
            line_number=line_number,
            column_number=column_number,
            attributes=attributes
        )
    
    def create_dependency(
        self,
        source: str,
        target: str,
        dependency_type: str,
        line_number: Optional[int] = None,
        is_relative: bool = False,
        is_external: bool = False,
    ) -> Dependency:
        """
        Create a Dependency object.
        
        Args:
            source: Source file path
            target: Target module/file path
            dependency_type: Type of dependency (import, require, etc.)
            line_number: Line number where dependency is declared
            is_relative: Whether this is a relative import
            is_external: Whether this is an external dependency
            
        Returns:
            Dependency: Created dependency object
        """
        return Dependency(
            source=source,
            target=target,
            dependency_type=dependency_type,
            line_number=line_number,
            is_relative=is_relative,
            is_external=is_external
        )
    
    def log_parse_error(self, file_path: str, error: str) -> None:
        """
        Log a parse error.
        
        Args:
            file_path: Path to the file that failed to parse
            error: Error message
        """
        logger.warning(f"Parse error in {file_path}: {error}")
    
    def is_external_dependency(self, dependency_name: str) -> bool:
        """
        Check if a dependency is external (not part of the current project).
        
        This is a basic implementation that can be overridden by specific parsers.
        
        Args:
            dependency_name: Name of the dependency
            
        Returns:
            bool: True if dependency is external
        """
        # Basic heuristics for external dependencies
        external_indicators = [
            # No relative path indicators
            not dependency_name.startswith('.'),
            not dependency_name.startswith('/'),
            # Common external package patterns
            '/' not in dependency_name or dependency_name.count('/') <= 2,
        ]
        
        return all(external_indicators)
