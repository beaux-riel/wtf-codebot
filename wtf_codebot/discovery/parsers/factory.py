"""
Parser factory for creating parser instances.
"""

from typing import Optional
from ..models import FileType
from .base import BaseParser
from .registry import get_global_registry


class ParserFactory:
    """
    Factory for creating parser instances.
    
    Provides a simple interface to create parsers for different file types
    using the global parser registry.
    """
    
    def __init__(self):
        """Initialize the parser factory."""
        self._registry = get_global_registry()
        self._ensure_parsers_registered()
    
    def get_parser(self, file_type: FileType) -> Optional[BaseParser]:
        """
        Get a parser instance for the specified file type.
        
        Args:
            file_type: FileType to get parser for
            
        Returns:
            Optional[BaseParser]: Parser instance if available, None otherwise
        """
        return self._registry.create_parser(file_type)
    
    def is_supported(self, file_type: FileType) -> bool:
        """
        Check if a file type is supported.
        
        Args:
            file_type: FileType to check
            
        Returns:
            bool: True if file type is supported
        """
        return self._registry.is_supported(file_type)
    
    def get_supported_file_types(self) -> list[FileType]:
        """
        Get all supported file types.
        
        Returns:
            list[FileType]: List of supported file types
        """
        return self._registry.get_supported_file_types()
    
    def _ensure_parsers_registered(self) -> None:
        """
        Ensure all available parsers are registered.
        
        This method registers all the built-in parsers with the global registry.
        """
        # Import here to avoid circular imports
        from .python_parser import PythonParser
        from .javascript_parser import JavaScriptParser
        from .typescript_parser import TypeScriptParser
        from .html_parser import HTMLParser
        from .css_parser import CSSParser
        from .json_parser import JSONParser
        from .yaml_parser import YAMLParser
        from .markdown_parser import MarkdownParser
        
        # Register all parsers
        parsers = [
            (FileType.PYTHON, PythonParser),
            (FileType.JAVASCRIPT, JavaScriptParser),
            (FileType.TYPESCRIPT, TypeScriptParser),
            (FileType.HTML, HTMLParser),
            (FileType.CSS, CSSParser),
            (FileType.JSON, JSONParser),
            (FileType.YAML, YAMLParser),
            (FileType.MARKDOWN, MarkdownParser),
        ]
        
        for file_type, parser_class in parsers:
            if not self._registry.is_supported(file_type):
                self._registry.register_parser(file_type, parser_class)
