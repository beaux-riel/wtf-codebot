"""
Parser registry for managing available parsers.
"""

from typing import Dict, Type, Optional
from ..models import FileType
from .base import BaseParser


class ParserRegistry:
    """
    Registry for managing language-specific parsers.
    
    Provides a central place to register and retrieve parsers
    for different file types.
    """
    
    def __init__(self):
        """Initialize the parser registry."""
        self._parsers: Dict[FileType, Type[BaseParser]] = {}
    
    def register_parser(self, file_type: FileType, parser_class: Type[BaseParser]) -> None:
        """
        Register a parser class for a specific file type.
        
        Args:
            file_type: FileType to register the parser for
            parser_class: Parser class to register
        """
        self._parsers[file_type] = parser_class
    
    def get_parser_class(self, file_type: FileType) -> Optional[Type[BaseParser]]:
        """
        Get the parser class for a specific file type.
        
        Args:
            file_type: FileType to get parser for
            
        Returns:
            Optional[Type[BaseParser]]: Parser class if found, None otherwise
        """
        return self._parsers.get(file_type)
    
    def create_parser(self, file_type: FileType) -> Optional[BaseParser]:
        """
        Create a parser instance for a specific file type.
        
        Args:
            file_type: FileType to create parser for
            
        Returns:
            Optional[BaseParser]: Parser instance if found, None otherwise
        """
        parser_class = self.get_parser_class(file_type)
        if parser_class:
            return parser_class()
        return None
    
    def get_supported_file_types(self) -> list[FileType]:
        """
        Get all supported file types.
        
        Returns:
            list[FileType]: List of supported file types
        """
        return list(self._parsers.keys())
    
    def is_supported(self, file_type: FileType) -> bool:
        """
        Check if a file type is supported.
        
        Args:
            file_type: FileType to check
            
        Returns:
            bool: True if file type is supported
        """
        return file_type in self._parsers


# Global registry instance
_global_registry = ParserRegistry()


def get_global_registry() -> ParserRegistry:
    """
    Get the global parser registry instance.
    
    Returns:
        ParserRegistry: Global registry instance
    """
    return _global_registry


def register_parser(file_type: FileType, parser_class: Type[BaseParser]) -> None:
    """
    Register a parser class with the global registry.
    
    Args:
        file_type: FileType to register the parser for
        parser_class: Parser class to register
    """
    _global_registry.register_parser(file_type, parser_class)
