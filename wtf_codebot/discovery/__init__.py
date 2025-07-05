"""
Codebase discovery and parsing layer for wtf-codebot.

This module provides functionality to recursively scan directories,
identify file types, and build in-memory representations with AST paths
and dependency graphs.
"""

from .scanner import CodebaseScanner
from .parsers import ParserFactory, ParserRegistry
from .models import FileNode, CodebaseGraph, DependencyGraph

__all__ = [
    "CodebaseScanner",
    "ParserFactory", 
    "ParserRegistry",
    "FileNode",
    "CodebaseGraph",
    "DependencyGraph",
]
