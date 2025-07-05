"""
TypeScript parser extending the JavaScript parser.
"""

import re
from typing import List, Set
from .javascript_parser import JavaScriptParser
from ..models import FileNode, Dependency


class TypeScriptParser(JavaScriptParser):
    """
    Parser for TypeScript files.
    
    Extends JavaScriptParser with TypeScript-specific features.
    """
    
    def __init__(self):
        """Initialize the TypeScript parser."""
        super().__init__()
        self.supported_extensions = {'.ts', '.tsx'}
        self.language_name = "typescript"
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract import dependencies from TypeScript content.
        
        Args:
            content: TypeScript source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        # Start with base JavaScript dependencies
        dependencies = super().extract_dependencies(content)
        
        # Add TypeScript-specific patterns
        lines = content.split('\n')
        
        # TypeScript-specific import patterns
        ts_patterns = [
            # import type { ... } from '...'
            (r'import\s+type\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]', 'type_import'),
            # import { type ... } from '...'
            (r'import\s+\{.*?type\s+.*?\}\s+from\s+[\'"]([^\'"]+)[\'"]', 'type_import'),
            # /// <reference path="..." />
            (r'///\s*<reference\s+path\s*=\s*[\'"]([^\'"]+)[\'"]\s*/>', 'reference'),
            # /// <reference types="..." />
            (r'///\s*<reference\s+types\s*=\s*[\'"]([^\'"]+)[\'"]\s*/>', 'reference'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            for pattern, dep_type in ts_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    module_path = match.group(1)
                    is_relative = module_path.startswith('.') or module_path.startswith('/')
                    
                    dep = self.create_dependency(
                        source="",  # Will be set by scanner
                        target=module_path,
                        dependency_type=dep_type,
                        line_number=line_num,
                        is_relative=is_relative,
                        is_external=not is_relative and self.is_external_dependency(module_path)
                    )
                    dependencies.append(dep)
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract functions, classes, and variables from TypeScript content.
        
        Args:
            content: TypeScript source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        # Start with base JavaScript symbols
        functions, classes, variables = super().extract_symbols(content)
        
        lines = content.split('\n')
        
        # TypeScript-specific patterns
        ts_patterns = [
            # Interface declarations
            (r'interface\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', classes),
            # Type aliases
            (r'type\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=', classes),
            # Enum declarations
            (r'enum\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', classes),
            # Namespace declarations
            (r'namespace\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', classes),
            # Abstract classes
            (r'abstract\s+class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', classes),
        ]
        
        for line in lines:
            line = line.strip()
            
            # Skip comments
            if line.startswith('//') or line.startswith('/*'):
                continue
            
            for pattern, symbol_set in ts_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    symbol_name = match.group(1)
                    symbol_set.add(symbol_name)
        
        return functions, classes, variables
