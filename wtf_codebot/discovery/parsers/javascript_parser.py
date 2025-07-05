"""
JavaScript parser using Tree-sitter.
"""

import re
from typing import List, Set, Optional
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency


class JavaScriptParser(BaseParser):
    """
    Parser for JavaScript files.
    
    Note: This is a regex-based implementation. For production use,
    consider integrating Tree-sitter for more accurate parsing.
    """
    
    def __init__(self):
        """Initialize the JavaScript parser."""
        super().__init__()
        self.supported_extensions = {'.js', '.jsx'}
        self.language_name = "javascript"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a JavaScript file and populate the FileNode.
        
        Args:
            file_node: FileNode to populate
        """
        if not file_node.content:
            return
        
        try:
            # Extract dependencies
            file_node.dependencies = self.extract_dependencies(file_node.content)
            
            # Extract symbols
            functions, classes, variables = self.extract_symbols(file_node.content)
            file_node.functions = functions
            file_node.classes = classes
            file_node.variables = variables
            
            # Extract imports and exports
            file_node.imports = self._extract_imports(file_node.content)
            file_node.exports = self._extract_exports(file_node.content)
            
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract import/require dependencies from JavaScript content.
        
        Args:
            content: JavaScript source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        lines = content.split('\n')
        
        # Patterns for different import types
        import_patterns = [
            # import ... from '...'
            (r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]', 'import'),
            # import('...')
            (r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', 'dynamic_import'),
            # require('...')
            (r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', 'require'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            for pattern, dep_type in import_patterns:
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
        Extract functions, classes, and variables from JavaScript content.
        
        Args:
            content: JavaScript source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        lines = content.split('\n')
        
        # Patterns for different symbols
        patterns = [
            # Function declarations
            (r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', functions),
            # Arrow functions assigned to variables
            (r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(.*?\)\s*=>', functions),
            (r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(.*?\)\s*=>', functions),
            (r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(.*?\)\s*=>', functions),
            # Method definitions
            (r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(.*?\)\s*\{', functions),
            # Class declarations
            (r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', classes),
            # Variable declarations
            (r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', variables),
            (r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', variables),
            (r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', variables),
        ]
        
        for line in lines:
            line = line.strip()
            
            # Skip comments
            if line.startswith('//') or line.startswith('/*'):
                continue
            
            for pattern, symbol_set in patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    symbol_name = match.group(1)
                    symbol_set.add(symbol_name)
        
        return functions, classes, variables
    
    def _extract_imports(self, content: str) -> Set[str]:
        """
        Extract imported modules from JavaScript content.
        
        Args:
            content: JavaScript source code
            
        Returns:
            Set[str]: Set of imported module names
        """
        imports = set()
        
        # Pattern to match import statements
        import_patterns = [
            r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
        ]
        
        for pattern in import_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                imports.add(match.group(1))
        
        return imports
    
    def _extract_exports(self, content: str) -> Set[str]:
        """
        Extract exported names from JavaScript content.
        
        Args:
            content: JavaScript source code
            
        Returns:
            Set[str]: Set of exported names
        """
        exports = set()
        
        # Patterns for exports
        export_patterns = [
            # export function/class/const
            r'export\s+(?:function|class|const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
            # export { name }
            r'export\s*\{\s*([a-zA-Z_$][a-zA-Z0-9_$,\s]*)\s*\}',
            # export default
            r'export\s+default\s+(?:function\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)',
        ]
        
        for pattern in export_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                export_names = match.group(1)
                # Handle multiple exports in braces
                if ',' in export_names:
                    for name in export_names.split(','):
                        name = name.strip()
                        if name:
                            exports.add(name)
                else:
                    exports.add(export_names.strip())
        
        return exports
    
    def is_external_dependency(self, dependency_name: str) -> bool:
        """
        Check if a JavaScript dependency is external.
        
        Args:
            dependency_name: Name of the dependency
            
        Returns:
            bool: True if dependency is external
        """
        if not dependency_name:
            return False
        
        # Node.js built-in modules
        builtin_modules = {
            'fs', 'path', 'os', 'crypto', 'http', 'https', 'url', 'util',
            'events', 'stream', 'buffer', 'child_process', 'cluster',
            'dgram', 'dns', 'net', 'readline', 'repl', 'tls', 'tty',
            'vm', 'zlib', 'assert', 'querystring', 'string_decoder'
        }
        
        # If it's a Node.js built-in, it's external
        if dependency_name in builtin_modules:
            return True
        
        # Use base class logic for other checks
        return super().is_external_dependency(dependency_name)
