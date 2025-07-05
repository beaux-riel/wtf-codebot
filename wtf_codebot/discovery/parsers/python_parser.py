"""
Python parser using the built-in ast module.
"""

import ast
import re
from typing import List, Set, Optional, Union
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency


class PythonParser(BaseParser):
    """
    Parser for Python files using the built-in ast module.
    
    Extracts:
    - AST structure
    - Import dependencies
    - Function and class definitions
    - Variable assignments
    """
    
    def __init__(self):
        """Initialize the Python parser."""
        super().__init__()
        self.supported_extensions = {'.py'}
        self.language_name = "python"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a Python file and populate the FileNode.
        
        Args:
            file_node: FileNode to populate
        """
        if not file_node.content:
            return
        
        try:
            # Parse the AST
            tree = ast.parse(file_node.content, filename=str(file_node.path))
            
            # Build our AST representation
            file_node.ast_root = self._convert_ast_node(tree)
            
            # Extract dependencies
            file_node.dependencies = self.extract_dependencies(file_node.content)
            
            # Extract symbols
            functions, classes, variables = self.extract_symbols(file_node.content)
            file_node.functions = functions
            file_node.classes = classes
            file_node.variables = variables
            
            # Extract imports and exports
            file_node.imports = self._extract_imports(tree)
            file_node.exports = self._extract_exports(tree)
            
        except SyntaxError as e:
            error_msg = f"Syntax error: {e}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract import dependencies from Python content.
        
        Args:
            content: Python source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        dep = self.create_dependency(
                            source="",  # Will be set by scanner
                            target=alias.name,
                            dependency_type="import",
                            line_number=node.lineno,
                            is_external=self.is_external_dependency(alias.name)
                        )
                        dependencies.append(dep)
                
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    is_relative = node.level > 0
                    
                    # Handle relative imports
                    if is_relative:
                        module = "." * node.level + (module if module else "")
                    
                    for alias in node.names:
                        target = f"{module}.{alias.name}" if module and alias.name != "*" else module
                        
                        dep = self.create_dependency(
                            source="",  # Will be set by scanner
                            target=target,
                            dependency_type="from_import",
                            line_number=node.lineno,
                            is_relative=is_relative,
                            is_external=not is_relative and self.is_external_dependency(module)
                        )
                        dependencies.append(dep)
        
        except SyntaxError:
            # If we can't parse, try regex fallback
            dependencies.extend(self._extract_dependencies_regex(content))
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract functions, classes, and variables from Python content.
        
        Args:
            content: Python source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.add(node.name)
                elif isinstance(node, ast.AsyncFunctionDef):
                    functions.add(node.name)
                elif isinstance(node, ast.ClassDef):
                    classes.add(node.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            variables.add(target.id)
                        elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                            for elt in target.elts:
                                if isinstance(elt, ast.Name):
                                    variables.add(elt.id)
        
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            functions, classes, variables = self._extract_symbols_regex(content)
        
        return functions, classes, variables
    
    def _convert_ast_node(self, node: ast.AST) -> ASTNode:
        """
        Convert a Python AST node to our ASTNode representation.
        
        Args:
            node: Python AST node
            
        Returns:
            ASTNode: Our AST node representation
        """
        node_type = type(node).__name__
        name = getattr(node, 'name', None)
        line_number = getattr(node, 'lineno', None)
        column_number = getattr(node, 'col_offset', None)
        
        # Build attributes dict
        attributes = {}
        for field_name, field_value in ast.iter_fields(node):
            if not isinstance(field_value, list) and not isinstance(field_value, ast.AST):
                attributes[field_name] = field_value
        
        # Filter out 'name' from attributes to avoid duplicate argument
        filtered_attributes = {k: v for k, v in attributes.items() if k != 'name'}
        
        ast_node = self.build_ast_node(
            node_type=node_type,
            name=name,
            line_number=line_number,
            column_number=column_number,
            **filtered_attributes
        )
        
        # Convert child nodes
        for field_name, field_value in ast.iter_fields(node):
            if isinstance(field_value, list):
                for item in field_value:
                    if isinstance(item, ast.AST):
                        child_node = self._convert_ast_node(item)
                        ast_node.children.append(child_node)
            elif isinstance(field_value, ast.AST):
                child_node = self._convert_ast_node(field_value)
                ast_node.children.append(child_node)
        
        return ast_node
    
    def _extract_imports(self, tree: ast.AST) -> Set[str]:
        """
        Extract all imported modules from an AST.
        
        Args:
            tree: Python AST
            
        Returns:
            Set[str]: Set of imported module names
        """
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        
        return imports
    
    def _extract_exports(self, tree: ast.AST) -> Set[str]:
        """
        Extract exports (__all__ definitions) from an AST.
        
        Args:
            tree: Python AST
            
        Returns:
            Set[str]: Set of exported names
        """
        exports = set()
        
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and 
                len(node.targets) == 1 and 
                isinstance(node.targets[0], ast.Name) and 
                node.targets[0].id == "__all__"):
                
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Str):
                            exports.add(elt.s)
                        elif isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            exports.add(elt.value)
        
        return exports
    
    def _extract_dependencies_regex(self, content: str) -> List[Dependency]:
        """
        Fallback regex-based dependency extraction.
        
        Args:
            content: Python source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        # Pattern for import statements
        import_pattern = r'^import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        from_import_pattern = r'^from\s+(\.*)([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import'
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for regular imports
            match = re.match(import_pattern, line)
            if match:
                module = match.group(1)
                dep = self.create_dependency(
                    source="",
                    target=module,
                    dependency_type="import",
                    line_number=line_num,
                    is_external=self.is_external_dependency(module)
                )
                dependencies.append(dep)
            
            # Check for from imports
            match = re.match(from_import_pattern, line)
            if match:
                relative_dots = match.group(1)
                module = match.group(2) if match.group(2) else ""
                is_relative = len(relative_dots) > 0
                
                if is_relative:
                    module = relative_dots + module
                
                dep = self.create_dependency(
                    source="",
                    target=module,
                    dependency_type="from_import",
                    line_number=line_num,
                    is_relative=is_relative,
                    is_external=not is_relative and self.is_external_dependency(module)
                )
                dependencies.append(dep)
        
        return dependencies
    
    def _extract_symbols_regex(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Fallback regex-based symbol extraction.
        
        Args:
            content: Python source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        # Patterns for different symbols
        func_pattern = r'^def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        async_func_pattern = r'^async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        class_pattern = r'^class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:\(]'
        var_pattern = r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract functions
            match = re.match(func_pattern, line)
            if match:
                functions.add(match.group(1))
                continue
            
            match = re.match(async_func_pattern, line)
            if match:
                functions.add(match.group(1))
                continue
            
            # Extract classes
            match = re.match(class_pattern, line)
            if match:
                classes.add(match.group(1))
                continue
            
            # Extract variables (top-level assignments)
            match = re.match(var_pattern, line)
            if match:
                variables.add(match.group(1))
        
        return functions, classes, variables
    
    def is_external_dependency(self, dependency_name: str) -> bool:
        """
        Check if a Python dependency is external.
        
        Args:
            dependency_name: Name of the dependency
            
        Returns:
            bool: True if dependency is external
        """
        if not dependency_name:
            return False
        
        # Standard library modules (common ones)
        stdlib_modules = {
            'os', 'sys', 'json', 'datetime', 'time', 'math', 'random',
            'collections', 'itertools', 'functools', 'operator', 'copy',
            'pickle', 're', 'glob', 'shutil', 'subprocess', 'threading',
            'multiprocessing', 'logging', 'unittest', 'argparse', 'configparser',
            'urllib', 'http', 'email', 'html', 'xml', 'sqlite3', 'csv',
            'hashlib', 'uuid', 'base64', 'zlib', 'gzip', 'tarfile', 'zipfile'
        }
        
        # Get the top-level module name
        top_level = dependency_name.split('.')[0]
        
        # If it's a standard library module, it's external but built-in
        if top_level in stdlib_modules:
            return True
        
        # Use base class logic for other checks
        return super().is_external_dependency(dependency_name)
