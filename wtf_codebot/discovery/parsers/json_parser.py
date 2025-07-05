"""
JSON parser for structured data files.
"""

import json
import re
from typing import List, Set, Optional, Any, Dict
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency


class JSONParser(BaseParser):
    """
    Parser for JSON files.
    
    Extracts:
    - Structure information
    - Key names
    - Dependencies (if it's a package.json or similar)
    """
    
    def __init__(self):
        """Initialize the JSON parser."""
        super().__init__()
        self.supported_extensions = {'.json'}
        self.language_name = "json"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a JSON file and populate the FileNode.
        
        Args:
            file_node: FileNode to populate
        """
        if not file_node.content:
            return
        
        try:
            # Parse JSON content
            json_data = json.loads(file_node.content)
            
            # Extract dependencies (for package.json, etc.)
            file_node.dependencies = self.extract_dependencies(file_node.content)
            
            # Extract symbols (key names)
            functions, classes, variables = self.extract_symbols(file_node.content)
            file_node.functions = functions
            file_node.classes = classes
            file_node.variables = variables
            
            # Build AST
            file_node.ast_root = self._build_json_ast(json_data)
            
        except json.JSONDecodeError as e:
            error_msg = f"JSON decode error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract dependencies from JSON content (mainly for package.json).
        
        Args:
            content: JSON source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        try:
            json_data = json.loads(content)
            
            # Check if this is a package.json or similar dependency file
            dependency_fields = [
                'dependencies',
                'devDependencies',
                'peerDependencies',
                'optionalDependencies',
                'bundledDependencies'
            ]
            
            for field in dependency_fields:
                if field in json_data and isinstance(json_data[field], dict):
                    for package_name, version in json_data[field].items():
                        dep = self.create_dependency(
                            source="",  # Will be set by scanner
                            target=package_name,
                            dependency_type=field,
                            is_external=True  # Package dependencies are external
                        )
                        dependencies.append(dep)
            
            # Check for other dependency patterns
            if 'imports' in json_data and isinstance(json_data['imports'], dict):
                for import_path in json_data['imports'].keys():
                    dep = self.create_dependency(
                        source="",
                        target=import_path,
                        dependency_type="import",
                        is_relative=import_path.startswith('.'),
                        is_external=not import_path.startswith('.')
                    )
                    dependencies.append(dep)
        
        except json.JSONDecodeError:
            # If JSON is invalid, we can't extract dependencies
            pass
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols from JSON content (mainly key names).
        
        Args:
            content: JSON source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()  # JSON keys are treated as variables
        
        try:
            json_data = json.loads(content)
            variables.update(self._extract_keys_recursive(json_data))
        except json.JSONDecodeError:
            # Fallback to regex if JSON is invalid
            variables = self._extract_keys_regex(content)
        
        return functions, classes, variables
    
    def _extract_keys_recursive(self, obj: Any, prefix: str = "") -> Set[str]:
        """
        Recursively extract all keys from a JSON object.
        
        Args:
            obj: JSON object (dict, list, or primitive)
            prefix: Current key prefix for nested objects
            
        Returns:
            Set[str]: Set of all keys found
        """
        keys = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.add(full_key)
                
                # Recursively extract nested keys
                nested_keys = self._extract_keys_recursive(value, full_key)
                keys.update(nested_keys)
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                nested_keys = self._extract_keys_recursive(item, f"{prefix}[{i}]" if prefix else f"[{i}]")
                keys.update(nested_keys)
        
        return keys
    
    def _extract_keys_regex(self, content: str) -> Set[str]:
        """
        Fallback regex-based key extraction for invalid JSON.
        
        Args:
            content: JSON-like content
            
        Returns:
            Set[str]: Set of key names found
        """
        keys = set()
        
        # Extract quoted keys
        key_pattern = r'[\'"]([^\'":]+)[\'"]\s*:'
        matches = re.finditer(key_pattern, content)
        
        for match in matches:
            keys.add(match.group(1))
        
        return keys
    
    def _build_json_ast(self, json_data: Any, name: str = "root") -> ASTNode:
        """
        Build an AST representation of JSON data.
        
        Args:
            json_data: Parsed JSON data
            name: Name for this node
            
        Returns:
            ASTNode: Root AST node
        """
        if isinstance(json_data, dict):
            node = self.build_ast_node(
                node_type="object",
                name=name
            )
            
            for key, value in json_data.items():
                child_node = self._build_json_ast(value, key)
                node.children.append(child_node)
            
            return node
        
        elif isinstance(json_data, list):
            node = self.build_ast_node(
                node_type="array",
                name=name
            )
            
            for i, item in enumerate(json_data):
                child_node = self._build_json_ast(item, f"[{i}]")
                node.children.append(child_node)
            
            return node
        
        else:
            # Primitive value
            value_type = type(json_data).__name__
            return self.build_ast_node(
                node_type=value_type,
                name=name,
                value=str(json_data) if json_data is not None else "null"
            )
