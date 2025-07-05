"""
YAML parser for configuration files.
"""

import re
from typing import List, Set, Optional, Any
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency

try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False


class YAMLParser(BaseParser):
    """
    Parser for YAML files.
    
    Extracts:
    - Structure information
    - Key names
    - Dependencies (if it's a docker-compose.yml or similar)
    """
    
    def __init__(self):
        """Initialize the YAML parser."""
        super().__init__()
        self.supported_extensions = {'.yml', '.yaml'}
        self.language_name = "yaml"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a YAML file and populate the FileNode.
        
        Args:
            file_node: FileNode to populate
        """
        if not file_node.content:
            return
        
        try:
            # Extract dependencies
            file_node.dependencies = self.extract_dependencies(file_node.content)
            
            # Extract symbols (key names)
            functions, classes, variables = self.extract_symbols(file_node.content)
            file_node.functions = functions
            file_node.classes = classes
            file_node.variables = variables
            
            # Build AST if PyYAML is available
            if HAS_YAML:
                yaml_data = yaml.safe_load(file_node.content)
                if yaml_data is not None:
                    file_node.ast_root = self._build_yaml_ast(yaml_data)
            
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract dependencies from YAML content.
        
        Args:
            content: YAML source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        if HAS_YAML:
            try:
                yaml_data = yaml.safe_load(content)
                if yaml_data:
                    dependencies.extend(self._extract_dependencies_from_yaml(yaml_data))
            except yaml.YAMLError:
                # Fallback to regex if YAML is invalid
                dependencies.extend(self._extract_dependencies_regex(content))
        else:
            dependencies.extend(self._extract_dependencies_regex(content))
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols from YAML content (mainly key names).
        
        Args:
            content: YAML source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()  # YAML keys are treated as variables
        
        if HAS_YAML:
            try:
                yaml_data = yaml.safe_load(content)
                if yaml_data:
                    variables.update(self._extract_keys_recursive(yaml_data))
            except yaml.YAMLError:
                # Fallback to regex if YAML is invalid
                variables = self._extract_keys_regex(content)
        else:
            variables = self._extract_keys_regex(content)
        
        return functions, classes, variables
    
    def _extract_dependencies_from_yaml(self, yaml_data: Any) -> List[Dependency]:
        """
        Extract dependencies from parsed YAML data.
        
        Args:
            yaml_data: Parsed YAML data
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        if isinstance(yaml_data, dict):
            # Docker Compose dependencies
            if 'services' in yaml_data:
                for service_name, service_config in yaml_data['services'].items():
                    if isinstance(service_config, dict):
                        # Image dependencies
                        if 'image' in service_config:
                            dep = self.create_dependency(
                                source="",
                                target=service_config['image'],
                                dependency_type="docker_image",
                                is_external=True
                            )
                            dependencies.append(dep)
                        
                        # Build dependencies
                        if 'build' in service_config:
                            build_context = service_config['build']
                            if isinstance(build_context, str):
                                dep = self.create_dependency(
                                    source="",
                                    target=build_context,
                                    dependency_type="build_context",
                                    is_relative=True
                                )
                                dependencies.append(dep)
                            elif isinstance(build_context, dict) and 'context' in build_context:
                                dep = self.create_dependency(
                                    source="",
                                    target=build_context['context'],
                                    dependency_type="build_context",
                                    is_relative=True
                                )
                                dependencies.append(dep)
            
            # Kubernetes dependencies
            if 'spec' in yaml_data and 'containers' in yaml_data.get('spec', {}):
                containers = yaml_data['spec']['containers']
                if isinstance(containers, list):
                    for container in containers:
                        if isinstance(container, dict) and 'image' in container:
                            dep = self.create_dependency(
                                source="",
                                target=container['image'],
                                dependency_type="container_image",
                                is_external=True
                            )
                            dependencies.append(dep)
            
            # GitHub Actions dependencies
            if 'jobs' in yaml_data:
                for job_name, job_config in yaml_data['jobs'].items():
                    if isinstance(job_config, dict) and 'uses' in job_config:
                        dep = self.create_dependency(
                            source="",
                            target=job_config['uses'],
                            dependency_type="github_action",
                            is_external=True
                        )
                        dependencies.append(dep)
                    
                    if isinstance(job_config, dict) and 'steps' in job_config:
                        steps = job_config['steps']
                        if isinstance(steps, list):
                            for step in steps:
                                if isinstance(step, dict) and 'uses' in step:
                                    dep = self.create_dependency(
                                        source="",
                                        target=step['uses'],
                                        dependency_type="github_action",
                                        is_external=True
                                    )
                                    dependencies.append(dep)
        
        return dependencies
    
    def _extract_dependencies_regex(self, content: str) -> List[Dependency]:
        """
        Fallback regex-based dependency extraction.
        
        Args:
            content: YAML content
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        lines = content.split('\n')
        
        # Patterns for common dependency types
        patterns = [
            # Docker images
            (r'image:\s*[\'"]?([^\s\'"]+)[\'"]?', 'docker_image'),
            # GitHub Actions
            (r'uses:\s*[\'"]?([^\s\'"]+)[\'"]?', 'github_action'),
            # Build contexts
            (r'build:\s*[\'"]?([^\s\'"]+)[\'"]?', 'build_context'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            for pattern, dep_type in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    target = match.group(1)
                    is_relative = target.startswith('.') or '/' in target
                    
                    dep = self.create_dependency(
                        source="",
                        target=target,
                        dependency_type=dep_type,
                        line_number=line_num,
                        is_relative=is_relative,
                        is_external=not is_relative
                    )
                    dependencies.append(dep)
        
        return dependencies
    
    def _extract_keys_recursive(self, obj: Any, prefix: str = "") -> Set[str]:
        """
        Recursively extract all keys from a YAML object.
        
        Args:
            obj: YAML object (dict, list, or primitive)
            prefix: Current key prefix for nested objects
            
        Returns:
            Set[str]: Set of all keys found
        """
        keys = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str):
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
        Fallback regex-based key extraction for invalid YAML.
        
        Args:
            content: YAML-like content
            
        Returns:
            Set[str]: Set of key names found
        """
        keys = set()
        
        # Extract YAML keys (simple pattern)
        key_pattern = r'^(\s*)([a-zA-Z_][a-zA-Z0-9_-]*)\s*:'
        lines = content.split('\n')
        
        for line in lines:
            match = re.match(key_pattern, line)
            if match:
                keys.add(match.group(2))
        
        return keys
    
    def _build_yaml_ast(self, yaml_data: Any, name: str = "root") -> ASTNode:
        """
        Build an AST representation of YAML data.
        
        Args:
            yaml_data: Parsed YAML data
            name: Name for this node
            
        Returns:
            ASTNode: Root AST node
        """
        if isinstance(yaml_data, dict):
            node = self.build_ast_node(
                node_type="mapping",
                name=name
            )
            
            for key, value in yaml_data.items():
                child_node = self._build_yaml_ast(value, str(key))
                node.children.append(child_node)
            
            return node
        
        elif isinstance(yaml_data, list):
            node = self.build_ast_node(
                node_type="sequence",
                name=name
            )
            
            for i, item in enumerate(yaml_data):
                child_node = self._build_yaml_ast(item, f"[{i}]")
                node.children.append(child_node)
            
            return node
        
        else:
            # Scalar value
            value_type = type(yaml_data).__name__
            return self.build_ast_node(
                node_type=value_type,
                name=name,
                value=str(yaml_data) if yaml_data is not None else "null"
            )
