"""
CSS parser using cssutils.
"""

import re
from typing import List, Set, Optional
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency

try:
    import cssutils
    HAS_CSSUTILS = True
except ImportError:
    cssutils = None
    HAS_CSSUTILS = False


class CSSParser(BaseParser):
    """
    Parser for CSS files using cssutils.
    
    Extracts:
    - @import dependencies
    - CSS selectors and rules
    - CSS custom properties (variables)
    """
    
    def __init__(self):
        """Initialize the CSS parser."""
        super().__init__()
        self.supported_extensions = {'.css', '.scss', '.sass'}
        self.language_name = "css"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a CSS file and populate the FileNode.
        
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
            
            # Build AST if cssutils is available
            if HAS_CSSUTILS:
                file_node.ast_root = self._build_css_ast(file_node.content)
            
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract @import dependencies from CSS content.
        
        Args:
            content: CSS source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        # Patterns for CSS imports
        import_patterns = [
            # @import "file.css"
            r'@import\s+[\'"]([^\'"]+)[\'"]',
            # @import url("file.css")
            r'@import\s+url\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
            # @import url(file.css)
            r'@import\s+url\s*\(\s*([^)\'"\s]+)\s*\)',
        ]
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            for pattern in import_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    import_path = match.group(1)
                    is_relative = not import_path.startswith(('http://', 'https://', '//'))
                    
                    dep = self.create_dependency(
                        source="",  # Will be set by scanner
                        target=import_path,
                        dependency_type="import",
                        line_number=line_num,
                        is_relative=is_relative,
                        is_external=not is_relative
                    )
                    dependencies.append(dep)
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols from CSS content.
        
        Args:
            content: CSS source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()  # CSS functions like calc(), var(), etc.
        classes = set()    # CSS class selectors
        variables = set()  # CSS custom properties
        
        if HAS_CSSUTILS:
            try:
                functions_css, classes_css, variables_css = self._extract_symbols_cssutils(content)
                functions.update(functions_css)
                classes.update(classes_css)
                variables.update(variables_css)
            except Exception:
                # Fallback to regex
                functions, classes, variables = self._extract_symbols_regex(content)
        else:
            functions, classes, variables = self._extract_symbols_regex(content)
        
        return functions, classes, variables
    
    def _extract_symbols_cssutils(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols using cssutils.
        
        Args:
            content: CSS source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        try:
            # Disable cssutils logging
            cssutils.log.setLevel('ERROR')
            
            sheet = cssutils.parseString(content)
            
            for rule in sheet:
                if hasattr(rule, 'selectorText'):
                    # Extract class selectors
                    selectors = rule.selectorText.split(',')
                    for selector in selectors:
                        selector = selector.strip()
                        class_matches = re.findall(r'\.([a-zA-Z_-][a-zA-Z0-9_-]*)', selector)
                        classes.update(class_matches)
                
                if hasattr(rule, 'style'):
                    for prop in rule.style:
                        # Extract CSS custom properties (variables)
                        if prop.name.startswith('--'):
                            variables.add(prop.name)
                        
                        # Extract CSS functions from property values
                        if prop.value:
                            func_matches = re.findall(r'([a-zA-Z-]+)\s*\(', prop.value)
                            functions.update(func_matches)
        
        except Exception as e:
            self.log_parse_error("", f"cssutils parsing error: {e}")
        
        return functions, classes, variables
    
    def _extract_symbols_regex(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Fallback regex-based symbol extraction.
        
        Args:
            content: CSS source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        # Extract class selectors
        class_matches = re.finditer(r'\.([a-zA-Z_-][a-zA-Z0-9_-]*)', content)
        for match in class_matches:
            classes.add(match.group(1))
        
        # Extract CSS custom properties
        var_matches = re.finditer(r'(--[a-zA-Z_-][a-zA-Z0-9_-]*)', content)
        for match in var_matches:
            variables.add(match.group(1))
        
        # Extract CSS functions
        func_matches = re.finditer(r'([a-zA-Z-]+)\s*\(', content)
        for match in func_matches:
            func_name = match.group(1)
            # Filter out common property names that aren't functions
            if func_name not in {'color', 'background', 'border', 'margin', 'padding', 'font'}:
                functions.add(func_name)
        
        return functions, classes, variables
    
    def _build_css_ast(self, content: str) -> Optional[ASTNode]:
        """
        Build an AST representation of CSS using cssutils.
        
        Args:
            content: CSS source code
            
        Returns:
            Optional[ASTNode]: Root AST node
        """
        if not HAS_CSSUTILS:
            return None
        
        try:
            # Disable cssutils logging
            cssutils.log.setLevel('ERROR')
            
            sheet = cssutils.parseString(content)
            return self._convert_css_to_ast(sheet)
        except Exception as e:
            self.log_parse_error("", f"CSS AST building error: {e}")
            return None
    
    def _convert_css_to_ast(self, sheet) -> ASTNode:
        """
        Convert a cssutils stylesheet to our ASTNode representation.
        
        Args:
            sheet: cssutils CSSStyleSheet
            
        Returns:
            ASTNode: Our AST node representation
        """
        root_node = self.build_ast_node(
            node_type="stylesheet",
            name="root"
        )
        
        for rule in sheet:
            rule_node = self._convert_css_rule_to_ast(rule)
            if rule_node:
                root_node.children.append(rule_node)
        
        return root_node
    
    def _convert_css_rule_to_ast(self, rule) -> Optional[ASTNode]:
        """
        Convert a CSS rule to an ASTNode.
        
        Args:
            rule: cssutils CSS rule
            
        Returns:
            Optional[ASTNode]: AST node for the rule
        """
        rule_type = type(rule).__name__
        
        if hasattr(rule, 'selectorText'):
            # Style rule
            rule_node = self.build_ast_node(
                node_type="style_rule",
                name=rule.selectorText
            )
            
            if hasattr(rule, 'style'):
                for prop in rule.style:
                    prop_node = self.build_ast_node(
                        node_type="property",
                        name=prop.name,
                        value=prop.value
                    )
                    rule_node.children.append(prop_node)
            
            return rule_node
        
        elif hasattr(rule, 'cssText'):
            # Other types of rules
            return self.build_ast_node(
                node_type=rule_type.lower(),
                name=str(rule.cssText)[:100]
            )
        
        return None
