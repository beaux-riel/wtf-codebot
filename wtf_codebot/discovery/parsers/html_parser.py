"""
HTML parser using BeautifulSoup.
"""

import re
from typing import List, Set, Optional
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency

try:
    from bs4 import BeautifulSoup, Comment
    HAS_BEAUTIFULSOUP = True
except ImportError:
    BeautifulSoup = None
    Comment = None
    HAS_BEAUTIFULSOUP = False


class HTMLParser(BaseParser):
    """
    Parser for HTML files using BeautifulSoup.
    
    Extracts:
    - External resource dependencies (CSS, JS, images)
    - HTML structure
    - Script and style content
    """
    
    def __init__(self):
        """Initialize the HTML parser."""
        super().__init__()
        self.supported_extensions = {'.html', '.htm'}
        self.language_name = "html"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse an HTML file and populate the FileNode.
        
        Args:
            file_node: FileNode to populate
        """
        if not file_node.content:
            return
        
        try:
            # Extract dependencies
            file_node.dependencies = self.extract_dependencies(file_node.content)
            
            # Extract symbols (limited for HTML)
            functions, classes, variables = self.extract_symbols(file_node.content)
            file_node.functions = functions
            file_node.classes = classes
            file_node.variables = variables
            
            # Build AST if BeautifulSoup is available
            if HAS_BEAUTIFULSOUP:
                file_node.ast_root = self._build_html_ast(file_node.content)
            
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract external resource dependencies from HTML content.
        
        Args:
            content: HTML source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        if HAS_BEAUTIFULSOUP:
            dependencies.extend(self._extract_dependencies_bs4(content))
        else:
            dependencies.extend(self._extract_dependencies_regex(content))
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols from HTML content (mainly IDs and classes).
        
        Args:
            content: HTML source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        if HAS_BEAUTIFULSOUP:
            try:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract class names
                for element in soup.find_all(class_=True):
                    if isinstance(element.get('class'), list):
                        classes.update(element.get('class'))
                    else:
                        classes.add(element.get('class'))
                
                # Extract IDs as variables
                for element in soup.find_all(id=True):
                    variables.add(element.get('id'))
                
                # Extract JavaScript functions from script tags
                for script in soup.find_all('script'):
                    if script.string:
                        js_functions = self._extract_js_functions(script.string)
                        functions.update(js_functions)
                
            except Exception:
                # Fallback to regex
                functions, classes, variables = self._extract_symbols_regex(content)
        else:
            functions, classes, variables = self._extract_symbols_regex(content)
        
        return functions, classes, variables
    
    def _extract_dependencies_bs4(self, content: str) -> List[Dependency]:
        """
        Extract dependencies using BeautifulSoup.
        
        Args:
            content: HTML source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # CSS dependencies
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    dep = self.create_dependency(
                        source="",
                        target=href,
                        dependency_type="stylesheet",
                        is_relative=not href.startswith(('http://', 'https://', '//')),
                        is_external=href.startswith(('http://', 'https://', '//'))
                    )
                    dependencies.append(dep)
            
            # JavaScript dependencies
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src:
                    dep = self.create_dependency(
                        source="",
                        target=src,
                        dependency_type="script",
                        is_relative=not src.startswith(('http://', 'https://', '//')),
                        is_external=src.startswith(('http://', 'https://', '//'))
                    )
                    dependencies.append(dep)
            
            # Image dependencies
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                if src:
                    dep = self.create_dependency(
                        source="",
                        target=src,
                        dependency_type="image",
                        is_relative=not src.startswith(('http://', 'https://', '//')),
                        is_external=src.startswith(('http://', 'https://', '//'))
                    )
                    dependencies.append(dep)
            
            # Other resource dependencies
            resource_tags = [
                ('link', 'href', 'resource'),
                ('source', 'src', 'media'),
                ('track', 'src', 'track'),
                ('embed', 'src', 'embed'),
                ('object', 'data', 'object'),
            ]
            
            for tag_name, attr_name, dep_type in resource_tags:
                for element in soup.find_all(tag_name):
                    resource_url = element.get(attr_name)
                    if resource_url:
                        dep = self.create_dependency(
                            source="",
                            target=resource_url,
                            dependency_type=dep_type,
                            is_relative=not resource_url.startswith(('http://', 'https://', '//')),
                            is_external=resource_url.startswith(('http://', 'https://', '//'))
                        )
                        dependencies.append(dep)
        
        except Exception as e:
            self.log_parse_error("", f"BeautifulSoup parsing error: {e}")
        
        return dependencies
    
    def _extract_dependencies_regex(self, content: str) -> List[Dependency]:
        """
        Fallback regex-based dependency extraction.
        
        Args:
            content: HTML source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        
        # Patterns for different resource types
        patterns = [
            (r'<link[^>]+href\s*=\s*[\'"]([^\'"]+)[\'"]', 'stylesheet'),
            (r'<script[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]', 'script'),
            (r'<img[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]', 'image'),
            (r'<source[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]', 'media'),
            (r'<track[^>]+src\s*=\s*[\'"]([^\'"]+)[\'"]', 'track'),
        ]
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, dep_type in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    resource_url = match.group(1)
                    dep = self.create_dependency(
                        source="",
                        target=resource_url,
                        dependency_type=dep_type,
                        line_number=line_num,
                        is_relative=not resource_url.startswith(('http://', 'https://', '//')),
                        is_external=resource_url.startswith(('http://', 'https://', '//'))
                    )
                    dependencies.append(dep)
        
        return dependencies
    
    def _extract_symbols_regex(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Fallback regex-based symbol extraction.
        
        Args:
            content: HTML source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        # Extract class names
        class_matches = re.finditer(r'class\s*=\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        for match in class_matches:
            class_list = match.group(1).split()
            classes.update(class_list)
        
        # Extract IDs
        id_matches = re.finditer(r'id\s*=\s*[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        for match in id_matches:
            variables.add(match.group(1))
        
        # Extract JavaScript functions from script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        script_matches = re.finditer(script_pattern, content, re.DOTALL | re.IGNORECASE)
        for match in script_matches:
            js_content = match.group(1)
            js_functions = self._extract_js_functions(js_content)
            functions.update(js_functions)
        
        return functions, classes, variables
    
    def _extract_js_functions(self, js_content: str) -> Set[str]:
        """
        Extract JavaScript function names from script content.
        
        Args:
            js_content: JavaScript code
            
        Returns:
            Set[str]: Set of function names
        """
        functions = set()
        
        # Simple patterns for function declarations
        patterns = [
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*function\s*\(',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content)
            for match in matches:
                functions.add(match.group(1))
        
        return functions
    
    def _build_html_ast(self, content: str) -> Optional[ASTNode]:
        """
        Build an AST representation of HTML using BeautifulSoup.
        
        Args:
            content: HTML source code
            
        Returns:
            Optional[ASTNode]: Root AST node
        """
        if not HAS_BEAUTIFULSOUP:
            return None
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            return self._convert_bs4_to_ast(soup)
        except Exception as e:
            self.log_parse_error("", f"HTML AST building error: {e}")
            return None
    
    def _convert_bs4_to_ast(self, element) -> ASTNode:
        """
        Convert a BeautifulSoup element to our ASTNode representation.
        
        Args:
            element: BeautifulSoup element
            
        Returns:
            ASTNode: Our AST node representation
        """
        if hasattr(element, 'name'):
            # HTML element
            node_type = element.name or "document"
            attributes = dict(element.attrs) if hasattr(element, 'attrs') else {}
            
            ast_node = self.build_ast_node(
                node_type=node_type,
                name=element.get('id') or element.get('class'),
                **attributes
            )
            
            # Add children
            if hasattr(element, 'children'):
                for child in element.children:
                    if hasattr(child, 'name') or str(child).strip():
                        child_node = self._convert_bs4_to_ast(child)
                        if child_node:
                            ast_node.children.append(child_node)
            
            return ast_node
        else:
            # Text node
            text_content = str(element).strip()
            if text_content:
                return self.build_ast_node(
                    node_type="text",
                    name=text_content[:50] + "..." if len(text_content) > 50 else text_content
                )
            return None
