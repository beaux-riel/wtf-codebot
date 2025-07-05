"""
Markdown parser for documentation files.
"""

import re
from typing import List, Set, Optional
from .base import BaseParser
from ..models import FileNode, ASTNode, Dependency


class MarkdownParser(BaseParser):
    """
    Parser for Markdown files.
    
    Extracts:
    - Link dependencies
    - Image dependencies
    - Headers and structure
    - Code blocks
    """
    
    def __init__(self):
        """Initialize the Markdown parser."""
        super().__init__()
        self.supported_extensions = {'.md', '.markdown'}
        self.language_name = "markdown"
    
    def parse(self, file_node: FileNode) -> None:
        """
        Parse a Markdown file and populate the FileNode.
        
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
            
            # Build AST
            file_node.ast_root = self._build_markdown_ast(file_node.content)
            
        except Exception as e:
            error_msg = f"Parse error: {str(e)}"
            file_node.parse_errors.append(error_msg)
            self.log_parse_error(str(file_node.path), error_msg)
    
    def extract_dependencies(self, content: str) -> List[Dependency]:
        """
        Extract link and image dependencies from Markdown content.
        
        Args:
            content: Markdown source code
            
        Returns:
            List[Dependency]: List of dependencies found
        """
        dependencies = []
        lines = content.split('\n')
        
        # Patterns for different types of references
        patterns = [
            # Links: [text](url)
            (r'\[([^\]]*)\]\(([^)]+)\)', 'link'),
            # Images: ![alt](src)
            (r'!\[([^\]]*)\]\(([^)]+)\)', 'image'),
            # Reference links: [text][ref]
            (r'\[([^\]]+)\]\[([^\]]+)\]', 'reference_link'),
            # Reference definitions: [ref]: url
            (r'^\[([^\]]+)\]:\s*(.+)$', 'reference_definition'),
            # Autolinks: <url>
            (r'<(https?://[^>]+)>', 'autolink'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, dep_type in patterns:
                matches = re.finditer(pattern, line, re.MULTILINE)
                for match in matches:
                    if dep_type == 'reference_definition':
                        # For reference definitions, the URL is in group 2
                        target = match.group(2).strip()
                    elif dep_type in ['link', 'image']:
                        # For direct links/images, the URL is in group 2
                        target = match.group(2)
                    elif dep_type == 'autolink':
                        # For autolinks, the URL is in group 1
                        target = match.group(1)
                    else:
                        # For reference links, we don't have the actual URL here
                        continue
                    
                    # Clean up the target URL
                    target = target.split()[0]  # Remove any title text
                    
                    # Determine if it's external or relative
                    is_external = target.startswith(('http://', 'https://', 'ftp://', 'mailto:'))
                    is_relative = not is_external and not target.startswith('/')
                    
                    dep = self.create_dependency(
                        source="",  # Will be set by scanner
                        target=target,
                        dependency_type=dep_type,
                        line_number=line_num,
                        is_relative=is_relative,
                        is_external=is_external
                    )
                    dependencies.append(dep)
        
        return dependencies
    
    def extract_symbols(self, content: str) -> tuple[Set[str], Set[str], Set[str]]:
        """
        Extract symbols from Markdown content.
        
        Args:
            content: Markdown source code
            
        Returns:
            tuple: (functions, classes, variables) sets
        """
        functions = set()
        classes = set()
        variables = set()
        
        lines = content.split('\n')
        
        for line in lines:
            # Extract headers as variables
            header_match = re.match(r'^(#{1,6})\s+(.+)$', line.strip())
            if header_match:
                level = len(header_match.group(1))
                header_text = header_match.group(2).strip()
                # Create a slug from the header text
                slug = re.sub(r'[^\w\s-]', '', header_text).strip()
                slug = re.sub(r'[-\s]+', '-', slug).lower()
                variables.add(f"h{level}-{slug}")
            
            # Extract code block languages as classes
            code_block_match = re.match(r'^```(\w+)', line.strip())
            if code_block_match:
                language = code_block_match.group(1)
                classes.add(f"code-{language}")
            
            # Extract inline code as functions (simple heuristic)
            inline_code_matches = re.finditer(r'`([^`]+)`', line)
            for match in inline_code_matches:
                code_content = match.group(1)
                # If it looks like a function call, add it
                if '(' in code_content and ')' in code_content:
                    func_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code_content)
                    if func_match:
                        functions.add(func_match.group(1))
        
        return functions, classes, variables
    
    def _build_markdown_ast(self, content: str) -> ASTNode:
        """
        Build a simple AST representation of Markdown content.
        
        Args:
            content: Markdown source code
            
        Returns:
            ASTNode: Root AST node
        """
        root_node = self.build_ast_node(
            node_type="document",
            name="root"
        )
        
        lines = content.split('\n')
        current_section = None
        current_list = None
        in_code_block = False
        code_block_lang = None
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Handle code blocks
            if line_stripped.startswith('```'):
                if not in_code_block:
                    # Starting a code block
                    in_code_block = True
                    code_match = re.match(r'^```(\w+)?', line_stripped)
                    code_block_lang = code_match.group(1) if code_match and code_match.group(1) else "text"
                    
                    code_node = self.build_ast_node(
                        node_type="code_block",
                        name=code_block_lang,
                        line_number=line_num
                    )
                    root_node.children.append(code_node)
                else:
                    # Ending a code block
                    in_code_block = False
                    code_block_lang = None
                continue
            
            if in_code_block:
                continue
            
            # Handle headers
            header_match = re.match(r'^(#{1,6})\s+(.+)$', line_stripped)
            if header_match:
                level = len(header_match.group(1))
                header_text = header_match.group(2).strip()
                
                header_node = self.build_ast_node(
                    node_type=f"header_{level}",
                    name=header_text,
                    line_number=line_num
                )
                root_node.children.append(header_node)
                current_section = header_node
                current_list = None
                continue
            
            # Handle lists
            list_match = re.match(r'^(\s*)[-*+]\s+(.+)$', line)
            if list_match:
                indent = len(list_match.group(1))
                list_text = list_match.group(2)
                
                if current_list is None or current_list.attributes.get('indent', 0) != indent:
                    # Start new list
                    current_list = self.build_ast_node(
                        node_type="list",
                        name=f"list_indent_{indent}",
                        line_number=line_num,
                        indent=indent
                    )
                    if current_section:
                        current_section.children.append(current_list)
                    else:
                        root_node.children.append(current_list)
                
                list_item = self.build_ast_node(
                    node_type="list_item",
                    name=list_text[:50] + "..." if len(list_text) > 50 else list_text,
                    line_number=line_num
                )
                current_list.children.append(list_item)
                continue
            
            # Handle numbered lists
            numbered_list_match = re.match(r'^(\s*)\d+\.\s+(.+)$', line)
            if numbered_list_match:
                indent = len(numbered_list_match.group(1))
                list_text = numbered_list_match.group(2)
                
                if current_list is None or current_list.attributes.get('indent', 0) != indent:
                    # Start new numbered list
                    current_list = self.build_ast_node(
                        node_type="numbered_list",
                        name=f"numbered_list_indent_{indent}",
                        line_number=line_num,
                        indent=indent
                    )
                    if current_section:
                        current_section.children.append(current_list)
                    else:
                        root_node.children.append(current_list)
                
                list_item = self.build_ast_node(
                    node_type="numbered_item",
                    name=list_text[:50] + "..." if len(list_text) > 50 else list_text,
                    line_number=line_num
                )
                current_list.children.append(list_item)
                continue
            
            # Handle links and images
            link_matches = re.finditer(r'\[([^\]]*)\]\(([^)]+)\)', line)
            for match in link_matches:
                link_text = match.group(1)
                link_url = match.group(2)
                
                link_node = self.build_ast_node(
                    node_type="link",
                    name=link_text or link_url,
                    line_number=line_num,
                    url=link_url
                )
                
                if current_section:
                    current_section.children.append(link_node)
                else:
                    root_node.children.append(link_node)
            
            # Reset list context for non-list lines
            if not re.match(r'^\s*[-*+\d]+[\.\)]\s+', line):
                current_list = None
        
        return root_node
