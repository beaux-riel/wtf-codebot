"""
Code batching system for efficient token usage and API optimization.
"""

import json
from typing import List, Dict, Any, Optional, Iterator, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import tiktoken

from ..discovery.models import FileNode, ASTNode, CodebaseGraph
try:
    from ..core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class BatchConfig:
    """Configuration for code batching."""
    max_tokens_per_batch: int = 8000  # Maximum tokens per batch (reduced for rate limits)
    overlap_tokens: int = 500  # Token overlap between batches
    min_batch_size: int = 1000  # Minimum tokens to create a batch
    prioritize_files: List[str] = field(default_factory=list)  # File patterns to prioritize
    exclude_patterns: List[str] = field(default_factory=list)  # Patterns to exclude
    include_metadata: bool = True  # Include file metadata in batches
    include_dependencies: bool = True  # Include dependency information
    chunk_large_files: bool = True  # Chunk files larger than max_tokens


@dataclass
class CodeSnippet:
    """Represents a code snippet with metadata."""
    content: str
    file_path: Path
    start_line: int
    end_line: int
    snippet_type: str  # "full_file", "function", "class", "chunk"
    language: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    
    def get_token_count(self, encoding_name: str = "cl100k_base") -> int:
        """Get token count for this snippet."""
        try:
            encoding = tiktoken.get_encoding(encoding_name)
            return len(encoding.encode(self.content))
        except Exception as e:
            logger.warning(f"Failed to count tokens: {e}")
            # Fallback to character-based estimation (rough)
            return len(self.content) // 3


@dataclass
class CodeBatch:
    """Represents a batch of code snippets for analysis."""
    id: str
    snippets: List[CodeSnippet]
    total_tokens: int
    batch_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_combined_content(self) -> str:
        """Get combined content of all snippets in the batch."""
        content_parts = []
        
        for snippet in self.snippets:
            content_parts.append(f"# File: {snippet.file_path}")
            content_parts.append(f"# Language: {snippet.language}")
            content_parts.append(f"# Lines: {snippet.start_line}-{snippet.end_line}")
            content_parts.append(f"# Type: {snippet.snippet_type}")
            
            if snippet.dependencies:
                content_parts.append(f"# Dependencies: {', '.join(snippet.dependencies)}")
            
            content_parts.append("")
            content_parts.append(snippet.content)
            content_parts.append("")
            content_parts.append("---")
            content_parts.append("")
        
        return "\n".join(content_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert batch to dictionary for serialization."""
        return {
            "id": self.id,
            "total_tokens": self.total_tokens,
            "snippet_count": len(self.snippets),
            "batch_metadata": self.batch_metadata,
            "snippets": [
                {
                    "file_path": str(snippet.file_path),
                    "start_line": snippet.start_line,
                    "end_line": snippet.end_line,
                    "snippet_type": snippet.snippet_type,
                    "language": snippet.language,
                    "token_count": snippet.get_token_count(),
                    "metadata": snippet.metadata,
                    "dependencies": snippet.dependencies
                }
                for snippet in self.snippets
            ]
        }


class CodeBatcher:
    """Batches code snippets for efficient API usage."""
    
    def __init__(self, config: BatchConfig = None):
        """Initialize code batcher.
        
        Args:
            config: Batch configuration
        """
        self.config = config or BatchConfig()
        self.encoding = tiktoken.get_encoding("cl100k_base")
        logger.info(f"Code batcher initialized with max {self.config.max_tokens_per_batch} tokens per batch")
    
    def create_batches_from_codebase(self, codebase: CodebaseGraph) -> List[CodeBatch]:
        """Create batches from a codebase graph.
        
        Args:
            codebase: Codebase graph to batch
            
        Returns:
            List of code batches
        """
        logger.info(f"Creating batches from codebase with {codebase.total_files} files")
        
        # Extract snippets from all files
        snippets = self._extract_snippets_from_codebase(codebase)
        
        # Sort snippets by priority
        snippets = self._sort_snippets_by_priority(snippets)
        
        # Create batches
        batches = self._create_batches_from_snippets(snippets)
        
        logger.info(f"Created {len(batches)} batches from {len(snippets)} snippets")
        return batches
    
    def create_batches_from_files(self, file_nodes: List[FileNode]) -> List[CodeBatch]:
        """Create batches from a list of file nodes.
        
        Args:
            file_nodes: List of file nodes to batch
            
        Returns:
            List of code batches
        """
        logger.info(f"Creating batches from {len(file_nodes)} files")
        
        # Extract snippets from files
        snippets = []
        for file_node in file_nodes:
            file_snippets = self._extract_snippets_from_file(file_node)
            snippets.extend(file_snippets)
        
        # Sort snippets by priority
        snippets = self._sort_snippets_by_priority(snippets)
        
        # Create batches
        batches = self._create_batches_from_snippets(snippets)
        
        logger.info(f"Created {len(batches)} batches from {len(snippets)} snippets")
        return batches
    
    def _extract_snippets_from_codebase(self, codebase: CodebaseGraph) -> List[CodeSnippet]:
        """Extract code snippets from codebase."""
        snippets = []
        
        for file_path, file_node in codebase.files.items():
            if self._should_exclude_file(file_node):
                continue
            
            file_snippets = self._extract_snippets_from_file(file_node)
            snippets.extend(file_snippets)
        
        return snippets
    
    def _extract_snippets_from_file(self, file_node: FileNode) -> List[CodeSnippet]:
        """Extract snippets from a single file."""
        if not file_node.content:
            return []
        
        snippets = []
        language = self._get_language_from_file(file_node)
        
        # Get dependencies
        dependencies = [dep.target for dep in file_node.dependencies]
        
        # Calculate file token count
        file_tokens = self._count_tokens(file_node.content)
        
        if file_tokens <= self.config.max_tokens_per_batch and not self.config.chunk_large_files:
            # Include entire file as one snippet
            snippet = CodeSnippet(
                content=file_node.content,
                file_path=file_node.path,
                start_line=1,
                end_line=len(file_node.content.splitlines()),
                snippet_type="full_file",
                language=language,
                metadata=self._extract_file_metadata(file_node),
                dependencies=dependencies
            )
            snippets.append(snippet)
        else:
            # Chunk file into smaller snippets
            if file_node.ast_root:
                # Use AST-based chunking for structured languages
                ast_snippets = self._extract_snippets_from_ast(file_node)
                snippets.extend(ast_snippets)
            else:
                # Use line-based chunking for other files
                line_snippets = self._chunk_file_by_lines(file_node)
                snippets.extend(line_snippets)
        
        return snippets
    
    def _extract_snippets_from_ast(self, file_node: FileNode) -> List[CodeSnippet]:
        """Extract snippets from AST nodes."""
        snippets = []
        
        if not file_node.ast_root or not file_node.content:
            return snippets
        
        content_lines = file_node.content.splitlines()
        language = self._get_language_from_file(file_node)
        dependencies = [dep.target for dep in file_node.dependencies]
        
        # Extract function and class snippets
        self._extract_ast_nodes_recursive(
            file_node.ast_root,
            content_lines,
            file_node.path,
            language,
            dependencies,
            snippets
        )
        
        return snippets
    
    def _extract_ast_nodes_recursive(self,
                                   node: ASTNode,
                                   content_lines: List[str],
                                   file_path: Path,
                                   language: str,
                                   dependencies: List[str],
                                   snippets: List[CodeSnippet]) -> None:
        """Recursively extract snippets from AST nodes."""
        
        # Check if this node represents a function, class, or other interesting construct
        if node.node_type in ["function", "method", "class", "interface", "module"]:
            if node.line_number is not None:
                # Determine end line (approximate)
                end_line = node.line_number
                for child in node.children:
                    if child.line_number and child.line_number > end_line:
                        end_line = child.line_number
                
                # Extract content for this node
                start_line = max(1, node.line_number)
                end_line = min(len(content_lines), end_line + 10)  # Add some context
                
                if end_line > start_line:
                    content = "\n".join(content_lines[start_line-1:end_line])
                    
                    snippet = CodeSnippet(
                        content=content,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet_type=node.node_type,
                        language=language,
                        metadata={
                            "name": node.name or "anonymous",
                            "node_type": node.node_type,
                            "attributes": node.attributes
                        },
                        dependencies=dependencies
                    )
                    
                    # Only add if it's a reasonable size
                    token_count = snippet.get_token_count()
                    if self.config.min_batch_size <= token_count <= self.config.max_tokens_per_batch:
                        snippets.append(snippet)
        
        # Recurse into children
        for child in node.children:
            self._extract_ast_nodes_recursive(
                child, content_lines, file_path, language, dependencies, snippets
            )
    
    def _chunk_file_by_lines(self, file_node: FileNode) -> List[CodeSnippet]:
        """Chunk file by lines when AST is not available."""
        if not file_node.content:
            return []
        
        snippets = []
        content_lines = file_node.content.splitlines()
        language = self._get_language_from_file(file_node)
        dependencies = [dep.target for dep in file_node.dependencies]
        
        # Calculate lines per chunk based on token limits
        avg_tokens_per_line = self._count_tokens(file_node.content) / len(content_lines)
        max_lines_per_chunk = int(self.config.max_tokens_per_batch / avg_tokens_per_line)
        overlap_lines = int(self.config.overlap_tokens / avg_tokens_per_line)
        
        start_line = 0
        chunk_id = 1
        
        while start_line < len(content_lines):
            end_line = min(start_line + max_lines_per_chunk, len(content_lines))
            
            chunk_content = "\n".join(content_lines[start_line:end_line])
            
            snippet = CodeSnippet(
                content=chunk_content,
                file_path=file_node.path,
                start_line=start_line + 1,
                end_line=end_line,
                snippet_type="chunk",
                language=language,
                metadata={
                    "chunk_id": chunk_id,
                    "total_chunks": -1  # Will be updated later
                },
                dependencies=dependencies
            )
            
            # Only add if it meets minimum size requirement
            if snippet.get_token_count() >= self.config.min_batch_size:
                snippets.append(snippet)
            
            # Move to next chunk with overlap
            start_line = max(start_line + max_lines_per_chunk - overlap_lines, end_line)
            chunk_id += 1
        
        # Update total chunks count
        for snippet in snippets:
            snippet.metadata["total_chunks"] = len(snippets)
        
        return snippets
    
    def _sort_snippets_by_priority(self, snippets: List[CodeSnippet]) -> List[CodeSnippet]:
        """Sort snippets by priority based on configuration."""
        
        def priority_score(snippet: CodeSnippet) -> int:
            score = 0
            
            # Prioritize files matching patterns
            for pattern in self.config.prioritize_files:
                if pattern in str(snippet.file_path):
                    score += 1000
            
            # Prioritize certain snippet types
            type_priorities = {
                "class": 500,
                "function": 400,
                "method": 300,
                "interface": 200,
                "full_file": 100,
                "chunk": 50
            }
            score += type_priorities.get(snippet.snippet_type, 0)
            
            # Prioritize files with more dependencies (likely more important)
            score += len(snippet.dependencies) * 10
            
            return score
        
        return sorted(snippets, key=priority_score, reverse=True)
    
    def _create_batches_from_snippets(self, snippets: List[CodeSnippet]) -> List[CodeBatch]:
        """Create batches from sorted snippets."""
        batches = []
        current_batch_snippets = []
        current_batch_tokens = 0
        batch_id = 1
        
        for snippet in snippets:
            snippet_tokens = snippet.get_token_count()
            
            # Check if adding this snippet would exceed the batch limit
            if (current_batch_tokens + snippet_tokens > self.config.max_tokens_per_batch and 
                current_batch_snippets):
                
                # Create batch from current snippets
                batch = self._create_batch(
                    batch_id,
                    current_batch_snippets,
                    current_batch_tokens
                )
                batches.append(batch)
                
                # Start new batch
                current_batch_snippets = []
                current_batch_tokens = 0
                batch_id += 1
            
            # Add snippet to current batch
            current_batch_snippets.append(snippet)
            current_batch_tokens += snippet_tokens
        
        # Create final batch if there are remaining snippets
        if current_batch_snippets:
            batch = self._create_batch(
                batch_id,
                current_batch_snippets,
                current_batch_tokens
            )
            batches.append(batch)
        
        return batches
    
    def _create_batch(self, 
                     batch_id: int,
                     snippets: List[CodeSnippet],
                     total_tokens: int) -> CodeBatch:
        """Create a code batch from snippets."""
        
        # Collect batch metadata
        metadata = {
            "creation_timestamp": "now",  # Would use datetime in real implementation
            "file_count": len(set(str(s.file_path) for s in snippets)),
            "languages": list(set(s.language for s in snippets)),
            "snippet_types": list(set(s.snippet_type for s in snippets)),
            "total_dependencies": len(set(
                dep for snippet in snippets for dep in snippet.dependencies
            ))
        }
        
        return CodeBatch(
            id=f"batch_{batch_id:03d}",
            snippets=snippets,
            total_tokens=total_tokens,
            batch_metadata=metadata
        )
    
    def _should_exclude_file(self, file_node: FileNode) -> bool:
        """Check if file should be excluded from batching."""
        file_path_str = str(file_node.path)
        
        for pattern in self.config.exclude_patterns:
            if pattern in file_path_str:
                return True
        
        return False
    
    def _get_language_from_file(self, file_node: FileNode) -> str:
        """Get programming language from file node."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".css": "css",
            ".html": "html",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".md": "markdown"
        }
        
        return extension_map.get(file_node.extension, "unknown")
    
    def _extract_file_metadata(self, file_node: FileNode) -> Dict[str, Any]:
        """Extract metadata from file node."""
        metadata = {
            "file_size": file_node.size,
            "last_modified": file_node.last_modified,
            "extension": file_node.extension,
            "file_type": file_node.file_type.value
        }
        
        if self.config.include_metadata:
            metadata.update({
                "functions": list(file_node.functions),
                "classes": list(file_node.classes),
                "variables": list(file_node.variables),
                "exports": list(file_node.exports),
                "imports": list(file_node.imports),
                "parse_errors": file_node.parse_errors
            })
        
        return metadata
    
    def _count_tokens(self, text: str) -> int:
        """Count tokens in text."""
        try:
            return len(self.encoding.encode(text))
        except Exception as e:
            logger.warning(f"Failed to count tokens: {e}")
            # Fallback to character-based estimation
            return len(text) // 3
    
    def save_batches(self, batches: List[CodeBatch], output_path: Path) -> None:
        """Save batches to file for inspection or reuse.
        
        Args:
            batches: List of batches to save
            output_path: Path to save batches
        """
        batch_data = {
            "total_batches": len(batches),
            "total_snippets": sum(len(batch.snippets) for batch in batches),
            "total_tokens": sum(batch.total_tokens for batch in batches),
            "config": {
                "max_tokens_per_batch": self.config.max_tokens_per_batch,
                "overlap_tokens": self.config.overlap_tokens,
                "min_batch_size": self.config.min_batch_size
            },
            "batches": [batch.to_dict() for batch in batches]
        }
        
        with open(output_path, 'w') as f:
            json.dump(batch_data, f, indent=2)
        
        logger.info(f"Saved {len(batches)} batches to {output_path}")
    
    def load_batches(self, input_path: Path) -> List[CodeBatch]:
        """Load batches from file.
        
        Args:
            input_path: Path to load batches from
            
        Returns:
            List of loaded batches
        """
        with open(input_path, 'r') as f:
            batch_data = json.load(f)
        
        batches = []
        for batch_dict in batch_data["batches"]:
            snippets = []
            for snippet_dict in batch_dict["snippets"]:
                snippet = CodeSnippet(
                    content="",  # Content not saved in metadata
                    file_path=Path(snippet_dict["file_path"]),
                    start_line=snippet_dict["start_line"],
                    end_line=snippet_dict["end_line"],
                    snippet_type=snippet_dict["snippet_type"],
                    language=snippet_dict["language"],
                    metadata=snippet_dict["metadata"],
                    dependencies=snippet_dict["dependencies"]
                )
                snippets.append(snippet)
            
            batch = CodeBatch(
                id=batch_dict["id"],
                snippets=snippets,
                total_tokens=batch_dict["total_tokens"],
                batch_metadata=batch_dict["batch_metadata"]
            )
            batches.append(batch)
        
        logger.info(f"Loaded {len(batches)} batches from {input_path}")
        return batches
