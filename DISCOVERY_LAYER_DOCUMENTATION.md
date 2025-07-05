# Codebase Discovery and Parsing Layer

This document describes the codebase discovery and parsing layer implemented for wtf-codebot in Step 4.

## Overview

The discovery layer provides comprehensive codebase analysis capabilities that recursively scan directories, identify file types, build in-memory representations with AST paths, and create dependency graphs. It utilizes language-specific parsers for accurate code analysis.

## Architecture

### Core Components

1. **CodebaseScanner** - Main entry point for directory scanning
2. **ParserFactory** - Creates appropriate parsers for different file types
3. **ParserRegistry** - Manages available language parsers
4. **Data Models** - Structured representations of code elements

### Data Models

#### FileNode
Represents a single file with:
- Path and metadata (size, last modified)
- File type classification
- Parsed content (AST, symbols, dependencies)
- Parse errors (if any)

#### CodebaseGraph
Complete in-memory representation containing:
- All discovered files
- Dependency relationships
- File type categorization
- Statistics and metrics

#### DependencyGraph
Manages dependency relationships:
- Nodes (files) and edges (dependencies)
- Dependency lookup by file
- Dependent files lookup

## Language Support

### Implemented Parsers

1. **Python Parser** (`ast` module)
   - Full AST parsing
   - Import/dependency extraction
   - Function, class, and variable identification
   - Support for relative imports

2. **JavaScript Parser** (regex-based)
   - Import/require statement parsing
   - Function and class extraction
   - ES6+ support (arrow functions, classes)
   - CommonJS and ES module support

3. **TypeScript Parser** (extends JavaScript)
   - TypeScript-specific imports (`import type`)
   - Interface, enum, and namespace detection
   - Reference directives parsing

4. **HTML Parser** (BeautifulSoup)
   - Resource dependency extraction (CSS, JS, images)
   - DOM structure analysis
   - Inline script parsing
   - Class and ID extraction

5. **CSS Parser** (cssutils)
   - @import statement parsing
   - Selector and rule extraction
   - CSS custom properties (variables)
   - CSS function identification

6. **JSON Parser**
   - Structure analysis
   - Package.json dependency extraction
   - Key name extraction
   - Nested object traversal

7. **YAML Parser** (PyYAML)
   - Docker Compose dependency extraction
   - Kubernetes resource parsing
   - GitHub Actions workflow analysis
   - Configuration structure analysis

8. **Markdown Parser** (regex-based)
   - Link and image dependency extraction
   - Header structure analysis
   - Code block language detection
   - Reference link parsing

## Features

### File Discovery
- Recursive directory traversal
- Configurable ignore patterns
- File size limits
- Encoding detection and handling

### AST Generation
- Language-specific AST creation
- Hierarchical structure preservation
- Line and column number tracking
- Node attribute extraction

### Dependency Analysis
- Import/require statement parsing
- Relative vs absolute dependency classification
- External vs internal dependency identification
- Line number tracking for dependencies

### Symbol Extraction
- Function definitions
- Class declarations
- Variable assignments
- Module exports/imports

### Error Handling
- Graceful parsing failure handling
- Error message collection
- Fallback regex parsing for invalid syntax

## Usage Examples

### Basic Scanning

```python
from pathlib import Path
from wtf_codebot.discovery import CodebaseScanner

# Initialize scanner
scanner = CodebaseScanner(
    include_content=True,
    parse_ast=True,
    max_file_size=10 * 1024 * 1024  # 10MB limit
)

# Scan directory
codebase_graph = scanner.scan_directory(Path("."))

# Access results
print(f"Found {codebase_graph.total_files} files")
print(f"Total dependencies: {len(codebase_graph.dependency_graph.edges)}")
```

### File Type Analysis

```python
from wtf_codebot.discovery.models import FileType

# Get Python files
python_files = codebase_graph.get_files_by_type(FileType.PYTHON)

for file_node in python_files:
    print(f"File: {file_node.path}")
    print(f"Functions: {file_node.functions}")
    print(f"Classes: {file_node.classes}")
    print(f"Dependencies: {len(file_node.dependencies)}")
```

### Dependency Graph Analysis

```python
# Get all dependencies
dependencies = codebase_graph.dependency_graph.edges

# Filter external dependencies
external_deps = [dep for dep in dependencies if dep.is_external]

# Find most common external dependencies
from collections import Counter
common_deps = Counter(dep.target for dep in external_deps)
print(common_deps.most_common(10))
```

## Configuration Options

### Scanner Configuration

```python
scanner = CodebaseScanner(
    ignore_dirs={'node_modules', '.git', '__pycache__'},
    ignore_files={'*.pyc', '*.log', '*.tmp'},
    max_file_size=5 * 1024 * 1024,  # 5MB
    include_content=True,  # Read file contents
    parse_ast=True,  # Generate ASTs
)
```

### Custom Parsers

```python
from wtf_codebot.discovery.parsers import register_parser
from wtf_codebot.discovery.models import FileType

# Register custom parser
register_parser(FileType.CUSTOM, CustomParser)
```

## Performance Characteristics

### Memory Usage
- Configurable content inclusion
- AST caching with size limits
- Efficient dependency graph representation

### Processing Speed
- Parallel parsing support (future enhancement)
- Incremental scanning capabilities (future enhancement)
- Selective parsing by file type

### Error Resilience
- Individual file parsing failures don't stop scanning
- Fallback parsing strategies
- Comprehensive error reporting

## Dependencies

### Required
- Python 3.8+
- Standard library modules (ast, re, json, pathlib)

### Optional (with graceful fallbacks)
- `beautifulsoup4` - Enhanced HTML parsing
- `cssutils` - Advanced CSS parsing
- `pyyaml` - YAML file support
- `tree-sitter-*` - Future Tree-sitter integration

## Testing

Run the demo scripts to test functionality:

```bash
# Basic discovery test
python demo_discovery.py

# Detailed parsing test
python test_detailed_parsing.py
```

## Future Enhancements

1. **Tree-sitter Integration**
   - More accurate JavaScript/TypeScript parsing
   - Support for additional languages (Go, Rust, etc.)

2. **Performance Optimizations**
   - Parallel processing
   - Incremental scanning
   - Caching mechanisms

3. **Advanced Analysis**
   - Call graph generation
   - Complexity metrics
   - Code quality analysis

4. **Additional Languages**
   - Go, Rust, Java, C++
   - Language-specific frameworks
   - Configuration formats (TOML, INI)

## Architecture Benefits

1. **Modularity** - Easy to add new parsers and file types
2. **Extensibility** - Plugin-based parser system
3. **Robustness** - Graceful error handling and fallbacks
4. **Performance** - Configurable scanning depth and file size limits
5. **Accuracy** - Language-specific parsing with AST generation

This discovery layer provides a solid foundation for code analysis tools, enabling comprehensive understanding of codebase structure, dependencies, and relationships across multiple programming languages and file formats.
