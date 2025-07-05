# Static Analysis Engines Implementation

## Overview

This implementation provides comprehensive static analysis engines for detecting design patterns, anti-patterns, code smells, and gathering code metadata. The system leverages existing linters (pylint, ESLint) for baseline metrics while adding custom pattern detection capabilities.

## Architecture

### Base Classes

#### `BaseAnalyzer` (abstract)
- Core interface for all static analyzers
- Provides common functionality for finding creation, metric calculation, and rule management
- Supports both file-level and codebase-level analysis

#### `LinterBasedAnalyzer` (abstract)
- Extends `BaseAnalyzer` for analyzers that use external linters
- Handles subprocess execution and output parsing
- Provides fallback mechanisms when linters are unavailable

### Data Models

#### `Finding`
- Represents detected patterns, anti-patterns, or code smells
- Includes severity levels, location information, and improvement suggestions

#### `Metric`
- Represents quantitative code measurements
- Supports file-level, function-level, and class-level metrics

#### `AnalysisResult`
- Aggregates findings, metrics, and metadata from analysis
- Provides filtering and querying capabilities

## Supported Languages

### Python (`PythonAnalyzer`)

**External Linter**: pylint (with JSON output format)

**Custom Pattern Detection**:
- **Design Patterns**:
  - Singleton pattern (detects `__new__` method with conditional logic)
  - Factory method pattern (functions with `create_`, `make_`, or `_factory` naming)
  - Observer pattern (classes with notify/add observer methods)

- **Anti-Patterns**:
  - God class (classes with >20 methods or >15 attributes)

- **Code Smells**:
  - Long methods (>50 lines)
  - Deep nesting (>4 levels)
  - Duplicate code (similar function structures)

**Metrics**:
- Lines of code (excluding comments/blank lines)
- Cyclomatic complexity
- Function/class/import counts

### JavaScript/TypeScript (`JavaScriptAnalyzer`)

**External Linter**: ESLint (with JSON output format)

**Custom Pattern Detection**:
- **Anti-Patterns**:
  - Callback hell (deeply nested callbacks)
  - Promise hell (long .then() chains without .catch())

- **Code Smells**:
  - Large functions (>50 lines)
  - Unused variables
  - Magic numbers (>2 digits, excluding common values)
  - Missing error handling in Promises

**Metrics**:
- Lines of code
- Function/class/import counts
- Cyclomatic complexity

## Registry System

### `AnalyzerRegistry`
- Central registry for managing analyzers
- Automatic language detection based on file extensions
- Supports both individual file and codebase analysis
- Provides statistics and configuration management

### Global Functions
- `get_registry()`: Access to global registry instance
- `analyze_file()`: Analyze single file
- `analyze_codebase()`: Analyze entire codebase
- `register_analyzer()`: Register custom analyzers

## Usage Examples

### Basic File Analysis
```python
from wtf_codebot.analyzers import analyze_file
from wtf_codebot.discovery.models import FileNode, FileType

# Create file node
file_node = FileNode(
    path=Path("example.py"),
    file_type=FileType.PYTHON,
    content=source_code
)

# Analyze
result = analyze_file(file_node)

# Access findings
for finding in result.findings:
    print(f"{finding.pattern_name}: {finding.message}")
```

### Codebase Analysis
```python
from wtf_codebot.analyzers import analyze_codebase

# Analyze entire codebase
results = analyze_codebase(codebase_graph)

# Results by language
python_results = results.get('python')
js_results = results.get('javascript')
```

### Custom Analyzer Registration
```python
from wtf_codebot.analyzers import register_analyzer

# Register custom analyzer
register_analyzer('rust', CustomRustAnalyzer())
```

## Configuration

### Rule Management
Each analyzer supports rule enabling/disabling:
```python
analyzer = PythonAnalyzer()
analyzer.enable_rule('singleton_detection')
analyzer.disable_rule('magic_numbers')
```

### Linter Configuration
External linter configurations can be specified:
```python
analyzer.linter_config = "/path/to/pylint.rc"
```

## Pattern Detection Details

### Design Patterns Detected

1. **Singleton Pattern** (Python):
   - Detects `__new__` method with conditional instance creation
   - Identifies class-level instance storage

2. **Factory Method Pattern** (Python):
   - Functions with factory naming conventions
   - Conditional return types based on parameters

3. **Observer Pattern** (Python):
   - Classes with observer lists and notification methods
   - Add/remove observer functionality

### Anti-Patterns Detected

1. **God Class**:
   - Classes with excessive methods or attributes
   - Configurable thresholds

2. **Callback Hell** (JavaScript):
   - Deeply nested callback functions
   - Based on indentation analysis

3. **Promise Hell** (JavaScript):
   - Long chains of .then() calls
   - Missing error handling

### Code Smells Detected

1. **Long Methods**:
   - Functions exceeding line count thresholds
   - Language-specific counting rules

2. **Deep Nesting**:
   - Control structures nested beyond threshold
   - Recursive depth calculation

3. **Magic Numbers**:
   - Numeric literals without named constants
   - Excludes common values (0, 1, 100, etc.)

4. **Unused Variables**:
   - Variables declared but never referenced
   - Simple heuristic-based detection

5. **Duplicate Code**:
   - Similar function structures
   - AST-based comparison for Python

## Metrics Collected

### Code Quality Metrics
- Lines of code (various counting methods)
- Cyclomatic complexity (simplified calculation)
- Function/class/variable counts
- Import dependency counts

### Language-Specific Metrics
- **Python**: AST-based accurate counting
- **JavaScript**: Regex-based pattern matching

## Extensibility

### Adding New Languages
1. Create analyzer class extending `BaseAnalyzer` or `LinterBasedAnalyzer`
2. Implement required abstract methods
3. Define supported file extensions
4. Register with the global registry

### Adding New Patterns
1. Implement detection method in relevant analyzer
2. Add to `_detect_custom_patterns()` method
3. Use appropriate pattern type and severity

### Adding New Metrics
1. Implement calculation method
2. Add to `_calculate_metrics()` method
3. Use descriptive names and units

## Testing

The implementation includes a comprehensive demo script (`demo_analyzers.py`) that:
- Tests both Python and JavaScript analyzers
- Uses realistic code samples with known patterns
- Demonstrates various finding types and metrics
- Shows registry functionality

## Performance Considerations

- External linters run with 30-second timeouts
- AST parsing includes syntax error handling
- Regex-based fallbacks for parsing failures
- Configurable rule sets to reduce analysis time

## Dependencies

- **Python**: Built-in `ast` module, optional `pylint`
- **JavaScript**: Optional `eslint`
- **Core**: `subprocess`, `json`, `re`, `logging`

## Future Enhancements

1. **Additional Languages**: TypeScript (enhanced), Java, C#, Go, Rust
2. **More Patterns**: Decorator, Strategy, Adapter, MVC violations
3. **Advanced Metrics**: Halstead complexity, maintainability index
4. **Integration**: CI/CD pipeline integration, IDE plugins
5. **Visualization**: Pattern relationship graphs, trend analysis
