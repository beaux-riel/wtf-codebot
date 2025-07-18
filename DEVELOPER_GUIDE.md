# Developer Guide

This guide provides comprehensive information for developers working on WTF CodeBot.

## 🏗️ Architecture Overview

WTF CodeBot follows a modular, plugin-based architecture designed for extensibility and maintainability.

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  CLI Interfaces │────│  Core Engine    │────│  Analysis APIs  │
│  (Click/Typer)  │    │  (Orchestrator) │    │  (Anthropic)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Configuration  │    │  Discovery      │    │  Pattern        │
│  Management     │    │  & Parsing      │    │  Recognition    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Static         │    │  Findings       │    │  Integration    │
│  Analyzers      │    │  Management     │    │  Services       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Performance    │    │  Reporting      │    │  Caching        │
│  Optimization   │    │  Engine         │    │  System         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Data Flow

1. **Input Processing**: CLI parses arguments and loads configuration
2. **Discovery**: File system scanner finds relevant source files
3. **Parsing**: Language-specific parsers extract code structure
4. **Analysis**: Multiple analyzers process the parsed code
5. **Pattern Recognition**: AI analyzes patterns and anti-patterns
6. **Findings Aggregation**: Results are unified and deduplicated
7. **Reporting**: Multiple output formats are generated
8. **Integration**: Results are sent to external services

## 🔧 Development Setup

### Prerequisites

- **Python**: 3.8.1 or higher
- **Poetry**: Latest version for dependency management
- **Git**: For version control
- **Docker**: Optional, for containerized testing
- **Anthropic API Key**: Required for AI analysis features

### Installation

```bash
# Clone the repository
git clone https://github.com/beaux-riel/wtf-codebot.git
cd wtf-codebot

# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install --with dev

# Install pre-commit hooks
poetry run pre-commit install

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys and preferences
```

### Project Structure

```
wtf-codebot/
├── wtf_codebot/              # Main package
│   ├── cli/                  # Command-line interfaces
│   ├── core/                 # Core system components
│   ├── analyzers/            # Static analysis engines
│   ├── discovery/            # File discovery and parsing
│   ├── findings/             # Findings management
│   ├── pattern_recognition/  # AI-powered pattern analysis
│   ├── performance/          # Performance optimization
│   ├── reporters/            # Output format handlers
│   ├── integrations/         # External service integrations
│   └── utils/                # Utility functions
├── tests/                    # Test suite
├── docs/                     # Documentation
├── templates/                # HTML report templates
├── scripts/                  # Utility scripts
├── .github/                  # GitHub Actions workflows
└── docker/                   # Docker configurations
```

## 🏃 Running the Application

### Development Mode

```bash
# Run with Poetry
poetry run wtf-codebot --help

# Run different CLI variants
poetry run wtf-codebot-typer --help
poetry run wtf-codebot-argparse --help

# Run specific modules
poetry run python -m wtf_codebot.cli.main --help
```

### Testing

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=wtf_codebot --cov-report=html

# Run specific test categories
poetry run pytest tests/unit/
poetry run pytest tests/integration/
poetry run pytest -m "not slow"  # Skip slow tests

# Run performance tests
poetry run pytest tests/performance/

# Run with debugging
poetry run pytest -v -s --tb=short
```

### Code Quality

```bash
# Format code
poetry run black wtf_codebot/ tests/
poetry run isort wtf_codebot/ tests/

# Lint code
poetry run flake8 wtf_codebot/
poetry run mypy wtf_codebot/

# Security scanning
poetry run bandit -r wtf_codebot/
poetry run safety check

# Run all quality checks
poetry run pre-commit run --all-files
```

## 🧩 Adding New Components

### Adding a New Language Analyzer

1. **Create the analyzer class**:

```python
# wtf_codebot/analyzers/java_analyzer.py
from typing import List
from .base import BaseAnalyzer
from ..findings.models import Finding, FindingSeverity

class JavaAnalyzer(BaseAnalyzer):
    """Analyzer for Java source code."""

    supported_extensions = ['.java']

    def analyze(self, file_content: str, file_path: str) -> List[Finding]:
        """Analyze Java code for issues."""
        findings = []

        # Implement Java-specific analysis logic
        if 'System.out.println' in file_content:
            findings.append(Finding(
                id='java-debug-print',
                title='Debug print statement found',
                severity=FindingSeverity.LOW,
                file_path=file_path,
                line_number=self._find_line_number(file_content, 'System.out.println'),
                description='Debug print statements should be removed in production code.'
            ))

        return findings
```

2. **Register the analyzer**:

```python
# wtf_codebot/analyzers/registry.py
from .java_analyzer import JavaAnalyzer

ANALYZERS = {
    # ... existing analyzers
    'java': JavaAnalyzer,
}
```

3. **Add tests**:

```python
# tests/analyzers/test_java_analyzer.py
import pytest
from wtf_codebot.analyzers.java_analyzer import JavaAnalyzer

class TestJavaAnalyzer:
    def setup_method(self):
        self.analyzer = JavaAnalyzer()

    def test_detects_debug_prints(self):
        code = '''
        public class HelloWorld {
            public static void main(String[] args) {
                System.out.println("Hello, World!");
            }
        }
        '''
        findings = self.analyzer.analyze(code, 'HelloWorld.java')
        assert len(findings) == 1
        assert findings[0].id == 'java-debug-print'
```

### Adding a New Output Format

1. **Create the reporter**:

```python
# wtf_codebot/reporters/xml_reporter.py
from typing import List
import xml.etree.ElementTree as ET
from ..findings.models import Finding

class XMLReporter:
    """Generate XML reports from findings."""

    def generate_report(self, findings: List[Finding], output_path: str) -> None:
        """Generate XML report."""
        root = ET.Element('analysis_report')

        for finding in findings:
            finding_elem = ET.SubElement(root, 'finding')
            finding_elem.set('id', finding.id)
            finding_elem.set('severity', finding.severity.value)

            title_elem = ET.SubElement(finding_elem, 'title')
            title_elem.text = finding.title

            # Add more elements as needed

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
```

2. **Integrate with CLI**:

```python
# In CLI handler
if output_format == 'xml':
    from wtf_codebot.reporters.xml_reporter import XMLReporter
    reporter = XMLReporter()
    reporter.generate_report(findings, output_path)
```

### Adding a New Integration

1. **Create the integration**:

```python
# wtf_codebot/integrations/teams.py
from typing import List, Dict, Any
import requests
from .base import BaseIntegration
from ..findings.models import Finding

class TeamsIntegration(BaseIntegration):
    """Integration with Microsoft Teams."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_findings(self, findings: List[Finding]) -> bool:
        """Send findings to Teams channel."""
        try:
            message = self._format_message(findings)
            response = requests.post(self.webhook_url, json=message)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Failed to send to Teams: {e}")
            return False

    def _format_message(self, findings: List[Finding]) -> Dict[str, Any]:
        """Format findings as Teams message."""
        # Implementation here
        pass
```

2. **Register and configure**:

```python
# In configuration
if config.integrations.teams_enabled:
    teams = TeamsIntegration(config.integrations.teams_webhook_url)
    teams.send_findings(critical_findings)
```

## 🎯 Testing Strategy

### Test Categories

1. **Unit Tests**: Fast, isolated tests for individual components
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Benchmark and performance validation
5. **Security Tests**: Security vulnerability testing

### Test Organization

```
tests/
├── unit/                    # Unit tests
│   ├── analyzers/
│   ├── discovery/
│   ├── findings/
│   └── reporters/
├── integration/             # Integration tests
│   ├── cli/
│   ├── api/
│   └── workflows/
├── e2e/                     # End-to-end tests
├── performance/             # Performance tests
├── security/                # Security tests
├── fixtures/                # Test data and fixtures
└── conftest.py             # Pytest configuration
```

### Writing Good Tests

```python
import pytest
from unittest.mock import Mock, patch
from wtf_codebot.analyzers.python_analyzer import PythonAnalyzer

class TestPythonAnalyzer:
    """Test suite for Python analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        return PythonAnalyzer()

    @pytest.fixture
    def sample_code(self):
        """Sample Python code for testing."""
        return '''
def divide(a, b):
    return a / b  # Potential division by zero
        '''

    def test_detects_division_by_zero(self, analyzer, sample_code):
        """Test detection of potential division by zero."""
        findings = analyzer.analyze(sample_code, 'test.py')

        assert len(findings) > 0
        division_findings = [f for f in findings if 'division' in f.id.lower()]
        assert len(division_findings) == 1

    @patch('wtf_codebot.analyzers.python_analyzer.tree_sitter_parse')
    def test_handles_parse_errors(self, mock_parse, analyzer):
        """Test graceful handling of parse errors."""
        mock_parse.side_effect = Exception("Parse error")

        findings = analyzer.analyze("invalid python code", "test.py")
        assert findings == []  # Should not crash

    @pytest.mark.slow
    def test_performance_with_large_file(self, analyzer):
        """Test performance with large files."""
        large_code = "def func():\n    pass\n" * 10000

        import time
        start = time.time()
        findings = analyzer.analyze(large_code, "large.py")
        duration = time.time() - start

        assert duration < 10.0  # Should complete within 10 seconds
```

## 🎨 Code Style Guide

### Python Code Style

We follow PEP 8 with some modifications:

```python
# Good: Clear, documented function with type hints
def analyze_code_quality(
    file_path: str,
    options: AnalysisOptions,
    cache: Optional[Cache] = None
) -> Tuple[List[Finding], AnalysisMetrics]:
    """Analyze code quality for a given file.

    Args:
        file_path: Path to the source code file
        options: Configuration options for analysis
        cache: Optional cache for performance optimization

    Returns:
        Tuple of findings list and analysis metrics

    Raises:
        FileNotFoundError: If file doesn't exist
        AnalysisError: If analysis fails
    """
    if not file_path or not options:
        raise ValueError("file_path and options are required")

    try:
        # Implementation here
        return findings, metrics
    except Exception as e:
        logger.error(f"Analysis failed for {file_path}: {e}")
        raise AnalysisError(f"Failed to analyze {file_path}") from e
```

### Error Handling

```python
# Good: Specific exceptions with context
class AnalysisError(Exception):
    """Raised when code analysis fails."""
    pass

def analyze_file(file_path: str) -> List[Finding]:
    """Analyze a source file."""
    try:
        content = read_file(file_path)
        return analyze_content(content, file_path)
    except FileNotFoundError:
        logger.warning(f"File not found: {file_path}")
        return []
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error analyzing {file_path}: {e}")
        raise AnalysisError(f"Failed to analyze {file_path}") from e
```

### Logging

```python
import structlog

logger = structlog.get_logger(__name__)

def process_findings(findings: List[Finding]) -> None:
    """Process analysis findings."""
    logger.info(
        "Processing findings",
        finding_count=len(findings),
        critical_count=len([f for f in findings if f.severity == FindingSeverity.CRITICAL])
    )

    for finding in findings:
        logger.debug(
            "Processing finding",
            finding_id=finding.id,
            severity=finding.severity.value,
            file_path=finding.file_path
        )
```

## 🚀 Performance Guidelines

### Optimization Strategies

1. **Use caching** for expensive operations
2. **Implement parallel processing** for independent tasks
3. **Stream large files** instead of loading into memory
4. **Profile code** to identify bottlenecks
5. **Use appropriate data structures** for the task

### Example: Efficient File Processing

```python
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Iterator, List
import asyncio

class EfficientFileProcessor:
    """Efficiently process multiple files."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers

    def process_files_parallel(self, file_paths: List[str]) -> List[Finding]:
        """Process files in parallel using threads."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.analyze_file, path) for path in file_paths]
            results = [future.result() for future in futures]

        # Flatten results
        return [finding for result in results for finding in result]

    def process_files_streaming(self, file_paths: Iterator[str]) -> Iterator[Finding]:
        """Stream process files to minimize memory usage."""
        for file_path in file_paths:
            try:
                findings = self.analyze_file(file_path)
                yield from findings
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                continue
```

### Memory Management

```python
def analyze_large_file(file_path: str, chunk_size: int = 8192) -> List[Finding]:
    """Analyze large files in chunks to manage memory."""
    findings = []

    with open(file_path, 'r', encoding='utf-8') as f:
        line_number = 0
        while chunk := f.read(chunk_size):
            chunk_findings = analyze_chunk(chunk, line_number)
            findings.extend(chunk_findings)
            line_number += chunk.count('\n')

    return findings
```

## 🔒 Security Guidelines

### Input Validation

```python
from pathlib import Path
import re

def validate_file_path(file_path: str) -> str:
    """Validate and sanitize file path."""
    if not file_path:
        raise ValueError("File path cannot be empty")

    # Resolve path and check for directory traversal
    resolved_path = Path(file_path).resolve()

    # Ensure path is within allowed directories
    allowed_dirs = [Path.cwd(), Path.home() / 'projects']
    if not any(str(resolved_path).startswith(str(allowed_dir)) for allowed_dir in allowed_dirs):
        raise ValueError(f"File path not allowed: {file_path}")

    return str(resolved_path)

def validate_api_key(api_key: str) -> str:
    """Validate API key format."""
    if not api_key:
        raise ValueError("API key is required")

    if not re.match(r'^sk-ant-[a-zA-Z0-9_-]+$', api_key):
        raise ValueError("Invalid API key format")

    return api_key
```

### Secure Configuration

```python
import os
from typing import Optional

class SecureConfig:
    """Secure configuration management."""

    def __init__(self):
        self._secrets = {}

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from environment variables."""
        value = os.getenv(key, default)
        if value:
            # Don't log secret values
            logger.debug(f"Retrieved secret for key: {key}")
        return value

    def validate_secrets(self) -> None:
        """Validate that required secrets are present."""
        required_secrets = ['ANTHROPIC_API_KEY']
        missing_secrets = [key for key in required_secrets if not self.get_secret(key)]

        if missing_secrets:
            raise ValueError(f"Missing required secrets: {missing_secrets}")
```

## 📊 Monitoring and Debugging

### Logging Configuration

```python
import structlog
import logging

def setup_logging(level: str = "INFO", format: str = "json") -> None:
    """Set up structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s" if format == "json" else "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
```

### Performance Profiling

```python
import cProfile
import pstats
from functools import wraps
import time

def profile_performance(func):
    """Decorator to profile function performance."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()

        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        profiler.disable()

        # Log performance metrics
        logger.info(
            "Function performance",
            function=func.__name__,
            duration=end_time - start_time,
            args_count=len(args),
            kwargs_count=len(kwargs)
        )

        # Optionally save detailed profile
        if os.getenv('PROFILE_DETAILED'):
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumulative')
            stats.dump_stats(f'{func.__name__}_profile.stats')

        return result
    return wrapper
```

## 🔄 CI/CD Integration

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ["-r", "wtf_codebot/"]
```

### Quality Gates

```python
# scripts/quality_check.py
"""Quality gate checks for CI/CD."""

import subprocess
import sys
from typing import List, Tuple

def run_command(cmd: List[str]) -> Tuple[int, str]:
    """Run a command and return exit code and output."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr

def check_test_coverage(min_coverage: float = 80.0) -> bool:
    """Check if test coverage meets minimum threshold."""
    exit_code, output = run_command(['poetry', 'run', 'pytest', '--cov-report=term-missing', '--cov=wtf_codebot'])

    if exit_code != 0:
        print(f"Tests failed: {output}")
        return False

    # Parse coverage from output
    for line in output.split('\n'):
        if 'TOTAL' in line and '%' in line:
            coverage_str = line.split()[-1].replace('%', '')
            coverage = float(coverage_str)
            if coverage < min_coverage:
                print(f"Coverage {coverage}% below minimum {min_coverage}%")
                return False
            break

    return True

def main():
    """Run all quality checks."""
    checks = [
        (check_test_coverage, "Test coverage"),
        # Add more checks as needed
    ]

    failed_checks = []
    for check_func, check_name in checks:
        if not check_func():
            failed_checks.append(check_name)

    if failed_checks:
        print(f"Quality checks failed: {', '.join(failed_checks)}")
        sys.exit(1)

    print("All quality checks passed!")

if __name__ == '__main__':
    main()
```

## 📚 Documentation

### API Documentation

Use Google-style docstrings for all public APIs:

```python
def analyze_codebase(
    directory: str,
    config: AnalysisConfig,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> AnalysisResult:
    """Analyze an entire codebase for issues and patterns.

    This function performs a comprehensive analysis of all supported
    source files in the given directory and its subdirectories.

    Args:
        directory: Path to the root directory to analyze
        config: Configuration object specifying analysis parameters
        progress_callback: Optional callback function called with (current, total)
                          to report progress. Default is None.

    Returns:
        AnalysisResult object containing all findings and metadata

    Raises:
        DirectoryNotFoundError: If the specified directory doesn't exist
        PermissionError: If unable to read files in the directory
        AnalysisError: If analysis fails due to configuration or processing errors

    Example:
        >>> config = AnalysisConfig(depth='standard', include_tests=True)
        >>> result = analyze_codebase('/path/to/project', config)
        >>> print(f"Found {len(result.findings)} issues")
        Found 42 issues

    Note:
        Large codebases may take significant time to analyze. Consider
        using the progress_callback to provide user feedback.
    """
```

### README Updates

Keep README.md comprehensive and up-to-date:

1. **Features**: Update when adding new capabilities
2. **Installation**: Update for new dependencies or installation methods
3. **Usage Examples**: Add examples for new features
4. **Configuration**: Document new configuration options
5. **Performance**: Update benchmark data

## 🎁 Release Process

### Version Management

```bash
# Update version in pyproject.toml and __init__.py
poetry version patch  # or minor/major

# Update CHANGELOG.md with new features and fixes

# Commit changes
git add .
git commit -m "Bump version to $(poetry version -s)"

# Create and push tag
git tag -a v$(poetry version -s) -m "Release v$(poetry version -s)"
git push origin main --tags
```

### Release Checklist

- [ ] All tests pass
- [ ] Code coverage meets threshold
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Version is bumped
- [ ] Security scan passes
- [ ] Performance benchmarks run
- [ ] Docker image builds successfully

### Automated Release

The GitHub Actions workflow handles automatic releases when tags are pushed:

1. **Build and test** on multiple platforms
2. **Security scanning** with Trivy
3. **Docker image** build and push
4. **PyPI package** build and publish
5. **GitHub release** creation with notes

---

For more information, see the [CONTRIBUTING.md](CONTRIBUTING.md) guide or reach out to the development team.
