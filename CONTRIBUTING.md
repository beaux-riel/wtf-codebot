# Contributing to WTF CodeBot

Thank you for your interest in contributing to WTF CodeBot! This document provides guidelines and information for contributors.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/wtf-codebot.git
   cd wtf-codebot
   ```
3. **Set up development environment**:
   ```bash
   poetry install --with dev
   poetry run pre-commit install
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. **Make your changes** and commit them
6. **Run tests** and ensure they pass
7. **Push to your fork** and create a Pull Request

## 🛠️ Development Environment

### Prerequisites

- Python 3.8+ 
- Poetry for dependency management
- Git for version control
- Docker (optional, for testing containerized features)

### Setup

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Clone and setup the project
git clone https://github.com/your-username/wtf-codebot.git
cd wtf-codebot

# Install dependencies including development tools
poetry install --with dev

# Install pre-commit hooks for code quality
poetry run pre-commit install

# Set up environment variables for testing
cp .env.example .env
# Edit .env with your Anthropic API key for testing
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=wtf_codebot --cov-report=html --cov-report=term

# Run specific test files
poetry run pytest tests/test_performance.py

# Run tests with verbose output
poetry run pytest -v

# Run only fast tests (excluding slow integration tests)
poetry run pytest -m "not slow"
```

### Code Quality Tools

We use several tools to maintain code quality:

```bash
# Format code
poetry run black wtf_codebot/ tests/
poetry run isort wtf_codebot/ tests/

# Lint code
poetry run flake8 wtf_codebot/
poetry run mypy wtf_codebot/

# Security scan
poetry run bandit -r wtf_codebot/

# Check dependencies for vulnerabilities
poetry run safety check

# Run all quality checks
poetry run pre-commit run --all-files
```

## 📋 Types of Contributions

### 🔍 New Language Analyzers

We welcome analyzers for new programming languages. To add a new language analyzer:

1. **Create the analyzer** in `wtf_codebot/analyzers/`:
   ```python
   # wtf_codebot/analyzers/new_language_analyzer.py
   from .base import BaseAnalyzer
   
   class NewLanguageAnalyzer(BaseAnalyzer):
       def analyze(self, file_content: str, file_path: str) -> List[Finding]:
           # Implementation here
           pass
   ```

2. **Register the analyzer** in `wtf_codebot/analyzers/registry.py`

3. **Add language-specific patterns** if needed

4. **Write comprehensive tests**

5. **Update documentation**

### 🎨 New Output Formats

To add a new output format:

1. **Create a reporter** in `wtf_codebot/reporters/`
2. **Implement the base reporter interface**
3. **Add format option to CLI**
4. **Add tests and documentation**

### 🔗 New Integrations

For external service integrations:

1. **Create integration** in `wtf_codebot/integrations/`
2. **Follow the base integration pattern**
3. **Add configuration options**
4. **Include authentication handling**
5. **Add comprehensive tests**

### 📊 Enhanced Reporting

For improving reports and visualizations:

1. **Update HTML templates** in `templates/`
2. **Enhance JSON schema** if needed
3. **Add new chart types or visualizations**
4. **Ensure responsive design**

## 🎯 Pull Request Guidelines

### Before Submitting

- [ ] Tests pass: `poetry run pytest`
- [ ] Code is formatted: `poetry run black . && poetry run isort .`
- [ ] Linting passes: `poetry run flake8 wtf_codebot/`
- [ ] Type checking passes: `poetry run mypy wtf_codebot/`
- [ ] Security scan clean: `poetry run bandit -r wtf_codebot/`
- [ ] Documentation updated if needed
- [ ] CHANGELOG updated for user-facing changes

### PR Description Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Added tests for new functionality
- [ ] All tests pass
- [ ] Tested manually with sample projects

## Documentation
- [ ] Updated README if needed
- [ ] Updated CLI help text if needed
- [ ] Added/updated docstrings

## Screenshots (if applicable)
Add screenshots for UI changes.

## Checklist
- [ ] My code follows the code style of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **Performance Tests**: Test performance characteristics
4. **CLI Tests**: Test command-line interfaces
5. **End-to-End Tests**: Test complete workflows

### Writing Tests

```python
# Example test structure
import pytest
from wtf_codebot.analyzers.python_analyzer import PythonAnalyzer

class TestPythonAnalyzer:
    def setup_method(self):
        self.analyzer = PythonAnalyzer()
    
    def test_analyze_simple_function(self):
        code = """
        def hello_world():
            print("Hello, World!")
        """
        findings = self.analyzer.analyze(code, "test.py")
        assert len(findings) == 0  # No issues expected
    
    @pytest.mark.slow
    def test_analyze_large_file(self):
        # Test with large files (marked as slow)
        pass
```

### Test Data

- Use realistic test data when possible
- Create fixtures for common test scenarios
- Mock external APIs and services
- Use parametrized tests for multiple scenarios

## 📝 Documentation Guidelines

### Code Documentation

- **Docstrings**: Use Google-style docstrings for all public functions and classes
- **Type hints**: Include type hints for all function parameters and return values
- **Comments**: Add comments for complex logic, not obvious code

```python
def analyze_code(file_path: str, options: AnalysisOptions) -> List[Finding]:
    """Analyze a source code file for issues and patterns.
    
    Args:
        file_path: Path to the source code file to analyze
        options: Configuration options for the analysis
    
    Returns:
        List of findings discovered during analysis
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist
        AnalysisError: If analysis fails due to invalid code
    """
    # Implementation here
    pass
```

### User Documentation

- **README**: Keep README.md up to date with new features
- **CLI Help**: Update help text for new commands and options
- **Examples**: Provide realistic examples for new features
- **Guides**: Create guides for complex features

## 🔒 Security Considerations

### Security Guidelines

1. **Never commit secrets** or API keys
2. **Validate all inputs** to prevent injection attacks
3. **Use secure defaults** for configuration options
4. **Handle errors gracefully** without exposing sensitive information
5. **Follow OWASP guidelines** for web-related features

### Security Review Process

All changes involving:
- External API calls
- File system operations
- User input handling
- Dependency updates

Will undergo additional security review.

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment information**:
   - OS and version
   - Python version
   - WTF CodeBot version
   - Relevant dependencies

2. **Steps to reproduce**:
   - Exact commands run
   - Input files or code samples
   - Configuration used

3. **Expected vs actual behavior**

4. **Error messages and logs**

5. **Additional context**

## 💡 Feature Requests

For feature requests, please provide:

1. **Use case description**: What problem does this solve?
2. **Proposed solution**: How should it work?
3. **Alternatives considered**: What other approaches were considered?
4. **Additional context**: Examples, mockups, etc.

## 🎖️ Recognition

Contributors will be recognized in:

- CHANGELOG for their contributions
- README contributors section
- GitHub releases notes
- Project documentation

## 📞 Getting Help

- **GitHub Discussions**: For questions and community discussion
- **GitHub Issues**: For bug reports and feature requests
- **Discord** (coming soon): For real-time chat
- **Email**: For security-related issues only

## 📜 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code.

### Our Standards

- **Be respectful** and inclusive
- **Be collaborative** and helpful
- **Be patient** with newcomers
- **Be constructive** in feedback
- **Focus on what's best** for the community

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

## 🚀 Release Process

For maintainers, the release process:

1. **Update version** in `pyproject.toml` and `__init__.py`
2. **Update CHANGELOG** with new features and fixes
3. **Create release PR** and get approval
4. **Tag release**: `git tag -a v0.1.1 -m "Release v0.1.1"`
5. **Push tag**: `git push origin v0.1.1`
6. **GitHub Actions** will automatically:
   - Build and test the package
   - Publish to PyPI
   - Build and push Docker image
   - Create GitHub release

## 📚 Additional Resources

- **Architecture Documentation**: See `docs/architecture.md`
- **API Documentation**: Generated from docstrings
- **Performance Guide**: See `docs/performance.md`
- **Integration Guide**: See `docs/integrations.md`

---

Thank you for contributing to WTF CodeBot! Your contributions help make code analysis better for everyone. 🎉
