# Changelog

All notable changes to WTF CodeBot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enhanced security analysis with compliance reporting
- Machine learning-based pattern recognition improvements
- IDE plugins for VSCode and IntelliJ
- Advanced dependency vulnerability tracking

### Changed
- Improved performance for large codebases
- Enhanced AI prompts for better analysis accuracy

### Fixed
- Memory optimization for processing large files
- Better error handling for network timeouts

## [0.1.0] - 2024-01-15

### Added
- **Core Analysis Engine**
  - Multi-language static analysis (Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP, Swift, Kotlin, Scala)
  - AI-powered code analysis using Anthropic's Claude
  - Advanced pattern recognition with confidence scoring
  - Comprehensive findings system with unified reporting
  - Technical debt quantification with business impact assessment

- **CLI Interfaces**
  - Click-based CLI (wtf-codebot) - Original implementation
  - Typer-based CLI (wtf-codebot-typer) - Enhanced with rich output
  - Argparse-based CLI (wtf-codebot-argparse) - Traditional interface
  - Dependency analysis CLI (wtf-codebot-deps)

- **Output Formats**
  - Console output with rich formatting and progress bars
  - JSON reports with enhanced schema v2.0.0
  - Interactive HTML reports with charts and filtering
  - SARIF format for CI/CD integration
  - Markdown, CSV, and YAML formats
  - Enhanced JSON schema with metadata, patterns, and remediation

- **Discovery and Parsing**
  - File system scanner with smart filtering
  - Language-specific parsers using Tree-sitter
  - Support for Python, JavaScript, TypeScript, HTML, CSS, JSON, YAML, Markdown
  - Configurable file inclusion/exclusion patterns

- **Pattern Recognition**
  - AI-powered pattern detection (God Object, Singleton, etc.)
  - Pattern confidence scoring and evidence collection
  - Cost tracking for API usage
  - Batch processing for efficient analysis

- **Performance Optimization**
  - SQLite-based caching for incremental analysis
  - Parallel processing with configurable worker count
  - Performance profiling and benchmarking
  - Memory optimization for large codebases

- **Integration Support**
  - GitHub Issues integration for critical findings
  - JIRA integration for ticket creation
  - Slack notifications via webhooks
  - Generic webhook support for custom integrations
  - CI/CD ready with GitHub Actions, GitLab CI, Jenkins examples

- **Security Analysis**
  - CWE (Common Weakness Enumeration) mapping
  - OWASP Top 10 categorization
  - Compliance violation tracking (PCI-DSS, SOX, HIPAA)
  - Security risk assessment and scoring

- **Quality Metrics**
  - Code quality scoring and grading (A-F)
  - Technical debt quantification
  - Multi-dimensional impact analysis
  - Business impact categorization

- **Configuration System**
  - YAML configuration file support
  - Environment variable configuration
  - CLI argument overrides
  - Flexible analysis depth settings (basic, standard, deep, comprehensive)

- **Docker Support**
  - Multi-stage Dockerfile for optimized images
  - Docker Compose for development and production
  - Health checks and security best practices
  - Development and CI/CD service configurations

- **Documentation**
  - Comprehensive README with usage examples
  - CLI usage guide with all three interfaces
  - Architecture documentation
  - Contributing guidelines
  - Performance optimization guide
  - Integration examples for CI/CD platforms

- **Development Tools**
  - Pre-commit hooks for code quality
  - Comprehensive test suite with coverage reporting
  - Code formatting with Black and isort
  - Linting with flake8 and mypy
  - Security scanning with bandit
  - Dependency vulnerability checking with safety

### Technical Features
- **Enhanced JSON Schema v2.0.0**
  - Comprehensive metadata with tool info and environment details
  - Pattern recognition data with confidence scores
  - Detailed remediation suggestions with step-by-step instructions
  - Security mappings (CWE, OWASP, compliance)
  - Quality metrics and technical debt scoring
  - Risk assessment framework

- **Findings Management**
  - Unified finding models across all analyzers
  - Finding aggregation and deduplication
  - Severity classification (Critical, High, Medium, Low, Info)
  - Type categorization (Security, Code Smell, Anti-pattern, etc.)

- **Performance Benchmarks**
  - Tested on codebases from 100 to 10,000+ files
  - Analysis time from 30 seconds to 60 minutes
  - Memory usage optimization
  - Cache benefits up to 80% performance improvement

### Dependencies
- **Core Dependencies**
  - Python 3.8.1+
  - Anthropic Claude API client
  - Rich for terminal output
  - Click/Typer for CLI interfaces
  - Pydantic for data validation
  - PyYAML for configuration
  - Tree-sitter for language parsing
  - BeautifulSoup4 for HTML parsing
  - structlog for structured logging

- **Development Dependencies**
  - pytest with coverage and async support
  - Black and isort for code formatting
  - flake8 and mypy for linting and type checking
  - bandit for security scanning
  - safety for dependency vulnerability checking
  - pre-commit for git hooks
  - Sphinx and MkDocs for documentation

### Supported Languages
- Python (.py)
- JavaScript (.js)
- TypeScript (.ts)
- Java (.java)
- C/C++ (.c, .cpp, .h, .hpp)
- Go (.go)
- Rust (.rs)
- Ruby (.rb)
- PHP (.php)
- Swift (.swift)
- Kotlin (.kt)
- Scala (.scala)
- HTML (.html)
- CSS (.css)
- JSON (.json)
- YAML (.yml, .yaml)
- Markdown (.md)

### Security
- Non-root user execution in Docker
- Secure defaults for all configuration options
- Input validation and sanitization
- API key protection and environment variable support
- Security scanning of dependencies

### Performance
- **Small projects** (< 100 files): 30-60 seconds, < 200MB memory
- **Medium projects** (< 1K files): 2-5 minutes, 200-500MB memory
- **Large projects** (< 10K files): 10-20 minutes, 500MB-1GB memory
- **Enterprise projects** (> 10K files): 30-60 minutes, 1-2GB memory
- **Cache benefits**: 40-80% faster on subsequent runs

### Known Limitations
- Requires Anthropic API key for AI-powered analysis
- Large files (> 1MB) are skipped by default
- Network connectivity required for API calls
- Memory usage scales with codebase size

### Installation
- Available via PyPI: `pip install wtf-codebot`
- Docker images: `wtfcodebot/wtf-codebot:latest`
- Source installation with Poetry

[Unreleased]: https://github.com/your-org/wtf-codebot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/wtf-codebot/releases/tag/v0.1.0
