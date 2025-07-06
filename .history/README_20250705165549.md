# WTF CodeBot 🤖

[![PyPI version](https://badge.fury.io/py/wtf-codebot.svg)](https://badge.fury.io/py/wtf-codebot)
[![Docker Image](https://img.shields.io/docker/v/wtfcodebot/wtf-codebot?label=docker)](https://hub.docker.com/r/wtfcodebot/wtf-codebot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

An AI-powered code analysis and review tool that helps you understand, analyze, and improve your codebase using advanced static analysis, pattern recognition, and AI-driven insights.

## ✨ Key Features

### Core Analysis
- 🤖 **AI-powered analysis** using Anthropic's Claude with advanced prompt engineering
- 🔍 **Multi-language support** (Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby, PHP, Swift, Kotlin, Scala)
- 🎯 **Advanced pattern recognition** with confidence scoring and evidence collection
- 📊 **Comprehensive findings system** with unified reporting across all analysis engines
- 🔧 **Dependency analysis** with vulnerability detection and license compliance
- 📝 **Technical debt quantification** with business impact assessment

### Output & Reporting
- 📋 **Multiple output formats**: Console, JSON, Markdown, HTML, CSV, SARIF, YAML
- 🎨 **Interactive HTML reports** with charts, tables, and filtering
- 📊 **Enhanced JSON schema** (v2.0.0) with metadata, patterns, and remediation
- 📈 **Performance benchmarking** with detailed metrics and optimization recommendations
- 🔒 **Security analysis** with CWE mapping, OWASP categorization, and compliance tracking

### Integration & Automation
- 🚀 **CI/CD integration** with GitHub Actions, GitLab CI, and Jenkins support
- 🔗 **Third-party integrations**: GitHub Issues, JIRA, Slack, Webhooks
- 🐳 **Docker support** for containerized analysis
- ⚙️ **Flexible configuration** via YAML files, environment variables, or CLI arguments
- 🎛️ **Multiple CLI interfaces** (Click, Typer, Argparse) for different use cases

### Performance & Scalability
- ⚡ **Parallel processing** with configurable batch sizes
- 💾 **Smart caching** with SQLite backend for incremental analysis
- 📏 **Configurable analysis depth** from basic to comprehensive
- 🎯 **Smart file filtering** with glob patterns and language-specific exclusions

## 🚀 Quick Start

### PyPI Installation (Recommended)

```bash
# Install from PyPI
pip install wtf-codebot

# Basic usage
wtf-codebot analyze /path/to/your/code --api-key your-anthropic-api-key
```

### Docker Installation

```bash
# Pull the Docker image
docker pull wtfcodebot/wtf-codebot:latest

# Run analysis
docker run -v $(pwd):/workspace wtfcodebot/wtf-codebot:latest analyze /workspace
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/your-org/wtf-codebot.git
cd wtf-codebot

# Using Poetry (recommended for development)
poetry install
poetry shell

# Using pip with virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

## Configuration

### Option 1: Configuration File

1. Copy the example configuration file:
   ```bash
   cp wtf-codebot.yaml.example wtf-codebot.yaml
   ```

2. Edit the configuration file and add your Anthropic API key:
   ```yaml
   anthropic_api_key: "your-actual-api-key-here"
   ```

### Option 2: Environment Variables

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file and add your API key:
   ```
   ANTHROPIC_API_KEY=your-actual-api-key-here
   ```

### Configuration Options

| Setting | Description | Default | Environment Variable |
|---------|-------------|---------|---------------------|
| `anthropic_api_key` | Anthropic API key (required) | - | `ANTHROPIC_API_KEY` |
| `anthropic_model` | Claude model to use | `claude-3-sonnet-20240229` | `ANTHROPIC_MODEL` |
| `output_format` | Output format | `console` | `WTF_CODEBOT_OUTPUT_FORMAT` |
| `verbose` | Enable verbose logging | `false` | `WTF_CODEBOT_VERBOSE` |
| `analysis.max_file_size` | Max file size (bytes) | `1048576` | `WTF_CODEBOT_MAX_FILE_SIZE` |
| `analysis.include_tests` | Include test files | `true` | `WTF_CODEBOT_INCLUDE_TESTS` |

## 📋 Usage Examples

### Basic Analysis

```bash
# Simple analysis of current directory
wtf-codebot analyze . --api-key your-api-key

# Analyze with verbose output
wtf-codebot analyze ./my-project --api-key your-api-key --verbose

# Quick dry run to test configuration
wtf-codebot analyze ./my-project --api-key your-api-key --dry-run
```

### Multi-Format Output

```bash
# Generate JSON and HTML reports
wtf-codebot analyze ./my-project \
  --api-key your-api-key \
  --export-json results.json \
  --export-html report.html

# Export to multiple formats with SARIF for CI/CD
wtf-codebot analyze ./my-project \
  --api-key your-api-key \
  --export-sarif security.sarif \
  --export-csv findings.csv
```

### Language-Specific Analysis

```bash
# Analyze only Python files
wtf-codebot-typer analyze ./my-project \
  --api-key your-api-key \
  --language python

# Multi-language analysis
wtf-codebot-typer analyze ./full-stack-project \
  --api-key your-api-key \
  --language python --language javascript --language typescript
```

### Advanced Filtering and Configuration

```bash
# Exclude specific directories and files
wtf-codebot analyze ./large-project \
  --api-key your-api-key \
  --exclude "**/node_modules/**" \
  --exclude "**/venv/**" \
  --exclude "**/.git/**" \
  --include "**/*.py" --include "**/*.js"

# Deep analysis with custom settings
wtf-codebot-typer analyze ./complex-project \
  --api-key your-api-key \
  --analysis-depth comprehensive \
  --batch-size 100 \
  --max-file-size 2097152
```

### Integration with External Services

```bash
# Create GitHub issues for critical findings
wtf-codebot analyze ./my-project \
  --api-key your-api-key \
  --github-issues \
  --github-repo owner/repository

# Send results to Slack
wtf-codebot analyze ./my-project \
  --api-key your-api-key \
  --slack-webhook https://hooks.slack.com/services/...

# Create JIRA tickets for high-priority issues
wtf-codebot analyze ./my-project \
  --api-key your-api-key \
  --jira-project PROJ
```

### Configuration Management

```bash
# Initialize configuration file
wtf-codebot init-config

# Use custom configuration
wtf-codebot analyze ./my-project --config my-config.yaml

# View current configuration
wtf-codebot config-info

# Save runtime configuration
wtf-codebot-typer analyze ./my-project \
  --api-key your-api-key \
  --save-config my-analysis-config.yaml
```

## 🔧 CLI Interfaces

WTF CodeBot provides three CLI implementations for different use cases:

- **`wtf-codebot`** - Click-based CLI (original)
- **`wtf-codebot-typer`** - Enhanced Typer-based CLI with rich output (recommended)
- **`wtf-codebot-argparse`** - Traditional argparse-based CLI

### Available Commands

```bash
# Analysis commands
wtf-codebot analyze [PATH]           # Analyze code
wtf-codebot init-config             # Initialize configuration
wtf-codebot config-info             # Show configuration
wtf-codebot version                 # Show version

# Specialized commands
wtf-codebot-deps analyze [PATH]     # Dependency analysis
```

### Command Line Options

#### Global Options
- `--config, -c`: Path to configuration file
- `--verbose, -v`: Enable verbose output
- `--dry-run`: Perform dry run without making changes
- `--api-key, -k`: Anthropic API key
- `--model, -m`: Anthropic model to use

#### Analysis Options
- `--output, -o`: Output file path
- `--format, -f`: Output format (console, json, markdown, html, yaml)
- `--language, -l`: Filter by programming language (repeatable)
- `--include, -i`: Include patterns (glob, repeatable)
- `--exclude, -x`: Exclude patterns (glob, repeatable)
- `--depth, -d`: Maximum directory depth (1-100)
- `--analysis-depth`: Analysis depth (basic, standard, deep, comprehensive)
- `--batch-size, -b`: Files per batch (1-1000)
- `--max-file-size`: Maximum file size to analyze
- `--include-tests/--exclude-tests`: Include/exclude test files
- `--include-hidden/--exclude-hidden`: Include/exclude hidden files
- `--follow-symlinks/--no-follow-symlinks`: Follow symbolic links

#### Export Options
- `--export-sarif`: Export to SARIF file
- `--export-html`: Export to HTML file
- `--export-csv`: Export to CSV file
- `--export-json`: Export to JSON file

#### Integration Options
- `--github-issues`: Create GitHub issues for critical findings
- `--github-repo`: GitHub repository (owner/repo)
- `--slack-webhook`: Slack webhook URL
- `--jira-project`: JIRA project key
- `--webhook-url`: Generic webhook URL

## 📋 Output Formats

WTF CodeBot supports multiple output formats for different use cases:

### Console Output
- **Rich formatted output** with colors and progress bars
- **Summary statistics** and finding counts
- **Interactive mode** with filtering options

### JSON Reports
- **Enhanced JSON schema v2.0.0** with comprehensive metadata
- **Pattern recognition data** with confidence scores
- **Remediation suggestions** with step-by-step instructions
- **Security mappings** (CWE, OWASP, compliance)
- **Quality metrics** and technical debt scoring

### HTML Reports
- **Interactive dashboards** with charts and tables
- **Filterable findings** by severity, type, and language
- **Dependency visualizations** with vulnerability tracking
- **Performance metrics** and optimization recommendations

### SARIF (Static Analysis Results Interchange Format)
- **Industry-standard format** for CI/CD integration
- **Security tool compatibility** (GitHub Security, SonarQube)
- **Automated vulnerability management**

### Other Formats
- **Markdown**: Human-readable reports for documentation
- **CSV**: Spreadsheet-compatible data for analysis
- **YAML**: Configuration-friendly structured data

## 🏠 Architecture

WTF CodeBot follows a modular architecture with clear separation of concerns:

```
wtf-codebot/
├── wtf_codebot/
│   ├── __init__.py
│   ├── cli/                    # Command-line interfaces
│   │   ├── main.py            # Click-based CLI
│   │   ├── enhanced_cli.py    # Typer-based CLI
│   │   ├── argparse_cli.py    # Argparse-based CLI
│   │   └── dependency_cli.py  # Dependency analysis CLI
│   ├── core/                  # Core system components
│   │   ├── config.py          # Configuration management
│   │   ├── logging.py         # Structured logging
│   │   └── exceptions.py      # Custom exceptions
│   ├── analyzers/             # Static analysis engines
│   │   ├── base.py            # Base analyzer interface
│   │   ├── python_analyzer.py # Python-specific analysis
│   │   ├── javascript_analyzer.py # JS/TS analysis
│   │   ├── dependency_analyzer.py # Dependency analysis
│   │   └── registry.py        # Analyzer registry
│   ├── discovery/             # Code discovery and parsing
│   │   ├── scanner.py         # File system scanner
│   │   ├── models.py          # Data models
│   │   └── parsers/           # Language-specific parsers
│   │       ├── python_parser.py
│   │       ├── javascript_parser.py
│   │       ├── typescript_parser.py
│   │       ├── html_parser.py
│   │       ├── css_parser.py
│   │       ├── json_parser.py
│   │       ├── yaml_parser.py
│   │       └── markdown_parser.py
│   ├── findings/              # Findings management system
│   │   ├── models.py          # Finding data models
│   │   ├── aggregator.py      # Finding aggregation
│   │   ├── deduplicator.py    # Duplicate removal
│   │   └── reporter.py        # Base reporting interface
│   ├── pattern_recognition/   # AI-powered pattern analysis
│   │   ├── orchestrator.py    # Pattern recognition orchestrator
│   │   ├── claude_client.py   # Anthropic Claude client
│   │   ├── patterns.py        # Pattern definitions
│   │   ├── batcher.py         # Batch processing
│   │   └── cost_tracker.py    # API cost tracking
│   ├── performance/           # Performance optimization
│   │   ├── cache.py           # SQLite-based caching
│   │   ├── parallel.py        # Parallel processing
│   │   ├── profiler.py        # Performance profiling
│   │   └── benchmarks.py      # Benchmark suite
│   ├── reporters/             # Output format handlers
│   │   └── dependency_reporter.py # Dependency reports
│   ├── integrations/          # External service integrations
│   │   ├── manager.py         # Integration manager
│   │   ├── github_issues.py   # GitHub Issues integration
│   │   ├── jira.py            # JIRA integration
│   │   ├── slack.py           # Slack integration
│   │   └── webhook.py         # Generic webhook support
│   └── utils/                 # Utility functions
│       └── file_utils.py      # File system utilities
├── templates/                 # HTML report templates
├── custom_templates/          # Custom report templates
├── reports/                   # Generated reports directory
├── docs/                      # Documentation
├── tests/                     # Test suite
├── scripts/                   # Utility scripts
├── benchmark_results/         # Performance benchmarks
├── pyproject.toml            # Poetry configuration
├── Dockerfile                # Docker configuration
├── .github/                  # GitHub Actions workflows
└── README.md
```

### Key Architectural Principles

1. **Modular Design**: Each component has a single responsibility
2. **Plugin Architecture**: Analyzers and parsers are pluggable
3. **Unified Findings**: All analysis results flow through a common findings system
4. **Performance First**: Built-in caching and parallel processing
5. **Extensible Reporting**: Multiple output formats with unified data models
6. **Configuration-Driven**: Flexible configuration via YAML, environment variables, or CLI
7. **Integration Ready**: Built-in support for CI/CD and external services

## 👾 Development

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/wtf-codebot.git
cd wtf-codebot

# Install development dependencies
poetry install --with dev

# Install pre-commit hooks
poetry run pre-commit install

# Run in development mode
poetry run python -m wtf_codebot.cli.main --help
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=wtf_codebot --cov-report=html

# Run specific test files
poetry run pytest tests/test_performance.py

# Run performance benchmarks
poetry run python scripts/run_benchmarks.py
```

### Code Quality

```bash
# Format code
poetry run black wtf_codebot/ tests/
poetry run isort wtf_codebot/ tests/

# Lint code
poetry run flake8 wtf_codebot/
poetry run mypy wtf_codebot/

# Security scan
poetry run bandit -r wtf_codebot/

# Check dependencies
poetry run safety check
```

### Building and Packaging

```bash
# Build the package
poetry build

# Publish to PyPI (maintainers only)
poetry publish

# Build Docker image
docker build -t wtfcodebot/wtf-codebot:latest .

# Test Docker image
docker run --rm -v $(pwd):/workspace wtfcodebot/wtf-codebot:latest analyze /workspace --dry-run
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/code-analysis.yml
name: Code Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run WTF CodeBot
      run: |
        pip install wtf-codebot
        wtf-codebot analyze . \
          --api-key ${{ secrets.ANTHROPIC_API_KEY }} \
          --export-sarif security.sarif \
          --export-json results.json \
          --github-issues \
          --github-repo ${{ github.repository }}
    
    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security.sarif
    
    - name: Upload results as artifacts
      uses: actions/upload-artifact@v3
      with:
        name: analysis-results
        path: |
          results.json
          security.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - analysis

code_analysis:
  stage: analysis
  image: python:3.11
  script:
    - pip install wtf-codebot
    - wtf-codebot analyze . 
        --api-key $ANTHROPIC_API_KEY 
        --export-json results.json 
        --export-html report.html
  artifacts:
    reports:
      junit: results.json
    paths:
      - report.html
    expire_in: 1 week
  only:
    - main
    - merge_requests
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    environment {
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
    }
    
    stages {
        stage('Code Analysis') {
            steps {
                sh '''
                    pip install wtf-codebot
                    wtf-codebot analyze . \
                        --api-key $ANTHROPIC_API_KEY \
                        --export-json results.json \
                        --export-html report.html
                '''
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'report.html',
                reportName: 'Code Analysis Report'
            ])
        }
    }
}
```

## 🐳 Docker Usage

### Basic Docker Usage

```bash
# Pull the latest image
docker pull wtfcodebot/wtf-codebot:latest

# Analyze current directory
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your-api-key \
  wtfcodebot/wtf-codebot:latest \
  analyze /workspace

# Generate reports with volume mount
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/reports:/reports \
  -e ANTHROPIC_API_KEY=your-api-key \
  wtfcodebot/wtf-codebot:latest \
  analyze /workspace --export-html /reports/analysis.html
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  wtf-codebot:
    image: wtfcodebot/wtf-codebot:latest
    volumes:
      - ./:/workspace
      - ./reports:/reports
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    command: >
      analyze /workspace 
      --export-html /reports/analysis.html
      --export-json /reports/results.json
      --verbose
```

### Custom Docker Image

```dockerfile
# Custom Dockerfile with additional tools
FROM wtfcodebot/wtf-codebot:latest

# Add additional analysis tools
RUN pip install bandit safety

# Add custom configuration
COPY wtf-codebot.yaml /etc/wtf-codebot/config.yaml

# Set default configuration
ENV WTF_CODEBOT_CONFIG_FILE=/etc/wtf-codebot/config.yaml
```

## 📜 Environment Variables Reference

All configuration options can be overridden using environment variables:

### Core Configuration
- `ANTHROPIC_API_KEY`: Anthropic API key (required)
- `ANTHROPIC_MODEL`: Claude model to use (default: claude-3-sonnet-20240229)
- `WTF_CODEBOT_CONFIG_FILE`: Path to configuration file

### Output Configuration
- `WTF_CODEBOT_OUTPUT_FORMAT`: Default output format (console, json, html, etc.)
- `WTF_CODEBOT_OUTPUT_FILE`: Default output file path
- `WTF_CODEBOT_VERBOSE`: Enable verbose mode (true/false)
- `WTF_CODEBOT_DRY_RUN`: Enable dry run mode (true/false)

### Analysis Configuration
- `WTF_CODEBOT_MAX_FILE_SIZE`: Maximum file size to analyze (bytes)
- `WTF_CODEBOT_INCLUDE_TESTS`: Include test files (true/false)
- `WTF_CODEBOT_ANALYSIS_DEPTH`: Analysis depth (basic/standard/deep/comprehensive)
- `WTF_CODEBOT_BATCH_SIZE`: Files per batch for processing
- `WTF_CODEBOT_MAX_DEPTH`: Maximum directory depth to scan

### Performance Configuration
- `WTF_CODEBOT_CACHE_ENABLED`: Enable caching (true/false)
- `WTF_CODEBOT_CACHE_DIR`: Cache directory path
- `WTF_CODEBOT_PARALLEL_ENABLED`: Enable parallel processing (true/false)
- `WTF_CODEBOT_WORKER_COUNT`: Number of parallel workers

### Logging Configuration
- `WTF_CODEBOT_LOG_LEVEL`: Logging level (DEBUG/INFO/WARNING/ERROR)
- `WTF_CODEBOT_LOG_FILE`: Log file path
- `WTF_CODEBOT_LOG_FORMAT`: Log format (json/text)

### Integration Configuration
- `GITHUB_TOKEN`: GitHub personal access token
- `JIRA_URL`: JIRA instance URL
- `JIRA_USERNAME`: JIRA username
- `JIRA_API_TOKEN`: JIRA API token
- `SLACK_WEBHOOK_URL`: Slack webhook URL

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Quick Contribution Guide

1. **Fork the repository** and clone your fork
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Install development dependencies**: `poetry install --with dev`
4. **Make your changes** and add tests
5. **Run the test suite**: `poetry run pytest`
6. **Format your code**: `poetry run black . && poetry run isort .`
7. **Commit your changes**: `git commit -m 'Add amazing feature'`
8. **Push to your fork**: `git push origin feature/amazing-feature`
9. **Open a Pull Request**

### Areas for Contribution

- 🔍 **New language analyzers** (Java, C#, Kotlin, etc.)
- 📊 **Enhanced reporting** features and visualizations
- 🔗 **Integration plugins** for more CI/CD platforms
- 🚀 **Performance optimizations** and caching improvements
- 📝 **Documentation** improvements and examples
- 🐛 **Bug fixes** and test coverage improvements

## 🔧 Troubleshooting

### Common Issues

#### API Key Issues
```bash
# Error: Invalid API key
# Solution: Check your API key format and permissions
export ANTHROPIC_API_KEY="sk-ant-your-actual-key-here"
wtf-codebot analyze . --dry-run --verbose
```

#### Memory Issues
```bash
# Error: Out of memory during analysis
# Solution: Reduce batch size and exclude large files
wtf-codebot analyze . \
  --batch-size 10 \
  --max-file-size 512000 \
  --exclude "**/node_modules/**" \
  --exclude "**/dist/**"
```

#### Performance Issues
```bash
# Enable caching for faster repeated analysis
export WTF_CODEBOT_CACHE_ENABLED=true
export WTF_CODEBOT_CACHE_DIR=~/.wtf-codebot-cache

# Use parallel processing
export WTF_CODEBOT_PARALLEL_ENABLED=true
export WTF_CODEBOT_WORKER_COUNT=4
```

#### Docker Issues
```bash
# Permission issues with Docker volumes
docker run --rm \
  -v $(pwd):/workspace \
  --user $(id -u):$(id -g) \
  wtfcodebot/wtf-codebot:latest \
  analyze /workspace
```

### Debug Mode

```bash
# Enable debug logging
export WTF_CODEBOT_LOG_LEVEL=DEBUG
wtf-codebot analyze . --verbose --dry-run

# Generate debug report
wtf-codebot analyze . \
  --verbose \
  --export-json debug-report.json \
  --api-key your-key
```

### Getting Help

- 💬 **GitHub Discussions**: Ask questions and share ideas
- 🐛 **GitHub Issues**: Report bugs and request features
- 📝 **Documentation**: Check our comprehensive docs
- 📧 **Email Support**: Contact maintainers for enterprise support

## 📈 Performance

### Benchmarks

WTF CodeBot has been tested on various codebases:

| Project Size | Files | Analysis Time | Memory Usage | Cache Benefit |
|-------------|-------|---------------|--------------|---------------|
| Small (< 100 files) | 50-100 | 30-60s | < 200MB | 40% faster |
| Medium (< 1K files) | 500-1000 | 2-5 min | 200-500MB | 60% faster |
| Large (< 10K files) | 5000-10000 | 10-20 min | 500MB-1GB | 75% faster |
| Enterprise (> 10K files) | 10000+ | 30-60 min | 1-2GB | 80% faster |

### Optimization Tips

1. **Use caching** for repeated analysis of the same codebase
2. **Enable parallel processing** for large codebases
3. **Exclude unnecessary files** (node_modules, build artifacts, etc.)
4. **Adjust batch size** based on available memory
5. **Use appropriate analysis depth** for your needs
6. **Filter by language** to focus on relevant code

### Performance Configuration

```yaml
# High-performance configuration
performance:
  cache_enabled: true
  cache_dir: "~/.wtf-codebot-cache"
  parallel_enabled: true
  worker_count: 8
  batch_size: 100
  
analysis:
  max_file_size: 1048576  # 1MB
  analysis_depth: "standard"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/venv/**"
    - "**/.git/**"
    - "**/dist/**"
    - "**/build/**"
```

## 📊 Changelog

### Version 0.1.0 (Current)

- ✅ **Core Features**: Multi-language analysis with AI-powered insights
- ✅ **CLI Interfaces**: Three different CLI implementations
- ✅ **Output Formats**: JSON, HTML, Markdown, SARIF, CSV
- ✅ **Integrations**: GitHub, JIRA, Slack, Webhooks
- ✅ **Performance**: Caching, parallel processing, benchmarks
- ✅ **Docker Support**: Containerized analysis
- ✅ **Documentation**: Comprehensive guides and examples

### Roadmap

- 🕰 **v0.2.0**: Enhanced security analysis and compliance reporting
- 🕰 **v0.3.0**: Machine learning-based pattern recognition
- 🕰 **v0.4.0**: IDE plugins and editor integrations
- 🕰 **v0.5.0**: Advanced dependency analysis and vulnerability tracking

## 📋 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Anthropic** for providing the Claude API
- **Tree-sitter** for language parsing capabilities
- **Rich** for beautiful terminal output
- **Poetry** for dependency management
- **All contributors** who have helped improve WTF CodeBot

---

**Built with ❤️ by the WTF CodeBot team**

For enterprise support, custom integrations, or consulting services, please contact us at [enterprise@wtfcodebot.com](mailto:enterprise@wtfcodebot.com).
