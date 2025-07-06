# WTF CodeBot Usage Documentation

Comprehensive usage guide for WTF CodeBot - AI-powered code analysis and review tool.

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (recommended)
pip install wtf-codebot

# Or using Docker
docker pull wtfcodebot/wtf-codebot:latest

# Or install from source
git clone https://github.com/your-org/wtf-codebot.git
cd wtf-codebot && poetry install
```

### Basic Usage

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Analyze current directory
wtf-codebot analyze .

# Analyze with verbose output and JSON export
wtf-codebot analyze ./my-project --verbose --export-json results.json

# Quick dry run to test configuration
wtf-codebot analyze . --dry-run
```

## 🔧 CLI Interfaces

WTF CodeBot provides three CLI implementations:

### 1. Click-based CLI (Original)
```bash
wtf-codebot analyze /path/to/code
wtf-codebot config-info
wtf-codebot init-config
wtf-codebot version
```

### 2. Typer-based CLI (Enhanced - Recommended)
```bash
wtf-codebot-typer analyze /path/to/code --api-key your-key
wtf-codebot-typer config --show
wtf-codebot-typer version
```

### 3. Argparse-based CLI (Traditional)
```bash
wtf-codebot-argparse analyze /path/to/code --api-key your-key
wtf-codebot-argparse --help
```

### 4. Dependency Analysis CLI
```bash
wtf-codebot-deps analyze /path/to/project
```

## 📊 Analysis Options

### Analysis Depth
```bash
# Basic analysis (fastest)
wtf-codebot analyze . --analysis-depth basic

# Standard analysis (recommended balance)
wtf-codebot analyze . --analysis-depth standard

# Deep analysis (more thorough)
wtf-codebot analyze . --analysis-depth deep

# Comprehensive analysis (most detailed)
wtf-codebot analyze . --analysis-depth comprehensive
```

### Language Filtering
```bash
# Analyze only Python files
wtf-codebot-typer analyze . --language python

# Multi-language analysis
wtf-codebot-typer analyze . --language python --language javascript --language typescript

# All supported languages (default)
wtf-codebot analyze .
```

### File Filtering
```bash
# Include specific patterns
wtf-codebot analyze . --include "**/*.py" --include "**/*.js"

# Exclude patterns
wtf-codebot analyze . --exclude "**/node_modules/**" --exclude "**/venv/**"

# Complex filtering
wtf-codebot analyze . \
  --include "**/*.py" \
  --exclude "**/test_*" \
  --exclude "**/__pycache__/**"
```

### Performance Tuning
```bash
# Adjust batch size for memory usage
wtf-codebot analyze . --batch-size 50

# Set maximum file size (in bytes)
wtf-codebot analyze . --max-file-size 1048576

# Control directory depth
wtf-codebot analyze . --depth 10

# Enable parallel processing
export WTF_CODEBOT_PARALLEL_ENABLED=true
export WTF_CODEBOT_WORKER_COUNT=4
wtf-codebot analyze .
```

## 📋 Output Formats

### Console Output (Default)
```bash
wtf-codebot analyze . --format console --verbose
```

### JSON Reports
```bash
# Standard JSON
wtf-codebot analyze . --export-json results.json

# Enhanced JSON with metadata, patterns, and remediation
wtf-codebot analyze . --export-json enhanced_results.json
```

### HTML Reports
```bash
# Interactive HTML report with charts and filtering
wtf-codebot analyze . --export-html report.html

# Custom template
wtf-codebot analyze . --export-html report.html --template custom
```

### SARIF (Security Analysis Results Interchange Format)
```bash
# For CI/CD integration and security tools
wtf-codebot analyze . --export-sarif security.sarif
```

### Other Formats
```bash
# CSV for spreadsheet analysis
wtf-codebot analyze . --export-csv findings.csv

# Markdown for documentation
wtf-codebot analyze . --format markdown --output report.md

# YAML for configuration-friendly output
wtf-codebot analyze . --format yaml --output results.yaml
```

### Multi-Format Export
```bash
# Generate multiple formats at once
wtf-codebot analyze . \
  --export-json results.json \
  --export-html report.html \
  --export-sarif security.sarif \
  --export-csv findings.csv
```

## 🔗 Integrations

### GitHub Issues
```bash
# Create GitHub issues for critical findings
wtf-codebot analyze . \
  --github-issues \
  --github-repo owner/repository \
  --api-key your-anthropic-key

# Requires GITHUB_TOKEN environment variable
export GITHUB_TOKEN="ghp_your_github_token"
```

### JIRA Integration
```bash
# Create JIRA tickets for high-priority issues
wtf-codebot analyze . \
  --jira-project PROJ \
  --api-key your-anthropic-key

# Requires JIRA environment variables
export JIRA_URL="https://your-company.atlassian.net"
export JIRA_USERNAME="your-email@company.com"
export JIRA_API_TOKEN="your-jira-api-token"
```

### Slack Notifications
```bash
# Send results to Slack channel
wtf-codebot analyze . \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --api-key your-anthropic-key

# Or use environment variable
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
wtf-codebot analyze . --api-key your-anthropic-key
```

### Generic Webhooks
```bash
# Send results to any webhook endpoint
wtf-codebot analyze . \
  --webhook-url "https://your-webhook-endpoint.com/receive" \
  --api-key your-anthropic-key
```

## ⚙️ Configuration

### Configuration File
```bash
# Initialize default configuration
wtf-codebot init-config

# Use custom configuration file
wtf-codebot analyze . --config my-config.yaml

# Save current CLI configuration to file
wtf-codebot-typer analyze . \
  --api-key your-key \
  --save-config my-analysis-config.yaml
```

### Sample Configuration File
```yaml
# wtf-codebot.yaml
anthropic_api_key: "sk-ant-your-key-here"
anthropic_model: "claude-3-sonnet-20240229"
output_format: "console"
verbose: false
dry_run: false

analysis:
  max_file_size: 1048576
  include_tests: true
  analysis_depth: "standard"
  supported_extensions:
    - ".py"
    - ".js"
    - ".ts"
    - ".java"
    - ".cpp"
    - ".go"
    - ".rs"
    - ".rb"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/__pycache__/**"
    - "**/venv/**"
    - "**/.env"

performance:
  cache_enabled: true
  cache_dir: "~/.wtf-codebot-cache"
  parallel_enabled: true
  worker_count: 4
  batch_size: 50

integrations:
  enabled: false
  github_issues_enabled: false
  slack_enabled: false
  jira_enabled: false

logging:
  level: "INFO"
  file_path: null
```

### Environment Variables
```bash
# Core configuration
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
export ANTHROPIC_MODEL="claude-3-sonnet-20240229"
export WTF_CODEBOT_CONFIG_FILE="/path/to/config.yaml"

# Output configuration
export WTF_CODEBOT_OUTPUT_FORMAT="json"
export WTF_CODEBOT_VERBOSE="true"
export WTF_CODEBOT_DRY_RUN="false"

# Analysis configuration
export WTF_CODEBOT_MAX_FILE_SIZE="1048576"
export WTF_CODEBOT_INCLUDE_TESTS="true"
export WTF_CODEBOT_ANALYSIS_DEPTH="standard"
export WTF_CODEBOT_BATCH_SIZE="50"

# Performance configuration
export WTF_CODEBOT_CACHE_ENABLED="true"
export WTF_CODEBOT_CACHE_DIR="~/.wtf-codebot-cache"
export WTF_CODEBOT_PARALLEL_ENABLED="true"
export WTF_CODEBOT_WORKER_COUNT="4"

# Integration configuration
export GITHUB_TOKEN="ghp_your_token"
export JIRA_URL="https://company.atlassian.net"
export JIRA_USERNAME="user@company.com"
export JIRA_API_TOKEN="jira_token"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

## 🐳 Docker Usage

### Basic Docker Usage
```bash
# Pull the image
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
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - ./:/workspace:ro
      - ./reports:/app/reports
    command: >
      analyze /workspace
      --export-html /app/reports/analysis.html
      --export-json /app/reports/results.json
```

### Development with Docker
```bash
# Run development container
docker-compose --profile development up wtf-codebot-dev

# Enter development container
docker-compose --profile development exec wtf-codebot-dev bash
```

## 🔄 CI/CD Integration

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
          --export-json results.json
    
    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security.sarif
```

### GitLab CI
```yaml
# .gitlab-ci.yml
code_analysis:
  stage: test
  image: python:3.11
  script:
    - pip install wtf-codebot
    - wtf-codebot analyze . 
        --api-key $ANTHROPIC_API_KEY 
        --export-json results.json
  artifacts:
    reports:
      junit: results.json
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
                        --export-html report.html
                '''
            }
        }
    }
}
```

## 📈 Performance Optimization

### Caching
```bash
# Enable caching for faster repeated analysis
export WTF_CODEBOT_CACHE_ENABLED=true
export WTF_CODEBOT_CACHE_DIR=~/.wtf-codebot-cache

# Clear cache when needed
rm -rf ~/.wtf-codebot-cache
```

### Parallel Processing
```bash
# Enable parallel processing
export WTF_CODEBOT_PARALLEL_ENABLED=true
export WTF_CODEBOT_WORKER_COUNT=8  # Adjust based on CPU cores

# Monitor resource usage
htop  # or similar monitoring tool
```

### Memory Management
```bash
# For large codebases, reduce batch size
wtf-codebot analyze . --batch-size 10

# Exclude large directories
wtf-codebot analyze . \
  --exclude "**/node_modules/**" \
  --exclude "**/dist/**" \
  --exclude "**/build/**"

# Limit file size
wtf-codebot analyze . --max-file-size 512000  # 500KB
```

### Performance Benchmarking
```bash
# Run performance benchmarks
poetry run python scripts/run_benchmarks.py

# Custom benchmark
time wtf-codebot analyze . --dry-run --verbose
```

## 🔧 Troubleshooting

### Common Issues

#### API Key Problems
```bash
# Check API key format
echo $ANTHROPIC_API_KEY | grep -E '^sk-ant-'

# Test API key
wtf-codebot analyze . --dry-run --verbose
```

#### Memory Issues
```bash
# Reduce memory usage
wtf-codebot analyze . \
  --batch-size 10 \
  --max-file-size 512000 \
  --exclude "**/node_modules/**"
```

#### Permission Issues with Docker
```bash
# Fix permission issues
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

# Save debug information
wtf-codebot analyze . --verbose 2>&1 | tee debug.log
```

### Getting Help
```bash
# Command help
wtf-codebot --help
wtf-codebot analyze --help

# Version information
wtf-codebot version

# Configuration info
wtf-codebot config-info
```

## 📊 Understanding Results

### Finding Severity Levels
- **Critical**: Security vulnerabilities, major bugs
- **High**: Performance issues, code smells affecting maintainability
- **Medium**: Style violations, minor code quality issues
- **Low**: Informational findings, suggestions
- **Info**: Pattern detections, architectural notes

### Finding Types
- **Security Vulnerability**: Security-related issues
- **Code Smell**: Code quality problems
- **Anti-pattern**: Poor design patterns
- **Style Violation**: Code style and formatting issues
- **Outdated Dependency**: Dependency management issues
- **Design Pattern**: Detected design patterns (informational)

### Report Sections
1. **Summary**: Overall statistics and metrics
2. **Findings**: Detailed list of all issues found
3. **Patterns**: Detected code patterns and anti-patterns
4. **Dependencies**: Dependency analysis and vulnerabilities
5. **Recommendations**: Actionable improvement suggestions
6. **Metrics**: Code quality scores and technical debt assessment

## 🎯 Best Practices

### Analysis Strategy
1. **Start with standard depth** for balanced analysis
2. **Use dry runs** to test configuration
3. **Enable caching** for repeated analysis
4. **Filter by language** to focus on relevant code
5. **Exclude build artifacts** and dependencies

### CI/CD Integration
1. **Use SARIF format** for security tool integration
2. **Set up GitHub Issues** for critical findings
3. **Configure webhooks** for team notifications
4. **Archive reports** as build artifacts
5. **Fail builds** on critical security issues

### Performance
1. **Monitor resource usage** during analysis
2. **Adjust batch sizes** based on available memory
3. **Use parallel processing** for large codebases
4. **Exclude unnecessary files** early
5. **Cache results** for incremental analysis

### Security
1. **Protect API keys** using environment variables
2. **Use least privilege** for CI/CD integrations
3. **Review findings** before auto-creating issues
4. **Audit webhook endpoints** for data security
5. **Rotate keys** regularly

---

For more detailed information, see:
- [README.md](README.md) - Project overview and features
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development and contribution guide
- [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) - Technical implementation details
- [CLI_USAGE.md](CLI_USAGE.md) - Comprehensive CLI reference
