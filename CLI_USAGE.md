# WTF CodeBot CLI Usage Guide

This document provides comprehensive information about using the WTF CodeBot command-line interface (CLI). The project includes three CLI implementations to demonstrate different approaches to argument parsing and validation.

## Available CLI Implementations

1. **Click-based CLI** (`wtf-codebot`) - Original implementation using Click
2. **Typer-based CLI** (`wtf-codebot-typer`) - Enhanced implementation using Typer with rich help
3. **Argparse-based CLI** (`wtf-codebot-argparse`) - Alternative implementation using argparse

## Installation

Install the package with all CLI entry points:

```bash
pip install wtf-codebot
# or using poetry
poetry install
```

## Basic Usage

All CLI implementations provide the same core functionality with slightly different interfaces:

### Analyze Command

The primary command for code analysis:

```bash
# Using the typer CLI (recommended)
wtf-codebot-typer analyze /path/to/code --api-key sk-ant-your-key

# Using the argparse CLI
wtf-codebot-argparse analyze /path/to/code --api-key sk-ant-your-key

# Using the original click CLI
wtf-codebot analyze /path/to/code
```

## API Key Configuration

The API key can be provided in several ways:

1. **Command line argument**:
   ```bash
   wtf-codebot-typer analyze /path/to/code --api-key sk-ant-your-key
   ```

2. **Environment variable**:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-your-key
   wtf-codebot-typer analyze /path/to/code
   ```

3. **Configuration file** (see Configuration section below)

## Command Arguments and Options

### Required Arguments

- `directory` - Path to the directory containing code to analyze

### API Configuration

- `--api-key, -k` - Anthropic API key (can also be set via `ANTHROPIC_API_KEY` env var)
- `--model, -m` - Anthropic model to use (default: `claude-3-sonnet-20240229`)

### Output Configuration

- `--format, -f` - Output format(s), can be specified multiple times
  - Available formats: `console`, `json`, `markdown`, `html`, `yaml`
  - Default: `console`
- `--output, -o` - Output file path (required for non-console formats)

### Language and File Filtering

- `--language, -l` - Filter by programming language, can be specified multiple times
  - Supported languages: `python`, `javascript`, `typescript`, `java`, `cpp`, `c`, `go`, `rust`, `ruby`, `php`, `swift`, `kotlin`, `scala`, and many more
- `--include, -i` - Include patterns (glob), can be specified multiple times
- `--exclude, -x` - Exclude patterns (glob), can be specified multiple times

### Analysis Configuration

- `--depth, -d` - Maximum directory depth to analyze (1-100, default: 10)
- `--analysis-depth` - Analysis depth level
  - Options: `basic`, `standard`, `deep`, `comprehensive`
  - Default: `standard`
- `--batch-size, -b` - Number of files to process in each batch (1-1000, default: 50)
- `--max-file-size` - Maximum file size to analyze in bytes (default: 1MB)

### Analysis Flags

- `--include-tests/--exclude-tests` - Include or exclude test files (default: include)
- `--include-hidden/--exclude-hidden` - Include or exclude hidden files and directories (default: exclude)
- `--follow-symlinks/--no-follow-symlinks` - Follow symbolic links (default: no)

### General Options

- `--verbose, -v` - Enable verbose output
- `--dry-run` - Perform dry run without making API calls
- `--config, -c` - Path to configuration file
- `--save-config` - Save current configuration to file

## Usage Examples

### Basic Analysis

```bash
# Simple analysis of a Python project
wtf-codebot-typer analyze ./my-python-project --api-key sk-ant-your-key

# Analyze with verbose output
wtf-codebot-typer analyze ./my-project --api-key sk-ant-your-key --verbose
```

### Multi-Format Output

```bash
# Generate both JSON and Markdown reports
wtf-codebot-typer analyze ./my-project \
  --api-key sk-ant-your-key \
  --format json \
  --format markdown \
  --output report

# This creates: report.json and report.md
```

### Language-Specific Analysis

```bash
# Analyze only Python and JavaScript files
wtf-codebot-typer analyze ./full-stack-project \
  --api-key sk-ant-your-key \
  --language python \
  --language javascript
```

### Advanced Filtering

```bash
# Exclude specific directories and include only certain file patterns
wtf-codebot-typer analyze ./large-project \
  --api-key sk-ant-your-key \
  --exclude "**/node_modules/**" \
  --exclude "**/venv/**" \
  --exclude "**/.git/**" \
  --include "**/*.py" \
  --include "**/*.js" \
  --include "**/*.ts"
```

### Deep Analysis with Custom Settings

```bash
# Comprehensive analysis with custom batch processing
wtf-codebot-typer analyze ./complex-project \
  --api-key sk-ant-your-key \
  --analysis-depth comprehensive \
  --batch-size 100 \
  --depth 15 \
  --max-file-size 2097152  # 2MB
```

### Dry Run

```bash
# Test configuration without making API calls
wtf-codebot-typer analyze ./my-project \
  --api-key sk-ant-your-key \
  --dry-run \
  --verbose
```

## Configuration Management

### Initialize Configuration

```bash
# Create a new configuration file
wtf-codebot-typer config --init
wtf-codebot-typer config --init --file custom-config.yaml
```

### Show Current Configuration

```bash
# Display current configuration
wtf-codebot-typer config --show
wtf-codebot-typer config --show --file custom-config.yaml
```

### Validate Configuration

```bash
# Validate a configuration file
wtf-codebot-typer config --validate --file config.yaml
```

### Save Runtime Configuration

```bash
# Save current command-line configuration to file
wtf-codebot-typer analyze ./my-project \
  --api-key sk-ant-your-key \
  --language python \
  --format json \
  --save-config my-analysis-config.yaml
```

## Configuration File Format

Configuration files use YAML format:

```yaml
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
    # ... more extensions
  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/__pycache__/**"
    - "**/venv/**"
    - "**/.env"

logging:
  level: "INFO"
  file_path: null
```

## Environment Variables

The following environment variables can be used:

- `ANTHROPIC_API_KEY` - Anthropic API key
- `ANTHROPIC_MODEL` - Anthropic model to use
- `WTF_CODEBOT_OUTPUT_FORMAT` - Default output format
- `WTF_CODEBOT_VERBOSE` - Enable verbose mode (true/false)
- `WTF_CODEBOT_DRY_RUN` - Enable dry run mode (true/false)
- `WTF_CODEBOT_LOG_LEVEL` - Logging level
- `WTF_CODEBOT_MAX_FILE_SIZE` - Maximum file size to analyze
- `WTF_CODEBOT_INCLUDE_TESTS` - Include test files (true/false)
- `WTF_CODEBOT_ANALYSIS_DEPTH` - Analysis depth level

## Error Handling and Validation

The CLI includes comprehensive validation:

### API Key Validation
- Checks for empty or placeholder values
- Warns if the format doesn't match Anthropic API key pattern
- Supports environment variable fallback

### Directory Validation
- Verifies directory exists and is readable
- Checks if path is actually a directory

### Parameter Validation
- Depth limits (1-100)
- Batch size limits (1-1000)
- Output format validation
- File size limits

### Language Filter Validation
- Warns about unknown/unsupported languages
- Maps languages to appropriate file extensions

## Help and Documentation

Get help for any command:

```bash
# General help
wtf-codebot-typer --help

# Command-specific help
wtf-codebot-typer analyze --help
wtf-codebot-typer config --help

# Using argparse CLI (includes detailed examples)
wtf-codebot-argparse --help
wtf-codebot-argparse analyze --help
```

## Version Information

```bash
wtf-codebot-typer version
wtf-codebot-argparse version
```

## CLI Implementation Comparison

| Feature | Click CLI | Typer CLI | Argparse CLI |
|---------|-----------|-----------|--------------|
| Rich output | ✓ | ✓ | ✓ |
| Progress bars | ✓ | ✓ | ✗ |
| Interactive prompts | ✓ | ✓ | Basic |
| Auto-completion | ✓ | ✓ | ✗ |
| Validation callbacks | ✓ | ✓ | Custom |
| Help formatting | Good | Excellent | Good |
| Type hints | Partial | Full | Manual |
| Error handling | Good | Excellent | Good |

## Best Practices

1. **Use environment variables** for API keys to avoid exposing them in command history
2. **Start with dry runs** when testing new configurations
3. **Use configuration files** for complex, repeated analysis setups
4. **Enable verbose output** when troubleshooting
5. **Use language filters** to focus analysis on relevant code
6. **Set appropriate batch sizes** based on your system resources
7. **Use exclude patterns** to skip irrelevant directories (node_modules, .git, etc.)

## Troubleshooting

### Common Issues

1. **API Key Errors**: Ensure your API key is valid and has proper permissions
2. **Directory Not Found**: Use absolute paths or verify relative paths
3. **Output File Errors**: Ensure the output directory exists and is writable
4. **Memory Issues**: Reduce batch size or exclude large directories
5. **Rate Limiting**: Reduce batch size or add delays between requests

### Debug Mode

Enable verbose output for detailed information:

```bash
wtf-codebot-typer analyze ./my-project --verbose --dry-run
```

This will show:
- Configuration details
- File discovery process
- Validation results
- Any warnings or errors

## Migration from Click to Typer/Argparse

If you're currently using the Click-based CLI and want to migrate:

1. **Typer CLI** offers the most similar experience with enhanced features
2. **Argparse CLI** provides a more traditional Unix-style interface
3. All CLIs accept the same core arguments, so existing scripts should work with minimal changes
4. Configuration files are compatible across all implementations
