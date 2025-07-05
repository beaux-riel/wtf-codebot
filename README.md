# WTF CodeBot

An AI-powered code analysis and review tool that helps you understand, analyze, and improve your codebase.

## Features

- 🤖 AI-powered code analysis using Anthropic's Claude
- 🔍 Multi-language support (Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, Ruby)
- ⚙️ Configurable analysis depth and options
- 📊 Multiple output formats (console, JSON, markdown)
- 🎯 Smart file filtering and exclusion patterns
- 🔧 Flexible configuration via files or environment variables
- 📝 Comprehensive logging and error handling

## Installation

### Using Poetry (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd wtf-codebot

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### Using pip with virtual environment

```bash
# Clone the repository
git clone <repository-url>
cd wtf-codebot

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
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

## Usage

### Initialize Configuration

Create a configuration file with default settings:

```bash
wtf-codebot init-config
```

### Analyze Code

Analyze a file or directory:

```bash
# Analyze current directory
wtf-codebot analyze .

# Analyze specific file
wtf-codebot analyze /path/to/file.py

# Analyze with options
wtf-codebot analyze /path/to/project \
  --format json \
  --output report.json \
  --exclude "**/*.test.js" \
  --verbose
```

### View Configuration

Display current configuration:

```bash
wtf-codebot config-info
```

### Get Help

```bash
# General help
wtf-codebot --help

# Command-specific help
wtf-codebot analyze --help
```

## Command Line Options

### Global Options

- `--config, -c`: Path to configuration file
- `--verbose, -v`: Enable verbose output
- `--dry-run`: Perform dry run without making changes

### Analyze Command Options

- `--output, -o`: Output file path
- `--format, -f`: Output format (console, json, markdown)
- `--include-tests`: Include test files in analysis
- `--exclude`: Exclude patterns (can be used multiple times)

## Directory Structure

```
wtf-codebot/
├── wtf_codebot/
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py          # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        # Configuration management
│   │   ├── logging.py       # Logging setup
│   │   └── exceptions.py    # Exception classes
│   ├── analyzers/
│   │   └── __init__.py      # Code analyzers (future)
│   ├── reporters/
│   │   └── __init__.py      # Output reporters (future)
│   └── utils/
│       ├── __init__.py
│       └── file_utils.py    # File utilities
├── pyproject.toml           # Poetry configuration
├── wtf-codebot.yaml.example # Example config file
├── .env.example             # Example environment file
└── README.md
```

## Development

### Running Tests

```bash
# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=wtf_codebot
```

### Code Formatting

```bash
# Format code
poetry run black wtf_codebot/
poetry run isort wtf_codebot/

# Check formatting
poetry run black --check wtf_codebot/
poetry run flake8 wtf_codebot/
```

### Type Checking

```bash
poetry run mypy wtf_codebot/
```

## Environment Variables Reference

All configuration options can be overridden using environment variables:

- `ANTHROPIC_API_KEY`: Anthropic API key
- `ANTHROPIC_MODEL`: Claude model to use
- `WTF_CODEBOT_OUTPUT_FORMAT`: Output format
- `WTF_CODEBOT_OUTPUT_FILE`: Output file path
- `WTF_CODEBOT_VERBOSE`: Enable verbose mode
- `WTF_CODEBOT_DRY_RUN`: Enable dry run mode
- `WTF_CODEBOT_LOG_LEVEL`: Logging level
- `WTF_CODEBOT_LOG_FILE`: Log file path
- `WTF_CODEBOT_MAX_FILE_SIZE`: Maximum file size
- `WTF_CODEBOT_INCLUDE_TESTS`: Include test files
- `WTF_CODEBOT_ANALYSIS_DEPTH`: Analysis depth

## License

This project is licensed under the MIT License.
