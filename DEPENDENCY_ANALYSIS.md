# Dependency & Security Analysis

This module provides comprehensive dependency analysis for various package managers, including dependency mapping, version analysis, license detection, and vulnerability scanning using public security advisories.

## Features

### 🔍 **Multi-Language Support**
- **JavaScript/Node.js**: `package.json`
- **Python**: `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`
- **Extensible**: Easy to add support for more package managers

### 📦 **Dependency Analysis**
- Parse and map all dependencies with version constraints
- Distinguish between production, development, and optional dependencies
- Build dependency trees to understand relationships
- Extract package metadata (descriptions, licenses, etc.)

### 🛡️ **Security Vulnerability Scanning**
- Integration with **GitHub Advisory Database**
- Integration with **OSV (Open Source Vulnerabilities) Database**  
- OWASP compatibility for known vulnerability detection
- Severity assessment (Critical, High, Medium, Low)
- Affected version ranges and fix recommendations

### 📜 **License Compliance**
- Automatic license detection for all dependencies
- License distribution analysis
- Compliance reporting for legal review
- Support for complex license expressions

### 📊 **Multiple Output Formats**
- **Console**: Rich, colorized terminal output
- **JSON**: Machine-readable structured data
- **HTML**: Beautiful web reports with charts
- **Markdown**: Documentation-friendly format
- **CSV**: Spreadsheet-compatible data export

## Installation

The dependency analysis module is part of the wtf-codebot package. Ensure you have the required dependencies:

```bash
pip install toml pyyaml rich click typer
```

## Usage

### Command Line Interface

#### Basic Analysis
```bash
# Analyze current directory
python wtf_codebot/cli/dependency_cli.py

# Analyze specific directory
python wtf_codebot/cli/dependency_cli.py /path/to/project

# Analyze specific file
python wtf_codebot/cli/dependency_cli.py /path/to/package.json
```

#### Advanced Options
```bash
# Skip network vulnerability checks (faster)
python wtf_codebot/cli/dependency_cli.py --no-network

# Show only vulnerabilities
python wtf_codebot/cli/dependency_cli.py --vulnerabilities-only

# Show only license information
python wtf_codebot/cli/dependency_cli.py --licenses-only

# Generate HTML report
python wtf_codebot/cli/dependency_cli.py --output report.html --format html

# Export to JSON
python wtf_codebot/cli/dependency_cli.py --output deps.json
```

### Integrated CLI (Typer-based)
```bash
# Using the main wtf-codebot CLI
PYTHONPATH=. python wtf_codebot/cli/enhanced_cli.py dependencies --help

# Quick summary
PYTHONPATH=. python wtf_codebot/cli/enhanced_cli.py dependencies --format summary

# Generate comprehensive report
PYTHONPATH=. python wtf_codebot/cli/enhanced_cli.py dependencies --report html --output security_report.html
```

### Programmatic Usage

```python
from wtf_codebot.analyzers.dependency_analyzer import DependencyAnalyzer
from wtf_codebot.reporters.dependency_reporter import DependencyReporter

# Initialize analyzer
analyzer = DependencyAnalyzer()

# Analyze entire directory
results = analyzer.analyze_directory("/path/to/project")

# Analyze single file
result = analyzer.analyze_dependency_file("/path/to/package.json")

# Generate reports
reporter = DependencyReporter()
for result in results:
    reporter.add_result(result)

# Export in different formats
reporter.generate_html_report("report.html")
reporter.generate_json_report("data.json")
reporter.generate_markdown_report("report.md")
```

## Example Output

### Console Output
```
🔍 Dependency & Security Analysis
Analyzing: .

📦 Package Manager: npm
📄 File: ./package.json
🔍 Dependencies Found: 25
🚨 Vulnerabilities: 2
📜 License Types: 8

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Package             ┃ Version     ┃ Type               ┃ License            ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ express             │ ^4.18.0     │ prod               │ MIT                │
│ lodash              │ ^4.17.21    │ prod               │ MIT                │
│ jest                │ ^28.1.0     │ dev                │ MIT                │
└─────────────────────┴─────────────┴────────────────────┴────────────────────┘

🚨 Security Vulnerabilities (2)
┌─ Critical Vulnerability ─────────────────────────────────────────────────────┐
│ CVE ID: CVE-2023-1234                                                       │
│ Advisory ID: GHSA-xxxx-yyyy-zzzz                                            │
│ Severity: CRITICAL                                                          │
│ Source: GitHub Advisory Database                                            │
│ Affected Versions: >=4.0.0, <4.18.2                                        │
│ Fixed Versions: 4.18.2                                                      │
│ Description: Remote code execution vulnerability in Express.js middleware   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### HTML Report Preview
The HTML reports include:
- Executive summary with statistics
- Interactive dependency tables
- Vulnerability details with severity color coding
- License distribution charts
- Actionable recommendations
- Professional styling for presentations

## Architecture

### Core Components

#### `DependencyAnalyzer`
Main analysis engine that:
- Orchestrates the analysis process
- Manages different package manager parsers
- Coordinates vulnerability scanning
- Generates comprehensive results

#### Package Manager Parsers
- **`NPMParser`**: Handles `package.json` files
- **`PythonParser`**: Handles Python package files (requirements.txt, pyproject.toml, etc.)
- Extensible architecture for adding new parsers

#### `SecurityAdvisoryClient`
- Interfaces with multiple vulnerability databases
- Handles API rate limiting and error handling
- Normalizes vulnerability data across sources

#### `DependencyReporter`
- Generates reports in multiple formats
- Provides customizable templates
- Includes best practice recommendations

### Data Models

#### `DependencyInfo`
```python
@dataclass
class DependencyInfo:
    name: str
    version: str
    version_constraint: Optional[str] = None
    license: Optional[str] = None
    description: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    dev_dependency: bool = False
    optional: bool = False
```

#### `VulnerabilityInfo`
```python
@dataclass
class VulnerabilityInfo:
    cve_id: Optional[str] = None
    advisory_id: Optional[str] = None
    severity: str = "unknown"
    title: str = ""
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    source: str = ""
```

## Security Considerations

### Vulnerability Sources
- **GitHub Advisory Database**: Comprehensive, well-maintained
- **OSV Database**: Google's open source vulnerability database
- **Rate Limiting**: Automatic handling of API limits
- **Privacy**: No sensitive project data sent to external services

### Network Security
- All API calls use HTTPS
- Timeout protection (10 seconds default)
- Graceful degradation when APIs are unavailable
- Option to disable network requests entirely (`--no-network`)

## Best Practices

### For Development Teams
1. **Regular Scanning**: Run dependency analysis in CI/CD pipelines
2. **Vulnerability Monitoring**: Set up alerts for new vulnerabilities
3. **License Compliance**: Regular license audits
4. **Dependency Pinning**: Pin critical dependencies to specific versions

### For Security Teams
1. **Automated Reports**: Generate regular security reports
2. **Severity Prioritization**: Focus on Critical and High severity issues
3. **SBOM Generation**: Maintain software bill of materials
4. **Compliance Tracking**: Monitor license compliance

### For Operations Teams
1. **Monitoring**: Track dependency health metrics
2. **Update Planning**: Use reports for update prioritization
3. **Risk Assessment**: Evaluate security posture
4. **Documentation**: Maintain dependency documentation

## Integration Examples

### CI/CD Pipeline (GitHub Actions)
```yaml
name: Dependency Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run dependency analysis
        run: |
          python wtf_codebot/cli/dependency_cli.py \
            --output security-report.json \
            --format json
      - name: Upload security report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json
```

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
python wtf_codebot/cli/dependency_cli.py --vulnerabilities-only
if [ $? -ne 0 ]; then
    echo "Security vulnerabilities detected! Please review and fix."
    exit 1
fi
```

## Future Enhancements

### Planned Features
- **More Package Managers**: Go modules, Rust Cargo, Maven, Gradle
- **Advanced Analytics**: Dependency graph visualization, update impact analysis
- **Integration APIs**: REST API for programmatic access
- **Machine Learning**: Intelligent vulnerability prioritization
- **SBOM Standards**: Support for SPDX and CycloneDX formats

### Community Contributions
We welcome contributions for:
- New package manager support
- Additional vulnerability sources
- Report format improvements
- Performance optimizations
- Documentation enhancements

## Troubleshooting

### Common Issues

#### "No package manager files found"
- Ensure you're in the correct directory
- Check that package files exist (package.json, requirements.txt, etc.)
- Verify file permissions

#### Network/API Errors
- Use `--no-network` flag to skip vulnerability scanning
- Check internet connectivity
- GitHub/OSV APIs may have rate limits

#### Performance Issues
- Use `--no-network` for faster scanning
- Consider analyzing specific files instead of entire directories
- Large projects may take several minutes

### Debug Mode
```bash
# Enable verbose logging
python wtf_codebot/cli/dependency_cli.py --verbose
```

## Support

For issues, feature requests, or contributions:
- GitHub Issues: [Project Repository]
- Documentation: This file and inline code comments
- Examples: See `demo_dependency_analysis.py`

---

**Note**: This dependency analysis feature integrates with the broader wtf-codebot ecosystem and can be combined with other code analysis tools for comprehensive project evaluation.
