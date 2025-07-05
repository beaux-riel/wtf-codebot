# Pattern Recognition System

## Overview

The Pattern Recognition System is a comprehensive solution for analyzing code patterns, anti-patterns, and code quality issues using Claude AI. It implements Step 7 of the broader plan: "Batch code context and call Claude for pattern recognition."

## Features

### 🚀 Core Capabilities

- **Design Pattern Detection**: Identifies well-known software design patterns (Singleton, Factory, Observer, etc.)
- **Anti-Pattern Recognition**: Detects code smells and poor practices (God Object, Spaghetti Code, etc.)
- **Code Quality Analysis**: Finds security vulnerabilities, performance issues, and maintainability concerns
- **Token-Efficient Batching**: Intelligently chunks code into optimal batches for AI analysis
- **Cost Tracking & Budget Management**: Monitors API usage and enforces budget limits
- **Retry Logic & Error Handling**: Robust error handling with exponential backoff
- **Streaming Support**: Real-time pattern detection with streaming responses
- **Multiple Output Formats**: JSON, CSV, and Markdown reports

### 🛠 Key Components

1. **Code Batcher** (`batcher.py`)
   - Intelligently splits code into token-efficient batches
   - AST-aware chunking for structured languages
   - Configurable batch sizes and overlap
   - File prioritization and filtering

2. **Claude Pattern Analyzer** (`claude_client.py`)
   - Claude API integration with retry logic
   - Streaming and standard analysis modes
   - Comprehensive prompt engineering for pattern detection
   - Token counting and usage optimization

3. **Cost Tracker** (`cost_tracker.py`)
   - Real-time cost calculation and tracking
   - Budget limits with alerts and enforcement
   - Usage analytics and reporting
   - Historical data persistence

4. **Pattern Data Models** (`patterns.py`)
   - Comprehensive pattern type definitions
   - Structured data models for analysis results
   - Serialization and reporting capabilities

5. **Orchestrator** (`orchestrator.py`)
   - High-level coordination of the analysis pipeline
   - Configuration management
   - Result aggregation and reporting

## Installation & Setup

### Prerequisites

```bash
pip install anthropic tiktoken
```

### Environment Configuration

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or create a `.env` file:

```
ANTHROPIC_API_KEY=your-api-key-here
ANTHROPIC_MODEL=claude-3-sonnet-20240229
```

## Usage

### Quick Start

```python
import asyncio
from pathlib import Path
from wtf_codebot.discovery.scanner import CodebaseScanner
from wtf_codebot.pattern_recognition import analyze_codebase_patterns

async def main():
    # Scan your codebase
    scanner = CodebaseScanner()
    codebase = await scanner.scan_codebase(Path("."))
    
    # Analyze patterns with default settings
    results = await analyze_codebase_patterns(
        codebase=codebase,
        output_dir=Path("pattern_results"),
        budget_limit=10.0  # $10 daily limit
    )
    
    print(f"Found {len(results.get_all_patterns())} patterns")

asyncio.run(main())
```

### Advanced Configuration

```python
from wtf_codebot.pattern_recognition import (
    PatternRecognitionOrchestrator,
    PatternRecognitionConfig
)

config = PatternRecognitionConfig(
    # Batching settings
    max_tokens_per_batch=75000,
    batch_overlap_tokens=2000,
    min_batch_size=1000,
    
    # Analysis settings
    concurrent_requests=3,
    enable_streaming=True,
    retry_max_attempts=3,
    
    # Cost management
    enable_cost_tracking=True,
    daily_budget_limit=50.0,
    monthly_budget_limit=500.0,
    
    # Output settings
    output_formats=["json", "markdown", "csv"],
    output_directory=Path("custom_results"),
    save_batches=True,
    
    # File filtering
    exclude_patterns=[
        "**/test/**", "**/tests/**", 
        "**/node_modules/**", "**/.git/**"
    ],
    prioritize_files=["**/src/**", "**/lib/**"]
)

orchestrator = PatternRecognitionOrchestrator(config)
results = await orchestrator.analyze_codebase(codebase)
```

## Pattern Types Detected

### Design Patterns

- **Creational**: Singleton, Factory, Builder, Prototype, Abstract Factory
- **Structural**: Adapter, Bridge, Composite, Decorator, Facade, Flyweight, Proxy
- **Behavioral**: Observer, Strategy, Command, State, Template Method, Visitor, etc.

### Anti-Patterns

- **Code Structure**: God Object, Spaghetti Code, Large Class, Long Method
- **Design Issues**: Feature Envy, Inappropriate Intimacy, Refused Bequest
- **Maintenance**: Dead Code, Duplicate Code, Magic Numbers, Comments
- **Architecture**: Shotgun Surgery, Divergent Change, Parallel Inheritance

### Code Quality Issues

- **Security**: SQL Injection, XSS vulnerabilities, Insecure configurations
- **Performance**: Inefficient algorithms, Memory leaks, N+1 queries
- **Complexity**: High cyclomatic complexity, Deep nesting, Long parameter lists
- **Maintainability**: Technical debt, Code smells, Architectural violations

## Output Formats

### JSON Report

```json
{
  "design_patterns": [
    {
      "pattern_type": "singleton",
      "confidence": 0.9,
      "file_path": "src/config.py",
      "line_start": 15,
      "line_end": 30,
      "description": "Singleton pattern implementation",
      "benefits": ["Controlled instantiation", "Global access"],
      "severity": "info"
    }
  ],
  "anti_patterns": [
    {
      "pattern_type": "god_object",
      "confidence": 0.8,
      "file_path": "src/main.py",
      "line_start": 1,
      "line_end": 500,
      "description": "Class with too many responsibilities",
      "problems": ["Poor maintainability", "High coupling"],
      "solutions": ["Split into focused classes"],
      "severity": "error"
    }
  ],
  "summary": {
    "total_patterns": 15,
    "critical_issues": 2,
    "high_issues": 5,
    "analysis_duration": 45.2
  }
}
```

### Markdown Report

```markdown
# Pattern Analysis Results

## Summary
- **Total Patterns Found**: 15
- **Design Patterns**: 8
- **Anti-patterns**: 5
- **Quality Issues**: 2

### Singleton
- **File**: `src/config.py`
- **Lines**: 15-30
- **Confidence**: 0.90
- **Description**: Singleton pattern implementation
```

## Cost Management

### Budget Configuration

```python
from wtf_codebot.pattern_recognition import CostBudget

budget = CostBudget(
    daily_limit=10.0,      # $10 per day
    monthly_limit=200.0,   # $200 per month
    total_limit=1000.0,    # $1000 total
    alert_threshold=0.8    # Alert at 80% usage
)
```

### Cost Tracking

```python
# Get usage summary
cost_summary = orchestrator.get_cost_summary()
print(f"Total cost: ${cost_summary['usage_summary']['total_cost']:.2f}")

# Export detailed usage data
orchestrator.export_cost_data(Path("usage_export.json"))
```

## Performance Optimization

### Batch Size Tuning

- **Large codebases**: Use smaller batches (50K-75K tokens) for more granular analysis
- **Small projects**: Use larger batches (100K+ tokens) for efficiency
- **API rate limits**: Reduce concurrent requests if hitting rate limits

### Token Optimization

- Use `exclude_patterns` to skip irrelevant files
- Set `prioritize_files` to analyze important code first
- Enable `chunk_large_files` for better token utilization

### Cost Optimization

- Set appropriate budget limits to control costs
- Use streaming mode for faster feedback
- Monitor token usage with detailed tracking

## Error Handling

The system includes comprehensive error handling:

- **API Errors**: Automatic retry with exponential backoff
- **Rate Limiting**: Built-in rate limit handling and delays
- **Budget Limits**: Automatic analysis stopping when budgets are exceeded
- **Token Limits**: Intelligent chunking to stay within model limits
- **Network Issues**: Resilient connection handling

## Demo & Testing

### Run Tests

```bash
python test_pattern_recognition.py
```

### Run Demo

```bash
python demo_pattern_recognition.py
```

The demo will:
1. Scan the current codebase
2. Create optimized code batches
3. Analyze patterns using Claude
4. Generate comprehensive reports
5. Show cost and usage statistics

## Integration Examples

### CI/CD Integration

```yaml
- name: Pattern Analysis
  run: |
    python -c "
    import asyncio
    from wtf_codebot.pattern_recognition import analyze_codebase_patterns
    from wtf_codebot.discovery.scanner import CodebaseScanner
    
    async def main():
        scanner = CodebaseScanner()
        codebase = await scanner.scan_codebase('.')
        results = await analyze_codebase_patterns(codebase, budget_limit=5.0)
        critical_issues = len(results.get_patterns_by_severity('critical'))
        if critical_issues > 0:
            exit(1)
    
    asyncio.run(main())
    "
```

### Custom Analysis Pipeline

```python
# Create custom analysis for specific file types
python_files = [f for f in codebase.files.values() 
                if f.file_type == FileType.PYTHON]

results = await orchestrator.analyze_files(python_files)

# Filter results by confidence
high_confidence_patterns = [
    p for p in results.get_all_patterns() 
    if p.confidence > 0.8
]
```

## Configuration Reference

### BatchConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_tokens_per_batch` | 100000 | Maximum tokens per batch |
| `overlap_tokens` | 2000 | Token overlap between batches |
| `min_batch_size` | 1000 | Minimum tokens to create a batch |
| `prioritize_files` | [] | File patterns to prioritize |
| `exclude_patterns` | [] | Patterns to exclude |
| `include_metadata` | True | Include file metadata |
| `chunk_large_files` | True | Chunk large files |

### RetryConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | 3 | Maximum retry attempts |
| `base_delay` | 1.0 | Base delay in seconds |
| `max_delay` | 60.0 | Maximum delay in seconds |
| `exponential_base` | 2.0 | Exponential backoff base |
| `jitter` | True | Add random jitter |

## Troubleshooting

### Common Issues

1. **API Key Not Set**
   ```
   ERROR: ANTHROPIC_API_KEY not set!
   ```
   Solution: Set the environment variable or update config file

2. **Budget Exceeded**
   ```
   RuntimeError: Budget limits exceeded
   ```
   Solution: Increase budget limits or wait for reset

3. **Rate Limiting**
   ```
   anthropic.RateLimitError
   ```
   Solution: Reduce concurrent requests or add delays

4. **Large Files**
   ```
   Token limit exceeded
   ```
   Solution: Enable `chunk_large_files` or increase `max_tokens_per_batch`

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

The pattern recognition system is designed to be extensible:

1. **Add New Pattern Types**: Extend the `PatternType` enum
2. **Custom Prompts**: Modify the analysis prompts in `claude_client.py`
3. **New Output Formats**: Add format handlers in the analyzer
4. **Custom Batching**: Implement new batching strategies

## License

This pattern recognition system is part of the WTF CodeBot project and follows the same licensing terms.

## Support

For issues, feature requests, or questions:

1. Check the troubleshooting section above
2. Run the test suite to verify functionality
3. Review the demo script for usage examples
4. Check configuration parameters for optimization opportunities

---

**Next Steps**: After running pattern analysis, consider integrating the results into your development workflow, setting up automated quality gates, and establishing regular pattern monitoring for your codebase.
