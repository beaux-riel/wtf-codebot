# Enhanced JSON Schema for Unified Findings Report

## Overview

The enhanced JSON schema provides a comprehensive structure for serializing unified code analysis findings with rich metadata, pattern recognition, security mappings, remediation suggestions, and quality metrics.

**Schema Version**: 2.0.0  
**Specification**: wtf-codebot-enhanced-findings

## Root Structure

```json
{
  "schema": {...},
  "metadata": {...},
  "statistics": {...},
  "findings": [...],
  "recommendations": [...],
  "quality_metrics": {...},
  "risk_assessment": {...}
}
```

## Schema Section

Defines the JSON schema version and specification details.

```json
{
  "schema": {
    "version": "2.0.0",
    "specification": "wtf-codebot-enhanced-findings",
    "documentation": "https://github.com/your-org/wtf-codebot/docs/json-schema.md"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Schema version following semantic versioning |
| `specification` | string | Unique identifier for this schema specification |
| `documentation` | string | URL to detailed schema documentation |

## Metadata Section

Contains comprehensive metadata about the report generation and analysis context.

```json
{
  "metadata": {
    "generated_at": "2025-07-05T16:18:31.466488",
    "tool": {
      "name": "wtf-codebot-enhanced",
      "version": "1.0.0",
      "schema_version": "2.0.0",
      "report_id": "wtf-codebot-20250705-161831"
    },
    "analysis": {
      "start_time": "2025-07-05T16:00:00.000000",
      "end_time": "2025-07-05T16:15:00.000000",
      "duration_seconds": 900.0,
      "total_files_analyzed": 6,
      "total_lines_analyzed": 1500
    },
    "configuration": {
      "analysis_types": ["static_analysis", "pattern_recognition", "security_scan"],
      "enabled_rules": ["all"],
      "severity_threshold": "info"
    },
    "environment": {
      "python_version": "3.10.13",
      "platform": "darwin",
      "cwd": "/Users/beauxwalton/wtf-codebot"
    },
    "collection_metadata": {...}
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `generated_at` | string (ISO 8601) | Timestamp when the report was generated |
| `tool.name` | string | Name of the analysis tool |
| `tool.version` | string | Version of the analysis tool |
| `tool.schema_version` | string | Version of the JSON schema used |
| `tool.report_id` | string | Unique identifier for this report |
| `analysis.start_time` | string (ISO 8601) | When the analysis started |
| `analysis.end_time` | string (ISO 8601) | When the analysis completed |
| `analysis.duration_seconds` | number | Total analysis duration in seconds |
| `analysis.total_files_analyzed` | number | Number of files analyzed |
| `analysis.total_lines_analyzed` | number | Total lines of code analyzed |
| `configuration` | object | Analysis configuration settings |
| `environment` | object | Runtime environment information |

## Statistics Section

Provides comprehensive statistics about the findings.

```json
{
  "statistics": {
    "total": 12,
    "severity_counts": {
      "critical": 1,
      "high": 1,
      "medium": 8,
      "low": 1,
      "info": 1
    },
    "type_counts": {
      "security_vulnerability": 1,
      "code_smell": 2,
      "anti_pattern": 1,
      "style_violation": 6,
      "outdated_dependency": 1,
      "design_pattern": 1
    },
    "source_counts": {
      "static_analyzer": 1,
      "linter": 7,
      "ai_analysis": 2,
      "dependency_analysis": 2
    },
    "affected_files_count": 6,
    "affected_files": ["/src/file1.py", "/src/file2.py"],
    "technical_debt": {
      "total_score": 61.32,
      "average_score": 5.11,
      "max_score": 15.0,
      "min_score": 0.46
    },
    "patterns": {
      "anti_pattern": 1,
      "creational_pattern": 1
    },
    "security": {
      "total_security_findings": 1,
      "unique_cwe_ids": ["CWE-89"],
      "unique_owasp_categories": ["A03:2021 – Injection"]
    }
  }
}
```

## Findings Section

Array of enhanced finding objects with comprehensive details.

### Enhanced Finding Structure

```json
{
  "id": "e07688a10b824cb7",
  "title": "Long method detected",
  "description": "Method has 150 lines, consider breaking it down into smaller methods",
  "finding_type": "code_smell",
  "severity": "medium",
  "confidence": 1.0,
  "source": "static_analyzer",
  "tool_name": "pylint",
  "rule_id": "too-many-lines",
  "location": {
    "file_path": "/src/user_service.py",
    "line_start": 45,
    "line_end": 195,
    "column_start": null,
    "column_end": null,
    "function_name": "process_user_data",
    "class_name": null
  },
  "affected_code": null,
  "message": "Method 'process_user_data' has too many lines (150/50)",
  "suggestion": "Break down into smaller, focused methods",
  "fix_recommendation": "",
  "metadata": {},
  "tags": ["maintainability", "complexity"],
  "detected_at": "2025-07-05T16:14:35.925982",
  "impact": "medium",
  "effort_to_fix": "medium",
  "related_findings": [],
  "duplicate_of": null,
  
  // Enhanced fields
  "pattern_info": {
    "pattern_id": "god_object",
    "name": "God Object",
    "category": "anti_pattern",
    "description": "A class that knows too much or does too much",
    "confidence_score": 0.85,
    "evidence": ["Large class size", "Multiple responsibilities", "High coupling"],
    "related_patterns": ["single_responsibility_violation", "high_coupling"]
  },
  "remediation": {
    "priority": "medium",
    "category": "refactor",
    "description": "Refactor code to improve maintainability",
    "steps": [
      "Identify the root cause of the code smell",
      "Extract methods or classes as needed",
      "Improve naming and structure",
      "Add or update documentation",
      "Write unit tests for refactored code"
    ],
    "code_example": null,
    "estimated_effort": "medium",
    "risk_level": "low",
    "prerequisites": [],
    "references": []
  },
  "impact_analysis": {
    "maintainability_impact": "medium",
    "security_impact": "minimal",
    "performance_impact": "minimal",
    "reliability_impact": "minimal"
  },
  "business_impact": "low",
  "technical_debt_score": 5.5,
  "security_info": {
    "cwe_ids": ["CWE-89"],
    "owasp_categories": ["A03:2021 – Injection"],
    "compliance_violations": ["PCI-DSS", "SOX"]
  }
}
```

### Core Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the finding |
| `title` | string | Human-readable title |
| `description` | string | Detailed description |
| `finding_type` | string | Type of finding (enum) |
| `severity` | string | Severity level (critical, high, medium, low, info) |
| `confidence` | number | Confidence score (0.0 - 1.0) |
| `source` | string | Source of the finding (enum) |
| `tool_name` | string | Name of the tool that detected this |
| `rule_id` | string | Specific rule identifier |
| `message` | string | Raw message from the tool |
| `suggestion` | string | Suggestion for fixing |
| `detected_at` | string (ISO 8601) | When the finding was detected |

### Enhanced Fields

#### Pattern Information

| Field | Type | Description |
|-------|------|-------------|
| `pattern_info.pattern_id` | string | Unique pattern identifier |
| `pattern_info.name` | string | Human-readable pattern name |
| `pattern_info.category` | string | Pattern category |
| `pattern_info.description` | string | Pattern description |
| `pattern_info.confidence_score` | number | Confidence in pattern detection |
| `pattern_info.evidence` | array | Evidence supporting pattern detection |
| `pattern_info.related_patterns` | array | Related pattern identifiers |

#### Remediation Suggestions

| Field | Type | Description |
|-------|------|-------------|
| `remediation.priority` | string | Priority level (immediate, high, medium, low) |
| `remediation.category` | string | Category (refactor, fix, optimize, modernize) |
| `remediation.description` | string | Remediation description |
| `remediation.steps` | array | Step-by-step remediation instructions |
| `remediation.code_example` | string | Example code for fix |
| `remediation.estimated_effort` | string | Effort estimate (low, medium, high) |
| `remediation.risk_level` | string | Risk level of applying fix |
| `remediation.prerequisites` | array | Prerequisites for remediation |
| `remediation.references` | array | Reference links and documentation |

#### Impact Analysis

| Field | Type | Description |
|-------|------|-------------|
| `impact_analysis.maintainability_impact` | string | Impact on code maintainability |
| `impact_analysis.security_impact` | string | Security impact level |
| `impact_analysis.performance_impact` | string | Performance impact level |
| `impact_analysis.reliability_impact` | string | Reliability impact level |

#### Security Information

| Field | Type | Description |
|-------|------|-------------|
| `security_info.cwe_ids` | array | Common Weakness Enumeration IDs |
| `security_info.owasp_categories` | array | OWASP Top 10 categories |
| `security_info.compliance_violations` | array | Compliance standard violations |

## Recommendations Section

Global recommendations based on findings patterns.

```json
{
  "recommendations": [
    {
      "priority": "immediate",
      "category": "security",
      "title": "Address Critical Security Issues",
      "description": "Found 1 critical issues that require immediate attention",
      "action": "Review and fix all critical security vulnerabilities before deployment"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `priority` | string | Recommendation priority |
| `category` | string | Recommendation category |
| `title` | string | Recommendation title |
| `description` | string | Detailed description |
| `action` | string | Recommended action |

## Quality Metrics Section

Overall code quality assessment.

```json
{
  "quality_metrics": {
    "overall_score": 72.5,
    "grade": "C",
    "total_issues": 12,
    "weighted_severity_score": 32.1
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `overall_score` | number | Overall quality score (0-100) |
| `grade` | string | Letter grade (A, B, C, D, F) |
| `total_issues` | number | Total number of issues |
| `weighted_severity_score` | number | Weighted score based on severity |

## Risk Assessment Section

Risk analysis based on findings.

```json
{
  "risk_assessment": {
    "overall_risk_level": "high",
    "security_risk_factors": 1,
    "critical_issues": 1,
    "high_priority_issues": 1,
    "risk_score": 50
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `overall_risk_level` | string | Overall risk level (minimal, low, medium, high) |
| `security_risk_factors` | number | Number of security-related findings |
| `critical_issues` | number | Number of critical severity issues |
| `high_priority_issues` | number | Number of high severity issues |
| `risk_score` | number | Calculated risk score (0-100) |

## Enumerations

### Finding Types

- `code_smell` - Code quality issues
- `design_pattern` - Detected design patterns
- `anti_pattern` - Anti-pattern detection
- `security_vulnerability` - Security issues
- `outdated_dependency` - Dependency management issues
- `style_violation` - Code style issues
- `performance_issue` - Performance problems
- `missing_documentation` - Documentation issues

### Severity Levels

- `critical` - Critical issues requiring immediate attention
- `high` - High priority issues
- `medium` - Medium priority issues
- `low` - Low priority issues
- `info` - Informational findings

### Source Types

- `static_analyzer` - Static analysis tools
- `linter` - Code linters
- `ai_analysis` - AI-powered analysis
- `dependency_analysis` - Dependency analysis tools
- `security_scanner` - Security scanning tools

## Usage Examples

### Loading and Processing

```python
import json
from pathlib import Path

# Load the enhanced JSON report
with open('enhanced_unified_findings.json', 'r') as f:
    report = json.load(f)

# Access findings
findings = report['findings']
for finding in findings:
    print(f"Issue: {finding['title']}")
    print(f"Severity: {finding['severity']}")
    if finding.get('pattern_info'):
        print(f"Pattern: {finding['pattern_info']['name']}")
    if finding.get('remediation'):
        print(f"Fix: {finding['remediation']['description']}")
```

### Filtering by Criteria

```python
# Get critical security issues
critical_security = [
    f for f in findings 
    if f['severity'] == 'critical' and 
       f['finding_type'] == 'security_vulnerability'
]

# Get findings with remediation suggestions
with_remediation = [
    f for f in findings 
    if f.get('remediation') is not None
]

# Get pattern-based findings
pattern_findings = [
    f for f in findings 
    if f.get('pattern_info') is not None
]
```

## Integration with CI/CD

The enhanced JSON format is designed for easy integration with CI/CD pipelines:

```bash
# Generate report
python enhanced_json_reporter.py

# Process with jq for CI/CD decisions
critical_count=$(jq '.statistics.severity_counts.critical // 0' enhanced_unified_findings.json)
if [ "$critical_count" -gt 0 ]; then
    echo "❌ Critical issues found: $critical_count"
    exit 1
fi

# Extract quality score
quality_score=$(jq '.quality_metrics.overall_score' enhanced_unified_findings.json)
echo "Quality Score: $quality_score"
```

## Changelog

### Version 2.0.0
- Added comprehensive pattern recognition
- Enhanced remediation suggestions with detailed steps
- Added security mappings (CWE, OWASP)
- Introduced technical debt scoring
- Added impact analysis across multiple dimensions
- Added global recommendations and risk assessment
- Enhanced metadata with environment and configuration details

### Version 1.0.0
- Initial unified findings format
- Basic finding structure with core fields
- Simple statistics and metadata
