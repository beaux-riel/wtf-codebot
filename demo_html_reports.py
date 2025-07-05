#!/usr/bin/env python3
"""
Demo: HTML Report Generation

This script demonstrates how to generate interactive HTML reports
from JSON findings and dependency analysis data using both the
basic and enhanced HTML report generators.
"""

import json
import logging
from pathlib import Path
from datetime import datetime

from html_report_generator import InteractiveHTMLReporter
from enhanced_html_reporter import EnhancedHTMLReporter

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_sample_data():
    """Generate sample data for demonstration purposes."""
    print("Generating sample data for demonstration...")
    
    # Sample findings data
    sample_findings = {
        "schema": {"version": "2.0.0"},
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": {"name": "wtf-codebot", "version": "1.0.0"}
        },
        "statistics": {
            "total_findings": 5,
            "severity_distribution": {
                "critical": 1,
                "high": 1,
                "medium": 2,
                "low": 1
            }
        },
        "findings": [
            {
                "id": "demo-001",
                "title": "SQL Injection Vulnerability",
                "severity": "critical",
                "finding_type": "security_vulnerability",
                "description": "Potential SQL injection in user input handling",
                "location": {
                    "file_path": "/src/database.py",
                    "line_start": 45,
                    "line_end": 47,
                    "function_name": "execute_query"
                },
                "confidence": 0.95,
                "technical_debt_score": 9.5,
                "business_impact": "high",
                "effort_to_fix": "medium",
                "source": "static_analyzer",
                "tool_name": "bandit",
                "detected_at": datetime.now().isoformat(),
                "tags": ["security", "database"],
                "security_info": {
                    "cwe_ids": ["CWE-89"],
                    "owasp_categories": ["A03:2021 – Injection"]
                },
                "remediation": {
                    "priority": "immediate",
                    "description": "Use parameterized queries to prevent SQL injection",
                    "category": "fix"
                }
            },
            {
                "id": "demo-002",
                "title": "Long Method Detected",
                "severity": "high",
                "finding_type": "code_smell",
                "description": "Method exceeds recommended length of 50 lines",
                "location": {
                    "file_path": "/src/user_service.py",
                    "line_start": 120,
                    "line_end": 190,
                    "function_name": "process_user_data",
                    "class_name": "UserService"
                },
                "confidence": 1.0,
                "technical_debt_score": 6.5,
                "business_impact": "medium",
                "effort_to_fix": "high",
                "source": "linter",
                "tool_name": "pylint",
                "detected_at": datetime.now().isoformat(),
                "tags": ["maintainability", "complexity"]
            },
            {
                "id": "demo-003",
                "title": "Unused Import",
                "severity": "medium",
                "finding_type": "style_violation",
                "description": "Import statement is not used",
                "location": {
                    "file_path": "/src/utils.py",
                    "line_start": 5,
                    "line_end": 5
                },
                "confidence": 1.0,
                "technical_debt_score": 1.0,
                "business_impact": "low",
                "effort_to_fix": "low",
                "source": "linter",
                "tool_name": "flake8",
                "detected_at": datetime.now().isoformat(),
                "tags": ["style", "imports"]
            },
            {
                "id": "demo-004",
                "title": "Performance Issue",
                "severity": "medium",
                "finding_type": "performance_issue",
                "description": "Inefficient loop implementation",
                "location": {
                    "file_path": "/src/analyzer.py",
                    "line_start": 78,
                    "line_end": 85,
                    "function_name": "analyze_data"
                },
                "confidence": 0.8,
                "technical_debt_score": 4.5,
                "business_impact": "medium",
                "effort_to_fix": "medium",
                "source": "profiler",
                "tool_name": "py-spy",
                "detected_at": datetime.now().isoformat(),
                "tags": ["performance", "optimization"]
            },
            {
                "id": "demo-005",
                "title": "Missing Documentation",
                "severity": "low",
                "finding_type": "missing_documentation",
                "description": "Public method lacks docstring",
                "location": {
                    "file_path": "/src/api.py",
                    "line_start": 25,
                    "line_end": 30,
                    "function_name": "get_user",
                    "class_name": "UserAPI"
                },
                "confidence": 1.0,
                "technical_debt_score": 2.0,
                "business_impact": "low",
                "effort_to_fix": "low",
                "source": "documentation_checker",
                "tool_name": "pydocstyle",
                "detected_at": datetime.now().isoformat(),
                "tags": ["documentation", "maintainability"]
            }
        ],
        "quality_metrics": {
            "overall_score": 75.0,
            "grade": "B",
            "total_issues": 5
        },
        "risk_assessment": {
            "overall_risk_level": "medium",
            "security_risk_factors": 1,
            "critical_issues": 1,
            "high_priority_issues": 1
        },
        "recommendations": [
            {
                "priority": "immediate",
                "category": "security",
                "title": "Fix SQL Injection Vulnerability",
                "description": "Address the critical SQL injection vulnerability immediately",
                "action": "Use parameterized queries"
            },
            {
                "priority": "high",
                "category": "maintainability",
                "title": "Refactor Long Methods",
                "description": "Break down large methods to improve maintainability",
                "action": "Extract smaller, focused methods"
            }
        ]
    }
    
    # Sample dependencies data
    sample_dependencies = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "dependency-analyzer",
            "version": "1.0.0",
            "total_files": 1,
            "total_dependencies": 5
        },
        "summary": {
            "total_dependencies": 5,
            "total_vulnerabilities": 0,
            "license_distribution": {
                "MIT": 3,
                "Apache-2.0": 1,
                "BSD-3-Clause": 1
            }
        },
        "results": [
            {
                "package_manager": "pip",
                "file_path": "/requirements.txt",
                "dependencies": {
                    "flask": {
                        "name": "flask",
                        "version": "2.3.2",
                        "license": "MIT",
                        "description": "A simple framework for building complex web applications",
                        "dev_dependency": False
                    },
                    "requests": {
                        "name": "requests",
                        "version": "2.31.0",
                        "license": "Apache-2.0",
                        "description": "Python HTTP for Humans",
                        "dev_dependency": False
                    },
                    "jinja2": {
                        "name": "jinja2",
                        "version": "3.1.2",
                        "license": "BSD-3-Clause",
                        "description": "A very fast and expressive template engine",
                        "dev_dependency": False
                    },
                    "pytest": {
                        "name": "pytest",
                        "version": "7.4.0",
                        "license": "MIT",
                        "description": "pytest: simple powerful testing with Python",
                        "dev_dependency": True
                    },
                    "black": {
                        "name": "black",
                        "version": "23.7.0",
                        "license": "MIT",
                        "description": "The uncompromising code formatter",
                        "dev_dependency": True
                    }
                }
            }
        ]
    }
    
    # Write sample data to files
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    sample_findings_path = reports_dir / "sample_findings.json"
    with open(sample_findings_path, 'w') as f:
        json.dump(sample_findings, f, indent=2)
    
    sample_dependencies_path = reports_dir / "sample_dependencies.json"
    with open(sample_dependencies_path, 'w') as f:
        json.dump(sample_dependencies, f, indent=2)
    
    print(f"Sample data written to:")
    print(f"  - {sample_findings_path}")
    print(f"  - {sample_dependencies_path}")
    
    return str(sample_findings_path), str(sample_dependencies_path)


def demo_basic_html_report():
    """Demonstrate basic HTML report generation."""
    print("\n" + "="*60)
    print("DEMO: Basic Interactive HTML Report")
    print("="*60)
    
    # Generate sample data
    findings_path, deps_path = generate_sample_data()
    
    # Initialize basic reporter
    reporter = InteractiveHTMLReporter()
    
    # Generate basic report
    output_path = "reports/demo_basic_report.html"
    
    print("Generating basic interactive HTML report...")
    generated_path = reporter.generate_interactive_report(
        findings_json_path=findings_path,
        dependencies_json_path=deps_path,
        output_path=output_path,
        title="Demo - Basic Interactive Report"
    )
    
    print(f"✓ Basic report generated: {generated_path}")
    print(f"  Open in browser: file://{Path(generated_path).absolute()}")
    
    # Show features
    print("\nBasic Report Features:")
    print("  ✓ Bootstrap-styled responsive design")
    print("  ✓ Chart.js visualizations (pie, bar, line charts)")
    print("  ✓ DataTables for sortable/filterable findings")
    print("  ✓ Vis.js dependency network graph")
    print("  ✓ Interactive finding details modals")
    print("  ✓ Severity and type filtering")
    print("  ✓ Executive dashboard overview")
    
    return generated_path


def demo_enhanced_html_report():
    """Demonstrate enhanced HTML report generation with Plotly."""
    print("\n" + "="*60)
    print("DEMO: Enhanced Interactive HTML Report with Plotly")
    print("="*60)
    
    # Use existing sample data
    findings_path = "reports/sample_findings.json"
    deps_path = "reports/sample_dependencies.json"
    
    # Initialize enhanced reporter
    reporter = EnhancedHTMLReporter()
    
    # Generate enhanced report
    output_path = "reports/demo_enhanced_report.html"
    
    print("Generating enhanced interactive HTML report with Plotly...")
    generated_path = reporter.generate_enhanced_report(
        findings_json_path=findings_path,
        dependencies_json_path=deps_path,
        output_path=output_path,
        title="Demo - Enhanced Interactive Report with Plotly"
    )
    
    print(f"✓ Enhanced report generated: {generated_path}")
    print(f"  Open in browser: file://{Path(generated_path).absolute()}")
    
    # Show enhanced features
    print("\nEnhanced Report Features:")
    print("  ✓ All basic features plus:")
    print("  ✓ Plotly.js advanced visualizations")
    print("  ✓ 3D dependency network graphs")
    print("  ✓ Technical debt heatmaps")
    print("  ✓ Sunburst complexity breakdown charts")
    print("  ✓ Security risk matrix heatmaps")
    print("  ✓ Multi-axis trend analysis")
    print("  ✓ Global filtering system")
    print("  ✓ Chart export capabilities")
    print("  ✓ Interactive chart controls")
    print("  ✓ Executive dashboard with trend indicators")
    
    return generated_path


def demo_custom_report():
    """Demonstrate customizing the HTML report generator."""
    print("\n" + "="*60)
    print("DEMO: Custom HTML Report Configuration")
    print("="*60)
    
    # Create a custom reporter with specific configuration
    custom_reporter = InteractiveHTMLReporter(template_dir="custom_templates")
    
    # Use existing sample data
    findings_path = "reports/sample_findings.json"
    deps_path = "reports/sample_dependencies.json"
    
    print("Generating custom configured HTML report...")
    
    # You can customize the report by:
    # 1. Providing custom templates
    # 2. Modifying the data processing
    # 3. Adding custom filters
    
    # Example: Generate with custom title and filtering
    output_path = "reports/demo_custom_report.html"
    generated_path = custom_reporter.generate_interactive_report(
        findings_json_path=findings_path,
        dependencies_json_path=deps_path,
        output_path=output_path,
        title="Custom Demo Report - Security Focus"
    )
    
    print(f"✓ Custom report generated: {generated_path}")
    print(f"  Open in browser: file://{Path(generated_path).absolute()}")
    
    print("\nCustomization Options:")
    print("  ✓ Custom Jinja2 templates")
    print("  ✓ Custom CSS styling")
    print("  ✓ Custom JavaScript functionality")
    print("  ✓ Custom data processing and filtering")
    print("  ✓ Custom chart types and visualizations")
    print("  ✓ Custom metrics and calculations")
    
    return generated_path


def compare_reports():
    """Compare features between basic and enhanced reports."""
    print("\n" + "="*60)
    print("COMPARISON: Basic vs Enhanced HTML Reports")
    print("="*60)
    
    comparison = {
        "Feature": [
            "Bootstrap Styling",
            "Responsive Design", 
            "Chart.js Charts",
            "DataTables",
            "Vis.js Network Graph",
            "Interactive Modals",
            "Basic Filtering",
            "Executive Dashboard",
            "Plotly.js Charts",
            "3D Visualizations",
            "Heatmaps",
            "Sunburst Charts",
            "Advanced Analytics Tab",
            "Global Filtering",
            "Chart Export",
            "Trend Analysis",
            "Security Matrix",
            "Interactive Controls"
        ],
        "Basic Report": [
            "✓", "✓", "✓", "✓", "✓", "✓", "✓", "✓",
            "✗", "✗", "✗", "✗", "✗", "✗", "✗", "✗", "✗", "✗"
        ],
        "Enhanced Report": [
            "✓", "✓", "✓", "✓", "✓", "✓", "✓", "✓",
            "✓", "✓", "✓", "✓", "✓", "✓", "✓", "✓", "✓", "✓"
        ]
    }
    
    # Print comparison table
    print(f"{'Feature':<25} {'Basic':<8} {'Enhanced':<8}")
    print("-" * 45)
    for i, feature in enumerate(comparison["Feature"]):
        basic = comparison["Basic Report"][i]
        enhanced = comparison["Enhanced Report"][i]
        print(f"{feature:<25} {basic:<8} {enhanced:<8}")
    
    print("\nRecommendations:")
    print("  • Use Basic Report for: Simple analysis, quick overview, minimal dependencies")
    print("  • Use Enhanced Report for: Advanced analytics, executive presentations, detailed analysis")


def print_usage_examples():
    """Print code examples for using the HTML report generators."""
    print("\n" + "="*60)
    print("USAGE EXAMPLES")
    print("="*60)
    
    basic_example = '''
# Basic HTML Report Generation
from html_report_generator import InteractiveHTMLReporter

reporter = InteractiveHTMLReporter()
report_path = reporter.generate_interactive_report(
    findings_json_path="findings.json",
    dependencies_json_path="dependencies.json",
    output_path="report.html",
    title="My Code Analysis Report"
)
print(f"Report generated: {report_path}")
'''
    
    enhanced_example = '''
# Enhanced HTML Report with Plotly
from enhanced_html_reporter import EnhancedHTMLReporter

reporter = EnhancedHTMLReporter()
report_path = reporter.generate_enhanced_report(
    findings_json_path="findings.json", 
    dependencies_json_path="dependencies.json",
    output_path="enhanced_report.html",
    title="Advanced Analysis Report"
)
print(f"Enhanced report generated: {report_path}")
'''
    
    custom_example = '''
# Custom Template Directory
from html_report_generator import InteractiveHTMLReporter

reporter = InteractiveHTMLReporter(template_dir="my_templates")
# Modify templates in my_templates/ directory
# - main_report.html
# - charts.html  
# - tables.html
# - dependencies.html
# - styles.css

report_path = reporter.generate_interactive_report(
    findings_json_path="findings.json",
    output_path="custom_report.html"
)
'''
    
    print("Basic Report Example:")
    print(basic_example)
    
    print("Enhanced Report Example:")
    print(enhanced_example)
    
    print("Custom Templates Example:")
    print(custom_example)


def main():
    """Run all HTML report generation demos."""
    print("HTML Report Generation Demo")
    print("=" * 60)
    print("This demo shows how to generate interactive HTML reports")
    print("from JSON findings and dependency analysis data.")
    
    try:
        # Generate sample data and basic report
        basic_path = demo_basic_html_report()
        
        # Generate enhanced report
        enhanced_path = demo_enhanced_html_report()
        
        # Show custom configuration options
        custom_path = demo_custom_report()
        
        # Compare features
        compare_reports()
        
        # Show usage examples
        print_usage_examples()
        
        # Final summary
        print("\n" + "="*60)
        print("DEMO COMPLETE")
        print("="*60)
        print(f"Generated Reports:")
        print(f"  1. Basic Report:    {basic_path}")
        print(f"  2. Enhanced Report: {enhanced_path}")
        print(f"  3. Custom Report:   {custom_path}")
        print()
        print("Open any of these files in your web browser to view the interactive reports.")
        print()
        print("Next Steps:")
        print("  • Integrate with your existing analysis pipeline")
        print("  • Customize templates for your organization's branding")
        print("  • Add custom visualizations for specific metrics")
        print("  • Set up automated report generation in CI/CD")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise


if __name__ == "__main__":
    main()
