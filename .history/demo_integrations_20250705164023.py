#!/usr/bin/env python3
"""
Demo script showing WTF CodeBot integrations functionality.

This script demonstrates:
1. Creating sample findings
2. Configuring various integrations (GitHub Issues, Slack, JIRA, Webhook)
3. Exporting to multiple formats (SARIF, HTML, CSV, JSON)
4. Testing integrations in dry-run mode
"""

import logging
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from wtf_codebot.findings.models import (
    FindingsCollection, 
    UnifiedFinding, 
    SourceLocation,
    FindingSeverity,
    FindingType,
    FindingSource
)
from wtf_codebot.integrations.manager import IntegrationsManager, IntegrationsConfig
from wtf_codebot.integrations.github_issues import GitHubIssuesConfig
from wtf_codebot.integrations.slack import SlackConfig
from wtf_codebot.integrations.jira import JiraConfig
from wtf_codebot.integrations.webhook import WebhookConfig


def create_sample_findings() -> FindingsCollection:
    """Create sample findings for testing integrations."""
    
    findings = []
    
    # Critical security vulnerability
    findings.append(UnifiedFinding(
        title="SQL Injection vulnerability in user authentication",
        description="Direct string concatenation in SQL query allows for SQL injection attacks",
        finding_type=FindingType.SECURITY_VULNERABILITY,
        severity=FindingSeverity.CRITICAL,
        source=FindingSource.SECURITY_SCANNER,
        tool_name="bandit",
        rule_id="B608",
        location=SourceLocation(
            file_path="src/auth/login.py",
            line_start=45,
            line_end=48,
            function_name="authenticate_user",
            class_name="AuthController"
        ),
        affected_code='query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"',
        message="Use parameterized queries to prevent SQL injection",
        suggestion="Replace string concatenation with parameterized query using ORM or prepared statements",
        fix_recommendation="Use SQLAlchemy ORM or parameterized queries: query = session.query(User).filter_by(username=username, password=hash_password(password))",
        confidence=0.95,
        impact="high",
        effort_to_fix="medium",
        tags={"security", "sql-injection", "authentication"},
        detected_at=datetime.now()
    ))
    
    # High severity code smell
    findings.append(UnifiedFinding(
        title="Complex method with high cyclomatic complexity",
        description="Method has cyclomatic complexity of 15, exceeding recommended threshold of 10",
        finding_type=FindingType.CYCLOMATIC_COMPLEXITY,
        severity=FindingSeverity.HIGH,
        source=FindingSource.STATIC_ANALYZER,
        tool_name="radon",
        rule_id="CC01",
        location=SourceLocation(
            file_path="src/business/order_processor.py",
            line_start=123,
            line_end=187,
            function_name="process_order",
            class_name="OrderProcessor"
        ),
        message="Method is too complex and should be refactored",
        suggestion="Break down the method into smaller, more focused methods",
        fix_recommendation="Extract order validation, payment processing, and inventory checks into separate methods",
        confidence=0.9,
        impact="medium",
        effort_to_fix="high",
        tags={"complexity", "refactoring", "maintainability"},
        detected_at=datetime.now()
    ))
    
    # Medium severity performance issue
    findings.append(UnifiedFinding(
        title="Inefficient database query in loop",
        description="Database query executed inside a loop, causing N+1 query problem",
        finding_type=FindingType.PERFORMANCE_ISSUE,
        severity=FindingSeverity.MEDIUM,
        source=FindingSource.AI_ANALYSIS,
        tool_name="wtf-codebot-ai",
        location=SourceLocation(
            file_path="src/reports/sales_report.py",
            line_start=78,
            line_end=85,
            function_name="generate_report",
            class_name="SalesReportGenerator"
        ),
        affected_code="""for order in orders:
    customer = Customer.objects.get(id=order.customer_id)  # N+1 query!
    # process customer data...""",
        message="Query executed in loop causes performance issues",
        suggestion="Use select_related() or prefetch_related() to optimize queries",
        fix_recommendation="Replace with: orders = Order.objects.select_related('customer').all()",
        confidence=0.85,
        impact="medium",
        effort_to_fix="low",
        tags={"performance", "database", "n+1-query"},
        detected_at=datetime.now()
    ))
    
    # Low severity style violation
    findings.append(UnifiedFinding(
        title="Missing docstring in public method",
        description="Public method lacks documentation",
        finding_type=FindingType.MISSING_DOCUMENTATION,
        severity=FindingSeverity.LOW,
        source=FindingSource.LINTER,
        tool_name="pylint",
        rule_id="C0111",
        location=SourceLocation(
            file_path="src/utils/helpers.py",
            line_start=34,
            line_end=34,
            function_name="format_currency"
        ),
        message="Missing function or method docstring",
        suggestion="Add a descriptive docstring explaining the method's purpose, parameters, and return value",
        fix_recommendation='Add docstring: """Format currency value with proper locale-specific formatting."""',
        confidence=1.0,
        impact="low",
        effort_to_fix="low",
        tags={"documentation", "style", "maintenance"},
        detected_at=datetime.now()
    ))
    
    # Info level finding
    findings.append(UnifiedFinding(
        title="Unused import statement",
        description="Import statement not used in the module",
        finding_type=FindingType.CODE_SMELL,
        severity=FindingSeverity.INFO,
        source=FindingSource.LINTER,
        tool_name="flake8",
        rule_id="F401",
        location=SourceLocation(
            file_path="src/models/user.py",
            line_start=7,
            line_end=7
        ),
        affected_code="import json",
        message="'json' imported but unused",
        suggestion="Remove unused import or use it in the code",
        fix_recommendation="Remove the unused import statement",
        confidence=1.0,
        impact="low",
        effort_to_fix="low",
        tags={"cleanup", "imports", "code-quality"},
        detected_at=datetime.now()
    ))
    
    # Create collection with metadata
    collection = FindingsCollection(
        findings=findings,
        metadata={
            "scan_type": "comprehensive",
            "project_name": "Demo E-commerce Application",
            "branch": "main",
            "commit_hash": "abc123def456",
            "scan_duration_seconds": 45.6,
            "tools_used": ["bandit", "radon", "pylint", "flake8", "wtf-codebot-ai"]
        }
    )
    
    return collection


def demo_github_integration():
    """Demo GitHub Issues integration."""
    print("\\n" + "="*60)
    print("GitHub Issues Integration Demo")
    print("="*60)
    
    # Configure GitHub integration
    github_config = GitHubIssuesConfig(
        enabled=True,
        dry_run=True,  # Safe for demo
        token="ghp_your_token_here",  # Would be real token in production
        repository="your-org/your-repo",
        labels=["code-analysis", "wtf-codebot", "security"],
        assignees=["dev-team-lead"],
        create_summary_issue=True,
        max_issues_per_run=10,
        severity_mapping={
            "critical": ["critical", "security", "bug", "high-priority"],
            "high": ["bug", "high-priority"],
            "medium": ["enhancement", "medium-priority"],
            "low": ["enhancement", "low-priority"],
            "info": ["documentation", "cleanup"]
        }
    )
    
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,
        github_issues=github_config
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Create sample findings and push to GitHub
    collection = create_sample_findings()
    results = manager.push_findings(collection)
    
    print(f"GitHub Integration Results:")
    print(f"  Success: {results['success']}")
    if 'github_issues' in results['integrations']:
        github_results = results['integrations']['github_issues']
        print(f"  Issues Created: {github_results.get('issues_created', 0)}")
        print(f"  Summary Issue: {github_results.get('summary_issue', {}).get('dry_run', False)}")
        print(f"  Errors: {len(github_results.get('errors', []))}")


def demo_slack_integration():
    """Demo Slack integration."""
    print("\\n" + "="*60)
    print("Slack Integration Demo")
    print("="*60)
    
    # Configure Slack integration
    slack_config = SlackConfig(
        enabled=True,
        dry_run=True,  # Safe for demo
        webhook_url="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
        channel="#code-analysis",
        username="WTF CodeBot",
        icon_emoji=":robot_face:",
        thread_replies=True,
        summary_only=False,
        max_findings_in_message=5,
        mention_users=["@dev-team", "@security-team"]
    )
    
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,
        slack=slack_config
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Create sample findings and post to Slack
    collection = create_sample_findings()
    results = manager.push_findings(collection)
    
    print(f"Slack Integration Results:")
    print(f"  Success: {results['success']}")
    if 'slack' in results['integrations']:
        slack_results = results['integrations']['slack']
        print(f"  Messages Sent: {slack_results.get('messages_sent', 0)}")
        print(f"  Errors: {len(slack_results.get('errors', []))}")


def demo_jira_integration():
    """Demo JIRA integration."""
    print("\\n" + "="*60)
    print("JIRA Integration Demo")
    print("="*60)
    
    # Configure JIRA integration
    jira_config = JiraConfig(
        enabled=True,
        dry_run=True,  # Safe for demo
        base_url="https://your-company.atlassian.net",
        username="your-email@company.com",
        api_token="your_jira_api_token",
        project_key="DEV",
        issue_type="Bug",
        component="Security",
        assignee="john.doe",
        create_epic=True,
        epic_summary_template="Code Analysis - {date}",
        max_issues_per_run=25,
        severity_filter=["critical", "high", "medium"],
        priority_mapping={
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest"
        }
    )
    
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,
        jira=jira_config
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Create sample findings and create JIRA tickets
    collection = create_sample_findings()
    results = manager.push_findings(collection)
    
    print(f"JIRA Integration Results:")
    print(f"  Success: {results['success']}")
    if 'jira' in results['integrations']:
        jira_results = results['integrations']['jira']
        print(f"  Epic Created: {jira_results.get('epic_created', {}).get('dry_run', False)}")
        print(f"  Issues Created: {jira_results.get('issues_created', 0)}")
        print(f"  Errors: {len(jira_results.get('errors', []))}")


def demo_webhook_integration():
    """Demo webhook integration."""
    print("\\n" + "="*60)
    print("Webhook Integration Demo")
    print("="*60)
    
    # Configure webhook integration
    webhook_config = WebhookConfig(
        enabled=True,
        dry_run=True,  # Safe for demo
        url="https://your-api.example.com/code-analysis-webhook",
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Version": "v1"},
        auth_token="your_webhook_auth_token",
        include_full_findings=True,
        summary_only=False
    )
    
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,
        webhook=webhook_config
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Create sample findings and send via webhook
    collection = create_sample_findings()
    results = manager.push_findings(collection)
    
    print(f"Webhook Integration Results:")
    print(f"  Success: {results['success']}")
    if 'webhook' in results['integrations']:
        webhook_results = results['integrations']['webhook']
        print(f"  Dry Run: {webhook_results.get('dry_run', False)}")
        print(f"  Errors: {len(webhook_results.get('errors', []) if 'errors' in webhook_results else [])}")


def demo_exports():
    """Demo various export formats."""
    print("\\n" + "="*60)
    print("Export Formats Demo")
    print("="*60)
    
    # Configure exports
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,  # Safe for demo
        export_sarif=True,
        sarif_output_path="demo-results.sarif",
        export_json=True,
        json_output_path="demo-results.json",
        export_html=True,
        html_output_path="demo-results.html",
        export_csv=True,
        csv_output_path="demo-results.csv"
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Create sample findings and export
    collection = create_sample_findings()
    results = manager.push_findings(collection)
    
    print(f"Export Results:")
    print(f"  Success: {results['success']}")
    if 'exports' in results:
        export_results = results['exports']
        print(f"  Files to create: {len(export_results.get('files_created', []))}")
        for file_path in export_results.get('files_created', []):
            print(f"    - {file_path}")
        print(f"  Errors: {len(export_results.get('errors', []))}")


def demo_comprehensive_integration():
    """Demo using multiple integrations together."""
    print("\\n" + "="*60)
    print("Comprehensive Integration Demo")
    print("="*60)
    
    # Configure all integrations
    github_config = GitHubIssuesConfig(
        enabled=True,
        dry_run=True,
        token="github_token",
        repository="company/project",
        create_summary_issue=True
    )
    
    slack_config = SlackConfig(
        enabled=True,
        dry_run=True,
        webhook_url="https://hooks.slack.com/services/...",
        channel="#security-alerts",
        summary_only=True
    )
    
    webhook_config = WebhookConfig(
        enabled=True,
        dry_run=True,
        url="https://api.company.com/security-findings",
        summary_only=True
    )
    
    integrations_config = IntegrationsConfig(
        enabled=True,
        dry_run=True,
        # Export formats
        export_sarif=True,
        export_json=True,
        export_html=True,
        # Integrations
        github_issues=github_config,
        slack=slack_config,
        webhook=webhook_config
    )
    
    manager = IntegrationsManager(integrations_config)
    
    # Test all integrations
    print("Testing all integrations...")
    test_results = manager.test_integrations()
    
    print(f"\\nComprehensive Test Results:")
    print(f"  Overall Success: {test_results['success']}")
    print(f"  Enabled Integrations: {manager.get_enabled_integrations()}")
    
    for integration_name, result in test_results.get('integrations', {}).items():
        print(f"  {integration_name.title()}: {'✅' if result.get('success') else '❌'}")
    
    if test_results.get('exports'):
        print(f"  Exports: {'✅' if test_results['exports'].get('success') else '❌'}")


if __name__ == "__main__":
    print("WTF CodeBot Integrations Demo")
    print("=" * 60)
    print("This demo shows how to use various integrations to push")
    print("code analysis results to external tools and export to")
    print("different formats.")
    print()
    print("All integrations are running in DRY RUN mode - no actual")
    print("issues, messages, or files will be created.")
    
    try:
        # Demo individual integrations
        demo_github_integration()
        demo_slack_integration()
        demo_jira_integration()
        demo_webhook_integration()
        demo_exports()
        
        # Demo using multiple integrations together
        demo_comprehensive_integration()
        
        print("\\n" + "="*60)
        print("Demo completed successfully! 🎉")
        print("="*60)
        print()
        print("To use integrations in your project:")
        print("1. Configure the integrations in your wtf-codebot.yaml file")
        print("2. Set appropriate environment variables for API tokens")
        print("3. Run analysis with integration flags:")
        print("   wtf-codebot analyze /path/to/code --github-issues --export-sarif")
        print("4. Check the generated reports and created issues/tickets")
        
    except Exception as e:
        print(f"\\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
