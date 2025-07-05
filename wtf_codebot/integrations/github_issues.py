"""GitHub Issues integration for creating issues from findings."""

import json
import time
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import requests

from .base import BaseIntegration, IntegrationConfig
from ..findings.models import FindingsCollection, UnifiedFinding, FindingSeverity

logger = logging.getLogger(__name__)


@dataclass
class GitHubIssuesConfig(IntegrationConfig):
    """Configuration for GitHub Issues integration."""
    token: str = ""
    repository: str = ""  # format: "owner/repo"
    labels: List[str] = None  # Default labels to add to issues
    assignees: List[str] = None  # Default assignees
    milestone: Optional[int] = None  # Milestone number
    severity_mapping: Dict[str, List[str]] = None  # Map severity to labels
    create_summary_issue: bool = True  # Create a summary issue with all findings
    max_issues_per_run: int = 20  # Limit issues created in one run
    duplicate_check_days: int = 7  # Check for duplicates in last N days
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = ["code-analysis", "wtf-codebot"]
        if self.assignees is None:
            self.assignees = []
        if self.severity_mapping is None:
            self.severity_mapping = {
                "critical": ["critical", "bug", "high-priority"],
                "high": ["bug", "high-priority"],
                "medium": ["enhancement", "medium-priority"],
                "low": ["enhancement", "low-priority"],
                "info": ["documentation", "low-priority"]
            }


class GitHubIssuesIntegration(BaseIntegration):
    """Integration for creating GitHub issues from findings."""
    
    def __init__(self, config: GitHubIssuesConfig):
        """Initialize GitHub Issues integration.
        
        Args:
            config: GitHub Issues configuration
        """
        super().__init__(config)
        self.config: GitHubIssuesConfig = config
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.config.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "WTF-CodeBot/1.0"
        })
    
    def validate_config(self) -> bool:
        """Validate GitHub configuration."""
        if not self.config.token:
            logger.error("GitHub token is required")
            return False
            
        if not self.config.repository or "/" not in self.config.repository:
            logger.error("Repository must be in 'owner/repo' format")
            return False
            
        # Test API access
        try:
            response = self.session.get(f"{self.base_url}/repos/{self.config.repository}")
            if response.status_code == 404:
                logger.error(f"Repository {self.config.repository} not found or no access")
                return False
            elif response.status_code != 200:
                logger.error(f"GitHub API error: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to validate GitHub access: {e}")
            return False
            
        return True
    
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Create GitHub issues from findings.
        
        Args:
            collection: Collection of findings to create issues for
            
        Returns:
            Dictionary with creation results
        """
        if not self.validate_config():
            return {"success": False, "error": "Invalid configuration"}
        
        results = {
            "success": True,
            "issues_created": 0,
            "issues_skipped": 0,
            "errors": [],
            "created_issues": [],
            "summary_issue": None
        }
        
        # Filter findings based on severity if configured
        findings = collection.findings
        if hasattr(self.config, 'severity_filter') and self.config.severity_filter:
            findings = self.filter_findings(findings, severity_filter=self.config.severity_filter)
        
        # Check for existing issues to avoid duplicates
        existing_issues = self._get_recent_issues()
        
        # Create individual issues for high-severity findings
        high_severity_findings = [f for f in findings 
                                if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        
        created_count = 0
        for finding in high_severity_findings:
            if created_count >= self.config.max_issues_per_run:
                logger.info(f"Reached maximum issues limit ({self.config.max_issues_per_run})")
                break
                
            if self._is_duplicate_issue(finding, existing_issues):
                results["issues_skipped"] += 1
                continue
            
            if self.config.dry_run:
                logger.info(f"DRY RUN: Would create issue for {finding.title}")
                results["issues_created"] += 1
                continue
            
            try:
                issue = self._create_issue_for_finding(finding)
                if issue:
                    results["created_issues"].append(issue)
                    results["issues_created"] += 1
                    created_count += 1
                    time.sleep(self.config.rate_limit_delay)
            except Exception as e:
                error_msg = f"Failed to create issue for {finding.title}: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        # Create summary issue if configured
        if self.config.create_summary_issue and findings:
            try:
                if self.config.dry_run:
                    logger.info("DRY RUN: Would create summary issue")
                    results["summary_issue"] = {"dry_run": True}
                else:
                    summary_issue = self._create_summary_issue(collection, findings)
                    if summary_issue:
                        results["summary_issue"] = summary_issue
            except Exception as e:
                error_msg = f"Failed to create summary issue: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        if results["errors"]:
            results["success"] = False
        
        return results
    
    def _get_recent_issues(self) -> List[Dict[str, Any]]:
        """Get recent issues to check for duplicates."""
        try:
            since_date = time.strftime('%Y-%m-%dT%H:%M:%SZ', 
                                     time.gmtime(time.time() - (self.config.duplicate_check_days * 24 * 3600)))
            
            response = self.session.get(
                f"{self.base_url}/repos/{self.config.repository}/issues",
                params={
                    "state": "all",
                    "since": since_date,
                    "creator": "app/wtf-codebot",  # Only check our own issues
                    "per_page": 100
                }
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Failed to get recent issues: {e}")
            return []
    
    def _is_duplicate_issue(self, finding: UnifiedFinding, existing_issues: List[Dict[str, Any]]) -> bool:
        """Check if an issue already exists for this finding."""
        finding_signature = f"{finding.location.file_path}:{finding.title}"
        
        for issue in existing_issues:
            if finding_signature in issue.get("body", ""):
                logger.info(f"Skipping duplicate issue for {finding.title}")
                return True
        return False
    
    def _create_issue_for_finding(self, finding: UnifiedFinding) -> Optional[Dict[str, Any]]:
        """Create a GitHub issue for a single finding."""
        title = f"[{finding.severity.value.upper()}] {finding.title}"
        
        body = self._generate_issue_body(finding)
        
        labels = list(self.config.labels)
        if finding.severity.value in self.config.severity_mapping:
            labels.extend(self.config.severity_mapping[finding.severity.value])
        
        # Add finding type as label
        labels.append(finding.finding_type.value.replace("_", "-"))
        
        issue_data = {
            "title": title,
            "body": body,
            "labels": list(set(labels)),  # Remove duplicates
        }
        
        if self.config.assignees:
            issue_data["assignees"] = self.config.assignees
            
        if self.config.milestone:
            issue_data["milestone"] = self.config.milestone
        
        try:
            response = self.session.post(
                f"{self.base_url}/repos/{self.config.repository}/issues",
                json=issue_data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            issue = response.json()
            logger.info(f"Created GitHub issue #{issue['number']}: {title}")
            return issue
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create GitHub issue: {e}")
            return None
    
    def _generate_issue_body(self, finding: UnifiedFinding) -> str:
        """Generate issue body for a finding."""
        body_parts = []
        
        # Add finding metadata
        body_parts.append("## Finding Details")
        body_parts.append(f"**Severity:** {finding.severity.value.title()}")
        body_parts.append(f"**Type:** {finding.finding_type.value.replace('_', ' ').title()}")
        body_parts.append(f"**Source:** {finding.source.value.replace('_', ' ').title()}")
        body_parts.append(f"**Tool:** {finding.tool_name}")
        body_parts.append(f"**Confidence:** {finding.confidence:.2f}")
        body_parts.append("")
        
        # Add location info
        body_parts.append("## Location")
        body_parts.append(f"**File:** `{finding.location.file_path}`")
        if finding.location.line_start:
            line_info = f"Line {finding.location.line_start}"
            if finding.location.line_end and finding.location.line_end != finding.location.line_start:
                line_info += f"-{finding.location.line_end}"
            body_parts.append(f"**Lines:** {line_info}")
        if finding.location.function_name:
            body_parts.append(f"**Function:** `{finding.location.function_name}`")
        if finding.location.class_name:
            body_parts.append(f"**Class:** `{finding.location.class_name}`")
        body_parts.append("")
        
        # Add description and message
        if finding.description:
            body_parts.append("## Description")
            body_parts.append(finding.description)
            body_parts.append("")
        
        if finding.message:
            body_parts.append("## Message")
            body_parts.append(finding.message)
            body_parts.append("")
        
        # Add affected code
        if finding.affected_code:
            body_parts.append("## Affected Code")
            body_parts.append("```")
            body_parts.append(finding.affected_code)
            body_parts.append("```")
            body_parts.append("")
        
        # Add suggestion
        if finding.suggestion:
            body_parts.append("## Suggestion")
            body_parts.append(finding.suggestion)
            body_parts.append("")
        
        # Add fix recommendation
        if finding.fix_recommendation:
            body_parts.append("## Fix Recommendation")
            body_parts.append(finding.fix_recommendation)
            body_parts.append("")
        
        # Add metadata
        body_parts.append("## Additional Information")
        body_parts.append(f"**Impact:** {finding.impact}")
        body_parts.append(f"**Effort to Fix:** {finding.effort_to_fix}")
        if finding.tags:
            body_parts.append(f"**Tags:** {', '.join(sorted(finding.tags))}")
        if finding.rule_id:
            body_parts.append(f"**Rule ID:** `{finding.rule_id}`")
        body_parts.append("")
        
        # Add signature for duplicate detection
        body_parts.append("---")
        body_parts.append(f"*Finding signature: {finding.location.file_path}:{finding.title}*")
        body_parts.append(f"*Generated by WTF CodeBot on {finding.detected_at.strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\\n".join(body_parts)
    
    def _create_summary_issue(self, collection: FindingsCollection, findings: List[UnifiedFinding]) -> Optional[Dict[str, Any]]:
        """Create a summary issue with all findings."""
        title = f"Code Analysis Summary - {len(findings)} findings"
        
        body = self._generate_summary_body(collection, findings)
        
        labels = list(self.config.labels)
        labels.extend(["summary", "code-analysis-report"])
        
        issue_data = {
            "title": title,
            "body": body,
            "labels": list(set(labels)),
        }
        
        if self.config.assignees:
            issue_data["assignees"] = self.config.assignees
        
        try:
            response = self.session.post(
                f"{self.base_url}/repos/{self.config.repository}/issues",
                json=issue_data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            issue = response.json()
            logger.info(f"Created GitHub summary issue #{issue['number']}")
            return issue
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create GitHub summary issue: {e}")
            return None
    
    def _generate_summary_body(self, collection: FindingsCollection, findings: List[UnifiedFinding]) -> str:
        """Generate summary issue body."""
        body_parts = []
        
        summary_stats = collection.get_summary_stats()
        
        body_parts.append("# Code Analysis Summary")
        body_parts.append(f"**Analysis Date:** {collection.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        body_parts.append(f"**Total Findings:** {summary_stats['total']}")
        body_parts.append(f"**Files Affected:** {summary_stats['affected_files_count']}")
        body_parts.append("")
        
        # Severity breakdown
        body_parts.append("## Findings by Severity")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary_stats["severity_counts"].get(severity, 0)
            if count > 0:
                emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}[severity]
                body_parts.append(f"- {emoji} **{severity.title()}:** {count}")
        body_parts.append("")
        
        # Top finding types
        if summary_stats["type_counts"]:
            body_parts.append("## Top Finding Types")
            sorted_types = sorted(summary_stats["type_counts"].items(), key=lambda x: x[1], reverse=True)
            for finding_type, count in sorted_types[:10]:
                body_parts.append(f"- **{finding_type.replace('_', ' ').title()}:** {count}")
            body_parts.append("")
        
        # Critical and high severity details
        critical_high = [f for f in findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        if critical_high:
            body_parts.append("## Critical & High Severity Issues")
            for finding in critical_high[:20]:  # Limit to first 20
                severity_emoji = "🚨" if finding.severity == FindingSeverity.CRITICAL else "🔴"
                body_parts.append(f"- {severity_emoji} **{finding.title}** ({finding.location.file_path})")
                if finding.location.line_start:
                    body_parts.append(f"  - Line {finding.location.line_start}")
                if finding.message:
                    body_parts.append(f"  - {finding.message[:100]}{'...' if len(finding.message) > 100 else ''}")
            
            if len(critical_high) > 20:
                body_parts.append(f"- ... and {len(critical_high) - 20} more critical/high severity issues")
            body_parts.append("")
        
        # Files with most issues
        file_counts = {}
        for finding in findings:
            file_path = finding.location.file_path
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
        
        if file_counts:
            body_parts.append("## Files with Most Issues")
            sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
            for file_path, count in sorted_files[:10]:
                body_parts.append(f"- **{file_path}:** {count} issues")
            body_parts.append("")
        
        # Add links to individual issues if any were created
        body_parts.append("---")
        body_parts.append("*This summary was generated by WTF CodeBot*")
        body_parts.append("*Individual issues may be created for critical and high severity findings*")
        
        return "\\n".join(body_parts)
