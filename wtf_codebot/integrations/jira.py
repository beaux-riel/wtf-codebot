"""JIRA integration for creating tickets from findings."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import requests
from base64 import b64encode

from .base import BaseIntegration, IntegrationConfig
from ..findings.models import FindingsCollection, UnifiedFinding, FindingSeverity

logger = logging.getLogger(__name__)


@dataclass
class JiraConfig(IntegrationConfig):
    """Configuration for JIRA integration."""
    base_url: str = ""  # JIRA instance URL
    username: str = ""  # JIRA username
    api_token: str = ""  # JIRA API token
    project_key: str = ""  # JIRA project key
    issue_type: str = "Bug"  # Default issue type
    priority_mapping: Dict[str, str] = None  # Map severity to JIRA priority
    component: str = ""  # Component to assign issues to
    labels: List[str] = None  # Default labels
    assignee: str = ""  # Default assignee
    create_epic: bool = True  # Create epic for analysis run
    epic_summary_template: str = "Code Analysis - {date}"
    max_issues_per_run: int = 50  # Limit issues created
    severity_filter: List[str] = None  # Only create issues for these severities
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = ["code-analysis", "wtf-codebot"]
        if self.priority_mapping is None:
            self.priority_mapping = {
                "critical": "Highest",
                "high": "High", 
                "medium": "Medium",
                "low": "Low",
                "info": "Lowest"
            }
        if self.severity_filter is None:
            self.severity_filter = ["critical", "high", "medium"]


class JiraIntegration(BaseIntegration):
    """Integration for creating JIRA tickets from findings."""
    
    def __init__(self, config: JiraConfig):
        """Initialize JIRA integration.
        
        Args:
            config: JIRA configuration
        """
        super().__init__(config)
        self.config: JiraConfig = config
        self.session = requests.Session()
        
        # Setup authentication
        if self.config.username and self.config.api_token:
            auth_string = f"{self.config.username}:{self.config.api_token}"
            encoded_auth = b64encode(auth_string.encode()).decode('ascii')
            self.session.headers.update({
                "Authorization": f"Basic {encoded_auth}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
    
    def validate_config(self) -> bool:
        """Validate JIRA configuration."""
        if not self.config.base_url:
            logger.error("JIRA base URL is required")
            return False
            
        if not self.config.username or not self.config.api_token:
            logger.error("JIRA username and API token are required")
            return False
            
        if not self.config.project_key:
            logger.error("JIRA project key is required")
            return False
        
        # Test JIRA connection
        if not self.config.dry_run:
            try:
                # Test authentication
                response = self.session.get(
                    f"{self.config.base_url}/rest/api/2/myself",
                    timeout=self.config.timeout
                )
                if response.status_code != 200:
                    logger.error(f"JIRA authentication failed: {response.status_code}")
                    return False
                
                # Test project access
                response = self.session.get(
                    f"{self.config.base_url}/rest/api/2/project/{self.config.project_key}",
                    timeout=self.config.timeout
                )
                if response.status_code != 200:
                    logger.error(f"JIRA project access failed: {response.status_code}")
                    return False
                    
            except Exception as e:
                logger.error(f"Failed to validate JIRA connection: {e}")
                return False
        
        return True
    
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Create JIRA tickets from findings.
        
        Args:
            collection: Collection of findings to create tickets for
            
        Returns:
            Dictionary with creation results
        """
        if not self.validate_config():
            return {"success": False, "error": "Invalid configuration"}
        
        results = {
            "success": True,
            "epic_created": None,
            "issues_created": 0,
            "issues_skipped": 0,
            "errors": [],
            "created_issues": []
        }
        
        # Filter findings by severity
        findings = self.filter_findings(
            collection.findings, 
            severity_filter=self.config.severity_filter
        )
        
        if not findings:
            logger.info("No findings match severity filter")
            return results
        
        epic_key = None
        
        # Create epic if configured
        if self.config.create_epic:
            try:
                if self.config.dry_run:
                    logger.info("DRY RUN: Would create JIRA epic")
                    epic_key = "EPIC-123"  # Dummy key for dry run
                    results["epic_created"] = {"key": epic_key, "dry_run": True}
                else:
                    epic = self._create_epic(collection)
                    if epic:
                        epic_key = epic["key"]
                        results["epic_created"] = epic
                        logger.info(f"Created JIRA epic: {epic_key}")
            except Exception as e:
                error_msg = f"Failed to create epic: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        # Create individual issues
        created_count = 0
        for finding in findings:
            if created_count >= self.config.max_issues_per_run:
                logger.info(f"Reached maximum issues limit ({self.config.max_issues_per_run})")
                break
            
            try:
                if self.config.dry_run:
                    logger.info(f"DRY RUN: Would create JIRA issue for {finding.title}")
                    results["issues_created"] += 1
                    created_count += 1
                    continue
                
                issue = self._create_issue_for_finding(finding, epic_key)
                if issue:
                    results["created_issues"].append(issue)
                    results["issues_created"] += 1
                    created_count += 1
                    logger.info(f"Created JIRA issue: {issue['key']}")
                else:
                    results["issues_skipped"] += 1
                    
            except Exception as e:
                error_msg = f"Failed to create issue for {finding.title}: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        if results["errors"]:
            results["success"] = False
        
        return results
    
    def _create_epic(self, collection: FindingsCollection) -> Optional[Dict[str, Any]]:
        """Create JIRA epic for the analysis run."""
        from datetime import datetime
        
        summary = self.config.epic_summary_template.format(
            date=collection.created_at.strftime("%Y-%m-%d")
        )
        
        description = self._generate_epic_description(collection)
        
        issue_data = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Epic"},
                "customfield_10011": summary,  # Epic Name field (may vary by JIRA instance)
                "labels": self.config.labels
            }
        }
        
        if self.config.assignee:
            issue_data["fields"]["assignee"] = {"name": self.config.assignee}
        
        try:
            response = self.session.post(
                f"{self.config.base_url}/rest/api/2/issue",
                json=issue_data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create JIRA epic: {e}")
            return None
    
    def _create_issue_for_finding(self, finding: UnifiedFinding, epic_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Create JIRA issue for a single finding."""
        summary = f"[{finding.severity.value.upper()}] {finding.title}"
        description = self._generate_issue_description(finding)
        
        # Map severity to JIRA priority
        priority = self.config.priority_mapping.get(finding.severity.value, "Medium")
        
        issue_data = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.config.issue_type},
                "priority": {"name": priority},
                "labels": self.config.labels + [finding.finding_type.value.replace("_", "-")]
            }
        }
        
        # Add component if specified
        if self.config.component:
            issue_data["fields"]["components"] = [{"name": self.config.component}]
        
        # Add assignee if specified
        if self.config.assignee:
            issue_data["fields"]["assignee"] = {"name": self.config.assignee}
        
        # Link to epic if created
        if epic_key:
            issue_data["fields"]["customfield_10014"] = epic_key  # Epic Link field (may vary)
        
        try:
            response = self.session.post(
                f"{self.config.base_url}/rest/api/2/issue",
                json=issue_data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create JIRA issue: {e}")
            return None
    
    def _generate_epic_description(self, collection: FindingsCollection) -> str:
        """Generate description for epic."""
        summary_stats = collection.get_summary_stats()
        
        description_parts = []
        description_parts.append("h2. Code Analysis Summary")
        description_parts.append(f"*Analysis Date:* {collection.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        description_parts.append(f"*Total Findings:* {summary_stats['total']}")
        description_parts.append(f"*Files Affected:* {summary_stats['affected_files_count']}")
        description_parts.append("")
        
        # Severity breakdown
        description_parts.append("h3. Findings by Severity")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary_stats["severity_counts"].get(severity, 0)
            if count > 0:
                description_parts.append(f"* *{severity.title()}:* {count}")
        description_parts.append("")
        
        # Top finding types
        if summary_stats.get("type_counts"):
            description_parts.append("h3. Top Finding Types")
            sorted_types = sorted(summary_stats["type_counts"].items(), key=lambda x: x[1], reverse=True)
            for finding_type, count in sorted_types[:10]:
                description_parts.append(f"* *{finding_type.replace('_', ' ').title()}:* {count}")
            description_parts.append("")
        
        description_parts.append("h3. Files with Most Issues")
        file_counts = {}
        for finding in collection.findings:
            file_path = finding.location.file_path
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
        
        if file_counts:
            sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
            for file_path, count in sorted_files[:10]:
                description_parts.append(f"* {file_path}: {count} issues")
        
        description_parts.append("")
        description_parts.append("---")
        description_parts.append("_This epic was created by WTF CodeBot_")
        
        return "\\n".join(description_parts)
    
    def _generate_issue_description(self, finding: UnifiedFinding) -> str:
        """Generate JIRA description for a finding."""
        description_parts = []
        
        # Finding details
        description_parts.append("h3. Finding Details")
        description_parts.append(f"*Severity:* {finding.severity.value.title()}")
        description_parts.append(f"*Type:* {finding.finding_type.value.replace('_', ' ').title()}")
        description_parts.append(f"*Source:* {finding.source.value.replace('_', ' ').title()}")
        description_parts.append(f"*Tool:* {finding.tool_name}")
        description_parts.append(f"*Confidence:* {finding.confidence:.2f}")
        description_parts.append("")
        
        # Location
        description_parts.append("h3. Location")
        description_parts.append(f"*File:* {{code}}{finding.location.file_path}{{code}}")
        if finding.location.line_start:
            line_info = f"Line {finding.location.line_start}"
            if finding.location.line_end and finding.location.line_end != finding.location.line_start:
                line_info += f"-{finding.location.line_end}"
            description_parts.append(f"*Lines:* {line_info}")
        if finding.location.function_name:
            description_parts.append(f"*Function:* {{code}}{finding.location.function_name}{{code}}")
        if finding.location.class_name:
            description_parts.append(f"*Class:* {{code}}{finding.location.class_name}{{code}}")
        description_parts.append("")
        
        # Description and message
        if finding.description:
            description_parts.append("h3. Description")
            description_parts.append(finding.description)
            description_parts.append("")
        
        if finding.message:
            description_parts.append("h3. Message")
            description_parts.append(finding.message)
            description_parts.append("")
        
        # Affected code
        if finding.affected_code:
            description_parts.append("h3. Affected Code")
            description_parts.append("{code}")
            description_parts.append(finding.affected_code)
            description_parts.append("{code}")
            description_parts.append("")
        
        # Suggestion
        if finding.suggestion:
            description_parts.append("h3. Suggestion")
            description_parts.append(finding.suggestion)
            description_parts.append("")
        
        # Fix recommendation
        if finding.fix_recommendation:
            description_parts.append("h3. Fix Recommendation")
            description_parts.append(finding.fix_recommendation)
            description_parts.append("")
        
        # Additional info
        description_parts.append("h3. Additional Information")
        description_parts.append(f"*Impact:* {finding.impact}")
        description_parts.append(f"*Effort to Fix:* {finding.effort_to_fix}")
        if finding.tags:
            description_parts.append(f"*Tags:* {', '.join(sorted(finding.tags))}")
        if finding.rule_id:
            description_parts.append(f"*Rule ID:* {{code}}{finding.rule_id}{{code}}")
        description_parts.append("")
        
        # Signature
        description_parts.append("---")
        description_parts.append(f"_Generated by WTF CodeBot on {finding.detected_at.strftime('%Y-%m-%d %H:%M:%S')}_")
        
        return "\\n".join(description_parts)
