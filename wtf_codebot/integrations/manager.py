"""Integration manager for coordinating multiple integrations."""

import logging
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass, field

from .base import BaseIntegration, IntegrationConfig
from .github_issues import GitHubIssuesIntegration, GitHubIssuesConfig
from .webhook import WebhookIntegration, WebhookConfig
from .slack import SlackIntegration, SlackConfig
from .jira import JiraIntegration, JiraConfig
from ..findings.models import FindingsCollection

logger = logging.getLogger(__name__)


@dataclass
class IntegrationsConfig:
    """Configuration for all integrations."""
    enabled: bool = False
    dry_run: bool = False
    
    # Individual integration configs
    github_issues: Optional[GitHubIssuesConfig] = None
    webhook: Optional[WebhookConfig] = None
    slack: Optional[SlackConfig] = None
    jira: Optional[JiraConfig] = None
    
    # Export configurations
    export_sarif: bool = False
    sarif_output_path: str = "results.sarif"
    export_json: bool = True
    json_output_path: str = "results.json"
    export_html: bool = False
    html_output_path: str = "results.html"
    export_csv: bool = False
    csv_output_path: str = "results.csv"
    
    def __post_init__(self):
        """Initialize integration configs if not provided."""
        if self.enabled:
            if self.github_issues is None:
                self.github_issues = GitHubIssuesConfig(enabled=False)
            if self.webhook is None:
                self.webhook = WebhookConfig(enabled=False)
            if self.slack is None:
                self.slack = SlackConfig(enabled=False)
            if self.jira is None:
                self.jira = JiraConfig(enabled=False)


class IntegrationsManager:
    """Manager for coordinating multiple integrations."""
    
    INTEGRATION_CLASSES = {
        'github_issues': GitHubIssuesIntegration,
        'webhook': WebhookIntegration,
        'slack': SlackIntegration,
        'jira': JiraIntegration
    }
    
    def __init__(self, config: IntegrationsConfig):
        """Initialize integrations manager.
        
        Args:
            config: Integrations configuration
        """
        self.config = config
        self.integrations: Dict[str, BaseIntegration] = {}
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize enabled integrations."""
        if not self.config.enabled:
            logger.info("Integrations are disabled")
            return
        
        # Initialize each integration type
        integration_configs = {
            'github_issues': self.config.github_issues,
            'webhook': self.config.webhook,
            'slack': self.config.slack,
            'jira': self.config.jira
        }
        
        for integration_name, integration_config in integration_configs.items():
            if integration_config and integration_config.enabled:
                try:
                    integration_class = self.INTEGRATION_CLASSES[integration_name]
                    integration = integration_class(integration_config)
                    
                    if integration.validate_config():
                        self.integrations[integration_name] = integration
                        logger.info(f"Initialized {integration_name} integration")
                    else:
                        logger.error(f"Failed to validate {integration_name} configuration")
                        
                except Exception as e:
                    logger.error(f"Failed to initialize {integration_name}: {e}")
    
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Push findings to all enabled integrations.
        
        Args:
            collection: Collection of findings to push
            
        Returns:
            Dictionary with results from all integrations
        """
        results = {
            "success": True,
            "integrations": {},
            "exports": {},
            "errors": []
        }
        
        if not self.config.enabled:
            logger.info("Integrations are disabled, skipping push")
            return results
        
        # Push to external integrations
        for integration_name, integration in self.integrations.items():
            try:
                logger.info(f"Pushing findings to {integration_name}")
                integration_result = integration.push_findings(collection)
                results["integrations"][integration_name] = integration_result
                
                if not integration_result.get("success", False):
                    results["success"] = False
                    error_msg = f"{integration_name}: {integration_result.get('error', 'Unknown error')}"
                    results["errors"].append(error_msg)
                    
            except Exception as e:
                error_msg = f"Failed to push to {integration_name}: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
                results["success"] = False
        
        # Handle exports
        export_results = self._handle_exports(collection)
        results["exports"] = export_results
        
        if not export_results.get("success", True):
            results["success"] = False
            results["errors"].extend(export_results.get("errors", []))
        
        return results
    
    def _handle_exports(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Handle various export formats.
        
        Args:
            collection: Collection of findings to export
            
        Returns:
            Dictionary with export results
        """
        from ..findings.reporter import UnifiedReporter
        
        export_results = {
            "success": True,
            "files_created": [],
            "errors": []
        }
        
        try:
            reporter = UnifiedReporter()
            
            # Export SARIF
            if self.config.export_sarif:
                try:
                    if self.config.dry_run:
                        logger.info(f"DRY RUN: Would export SARIF to {self.config.sarif_output_path}")
                    else:
                        reporter.generate_sarif_report(collection, self.config.sarif_output_path)
                        export_results["files_created"].append(self.config.sarif_output_path)
                        logger.info(f"Exported SARIF to {self.config.sarif_output_path}")
                except Exception as e:
                    error_msg = f"Failed to export SARIF: {e}"
                    logger.error(error_msg)
                    export_results["errors"].append(error_msg)
            
            # Export JSON
            if self.config.export_json:
                try:
                    if self.config.dry_run:
                        logger.info(f"DRY RUN: Would export JSON to {self.config.json_output_path}")
                    else:
                        reporter.generate_json_report(collection, self.config.json_output_path)
                        export_results["files_created"].append(self.config.json_output_path)
                        logger.info(f"Exported JSON to {self.config.json_output_path}")
                except Exception as e:
                    error_msg = f"Failed to export JSON: {e}"
                    logger.error(error_msg)
                    export_results["errors"].append(error_msg)
            
            # Export HTML
            if self.config.export_html:
                try:
                    if self.config.dry_run:
                        logger.info(f"DRY RUN: Would export HTML to {self.config.html_output_path}")
                    else:
                        reporter.generate_html_report(collection, self.config.html_output_path)
                        export_results["files_created"].append(self.config.html_output_path)
                        logger.info(f"Exported HTML to {self.config.html_output_path}")
                except Exception as e:
                    error_msg = f"Failed to export HTML: {e}"
                    logger.error(error_msg)
                    export_results["errors"].append(error_msg)
            
            # Export CSV
            if self.config.export_csv:
                try:
                    if self.config.dry_run:
                        logger.info(f"DRY RUN: Would export CSV to {self.config.csv_output_path}")
                    else:
                        reporter.generate_csv_report(collection, self.config.csv_output_path)
                        export_results["files_created"].append(self.config.csv_output_path)
                        logger.info(f"Exported CSV to {self.config.csv_output_path}")
                except Exception as e:
                    error_msg = f"Failed to export CSV: {e}"
                    logger.error(error_msg)
                    export_results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"Failed to initialize reporter: {e}"
            logger.error(error_msg)
            export_results["errors"].append(error_msg)
            export_results["success"] = False
        
        if export_results["errors"]:
            export_results["success"] = False
        
        return export_results
    
    def get_enabled_integrations(self) -> List[str]:
        """Get list of enabled integration names.
        
        Returns:
            List of enabled integration names
        """
        return list(self.integrations.keys())
    
    def validate_all_configs(self) -> Dict[str, bool]:
        """Validate all integration configurations.
        
        Returns:
            Dictionary mapping integration names to validation results
        """
        validation_results = {}
        
        for integration_name, integration in self.integrations.items():
            try:
                validation_results[integration_name] = integration.validate_config()
            except Exception as e:
                logger.error(f"Error validating {integration_name}: {e}")
                validation_results[integration_name] = False
        
        return validation_results
    
    def test_integrations(self, test_collection: Optional[FindingsCollection] = None) -> Dict[str, Any]:
        """Test all integrations with dry run.
        
        Args:
            test_collection: Optional test collection, will create minimal one if not provided
            
        Returns:
            Dictionary with test results
        """
        if test_collection is None:
            # Create minimal test collection
            from ..findings.models import UnifiedFinding, SourceLocation, FindingSeverity, FindingType, FindingSource
            from datetime import datetime
            
            test_finding = UnifiedFinding(
                title="Test Finding",
                description="This is a test finding for integration testing",
                finding_type=FindingType.CODE_SMELL,
                severity=FindingSeverity.MEDIUM,
                source=FindingSource.STATIC_ANALYZER,
                tool_name="test-tool",
                location=SourceLocation("test_file.py", 10, 15),
                message="Test message",
                detected_at=datetime.now()
            )
            
            test_collection = FindingsCollection(findings=[test_finding])
        
        # Temporarily enable dry run for all integrations
        original_dry_run_states = {}
        for integration_name, integration in self.integrations.items():
            original_dry_run_states[integration_name] = integration.config.dry_run
            integration.config.dry_run = True
        
        # Run tests
        test_results = self.push_findings(test_collection)
        
        # Restore original dry run states
        for integration_name, integration in self.integrations.items():
            integration.config.dry_run = original_dry_run_states[integration_name]
        
        return test_results
