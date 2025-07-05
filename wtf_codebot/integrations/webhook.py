"""Webhook integration for pushing findings to external endpoints."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import requests

from .base import BaseIntegration, IntegrationConfig
from ..findings.models import FindingsCollection

logger = logging.getLogger(__name__)


@dataclass 
class WebhookConfig(IntegrationConfig):
    """Configuration for webhook integration."""
    url: str = ""
    method: str = "POST"  # HTTP method
    headers: Dict[str, str] = None  # Custom headers
    auth_token: str = ""  # Bearer token
    custom_payload: bool = False  # Use custom payload format
    payload_template: str = ""  # Custom payload template
    include_full_findings: bool = True  # Include full finding details
    summary_only: bool = False  # Send only summary stats
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}


class WebhookIntegration(BaseIntegration):
    """Integration for sending findings via webhook."""
    
    def __init__(self, config: WebhookConfig):
        """Initialize webhook integration.
        
        Args:
            config: Webhook configuration
        """
        super().__init__(config)
        self.config: WebhookConfig = config
        self.session = requests.Session()
        
        # Setup headers
        headers = dict(self.config.headers)
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        self.session.headers.update(headers)
    
    def validate_config(self) -> bool:
        """Validate webhook configuration."""
        if not self.config.url:
            logger.error("Webhook URL is required")
            return False
            
        if self.config.method not in ["GET", "POST", "PUT", "PATCH"]:
            logger.error(f"Unsupported HTTP method: {self.config.method}")
            return False
            
        # Test webhook endpoint if not in dry run
        if not self.config.dry_run:
            try:
                test_payload = {"test": True, "source": "wtf-codebot"}
                response = self.session.request(
                    method=self.config.method,
                    url=self.config.url,
                    json=test_payload,
                    timeout=self.config.timeout
                )
                if response.status_code >= 400:
                    logger.warning(f"Webhook test returned status {response.status_code}")
                    return False
            except Exception as e:
                logger.error(f"Failed to test webhook: {e}")
                return False
                
        return True
    
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Send findings via webhook.
        
        Args:
            collection: Collection of findings to send
            
        Returns:
            Dictionary with send results
        """
        if not self.validate_config():
            return {"success": False, "error": "Invalid configuration"}
        
        results = {
            "success": True,
            "response_status": None,
            "response_body": None,
            "error": None
        }
        
        try:
            # Prepare payload
            if self.config.custom_payload and self.config.payload_template:
                payload = self._generate_custom_payload(collection)
            else:
                payload = self._generate_default_payload(collection)
            
            if self.config.dry_run:
                logger.info("DRY RUN: Would send webhook payload")
                logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
                results["dry_run"] = True
                return results
            
            # Send webhook
            response = self.session.request(
                method=self.config.method,
                url=self.config.url,
                json=payload,
                timeout=self.config.timeout
            )
            
            results["response_status"] = response.status_code
            results["response_body"] = response.text
            
            if response.status_code >= 400:
                results["success"] = False
                results["error"] = f"HTTP {response.status_code}: {response.text}"
                logger.error(f"Webhook failed with status {response.status_code}")
            else:
                logger.info(f"Webhook sent successfully (status {response.status_code})")
                
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            logger.error(f"Failed to send webhook: {e}")
        
        return results
    
    def _generate_default_payload(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Generate default webhook payload."""
        summary_stats = collection.get_summary_stats()
        
        payload = {
            "source": "wtf-codebot",
            "timestamp": collection.created_at.isoformat(),
            "summary": summary_stats
        }
        
        # Add full findings if requested
        if self.config.include_full_findings and not self.config.summary_only:
            payload["findings"] = [finding.to_dict() for finding in collection.findings]
        
        # Add metadata
        if collection.metadata:
            payload["metadata"] = collection.metadata
        
        return payload
    
    def _generate_custom_payload(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Generate custom webhook payload using template."""
        try:
            # Simple template substitution
            # In a real implementation, you might use Jinja2 or similar
            template_vars = {
                "total_findings": len(collection.findings),
                "critical_count": len([f for f in collection.findings if f.severity.value == "critical"]),
                "high_count": len([f for f in collection.findings if f.severity.value == "high"]),
                "medium_count": len([f for f in collection.findings if f.severity.value == "medium"]),
                "low_count": len([f for f in collection.findings if f.severity.value == "low"]),
                "timestamp": collection.created_at.isoformat(),
                "findings": [finding.to_dict() for finding in collection.findings] if self.config.include_full_findings else []
            }
            
            # Replace variables in template
            payload_str = self.config.payload_template
            for var, value in template_vars.items():
                payload_str = payload_str.replace(f"{{{var}}}", str(value))
            
            return json.loads(payload_str)
            
        except Exception as e:
            logger.error(f"Failed to generate custom payload: {e}")
            # Fallback to default payload
            return self._generate_default_payload(collection)
