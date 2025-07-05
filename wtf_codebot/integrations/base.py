"""Base integration class for external tool integrations."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..findings.models import FindingsCollection, UnifiedFinding


@dataclass
class IntegrationConfig:
    """Base configuration for integrations."""
    enabled: bool = False
    dry_run: bool = False
    rate_limit_delay: float = 1.0  # seconds between requests
    max_retries: int = 3
    timeout: int = 30  # seconds


class BaseIntegration(ABC):
    """Base class for all integrations."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize integration with configuration.
        
        Args:
            config: Integration configuration
        """
        self.config = config
        
    @abstractmethod
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Push findings to the external service.
        
        Args:
            collection: Collection of findings to push
            
        Returns:
            Dictionary containing results and metadata
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate the integration configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        pass
    
    def filter_findings(self, findings: List[UnifiedFinding], 
                       severity_filter: Optional[List[str]] = None,
                       type_filter: Optional[List[str]] = None) -> List[UnifiedFinding]:
        """Filter findings based on criteria.
        
        Args:
            findings: List of findings to filter
            severity_filter: List of severity levels to include
            type_filter: List of finding types to include
            
        Returns:
            Filtered list of findings
        """
        filtered = findings
        
        if severity_filter:
            filtered = [f for f in filtered if f.severity.value in severity_filter]
            
        if type_filter:
            filtered = [f for f in filtered if f.finding_type.value in type_filter]
            
        return filtered
