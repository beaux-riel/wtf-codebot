"""
Base analyzer classes for static analysis.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from ..discovery.models import FileNode, CodebaseGraph

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of patterns that can be detected."""
    DESIGN_PATTERN = "design_pattern"
    ANTI_PATTERN = "anti_pattern"
    CODE_SMELL = "code_smell"


class Severity(Enum):
    """Severity levels for analysis findings."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Represents a finding from static analysis."""
    pattern_type: PatternType
    pattern_name: str
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    message: str = ""
    description: str = ""
    suggestion: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Metric:
    """Represents a code metric."""
    name: str
    value: float
    description: str
    file_path: Optional[str] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Results from static analysis."""
    findings: List[Finding] = field(default_factory=list)
    metrics: List[Metric] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
    
    def add_metric(self, metric: Metric) -> None:
        """Add a metric to the results."""
        self.metrics.append(metric)
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_type(self, pattern_type: PatternType) -> List[Finding]:
        """Get findings by pattern type."""
        return [f for f in self.findings if f.pattern_type == pattern_type]


class BaseAnalyzer(ABC):
    """Base class for all static analyzers."""
    
    def __init__(self, name: str):
        """Initialize the analyzer."""
        self.name = name
        self.supported_extensions: Set[str] = set()
        self.language_name: str = ""
        self.enabled_rules: Set[str] = set()
        self.disabled_rules: Set[str] = set()
    
    @abstractmethod
    def analyze_file(self, file_node: FileNode) -> AnalysisResult:
        """
        Analyze a single file.
        
        Args:
            file_node: File to analyze
            
        Returns:
            AnalysisResult: Analysis results
        """
        pass
    
    def analyze_codebase(self, codebase: CodebaseGraph) -> AnalysisResult:
        """
        Analyze the entire codebase.
        
        Args:
            codebase: Codebase to analyze
            
        Returns:
            AnalysisResult: Combined analysis results
        """
        combined_result = AnalysisResult()
        
        for file_path, file_node in codebase.files.items():
            if self.supports_file(file_node):
                try:
                    result = self.analyze_file(file_node)
                    combined_result.findings.extend(result.findings)
                    combined_result.metrics.extend(result.metrics)
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {str(e)}")
                    finding = Finding(
                        pattern_type=PatternType.CODE_SMELL,
                        pattern_name="analysis_error",
                        severity=Severity.ERROR,
                        file_path=file_path,
                        message=f"Analysis failed: {str(e)}"
                    )
                    combined_result.add_finding(finding)
        
        return combined_result
    
    def supports_file(self, file_node: FileNode) -> bool:
        """
        Check if this analyzer can handle the given file.
        
        Args:
            file_node: File to check
            
        Returns:
            bool: True if analyzer supports this file type
        """
        return file_node.extension in self.supported_extensions
    
    def create_finding(
        self,
        pattern_type: PatternType,
        pattern_name: str,
        severity: Severity,
        file_path: str,
        line_number: Optional[int] = None,
        column_number: Optional[int] = None,
        message: str = "",
        description: str = "",
        suggestion: str = "",
        **metadata
    ) -> Finding:
        """
        Create a finding with the given parameters.
        
        Args:
            pattern_type: Type of pattern
            pattern_name: Name of the pattern
            severity: Severity level
            file_path: Path to the file
            line_number: Line number (optional)
            column_number: Column number (optional)
            message: Short message
            description: Detailed description
            suggestion: Suggestion for improvement
            **metadata: Additional metadata
            
        Returns:
            Finding: Created finding
        """
        return Finding(
            pattern_type=pattern_type,
            pattern_name=pattern_name,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            message=message,
            description=description,
            suggestion=suggestion,
            metadata=metadata
        )
    
    def create_metric(
        self,
        name: str,
        value: float,
        description: str,
        file_path: Optional[str] = None,
        function_name: Optional[str] = None,
        class_name: Optional[str] = None,
        **metadata
    ) -> Metric:
        """
        Create a metric with the given parameters.
        
        Args:
            name: Name of the metric
            value: Metric value
            description: Description of the metric
            file_path: Path to the file (optional)
            function_name: Function name (optional)
            class_name: Class name (optional)
            **metadata: Additional metadata
            
        Returns:
            Metric: Created metric
        """
        return Metric(
            name=name,
            value=value,
            description=description,
            file_path=file_path,
            function_name=function_name,
            class_name=class_name,
            metadata=metadata
        )
    
    def enable_rule(self, rule_name: str) -> None:
        """Enable a specific rule."""
        self.enabled_rules.add(rule_name)
        self.disabled_rules.discard(rule_name)
    
    def disable_rule(self, rule_name: str) -> None:
        """Disable a specific rule."""
        self.disabled_rules.add(rule_name)
        self.enabled_rules.discard(rule_name)
    
    def is_rule_enabled(self, rule_name: str) -> bool:
        """Check if a rule is enabled."""
        if rule_name in self.disabled_rules:
            return False
        return len(self.enabled_rules) == 0 or rule_name in self.enabled_rules


class LinterBasedAnalyzer(BaseAnalyzer):
    """Base class for analyzers that leverage external linters."""
    
    def __init__(self, name: str, linter_command: str):
        """Initialize the linter-based analyzer."""
        super().__init__(name)
        self.linter_command = linter_command
        self.linter_config: Optional[str] = None
    
    @abstractmethod
    def parse_linter_output(self, output: str, file_path: str) -> List[Finding]:
        """
        Parse linter output into findings.
        
        Args:
            output: Linter output
            file_path: Path to the analyzed file
            
        Returns:
            List[Finding]: Parsed findings
        """
        pass
    
    def run_linter(self, file_path: str) -> Optional[str]:
        """
        Run the linter on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Optional[str]: Linter output, or None if linter failed
        """
        import subprocess
        
        try:
            cmd = [self.linter_command, file_path]
            if self.linter_config:
                cmd.extend(["--config", self.linter_config])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.stdout + result.stderr
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Linter timeout for {file_path}")
            return None
        except FileNotFoundError:
            logger.warning(f"Linter command not found: {self.linter_command}")
            return None
        except Exception as e:
            logger.error(f"Error running linter on {file_path}: {str(e)}")
            return None
