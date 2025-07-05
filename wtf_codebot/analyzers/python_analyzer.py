"""
Python static analysis using pylint.
"""

import json
import ast
import re
import logging
from typing import List
from .base import LinterBasedAnalyzer, AnalysisResult, PatternType, Severity, Finding
from ..discovery.models import FileNode

logger = logging.getLogger(__name__)


class PythonAnalyzer(LinterBasedAnalyzer):
    """
    Python static analysis leveraging pylint.
    """

    def __init__(self):
        """Initialize the Python analyzer."""
        super().__init__("PythonAnalyzer", "pylint")
        self.supported_extensions = {'.py'}
        self.language_name = "python"

    def analyze_file(self, file_node: FileNode) -> AnalysisResult:
        """
        Analyze a single Python file.

        Args:
            file_node: File to analyze

        Returns:
            AnalysisResult: Analysis results
        """
        result = AnalysisResult()
        linter_output = self.run_linter(str(file_node.path))

        if linter_output is not None:
            findings = self.parse_linter_output(linter_output, str(file_node.path))
            result.findings.extend(findings)

        # Add custom pattern detection
        custom_findings = self._detect_custom_patterns(file_node)
        result.findings.extend(custom_findings)
        
        # Add metrics
        metrics = self._calculate_metrics(file_node)
        result.metrics.extend(metrics)

        # Populate metadata using file_node attributes
        result.metadata.update({
            "functions": list(file_node.functions),
            "classes": list(file_node.classes),
            "variables": list(file_node.variables),
            "imports": list(file_node.imports),
            "exports": list(file_node.exports),
        })

        return result

    def parse_linter_output(self, output: str, file_path: str) -> List:
        """
        Parse pylint output into findings.

        Args:
            output: Linter output
            file_path: Path to the analyzed file

        Returns:
            List: Parsed findings
        """
        findings = []

        try:
            linter_json = json.loads(output)

            for issue in linter_json:
                finding = self.create_finding(
                    pattern_type=self.map_category_to_pattern_type(issue.get("type")),
                    pattern_name=issue.get("message-id", "Unknown"),
                    severity=self.map_linter_severity_to_severity(issue.get("severity")),
                    file_path=file_path,
                    line_number=issue.get("line"),
                    column_number=issue.get("column"),
                    message=issue.get("message"),
                    description=issue.get("symbol"),
                )
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON output from linter for {file_path}: {str(e)}")

        return findings

    def map_category_to_pattern_type(self, category: str):
        """Map linter category to pattern type."""
        mapping = {
            "convention": PatternType.DESIGN_PATTERN,
            "refactor": PatternType.CODE_SMELL,
            "warning": PatternType.CODE_SMELL,
            "error": PatternType.ANTI_PATTERN,
            "fatal": PatternType.ANTI_PATTERN,
        }
        return mapping.get(category, PatternType.CODE_SMELL)

    def map_linter_severity_to_severity(self, severity: str):
        """Map linter severity to internal severity."""
        mapping = {
            "convention": Severity.INFO,
            "refactor": Severity.WARNING,
            "warning": Severity.WARNING,
            "error": Severity.ERROR,
            "fatal": Severity.CRITICAL,
        }
        return mapping.get(severity, Severity.INFO)
    
    def _detect_custom_patterns(self, file_node: FileNode) -> List[Finding]:
        """Detect custom design patterns and anti-patterns."""
        findings = []
        
        if not file_node.content:
            return findings
        
        try:
            tree = ast.parse(file_node.content)
            
            # Detect design patterns
            findings.extend(self._detect_singleton_pattern(tree, file_node.path))
            findings.extend(self._detect_factory_pattern(tree, file_node.path))
            findings.extend(self._detect_observer_pattern(tree, file_node.path))
            
            # Detect anti-patterns and code smells
            findings.extend(self._detect_god_class(tree, file_node.path))
            findings.extend(self._detect_long_methods(tree, file_node.path))
            findings.extend(self._detect_deep_nesting(tree, file_node.path))
            findings.extend(self._detect_duplicate_code(tree, file_node.path))
            
        except SyntaxError:
            # If AST parsing fails, skip custom analysis
            pass
        
        return findings
    
    def _detect_singleton_pattern(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect Singleton design pattern."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Look for __new__ method with singleton characteristics
                for item in node.body:
                    if (isinstance(item, ast.FunctionDef) and 
                        item.name == '__new__' and 
                        any(isinstance(stmt, ast.If) for stmt in item.body)):
                        
                        finding = self.create_finding(
                            pattern_type=PatternType.DESIGN_PATTERN,
                            pattern_name="singleton",
                            severity=Severity.INFO,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            message=f"Singleton pattern detected in class {node.name}",
                            description="Class implements singleton pattern using __new__ method"
                        )
                        findings.append(finding)
        
        return findings
    
    def _detect_factory_pattern(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect Factory design pattern."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Look for factory method patterns
                if (node.name.startswith('create_') or 
                    node.name.startswith('make_') or 
                    node.name.endswith('_factory')):
                    
                    # Check if it returns different types based on conditions
                    has_conditional_returns = any(
                        isinstance(stmt, ast.If) and 
                        any(isinstance(s, ast.Return) for s in ast.walk(stmt))
                        for stmt in node.body
                    )
                    
                    if has_conditional_returns:
                        finding = self.create_finding(
                            pattern_type=PatternType.DESIGN_PATTERN,
                            pattern_name="factory_method",
                            severity=Severity.INFO,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            message=f"Factory method pattern detected: {node.name}",
                            description="Function appears to implement factory method pattern"
                        )
                        findings.append(finding)
        
        return findings
    
    def _detect_observer_pattern(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect Observer design pattern."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Look for observer pattern characteristics
                has_observers_list = False
                has_notify_method = False
                has_add_observer = False
                
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if (isinstance(target, ast.Name) and 
                                ('observer' in target.id.lower() or 
                                 'listener' in target.id.lower())):
                                has_observers_list = True
                    
                    elif isinstance(item, ast.FunctionDef):
                        if 'notify' in item.name.lower():
                            has_notify_method = True
                        elif ('add' in item.name.lower() and 
                              ('observer' in item.name.lower() or 
                               'listener' in item.name.lower())):
                            has_add_observer = True
                
                if has_observers_list and has_notify_method and has_add_observer:
                    finding = self.create_finding(
                        pattern_type=PatternType.DESIGN_PATTERN,
                        pattern_name="observer",
                        severity=Severity.INFO,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"Observer pattern detected in class {node.name}",
                        description="Class implements observer pattern with notify and add methods"
                    )
                    findings.append(finding)
        
        return findings
    
    def _detect_god_class(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect God Class anti-pattern."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Count methods and attributes
                method_count = 0
                attribute_count = 0
                
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        method_count += 1
                    elif isinstance(item, ast.Assign):
                        attribute_count += 1
                
                # Heuristic: more than 20 methods or 15 attributes
                if method_count > 20 or attribute_count > 15:
                    finding = self.create_finding(
                        pattern_type=PatternType.ANTI_PATTERN,
                        pattern_name="god_class",
                        severity=Severity.WARNING,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"God class detected: {node.name} ({method_count} methods, {attribute_count} attributes)",
                        description="Class has too many responsibilities (high method/attribute count)",
                        suggestion="Consider breaking this class into smaller, more focused classes"
                    )
                    findings.append(finding)
        
        return findings
    
    def _detect_long_methods(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect long method code smell."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Count lines of code (excluding comments and docstrings)
                line_count = 0
                if hasattr(node, 'end_lineno') and node.end_lineno:
                    line_count = node.end_lineno - node.lineno + 1
                else:
                    # Fallback: count statements
                    line_count = len([n for n in ast.walk(node) if isinstance(n, ast.stmt)])
                
                # Heuristic: more than 50 lines
                if line_count > 50:
                    finding = self.create_finding(
                        pattern_type=PatternType.CODE_SMELL,
                        pattern_name="long_method",
                        severity=Severity.WARNING,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"Long method detected: {node.name} ({line_count} lines)",
                        description="Method is too long and may be difficult to understand and maintain",
                        suggestion="Consider breaking this method into smaller, more focused methods"
                    )
                    findings.append(finding)
        
        return findings
    
    def _detect_deep_nesting(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect deep nesting code smell."""
        findings = []
        
        def get_nesting_depth(node, depth=0):
            max_depth = depth
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    child_depth = get_nesting_depth(child, depth + 1)
                    max_depth = max(max_depth, child_depth)
                else:
                    child_depth = get_nesting_depth(child, depth)
                    max_depth = max(max_depth, child_depth)
            return max_depth
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                nesting_depth = get_nesting_depth(node)
                
                # Heuristic: more than 4 levels of nesting
                if nesting_depth > 4:
                    finding = self.create_finding(
                        pattern_type=PatternType.CODE_SMELL,
                        pattern_name="deep_nesting",
                        severity=Severity.WARNING,
                        file_path=str(file_path),
                        line_number=node.lineno,
                        message=f"Deep nesting detected in {node.name} (depth: {nesting_depth})",
                        description="Function has too many nested control structures",
                        suggestion="Consider using early returns or extracting nested logic into separate functions"
                    )
                    findings.append(finding)
        
        return findings
    
    def _detect_duplicate_code(self, tree: ast.AST, file_path: str) -> List[Finding]:
        """Detect duplicate code blocks."""
        findings = []
        
        # Simple heuristic: look for identical function bodies
        function_bodies = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Create a simple signature of the function body
                body_signature = []
                for stmt in node.body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Str):
                        # Skip docstrings
                        continue
                    body_signature.append(type(stmt).__name__)
                
                signature = tuple(body_signature)
                if len(signature) > 3:  # Only check functions with substantial bodies
                    if signature in function_bodies:
                        finding = self.create_finding(
                            pattern_type=PatternType.CODE_SMELL,
                            pattern_name="duplicate_code",
                            severity=Severity.INFO,
                            file_path=str(file_path),
                            line_number=node.lineno,
                            message=f"Potential duplicate code in {node.name}",
                            description=f"Function {node.name} has similar structure to {function_bodies[signature]}",
                            suggestion="Consider extracting common logic into a shared function"
                        )
                        findings.append(finding)
                    else:
                        function_bodies[signature] = node.name
        
        return findings
    
    def _calculate_metrics(self, file_node: FileNode) -> List:
        """Calculate code metrics."""
        metrics = []
        
        if not file_node.content:
            return metrics
        
        try:
            tree = ast.parse(file_node.content)
            
            # Lines of code
            lines = file_node.content.split('\n')
            loc = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
            
            metrics.append(self.create_metric(
                name="lines_of_code",
                value=float(loc),
                description="Number of lines of code (excluding comments and blank lines)",
                file_path=str(file_node.path)
            ))
            
            # Cyclomatic complexity (simplified)
            complexity = self._calculate_cyclomatic_complexity(tree)
            metrics.append(self.create_metric(
                name="cyclomatic_complexity",
                value=float(complexity),
                description="Simplified cyclomatic complexity measure",
                file_path=str(file_node.path)
            ))
            
            # Function and class counts
            metrics.append(self.create_metric(
                name="function_count",
                value=float(len(file_node.functions)),
                description="Number of functions defined",
                file_path=str(file_node.path)
            ))
            
            metrics.append(self.create_metric(
                name="class_count",
                value=float(len(file_node.classes)),
                description="Number of classes defined",
                file_path=str(file_node.path)
            ))
            
            # Import count
            metrics.append(self.create_metric(
                name="import_count",
                value=float(len(file_node.imports)),
                description="Number of imported modules",
                file_path=str(file_node.path)
            ))
            
        except SyntaxError:
            # If parsing fails, just return basic metrics
            lines = file_node.content.split('\n')
            loc = len([line for line in lines if line.strip()])
            metrics.append(self.create_metric(
                name="total_lines",
                value=float(loc),
                description="Total number of lines",
                file_path=str(file_node.path)
            ))
        
        return metrics
    
    def _calculate_cyclomatic_complexity(self, tree: ast.AST) -> int:
        """Calculate simplified cyclomatic complexity."""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, ast.With):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                # Add complexity for each additional condition
                complexity += len(node.values) - 1
        
        return complexity
