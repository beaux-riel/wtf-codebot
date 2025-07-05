"""
JavaScript/TypeScript static analysis using ESLint.
"""

import json
import re
import logging
from typing import List, Optional
from .base import LinterBasedAnalyzer, AnalysisResult, PatternType, Severity, Finding
from ..discovery.models import FileNode

logger = logging.getLogger(__name__)


class JavaScriptAnalyzer(LinterBasedAnalyzer):
    """
    JavaScript/TypeScript static analysis leveraging ESLint.
    """

    def __init__(self):
        """Initialize the JavaScript analyzer."""
        super().__init__("JavaScriptAnalyzer", "eslint")
        self.supported_extensions = {'.js', '.jsx', '.ts', '.tsx'}
        self.language_name = "javascript"

    def analyze_file(self, file_node: FileNode) -> AnalysisResult:
        """
        Analyze a single JavaScript/TypeScript file.

        Args:
            file_node: File to analyze

        Returns:
            AnalysisResult: Analysis results
        """
        result = AnalysisResult()
        
        # Run ESLint with JSON output
        linter_output = self.run_linter_with_json(str(file_node.path))
        
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

    def run_linter_with_json(self, file_path: str) -> Optional[str]:
        """
        Run ESLint with JSON output format.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Optional[str]: ESLint JSON output, or None if failed
        """
        import subprocess
        
        try:
            cmd = ["eslint", "--format", "json", file_path]
            if self.linter_config:
                cmd.extend(["--config", self.linter_config])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.warning(f"ESLint timeout for {file_path}")
            return None
        except FileNotFoundError:
            logger.warning("ESLint not found, falling back to basic analysis")
            return None
        except Exception as e:
            logger.error(f"Error running ESLint on {file_path}: {str(e)}")
            return None

    def parse_linter_output(self, output: str, file_path: str) -> List[Finding]:
        """
        Parse ESLint JSON output into findings.

        Args:
            output: ESLint JSON output
            file_path: Path to the analyzed file

        Returns:
            List[Finding]: Parsed findings
        """
        findings = []

        try:
            eslint_results = json.loads(output)
            
            if not eslint_results:
                return findings
            
            # ESLint returns an array of file results
            for file_result in eslint_results:
                if file_result.get("filePath") == file_path:
                    for message in file_result.get("messages", []):
                        finding = self.create_finding(
                            pattern_type=self.map_rule_to_pattern_type(message.get("ruleId")),
                            pattern_name=message.get("ruleId", "unknown"),
                            severity=self.map_eslint_severity(message.get("severity")),
                            file_path=file_path,
                            line_number=message.get("line"),
                            column_number=message.get("column"),
                            message=message.get("message", ""),
                            description=f"ESLint rule: {message.get('ruleId', 'unknown')}"
                        )
                        findings.append(finding)

        except json.JSONDecodeError as e:
            # If JSON parsing fails, try regex parsing
            findings = self._parse_text_output(output, file_path)

        return findings

    def map_rule_to_pattern_type(self, rule_id: Optional[str]) -> PatternType:
        """Map ESLint rule to pattern type."""
        if not rule_id:
            return PatternType.CODE_SMELL
        
        # Design patterns
        design_patterns = {
            "prefer-const", "prefer-template", "prefer-arrow-callback",
            "class-methods-use-this", "prefer-destructuring"
        }
        
        # Anti-patterns
        anti_patterns = {
            "no-var", "no-eval", "no-implicit-globals", "no-with",
            "no-prototype-builtins", "no-constructor-return"
        }
        
        if rule_id in design_patterns:
            return PatternType.DESIGN_PATTERN
        elif rule_id in anti_patterns:
            return PatternType.ANTI_PATTERN
        else:
            return PatternType.CODE_SMELL

    def map_eslint_severity(self, severity: Optional[int]) -> Severity:
        """Map ESLint severity to internal severity."""
        mapping = {
            1: Severity.WARNING,  # ESLint warning
            2: Severity.ERROR,    # ESLint error
        }
        return mapping.get(severity, Severity.INFO)

    def _parse_text_output(self, output: str, file_path: str) -> List[Finding]:
        """Fallback parser for ESLint text output."""
        findings = []
        
        # Pattern: file_path:line:column: severity message [rule_id]
        pattern = r'(\d+):(\d+):\s+(error|warning)\s+(.+?)\s+([a-zA-Z-]+)$'
        
        for line in output.split('\n'):
            match = re.search(pattern, line)
            if match:
                line_num = int(match.group(1))
                col_num = int(match.group(2))
                severity = match.group(3)
                message = match.group(4)
                rule_id = match.group(5)
                
                finding = self.create_finding(
                    pattern_type=self.map_rule_to_pattern_type(rule_id),
                    pattern_name=rule_id,
                    severity=Severity.ERROR if severity == "error" else Severity.WARNING,
                    file_path=file_path,
                    line_number=line_num,
                    column_number=col_num,
                    message=message
                )
                findings.append(finding)
        
        return findings

    def _detect_custom_patterns(self, file_node: FileNode) -> List[Finding]:
        """Detect custom JavaScript/TypeScript patterns."""
        findings = []
        
        if not file_node.content:
            return findings
        
        # Detect patterns using regex since we don't have full AST parsing
        findings.extend(self._detect_callback_hell(file_node))
        findings.extend(self._detect_large_functions(file_node))
        findings.extend(self._detect_unused_variables(file_node))
        findings.extend(self._detect_magic_numbers(file_node))
        findings.extend(self._detect_promise_patterns(file_node))
        
        return findings

    def _detect_callback_hell(self, file_node: FileNode) -> List[Finding]:
        """Detect callback hell anti-pattern."""
        findings = []
        lines = file_node.content.split('\n')
        
        # Look for deeply nested callbacks
        for i, line in enumerate(lines, 1):
            # Count nesting level by counting opening braces and function keywords
            stripped = line.strip()
            if 'function(' in stripped or '=>' in stripped:
                # Check nesting depth by looking at indentation
                indent_level = len(line) - len(line.lstrip())
                if indent_level > 16:  # More than 4 levels of nesting (assuming 4 spaces)
                    finding = self.create_finding(
                        pattern_type=PatternType.ANTI_PATTERN,
                        pattern_name="callback_hell",
                        severity=Severity.WARNING,
                        file_path=str(file_node.path),
                        line_number=i,
                        message="Deeply nested callback detected",
                        description="Excessive callback nesting makes code hard to read and maintain",
                        suggestion="Consider using Promises, async/await, or extracting functions"
                    )
                    findings.append(finding)
        
        return findings

    def _detect_large_functions(self, file_node: FileNode) -> List[Finding]:
        """Detect large functions."""
        findings = []
        lines = file_node.content.split('\n')
        
        in_function = False
        function_start = 0
        function_name = ""
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Function start patterns
            function_match = re.search(r'function\s+(\w+)', stripped)
            arrow_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=.*=>', stripped)
            method_match = re.search(r'(\w+)\s*\([^)]*\)\s*{', stripped)
            
            if function_match or arrow_match or method_match:
                if in_function:
                    # Previous function ended
                    function_length = i - function_start
                    if function_length > 50:
                        finding = self.create_finding(
                            pattern_type=PatternType.CODE_SMELL,
                            pattern_name="large_function",
                            severity=Severity.WARNING,
                            file_path=str(file_node.path),
                            line_number=function_start,
                            message=f"Large function detected: {function_name} ({function_length} lines)",
                            description="Function is too long and may be difficult to understand",
                            suggestion="Consider breaking this function into smaller functions"
                        )
                        findings.append(finding)
                
                # Start new function
                in_function = True
                function_start = i
                if function_match:
                    function_name = function_match.group(1)
                elif arrow_match:
                    function_name = arrow_match.group(1)
                elif method_match:
                    function_name = method_match.group(1)
        
        return findings

    def _detect_unused_variables(self, file_node: FileNode) -> List[Finding]:
        """Detect potentially unused variables."""
        findings = []
        lines = file_node.content.split('\n')
        
        # Simple heuristic: find variable declarations and check if they're used later
        declared_vars = {}
        
        for i, line in enumerate(lines, 1):
            # Find variable declarations
            var_matches = re.finditer(r'(?:const|let|var)\s+(\w+)', line)
            for match in var_matches:
                var_name = match.group(1)
                declared_vars[var_name] = i
        
        # Check if variables are used
        for var_name, line_num in declared_vars.items():
            used = False
            for j, line in enumerate(lines):
                if j + 1 != line_num:  # Skip declaration line
                    if re.search(r'\b' + re.escape(var_name) + r'\b', line):
                        used = True
                        break
            
            if not used:
                finding = self.create_finding(
                    pattern_type=PatternType.CODE_SMELL,
                    pattern_name="unused_variable",
                    severity=Severity.INFO,
                    file_path=str(file_node.path),
                    line_number=line_num,
                    message=f"Potentially unused variable: {var_name}",
                    description="Variable is declared but never used",
                    suggestion="Remove unused variable or use it"
                )
                findings.append(finding)
        
        return findings

    def _detect_magic_numbers(self, file_node: FileNode) -> List[Finding]:
        """Detect magic numbers."""
        findings = []
        lines = file_node.content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for numeric literals (excluding common values like 0, 1, -1)
            magic_numbers = re.finditer(r'\b(?!(?:0|1|-1|100|1000)\b)\d{2,}\b', line)
            for match in magic_numbers:
                number = match.group()
                finding = self.create_finding(
                    pattern_type=PatternType.CODE_SMELL,
                    pattern_name="magic_number",
                    severity=Severity.INFO,
                    file_path=str(file_node.path),
                    line_number=i,
                    message=f"Magic number detected: {number}",
                    description="Numeric literal should be replaced with a named constant",
                    suggestion="Extract this number into a named constant"
                )
                findings.append(finding)
        
        return findings

    def _detect_promise_patterns(self, file_node: FileNode) -> List[Finding]:
        """Detect Promise usage patterns."""
        findings = []
        lines = file_node.content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Detect nested .then() calls (Promise hell)
            if '.then(' in line and line.count('.then(') > 2:
                finding = self.create_finding(
                    pattern_type=PatternType.ANTI_PATTERN,
                    pattern_name="promise_hell",
                    severity=Severity.WARNING,
                    file_path=str(file_node.path),
                    line_number=i,
                    message="Promise chaining detected",
                    description="Long Promise chains can be hard to read and maintain",
                    suggestion="Consider using async/await syntax"
                )
                findings.append(finding)
            
            # Detect missing .catch()
            if '.then(' in line and '.catch(' not in line and i < len(lines) - 5:
                # Check next few lines for .catch()
                has_catch = any('.catch(' in lines[j] for j in range(i, min(i + 5, len(lines))))
                if not has_catch:
                    finding = self.create_finding(
                        pattern_type=PatternType.CODE_SMELL,
                        pattern_name="missing_error_handling",
                        severity=Severity.WARNING,
                        file_path=str(file_node.path),
                        line_number=i,
                        message="Promise without error handling",
                        description="Promise should have .catch() for error handling",
                        suggestion="Add .catch() to handle potential errors"
                    )
                    findings.append(finding)
        
        return findings

    def _calculate_metrics(self, file_node: FileNode) -> List:
        """Calculate JavaScript/TypeScript metrics."""
        metrics = []
        
        if not file_node.content:
            return metrics
        
        lines = file_node.content.split('\n')
        
        # Lines of code (excluding comments and blank lines)
        loc = len([
            line for line in lines 
            if line.strip() and not line.strip().startswith('//') and not line.strip().startswith('/*')
        ])
        
        metrics.append(self.create_metric(
            name="lines_of_code",
            value=float(loc),
            description="Number of lines of code (excluding comments and blank lines)",
            file_path=str(file_node.path)
        ))
        
        # Function count (simple regex-based)
        function_count = len(re.findall(r'function\s+\w+|=>\s*{|\w+\s*\([^)]*\)\s*{', file_node.content))
        metrics.append(self.create_metric(
            name="function_count",
            value=float(function_count),
            description="Number of functions defined",
            file_path=str(file_node.path)
        ))
        
        # Class count
        class_count = len(re.findall(r'class\s+\w+', file_node.content))
        metrics.append(self.create_metric(
            name="class_count",
            value=float(class_count),
            description="Number of classes defined",
            file_path=str(file_node.path)
        ))
        
        # Import count
        import_count = len(re.findall(r'import\s+.*from|require\s*\(', file_node.content))
        metrics.append(self.create_metric(
            name="import_count",
            value=float(import_count),
            description="Number of imports/requires",
            file_path=str(file_node.path)
        ))
        
        # Cyclomatic complexity (simplified)
        complexity = self._calculate_cyclomatic_complexity(file_node.content)
        metrics.append(self.create_metric(
            name="cyclomatic_complexity",
            value=float(complexity),
            description="Simplified cyclomatic complexity",
            file_path=str(file_node.path)
        ))
        
        return metrics

    def _calculate_cyclomatic_complexity(self, content: str) -> int:
        """Calculate simplified cyclomatic complexity for JavaScript."""
        complexity = 1  # Base complexity
        
        # Count decision points
        complexity += len(re.findall(r'\bif\b', content))
        complexity += len(re.findall(r'\belse\b', content))
        complexity += len(re.findall(r'\bwhile\b', content))
        complexity += len(re.findall(r'\bfor\b', content))
        complexity += len(re.findall(r'\bswitch\b', content))
        complexity += len(re.findall(r'\bcase\b', content))
        complexity += len(re.findall(r'\bcatch\b', content))
        complexity += len(re.findall(r'\?\s*.*?:', content))  # Ternary operators
        complexity += len(re.findall(r'&&|\|\|', content))  # Logical operators
        
        return complexity
