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
        self._eslint_config_checked = False
        self._has_eslint_config = False
        self._project_root = None
        self._config_logged = False
        self._codebase_root = None

    def analyze_codebase(self, codebase, progress_callback=None):
        """Override to capture codebase root path."""
        # Store the codebase root path for ESLint config detection
        self._codebase_root = codebase.root_path
        logger.debug(f"JavaScript analyzer: codebase root set to {self._codebase_root}")
        
        # Call parent implementation
        return super().analyze_codebase(codebase, progress_callback)

    def analyze_file(self, file_node: FileNode) -> AnalysisResult:
        """
        Analyze a single JavaScript/TypeScript file.

        Args:
            file_node: File to analyze

        Returns:
            AnalysisResult: Analysis results
        """
        logger.debug(f"Starting JavaScript analysis for: {file_node.path}")
        result = AnalysisResult()
        
        # Check if we should run ESLint
        if self._should_run_eslint(file_node):
            # Run ESLint with JSON output
            logger.debug(f"Running ESLint on: {file_node.path}")
            try:
                linter_output = self.run_linter_with_json(str(file_node.path))
                
                if linter_output is not None:
                    logger.debug(f"ESLint output received for: {file_node.path}")
                    findings = self.parse_linter_output(linter_output, str(file_node.path))
                    result.findings.extend(findings)
                else:
                    logger.debug(f"No ESLint output for: {file_node.path}, using only custom pattern detection")
            except Exception as e:
                logger.error(f"ESLint analysis failed for {file_node.path}: {str(e)}, falling back to custom patterns only")
        else:
            logger.debug(f"Skipping ESLint for {file_node.path} - no ESLint config found")

        # Add custom pattern detection
        logger.debug(f"Running custom pattern detection for: {file_node.path}")
        custom_findings = self._detect_custom_patterns(file_node)
        result.findings.extend(custom_findings)
        
        # Add metrics
        logger.debug(f"Calculating metrics for: {file_node.path}")
        metrics = self._calculate_metrics(file_node)
        result.metrics.extend(metrics)
        
        logger.debug(f"Completed JavaScript analysis for: {file_node.path} - {len(result.findings)} findings, {len(result.metrics)} metrics")

        # Populate metadata using file_node attributes
        result.metadata.update({
            "functions": list(file_node.functions),
            "classes": list(file_node.classes),
            "variables": list(file_node.variables),
            "imports": list(file_node.imports),
            "exports": list(file_node.exports),
        })

        return result

    def _should_run_eslint(self, file_node: FileNode) -> bool:
        """
        Check if ESLint should be run for this project.
        
        Args:
            file_node: File node being analyzed
            
        Returns:
            bool: True if ESLint should run, False otherwise
        """
        import os
        
        # Only check once per analyzer instance (not per file)
        if not self._eslint_config_checked:
            self._eslint_config_checked = True
            logger.debug(f"First file triggering ESLint config check: {file_node.path}")
            
            # Ensure we have an absolute path
            file_path = file_node.path
            logger.debug(f"Original file path: {file_path}, is_absolute: {file_path.is_absolute()}")
            
            if not file_path.is_absolute():
                file_path = file_path.resolve()
                logger.debug(f"Resolved to absolute path: {file_path}")
            
            logger.debug(f"Checking for ESLint config starting from: {file_path.parent}")
            
            # Check for ESLint config files
            config_files = [
                'eslint.config.js',
                'eslint.config.mjs',
                'eslint.config.cjs',
                '.eslintrc.js',
                '.eslintrc.cjs',
                '.eslintrc.yaml',
                '.eslintrc.yml',
                '.eslintrc.json',
                '.eslintrc'
            ]
            
            # First, check the codebase root if available
            if self._codebase_root:
                logger.debug(f"Checking codebase root for ESLint config: {self._codebase_root}")
                for config_file in config_files:
                    config_path = self._codebase_root / config_file
                    if config_path.exists():
                        if not self._config_logged:
                            logger.info(f"Found ESLint config: {config_path}")
                            self._config_logged = True
                        self._has_eslint_config = True
                        # Store the config path and project root
                        self.linter_config = str(config_path)
                        self._project_root = str(self._codebase_root)
                        return True
            
            # If not found at codebase root, search upward from file
            project_root = file_path.parent
            
            # Handle edge case where parent is empty or current directory
            if str(project_root) == '.' or not str(project_root):
                from pathlib import Path as PathLib
                project_root = PathLib.cwd()
                logger.debug(f"Parent was relative, using cwd: {project_root}")
            
            search_count = 0
            max_search_depth = 10  # Prevent infinite loops
            
            while project_root.parent != project_root and search_count < max_search_depth:
                search_count += 1
                logger.debug(f"Searching for ESLint config in: {project_root}")
                
                for config_file in config_files:
                    config_path = project_root / config_file
                    if config_path.exists():
                        if not self._config_logged:
                            logger.info(f"Found ESLint config: {config_path}")
                            self._config_logged = True
                        self._has_eslint_config = True
                        # Store the config path and project root
                        self.linter_config = str(config_path)
                        self._project_root = str(project_root)
                        return True
                
                # Check parent directory
                if project_root.parent == project_root:
                    break
                project_root = project_root.parent
            
            if not self._has_eslint_config and not self._config_logged:
                logger.info(f"No ESLint config found when searching from {file_path.parent} - will use custom pattern detection only")
                self._config_logged = True
        
        return self._has_eslint_config

    def run_linter_with_json(self, file_path: str) -> Optional[str]:
        """
        Run ESLint with JSON output format.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Optional[str]: ESLint JSON output, or None if failed
        """
        import subprocess
        import os
        
        # Check if file exists before running ESLint
        if not os.path.exists(file_path):
            logger.debug(f"File does not exist: {file_path}")
            return None
        
        try:
            # Build ESLint command
            cmd = ["eslint", "--format", "json"]
            
            # For flat config files (eslint.config.*), don't use --config flag
            # ESLint 9+ will automatically find and use these files
            if self.linter_config:
                config_name = os.path.basename(self.linter_config)
                if config_name.startswith('eslint.config.'):
                    # Flat config file - ESLint will find it automatically
                    logger.debug(f"Using flat ESLint config: {self.linter_config} (no --config flag needed)")
                else:
                    # Legacy config file - use --config flag
                    cmd.extend(["--config", self.linter_config])
                    logger.debug(f"Using legacy ESLint config: {self.linter_config}")
            
            # Add file path
            cmd.append(file_path)
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run from project root if available (for flat config to work properly)
            cwd = self._project_root if self._project_root else None
            if cwd:
                logger.debug(f"Running ESLint from directory: {cwd}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=cwd
            )
            
            # ESLint returns non-zero exit code when it finds issues, which is normal
            if result.returncode not in [0, 1]:
                logger.debug(f"ESLint failed with exit code {result.returncode}")
                if result.stderr:
                    logger.debug(f"stderr: {result.stderr}")
                return None
            
            if result.stderr and "Oops! Something went wrong" not in result.stderr:
                logger.debug(f"ESLint stderr for {file_path}: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.debug(f"ESLint timeout for {file_path} after 30 seconds")
            return None
        except FileNotFoundError:
            logger.debug("ESLint not found in PATH, falling back to basic analysis")
            return None
        except Exception as e:
            logger.debug(f"Error running ESLint on {file_path}: {type(e).__name__}: {str(e)}")
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
            logger.debug(f"Parsing ESLint output for {file_path}, output length: {len(output)}")
            eslint_results = json.loads(output)
            
            if not eslint_results:
                logger.debug(f"Empty ESLint results for {file_path}")
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
            logger.error(f"Failed to parse ESLint JSON output for {file_path}: {str(e)}")
            logger.error(f"Output preview: {output[:200]}..." if len(output) > 200 else f"Output: {output}")
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
