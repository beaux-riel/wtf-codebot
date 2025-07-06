"""
Claude API client for pattern recognition with retry, back-off, and streaming support.
"""

import asyncio
import json
import time
from typing import List, Dict, Any, Optional, AsyncIterator, Union
from dataclasses import dataclass
import random
from pathlib import Path

import anthropic
from anthropic import AsyncAnthropic

from .batcher import CodeBatch, CodeSnippet
from .patterns import (
    PatternType, PatternMatch, DesignPattern, AntiPattern, 
    PatternAnalysisResults
)
from .cost_tracker import CostTracker
try:
    from ..core.config import get_config
except ImportError:
    # Fallback if config module is not available
    class MockConfig:
        anthropic_api_key = ""
        anthropic_model = "claude-sonnet-4-0"
    def get_config():
        return MockConfig()

try:
    from ..core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class PatternAnalysisResult:
    """Result from pattern analysis of a single batch."""
    batch_id: str
    patterns: List[PatternMatch]
    analysis_time: float
    token_usage: Dict[str, int]
    success: bool
    error_message: Optional[str] = None


class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(self,
                 max_retries: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            # Add ±25% jitter
            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(0, delay)


class ClaudePatternAnalyzer:
    """Claude-powered pattern analysis with advanced features."""
    
    PATTERN_ANALYSIS_PROMPT = """
You are an expert software architect and code quality analyst. Analyze the provided code snippets to identify design patterns, anti-patterns, and code quality issues.

For each code snippet, identify:

1. **Design Patterns**: Well-known software design patterns (Singleton, Factory, Observer, etc.)
2. **Anti-patterns**: Code smells and poor practices (God Object, Spaghetti Code, etc.)
3. **Code Quality Issues**: Performance, security, maintainability concerns

For each pattern detected, provide:
- Pattern type and confidence level (0.0-1.0)
- Line numbers where the pattern occurs
- Evidence supporting the detection
- Severity (info, warning, error, critical)
- Impact and effort estimates for fixes
- Specific recommendations for improvement

Respond in valid JSON format with this structure:
```json
{{
  "design_patterns": [
    {{
      "pattern_type": "singleton",
      "confidence": 0.9,
      "file_path": "path/to/file.py",
      "line_start": 10,
      "line_end": 25,
      "description": "Singleton pattern implementation",
      "evidence": ["Private constructor", "Static instance method"],
      "severity": "info",
      "impact": "low",
      "effort": "low",
      "benefits": ["Controlled instantiation", "Global access point"],
      "use_cases": ["Configuration managers", "Logging services"],
      "related_patterns": ["Factory", "Abstract Factory"]
    }}
  ],
  "anti_patterns": [
    {{
      "pattern_type": "god_object",
      "confidence": 0.8,
      "file_path": "path/to/file.py",
      "line_start": 1,
      "line_end": 200,
      "description": "Class with too many responsibilities",
      "evidence": ["50+ methods", "Multiple unrelated concerns"],
      "severity": "error",
      "impact": "high",
      "effort": "high",
      "problems": ["Poor maintainability", "High coupling"],
      "solutions": ["Split into focused classes", "Use composition"],
      "refactoring_suggestions": ["Extract service classes", "Apply Single Responsibility Principle"]
    }}
  ],
  "code_quality_issues": [
    {{
      "pattern_type": "security_vulnerability",
      "confidence": 0.95,
      "file_path": "path/to/file.py",
      "line_start": 45,
      "line_end": 48,
      "description": "SQL injection vulnerability",
      "evidence": ["Dynamic SQL construction", "Unsanitized user input"],
      "severity": "critical",
      "impact": "critical",
      "effort": "medium"
    }}
  ]
}}
```

Code to analyze:
{code_content}
"""

    STREAMING_PATTERN_PROMPT = """
Analyze the following code for design patterns and anti-patterns. 
Stream your analysis as you identify each pattern.

Code:
{code_content}

Provide analysis in JSON format, one pattern per response.
"""

    def __init__(self, 
                 cost_tracker: Optional[CostTracker] = None,
                 retry_config: Optional[RetryConfig] = None,
                 enable_streaming: bool = False):
        """Initialize Claude pattern analyzer.
        
        Args:
            cost_tracker: Cost tracking instance
            retry_config: Retry configuration
            enable_streaming: Enable streaming responses
        """
        self.config = get_config()
        self.cost_tracker = cost_tracker
        self.retry_config = retry_config or RetryConfig()
        self.enable_streaming = enable_streaming
        
        # Initialize Claude client
        self.client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
        self.async_client = AsyncAnthropic(api_key=self.config.anthropic_api_key)
        
        logger.info(f"Claude pattern analyzer initialized with model {self.config.anthropic_model}")
        if self.cost_tracker:
            logger.info("Cost tracking enabled")
        if self.enable_streaming:
            logger.info("Streaming mode enabled")
    
    async def analyze_batches(self, 
                            batches: List[CodeBatch],
                            concurrent_requests: int = 3) -> PatternAnalysisResults:
        """Analyze multiple code batches concurrently.
        
        Args:
            batches: List of code batches to analyze
            concurrent_requests: Number of concurrent API requests
            
        Returns:
            Combined pattern analysis results
        """
        logger.info(f"Starting analysis of {len(batches)} batches with {concurrent_requests} concurrent requests")
        
        # Check budget limits
        if self.cost_tracker and not self.cost_tracker.check_budget_limits():
            raise RuntimeError("Budget limits exceeded, cannot proceed with analysis")
        
        start_time = time.time()
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(concurrent_requests)
        
        # Analyze batches concurrently
        tasks = [
            self._analyze_batch_with_semaphore(batch, semaphore)
            for batch in batches
        ]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        design_patterns = []
        anti_patterns = []
        code_quality_issues = []
        total_files = 0
        total_lines = 0
        
        successful_results = 0
        for result in batch_results:
            if isinstance(result, Exception):
                logger.error(f"Batch analysis failed: {result}")
                continue
            
            if not result.success:
                logger.warning(f"Batch {result.batch_id} analysis failed: {result.error_message}")
                continue
            
            successful_results += 1
            for pattern in result.patterns:
                if isinstance(pattern, DesignPattern):
                    design_patterns.append(pattern)
                elif isinstance(pattern, AntiPattern):
                    anti_patterns.append(pattern)
                else:
                    code_quality_issues.append(pattern)
            
            # Count files and lines from batch
            batch = next((b for b in batches if b.id == result.batch_id), None)
            if batch:
                batch_files = set(str(s.file_path) for s in batch.snippets)
                total_files += len(batch_files)
                total_lines += sum(s.end_line - s.start_line + 1 for s in batch.snippets)
        
        analysis_duration = time.time() - start_time
        
        logger.info(f"Analysis completed: {successful_results}/{len(batches)} batches successful, "
                   f"found {len(design_patterns)} design patterns, {len(anti_patterns)} anti-patterns, "
                   f"{len(code_quality_issues)} quality issues in {analysis_duration:.2f}s")
        
        return PatternAnalysisResults(
            design_patterns=design_patterns,
            anti_patterns=anti_patterns,
            code_quality_issues=code_quality_issues,
            total_files_analyzed=total_files,
            total_lines_analyzed=total_lines,
            analysis_duration=analysis_duration
        )
    
    async def _analyze_batch_with_semaphore(self, 
                                          batch: CodeBatch, 
                                          semaphore: asyncio.Semaphore) -> PatternAnalysisResult:
        """Analyze a single batch with semaphore control."""
        async with semaphore:
            return await self.analyze_batch(batch)
    
    async def analyze_batch(self, batch: CodeBatch) -> PatternAnalysisResult:
        """Analyze a single code batch.
        
        Args:
            batch: Code batch to analyze
            
        Returns:
            Pattern analysis result
        """
        logger.debug(f"Analyzing batch {batch.id} with {len(batch.snippets)} snippets")
        
        start_time = time.time()
        
        # Prepare content for analysis
        content = batch.get_combined_content()
        
        if self.enable_streaming:
            return await self._analyze_batch_streaming(batch, content)
        else:
            return await self._analyze_batch_standard(batch, content)
    
    async def _analyze_batch_standard(self, 
                                    batch: CodeBatch, 
                                    content: str) -> PatternAnalysisResult:
        """Analyze batch using standard API calls."""
        start_time = time.time()
        
        # Count input tokens
        input_tokens = self._count_tokens(content)
        
        # Prepare prompt
        prompt = self.PATTERN_ANALYSIS_PROMPT.format(code_content=content)
        
        try:
            # Make API call with retry logic
            if self.cost_tracker:
                with self.cost_tracker.track_request(
                    model=self.config.anthropic_model,
                    request_type="pattern_analysis",
                    input_tokens=input_tokens
                ) as record_completion:
                    
                    response = await self._make_api_call_with_retry(prompt)
                    output_tokens = self._count_tokens(response.content[0].text)
                    record_completion(output_tokens)
            else:
                response = await self._make_api_call_with_retry(prompt)
            
            # Parse response
            patterns = self._parse_pattern_response(response.content[0].text, batch)
            
            analysis_time = time.time() - start_time
            
            return PatternAnalysisResult(
                batch_id=batch.id,
                patterns=patterns,
                analysis_time=analysis_time,
                token_usage={
                    "input_tokens": input_tokens,
                    "output_tokens": self._count_tokens(response.content[0].text) if response else 0
                },
                success=True
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze batch {batch.id}: {e}", exc_info=True)
            return PatternAnalysisResult(
                batch_id=batch.id,
                patterns=[],
                analysis_time=time.time() - start_time,
                token_usage={"input_tokens": input_tokens, "output_tokens": 0},
                success=False,
                error_message=str(e)
            )
    
    async def _analyze_batch_streaming(self, 
                                     batch: CodeBatch, 
                                     content: str) -> PatternAnalysisResult:
        """Analyze batch using streaming API."""
        start_time = time.time()
        input_tokens = self._count_tokens(content)
        
        prompt = self.STREAMING_PATTERN_PROMPT.format(code_content=content)
        
        patterns = []
        total_output_tokens = 0
        
        try:
            if self.cost_tracker:
                with self.cost_tracker.track_request(
                    model=self.config.anthropic_model,
                    request_type="pattern_analysis_streaming",
                    input_tokens=input_tokens
                ) as record_completion:
                    
                    async for pattern_data in self._stream_pattern_analysis(prompt):
                        if pattern_data:
                            pattern = self._parse_single_pattern(pattern_data, batch)
                            if pattern:
                                patterns.append(pattern)
                        total_output_tokens += self._count_tokens(str(pattern_data))
                    
                    record_completion(total_output_tokens)
            else:
                async for pattern_data in self._stream_pattern_analysis(prompt):
                    if pattern_data:
                        pattern = self._parse_single_pattern(pattern_data, batch)
                        if pattern:
                            patterns.append(pattern)
            
            analysis_time = time.time() - start_time
            
            return PatternAnalysisResult(
                batch_id=batch.id,
                patterns=patterns,
                analysis_time=analysis_time,
                token_usage={
                    "input_tokens": input_tokens,
                    "output_tokens": total_output_tokens
                },
                success=True
            )
            
        except Exception as e:
            logger.error(f"Failed to stream analyze batch {batch.id}: {e}")
            return PatternAnalysisResult(
                batch_id=batch.id,
                patterns=patterns,
                analysis_time=time.time() - start_time,
                token_usage={"input_tokens": input_tokens, "output_tokens": total_output_tokens},
                success=False,
                error_message=str(e)
            )
    
    async def _make_api_call_with_retry(self, prompt: str) -> anthropic.types.Message:
        """Make API call with retry logic."""
        last_exception = None
        
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                response = await self.async_client.messages.create(
                    model=self.config.anthropic_model,
                    max_tokens=4000,
                    temperature=0.1,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
                return response
                
            except anthropic.RateLimitError as e:
                last_exception = e
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.get_delay(attempt)
                    logger.warning(f"Rate limited, retrying in {delay:.2f}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                else:
                    raise e
                    
            except (anthropic.APIError, anthropic.APIConnectionError) as e:
                last_exception = e
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.get_delay(attempt)
                    logger.warning(f"API error, retrying in {delay:.2f}s (attempt {attempt + 1}): {e}")
                    await asyncio.sleep(delay)
                else:
                    raise e
                    
            except Exception as e:
                logger.error(f"Unexpected error in API call: {e}")
                raise e
        
        raise last_exception or RuntimeError("Max retries exceeded")
    
    async def _stream_pattern_analysis(self, prompt: str) -> AsyncIterator[Dict[str, Any]]:
        """Stream pattern analysis results."""
        try:
            async with self.async_client.messages.stream(
                model=self.config.anthropic_model,
                max_tokens=4000,
                temperature=0.1,
                messages=[
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ]
            ) as stream:
                accumulated_text = ""
                async for text in stream.text_stream:
                    accumulated_text += text
                    
                    # Try to parse complete JSON objects
                    try:
                        # Look for complete JSON objects
                        start_idx = 0
                        while True:
                            start = accumulated_text.find('{', start_idx)
                            if start == -1:
                                break
                            
                            # Find matching closing brace
                            brace_count = 0
                            end = start
                            for i, char in enumerate(accumulated_text[start:], start):
                                if char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        end = i
                                        break
                            
                            if brace_count == 0:  # Found complete JSON object
                                json_str = accumulated_text[start:end+1]
                                try:
                                    pattern_data = json.loads(json_str)
                                    yield pattern_data
                                    accumulated_text = accumulated_text[end+1:]
                                    start_idx = 0
                                except json.JSONDecodeError:
                                    start_idx = start + 1
                            else:
                                break
                                
                    except Exception as e:
                        logger.debug(f"Error parsing streaming JSON: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Streaming API error: {e}")
            raise
    
    def _parse_pattern_response(self, response_text: str, batch: CodeBatch) -> List[PatternMatch]:
        """Parse pattern analysis response into pattern objects."""
        try:
            # Clean up response text (remove markdown formatting if present)
            response_text = response_text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            data = json.loads(response_text)
            patterns = []
            
            # Parse design patterns
            for pattern_data in data.get('design_patterns', []):
                pattern = self._create_design_pattern(pattern_data, batch)
                if pattern:
                    patterns.append(pattern)
            
            # Parse anti-patterns
            for pattern_data in data.get('anti_patterns', []):
                pattern = self._create_anti_pattern(pattern_data, batch)
                if pattern:
                    patterns.append(pattern)
            
            # Parse code quality issues
            for pattern_data in data.get('code_quality_issues', []):
                pattern = self._create_pattern_match(pattern_data, batch)
                if pattern:
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Failed to parse pattern response: {e}")
            logger.debug(f"Response text: {response_text[:500]}...")
            return []
    
    def _parse_single_pattern(self, pattern_data: Dict[str, Any], batch: CodeBatch) -> Optional[PatternMatch]:
        """Parse a single pattern from streaming data."""
        try:
            # Determine pattern type
            if 'benefits' in pattern_data:
                return self._create_design_pattern(pattern_data, batch)
            elif 'problems' in pattern_data:
                return self._create_anti_pattern(pattern_data, batch)
            else:
                return self._create_pattern_match(pattern_data, batch)
        except Exception as e:
            logger.debug(f"Failed to parse single pattern: {e}")
            return None
    
    def _create_design_pattern(self, data: Dict[str, Any], batch: CodeBatch) -> Optional[DesignPattern]:
        """Create DesignPattern from data."""
        try:
            pattern_type = PatternType(data['pattern_type'])
            
            return DesignPattern(
                pattern_type=pattern_type,
                confidence=data['confidence'],
                file_path=Path(data['file_path']),
                line_start=data['line_start'],
                line_end=data['line_end'],
                description=data['description'],
                evidence=data['evidence'],
                severity=data['severity'],
                impact=data['impact'],
                effort=data['effort'],
                benefits=data.get('benefits', []),
                use_cases=data.get('use_cases', []),
                related_patterns=data.get('related_patterns', [])
            )
        except Exception as e:
            logger.debug(f"Failed to create design pattern: {e}")
            return None
    
    def _create_anti_pattern(self, data: Dict[str, Any], batch: CodeBatch) -> Optional[AntiPattern]:
        """Create AntiPattern from data."""
        try:
            pattern_type = PatternType(data['pattern_type'])
            
            return AntiPattern(
                pattern_type=pattern_type,
                confidence=data['confidence'],
                file_path=Path(data['file_path']),
                line_start=data['line_start'],
                line_end=data['line_end'],
                description=data['description'],
                evidence=data['evidence'],
                severity=data['severity'],
                impact=data['impact'],
                effort=data['effort'],
                problems=data.get('problems', []),
                solutions=data.get('solutions', []),
                refactoring_suggestions=data.get('refactoring_suggestions', [])
            )
        except Exception as e:
            logger.debug(f"Failed to create anti-pattern: {e}")
            return None
    
    def _create_pattern_match(self, data: Dict[str, Any], batch: CodeBatch) -> Optional[PatternMatch]:
        """Create PatternMatch from data."""
        try:
            pattern_type = PatternType(data['pattern_type'])
            
            return PatternMatch(
                pattern_type=pattern_type,
                confidence=data['confidence'],
                file_path=Path(data['file_path']),
                line_start=data['line_start'],
                line_end=data['line_end'],
                description=data['description'],
                evidence=data['evidence'],
                severity=data['severity'],
                impact=data['impact'],
                effort=data['effort']
            )
        except Exception as e:
            logger.debug(f"Failed to create pattern match: {e}")
            return None
    
    def _count_tokens(self, text: str) -> int:
        """Count tokens in text using tiktoken."""
        try:
            import tiktoken
            encoding = tiktoken.get_encoding("cl100k_base")
            return len(encoding.encode(text))
        except Exception:
            # Fallback estimation
            return len(text) // 3
    
    def save_analysis_results(self, 
                            results: PatternAnalysisResults, 
                            output_path: Path,
                            format: str = "json") -> None:
        """Save analysis results to file.
        
        Args:
            results: Analysis results to save
            output_path: Output file path
            format: Output format (json, csv, markdown)
        """
        if format == "json":
            self._save_results_json(results, output_path)
        elif format == "csv":
            self._save_results_csv(results, output_path)
        elif format == "markdown":
            self._save_results_markdown(results, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _save_results_json(self, results: PatternAnalysisResults, output_path: Path) -> None:
        """Save results as JSON."""
        with open(output_path, 'w') as f:
            json.dump(results.to_dict(), f, indent=2)
        logger.info(f"Saved analysis results to {output_path}")
    
    def _save_results_csv(self, results: PatternAnalysisResults, output_path: Path) -> None:
        """Save results as CSV."""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "pattern_type", "confidence", "file_path", "line_start", "line_end",
                "description", "severity", "impact", "effort", "category"
            ])
            
            for pattern in results.get_all_patterns():
                category = "design_pattern" if isinstance(pattern, DesignPattern) else \
                          "anti_pattern" if isinstance(pattern, AntiPattern) else \
                          "quality_issue"
                
                writer.writerow([
                    pattern.pattern_type.value,
                    pattern.confidence,
                    str(pattern.file_path),
                    pattern.line_start,
                    pattern.line_end,
                    pattern.description,
                    pattern.severity,
                    pattern.impact,
                    pattern.effort,
                    category
                ])
        
        logger.info(f"Saved analysis results to {output_path}")
    
    def _save_results_markdown(self, results: PatternAnalysisResults, output_path: Path) -> None:
        """Save results as Markdown."""
        content = ["# Pattern Analysis Results\n"]
        
        # Summary
        summary = results.to_dict()["summary"]
        content.append("## Summary\n")
        content.append(f"- **Total Patterns Found**: {summary['total_patterns']}")
        content.append(f"- **Design Patterns**: {summary['design_patterns_count']}")
        content.append(f"- **Anti-patterns**: {summary['anti_patterns_count']}")
        content.append(f"- **Quality Issues**: {summary['code_quality_issues_count']}")
        content.append(f"- **Files Analyzed**: {results.total_files_analyzed}")
        content.append(f"- **Lines Analyzed**: {results.total_lines_analyzed}")
        content.append(f"- **Analysis Duration**: {results.analysis_duration:.2f}s\n")
        
        # Issues by severity
        content.append("### Issues by Severity\n")
        content.append(f"- **Critical**: {summary['critical_issues']}")
        content.append(f"- **High**: {summary['high_issues']}")
        content.append(f"- **Medium**: {summary['medium_issues']}")
        content.append(f"- **Low**: {summary['low_issues']}\n")
        
        # Detailed patterns
        if results.design_patterns:
            content.append("## Design Patterns\n")
            for pattern in results.design_patterns:
                content.append(f"### {pattern.pattern_type.value.title()}\n")
                content.append(f"- **File**: `{pattern.file_path}`")
                content.append(f"- **Lines**: {pattern.line_start}-{pattern.line_end}")
                content.append(f"- **Confidence**: {pattern.confidence:.2f}")
                content.append(f"- **Description**: {pattern.description}")
                content.append(f"- **Benefits**: {', '.join(pattern.benefits)}\n")
        
        if results.anti_patterns:
            content.append("## Anti-patterns\n")
            for pattern in results.anti_patterns:
                content.append(f"### {pattern.pattern_type.value.title()} ({pattern.severity.upper()})\n")
                content.append(f"- **File**: `{pattern.file_path}`")
                content.append(f"- **Lines**: {pattern.line_start}-{pattern.line_end}")
                content.append(f"- **Confidence**: {pattern.confidence:.2f}")
                content.append(f"- **Description**: {pattern.description}")
                content.append(f"- **Problems**: {', '.join(pattern.problems)}")
                content.append(f"- **Solutions**: {', '.join(pattern.solutions)}\n")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(content))
        
        logger.info(f"Saved analysis results to {output_path}")
