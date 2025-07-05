"""
Pattern recognition orchestrator that coordinates batching, analysis, and reporting.
"""

import asyncio
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from .batcher import CodeBatcher, BatchConfig
from .claude_client import ClaudePatternAnalyzer, RetryConfig
from .cost_tracker import CostTracker, CostBudget
from .patterns import PatternAnalysisResults
from ..discovery.models import CodebaseGraph, FileNode
try:
    from ..core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class PatternRecognitionConfig:
    """Configuration for pattern recognition analysis."""
    
    # Batching configuration
    max_tokens_per_batch: int = 100000
    batch_overlap_tokens: int = 2000
    min_batch_size: int = 1000
    prioritize_files: List[str] = None
    exclude_patterns: List[str] = None
    
    # Analysis configuration
    concurrent_requests: int = 3
    enable_streaming: bool = False
    retry_max_attempts: int = 3
    retry_base_delay: float = 1.0
    
    # Cost tracking
    enable_cost_tracking: bool = True
    daily_budget_limit: float = 0.0
    monthly_budget_limit: float = 0.0
    total_budget_limit: float = 0.0
    
    # Output configuration
    save_batches: bool = False
    output_formats: List[str] = None  # json, csv, markdown
    output_directory: Optional[Path] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.prioritize_files is None:
            self.prioritize_files = []
        if self.exclude_patterns is None:
            self.exclude_patterns = [
                "**/test/**", "**/tests/**", "**/*test*", "**/*.test.*",
                "**/node_modules/**", "**/.git/**", "**/venv/**", "**/__pycache__/**"
            ]
        if self.output_formats is None:
            self.output_formats = ["json", "markdown"]
        if self.output_directory is None:
            self.output_directory = Path("pattern_analysis_results")


class PatternRecognitionOrchestrator:
    """Orchestrates the complete pattern recognition pipeline."""
    
    def __init__(self, config: PatternRecognitionConfig = None):
        """Initialize the orchestrator.
        
        Args:
            config: Pattern recognition configuration
        """
        self.config = config or PatternRecognitionConfig()
        self.cost_tracker = None
        self.batcher = None
        self.analyzer = None
        
        # Initialize components
        self._initialize_components()
        
        logger.info("Pattern recognition orchestrator initialized")
    
    def _initialize_components(self):
        """Initialize all components with configuration."""
        
        # Initialize cost tracker if enabled
        if self.config.enable_cost_tracking:
            budget = CostBudget(
                daily_limit=self.config.daily_budget_limit,
                monthly_limit=self.config.monthly_budget_limit,
                total_limit=self.config.total_budget_limit
            )
            
            cost_storage_path = self.config.output_directory / "cost_tracking.json"
            self.cost_tracker = CostTracker(
                storage_path=cost_storage_path,
                budget=budget,
                auto_save=True
            )
        
        # Initialize code batcher
        batch_config = BatchConfig(
            max_tokens_per_batch=self.config.max_tokens_per_batch,
            overlap_tokens=self.config.batch_overlap_tokens,
            min_batch_size=self.config.min_batch_size,
            prioritize_files=self.config.prioritize_files,
            exclude_patterns=self.config.exclude_patterns,
            include_metadata=True,
            include_dependencies=True,
            chunk_large_files=True
        )
        self.batcher = CodeBatcher(batch_config)
        
        # Initialize Claude analyzer
        retry_config = RetryConfig(
            max_retries=self.config.retry_max_attempts,
            base_delay=self.config.retry_base_delay,
            max_delay=60.0,
            exponential_base=2.0,
            jitter=True
        )
        
        self.analyzer = ClaudePatternAnalyzer(
            cost_tracker=self.cost_tracker,
            retry_config=retry_config,
            enable_streaming=self.config.enable_streaming
        )
    
    async def analyze_codebase(self, codebase: CodebaseGraph) -> PatternAnalysisResults:
        """Analyze an entire codebase for patterns.
        
        Args:
            codebase: Codebase graph to analyze
            
        Returns:
            Pattern analysis results
        """
        logger.info(f"Starting codebase pattern analysis for {codebase.total_files} files")
        
        # Ensure output directory exists
        self.config.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Create code batches
        logger.info("Creating code batches...")
        batches = self.batcher.create_batches_from_codebase(codebase)
        
        if not batches:
            logger.warning("No code batches created - no analyzable content found")
            return PatternAnalysisResults(
                design_patterns=[],
                anti_patterns=[],
                code_quality_issues=[],
                total_files_analyzed=0,
                total_lines_analyzed=0,
                analysis_duration=0.0
            )
        
        # Save batches if requested
        if self.config.save_batches:
            batch_file = self.config.output_directory / "code_batches.json"
            self.batcher.save_batches(batches, batch_file)
        
        # Log batch statistics
        total_tokens = sum(batch.total_tokens for batch in batches)
        logger.info(f"Created {len(batches)} batches with {total_tokens:,} total tokens")
        
        if self.cost_tracker:
            estimated_cost = self._estimate_analysis_cost(batches)
            logger.info(f"Estimated analysis cost: ${estimated_cost:.2f}")
            
            # Check budget before proceeding
            if not self.cost_tracker.check_budget_limits():
                raise RuntimeError("Budget limits would be exceeded - analysis aborted")
        
        # Analyze batches
        logger.info("Starting pattern analysis...")
        results = await self.analyzer.analyze_batches(
            batches, 
            concurrent_requests=self.config.concurrent_requests
        )
        
        # Save results in requested formats
        await self._save_analysis_results(results)
        
        # Log final statistics
        self._log_analysis_summary(results)
        
        return results
    
    async def analyze_files(self, file_nodes: List[FileNode]) -> PatternAnalysisResults:
        """Analyze a specific set of files for patterns.
        
        Args:
            file_nodes: List of file nodes to analyze
            
        Returns:
            Pattern analysis results
        """
        logger.info(f"Starting file pattern analysis for {len(file_nodes)} files")
        
        # Ensure output directory exists
        self.config.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Create code batches
        logger.info("Creating code batches...")
        batches = self.batcher.create_batches_from_files(file_nodes)
        
        if not batches:
            logger.warning("No code batches created - no analyzable content found")
            return PatternAnalysisResults(
                design_patterns=[],
                anti_patterns=[],
                code_quality_issues=[],
                total_files_analyzed=0,
                total_lines_analyzed=0,
                analysis_duration=0.0
            )
        
        # Save batches if requested
        if self.config.save_batches:
            batch_file = self.config.output_directory / "code_batches.json"
            self.batcher.save_batches(batches, batch_file)
        
        # Log batch statistics
        total_tokens = sum(batch.total_tokens for batch in batches)
        logger.info(f"Created {len(batches)} batches with {total_tokens:,} total tokens")
        
        if self.cost_tracker:
            estimated_cost = self._estimate_analysis_cost(batches)
            logger.info(f"Estimated analysis cost: ${estimated_cost:.2f}")
            
            # Check budget before proceeding
            if not self.cost_tracker.check_budget_limits():
                raise RuntimeError("Budget limits would be exceeded - analysis aborted")
        
        # Analyze batches
        logger.info("Starting pattern analysis...")
        results = await self.analyzer.analyze_batches(
            batches, 
            concurrent_requests=self.config.concurrent_requests
        )
        
        # Save results in requested formats
        await self._save_analysis_results(results)
        
        # Log final statistics
        self._log_analysis_summary(results)
        
        return results
    
    def _estimate_analysis_cost(self, batches) -> float:
        """Estimate the cost of analyzing batches."""
        if not self.cost_tracker:
            return 0.0
        
        total_input_tokens = sum(batch.total_tokens for batch in batches)
        # Estimate output tokens as 20% of input tokens (rough estimate)
        estimated_output_tokens = int(total_input_tokens * 0.2)
        
        # Get model from config
        from ..core.config import get_config
        config = get_config()
        
        return self.cost_tracker.calculate_cost(
            model=config.anthropic_model,
            input_tokens=total_input_tokens,
            output_tokens=estimated_output_tokens
        )
    
    async def _save_analysis_results(self, results: PatternAnalysisResults):
        """Save analysis results in all requested formats."""
        timestamp = asyncio.get_event_loop().time()
        
        for format_type in self.config.output_formats:
            if format_type == "json":
                output_path = self.config.output_directory / "pattern_analysis.json"
            elif format_type == "csv":
                output_path = self.config.output_directory / "pattern_analysis.csv"
            elif format_type == "markdown":
                output_path = self.config.output_directory / "pattern_analysis.md"
            else:
                logger.warning(f"Unknown output format: {format_type}")
                continue
            
            try:
                self.analyzer.save_analysis_results(results, output_path, format_type)
            except Exception as e:
                logger.error(f"Failed to save results in {format_type} format: {e}")
        
        # Save cost tracking data if enabled
        if self.cost_tracker:
            self.cost_tracker.save_data()
            
            # Export usage summary
            usage_summary = self.cost_tracker.get_usage_summary(days=30)
            budget_status = self.cost_tracker.get_budget_status()
            
            summary_path = self.config.output_directory / "cost_summary.json"
            import json
            with open(summary_path, 'w') as f:
                json.dump({
                    "usage_summary": usage_summary,
                    "budget_status": budget_status
                }, f, indent=2)
            
            logger.info(f"Saved cost summary to {summary_path}")
    
    def _log_analysis_summary(self, results: PatternAnalysisResults):
        """Log a summary of the analysis results."""
        summary = results.to_dict()["summary"]
        
        logger.info("=== PATTERN ANALYSIS COMPLETE ===")
        logger.info(f"Total patterns found: {summary['total_patterns']}")
        logger.info(f"  - Design patterns: {summary['design_patterns_count']}")
        logger.info(f"  - Anti-patterns: {summary['anti_patterns_count']}")
        logger.info(f"  - Quality issues: {summary['code_quality_issues_count']}")
        logger.info(f"Files analyzed: {results.total_files_analyzed}")
        logger.info(f"Lines analyzed: {results.total_lines_analyzed:,}")
        logger.info(f"Analysis duration: {results.analysis_duration:.2f}s")
        
        # Log severity breakdown
        logger.info("Issues by severity:")
        logger.info(f"  - Critical: {summary['critical_issues']}")
        logger.info(f"  - High: {summary['high_issues']}")
        logger.info(f"  - Medium: {summary['medium_issues']}")
        logger.info(f"  - Low: {summary['low_issues']}")
        
        if self.cost_tracker:
            usage_summary = self.cost_tracker.get_usage_summary(days=1)  # Today's usage
            logger.info(f"Analysis cost: ${usage_summary['total_cost']:.2f}")
            logger.info(f"Tokens processed: {usage_summary['total_tokens']:,}")
        
        logger.info("Results saved to:", str(self.config.output_directory))
    
    def get_cost_summary(self) -> Optional[Dict[str, Any]]:
        """Get cost tracking summary.
        
        Returns:
            Cost summary or None if cost tracking is disabled
        """
        if not self.cost_tracker:
            return None
        
        return {
            "usage_summary": self.cost_tracker.get_usage_summary(),
            "budget_status": self.cost_tracker.get_budget_status()
        }
    
    def export_cost_data(self, export_path: Path, format: str = "json"):
        """Export cost tracking data.
        
        Args:
            export_path: Path to export file
            format: Export format (json, csv)
        """
        if self.cost_tracker:
            self.cost_tracker.export_usage_data(export_path, format)
        else:
            logger.warning("Cost tracking is not enabled")


# Convenience function for simple pattern analysis
async def analyze_codebase_patterns(
    codebase: CodebaseGraph,
    output_dir: Path = None,
    max_tokens_per_batch: int = 100000,
    concurrent_requests: int = 3,
    enable_cost_tracking: bool = True,
    budget_limit: float = 0.0
) -> PatternAnalysisResults:
    """Convenient function to analyze codebase patterns with default settings.
    
    Args:
        codebase: Codebase graph to analyze
        output_dir: Output directory for results
        max_tokens_per_batch: Maximum tokens per batch
        concurrent_requests: Number of concurrent API requests
        enable_cost_tracking: Enable cost tracking
        budget_limit: Daily budget limit (0 = no limit)
        
    Returns:
        Pattern analysis results
    """
    config = PatternRecognitionConfig(
        max_tokens_per_batch=max_tokens_per_batch,
        concurrent_requests=concurrent_requests,
        enable_cost_tracking=enable_cost_tracking,
        daily_budget_limit=budget_limit,
        output_directory=output_dir or Path("pattern_analysis_results")
    )
    
    orchestrator = PatternRecognitionOrchestrator(config)
    return await orchestrator.analyze_codebase(codebase)
