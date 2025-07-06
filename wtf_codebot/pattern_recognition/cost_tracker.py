"""
Cost tracking for API usage monitoring and budget management.
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import threading
from contextlib import contextmanager

try:
    from ..core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class Usage:
    """Represents API usage for a single request."""
    timestamp: datetime
    model: str
    input_tokens: int
    output_tokens: int
    cost: float
    request_type: str  # "pattern_analysis", "batch_analysis", etc.
    duration: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class CostBudget:
    """Budget configuration for cost limits."""
    daily_limit: float = 0.0
    monthly_limit: float = 0.0
    total_limit: float = 0.0
    alert_threshold: float = 0.8  # Alert when 80% of budget is used
    
    def is_valid(self) -> bool:
        """Check if budget has any limits set."""
        return self.daily_limit > 0 or self.monthly_limit > 0 or self.total_limit > 0


class CostTracker:
    """Tracks API usage and costs with budget management."""
    
    # Claude pricing per 1M tokens (as of 2024)
    CLAUDE_PRICING = {
        "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
        "claude-3-sonnet-20240229": {"input": 3.0, "output": 15.0},
        "claude-sonnet-4-0": {"input": 3.0, "output": 15.0},
        "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
        "claude-3-5-sonnet-20240620": {"input": 3.0, "output": 15.0},
        "claude-3-5-haiku-20241022": {"input": 0.25, "output": 1.25},
        "claude-sonnet-4-0": {"input": 0.25, "output": 1.25}
    }
    
    def __init__(self, 
                 storage_path: Optional[Path] = None,
                 budget: Optional[CostBudget] = None,
                 auto_save: bool = True):
        """Initialize cost tracker.
        
        Args:
            storage_path: Path to store usage data
            budget: Budget configuration
            auto_save: Whether to auto-save usage data
        """
        self.storage_path = storage_path or Path("usage_data.json")
        self.budget = budget or CostBudget()
        self.auto_save = auto_save
        self.usage_history: List[Usage] = []
        self._lock = threading.Lock()
        
        # Load existing data
        self._load_data()
        
        logger.info(f"Cost tracker initialized with storage at {self.storage_path}")
        if self.budget.is_valid():
            logger.info(f"Budget limits: daily=${self.budget.daily_limit}, "
                       f"monthly=${self.budget.monthly_limit}, total=${self.budget.total_limit}")
    
    def calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for token usage.
        
        Args:
            model: Claude model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        if model not in self.CLAUDE_PRICING:
            logger.warning(f"Unknown model {model}, using default Sonnet pricing")
            model = "claude-sonnet-4-0"
        
        pricing = self.CLAUDE_PRICING[model]
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        
        return input_cost + output_cost
    
    def record_usage(self, 
                    model: str,
                    input_tokens: int,
                    output_tokens: int,
                    request_type: str,
                    duration: float,
                    success: bool = True,
                    error_message: Optional[str] = None) -> Usage:
        """Record API usage.
        
        Args:
            model: Claude model used
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            request_type: Type of request
            duration: Request duration in seconds
            success: Whether request was successful
            error_message: Error message if request failed
            
        Returns:
            Usage record
        """
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        
        usage = Usage(
            timestamp=datetime.now(),
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            request_type=request_type,
            duration=duration,
            success=success,
            error_message=error_message
        )
        
        with self._lock:
            self.usage_history.append(usage)
            
            if self.auto_save:
                self._save_data()
        
        logger.info(f"Recorded usage: {request_type} - ${cost:.4f} "
                   f"({input_tokens} input, {output_tokens} output tokens)")
        
        # Check budget limits
        self._check_budget_limits()
        
        return usage
    
    @contextmanager
    def track_request(self, 
                     model: str,
                     request_type: str,
                     input_tokens: int):
        """Context manager for tracking API requests.
        
        Args:
            model: Claude model being used
            request_type: Type of request
            input_tokens: Number of input tokens
            
        Yields:
            Function to record output tokens and completion
        """
        start_time = time.time()
        success = False
        error_message = None
        output_tokens = 0
        
        def record_completion(tokens: int):
            nonlocal output_tokens
            output_tokens = tokens
        
        try:
            yield record_completion
            success = True
        except Exception as e:
            error_message = str(e)
            raise
        finally:
            duration = time.time() - start_time
            self.record_usage(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                request_type=request_type,
                duration=duration,
                success=success,
                error_message=error_message
            )
    
    def get_usage_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get usage summary for the last N days.
        
        Args:
            days: Number of days to include in summary
            
        Returns:
            Usage summary
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_usage = [u for u in self.usage_history if u.timestamp >= cutoff_date]
        
        if not recent_usage:
            return {
                "total_requests": 0,
                "total_cost": 0.0,
                "total_tokens": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "average_cost_per_request": 0.0,
                "cost_by_model": {},
                "usage_by_type": {}
            }
        
        total_cost = sum(u.cost for u in recent_usage)
        total_tokens = sum(u.input_tokens + u.output_tokens for u in recent_usage)
        successful_requests = sum(1 for u in recent_usage if u.success)
        failed_requests = len(recent_usage) - successful_requests
        
        # Cost by model
        cost_by_model = {}
        for usage in recent_usage:
            if usage.model not in cost_by_model:
                cost_by_model[usage.model] = 0.0
            cost_by_model[usage.model] += usage.cost
        
        # Usage by type
        usage_by_type = {}
        for usage in recent_usage:
            if usage.request_type not in usage_by_type:
                usage_by_type[usage.request_type] = {
                    "count": 0,
                    "cost": 0.0,
                    "tokens": 0
                }
            usage_by_type[usage.request_type]["count"] += 1
            usage_by_type[usage.request_type]["cost"] += usage.cost
            usage_by_type[usage.request_type]["tokens"] += usage.input_tokens + usage.output_tokens
        
        return {
            "period_days": days,
            "total_requests": len(recent_usage),
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "average_cost_per_request": total_cost / len(recent_usage),
            "cost_by_model": cost_by_model,
            "usage_by_type": usage_by_type
        }
    
    def get_budget_status(self) -> Dict[str, Any]:
        """Get current budget status.
        
        Returns:
            Budget status information
        """
        if not self.budget.is_valid():
            return {"budget_enabled": False}
        
        now = datetime.now()
        
        # Daily usage
        daily_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        daily_usage = sum(u.cost for u in self.usage_history if u.timestamp >= daily_start)
        
        # Monthly usage
        monthly_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_usage = sum(u.cost for u in self.usage_history if u.timestamp >= monthly_start)
        
        # Total usage
        total_usage = sum(u.cost for u in self.usage_history)
        
        return {
            "budget_enabled": True,
            "daily": {
                "limit": self.budget.daily_limit,
                "used": daily_usage,
                "remaining": max(0, self.budget.daily_limit - daily_usage),
                "percentage": (daily_usage / self.budget.daily_limit * 100) if self.budget.daily_limit > 0 else 0
            },
            "monthly": {
                "limit": self.budget.monthly_limit,
                "used": monthly_usage,
                "remaining": max(0, self.budget.monthly_limit - monthly_usage),
                "percentage": (monthly_usage / self.budget.monthly_limit * 100) if self.budget.monthly_limit > 0 else 0
            },
            "total": {
                "limit": self.budget.total_limit,
                "used": total_usage,
                "remaining": max(0, self.budget.total_limit - total_usage),
                "percentage": (total_usage / self.budget.total_limit * 100) if self.budget.total_limit > 0 else 0
            }
        }
    
    def _check_budget_limits(self) -> None:
        """Check if budget limits are exceeded."""
        if not self.budget.is_valid():
            return
        
        budget_status = self.get_budget_status()
        
        # Check for alerts
        for period in ["daily", "monthly", "total"]:
            if period in budget_status:
                percentage = budget_status[period]["percentage"]
                if percentage >= self.budget.alert_threshold * 100:
                    logger.warning(f"Budget alert: {period} usage is {percentage:.1f}% "
                                 f"of limit (${budget_status[period]['used']:.2f})")
                
                if percentage >= 100:
                    logger.error(f"Budget exceeded: {period} limit of "
                               f"${budget_status[period]['limit']:.2f} exceeded")
    
    def check_budget_limits(self) -> bool:
        """Check if any budget limits would be exceeded by the next request.
        
        Returns:
            True if request can proceed, False if budget would be exceeded
        """
        if not self.budget.is_valid():
            return True
        
        budget_status = self.get_budget_status()
        
        # Check if any limit is already exceeded
        for period in ["daily", "monthly", "total"]:
            if period in budget_status:
                if budget_status[period]["percentage"] >= 100:
                    logger.error(f"Budget limit exceeded: {period}")
                    return False
        
        return True
    
    def _load_data(self) -> None:
        """Load usage data from storage."""
        if not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            self.usage_history = []
            for usage_data in data.get('usage_history', []):
                usage = Usage(
                    timestamp=datetime.fromisoformat(usage_data['timestamp']),
                    model=usage_data['model'],
                    input_tokens=usage_data['input_tokens'],
                    output_tokens=usage_data['output_tokens'],
                    cost=usage_data['cost'],
                    request_type=usage_data['request_type'],
                    duration=usage_data['duration'],
                    success=usage_data['success'],
                    error_message=usage_data.get('error_message')
                )
                self.usage_history.append(usage)
                
            logger.info(f"Loaded {len(self.usage_history)} usage records")
            
        except Exception as e:
            logger.error(f"Failed to load usage data: {e}")
    
    def _save_data(self) -> None:
        """Save usage data to storage."""
        try:
            data = {
                'usage_history': [
                    {
                        'timestamp': usage.timestamp.isoformat(),
                        'model': usage.model,
                        'input_tokens': usage.input_tokens,
                        'output_tokens': usage.output_tokens,
                        'cost': usage.cost,
                        'request_type': usage.request_type,
                        'duration': usage.duration,
                        'success': usage.success,
                        'error_message': usage.error_message
                    }
                    for usage in self.usage_history
                ]
            }
            
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save usage data: {e}")
    
    def save_data(self) -> None:
        """Manually save usage data."""
        with self._lock:
            self._save_data()
    
    def export_usage_data(self, export_path: Path, format: str = "json") -> None:
        """Export usage data to file.
        
        Args:
            export_path: Path to export file
            format: Export format (json, csv)
        """
        if format == "json":
            self._export_json(export_path)
        elif format == "csv":
            self._export_csv(export_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, export_path: Path) -> None:
        """Export usage data as JSON."""
        summary = self.get_usage_summary(days=365)  # Full year
        budget_status = self.get_budget_status()
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "summary": summary,
            "budget_status": budget_status,
            "usage_history": [
                {
                    "timestamp": usage.timestamp.isoformat(),
                    "model": usage.model,
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cost": usage.cost,
                    "request_type": usage.request_type,
                    "duration": usage.duration,
                    "success": usage.success,
                    "error_message": usage.error_message
                }
                for usage in self.usage_history
            ]
        }
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported usage data to {export_path}")
    
    def _export_csv(self, export_path: Path) -> None:
        """Export usage data as CSV."""
        import csv
        
        with open(export_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "model", "input_tokens", "output_tokens", 
                "cost", "request_type", "duration", "success", "error_message"
            ])
            
            for usage in self.usage_history:
                writer.writerow([
                    usage.timestamp.isoformat(),
                    usage.model,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.cost,
                    usage.request_type,
                    usage.duration,
                    usage.success,
                    usage.error_message
                ])
        
        logger.info(f"Exported usage data to {export_path}")
