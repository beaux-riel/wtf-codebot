"""
Performance profiler for memory and CPU profiling.
"""

import time
import psutil
import tracemalloc
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from functools import wraps
import threading
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProfileResult:
    """Results from performance profiling."""
    duration: float
    peak_memory_mb: float
    cpu_percent: float
    memory_timeline: List[float] = field(default_factory=list)
    cpu_timeline: List[float] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    memory_traces: Optional[List[Any]] = None
    function_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate additional metrics."""
        if self.memory_timeline:
            self.avg_memory_mb = sum(self.memory_timeline) / len(self.memory_timeline)
            self.min_memory_mb = min(self.memory_timeline)
            self.max_memory_mb = max(self.memory_timeline)
        else:
            self.avg_memory_mb = self.peak_memory_mb
            self.min_memory_mb = self.peak_memory_mb
            self.max_memory_mb = self.peak_memory_mb

        if self.cpu_timeline:
            self.avg_cpu_percent = sum(self.cpu_timeline) / len(self.cpu_timeline)
            self.min_cpu_percent = min(self.cpu_timeline)
            self.max_cpu_percent = max(self.cpu_timeline)
        else:
            self.avg_cpu_percent = self.cpu_percent
            self.min_cpu_percent = self.cpu_percent
            self.max_cpu_percent = self.cpu_percent

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            'function_name': self.function_name,
            'duration': self.duration,
            'peak_memory_mb': self.peak_memory_mb,
            'avg_memory_mb': self.avg_memory_mb,
            'min_memory_mb': self.min_memory_mb,
            'max_memory_mb': self.max_memory_mb,
            'cpu_percent': self.cpu_percent,
            'avg_cpu_percent': self.avg_cpu_percent,
            'min_cpu_percent': self.min_cpu_percent,
            'max_cpu_percent': self.max_cpu_percent,
            'sample_count': len(self.memory_timeline),
            'metadata': self.metadata,
        }


class PerformanceProfiler:
    """Performance profiler for memory and CPU monitoring."""

    def __init__(self, sample_interval: float = 0.1, trace_memory: bool = True):
        """
        Initialize the profiler.

        Args:
            sample_interval: Interval between samples in seconds
            trace_memory: Whether to trace memory allocations
        """
        self.sample_interval = sample_interval
        self.trace_memory = trace_memory
        self.process = psutil.Process()
        self._monitoring = False
        self._monitor_thread = None
        self._memory_timeline = []
        self._cpu_timeline = []
        self._timestamps = []
        self._peak_memory = 0
        self._start_time = 0

    def start_monitoring(self) -> None:
        """Start performance monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._memory_timeline = []
        self._cpu_timeline = []
        self._timestamps = []
        self._peak_memory = 0
        self._start_time = time.time()

        if self.trace_memory:
            tracemalloc.start()

        self._monitor_thread = threading.Thread(target=self._monitor_loop)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()

    def stop_monitoring(self) -> ProfileResult:
        """Stop monitoring and return results."""
        if not self._monitoring:
            return ProfileResult(duration=0, peak_memory_mb=0, cpu_percent=0)

        self._monitoring = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)

        duration = time.time() - self._start_time
        peak_memory_mb = self._peak_memory / (1024 * 1024)
        
        # Get final CPU reading
        try:
            cpu_percent = self.process.cpu_percent()
        except psutil.NoSuchProcess:
            cpu_percent = 0

        # Get memory traces if enabled
        memory_traces = None
        if self.trace_memory:
            try:
                snapshot = tracemalloc.take_snapshot()
                memory_traces = snapshot.statistics('lineno')[:10]  # Top 10
                tracemalloc.stop()
            except Exception as e:
                logger.warning(f"Failed to get memory traces: {e}")

        return ProfileResult(
            duration=duration,
            peak_memory_mb=peak_memory_mb,
            cpu_percent=cpu_percent,
            memory_timeline=self._memory_timeline.copy(),
            cpu_timeline=self._cpu_timeline.copy(),
            timestamps=self._timestamps.copy(),
            memory_traces=memory_traces,
        )

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                # Get current memory usage
                memory_info = self.process.memory_info()
                current_memory = memory_info.rss
                self._peak_memory = max(self._peak_memory, current_memory)

                # Get CPU usage
                cpu_percent = self.process.cpu_percent()

                # Record timeline data
                current_time = time.time()
                self._memory_timeline.append(current_memory / (1024 * 1024))
                self._cpu_timeline.append(cpu_percent)
                self._timestamps.append(current_time - self._start_time)

                time.sleep(self.sample_interval)

            except psutil.NoSuchProcess:
                break
            except Exception as e:
                logger.warning(f"Error in monitoring loop: {e}")
                break

    def profile_function(self, func: Callable) -> Callable:
        """Decorator to profile a function."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            self.start_monitoring()
            try:
                result = func(*args, **kwargs)
                profile_result = self.stop_monitoring()
                profile_result.function_name = func.__name__
                
                # Store profile result for later access
                if not hasattr(wrapper, '_profile_results'):
                    wrapper._profile_results = []
                wrapper._profile_results.append(profile_result)
                
                return result
            except Exception as e:
                self.stop_monitoring()
                raise e
        
        return wrapper

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for context."""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                'memory_available_gb': psutil.virtual_memory().available / (1024**3),
                'disk_usage_percent': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            }
        except Exception as e:
            logger.warning(f"Failed to get system info: {e}")
            return {}


def profile_performance(sample_interval: float = 0.1, trace_memory: bool = True):
    """Decorator for profiling function performance."""
    def decorator(func: Callable) -> Callable:
        profiler = PerformanceProfiler(sample_interval, trace_memory)
        return profiler.profile_function(func)
    return decorator


class ProfileManager:
    """Manager for collecting and analyzing multiple profile results."""

    def __init__(self):
        self.profiles: Dict[str, List[ProfileResult]] = {}

    def add_profile(self, name: str, profile_result: ProfileResult) -> None:
        """Add a profile result."""
        if name not in self.profiles:
            self.profiles[name] = []
        self.profiles[name].append(profile_result)

    def get_summary(self) -> Dict[str, Dict[str, Any]]:
        """Get summary statistics for all profiles."""
        summary = {}
        
        for name, profiles in self.profiles.items():
            if not profiles:
                continue
            
            durations = [p.duration for p in profiles]
            peak_memories = [p.peak_memory_mb for p in profiles]
            cpu_percents = [p.cpu_percent for p in profiles]
            
            summary[name] = {
                'count': len(profiles),
                'duration': {
                    'min': min(durations),
                    'max': max(durations),
                    'avg': sum(durations) / len(durations),
                    'total': sum(durations),
                },
                'peak_memory_mb': {
                    'min': min(peak_memories),
                    'max': max(peak_memories),
                    'avg': sum(peak_memories) / len(peak_memories),
                },
                'cpu_percent': {
                    'min': min(cpu_percents),
                    'max': max(cpu_percents),
                    'avg': sum(cpu_percents) / len(cpu_percents),
                },
            }
        
        return summary

    def clear(self) -> None:
        """Clear all profiles."""
        self.profiles.clear()

    def export_profiles(self, output_file: str) -> None:
        """Export profiles to JSON file."""
        import json
        
        export_data = {
            'profiles': {
                name: [p.to_dict() for p in profiles]
                for name, profiles in self.profiles.items()
            },
            'summary': self.get_summary(),
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
