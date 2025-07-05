"""Exception classes for WTF CodeBot."""

from typing import Any, Dict, Optional


class WTFCodeBotError(Exception):
    """Base exception class for WTF CodeBot."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize exception.
        
        Args:
            message: Error message
            details: Optional additional details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        """String representation of exception."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ConfigurationError(WTFCodeBotError):
    """Exception raised for configuration-related errors."""
    pass


class AnalysisError(WTFCodeBotError):
    """Exception raised during code analysis."""
    pass


class APIError(WTFCodeBotError):
    """Exception raised for API-related errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response: Optional[str] = None):
        """Initialize API exception.
        
        Args:
            message: Error message
            status_code: HTTP status code
            response: API response content
        """
        details = {}
        if status_code is not None:
            details["status_code"] = status_code
        if response is not None:
            details["response"] = response
        
        super().__init__(message, details)
        self.status_code = status_code
        self.response = response


class FileProcessingError(WTFCodeBotError):
    """Exception raised during file processing."""
    
    def __init__(self, message: str, file_path: Optional[str] = None, line_number: Optional[int] = None):
        """Initialize file processing exception.
        
        Args:
            message: Error message
            file_path: Path to the file that caused the error
            line_number: Line number where error occurred
        """
        details = {}
        if file_path is not None:
            details["file_path"] = file_path
        if line_number is not None:
            details["line_number"] = line_number
        
        super().__init__(message, details)
        self.file_path = file_path
        self.line_number = line_number


class ValidationError(WTFCodeBotError):
    """Exception raised for validation errors."""
    pass


class ReportGenerationError(WTFCodeBotError):
    """Exception raised during report generation."""
    pass


class AuthenticationError(APIError):
    """Exception raised for authentication errors."""
    pass


class RateLimitError(APIError):
    """Exception raised when API rate limits are exceeded."""
    pass


class NetworkError(WTFCodeBotError):
    """Exception raised for network-related errors."""
    pass


class TimeoutError(WTFCodeBotError):
    """Exception raised for timeout errors."""
    pass
