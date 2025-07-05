"""Configuration management for WTF CodeBot."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv


class AnalysisConfig(BaseModel):
    """Configuration for code analysis options."""
    
    max_file_size: int = Field(default=1024 * 1024, description="Maximum file size to analyze (bytes)")
    supported_extensions: List[str] = Field(
        default=[".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".rb"],
        description="Supported file extensions for analysis"
    )
    exclude_patterns: List[str] = Field(
        default=["**/node_modules/**", "**/.git/**", "**/__pycache__/**", "**/venv/**", "**/.env"],
        description="Patterns to exclude from analysis"
    )
    include_tests: bool = Field(default=True, description="Include test files in analysis")
    analysis_depth: str = Field(default="standard", description="Analysis depth: basic, standard, deep")


class LoggingConfig(BaseModel):
    """Configuration for logging."""
    
    level: str = Field(default="INFO", description="Logging level")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    file_path: Optional[str] = Field(default=None, description="Path to log file")
    
    @validator('level')
    def validate_level(cls, v: str) -> str:
        """Validate logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of: {valid_levels}")
        return v.upper()


class Config(BaseModel):
    """Main configuration class for WTF CodeBot."""
    
    # API Configuration
    anthropic_api_key: str = Field(..., description="Anthropic API key")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", description="Anthropic model to use")
    
    # Analysis Configuration
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    
    # Logging Configuration
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # Output Configuration
    output_format: str = Field(default="console", description="Output format: console, json, markdown")
    output_file: Optional[str] = Field(default=None, description="Output file path")
    
    # General Configuration
    verbose: bool = Field(default=False, description="Enable verbose output")
    dry_run: bool = Field(default=False, description="Perform dry run without making changes")
    
    @validator('anthropic_api_key')
    def validate_api_key(cls, v: str) -> str:
        """Validate API key is not empty."""
        if not v or v.strip() == "":
            raise ValueError("Anthropic API key cannot be empty")
        return v.strip()
    
    @validator('output_format')
    def validate_output_format(cls, v: str) -> str:
        """Validate output format."""
        valid_formats = ["console", "json", "markdown"]
        if v.lower() not in valid_formats:
            raise ValueError(f"Invalid output format. Must be one of: {valid_formats}")
        return v.lower()


class ConfigManager:
    """Manages configuration loading from various sources."""
    
    DEFAULT_CONFIG_FILES = [
        "wtf-codebot.yaml",
        "wtf-codebot.yml",
        ".wtf-codebot.yaml",
        ".wtf-codebot.yml",
        "config/wtf-codebot.yaml",
        "config/wtf-codebot.yml"
    ]
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self._config: Optional[Config] = None
    
    def load_config(self) -> Config:
        """Load configuration from file and environment variables.
        
        Returns:
            Loaded configuration
            
        Raises:
            ValueError: If configuration is invalid
            FileNotFoundError: If specified config file doesn't exist
        """
        if self._config is not None:
            return self._config
        
        # Load .env file if it exists
        env_path = Path(".env")
        if env_path.exists():
            load_dotenv(env_path)
        
        # Load configuration from file
        config_data = self._load_config_file()
        
        # Override with environment variables
        config_data = self._override_with_env(config_data)
        
        # Validate and create configuration
        self._config = Config(**config_data)
        return self._config
    
    def _load_config_file(self) -> Dict[str, Any]:
        """Load configuration from file.
        
        Returns:
            Configuration data as dictionary
        """
        config_data = {}
        
        if self.config_file:
            # Use specified config file
            config_path = Path(self.config_file)
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
            config_data = self._read_yaml_file(config_path)
        else:
            # Try default config files
            for config_file in self.DEFAULT_CONFIG_FILES:
                config_path = Path(config_file)
                if config_path.exists():
                    config_data = self._read_yaml_file(config_path)
                    break
        
        return config_data
    
    def _read_yaml_file(self, path: Path) -> Dict[str, Any]:
        """Read YAML configuration file.
        
        Args:
            path: Path to YAML file
            
        Returns:
            Configuration data as dictionary
        """
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in configuration file {path}: {e}")
    
    def _override_with_env(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Override configuration with environment variables.
        
        Args:
            config_data: Base configuration data
            
        Returns:
            Configuration data with environment overrides
        """
        # Define environment variable mappings
        env_mappings = {
            "ANTHROPIC_API_KEY": "anthropic_api_key",
            "ANTHROPIC_MODEL": "anthropic_model",
            "WTF_CODEBOT_OUTPUT_FORMAT": "output_format",
            "WTF_CODEBOT_OUTPUT_FILE": "output_file",
            "WTF_CODEBOT_VERBOSE": "verbose",
            "WTF_CODEBOT_DRY_RUN": "dry_run",
            "WTF_CODEBOT_LOG_LEVEL": "logging.level",
            "WTF_CODEBOT_LOG_FILE": "logging.file_path",
            "WTF_CODEBOT_MAX_FILE_SIZE": "analysis.max_file_size",
            "WTF_CODEBOT_INCLUDE_TESTS": "analysis.include_tests",
            "WTF_CODEBOT_ANALYSIS_DEPTH": "analysis.analysis_depth",
        }
        
        for env_var, config_key in env_mappings.items():
            env_value = os.environ.get(env_var)
            if env_value is not None:
                self._set_nested_value(config_data, config_key, self._parse_env_value(env_value))
        
        return config_data
    
    def _set_nested_value(self, data: Dict[str, Any], key: str, value: Any) -> None:
        """Set nested dictionary value using dot notation.
        
        Args:
            data: Dictionary to modify
            key: Dot-separated key path
            value: Value to set
        """
        keys = key.split(".")
        current = data
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def _parse_env_value(self, value: str) -> Union[str, int, bool]:
        """Parse environment variable value to appropriate type.
        
        Args:
            value: Environment variable value
            
        Returns:
            Parsed value
        """
        # Handle boolean values
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        elif value.lower() in ("false", "0", "no", "off"):
            return False
        
        # Handle integer values
        try:
            return int(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def save_config(self, config: Config, path: Optional[str] = None) -> None:
        """Save configuration to file.
        
        Args:
            config: Configuration to save
            path: Optional path to save configuration
        """
        if path is None:
            path = self.config_file or "wtf-codebot.yaml"
        
        config_dict = config.dict()
        
        # Convert Path objects to strings for serialization
        if config_dict.get("logging", {}).get("file_path"):
            config_dict["logging"]["file_path"] = str(config_dict["logging"]["file_path"])
        
        with open(path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)


# Global configuration instance
_config_manager = ConfigManager()


def get_config(config_file: Optional[str] = None) -> Config:
    """Get the current configuration.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        Current configuration
    """
    global _config_manager
    if config_file and config_file != _config_manager.config_file:
        _config_manager = ConfigManager(config_file)
    return _config_manager.load_config()


def reload_config(config_file: Optional[str] = None) -> Config:
    """Reload configuration from file.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        Reloaded configuration
    """
    global _config_manager
    _config_manager = ConfigManager(config_file)
    return _config_manager.load_config()
