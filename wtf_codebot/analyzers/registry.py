"""
Analyzer registry for managing static analysis engines.
"""

from typing import Dict, List, Optional, Type
import logging

from .base import BaseAnalyzer, AnalysisResult
from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from ..discovery.models import FileNode, CodebaseGraph

logger = logging.getLogger(__name__)


class AnalyzerRegistry:
    """
    Registry for managing and coordinating static analysis engines.
    """
    
    def __init__(self):
        """Initialize the analyzer registry."""
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        self._register_default_analyzers()
    
    def _register_default_analyzers(self) -> None:
        """Register default analyzers for supported languages."""
        # Register Python analyzer
        python_analyzer = PythonAnalyzer()
        self.register_analyzer("python", python_analyzer)
        
        # Register JavaScript/TypeScript analyzer
        js_analyzer = JavaScriptAnalyzer()
        self.register_analyzer("javascript", js_analyzer)
        self.register_analyzer("typescript", js_analyzer)  # Same analyzer handles both
    
    def register_analyzer(self, language: str, analyzer: BaseAnalyzer) -> None:
        """
        Register an analyzer for a specific language.
        
        Args:
            language: Language name (e.g., 'python', 'javascript')
            analyzer: Analyzer instance
        """
        self._analyzers[language] = analyzer
        logger.info(f"Registered analyzer for {language}: {analyzer.name}")
    
    def get_analyzer(self, language: str) -> Optional[BaseAnalyzer]:
        """
        Get an analyzer for a specific language.
        
        Args:
            language: Language name
            
        Returns:
            Optional[BaseAnalyzer]: Analyzer instance or None if not found
        """
        return self._analyzers.get(language)
    
    def get_analyzer_for_file(self, file_node: FileNode) -> Optional[BaseAnalyzer]:
        """
        Get the appropriate analyzer for a file based on its extension.
        
        Args:
            file_node: File to analyze
            
        Returns:
            Optional[BaseAnalyzer]: Appropriate analyzer or None if not found
        """
        for analyzer in self._analyzers.values():
            if analyzer.supports_file(file_node):
                return analyzer
        return None
    
    def get_supported_languages(self) -> List[str]:
        """
        Get list of supported languages.
        
        Returns:
            List[str]: List of supported language names
        """
        return list(self._analyzers.keys())
    
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of all supported file extensions.
        
        Returns:
            List[str]: List of supported file extensions
        """
        extensions = set()
        for analyzer in self._analyzers.values():
            extensions.update(analyzer.supported_extensions)
        return list(extensions)
    
    def analyze_file(self, file_node: FileNode) -> Optional[AnalysisResult]:
        """
        Analyze a single file using the appropriate analyzer.
        
        Args:
            file_node: File to analyze
            
        Returns:
            Optional[AnalysisResult]: Analysis results or None if no analyzer available
        """
        analyzer = self.get_analyzer_for_file(file_node)
        if analyzer:
            try:
                return analyzer.analyze_file(file_node)
            except Exception as e:
                logger.error(f"Error analyzing {file_node.path} with {analyzer.name}: {str(e)}")
                return None
        else:
            logger.debug(f"No analyzer available for {file_node.path}")
            return None
    
    def analyze_codebase(
        self, 
        codebase: CodebaseGraph, 
        languages: Optional[List[str]] = None
    ) -> Dict[str, AnalysisResult]:
        """
        Analyze entire codebase using appropriate analyzers.
        
        Args:
            codebase: Codebase to analyze
            languages: Optional list of languages to analyze (all if None)
            
        Returns:
            Dict[str, AnalysisResult]: Analysis results by language
        """
        results = {}
        
        # Determine which languages to analyze
        if languages is None:
            languages = self.get_supported_languages()
        
        for language in languages:
            analyzer = self.get_analyzer(language)
            if analyzer:
                try:
                    logger.info(f"Running {language} analysis...")
                    result = analyzer.analyze_codebase(codebase)
                    results[language] = result
                    logger.info(f"Completed {language} analysis: "
                              f"{len(result.findings)} findings, {len(result.metrics)} metrics")
                except Exception as e:
                    logger.error(f"Error in {language} analysis: {str(e)}")
        
        return results
    
    def get_registry_stats(self) -> Dict[str, any]:
        """
        Get statistics about the registry.
        
        Returns:
            Dict[str, any]: Registry statistics
        """
        return {
            "total_analyzers": len(self._analyzers),
            "supported_languages": self.get_supported_languages(),
            "supported_extensions": self.get_supported_extensions(),
            "analyzer_details": {
                lang: {
                    "name": analyzer.name,
                    "extensions": list(analyzer.supported_extensions),
                    "enabled_rules": len(analyzer.enabled_rules),
                    "disabled_rules": len(analyzer.disabled_rules)
                }
                for lang, analyzer in self._analyzers.items()
            }
        }


# Global registry instance
_registry = None


def get_registry() -> AnalyzerRegistry:
    """
    Get the global analyzer registry instance.
    
    Returns:
        AnalyzerRegistry: Global registry instance
    """
    global _registry
    if _registry is None:
        _registry = AnalyzerRegistry()
    return _registry


def register_analyzer(language: str, analyzer: BaseAnalyzer) -> None:
    """
    Register an analyzer with the global registry.
    
    Args:
        language: Language name
        analyzer: Analyzer instance
    """
    registry = get_registry()
    registry.register_analyzer(language, analyzer)


def analyze_file(file_node: FileNode) -> Optional[AnalysisResult]:
    """
    Analyze a file using the global registry.
    
    Args:
        file_node: File to analyze
        
    Returns:
        Optional[AnalysisResult]: Analysis results
    """
    registry = get_registry()
    return registry.analyze_file(file_node)


def analyze_codebase(
    codebase: CodebaseGraph, 
    languages: Optional[List[str]] = None
) -> Dict[str, AnalysisResult]:
    """
    Analyze a codebase using the global registry.
    
    Args:
        codebase: Codebase to analyze
        languages: Optional list of languages to analyze
        
    Returns:
        Dict[str, AnalysisResult]: Analysis results by language
    """
    registry = get_registry()
    return registry.analyze_codebase(codebase, languages)
