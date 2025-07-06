"""
Dependency and Security Analysis Module

This module provides comprehensive dependency analysis for various package managers,
including dependency mapping, version analysis, license detection, and vulnerability
scanning using public security advisories.
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime
import logging

import toml
import yaml

from wtf_codebot.core.exceptions import AnalysisError
from wtf_codebot.analyzers.base import BaseAnalyzer


@dataclass
class DependencyInfo:
    """Information about a single dependency"""
    name: str
    version: str
    version_constraint: Optional[str] = None
    license: Optional[str] = None
    description: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    dev_dependency: bool = False
    optional: bool = False
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class VulnerabilityInfo:
    """Information about a security vulnerability"""
    cve_id: Optional[str] = None
    advisory_id: Optional[str] = None
    severity: str = "unknown"
    title: str = ""
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    source: str = ""
    
    def __post_init__(self):
        if self.affected_versions is None:
            self.affected_versions = []
        if self.fixed_versions is None:
            self.fixed_versions = []


@dataclass
class DependencyAnalysisResult:
    """Result of dependency analysis"""
    package_manager: str
    file_path: str
    dependencies: Dict[str, DependencyInfo] = field(default_factory=dict)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    license_summary: Dict[str, List[str]] = field(default_factory=dict)
    dependency_tree: Dict[str, List[str]] = field(default_factory=dict)
    outdated_packages: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.license_summary is None:
            self.license_summary = {}
        if self.dependency_tree is None:
            self.dependency_tree = {}
        if self.outdated_packages is None:
            self.outdated_packages = []


class PackageManagerParser(ABC):
    """Abstract base class for package manager parsers"""
    
    @abstractmethod
    def parse_dependencies(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse dependencies from package manager file"""
        pass
    
    @abstractmethod
    def get_package_info(self, package_name: str, version: str) -> Optional[DependencyInfo]:
        """Get detailed package information"""
        pass


class NPMParser(PackageManagerParser):
    """Parser for npm package.json files"""
    
    def parse_dependencies(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse dependencies from package.json"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = {}
            
            # Parse production dependencies
            for name, version in data.get('dependencies', {}).items():
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version,
                    version_constraint=version,
                    dev_dependency=False
                )
            
            # Parse dev dependencies
            for name, version in data.get('devDependencies', {}).items():
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version,
                    version_constraint=version,
                    dev_dependency=True
                )
            
            # Parse optional dependencies
            for name, version in data.get('optionalDependencies', {}).items():
                if name in dependencies:
                    dependencies[name].optional = True
                else:
                    dependencies[name] = DependencyInfo(
                        name=name,
                        version=version,
                        version_constraint=version,
                        optional=True
                    )
            
            return dependencies
            
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            raise AnalysisError(f"Failed to parse package.json: {e}")
    
    def get_package_info(self, package_name: str, version: str) -> Optional[DependencyInfo]:
        """Get package info from npm registry"""
        try:
            # Clean version for npm registry lookup
            clean_version = re.sub(r'[^\d\.]', '', version)
            url = f"https://registry.npmjs.org/{package_name}/{clean_version}"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                return DependencyInfo(
                    name=package_name,
                    version=clean_version,
                    license=data.get('license'),
                    description=data.get('description'),
                    dependencies=list(data.get('dependencies', {}).keys())
                )
        except (urllib.error.URLError, json.JSONDecodeError, KeyError):
            return None


class PythonParser(PackageManagerParser):
    """Parser for Python package files (requirements.txt, pyproject.toml, poetry.lock)"""
    
    def parse_dependencies(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse dependencies from Python package files"""
        file_name = os.path.basename(file_path).lower()
        
        if file_name == 'requirements.txt':
            return self._parse_requirements_txt(file_path)
        elif file_name == 'pyproject.toml':
            return self._parse_pyproject_toml(file_path)
        elif file_name == 'poetry.lock':
            return self._parse_poetry_lock(file_path)
        elif file_name == 'pipfile':
            return self._parse_pipfile(file_path)
        else:
            raise AnalysisError(f"Unsupported Python package file: {file_name}")
    
    def _parse_requirements_txt(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse requirements.txt file"""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse requirement line (e.g., "package==1.0.0", "package>=1.0.0")
                        match = re.match(r'([a-zA-Z0-9\-_\.]+)([><=!~]+)([0-9\.]+.*)', line)
                        if match:
                            name, constraint, version = match.groups()
                            dependencies[name] = DependencyInfo(
                                name=name,
                                version=version,
                                version_constraint=f"{constraint}{version}"
                            )
        except FileNotFoundError:
            raise AnalysisError(f"Requirements file not found: {file_path}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse pyproject.toml file"""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Parse Poetry dependencies
            if 'tool' in data and 'poetry' in data['tool']:
                poetry_deps = data['tool']['poetry'].get('dependencies', {})
                for name, version in poetry_deps.items():
                    if name != 'python':  # Skip Python version constraint
                        version_str = version if isinstance(version, str) else str(version)
                        dependencies[name] = DependencyInfo(
                            name=name,
                            version=version_str,
                            version_constraint=version_str,
                            dev_dependency=False
                        )
                
                # Parse dev dependencies
                if 'group' in data['tool']['poetry'] and 'dev' in data['tool']['poetry']['group']:
                    dev_deps = data['tool']['poetry']['group']['dev'].get('dependencies', {})
                    for name, version in dev_deps.items():
                        version_str = version if isinstance(version, str) else str(version)
                        dependencies[name] = DependencyInfo(
                            name=name,
                            version=version_str,
                            version_constraint=version_str,
                            dev_dependency=True
                        )
            
            # Parse setuptools dependencies
            if 'project' in data:
                project_deps = data['project'].get('dependencies', [])
                for dep in project_deps:
                    match = re.match(r'([a-zA-Z0-9\-_\.]+)([><=!~]+)([0-9\.]+.*)', dep)
                    if match:
                        name, constraint, version = match.groups()
                        dependencies[name] = DependencyInfo(
                            name=name,
                            version=version,
                            version_constraint=f"{constraint}{version}"
                        )
            
        except (FileNotFoundError, toml.TomlDecodeError) as e:
            raise AnalysisError(f"Failed to parse pyproject.toml: {e}")
        
        return dependencies
    
    def _parse_poetry_lock(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse poetry.lock file"""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            for package in data.get('package', []):
                name = package['name']
                version = package['version']
                
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version,
                    description=package.get('description'),
                    dependencies=list(package.get('dependencies', {}).keys()),
                    dev_dependency=package.get('category') == 'dev'
                )
        
        except (FileNotFoundError, toml.TomlDecodeError) as e:
            raise AnalysisError(f"Failed to parse poetry.lock: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> Dict[str, DependencyInfo]:
        """Parse Pipfile"""
        dependencies = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Parse packages
            for name, version in data.get('packages', {}).items():
                version_str = version if isinstance(version, str) else str(version)
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version_str,
                    version_constraint=version_str,
                    dev_dependency=False
                )
            
            # Parse dev packages
            for name, version in data.get('dev-packages', {}).items():
                version_str = version if isinstance(version, str) else str(version)
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version_str,
                    version_constraint=version_str,
                    dev_dependency=True
                )
        
        except (FileNotFoundError, toml.TomlDecodeError) as e:
            raise AnalysisError(f"Failed to parse Pipfile: {e}")
        
        return dependencies
    
    def get_package_info(self, package_name: str, version: str) -> Optional[DependencyInfo]:
        """Get package info from PyPI"""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                info = data.get('info', {})
                return DependencyInfo(
                    name=package_name,
                    version=version,
                    license=info.get('license'),
                    description=info.get('summary'),
                    dependencies=[]  # PyPI doesn't provide dependency info in this endpoint
                )
        except (urllib.error.URLError, json.JSONDecodeError, KeyError):
            return None


class SecurityAdvisoryClient:
    """Client for fetching security advisories from various sources"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_vulnerabilities(self, package_name: str, version: str, ecosystem: str) -> List[VulnerabilityInfo]:
        """Get vulnerabilities for a package from multiple sources"""
        vulnerabilities = []
        
        # Try GitHub Advisory Database
        github_vulns = self._get_github_advisories(package_name, version, ecosystem)
        vulnerabilities.extend(github_vulns)
        
        # Try OSV database
        osv_vulns = self._get_osv_advisories(package_name, version, ecosystem)
        vulnerabilities.extend(osv_vulns)
        
        return vulnerabilities
    
    def _get_github_advisories(self, package_name: str, version: str, ecosystem: str) -> List[VulnerabilityInfo]:
        """Get vulnerabilities from GitHub Advisory Database"""
        # GitHub Advisory Database requires GraphQL API with authentication
        # Skipping for now to avoid authentication requirements
        return []
    
    def _get_osv_advisories(self, package_name: str, version: str, ecosystem: str) -> List[VulnerabilityInfo]:
        """Get vulnerabilities from OSV database"""
        try:
            # Map ecosystem to OSV format
            ecosystem_map = {
                'python': 'PyPI',
                'npm': 'npm',
                'pip': 'PyPI',
                'pypi': 'PyPI'
            }
            osv_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem)
            
            # OSV API query
            query_data = {
                "package": {
                    "name": package_name,
                    "ecosystem": osv_ecosystem
                },
                "version": version
            }
            
            url = "https://api.osv.dev/v1/query"
            req = urllib.request.Request(
                url,
                data=json.dumps(query_data).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                vulnerabilities = []
                for vuln_data in data.get('vulns', []):
                    vuln = VulnerabilityInfo(
                        advisory_id=vuln_data.get('id'),
                        severity=vuln_data.get('database_specific', {}).get('severity', 'unknown'),
                        title=vuln_data.get('summary', ''),
                        description=vuln_data.get('details', ''),
                        source='OSV Database'
                    )
                    
                    # Parse affected versions
                    for affected in vuln_data.get('affected', []):
                        if affected.get('package', {}).get('name') == package_name:
                            for version_range in affected.get('ranges', []):
                                for event in version_range.get('events', []):
                                    if 'introduced' in event:
                                        vuln.affected_versions.append(f">={event['introduced']}")
                                    if 'fixed' in event:
                                        vuln.fixed_versions.append(event['fixed'])
                    
                    vulnerabilities.append(vuln)
                
                return vulnerabilities
        
        except urllib.error.HTTPError as e:
            # Only log debug for common API errors
            if e.code in [400, 404, 422]:
                self.logger.debug(f"No OSV advisories found for {package_name}: HTTP {e.code}")
            else:
                self.logger.warning(f"Failed to fetch OSV advisories for {package_name}: HTTP Error {e.code}")
            return []
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            self.logger.warning(f"Failed to fetch OSV advisories for {package_name}: {e}")
            return []


class DependencyAnalyzer(BaseAnalyzer):
    """Main dependency analyzer class"""
    
    def __init__(self, name: str = "dependency_analyzer"):
        super().__init__(name)
        self.logger = logging.getLogger(__name__)
        self.parsers = {
            'package.json': NPMParser(),
            'requirements.txt': PythonParser(),
            'pyproject.toml': PythonParser(),
            'poetry.lock': PythonParser(),
            'pipfile': PythonParser()
        }
        self.security_client = SecurityAdvisoryClient()
    
    def analyze_directory(self, directory: str) -> List[DependencyAnalysisResult]:
        """Analyze all package manager files in a directory"""
        results = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower() in self.parsers:
                    file_path = os.path.join(root, file)
                    try:
                        result = self.analyze_dependency_file(file_path)
                        results.append(result)
                    except AnalysisError as e:
                        self.logger.error(f"Failed to analyze {file_path}: {e}")
        
        return results
    
    def analyze_dependency_file(self, file_path: str) -> DependencyAnalysisResult:
        """Analyze a single package manager file"""
        file_name = os.path.basename(file_path).lower()
        
        if file_name not in self.parsers:
            raise AnalysisError(f"Unsupported file type: {file_name}")
        
        parser = self.parsers[file_name]
        
        # Parse dependencies
        dependencies = parser.parse_dependencies(file_path)
        
        # Determine package manager and ecosystem
        package_manager = self._get_package_manager(file_name)
        ecosystem = self._get_ecosystem(file_name)
        
        # Create result object
        result = DependencyAnalysisResult(
            package_manager=package_manager,
            file_path=file_path,
            dependencies=dependencies
        )
        
        # Enhance with additional information
        self._enhance_dependencies(result, parser, ecosystem)
        
        # Check for vulnerabilities
        self._check_vulnerabilities(result, ecosystem)
        
        # Generate license summary
        self._generate_license_summary(result)
        
        # Build dependency tree
        self._build_dependency_tree(result)
        
        return result
    
    def _get_package_manager(self, file_name: str) -> str:
        """Get package manager name from file name"""
        mapping = {
            'package.json': 'npm',
            'requirements.txt': 'pip',
            'pyproject.toml': 'poetry/setuptools',
            'poetry.lock': 'poetry',
            'pipfile': 'pipenv'
        }
        return mapping.get(file_name, 'unknown')
    
    def _get_ecosystem(self, file_name: str) -> str:
        """Get ecosystem name from file name"""
        mapping = {
            'package.json': 'npm',
            'requirements.txt': 'pypi',
            'pyproject.toml': 'pypi',
            'poetry.lock': 'pypi',
            'pipfile': 'pypi'
        }
        return mapping.get(file_name, 'unknown')
    
    def _enhance_dependencies(self, result: DependencyAnalysisResult, parser: PackageManagerParser, ecosystem: str):
        """Enhance dependency information with additional details"""
        for name, dep_info in result.dependencies.items():
            # Try to get additional package information
            enhanced_info = parser.get_package_info(name, dep_info.version)
            if enhanced_info:
                dep_info.license = enhanced_info.license or dep_info.license
                dep_info.description = enhanced_info.description or dep_info.description
                dep_info.dependencies = enhanced_info.dependencies or dep_info.dependencies
    
    def _check_vulnerabilities(self, result: DependencyAnalysisResult, ecosystem: str):
        """Check for vulnerabilities in dependencies"""
        if self.security_client is None:
            return
        
        # Skip vulnerability checking if disabled via environment variable
        if os.environ.get('WTF_CODEBOT_SKIP_VULNERABILITY_CHECK', '').lower() == 'true':
            self.logger.info("Skipping vulnerability checks (disabled via environment)")
            return
        
        for name, dep_info in result.dependencies.items():
            vulns = self.security_client.get_vulnerabilities(name, dep_info.version, ecosystem)
            result.vulnerabilities.extend(vulns)
    
    def _generate_license_summary(self, result: DependencyAnalysisResult):
        """Generate license summary"""
        for name, dep_info in result.dependencies.items():
            if dep_info.license:
                license_key = dep_info.license.lower()
                if license_key not in result.license_summary:
                    result.license_summary[license_key] = []
                result.license_summary[license_key].append(name)
    
    def _build_dependency_tree(self, result: DependencyAnalysisResult):
        """Build dependency tree"""
        for name, dep_info in result.dependencies.items():
            result.dependency_tree[name] = dep_info.dependencies
    
    def get_supported_extensions(self) -> List[str]:
        """Get supported file extensions"""
        return ['.json', '.txt', '.toml', '.lock']
    
    def get_supported_languages(self) -> List[str]:
        """Get supported languages"""
        return ['javascript', 'python']
    
    def analyze_file(self, file_node):
        """Analyze a single file (required by BaseAnalyzer)"""
        from .base import AnalysisResult
        # This is a simple stub - dependency analysis works differently
        # than the standard file-by-file analysis pattern
        return AnalysisResult()
    
    def supports_file(self, file_node) -> bool:
        """Check if this analyzer supports the given file"""
        if hasattr(file_node, 'name'):
            filename = file_node.name.lower()
        elif hasattr(file_node, 'path'):
            filename = os.path.basename(file_node.path).lower()
        else:
            return False
        
        return filename in self.parsers
