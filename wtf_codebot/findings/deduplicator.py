"""
Deduplicator for removing duplicate findings from multiple analysis sources.

This module identifies and merges duplicate findings that may arise when
multiple tools report the same issue or when similar issues are detected
in nearby locations.
"""

import logging
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict

from .models import UnifiedFinding, FindingsCollection, FindingSeverity, FindingType

logger = logging.getLogger(__name__)


class FindingsDeduplicator:
    """
    Deduplicates findings based on various similarity criteria.
    
    The deduplicator uses multiple strategies:
    1. Exact matches based on file, line, and rule ID
    2. Location-based matching within tolerance
    3. Content similarity matching
    4. Type-based grouping for related findings
    """
    
    def __init__(self, location_tolerance: int = 2, similarity_threshold: float = 0.8):
        """
        Initialize the deduplicator.
        
        Args:
            location_tolerance: Line number tolerance for location matching
            similarity_threshold: Threshold for content similarity (0.0-1.0)
        """
        self.location_tolerance = location_tolerance
        self.similarity_threshold = similarity_threshold
        self._processed_groups: List[List[UnifiedFinding]] = []
    
    def deduplicate_findings(self, collection: FindingsCollection) -> FindingsCollection:
        """
        Deduplicate findings in a collection.
        
        Args:
            collection: Collection of findings to deduplicate
            
        Returns:
            New collection with deduplicated findings
        """
        if not collection.findings:
            return collection
        
        logger.info(f"Starting deduplication of {len(collection.findings)} findings")
        
        # Group findings for deduplication
        groups = self._group_similar_findings(collection.findings)
        
        # Merge groups and create deduplicated collection
        deduplicated_findings = []
        merge_stats = {'total_groups': len(groups), 'merged_count': 0, 'kept_count': 0}
        
        for group in groups:
            if len(group) == 1:
                # Single finding, keep as-is
                deduplicated_findings.append(group[0])
                merge_stats['kept_count'] += 1
            else:
                # Multiple findings, merge them
                merged_finding = self._merge_finding_group(group)
                deduplicated_findings.append(merged_finding)
                merge_stats['merged_count'] += len(group)
                
                # Update duplicate references
                for finding in group[1:]:
                    finding.duplicate_of = merged_finding.id
        
        # Create new collection
        deduplicated_collection = FindingsCollection(
            findings=deduplicated_findings,
            metadata={
                **collection.metadata,
                'deduplication_stats': merge_stats,
                'original_count': len(collection.findings),
                'deduplicated_count': len(deduplicated_findings)
            },
            created_at=collection.created_at
        )
        
        logger.info(f"Deduplication complete: {len(collection.findings)} -> {len(deduplicated_findings)} findings")
        logger.info(f"Merged {merge_stats['merged_count']} findings into {len([g for g in groups if len(g) > 1])} groups")
        
        return deduplicated_collection
    
    def _group_similar_findings(self, findings: List[UnifiedFinding]) -> List[List[UnifiedFinding]]:
        """
        Group similar findings together for merging.
        
        Args:
            findings: List of findings to group
            
        Returns:
            List of groups, where each group contains similar findings
        """
        # Create groups based on different criteria
        file_groups = self._group_by_file(findings)
        groups = []
        
        for file_path, file_findings in file_groups.items():
            # Further group by similarity within each file
            file_groups_list = self._group_by_similarity(file_findings)
            groups.extend(file_groups_list)
        
        return groups
    
    def _group_by_file(self, findings: List[UnifiedFinding]) -> Dict[str, List[UnifiedFinding]]:
        """Group findings by file path."""
        file_groups = defaultdict(list)
        for finding in findings:
            file_groups[finding.location.file_path].append(finding)
        return dict(file_groups)
    
    def _group_by_similarity(self, findings: List[UnifiedFinding]) -> List[List[UnifiedFinding]]:
        """
        Group findings within a file by similarity.
        
        Args:
            findings: Findings from the same file
            
        Returns:
            List of groups of similar findings
        """
        if not findings:
            return []
        
        groups = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # Start a new group with this finding
            group = [finding]
            processed.add(i)
            
            # Find all similar findings
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed:
                    continue
                
                if self._are_findings_similar(finding, other_finding):
                    group.append(other_finding)
                    processed.add(j)
            
            groups.append(group)
        
        return groups
    
    def _are_findings_similar(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        """
        Check if two findings are similar enough to be considered duplicates.
        
        Args:
            finding1: First finding
            finding2: Second finding
            
        Returns:
            True if findings are similar enough to merge
        """
        # Use the built-in duplicate detection from the model
        return finding1.is_duplicate_of(finding2, self.location_tolerance)
    
    def _merge_finding_group(self, group: List[UnifiedFinding]) -> UnifiedFinding:
        """
        Merge a group of similar findings into a single finding.
        
        Args:
            group: List of similar findings to merge
            
        Returns:
            Merged finding with combined information
        """
        if len(group) == 1:
            return group[0]
        
        # Sort by severity and confidence to pick the best primary finding
        primary_finding = max(group, key=lambda f: (f.severity.score(), f.confidence))
        
        # Merge with all other findings
        merged = primary_finding
        for other_finding in group:
            if other_finding.id != primary_finding.id:
                merged = merged.merge_with(other_finding)
        
        # Add merge metadata
        merge_info = {
            'merged_from_count': len(group),
            'merged_findings': [f.id for f in group],
            'merge_reasons': self._get_merge_reasons(group)
        }
        
        merged.metadata.update({
            'merge_info': merge_info,
            'is_merged': True
        })
        
        return merged
    
    def _get_merge_reasons(self, group: List[UnifiedFinding]) -> List[str]:
        """
        Get reasons why findings were merged.
        
        Args:
            group: Group of findings that were merged
            
        Returns:
            List of merge reasons
        """
        if len(group) <= 1:
            return []
        
        reasons = []
        
        # Check for exact location matches
        locations = [(f.location.line_start, f.location.column_start) for f in group]
        if len(set(locations)) == 1:
            reasons.append("exact_location_match")
        elif len(set(loc[0] for loc in locations if loc[0] is not None)) <= self.location_tolerance:
            reasons.append("nearby_location_match")
        
        # Check for rule ID matches
        rule_ids = [f.rule_id for f in group if f.rule_id]
        if len(set(rule_ids)) == 1 and rule_ids:
            reasons.append("same_rule_id")
        
        # Check for type compatibility
        types = [f.finding_type for f in group]
        if len(set(types)) == 1:
            reasons.append("same_finding_type")
        elif self._are_types_compatible([f.finding_type for f in group]):
            reasons.append("compatible_finding_types")
        
        # Check for content similarity
        titles = [f.title.lower() for f in group if f.title]
        if len(titles) > 1 and any(t1 in t2 or t2 in t1 for t1 in titles for t2 in titles if t1 != t2):
            reasons.append("similar_titles")
        
        messages = [f.message.lower() for f in group if f.message]
        if len(messages) > 1 and any(m1 in m2 or m2 in m1 for m1 in messages for m2 in messages if m1 != m2):
            reasons.append("similar_messages")
        
        return reasons if reasons else ["similarity_match"]
    
    def _are_types_compatible(self, types: List[FindingType]) -> bool:
        """Check if finding types are compatible for merging."""
        if len(set(types)) <= 1:
            return True
        
        # Define compatible type groups
        security_types = {
            FindingType.SECURITY_VULNERABILITY,
            FindingType.AUTHENTICATION_ISSUE,
            FindingType.AUTHORIZATION_ISSUE,
            FindingType.INPUT_VALIDATION,
            FindingType.CRYPTOGRAPHY_ISSUE
        }
        
        quality_types = {
            FindingType.CODE_SMELL,
            FindingType.ANTI_PATTERN,
            FindingType.MAINTAINABILITY
        }
        
        style_types = {
            FindingType.STYLE_VIOLATION,
            FindingType.FORMATTING_ISSUE,
            FindingType.NAMING_CONVENTION
        }
        
        dependency_types = {
            FindingType.OUTDATED_DEPENDENCY,
            FindingType.VULNERABLE_DEPENDENCY,
            FindingType.LICENSE_ISSUE,
            FindingType.UNUSED_DEPENDENCY
        }
        
        performance_types = {
            FindingType.PERFORMANCE_ISSUE,
            FindingType.MEMORY_LEAK,
            FindingType.INEFFICIENT_ALGORITHM
        }
        
        # Check if all types belong to the same group
        type_set = set(types)
        return (type_set.issubset(security_types) or
                type_set.issubset(quality_types) or
                type_set.issubset(style_types) or
                type_set.issubset(dependency_types) or
                type_set.issubset(performance_types))
    
    def get_deduplication_report(self, original_collection: FindingsCollection,
                               deduplicated_collection: FindingsCollection) -> Dict[str, any]:
        """
        Generate a deduplication report.
        
        Args:
            original_collection: Original collection before deduplication
            deduplicated_collection: Collection after deduplication
            
        Returns:
            Report with deduplication statistics and details
        """
        original_count = len(original_collection.findings)
        deduplicated_count = len(deduplicated_collection.findings)
        reduction = original_count - deduplicated_count
        reduction_percent = (reduction / original_count * 100) if original_count > 0 else 0
        
        # Count by severity
        original_severity_counts = {}
        deduplicated_severity_counts = {}
        
        for severity in FindingSeverity:
            original_severity_counts[severity.value] = len(original_collection.get_by_severity(severity))
            deduplicated_severity_counts[severity.value] = len(deduplicated_collection.get_by_severity(severity))
        
        # Count by type
        original_type_counts = {}
        deduplicated_type_counts = {}
        
        for finding_type in FindingType:
            orig_count = len(original_collection.get_by_type(finding_type))
            dedup_count = len(deduplicated_collection.get_by_type(finding_type))
            
            if orig_count > 0:
                original_type_counts[finding_type.value] = orig_count
            if dedup_count > 0:
                deduplicated_type_counts[finding_type.value] = dedup_count
        
        # Get merge information
        merge_info = deduplicated_collection.metadata.get('deduplication_stats', {})
        
        return {
            'summary': {
                'original_count': original_count,
                'deduplicated_count': deduplicated_count,
                'reduction_count': reduction,
                'reduction_percentage': round(reduction_percent, 2)
            },
            'by_severity': {
                'original': original_severity_counts,
                'deduplicated': deduplicated_severity_counts
            },
            'by_type': {
                'original': original_type_counts,
                'deduplicated': deduplicated_type_counts
            },
            'merge_stats': merge_info,
            'settings': {
                'location_tolerance': self.location_tolerance,
                'similarity_threshold': self.similarity_threshold
            }
        }


def auto_deduplicate_collection(collection: FindingsCollection,
                               location_tolerance: int = 2,
                               similarity_threshold: float = 0.8) -> FindingsCollection:
    """
    Convenience function to deduplicate a findings collection.
    
    Args:
        collection: Collection to deduplicate
        location_tolerance: Line number tolerance for location matching
        similarity_threshold: Content similarity threshold
        
    Returns:
        Deduplicated collection
    """
    deduplicator = FindingsDeduplicator(location_tolerance, similarity_threshold)
    return deduplicator.deduplicate_findings(collection)
