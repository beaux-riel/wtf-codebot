"""Slack integration for posting findings to Slack channels."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import requests

from .base import BaseIntegration, IntegrationConfig
from ..findings.models import FindingsCollection, UnifiedFinding, FindingSeverity

logger = logging.getLogger(__name__)


@dataclass
class SlackConfig(IntegrationConfig):
    """Configuration for Slack integration."""
    webhook_url: str = ""  # Slack webhook URL
    bot_token: str = ""  # Bot token for Slack API
    channel: str = ""  # Channel to post to (e.g., #general)
    username: str = "WTF CodeBot"  # Bot username
    icon_emoji: str = ":robot_face:"  # Bot icon emoji
    thread_replies: bool = True  # Post findings as thread replies
    summary_only: bool = False  # Post only summary, not individual findings
    max_findings_in_message: int = 10  # Max findings to include in one message
    mention_users: List[str] = None  # Users to mention for critical findings
    severity_colors: Dict[str, str] = None  # Colors for different severities
    
    def __post_init__(self):
        if self.mention_users is None:
            self.mention_users = []
        if self.severity_colors is None:
            self.severity_colors = {
                "critical": "#FF0000",  # Red
                "high": "#FF8C00",      # Orange
                "medium": "#FFD700",    # Gold
                "low": "#90EE90",       # Light Green
                "info": "#87CEEB"       # Sky Blue
            }


class SlackIntegration(BaseIntegration):
    """Integration for posting findings to Slack."""
    
    def __init__(self, config: SlackConfig):
        """Initialize Slack integration.
        
        Args:
            config: Slack configuration
        """
        super().__init__(config)
        self.config: SlackConfig = config
        self.session = requests.Session()
        
        if self.config.bot_token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.config.bot_token}",
                "Content-Type": "application/json"
            })
    
    def validate_config(self) -> bool:
        """Validate Slack configuration."""
        if not self.config.webhook_url and not self.config.bot_token:
            logger.error("Either webhook_url or bot_token is required for Slack integration")
            return False
            
        if self.config.bot_token and not self.config.channel:
            logger.error("Channel is required when using bot token")
            return False
            
        # Test Slack connection
        if not self.config.dry_run:
            try:
                if self.config.webhook_url:
                    # Test webhook
                    test_payload = {
                        "text": "Test message from WTF CodeBot",
                        "username": self.config.username
                    }
                    response = requests.post(
                        self.config.webhook_url,
                        json=test_payload,
                        timeout=self.config.timeout
                    )
                    if response.status_code != 200:
                        logger.error(f"Slack webhook test failed: {response.status_code}")
                        return False
                else:
                    # Test bot token
                    response = self.session.post(
                        "https://slack.com/api/auth.test",
                        timeout=self.config.timeout
                    )
                    data = response.json()
                    if not data.get("ok"):
                        logger.error(f"Slack API test failed: {data.get('error')}")
                        return False
                        
            except Exception as e:
                logger.error(f"Failed to test Slack connection: {e}")
                return False
                
        return True
    
    def push_findings(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Post findings to Slack.
        
        Args:
            collection: Collection of findings to post
            
        Returns:
            Dictionary with posting results
        """
        if not self.validate_config():
            return {"success": False, "error": "Invalid configuration"}
        
        results = {
            "success": True,
            "messages_sent": 0,
            "errors": [],
            "thread_ts": None
        }
        
        try:
            # Send summary message
            summary_result = self._send_summary_message(collection)
            if summary_result.get("success"):
                results["messages_sent"] += 1
                results["thread_ts"] = summary_result.get("ts")
            else:
                results["errors"].append(f"Failed to send summary: {summary_result.get('error')}")
            
            # Send individual findings if not summary-only
            if not self.config.summary_only and collection.findings:
                # Filter to critical/high findings for individual messages
                important_findings = [f for f in collection.findings 
                                    if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
                
                findings_to_send = important_findings[:self.config.max_findings_in_message]
                
                for finding in findings_to_send:
                    if self.config.dry_run:
                        logger.info(f"DRY RUN: Would send finding {finding.title}")
                        results["messages_sent"] += 1
                        continue
                        
                    finding_result = self._send_finding_message(finding, results["thread_ts"])
                    if finding_result.get("success"):
                        results["messages_sent"] += 1
                    else:
                        results["errors"].append(f"Failed to send finding {finding.title}: {finding_result.get('error')}")
                
                # Mention if there are more findings
                if len(important_findings) > self.config.max_findings_in_message:
                    remaining = len(important_findings) - self.config.max_findings_in_message
                    self._send_simple_message(
                        f"... and {remaining} more critical/high severity findings. Check the full report for details.",
                        thread_ts=results["thread_ts"]
                    )
            
        except Exception as e:
            results["success"] = False
            results["errors"].append(str(e))
            logger.error(f"Failed to post to Slack: {e}")
        
        if results["errors"]:
            results["success"] = False
        
        return results
    
    def _send_summary_message(self, collection: FindingsCollection) -> Dict[str, Any]:
        """Send summary message to Slack."""
        summary_stats = collection.get_summary_stats()
        
        # Create Slack blocks for rich formatting
        blocks = self._create_summary_blocks(collection, summary_stats)
        
        payload = {
            "blocks": blocks,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji
        }
        
        if self.config.channel:
            payload["channel"] = self.config.channel
        
        if self.config.dry_run:
            logger.info("DRY RUN: Would send Slack summary message")
            return {"success": True, "dry_run": True}
        
        return self._send_slack_message(payload)
    
    def _send_finding_message(self, finding: UnifiedFinding, thread_ts: Optional[str] = None) -> Dict[str, Any]:
        """Send individual finding message to Slack."""
        blocks = self._create_finding_blocks(finding)
        
        payload = {
            "blocks": blocks,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji
        }
        
        if self.config.channel:
            payload["channel"] = self.config.channel
            
        if thread_ts and self.config.thread_replies:
            payload["thread_ts"] = thread_ts
        
        return self._send_slack_message(payload)
    
    def _send_simple_message(self, text: str, thread_ts: Optional[str] = None) -> Dict[str, Any]:
        """Send simple text message to Slack."""
        payload = {
            "text": text,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji
        }
        
        if self.config.channel:
            payload["channel"] = self.config.channel
            
        if thread_ts and self.config.thread_replies:
            payload["thread_ts"] = thread_ts
        
        return self._send_slack_message(payload)
    
    def _send_slack_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send message to Slack via webhook or API."""
        try:
            if self.config.webhook_url:
                # Use webhook
                response = requests.post(
                    self.config.webhook_url,
                    json=payload,
                    timeout=self.config.timeout
                )
                if response.status_code == 200:
                    return {"success": True}
                else:
                    return {"success": False, "error": f"HTTP {response.status_code}: {response.text}"}
            else:
                # Use bot API
                response = self.session.post(
                    "https://slack.com/api/chat.postMessage",
                    json=payload,
                    timeout=self.config.timeout
                )
                data = response.json()
                if data.get("ok"):
                    return {"success": True, "ts": data.get("ts")}
                else:
                    return {"success": False, "error": data.get("error", "Unknown error")}
                    
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _create_summary_blocks(self, collection: FindingsCollection, summary_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create Slack blocks for summary message."""
        blocks = []
        
        # Header
        critical_count = summary_stats["severity_counts"].get("critical", 0)
        high_count = summary_stats["severity_counts"].get("high", 0)
        
        header_text = f"🔍 *Code Analysis Complete*"
        if critical_count > 0 or high_count > 0:
            header_text += f" - {critical_count + high_count} critical/high issues found!"
            
        # Mention users for critical findings
        if critical_count > 0 and self.config.mention_users:
            mentions = " ".join([f"<@{user}>" for user in self.config.mention_users])
            header_text += f" {mentions}"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": header_text
            }
        })
        
        # Summary stats
        fields = []
        fields.append({
            "type": "mrkdwn",
            "text": f"*Total Findings:*\\n{summary_stats['total']}"
        })
        fields.append({
            "type": "mrkdwn", 
            "text": f"*Files Affected:*\\n{summary_stats['affected_files_count']}"
        })
        
        # Severity breakdown
        for severity in ["critical", "high", "medium", "low"]:
            count = summary_stats["severity_counts"].get(severity, 0)
            if count > 0:
                emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}[severity]
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*{emoji} {severity.title()}:*\\n{count}"
                })
        
        blocks.append({
            "type": "section",
            "fields": fields
        })
        
        # Top finding types
        if summary_stats.get("type_counts"):
            type_text = "*Top Issues:*\\n"
            sorted_types = sorted(summary_stats["type_counts"].items(), key=lambda x: x[1], reverse=True)
            for finding_type, count in sorted_types[:5]:
                type_text += f"• {finding_type.replace('_', ' ').title()}: {count}\\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": type_text
                }
            })
        
        # Divider
        blocks.append({"type": "divider"})
        
        return blocks
    
    def _create_finding_blocks(self, finding: UnifiedFinding) -> List[Dict[str, Any]]:
        """Create Slack blocks for individual finding."""
        blocks = []
        
        # Finding header with color
        severity_color = self.config.severity_colors.get(finding.severity.value, "#808080")
        severity_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}.get(finding.severity.value, "⚪")
        
        header_text = f"{severity_emoji} *{finding.title}*"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": header_text
            },
            "accessory": {
                "type": "overflow",
                "options": [
                    {
                        "text": {
                            "type": "plain_text",
                            "text": f"Severity: {finding.severity.value.title()}"
                        },
                        "value": "severity"
                    }
                ]
            }
        })
        
        # Finding details
        fields = []
        fields.append({
            "type": "mrkdwn",
            "text": f"*File:*\\n`{finding.location.file_path}`"
        })
        
        if finding.location.line_start:
            line_info = f"Line {finding.location.line_start}"
            if finding.location.line_end and finding.location.line_end != finding.location.line_start:
                line_info += f"-{finding.location.line_end}"
            fields.append({
                "type": "mrkdwn",
                "text": f"*Location:*\\n{line_info}"
            })
        
        fields.append({
            "type": "mrkdwn",
            "text": f"*Type:*\\n{finding.finding_type.value.replace('_', ' ').title()}"
        })
        
        fields.append({
            "type": "mrkdwn",
            "text": f"*Source:*\\n{finding.source.value.replace('_', ' ').title()}"
        })
        
        blocks.append({
            "type": "section",
            "fields": fields
        })
        
        # Message/Description
        if finding.message:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Message:*\\n{finding.message}"
                }
            })
        
        # Suggestion
        if finding.suggestion:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Suggestion:*\\n{finding.suggestion}"
                }
            })
        
        # Code snippet (if short enough)
        if finding.affected_code and len(finding.affected_code) < 500:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Code:*\\n```\\n{finding.affected_code}\\n```"
                }
            })
        
        return blocks
