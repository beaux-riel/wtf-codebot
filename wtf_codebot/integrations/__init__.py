"""Integrations for pushing results to external tools and services."""

from .github_issues import GitHubIssuesIntegration
from .webhook import WebhookIntegration
from .jira import JiraIntegration
from .slack import SlackIntegration

__all__ = [
    'GitHubIssuesIntegration',
    'WebhookIntegration', 
    'JiraIntegration',
    'SlackIntegration'
]
