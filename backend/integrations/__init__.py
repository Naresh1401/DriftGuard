"""
DriftGuard Integration Connectors
==================================
Connectors for ingesting signals from external platforms:
- Splunk (SIEM)
- Microsoft Sentinel (SIEM)
- AWS CloudTrail (Cloud audit)
- Google Workspace (Collaboration audit)
- Epic EMR (Healthcare EHR)

All connectors implement BaseConnector and feed into the signal ingestion pipeline.
"""

from .base import BaseConnector, ConnectorConfig, ConnectorStatus
from .splunk import SplunkConnector
from .sentinel import SentinelConnector
from .cloudtrail import CloudTrailConnector
from .google_workspace import GoogleWorkspaceConnector
from .epic_emr import EpicEMRConnector

AVAILABLE_CONNECTORS = {
    "splunk": SplunkConnector,
    "sentinel": SentinelConnector,
    "cloudtrail": CloudTrailConnector,
    "google_workspace": GoogleWorkspaceConnector,
    "epic_emr": EpicEMRConnector,
}

__all__ = [
    "BaseConnector",
    "ConnectorConfig",
    "ConnectorStatus",
    "SplunkConnector",
    "SentinelConnector",
    "CloudTrailConnector",
    "GoogleWorkspaceConnector",
    "EpicEMRConnector",
    "AVAILABLE_CONNECTORS",
]
