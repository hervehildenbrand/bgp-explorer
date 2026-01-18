"""BGPEvent data model for anomaly events from bgp-radar."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class EventType(str, Enum):
    """Types of BGP anomaly events."""

    HIJACK = "hijack"
    LEAK = "leak"
    BLACKHOLE = "blackhole"


class Severity(str, Enum):
    """Severity levels for BGP events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BGPEvent:
    """Representation of a BGP anomaly event from bgp-radar.

    Attributes:
        type: Type of anomaly (hijack, leak, blackhole)
        severity: Severity level (low, medium, high)
        affected_prefix: The prefix affected by this anomaly
        detected_at: When the anomaly was detected
        affected_asn: The ASN affected (if applicable)
        details: Additional event-specific details
    """

    type: EventType
    severity: Severity
    affected_prefix: str
    detected_at: datetime
    affected_asn: Optional[int] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert event to dictionary for JSON serialization."""
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "affected_prefix": self.affected_prefix,
            "affected_asn": self.affected_asn,
            "detected_at": self.detected_at.isoformat(),
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BGPEvent":
        """Create a BGPEvent from a dictionary."""
        detected_at = data["detected_at"]
        if isinstance(detected_at, str):
            detected_at = datetime.fromisoformat(detected_at)
        return cls(
            type=EventType(data["type"]),
            severity=Severity(data["severity"]),
            affected_prefix=data["affected_prefix"],
            detected_at=detected_at,
            affected_asn=data.get("affected_asn"),
            details=data.get("details", {}),
        )

    @classmethod
    def from_bgp_radar(cls, data: dict) -> "BGPEvent":
        """Create a BGPEvent from bgp-radar JSON output.

        bgp-radar outputs events in a format like:
        {
            "type": "hijack",
            "severity": "high",
            "affected_prefix": "1.1.1.0/24",
            "affected_asn": 13335,
            "timestamp": "2024-01-01T12:00:00Z",
            "expected_origin": 13335,
            "observed_origin": 64496
        }
        """
        timestamp = data.get("timestamp") or data.get("detected_at")
        if isinstance(timestamp, str):
            # Handle both ISO format and Z suffix
            timestamp = timestamp.replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(timestamp)

        # Extract known fields, put the rest in details
        known_fields = {
            "type",
            "severity",
            "affected_prefix",
            "affected_asn",
            "timestamp",
            "detected_at",
        }
        details = {k: v for k, v in data.items() if k not in known_fields}

        return cls(
            type=EventType(data["type"]),
            severity=Severity(data["severity"]),
            affected_prefix=data["affected_prefix"],
            detected_at=timestamp,
            affected_asn=data.get("affected_asn"),
            details=details,
        )
