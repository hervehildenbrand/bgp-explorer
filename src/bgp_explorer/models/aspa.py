"""ASPA (AS Provider Authorization) validation data models.

ASPA validates that each hop in an AS path represents an authorized
customer-provider relationship. This complements RPKI ROA validation
(which checks origin authorization) by detecting route leaks.
"""

from dataclasses import dataclass, field
from enum import Enum


class ASPAState(Enum):
    """Overall ASPA validation state for an AS path."""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    UNVERIFIABLE = "unverifiable"


@dataclass
class ASPAHopResult:
    """Per-hop ASPA validation result.

    Attributes:
        asn: The AS at this hop.
        next_asn: The next AS in the path.
        is_authorized_provider: Whether the next AS is an authorized provider.
        relationship_type: Observed relationship (upstream, peer, downstream, unknown).
        data_source: Where the relationship data came from.
        confidence: Confidence in the relationship data (0.0-1.0).
    """

    asn: int
    next_asn: int
    is_authorized_provider: bool | None
    relationship_type: str
    data_source: str
    confidence: float


@dataclass
class ASPAValidationResult:
    """Overall ASPA validation result for an AS path.

    Attributes:
        as_path: The validated AS path.
        state: Overall validation state.
        hop_results: Per-hop validation details.
        valley_free: Whether the path follows valley-free routing.
        issues: List of issues found during validation.
        summary: Human-readable summary.
    """

    as_path: list[int]
    state: ASPAState
    hop_results: list[ASPAHopResult] = field(default_factory=list)
    valley_free: bool = True
    issues: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "as_path": self.as_path,
            "state": self.state.value,
            "hop_results": [
                {
                    "asn": h.asn,
                    "next_asn": h.next_asn,
                    "is_authorized_provider": h.is_authorized_provider,
                    "relationship_type": h.relationship_type,
                    "data_source": h.data_source,
                    "confidence": h.confidence,
                }
                for h in self.hop_results
            ],
            "valley_free": self.valley_free,
            "issues": self.issues,
            "summary": self.summary,
        }
