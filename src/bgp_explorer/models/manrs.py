"""MANRS data models for conformance and readiness assessment.

Represents MANRS (Mutually Agreed Norms for Routing Security) data:
- Official conformance from the MANRS Observatory API
- Local readiness assessment results per MANRS Action
"""

from dataclasses import dataclass, field
from enum import Enum


class MANRSAction(Enum):
    """The four MANRS Actions for network operators."""

    FILTERING = "filtering"
    ANTI_SPOOFING = "anti_spoofing"
    COORDINATION = "coordination"
    VALIDATION = "validation"


class MANRSReadiness(Enum):
    """MANRS readiness level per action."""

    READY = "ready"
    ASPIRING = "aspiring"
    LAGGING = "lagging"
    UNKNOWN = "unknown"


@dataclass
class MANRSConformance:
    """Official MANRS conformance data from the Observatory API.

    Attributes:
        asn: Autonomous System Number.
        name: Organization name.
        country: Two-letter ISO country code.
        status: Overall MANRS status string.
        action1_filtering: Readiness for Action 1 (Filtering).
        action2_anti_spoofing: Readiness for Action 2 (Anti-Spoofing).
        action3_coordination: Readiness for Action 3 (Coordination).
        action4_validation: Readiness for Action 4 (Global Validation).
        last_updated: ISO timestamp of last conformance update.
        manrs_participant: Whether this ASN has joined MANRS.
    """

    asn: int
    name: str
    country: str
    status: str
    action1_filtering: MANRSReadiness
    action2_anti_spoofing: MANRSReadiness
    action3_coordination: MANRSReadiness
    action4_validation: MANRSReadiness
    last_updated: str
    manrs_participant: bool


@dataclass
class MANRSActionFinding:
    """Assessment finding for a single MANRS action.

    Attributes:
        action: Which MANRS action this finding covers.
        readiness: Assessed readiness level.
        evidence: List of evidence strings supporting the assessment.
        measurable: Whether this action can be verified externally.
        recommendations: Suggested improvements.
        data_sources_used: Which data sources informed this finding.
    """

    action: MANRSAction
    readiness: MANRSReadiness
    evidence: list[str]
    measurable: bool
    recommendations: list[str]
    data_sources_used: list[str]


@dataclass
class MANRSReadinessReport:
    """Complete MANRS readiness assessment report.

    Attributes:
        asn: Assessed ASN.
        timestamp: When the assessment was performed.
        overall_readiness: Aggregate readiness level.
        overall_score: Numeric score (0-100).
        action_findings: Per-action assessment findings.
        summary: Human-readable summary.
        limitations: What could not be measured externally.
    """

    asn: int
    timestamp: str
    overall_readiness: MANRSReadiness
    overall_score: float
    action_findings: list[MANRSActionFinding] = field(default_factory=list)
    summary: str = ""
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asn": self.asn,
            "timestamp": self.timestamp,
            "overall_readiness": self.overall_readiness.value,
            "overall_score": self.overall_score,
            "action_findings": [
                {
                    "action": f.action.value,
                    "readiness": f.readiness.value,
                    "evidence": f.evidence,
                    "measurable": f.measurable,
                    "recommendations": f.recommendations,
                    "data_sources_used": f.data_sources_used,
                }
                for f in self.action_findings
            ],
            "summary": self.summary,
            "limitations": self.limitations,
        }
