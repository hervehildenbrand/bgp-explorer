"""MANRS readiness assessment module.

Evaluates MANRS (Mutually Agreed Norms for Routing Security) readiness
using locally available data sources. Does NOT require the MANRS API.

The 4 MANRS Actions for network operators:
1. Filtering: Preventing propagation of incorrect routing info
2. Anti-Spoofing: Preventing traffic with spoofed source IPs
3. Coordination: Maintaining up-to-date contact info
4. Global Validation: Publicly documenting routing policy (RPKI/IRR)
"""

from __future__ import annotations

from datetime import UTC, datetime

from bgp_explorer.analysis.rov_coverage import ROVCoverageReport
from bgp_explorer.models.manrs import (
    MANRSAction,
    MANRSActionFinding,
    MANRSReadiness,
    MANRSReadinessReport,
)

# Scoring weights per action
ACTION_WEIGHTS: dict[MANRSAction, float] = {
    MANRSAction.FILTERING: 0.30,
    MANRSAction.ANTI_SPOOFING: 0.10,  # Low weight: unmeasurable externally
    MANRSAction.COORDINATION: 0.25,
    MANRSAction.VALIDATION: 0.35,
}

READINESS_SCORES: dict[MANRSReadiness, float] = {
    MANRSReadiness.READY: 100.0,
    MANRSReadiness.ASPIRING: 60.0,
    MANRSReadiness.LAGGING: 20.0,
    MANRSReadiness.UNKNOWN: 50.0,  # Neutral for unmeasurable
}


def _has_contacts(data: dict | None) -> bool:
    """Check if contact data contains any actual contact info."""
    if not data:
        return False
    for _key, value in data.items():
        if value and isinstance(value, str) and "@" in value:
            return True
        if value and isinstance(value, list) and any(v for v in value):
            return True
    return False


class MANRSReadinessAssessor:
    """Assess MANRS readiness using local data sources.

    Receives pre-computed data from existing analyzers and evaluates
    each of the 4 MANRS Actions. Does NOT call external APIs directly.
    """

    def assess(
        self,
        asn: int,
        rpki_coverage: float | None = None,
        has_aspa: bool | None = None,
        whois_data: dict | None = None,
        contacts: dict | None = None,
        rov_report: ROVCoverageReport | None = None,
    ) -> MANRSReadinessReport:
        """Run MANRS readiness assessment."""
        findings = [
            self._assess_filtering(rpki_coverage, rov_report),
            self._assess_anti_spoofing(),
            self._assess_coordination(contacts, whois_data),
            self._assess_validation(rpki_coverage, has_aspa),
        ]
        return self._build_report(asn, findings)

    def _assess_filtering(
        self,
        rpki_coverage: float | None,
        rov_report: ROVCoverageReport | None,
    ) -> MANRSActionFinding:
        """Action 1: Filtering — proxy via ROV coverage."""
        evidence: list[str] = []
        recommendations: list[str] = []
        data_sources: list[str] = []

        if rpki_coverage is not None:
            evidence.append(f"ROA coverage: {rpki_coverage:.0%}")
            data_sources.append("rpki_validation")
        if rov_report is not None:
            evidence.append(
                f"ROV path coverage: {rov_report.path_coverage:.0%} ({rov_report.protection_level})"
            )
            data_sources.append("rov_coverage")

        if rpki_coverage is None and rov_report is None:
            readiness = MANRSReadiness.UNKNOWN
            recommendations.append("Run RPKI validation to assess filtering readiness")
        elif (
            rpki_coverage is not None
            and rpki_coverage >= 0.9
            and rov_report is not None
            and rov_report.protection_level == "high"
        ):
            readiness = MANRSReadiness.READY
        elif (rpki_coverage is not None and rpki_coverage >= 0.7) or (
            rov_report is not None and rov_report.protection_level == "medium"
        ):
            readiness = MANRSReadiness.ASPIRING
            if rpki_coverage is not None and rpki_coverage < 0.9:
                recommendations.append("Increase ROA coverage to 90%+")
        else:
            readiness = MANRSReadiness.LAGGING
            recommendations.append("Deploy RPKI ROAs for all announced prefixes")
            recommendations.append("Encourage upstreams to enforce ROV filtering")

        return MANRSActionFinding(
            action=MANRSAction.FILTERING,
            readiness=readiness,
            evidence=evidence,
            measurable=True,
            recommendations=recommendations,
            data_sources_used=data_sources,
        )

    def _assess_anti_spoofing(self) -> MANRSActionFinding:
        """Action 2: Anti-Spoofing — cannot be verified externally."""
        return MANRSActionFinding(
            action=MANRSAction.ANTI_SPOOFING,
            readiness=MANRSReadiness.UNKNOWN,
            evidence=[],
            measurable=False,
            recommendations=[
                "Self-verify BCP38/uRPF implementation on all customer-facing interfaces",
                "Test with CAIDA Spoofer project (https://spoofer.caida.org/)",
            ],
            data_sources_used=[],
        )

    def _assess_coordination(
        self,
        contacts: dict | None,
        whois_data: dict | None,
    ) -> MANRSActionFinding:
        """Action 3: Coordination — contact availability."""
        evidence: list[str] = []
        recommendations: list[str] = []
        data_sources: list[str] = []

        has_peeringdb = _has_contacts(contacts)
        has_whois = _has_contacts(whois_data)

        if has_peeringdb:
            evidence.append("PeeringDB contacts available")
            data_sources.append("peeringdb")
        if has_whois:
            evidence.append("WHOIS abuse contact available")
            data_sources.append("whois")

        if has_peeringdb and has_whois:
            readiness = MANRSReadiness.READY
        elif has_peeringdb or has_whois:
            readiness = MANRSReadiness.ASPIRING
            if not has_peeringdb:
                recommendations.append("Register NOC contacts in PeeringDB")
            if not has_whois:
                recommendations.append("Ensure abuse contact is in WHOIS/RIR database")
        else:
            readiness = MANRSReadiness.LAGGING
            recommendations.append("Register NOC contacts in PeeringDB")
            recommendations.append("Register abuse contact in WHOIS/RIR database")

        return MANRSActionFinding(
            action=MANRSAction.COORDINATION,
            readiness=readiness,
            evidence=evidence,
            measurable=True,
            recommendations=recommendations,
            data_sources_used=data_sources,
        )

    def _assess_validation(
        self,
        rpki_coverage: float | None,
        has_aspa: bool | None,
    ) -> MANRSActionFinding:
        """Action 4: Global Validation — RPKI ROA/ASPA deployment."""
        evidence: list[str] = []
        recommendations: list[str] = []
        data_sources: list[str] = []

        if rpki_coverage is not None:
            evidence.append(f"ROA coverage: {rpki_coverage:.0%}")
            data_sources.append("rpki_validation")
        if has_aspa is not None:
            evidence.append(f"ASPA published: {'yes' if has_aspa else 'no'}")
            data_sources.append("rpki_aspa")

        if rpki_coverage is None:
            readiness = MANRSReadiness.UNKNOWN
            recommendations.append("Run RPKI validation to assess deployment")
        elif rpki_coverage >= 0.9 and has_aspa:
            readiness = MANRSReadiness.READY
        elif rpki_coverage >= 0.7 or (rpki_coverage >= 0.9 and not has_aspa):
            readiness = MANRSReadiness.ASPIRING
            if rpki_coverage < 0.9:
                recommendations.append("Increase ROA coverage to 90%+")
            if not has_aspa:
                recommendations.append(
                    "Publish ASPA object at your RIR portal for route leak protection"
                )
        else:
            readiness = MANRSReadiness.LAGGING
            recommendations.append("Create RPKI ROAs for all announced prefixes")
            if not has_aspa:
                recommendations.append("Publish ASPA object for route leak protection")

        return MANRSActionFinding(
            action=MANRSAction.VALIDATION,
            readiness=readiness,
            evidence=evidence,
            measurable=True,
            recommendations=recommendations,
            data_sources_used=data_sources,
        )

    def _build_report(
        self,
        asn: int,
        findings: list[MANRSActionFinding],
    ) -> MANRSReadinessReport:
        """Build the overall readiness report from per-action findings."""
        total_score = sum(
            ACTION_WEIGHTS[f.action] * READINESS_SCORES[f.readiness] for f in findings
        )

        if total_score >= 80:
            overall = MANRSReadiness.READY
        elif total_score >= 55:
            overall = MANRSReadiness.ASPIRING
        else:
            overall = MANRSReadiness.LAGGING

        if all(f.readiness == MANRSReadiness.UNKNOWN for f in findings):
            overall = MANRSReadiness.UNKNOWN

        action_summaries = []
        for f in findings:
            action_summaries.append(f"{f.action.value}: {f.readiness.value}")
        summary = (
            f"MANRS readiness for AS{asn}: {overall.value.upper()} "
            f"(score: {total_score:.0f}/100). " + ", ".join(action_summaries)
        )

        limitations = [
            "Anti-spoofing (Action 2) cannot be verified externally — "
            "requires self-assessment or active probing",
            "Filtering (Action 1) assessed via ROV coverage proxy, "
            "not direct ingress filter verification",
        ]

        return MANRSReadinessReport(
            asn=asn,
            timestamp=datetime.now(UTC).isoformat(),
            overall_readiness=overall,
            overall_score=total_score,
            action_findings=findings,
            summary=summary,
            limitations=limitations,
        )

    def format_report(self, report: MANRSReadinessReport) -> str:
        """Format a readiness report as human-readable text."""
        lines = [
            f"**MANRS Readiness Assessment: AS{report.asn}**",
            f"Timestamp: {report.timestamp}",
            "",
            f"**Overall Readiness:** {report.overall_readiness.value.upper()} "
            f"(Score: {report.overall_score:.0f}/100)",
            "",
        ]

        action_names = {
            MANRSAction.FILTERING: "Action 1: Filtering",
            MANRSAction.ANTI_SPOOFING: "Action 2: Anti-Spoofing",
            MANRSAction.COORDINATION: "Action 3: Coordination",
            MANRSAction.VALIDATION: "Action 4: Global Validation",
        }

        for finding in report.action_findings:
            name = action_names.get(finding.action, finding.action.value)
            measurable_note = "" if finding.measurable else " (cannot verify externally)"
            lines.append(f"### {name}: {finding.readiness.value.upper()}{measurable_note}")
            for e in finding.evidence:
                lines.append(f"  - {e}")
            for r in finding.recommendations:
                lines.append(f"  RECOMMENDATION: {r}")
            lines.append("")

        if report.limitations:
            lines.append("### Limitations")
            for limitation in report.limitations:
                lines.append(f"  - {limitation}")
            lines.append("")

        lines.append(f"**Summary:** {report.summary}")
        return "\n".join(lines)
