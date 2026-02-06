"""Network resilience assessment module.

Provides tools to assess network resilience and diversity for an ASN,
producing a score (1-10) plus detailed report with recommendations.
"""

from dataclasses import dataclass

from bgp_explorer.data.ddos_providers import find_ddos_provider
from bgp_explorer.models.as_relationship import ASRelationship
from bgp_explorer.models.ixp import IXPPresence


@dataclass
class ResilienceReport:
    """Report of network resilience assessment.

    Contains the overall score, component scores, and recommendations
    for improving network resilience.
    """

    asn: int
    score: float  # 1-10 scale

    # Component scores (0-1 scale)
    transit_score: float
    peering_score: float
    ixp_score: float
    path_redundancy_score: float

    # Counts
    upstream_count: int
    peer_count: int
    ixp_count: int

    # Details
    upstreams: list[str]
    ixps: list[str]

    # Issues and recommendations
    issues: list[str]
    recommendations: list[str]

    # Flags
    single_transit: bool
    ddos_provider_detected: str | None


# Scoring weights (must sum to 1.0)
WEIGHT_TRANSIT = 0.30  # Transit diversity
WEIGHT_PEERING = 0.25  # Peering breadth
WEIGHT_IXP = 0.20  # IXP presence
WEIGHT_PATH_REDUNDANCY = 0.25  # Path redundancy

# Thresholds for scoring
MIN_UPSTREAMS_REQUIRED = 2
OPTIMAL_UPSTREAMS = 3
OPTIMAL_PEER_COUNT = 100  # 100+ peers is excellent
OPTIMAL_IXP_COUNT = 5  # 5+ IXPs is excellent

# Score cap when critical issues are present
CAPPED_MAX_SCORE = 5.0


class ResilienceAssessor:
    """Assessor for network resilience and diversity.

    Evaluates an ASN's resilience based on:
    - Transit diversity: Number of upstream providers
    - Peering breadth: Total peer count
    - IXP presence: Number of IXPs (geographic diversity)
    - Path redundancy: Distinct AS paths from collectors

    Scoring Model:
    | Dimension        | Weight | Criteria                                    |
    |------------------|--------|---------------------------------------------|
    | Transit Diversity| 30%    | Upstream count (min 2 required, 3+ optimal) |
    | Peering Breadth  | 25%    | Total peer count (more = better DDoS absorb)|
    | IXP Presence     | 20%    | Number of IXPs (geographic diversity)       |
    | Path Redundancy  | 25%    | Distinct AS paths from collectors           |

    Score capped at 5 if:
    - Single transit provider
    - Always-on DDoS provider detected in upstream path
    """

    def _score_transit(
        self,
        upstreams: list[ASRelationship],
        peer_count: int = 0,
        downstream_count: int = 0,
    ) -> tuple[float, list[str]]:
        """Score transit diversity.

        Args:
            upstreams: List of upstream provider relationships.
            peer_count: Number of peers (used for Tier 1 detection).
            downstream_count: Number of downstreams (used for Tier 1 detection).

        Returns:
            Tuple of (score 0-1, list of issues).
        """
        issues: list[str] = []
        upstream_count = len(upstreams)

        if upstream_count == 0:
            # Tier 1 / transit-free networks have no upstreams by definition
            if peer_count >= 100 and downstream_count >= 100:
                issues.append(
                    "Transit-free network (Tier 1) - no upstream providers needed"
                )
                return 1.0, issues
            issues.append(
                "No transit providers detected - network may be Tier 1 or data incomplete"
            )
            return 0.0, issues

        if upstream_count == 1:
            issues.append("Single transit provider - critical single point of failure")
            return 0.2, issues  # Very poor score

        if upstream_count == 2:
            issues.append("Only 2 transit providers - consider adding a third for redundancy")
            return 0.6, issues

        # 3+ upstreams is good
        if upstream_count >= OPTIMAL_UPSTREAMS:
            # Scale from 0.8 to 1.0 based on additional upstreams
            score = min(1.0, 0.8 + (upstream_count - OPTIMAL_UPSTREAMS) * 0.05)
            return score, issues

        return 0.7, issues

    def _score_peering(self, peers: list[ASRelationship]) -> tuple[float, int]:
        """Score peering breadth.

        Args:
            peers: List of peer relationships.

        Returns:
            Tuple of (score 0-1, peer count).
        """
        peer_count = len(peers)

        if peer_count == 0:
            return 0.0, peer_count

        # Linear scaling up to OPTIMAL_PEER_COUNT
        score = min(1.0, peer_count / OPTIMAL_PEER_COUNT)
        return score, peer_count

    def _score_ixp(self, ixps: list[IXPPresence]) -> tuple[float, list[str]]:
        """Score IXP presence.

        Args:
            ixps: List of IXP presence records.

        Returns:
            Tuple of (score 0-1, list of IXP names).
        """
        ixp_count = len(ixps)
        ixp_names = [ixp.ixp_name for ixp in ixps]

        if ixp_count == 0:
            return 0.0, ixp_names

        # Linear scaling up to OPTIMAL_IXP_COUNT
        score = min(1.0, ixp_count / OPTIMAL_IXP_COUNT)
        return score, ixp_names

    def _detect_ddos_provider(self, upstreams: list[ASRelationship]) -> str | None:
        """Detect if a DDoS protection provider is in the upstream path.

        Args:
            upstreams: List of upstream provider relationships.

        Returns:
            Provider name if detected, None otherwise.
        """
        for upstream in upstreams:
            provider = find_ddos_provider(upstream.asn2)
            if provider:
                return provider
        return None

    def _calculate_final_score(
        self,
        scores: dict[str, float],
        flags: dict[str, bool | str | None],
    ) -> float:
        """Calculate the final resilience score.

        Args:
            scores: Component scores (transit, peering, ixp, path_redundancy).
            flags: Flags for single_transit and ddos_provider.

        Returns:
            Final score on 1-10 scale.
        """
        # Calculate weighted score
        weighted_score = (
            scores["transit"] * WEIGHT_TRANSIT
            + scores["peering"] * WEIGHT_PEERING
            + scores["ixp"] * WEIGHT_IXP
            + scores["path_redundancy"] * WEIGHT_PATH_REDUNDANCY
        )

        # Convert to 1-10 scale
        final_score = weighted_score * 10

        # Cap score if critical issues present
        if flags.get("single_transit"):
            final_score = min(final_score, CAPPED_MAX_SCORE)

        if flags.get("ddos_provider"):
            final_score = min(final_score, CAPPED_MAX_SCORE)

        # Ensure minimum score of 1
        return max(1.0, final_score)

    def _generate_recommendations(
        self,
        report: ResilienceReport,
    ) -> list[str]:
        """Generate recommendations based on assessment.

        Args:
            report: The resilience report with scores and issues.

        Returns:
            List of recommendations.
        """
        recommendations: list[str] = []

        if report.single_transit:
            recommendations.append(
                "CRITICAL: Add at least one more transit provider to eliminate single point of failure"
            )
        elif report.upstream_count == 2:
            recommendations.append(
                "Consider adding a third transit provider for improved redundancy"
            )

        if report.peer_count < 20:
            recommendations.append(
                "Increase peering to improve DDoS absorption capacity and reduce transit costs"
            )
        elif report.peer_count < 50:
            recommendations.append(
                "Consider expanding peering relationships for better traffic optimization"
            )

        if report.ixp_count == 0:
            recommendations.append(
                "Join at least one IXP for improved connectivity and reduced latency"
            )
        elif report.ixp_count < 3:
            recommendations.append("Expand IXP presence for better geographic diversity")

        if report.ddos_provider_detected:
            recommendations.append(
                f"Note: {report.ddos_provider_detected} detected in upstream path - "
                "ensure you have direct paths available as backup"
            )

        is_transit_free = any("transit-free" in issue.lower() for issue in report.issues)
        if report.path_redundancy_score < 0.5 and not is_transit_free:
            recommendations.append(
                "Low path diversity observed - ensure multiple upstream paths are advertised"
            )

        return recommendations

    def format_report(self, report: ResilienceReport) -> str:
        """Format resilience report as human-readable text.

        Args:
            report: The resilience report to format.

        Returns:
            Formatted report string.
        """
        # Score emoji based on level
        if report.score >= 8:
            score_emoji = "🟢"
            score_label = "Excellent"
        elif report.score >= 6:
            score_emoji = "🟡"
            score_label = "Good"
        elif report.score >= 4:
            score_emoji = "🟠"
            score_label = "Fair"
        else:
            score_emoji = "🔴"
            score_label = "Poor"

        lines = [
            f"**Network Resilience Assessment: AS{report.asn}**",
            "",
            f"**Overall Score:** {score_emoji} {report.score:.1f}/10 ({score_label})",
            "",
        ]

        # Cap warning
        if report.single_transit or report.ddos_provider_detected:
            cap_reasons = []
            if report.single_transit:
                cap_reasons.append("single transit provider")
            if report.ddos_provider_detected:
                cap_reasons.append(f"DDoS provider ({report.ddos_provider_detected}) in path")
            lines.append(f"⚠️ **Score capped at 5** due to: {', '.join(cap_reasons)}")
            lines.append("")

        # Component scores
        lines.extend(
            [
                "**Component Scores:**",
                f"  - Transit Diversity: {report.transit_score * 100:.0f}% ({report.upstream_count} upstreams)",
                f"  - Peering Breadth: {report.peering_score * 100:.0f}% ({report.peer_count} peers)",
                f"  - IXP Presence: {report.ixp_score * 100:.0f}% ({report.ixp_count} IXPs)",
                f"  - Path Redundancy: {report.path_redundancy_score * 100:.0f}%",
                "",
            ]
        )

        # Upstreams
        if report.upstreams:
            lines.append("**Transit Providers:**")
            for upstream in report.upstreams[:5]:
                lines.append(f"  - {upstream}")
            if len(report.upstreams) > 5:
                lines.append(f"  ... and {len(report.upstreams) - 5} more")
            lines.append("")

        # IXPs
        if report.ixps:
            lines.append("**IXP Presence:**")
            for ixp in report.ixps[:10]:
                lines.append(f"  - {ixp}")
            if len(report.ixps) > 10:
                lines.append(f"  ... and {len(report.ixps) - 10} more")
            lines.append("")

        # Issues
        if report.issues:
            lines.append("**Issues:**")
            for issue in report.issues:
                lines.append(f"  ⚠️ {issue}")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("**Recommendations:**")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {i}. {rec}")

        return "\n".join(lines)
