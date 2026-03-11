"""ROV coverage analysis module.

Provides tools to analyze how well a prefix is protected by ROV-enforcing
networks in the global routing table.
"""

from dataclasses import dataclass

from bgp_explorer.data.rov_enforcers import (
    TIER1_ROV_ENFORCERS,
    get_rov_enforcer_info,
    is_known_rov_enforcer,
)
from bgp_explorer.models.route import BGPRoute


@dataclass
class ROVCoverageReport:
    """Report of ROV coverage analysis for a prefix.

    Contains metrics about how many paths to a prefix pass through
    networks known to enforce ROV filtering.
    """

    prefix: str
    total_paths: int
    paths_with_rov_enforcer: int
    path_coverage: float  # 0.0-1.0, fraction of paths with ROV enforcer
    tier1_coverage: float  # 0.0-1.0, fraction of paths with Tier-1 ROV enforcer
    protection_level: str  # "high", "medium", "low"
    rov_enforcers_in_paths: list[dict]  # [{"asn": int, "name": str, "category": str, "path_count": int}]
    summary: str


class ROVCoverageAnalyzer:
    """Analyzer for ROV coverage of BGP routes.

    Evaluates how many routes to a prefix pass through networks that
    enforce ROV (Route Origin Validation), which provides protection
    against BGP hijacks.
    """

    def analyze_prefix_coverage(
        self, prefix: str, routes: list[BGPRoute]
    ) -> ROVCoverageReport:
        """Analyze ROV coverage for a prefix based on observed routes.

        Args:
            prefix: The IP prefix being analyzed.
            routes: List of BGPRoute objects representing paths to the prefix.

        Returns:
            ROVCoverageReport with coverage metrics and analysis.
        """
        if not routes:
            return ROVCoverageReport(
                prefix=prefix,
                total_paths=0,
                paths_with_rov_enforcer=0,
                path_coverage=0.0,
                tier1_coverage=0.0,
                protection_level="low",
                rov_enforcers_in_paths=[],
                summary=f"No routes found for {prefix}. Unable to assess ROV coverage.",
            )

        total_paths = len(routes)
        paths_with_rov = 0
        paths_with_tier1 = 0
        enforcer_counts: dict[int, int] = {}

        for route in routes:
            has_enforcer, enforcers = self._check_path_for_rov(route.as_path)
            if has_enforcer:
                paths_with_rov += 1

            # Check for Tier-1 specifically
            has_tier1 = any(asn in TIER1_ROV_ENFORCERS for asn in route.as_path)
            if has_tier1:
                paths_with_tier1 += 1

            # Track enforcer counts
            for enforcer in enforcers:
                asn = enforcer["asn"]
                enforcer_counts[asn] = enforcer_counts.get(asn, 0) + 1

        path_coverage = paths_with_rov / total_paths
        tier1_coverage = paths_with_tier1 / total_paths
        protection_level = self._calculate_protection_level(path_coverage, tier1_coverage)

        # Build enforcer list with counts
        rov_enforcers_in_paths = []
        for asn, count in sorted(enforcer_counts.items(), key=lambda x: -x[1]):
            info = get_rov_enforcer_info(asn)
            if info:
                rov_enforcers_in_paths.append({
                    "asn": asn,
                    "name": info["name"],
                    "category": info["category"],
                    "path_count": count,
                })

        # Generate summary
        summary = self._generate_summary(
            prefix, total_paths, paths_with_rov, path_coverage,
            tier1_coverage, protection_level, rov_enforcers_in_paths
        )

        return ROVCoverageReport(
            prefix=prefix,
            total_paths=total_paths,
            paths_with_rov_enforcer=paths_with_rov,
            path_coverage=path_coverage,
            tier1_coverage=tier1_coverage,
            protection_level=protection_level,
            rov_enforcers_in_paths=rov_enforcers_in_paths,
            summary=summary,
        )

    def _check_path_for_rov(self, as_path: list[int]) -> tuple[bool, list[dict]]:
        """Check if an AS path contains any ROV enforcers.

        Args:
            as_path: List of ASNs in the path.

        Returns:
            Tuple of (has_enforcer, list of enforcer info dicts).
        """
        if not as_path:
            return False, []

        enforcers = []
        for asn in as_path:
            if is_known_rov_enforcer(asn):
                info = get_rov_enforcer_info(asn)
                if info:
                    enforcers.append(info)

        has_enforcer = len(enforcers) > 0
        return has_enforcer, enforcers

    def _calculate_protection_level(
        self, path_coverage: float, tier1_coverage: float
    ) -> str:
        """Calculate the protection level based on coverage metrics.

        Args:
            path_coverage: Fraction of paths with any ROV enforcer (0.0-1.0).
            tier1_coverage: Fraction of paths with Tier-1 ROV enforcer (0.0-1.0).

        Returns:
            Protection level: "high", "medium", or "low".
        """
        # High: path_coverage >= 0.8 AND tier1_coverage >= 0.6
        if path_coverage >= 0.8 and tier1_coverage >= 0.6:
            return "high"

        # Medium: path_coverage >= 0.5
        if path_coverage >= 0.5:
            return "medium"

        # Low: everything else
        return "low"

    def _generate_summary(
        self,
        prefix: str,
        total_paths: int,
        paths_with_rov: int,
        path_coverage: float,
        tier1_coverage: float,
        protection_level: str,
        enforcers: list[dict],
    ) -> str:
        """Generate a human-readable summary of the coverage analysis.

        Args:
            prefix: The analyzed prefix.
            total_paths: Total number of routes analyzed.
            paths_with_rov: Number of routes through ROV enforcers.
            path_coverage: Fraction of paths with ROV enforcer.
            tier1_coverage: Fraction of paths with Tier-1 ROV enforcer.
            protection_level: Calculated protection level.
            enforcers: List of enforcer info dicts.

        Returns:
            Summary string.
        """
        coverage_pct = path_coverage * 100
        tier1_pct = tier1_coverage * 100

        if protection_level == "high":
            level_desc = "well-protected"
        elif protection_level == "medium":
            level_desc = "moderately protected"
        else:
            level_desc = "poorly protected"

        summary = (
            f"Prefix {prefix} is {level_desc} by ROV-enforcing networks. "
            f"{paths_with_rov} of {total_paths} paths ({coverage_pct:.0f}%) "
            f"pass through known ROV enforcers. "
            f"Tier-1 coverage: {tier1_pct:.0f}%."
        )

        if enforcers:
            top_enforcers = enforcers[:3]
            names = ", ".join(e["name"] for e in top_enforcers)
            summary += f" Key enforcers: {names}."

        return summary
