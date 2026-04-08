"""Tests for ROV coverage analysis.

Tests ROV enforcer data and coverage analysis functionality.
"""

from datetime import UTC, datetime

from bgp_explorer.analysis.rov_coverage import ROVCoverageAnalyzer, ROVCoverageReport
from bgp_explorer.data.rov_enforcers import (
    MAJOR_ROV_ENFORCERS,
    TIER1_ROV_ENFORCERS,
    get_rov_enforcer_info,
    is_known_rov_enforcer,
)
from bgp_explorer.models.route import BGPRoute


def make_route(prefix: str, as_path: list[int], collector: str = "rrc00") -> BGPRoute:
    """Helper to create a BGPRoute for testing."""
    return BGPRoute(
        prefix=prefix,
        origin_asn=as_path[-1] if as_path else 0,
        as_path=as_path,
        collector=collector,
        timestamp=datetime(2024, 1, 1, tzinfo=UTC),
        source="ripe_stat",
    )


# --- Tests for rov_enforcers module ---


class TestIsKnownRovEnforcer:
    """Tests for is_known_rov_enforcer function."""

    def test_is_known_rov_enforcer_tier1(self) -> None:
        """Test that Tier-1 ROV enforcer is recognized."""
        assert is_known_rov_enforcer(3356) is True  # Lumen/Level3

    def test_is_known_rov_enforcer_major(self) -> None:
        """Test that major ROV enforcer is recognized."""
        assert is_known_rov_enforcer(15169) is True  # Google

    def test_is_not_rov_enforcer(self) -> None:
        """Test that unknown ASN is not recognized as ROV enforcer."""
        assert is_known_rov_enforcer(64496) is False  # Private use ASN


class TestGetRovEnforcerInfo:
    """Tests for get_rov_enforcer_info function."""

    def test_get_rov_enforcer_info_tier1(self) -> None:
        """Test getting info for Tier-1 ROV enforcer."""
        info = get_rov_enforcer_info(3356)
        assert info is not None
        assert info["asn"] == 3356
        assert info["name"] == "Lumen/Level3"
        assert info["category"] == "tier1"

    def test_get_rov_enforcer_info_major(self) -> None:
        """Test getting info for major ROV enforcer."""
        info = get_rov_enforcer_info(15169)
        assert info is not None
        assert info["asn"] == 15169
        assert info["name"] == "Google"
        assert info["category"] == "major"

    def test_get_rov_enforcer_info_none(self) -> None:
        """Test that unknown ASN returns None."""
        info = get_rov_enforcer_info(64496)
        assert info is None


class TestRovEnforcerDataIntegrity:
    """Tests to ensure ROV enforcer data integrity."""

    def test_tier1_has_expected_count(self) -> None:
        """Test that TIER1_ROV_ENFORCERS has 15 entries."""
        assert len(TIER1_ROV_ENFORCERS) == 15

    def test_major_has_expected_count(self) -> None:
        """Test that MAJOR_ROV_ENFORCERS has approximately 50 entries."""
        assert len(MAJOR_ROV_ENFORCERS) >= 40  # Allow some flexibility

    def test_no_overlap_between_tier1_and_major(self) -> None:
        """Test that there's no overlap between tier1 and major lists."""
        tier1_asns = set(TIER1_ROV_ENFORCERS.keys())
        major_asns = set(MAJOR_ROV_ENFORCERS.keys())
        overlap = tier1_asns & major_asns
        assert len(overlap) == 0, f"Overlap found: {overlap}"


# --- Tests for ROVCoverageAnalyzer ---


class TestCheckPathForRov:
    """Tests for _check_path_for_rov method."""

    def test_check_path_for_rov_found(self) -> None:
        """Test that ROV enforcer is found in path."""
        analyzer = ROVCoverageAnalyzer()
        has_enforcer, enforcers = analyzer._check_path_for_rov([64496, 3356, 15169])
        assert has_enforcer is True
        assert len(enforcers) >= 1  # Should find at least one enforcer

    def test_check_path_for_rov_not_found(self) -> None:
        """Test that no ROV enforcer is found in path without enforcers."""
        analyzer = ROVCoverageAnalyzer()
        has_enforcer, enforcers = analyzer._check_path_for_rov([64496, 64497])
        assert has_enforcer is False
        assert len(enforcers) == 0

    def test_check_path_for_rov_empty_path(self) -> None:
        """Test handling of empty AS path."""
        analyzer = ROVCoverageAnalyzer()
        has_enforcer, enforcers = analyzer._check_path_for_rov([])
        assert has_enforcer is False
        assert len(enforcers) == 0


class TestCalculateProtectionLevel:
    """Tests for _calculate_protection_level method."""

    def test_protection_level_high(self) -> None:
        """Test that high coverage results in 'high' protection level."""
        analyzer = ROVCoverageAnalyzer()
        level = analyzer._calculate_protection_level(0.9, 0.7)
        assert level == "high"

    def test_protection_level_high_boundary(self) -> None:
        """Test boundary conditions for 'high' protection level."""
        analyzer = ROVCoverageAnalyzer()
        # Exactly at boundary
        level = analyzer._calculate_protection_level(0.8, 0.6)
        assert level == "high"

    def test_protection_level_medium(self) -> None:
        """Test that medium coverage results in 'medium' protection level."""
        analyzer = ROVCoverageAnalyzer()
        level = analyzer._calculate_protection_level(0.6, 0.3)
        assert level == "medium"

    def test_protection_level_medium_boundary(self) -> None:
        """Test boundary conditions for 'medium' protection level."""
        analyzer = ROVCoverageAnalyzer()
        # Exactly at boundary
        level = analyzer._calculate_protection_level(0.5, 0.1)
        assert level == "medium"

    def test_protection_level_low(self) -> None:
        """Test that low coverage results in 'low' protection level."""
        analyzer = ROVCoverageAnalyzer()
        level = analyzer._calculate_protection_level(0.3, 0.1)
        assert level == "low"

    def test_protection_level_low_zero(self) -> None:
        """Test that zero coverage results in 'low' protection level."""
        analyzer = ROVCoverageAnalyzer()
        level = analyzer._calculate_protection_level(0.0, 0.0)
        assert level == "low"

    def test_protection_level_high_path_low_tier1(self) -> None:
        """Test high path coverage but low tier1 coverage is medium."""
        analyzer = ROVCoverageAnalyzer()
        # High path coverage (0.85) but low tier1 (0.4) should be medium
        level = analyzer._calculate_protection_level(0.85, 0.4)
        assert level == "medium"


class TestAnalyzePrefixCoverage:
    """Tests for analyze_prefix_coverage method."""

    def test_all_paths_have_rov_enforcer(self) -> None:
        """Test routes all through ROV enforcers result in high coverage."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 3356, 12345]),  # Through Lumen (Tier-1)
            make_route("192.0.2.0/24", [64497, 2914, 12345]),  # Through NTT (Tier-1)
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.total_paths == 2
        assert report.paths_with_rov_enforcer == 2
        assert report.path_coverage == 1.0
        assert report.tier1_coverage == 1.0
        assert report.protection_level == "high"

    def test_no_rov_enforcers_in_paths(self) -> None:
        """Test routes without ROV enforcers result in low coverage."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 64497, 12345]),
            make_route("192.0.2.0/24", [64498, 64499, 12345]),
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.total_paths == 2
        assert report.paths_with_rov_enforcer == 0
        assert report.path_coverage == 0.0
        assert report.tier1_coverage == 0.0
        assert report.protection_level == "low"

    def test_mixed_coverage(self) -> None:
        """Test mixed routes result in medium coverage."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 3356, 12345]),  # Through Tier-1
            make_route("192.0.2.0/24", [64497, 64498, 12345]),  # No enforcer
            make_route("192.0.2.0/24", [64499, 2914, 12345]),  # Through Tier-1
            make_route("192.0.2.0/24", [64500, 64501, 12345]),  # No enforcer
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.total_paths == 4
        assert report.paths_with_rov_enforcer == 2
        assert report.path_coverage == 0.5
        assert report.protection_level == "medium"

    def test_tier1_vs_major_coverage(self) -> None:
        """Test routes through major (not Tier-1) show different coverage."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 15169, 12345]),  # Through Google (major)
            make_route("192.0.2.0/24", [64497, 13335, 12345]),  # Through Cloudflare (major)
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.total_paths == 2
        assert report.paths_with_rov_enforcer == 2
        assert report.path_coverage == 1.0
        assert report.tier1_coverage == 0.0  # No Tier-1 in paths
        assert report.protection_level == "medium"  # High path but no tier1

    def test_empty_routes(self) -> None:
        """Test empty routes list results in zero coverage and low protection."""
        analyzer = ROVCoverageAnalyzer()
        routes: list[BGPRoute] = []
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.total_paths == 0
        assert report.paths_with_rov_enforcer == 0
        assert report.path_coverage == 0.0
        assert report.tier1_coverage == 0.0
        assert report.protection_level == "low"
        assert "no routes" in report.summary.lower() or "0 routes" in report.summary.lower()

    def test_rov_enforcers_in_paths_tracking(self) -> None:
        """Test that ROV enforcers are tracked with correct path counts."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 3356, 12345], "rrc00"),  # Through Lumen
            make_route("192.0.2.0/24", [64497, 3356, 12345], "rrc01"),  # Through Lumen again
            make_route("192.0.2.0/24", [64498, 2914, 12345], "rrc02"),  # Through NTT
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert len(report.rov_enforcers_in_paths) >= 2  # At least Lumen and NTT

        # Find Lumen in the list
        lumen_entry = next((e for e in report.rov_enforcers_in_paths if e["asn"] == 3356), None)
        assert lumen_entry is not None
        assert lumen_entry["path_count"] == 2  # Appears in 2 routes

    def test_report_has_summary(self) -> None:
        """Test that the report includes a summary string."""
        analyzer = ROVCoverageAnalyzer()
        routes = [
            make_route("192.0.2.0/24", [64496, 3356, 12345]),
        ]
        report = analyzer.analyze_prefix_coverage("192.0.2.0/24", routes)

        assert report.summary is not None
        assert len(report.summary) > 0


class TestROVCoverageReportDataclass:
    """Tests for ROVCoverageReport dataclass."""

    def test_report_fields(self) -> None:
        """Test that ROVCoverageReport has all required fields."""
        report = ROVCoverageReport(
            prefix="192.0.2.0/24",
            total_paths=10,
            paths_with_rov_enforcer=8,
            path_coverage=0.8,
            tier1_coverage=0.6,
            protection_level="high",
            rov_enforcers_in_paths=[
                {"asn": 3356, "name": "Lumen/Level3", "category": "tier1", "path_count": 5}
            ],
            summary="Test summary",
        )

        assert report.prefix == "192.0.2.0/24"
        assert report.total_paths == 10
        assert report.paths_with_rov_enforcer == 8
        assert report.path_coverage == 0.8
        assert report.tier1_coverage == 0.6
        assert report.protection_level == "high"
        assert len(report.rov_enforcers_in_paths) == 1
        assert report.summary == "Test summary"
