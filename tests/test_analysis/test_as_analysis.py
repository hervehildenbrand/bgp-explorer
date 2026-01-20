"""Tests for AS analysis module."""

from datetime import UTC, datetime

import pytest

from bgp_explorer.analysis.as_analysis import ASAnalyzer
from bgp_explorer.models.route import BGPRoute


class TestASAnalyzer:
    """Tests for ASAnalyzer."""

    @pytest.fixture
    def sample_routes(self):
        """Create sample routes for testing."""
        ts = datetime.now(UTC)
        return [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[64496, 3356, 15169],
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.4.0/24",
                origin_asn=15169,
                as_path=[64496, 174, 15169],
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="1.1.1.0/24",
                origin_asn=13335,
                as_path=[64496, 3356, 13335],
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
        ]

    def test_get_asn_neighbors(self, sample_routes):
        """Test finding ASN neighbors from paths."""
        analyzer = ASAnalyzer()
        neighbors = analyzer.get_asn_neighbors(sample_routes, 3356)

        # 3356 appears next to 64496 and 15169/13335
        assert 64496 in neighbors
        assert 15169 in neighbors or 13335 in neighbors

    def test_get_asn_position_stats(self, sample_routes):
        """Test calculating ASN position statistics."""
        analyzer = ASAnalyzer()
        stats = analyzer.get_asn_position_stats(sample_routes, 3356)

        assert stats["appearances"] > 0
        assert "avg_position" in stats
        assert "as_origin" in stats
        assert "as_transit" in stats

    def test_infer_relationship_customer_provider(self):
        """Test inferring customer-provider relationship."""
        analyzer = ASAnalyzer()

        # Typical customer-provider: small AS via large transit
        paths = [
            [64496, 3356, 15169],  # 64496 -> 3356 -> 15169
            [64497, 3356, 15169],  # 64497 -> 3356 -> 15169
        ]

        # 3356 (Level3) is likely provider to smaller ASNs
        relationship = analyzer.infer_relationship(3356, 64496, paths)
        assert relationship in ("provider", "peer", "unknown")

    def test_get_asn_prefixes(self, sample_routes):
        """Test extracting prefixes originated by an ASN."""
        analyzer = ASAnalyzer()
        prefixes = analyzer.get_asn_prefixes(sample_routes, 15169)

        assert "8.8.8.0/24" in prefixes
        assert "8.8.4.0/24" in prefixes
        assert "1.1.1.0/24" not in prefixes  # This is 13335

    def test_get_upstream_providers(self, sample_routes):
        """Test identifying upstream providers for an ASN."""
        analyzer = ASAnalyzer()
        upstreams = analyzer.get_upstream_providers(sample_routes, 15169)

        # Upstreams of 15169 in these paths are 3356 and 174
        assert 3356 in upstreams or 174 in upstreams

    def test_get_downstream_customers(self, sample_routes):
        """Test identifying downstream customers for an ASN."""
        analyzer = ASAnalyzer()
        # 3356 has downstream customers in these paths
        downstreams = analyzer.get_downstream_customers(sample_routes, 3356)

        # 15169 and 13335 are downstream of 3356
        assert 15169 in downstreams or 13335 in downstreams

    def test_count_asn_appearances(self, sample_routes):
        """Test counting ASN appearances in paths."""
        analyzer = ASAnalyzer()

        count_3356 = analyzer.count_asn_appearances(sample_routes, 3356)
        count_15169 = analyzer.count_asn_appearances(sample_routes, 15169)

        assert count_3356 == 2  # Appears in 2 paths
        assert count_15169 == 2  # Appears as origin in 2 routes

    def test_get_asn_summary(self, sample_routes):
        """Test generating ASN summary."""
        analyzer = ASAnalyzer()
        summary = analyzer.get_asn_summary(sample_routes, 15169)

        assert "asn" in summary
        assert summary["asn"] == 15169
        assert "prefixes" in summary
        assert "upstream_asns" in summary
        assert "appearances" in summary

    def test_empty_routes(self):
        """Test handling empty route list."""
        analyzer = ASAnalyzer()

        assert analyzer.get_asn_prefixes([], 15169) == set()
        assert analyzer.get_asn_neighbors([], 15169) == set()
        assert analyzer.count_asn_appearances([], 15169) == 0

    def test_asn_not_in_paths(self, sample_routes):
        """Test handling ASN not present in any path."""
        analyzer = ASAnalyzer()

        prefixes = analyzer.get_asn_prefixes(sample_routes, 99999)
        neighbors = analyzer.get_asn_neighbors(sample_routes, 99999)

        assert prefixes == set()
        assert neighbors == set()
