"""Tests for path analysis module."""

from datetime import UTC, datetime

import pytest

from bgp_explorer.analysis.path_analysis import PathAnalyzer
from bgp_explorer.models.route import BGPRoute


class TestPathAnalyzer:
    """Tests for PathAnalyzer."""

    @pytest.fixture
    def sample_routes(self):
        """Create sample routes for testing."""
        ts = datetime.now(UTC)
        return [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[174, 3356, 15169],
                collector="rrc01",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[2914, 15169],
                collector="rrc21",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[6939, 15169],
                collector="rrc03",
                timestamp=ts,
                source="ripe_stat",
            ),
        ]

    def test_get_unique_paths(self, sample_routes):
        """Test extracting unique AS paths."""
        analyzer = PathAnalyzer()
        unique_paths = analyzer.get_unique_paths(sample_routes)

        assert len(unique_paths) == 4
        assert (3356, 15169) in unique_paths
        assert (174, 3356, 15169) in unique_paths

    def test_get_origin_asns(self, sample_routes):
        """Test extracting origin ASNs."""
        analyzer = PathAnalyzer()
        origins = analyzer.get_origin_asns(sample_routes)

        assert len(origins) == 1
        assert 15169 in origins

    def test_get_path_diversity(self, sample_routes):
        """Test calculating path diversity metrics."""
        analyzer = PathAnalyzer()
        diversity = analyzer.get_path_diversity(sample_routes)

        assert diversity["unique_paths"] == 4
        assert diversity["unique_origins"] == 1
        assert diversity["collectors"] == 4
        assert diversity["min_path_length"] == 2
        assert diversity["max_path_length"] == 3
        assert diversity["avg_path_length"] == 2.25

    def test_get_upstream_asns(self, sample_routes):
        """Test extracting upstream ASNs (first hop after origin)."""
        analyzer = PathAnalyzer()
        upstreams = analyzer.get_upstream_asns(sample_routes)

        # Upstreams should be the ASNs that directly connect to origin
        # In paths like [3356, 15169], upstream of 15169 is 3356
        assert 3356 in upstreams
        assert 2914 in upstreams
        assert 6939 in upstreams

    def test_detect_path_changes(self):
        """Test detecting path changes between two route sets."""
        ts1 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
        ts2 = datetime(2024, 1, 1, 13, 0, tzinfo=UTC)

        old_routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=ts1,
                source="ripe_stat",
            ),
        ]
        new_routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[174, 15169],  # Path changed
                collector="rrc00",
                timestamp=ts2,
                source="ripe_stat",
            ),
        ]

        analyzer = PathAnalyzer()
        changes = analyzer.detect_path_changes(old_routes, new_routes)

        assert len(changes) > 0
        assert any(c["type"] == "path_change" for c in changes)

    def test_detect_origin_change(self):
        """Test detecting origin ASN changes."""
        ts1 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
        ts2 = datetime(2024, 1, 1, 13, 0, tzinfo=UTC)

        old_routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64496,
                as_path=[3356, 64496],
                collector="rrc00",
                timestamp=ts1,
                source="ripe_stat",
            ),
        ]
        new_routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64497,  # Origin changed - possible hijack!
                as_path=[3356, 64497],
                collector="rrc00",
                timestamp=ts2,
                source="ripe_stat",
            ),
        ]

        analyzer = PathAnalyzer()
        changes = analyzer.detect_path_changes(old_routes, new_routes)

        assert any(c["type"] == "origin_change" for c in changes)

    def test_get_transit_asns(self, sample_routes):
        """Test extracting transit ASNs (middle of path)."""
        analyzer = PathAnalyzer()
        transits = analyzer.get_transit_asns(sample_routes)

        # In path [174, 3356, 15169], 3356 is transit
        assert 3356 in transits

    def test_empty_routes(self):
        """Test handling of empty route list."""
        analyzer = PathAnalyzer()

        assert analyzer.get_unique_paths([]) == set()
        assert analyzer.get_origin_asns([]) == set()
        assert analyzer.get_path_diversity([])["unique_paths"] == 0

    def test_single_asn_path(self):
        """Test handling routes with single ASN path."""
        route = BGPRoute(
            prefix="10.0.0.0/8",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        analyzer = PathAnalyzer()

        diversity = analyzer.get_path_diversity([route])
        assert diversity["min_path_length"] == 1
        assert diversity["max_path_length"] == 1
