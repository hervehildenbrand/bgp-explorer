"""Tests for BGPRoute data model."""

from datetime import UTC, datetime

from bgp_explorer.models.route import BGPRoute


class TestBGPRoute:
    """Tests for BGPRoute dataclass."""

    def test_create_basic_route(self):
        """Test creating a route with required fields."""
        route = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            source="ripe_stat",
        )
        assert route.prefix == "192.0.2.0/24"
        assert route.origin_asn == 64496
        assert route.as_path == [64496]
        assert route.collector == "rrc00"
        assert route.source == "ripe_stat"

    def test_create_full_route(self):
        """Test creating a route with all fields."""
        route = BGPRoute(
            prefix="8.8.8.0/24",
            origin_asn=15169,
            as_path=[64496, 3356, 15169],
            next_hop="192.0.2.1",
            origin="igp",
            communities=["3356:123", "3356:456"],
            collector="rrc21",
            peer_ip="192.0.2.100",
            peer_asn=64496,
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            source="ris_live",
            rpki_status="valid",
        )
        assert route.prefix == "8.8.8.0/24"
        assert route.origin_asn == 15169
        assert route.as_path == [64496, 3356, 15169]
        assert route.next_hop == "192.0.2.1"
        assert route.origin == "igp"
        assert route.communities == ["3356:123", "3356:456"]
        assert route.collector == "rrc21"
        assert route.peer_ip == "192.0.2.100"
        assert route.peer_asn == 64496
        assert route.rpki_status == "valid"

    def test_route_defaults(self):
        """Test that optional fields have correct defaults."""
        route = BGPRoute(
            prefix="10.0.0.0/8",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        assert route.next_hop is None
        assert route.origin is None
        assert route.communities == []
        assert route.peer_ip is None
        assert route.peer_asn is None
        assert route.rpki_status is None

    def test_route_to_dict(self):
        """Test converting route to dictionary."""
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        route = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=64496,
            as_path=[64496, 3356],
            collector="rrc00",
            timestamp=ts,
            source="ripe_stat",
        )
        d = route.to_dict()
        assert d["prefix"] == "192.0.2.0/24"
        assert d["origin_asn"] == 64496
        assert d["as_path"] == [64496, 3356]
        assert d["timestamp"] == "2024-01-01T12:00:00+00:00"

    def test_route_from_dict(self):
        """Test creating route from dictionary."""
        data = {
            "prefix": "192.0.2.0/24",
            "origin_asn": 64496,
            "as_path": [64496],
            "collector": "rrc00",
            "timestamp": "2024-01-01T12:00:00+00:00",
            "source": "ripe_stat",
        }
        route = BGPRoute.from_dict(data)
        assert route.prefix == "192.0.2.0/24"
        assert route.origin_asn == 64496
        assert route.timestamp.year == 2024

    def test_route_equality(self):
        """Test route equality comparison."""
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        route1 = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=ts,
            source="ripe_stat",
        )
        route2 = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=ts,
            source="ripe_stat",
        )
        assert route1 == route2

    def test_route_as_path_length(self):
        """Test AS path length property."""
        route = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=15169,
            as_path=[64496, 3356, 174, 15169],
            collector="rrc00",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        assert route.as_path_length == 4

    def test_route_ipv6_prefix(self):
        """Test route with IPv6 prefix."""
        route = BGPRoute(
            prefix="2001:db8::/32",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        assert route.prefix == "2001:db8::/32"
        assert route.is_ipv6 is True

    def test_route_ipv4_prefix(self):
        """Test route with IPv4 prefix."""
        route = BGPRoute(
            prefix="192.0.2.0/24",
            origin_asn=64496,
            as_path=[64496],
            collector="rrc00",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        assert route.is_ipv6 is False
