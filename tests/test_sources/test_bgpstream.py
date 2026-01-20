"""Tests for BGPStream client."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

# Check if pybgpstream is available
try:
    import pybgpstream  # noqa: F401

    BGPSTREAM_AVAILABLE = True
except ImportError:
    BGPSTREAM_AVAILABLE = False


# Skip all tests if pybgpstream is not available
pytestmark = pytest.mark.skipif(not BGPSTREAM_AVAILABLE, reason="pybgpstream not installed")


class TestBGPStreamClient:
    """Tests for BGPStreamClient."""

    def test_is_available(self):
        """Test is_available class method."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        assert BGPStreamClient.is_available() == BGPSTREAM_AVAILABLE

    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        """Test connect and disconnect."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        client = BGPStreamClient()
        await client.connect()
        assert client._connected is True

        await client.disconnect()
        assert client._connected is False

    def test_elem_to_route_announcement(self):
        """Test converting BGPStream element to BGPRoute."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        client = BGPStreamClient()

        # Mock element
        mock_elem = MagicMock()
        mock_elem.type = "A"  # Announcement
        mock_elem.fields = {
            "prefix": "8.8.8.0/24",
            "as-path": "64496 3356 15169",
            "next-hop": "192.0.2.1",
            "communities": "3356:123 3356:456",
        }
        mock_elem.peer_asn = 64496
        mock_elem.peer_address = "192.0.2.1"

        # Mock record
        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200  # 2024-01-01 00:00:00 UTC

        route = client._elem_to_route(mock_elem, mock_rec)

        assert route is not None
        assert route.prefix == "8.8.8.0/24"
        assert route.origin_asn == 15169
        assert route.as_path == [64496, 3356, 15169]
        assert route.collector == "rrc00"
        assert route.source == "bgpstream"
        assert route.peer_asn == 64496

    def test_elem_to_route_withdrawal(self):
        """Test that withdrawals return None."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        client = BGPStreamClient()

        mock_elem = MagicMock()
        mock_elem.type = "W"  # Withdrawal

        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200

        route = client._elem_to_route(mock_elem, mock_rec)

        assert route is None

    def test_elem_to_route_with_as_set(self):
        """Test handling AS sets in path."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        client = BGPStreamClient()

        mock_elem = MagicMock()
        mock_elem.type = "A"
        mock_elem.fields = {
            "prefix": "10.0.0.0/8",
            "as-path": "64496 {1,2,3} 15169",  # AS set
            "next-hop": "192.0.2.1",
        }
        mock_elem.peer_asn = 64496
        mock_elem.peer_address = "192.0.2.1"

        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200

        route = client._elem_to_route(mock_elem, mock_rec)

        assert route is not None
        # AS set should take first ASN
        assert route.as_path == [64496, 1, 15169]

    def test_elem_to_route_empty_path(self):
        """Test handling empty AS path."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        client = BGPStreamClient()

        mock_elem = MagicMock()
        mock_elem.type = "A"
        mock_elem.fields = {
            "prefix": "10.0.0.0/8",
            "as-path": "",
            "next-hop": "192.0.2.1",
        }
        mock_elem.peer_asn = 64496
        mock_elem.peer_address = "192.0.2.1"

        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200

        route = client._elem_to_route(mock_elem, mock_rec)

        assert route is not None
        assert route.as_path == []
        assert route.origin_asn == 0

    @patch("bgp_explorer.sources.bgpstream.pybgpstream.BGPStream")
    def test_get_historical_updates(self, mock_bgpstream_class):
        """Test getting historical updates."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        # Setup mock stream
        mock_stream = MagicMock()
        mock_bgpstream_class.return_value = mock_stream

        # Create mock records
        mock_elem = MagicMock()
        mock_elem.type = "A"
        mock_elem.fields = {
            "prefix": "8.8.8.0/24",
            "as-path": "64496 15169",
            "next-hop": "192.0.2.1",
        }
        mock_elem.peer_asn = 64496
        mock_elem.peer_address = "192.0.2.1"

        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200
        mock_rec.__iter__ = lambda self: iter([mock_elem])

        mock_stream.records.return_value = [mock_rec]

        client = BGPStreamClient()
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 1, 0, tzinfo=UTC)

        routes = client.get_historical_updates(
            start_time=start,
            end_time=end,
            collectors=["rrc00"],
            prefix_filter="8.8.8.0/24",
        )

        assert len(routes) == 1
        assert routes[0].prefix == "8.8.8.0/24"
        mock_stream.add_filter.assert_any_call("collector", "rrc00")
        mock_stream.add_filter.assert_any_call("prefix", "8.8.8.0/24")

    @patch("bgp_explorer.sources.bgpstream.pybgpstream.BGPStream")
    def test_get_prefix_events(self, mock_bgpstream_class):
        """Test getting prefix events."""
        from bgp_explorer.sources.bgpstream import BGPStreamClient

        mock_stream = MagicMock()
        mock_bgpstream_class.return_value = mock_stream

        # Announcement
        mock_elem_a = MagicMock()
        mock_elem_a.type = "A"
        mock_elem_a.fields = {
            "prefix": "8.8.8.0/24",
            "as-path": "64496 15169",
            "next-hop": "192.0.2.1",
            "communities": "",
        }
        mock_elem_a.peer_asn = 64496
        mock_elem_a.peer_address = "192.0.2.1"

        # Withdrawal
        mock_elem_w = MagicMock()
        mock_elem_w.type = "W"
        mock_elem_w.fields = {"prefix": "8.8.8.0/24"}
        mock_elem_w.peer_asn = 64496
        mock_elem_w.peer_address = "192.0.2.1"

        mock_rec = MagicMock()
        mock_rec.collector = "rrc00"
        mock_rec.time = 1704067200
        mock_rec.__iter__ = lambda self: iter([mock_elem_a, mock_elem_w])

        mock_stream.records.return_value = [mock_rec]

        client = BGPStreamClient()
        start = datetime(2024, 1, 1, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 1, 0, tzinfo=UTC)

        events = client.get_prefix_events("8.8.8.0/24", start, end)

        assert len(events) == 2
        assert events[0]["type"] == "announcement"
        assert events[1]["type"] == "withdrawal"


class TestBGPStreamNotAvailable:
    """Tests for when pybgpstream is not available."""

    def test_error_when_not_available(self):
        """Test that BGPStreamError is raised when not available."""
        with patch.dict("sys.modules", {"pybgpstream": None}):
            # Need to reload the module to pick up the patched import
            from bgp_explorer.sources import bgpstream

            # Temporarily set BGPSTREAM_AVAILABLE to False
            original = bgpstream.BGPSTREAM_AVAILABLE
            bgpstream.BGPSTREAM_AVAILABLE = False

            try:
                with pytest.raises(bgpstream.BGPStreamError):
                    bgpstream.BGPStreamClient()
            finally:
                bgpstream.BGPSTREAM_AVAILABLE = original
