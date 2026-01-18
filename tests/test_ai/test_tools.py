"""Tests for AI tools."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.ai.tools import BGPTools
from bgp_explorer.models.event import BGPEvent, EventType, Severity
from bgp_explorer.models.route import BGPRoute


class TestBGPTools:
    """Tests for BGPTools."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        mock = AsyncMock()
        return mock

    @pytest.fixture
    def mock_bgp_radar(self):
        """Create a mock bgp-radar client."""
        mock = AsyncMock()
        mock.is_running = True
        return mock

    @pytest.fixture
    def tools(self, mock_ripe_stat, mock_bgp_radar):
        """Create BGPTools instance with mocked clients."""
        return BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=mock_bgp_radar)

    @pytest.mark.asyncio
    async def test_lookup_prefix_success(self, tools, mock_ripe_stat):
        """Test looking up a prefix."""
        mock_routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=datetime.now(timezone.utc),
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[174, 15169],
                collector="rrc01",
                timestamp=datetime.now(timezone.utc),
                source="ripe_stat",
            ),
        ]
        mock_ripe_stat.get_bgp_state.return_value = mock_routes

        result = await tools.lookup_prefix("8.8.8.0/24")

        assert "8.8.8.0/24" in result
        assert "15169" in result
        mock_ripe_stat.get_bgp_state.assert_called_once_with("8.8.8.0/24")

    @pytest.mark.asyncio
    async def test_lookup_prefix_not_found(self, tools, mock_ripe_stat):
        """Test looking up a prefix with no results."""
        mock_ripe_stat.get_bgp_state.return_value = []

        result = await tools.lookup_prefix("192.0.2.0/24")

        assert "not found" in result.lower() or "no routes" in result.lower()

    @pytest.mark.asyncio
    async def test_get_asn_announcements_success(self, tools, mock_ripe_stat):
        """Test getting ASN announcements."""
        mock_ripe_stat.get_announced_prefixes.return_value = [
            "8.8.8.0/24",
            "8.8.4.0/24",
        ]

        result = await tools.get_asn_announcements(15169)

        assert "8.8.8.0/24" in result
        assert "8.8.4.0/24" in result
        mock_ripe_stat.get_announced_prefixes.assert_called_once_with(15169)

    @pytest.mark.asyncio
    async def test_get_asn_announcements_none(self, tools, mock_ripe_stat):
        """Test getting announcements for ASN with none."""
        mock_ripe_stat.get_announced_prefixes.return_value = []

        result = await tools.get_asn_announcements(64496)

        assert "not announcing any prefixes" in result.lower() or "no prefixes" in result.lower()

    @pytest.mark.asyncio
    async def test_get_routing_history(self, tools, mock_ripe_stat):
        """Test getting routing history."""
        mock_ripe_stat.get_routing_history.return_value = {
            "resource": "8.8.8.0/24",
            "by_origin": [
                {
                    "origin": "15169",
                    "prefixes": [{"prefix": "8.8.8.0/24", "timelines": []}],
                }
            ],
        }

        result = await tools.get_routing_history(
            "8.8.8.0/24",
            "2024-01-01",
            "2024-01-31",
        )

        assert "8.8.8.0/24" in result
        assert "15169" in result

    @pytest.mark.asyncio
    async def test_get_anomalies_all(self, tools, mock_bgp_radar):
        """Test getting all anomalies."""
        mock_events = [
            BGPEvent(
                type=EventType.HIJACK,
                severity=Severity.HIGH,
                affected_prefix="8.8.8.0/24",
                affected_asn=15169,
                detected_at=datetime.now(timezone.utc),
            ),
        ]
        mock_bgp_radar.get_recent_anomalies.return_value = mock_events

        result = await tools.get_anomalies()

        assert "hijack" in result.lower()
        mock_bgp_radar.get_recent_anomalies.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_anomalies_filtered(self, tools, mock_bgp_radar):
        """Test getting filtered anomalies."""
        mock_events = []
        mock_bgp_radar.get_recent_anomalies.return_value = mock_events

        result = await tools.get_anomalies(
            event_type="hijack", prefix="8.8.8.0/24", asn=15169
        )

        mock_bgp_radar.get_recent_anomalies.assert_called_once()
        call_kwargs = mock_bgp_radar.get_recent_anomalies.call_args.kwargs
        assert call_kwargs["event_type"] == EventType.HIJACK
        assert call_kwargs["prefix"] == "8.8.8.0/24"
        assert call_kwargs["asn"] == 15169

    @pytest.mark.asyncio
    async def test_get_anomalies_no_radar(self, mock_ripe_stat):
        """Test getting anomalies when bgp-radar not available."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)

        result = await tools.get_anomalies()

        assert "not available" in result.lower() or "not running" in result.lower()

    @pytest.mark.asyncio
    async def test_get_rpki_status(self, tools, mock_ripe_stat):
        """Test getting RPKI validation status."""
        mock_ripe_stat.get_rpki_validation.return_value = "valid"

        result = await tools.get_rpki_status("8.8.8.0/24", 15169)

        assert "valid" in result.lower()
        mock_ripe_stat.get_rpki_validation.assert_called_once_with("8.8.8.0/24", 15169)

    def test_get_all_tools(self, tools):
        """Test getting all tool functions."""
        tool_funcs = tools.get_all_tools()

        assert len(tool_funcs) >= 4
        tool_names = [f.__name__ for f in tool_funcs]
        assert "lookup_prefix" in tool_names
        assert "get_asn_announcements" in tool_names
        assert "get_anomalies" in tool_names

    def test_tool_docstrings(self, tools):
        """Test that all tools have docstrings."""
        for func in tools.get_all_tools():
            assert func.__doc__ is not None
            assert len(func.__doc__) > 10
