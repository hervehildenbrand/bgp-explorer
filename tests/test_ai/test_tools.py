"""Tests for AI tools."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

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
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[174, 15169],
                collector="rrc01",
                timestamp=datetime.now(UTC),
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
                detected_at=datetime.now(UTC),
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

        await tools.get_anomalies(event_type="hijack", prefix="8.8.8.0/24", asn=15169)

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


class TestBGPToolsWithPeeringDB:
    """Tests for BGPTools with PeeringDB integration."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def mock_peeringdb(self):
        """Create a mock PeeringDB client."""
        from bgp_explorer.models.ixp import IXP, IXPPresence, Network

        mock = MagicMock()
        mock._loaded = True

        # Setup mock data
        mock.get_ixps_for_asn.return_value = [
            IXPPresence(
                asn=15169, ixp_id=31, ixp_name="AMS-IX", ipaddr4="80.249.208.1", speed=100000
            ),
            IXPPresence(
                asn=15169,
                ixp_id=26,
                ixp_name="DE-CIX Frankfurt",
                ipaddr4="80.81.192.1",
                speed=100000,
            ),
        ]

        mock.get_networks_at_ixp.return_value = [
            Network(asn=15169, name="Google LLC", info_type="Content"),
            Network(asn=13335, name="Cloudflare, Inc.", info_type="NSP"),
        ]

        mock.get_ixp_details.return_value = IXP(
            id=31,
            name="AMS-IX",
            city="Amsterdam",
            country="NL",
            website="https://www.ams-ix.net/",
            participant_count=900,
        )

        mock.get_network_info.return_value = Network(
            asn=15169,
            name="Google LLC",
            info_type="Content",
            website="https://www.google.com",
        )

        return mock

    @pytest.fixture
    def tools_with_peeringdb(self, mock_ripe_stat, mock_peeringdb):
        """Create BGPTools instance with PeeringDB."""
        return BGPTools(ripe_stat=mock_ripe_stat, peeringdb=mock_peeringdb)

    @pytest.mark.asyncio
    async def test_get_ixps_for_asn(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting IXPs for an ASN."""
        result = await tools_with_peeringdb.get_ixps_for_asn(15169)

        assert "AMS-IX" in result
        assert "DE-CIX Frankfurt" in result
        assert "15169" in result
        mock_peeringdb.get_ixps_for_asn.assert_called_once_with(15169)

    @pytest.mark.asyncio
    async def test_get_ixps_for_asn_not_found(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting IXPs for an ASN with no presence."""
        mock_peeringdb.get_ixps_for_asn.return_value = []

        result = await tools_with_peeringdb.get_ixps_for_asn(99999)

        assert (
            "no ixp" in result.lower()
            or "not present" in result.lower()
            or "not found" in result.lower()
        )

    @pytest.mark.asyncio
    async def test_get_networks_at_ixp(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting networks at an IXP."""
        result = await tools_with_peeringdb.get_networks_at_ixp("AMS-IX")

        assert "Google" in result
        assert "Cloudflare" in result
        mock_peeringdb.get_networks_at_ixp.assert_called_once_with("AMS-IX")

    @pytest.mark.asyncio
    async def test_get_networks_at_ixp_not_found(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting networks at an IXP that doesn't exist."""
        mock_peeringdb.get_networks_at_ixp.return_value = []

        result = await tools_with_peeringdb.get_networks_at_ixp("NonExistentIXP")

        assert "no networks" in result.lower() or "not found" in result.lower()

    @pytest.mark.asyncio
    async def test_get_ixp_details(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting IXP details."""
        result = await tools_with_peeringdb.get_ixp_details("AMS-IX")

        assert "AMS-IX" in result
        assert "Amsterdam" in result
        assert "900" in result  # participant count
        mock_peeringdb.get_ixp_details.assert_called_once_with("AMS-IX")

    @pytest.mark.asyncio
    async def test_get_ixp_details_not_found(self, tools_with_peeringdb, mock_peeringdb):
        """Test getting details for non-existent IXP."""
        mock_peeringdb.get_ixp_details.return_value = None

        result = await tools_with_peeringdb.get_ixp_details("NonExistentIXP")

        assert "not found" in result.lower()

    def test_get_all_tools_includes_peeringdb(self, tools_with_peeringdb):
        """Test that PeeringDB tools are included when available."""
        tool_funcs = tools_with_peeringdb.get_all_tools()
        tool_names = [f.__name__ for f in tool_funcs]

        assert "get_ixps_for_asn" in tool_names
        assert "get_networks_at_ixp" in tool_names
        assert "get_ixp_details" in tool_names

    def test_get_all_tools_excludes_peeringdb_when_none(self, mock_ripe_stat):
        """Test that PeeringDB tools are excluded when not available."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, peeringdb=None)
        tool_funcs = tools.get_all_tools()
        tool_names = [f.__name__ for f in tool_funcs]

        assert "get_ixps_for_asn" not in tool_names
        assert "get_networks_at_ixp" not in tool_names
        assert "get_ixp_details" not in tool_names


class TestBGPToolsMonitoring:
    """Tests for monitoring control tools."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def mock_bgp_radar(self):
        """Create a mock bgp-radar client."""
        mock = AsyncMock()
        mock.is_running = False
        mock._collectors = ["rrc00"]
        return mock

    @pytest.fixture
    def tools(self, mock_ripe_stat, mock_bgp_radar):
        """Create BGPTools instance with mocked clients."""
        return BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=mock_bgp_radar)

    @pytest.mark.asyncio
    async def test_start_monitoring_success(self, tools, mock_bgp_radar):
        """Test starting monitoring successfully."""
        mock_bgp_radar.is_running = False
        mock_bgp_radar.start = AsyncMock()

        result = await tools.start_monitoring()

        mock_bgp_radar.start.assert_called_once()
        assert "started" in result.lower() or "monitoring" in result.lower()

    @pytest.mark.asyncio
    async def test_start_monitoring_already_running(self, tools, mock_bgp_radar):
        """Test starting monitoring when already running."""
        mock_bgp_radar.is_running = True

        result = await tools.start_monitoring()

        assert "already" in result.lower()

    @pytest.mark.asyncio
    async def test_start_monitoring_with_collectors(self, tools, mock_bgp_radar):
        """Test starting monitoring with custom collectors."""
        mock_bgp_radar.is_running = False
        mock_bgp_radar.start = AsyncMock()

        await tools.start_monitoring(collectors=["rrc00", "rrc01"])

        mock_bgp_radar.start.assert_called_once_with(collectors=["rrc00", "rrc01"])

    @pytest.mark.asyncio
    async def test_start_monitoring_no_radar(self, mock_ripe_stat):
        """Test starting monitoring when bgp-radar not available."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)

        result = await tools.start_monitoring()

        assert "not available" in result.lower() or "not configured" in result.lower()

    @pytest.mark.asyncio
    async def test_stop_monitoring_success(self, tools, mock_bgp_radar):
        """Test stopping monitoring successfully."""
        mock_bgp_radar.is_running = True
        mock_bgp_radar.stop = AsyncMock()

        result = await tools.stop_monitoring()

        mock_bgp_radar.stop.assert_called_once()
        assert "stopped" in result.lower()

    @pytest.mark.asyncio
    async def test_stop_monitoring_not_running(self, tools, mock_bgp_radar):
        """Test stopping monitoring when not running."""
        mock_bgp_radar.is_running = False

        result = await tools.stop_monitoring()

        assert "not running" in result.lower()

    @pytest.mark.asyncio
    async def test_stop_monitoring_no_radar(self, mock_ripe_stat):
        """Test stopping monitoring when bgp-radar not available."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)

        result = await tools.stop_monitoring()

        assert "not available" in result.lower() or "not configured" in result.lower()

    def test_monitoring_tools_included(self, tools):
        """Test that monitoring tools are included when bgp-radar is available."""
        tool_funcs = tools.get_all_tools()
        tool_names = [f.__name__ for f in tool_funcs]

        assert "start_monitoring" in tool_names
        assert "stop_monitoring" in tool_names

    def test_monitoring_tools_excluded_when_no_radar(self, mock_ripe_stat):
        """Test that monitoring tools are excluded when bgp-radar not available."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)
        tool_funcs = tools.get_all_tools()
        tool_names = [f.__name__ for f in tool_funcs]

        assert "start_monitoring" not in tool_names
        assert "stop_monitoring" not in tool_names


class TestAddressFamilyFiltering:
    """Tests for IPv4/IPv6 address family filtering."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def tools(self, mock_ripe_stat):
        """Create BGPTools instance with mocked clients."""
        return BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)

    @pytest.mark.asyncio
    async def test_get_asn_announcements_default_shows_both(self, tools, mock_ripe_stat):
        """Test that default shows both IPv4 and IPv6."""
        mock_ripe_stat.get_announced_prefixes.return_value = [
            "8.8.8.0/24",
            "8.8.4.0/24",
            "2001:4860::/32",
        ]

        result = await tools.get_asn_announcements(15169)

        assert "IPv4: 2" in result
        assert "IPv6: 1" in result
        assert "8.8.8.0/24" in result
        assert "2001:4860::/32" in result

    @pytest.mark.asyncio
    async def test_get_asn_announcements_ipv4_only(self, tools, mock_ripe_stat):
        """Test filtering to IPv4 only."""
        mock_ripe_stat.get_announced_prefixes.return_value = [
            "8.8.8.0/24",
            "8.8.4.0/24",
            "2001:4860::/32",
        ]

        result = await tools.get_asn_announcements(15169, address_family=4)

        assert "IPv4 prefixes (filtered)" in result
        assert "8.8.8.0/24" in result
        assert "8.8.4.0/24" in result
        # IPv6 prefix should not be in the filtered output section
        # but totals should still show both
        assert "IPv4: 2" in result
        assert "IPv6: 1" in result

    @pytest.mark.asyncio
    async def test_get_asn_announcements_ipv6_only(self, tools, mock_ripe_stat):
        """Test filtering to IPv6 only."""
        mock_ripe_stat.get_announced_prefixes.return_value = [
            "8.8.8.0/24",
            "2001:4860::/32",
            "2607:f8b0::/32",
        ]

        result = await tools.get_asn_announcements(15169, address_family=6)

        assert "IPv6 prefixes (filtered)" in result
        assert "2001:4860::/32" in result
        assert "2607:f8b0::/32" in result
        # Totals should still show both
        assert "IPv4: 1" in result
        assert "IPv6: 2" in result

    @pytest.mark.asyncio
    async def test_lookup_prefix_reports_ipv4_family(self, tools, mock_ripe_stat):
        """Test that lookup_prefix reports IPv4 address family."""
        mock_routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]
        mock_ripe_stat.get_bgp_state.return_value = mock_routes

        result = await tools.lookup_prefix("8.8.8.0/24")

        assert "(IPv4)" in result
        assert "8.8.8.0/24" in result

    @pytest.mark.asyncio
    async def test_lookup_prefix_reports_ipv6_family(self, tools, mock_ripe_stat):
        """Test that lookup_prefix reports IPv6 address family."""
        mock_routes = [
            BGPRoute(
                prefix="2001:4860::/32",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]
        mock_ripe_stat.get_bgp_state.return_value = mock_routes

        result = await tools.lookup_prefix("2001:4860::/32")

        assert "(IPv6)" in result
        assert "2001:4860::/32" in result

    @pytest.mark.asyncio
    async def test_lookup_prefix_not_found_includes_family(self, tools, mock_ripe_stat):
        """Test that not found message includes address family."""
        mock_ripe_stat.get_bgp_state.return_value = []

        result_ipv4 = await tools.lookup_prefix("192.0.2.0/24")
        result_ipv6 = await tools.lookup_prefix("2001:db8::/32")

        assert "IPv4 prefix" in result_ipv4
        assert "IPv6 prefix" in result_ipv6


class TestSearchAsnPeeringDBFallback:
    """Tests for search_asn with PeeringDB fallback."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def mock_peeringdb(self):
        """Create a mock PeeringDB client."""
        from bgp_explorer.models.ixp import Network

        mock = MagicMock()
        mock._loaded = True

        # Setup mock data - La Poste found in PeeringDB
        mock.search_networks.return_value = [
            Network(asn=35676, name="Groupe La Poste France", info_type="Enterprise"),
        ]

        return mock

    @pytest.fixture
    def tools_with_peeringdb(self, mock_ripe_stat, mock_peeringdb):
        """Create BGPTools instance with PeeringDB."""
        return BGPTools(ripe_stat=mock_ripe_stat, peeringdb=mock_peeringdb)

    @pytest.mark.asyncio
    async def test_search_asn_uses_peeringdb_fallback_when_ripe_empty(
        self, tools_with_peeringdb, mock_ripe_stat, mock_peeringdb
    ):
        """Test that PeeringDB is used as fallback when RIPE Stat returns nothing."""
        # RIPE Stat returns empty for "La Poste"
        mock_ripe_stat.search_asn.return_value = []

        result = await tools_with_peeringdb.search_asn("La Poste")

        # Should have called PeeringDB as fallback
        mock_peeringdb.search_networks.assert_called()
        # Should find La Poste via PeeringDB
        assert "35676" in result
        assert "Poste" in result

    @pytest.mark.asyncio
    async def test_search_asn_prefers_ripe_when_results_found(
        self, tools_with_peeringdb, mock_ripe_stat, mock_peeringdb
    ):
        """Test that RIPE Stat results are used when available."""
        # RIPE Stat returns results
        mock_ripe_stat.search_asn.return_value = [
            {"asn": 15169, "description": "Google LLC"}
        ]

        result = await tools_with_peeringdb.search_asn("Google")

        # Should NOT have called PeeringDB (RIPE had results)
        mock_peeringdb.search_networks.assert_not_called()
        # Should find Google via RIPE
        assert "15169" in result
        assert "Google" in result

    @pytest.mark.asyncio
    async def test_search_asn_works_without_peeringdb(self, mock_ripe_stat):
        """Test that search_asn works when PeeringDB is not available."""
        # Create tools without PeeringDB
        tools = BGPTools(ripe_stat=mock_ripe_stat, peeringdb=None)

        # RIPE Stat returns empty
        mock_ripe_stat.search_asn.return_value = []

        result = await tools.search_asn("Unknown Network")

        # Should gracefully handle missing PeeringDB
        assert "No ASNs found" in result


class TestCheckPrefixAnomalies:
    """Tests for check_prefix_anomalies tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create a mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def tools(self, mock_ripe_stat):
        """Create BGPTools instance with mocked clients."""
        return BGPTools(ripe_stat=mock_ripe_stat, bgp_radar=None)

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_normal(self, tools, mock_ripe_stat):
        """Test checking a normal prefix with no anomalies."""
        # Setup mock for single origin, RPKI valid
        mock_routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[174, 15169],
                collector="rrc01",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]
        # Add more collectors for normal visibility
        for i in range(10):
            mock_routes.append(
                BGPRoute(
                    prefix="8.8.8.0/24",
                    origin_asn=15169,
                    as_path=[i, 15169],
                    collector=f"rrc{i:02d}",
                    timestamp=datetime.now(UTC),
                    source="ripe_stat",
                )
            )

        mock_ripe_stat.get_bgp_state.return_value = mock_routes
        mock_ripe_stat.get_rpki_validation.return_value = "valid"
        mock_ripe_stat.get_routing_history.return_value = {
            "by_origin": [{"origin": "15169", "prefixes": []}]
        }

        result = await tools.check_prefix_anomalies("8.8.8.0/24")

        assert "8.8.8.0/24" in result
        assert "LOW" in result
        assert "Single Origin" in result
        assert "AS15169" in result
        assert "valid" in result.lower()
        assert "No risk factors" in result

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_moas(self, tools, mock_ripe_stat):
        """Test detecting MOAS (Multiple Origin AS)."""
        mock_routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=12345,
                as_path=[100, 12345],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=67890,  # Different origin!
                as_path=[200, 67890],
                collector="rrc01",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]

        mock_ripe_stat.get_bgp_state.return_value = mock_routes
        mock_ripe_stat.get_rpki_validation.return_value = "not-found"
        mock_ripe_stat.get_routing_history.return_value = {"by_origin": []}

        result = await tools.check_prefix_anomalies("1.2.3.0/24")

        assert "MOAS Detected" in result
        assert "Multiple Origin" in result
        assert "AS12345" in result
        assert "AS67890" in result
        # Should have medium or high risk due to MOAS
        assert "MEDIUM" in result or "HIGH" in result

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_rpki_invalid(self, tools, mock_ripe_stat):
        """Test detecting RPKI invalid status (high risk)."""
        mock_routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64496,
                as_path=[100, 64496],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]
        # Add collectors for normal visibility
        for i in range(10):
            mock_routes.append(
                BGPRoute(
                    prefix="1.2.3.0/24",
                    origin_asn=64496,
                    as_path=[i, 64496],
                    collector=f"rrc{i:02d}",
                    timestamp=datetime.now(UTC),
                    source="ripe_stat",
                )
            )

        mock_ripe_stat.get_bgp_state.return_value = mock_routes
        mock_ripe_stat.get_rpki_validation.return_value = "invalid"
        mock_ripe_stat.get_routing_history.return_value = {"by_origin": []}

        result = await tools.check_prefix_anomalies("1.2.3.0/24")

        assert "INVALID" in result
        assert "HIGH" in result
        assert "RPKI Invalid" in result

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_not_routed(self, tools, mock_ripe_stat):
        """Test checking a prefix that is not routed."""
        mock_ripe_stat.get_bgp_state.return_value = []

        result = await tools.check_prefix_anomalies("192.0.2.0/24")

        assert "Not routed" in result
        assert "No routes found" in result

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_low_visibility(self, tools, mock_ripe_stat):
        """Test detecting low visibility as a risk factor."""
        mock_routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=12345,
                as_path=[100, 12345],
                collector="rrc00",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=12345,
                as_path=[200, 12345],
                collector="rrc01",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            ),
        ]

        mock_ripe_stat.get_bgp_state.return_value = mock_routes
        mock_ripe_stat.get_rpki_validation.return_value = "valid"
        mock_ripe_stat.get_routing_history.return_value = {"by_origin": []}

        result = await tools.check_prefix_anomalies("1.2.3.0/24")

        assert "2 collectors" in result
        assert "Low visibility" in result or "limited" in result.lower()

    @pytest.mark.asyncio
    async def test_check_prefix_anomalies_error(self, tools, mock_ripe_stat):
        """Test error handling."""
        mock_ripe_stat.get_bgp_state.side_effect = Exception("API error")

        result = await tools.check_prefix_anomalies("8.8.8.0/24")

        assert "Error" in result
        assert "API error" in result

    def test_check_prefix_anomalies_in_tools_list(self, tools):
        """Test that check_prefix_anomalies is in the tools list."""
        tool_funcs = tools.get_all_tools()
        tool_names = [f.__name__ for f in tool_funcs]

        assert "check_prefix_anomalies" in tool_names

    def test_check_prefix_anomalies_has_docstring(self, tools):
        """Test that check_prefix_anomalies has a proper docstring."""
        assert tools.check_prefix_anomalies.__doc__ is not None
        assert "hijack" in tools.check_prefix_anomalies.__doc__.lower()
        assert "MOAS" in tools.check_prefix_anomalies.__doc__
        assert "RPKI" in tools.check_prefix_anomalies.__doc__
