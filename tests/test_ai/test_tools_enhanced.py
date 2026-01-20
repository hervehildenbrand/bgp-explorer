"""Tests for enhanced AI tools (Phase 2)."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from bgp_explorer.ai.tools import BGPTools
from bgp_explorer.models.route import BGPRoute
from bgp_explorer.sources.globalping import MeasurementResult, ProbeResult


class TestAnalyzeAsPath:
    """Tests for analyze_as_path tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create mock RIPE Stat client."""
        return AsyncMock()

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
        ]

    @pytest.mark.asyncio
    async def test_analyze_as_path_success(self, mock_ripe_stat, sample_routes):
        """Test successful path analysis."""
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=sample_routes)
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.analyze_as_path("8.8.8.0/24")

        assert "AS Path Analysis: 8.8.8.0/24" in result
        assert "Path Diversity Metrics" in result
        assert "Unique paths" in result
        assert "Upstream ASNs" in result
        mock_ripe_stat.get_bgp_state.assert_called_once_with("8.8.8.0/24")

    @pytest.mark.asyncio
    async def test_analyze_as_path_no_routes(self, mock_ripe_stat):
        """Test path analysis with no routes found."""
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=[])
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.analyze_as_path("10.0.0.0/8")

        assert "No routes found" in result
        assert "Cannot analyze paths" in result

    @pytest.mark.asyncio
    async def test_analyze_as_path_with_prepending(self, mock_ripe_stat):
        """Test path analysis detecting prepending."""
        ts = datetime.now(UTC)
        routes = [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64496,
                as_path=[3356, 64496, 64496, 64496],  # Prepended
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
        ]
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=routes)
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.analyze_as_path("1.2.3.0/24")

        assert "Path Prepending Detected" in result

    @pytest.mark.asyncio
    async def test_analyze_as_path_error(self, mock_ripe_stat):
        """Test path analysis error handling."""
        mock_ripe_stat.get_bgp_state = AsyncMock(side_effect=Exception("API error"))
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.analyze_as_path("8.8.8.0/24")

        assert "Error analyzing AS paths" in result


class TestCompareCollectors:
    """Tests for compare_collectors tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def consistent_routes(self):
        """Create routes with consistent origin."""
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
                as_path=[174, 15169],
                collector="rrc01",
                timestamp=ts,
                source="ripe_stat",
            ),
        ]

    @pytest.fixture
    def inconsistent_routes(self):
        """Create routes with inconsistent origins (possible hijack)."""
        ts = datetime.now(UTC)
        return [
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64496,
                as_path=[3356, 64496],
                collector="rrc00",
                timestamp=ts,
                source="ripe_stat",
            ),
            BGPRoute(
                prefix="1.2.3.0/24",
                origin_asn=64497,  # Different origin!
                as_path=[174, 64497],
                collector="rrc01",
                timestamp=ts,
                source="ripe_stat",
            ),
        ]

    @pytest.mark.asyncio
    async def test_compare_collectors_consistent(self, mock_ripe_stat, consistent_routes):
        """Test collector comparison with consistent origins."""
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=consistent_routes)
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.compare_collectors("8.8.8.0/24")

        assert "Collector Comparison: 8.8.8.0/24" in result
        assert "Consistent origin:** Yes" in result
        assert "rrc00" in result
        assert "rrc01" in result

    @pytest.mark.asyncio
    async def test_compare_collectors_inconsistent(self, mock_ripe_stat, inconsistent_routes):
        """Test collector comparison detecting inconsistent origins."""
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=inconsistent_routes)
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.compare_collectors("1.2.3.0/24")

        assert "Consistent origin:** No" in result
        assert "Warning" in result
        assert "Multiple origin ASNs detected" in result

    @pytest.mark.asyncio
    async def test_compare_collectors_no_routes(self, mock_ripe_stat):
        """Test collector comparison with no routes."""
        mock_ripe_stat.get_bgp_state = AsyncMock(return_value=[])
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.compare_collectors("10.0.0.0/8")

        assert "No routes found" in result
        assert "Cannot compare collectors" in result


class TestGetAsnDetails:
    """Tests for get_asn_details tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create mock RIPE Stat client."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_get_asn_details_success(self, mock_ripe_stat):
        """Test successful ASN details retrieval."""
        ts = datetime.now(UTC)
        mock_ripe_stat.get_announced_prefixes = AsyncMock(
            return_value=["8.8.8.0/24", "8.8.4.0/24", "2001:4860::/32"]
        )
        mock_ripe_stat.get_bgp_state = AsyncMock(
            return_value=[
                BGPRoute(
                    prefix="8.8.8.0/24",
                    origin_asn=15169,
                    as_path=[3356, 15169],
                    collector="rrc00",
                    timestamp=ts,
                    source="ripe_stat",
                ),
            ]
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.get_asn_details(15169)

        assert "AS15169 Details" in result
        assert "Announcements" in result
        assert "Total prefixes: 3" in result
        assert "IPv4: 2" in result
        assert "IPv6: 1" in result

    @pytest.mark.asyncio
    async def test_get_asn_details_no_prefixes(self, mock_ripe_stat):
        """Test ASN details with no announced prefixes."""
        mock_ripe_stat.get_announced_prefixes = AsyncMock(return_value=[])
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.get_asn_details(99999)

        assert "not announcing any prefixes" in result

    @pytest.mark.asyncio
    async def test_get_asn_details_with_relationships(self, mock_ripe_stat):
        """Test ASN details including upstream/downstream relationships."""
        ts = datetime.now(UTC)
        mock_ripe_stat.get_announced_prefixes = AsyncMock(return_value=["8.8.8.0/24"])
        mock_ripe_stat.get_bgp_state = AsyncMock(
            return_value=[
                BGPRoute(
                    prefix="8.8.8.0/24",
                    origin_asn=15169,
                    as_path=[64496, 3356, 15169],
                    collector="rrc00",
                    timestamp=ts,
                    source="ripe_stat",
                ),
                BGPRoute(
                    prefix="8.8.8.0/24",
                    origin_asn=15169,
                    as_path=[64497, 174, 15169],
                    collector="rrc01",
                    timestamp=ts,
                    source="ripe_stat",
                ),
            ]
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat)

        result = await tools.get_asn_details(15169)

        assert "Upstream Providers" in result
        assert "Routing Behavior" in result


def _make_probe_result(
    city: str = "Unknown",
    country: str = "XX",
    avg_latency: float | None = None,
    packet_loss: float | None = None,
    hops: list | None = None,
) -> ProbeResult:
    """Helper to create ProbeResult with correct fields."""
    return ProbeResult(
        continent="",
        country=country,
        city=city,
        asn=0,
        network="",
        status="finished" if avg_latency or hops else "failed",
        raw_output="",
        min_latency=avg_latency,
        avg_latency=avg_latency,
        max_latency=avg_latency,
        packet_loss=packet_loss,
        hops=hops,
    )


def _make_measurement_result(
    measurement_id: str,
    measurement_type: str = "ping",
    target: str = "8.8.8.8",
    probes: list[ProbeResult] | None = None,
) -> MeasurementResult:
    """Helper to create MeasurementResult with correct fields."""
    return MeasurementResult(
        measurement_id=measurement_id,
        measurement_type=measurement_type,
        target=target,
        status="finished",
        probes=probes or [],
    )


class TestPingFromGlobal:
    """Tests for ping_from_global tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def mock_globalping(self):
        """Create mock Globalping client."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_ping_without_globalping(self, mock_ripe_stat):
        """Test ping when Globalping is not configured."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=None)

        result = await tools.ping_from_global("8.8.8.8")

        assert "Globalping is not configured" in result

    @pytest.mark.asyncio
    async def test_ping_success(self, mock_ripe_stat, mock_globalping):
        """Test successful ping measurement."""
        mock_globalping.ping = AsyncMock(
            return_value=_make_measurement_result(
                measurement_id="test-123",
                probes=[
                    _make_probe_result(city="New York", country="US", avg_latency=25.5),
                    _make_probe_result(city="London", country="GB", avg_latency=85.2),
                ],
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.ping_from_global("8.8.8.8")

        assert "Global Ping Results: 8.8.8.8" in result
        assert "Measurement ID:** test-123" in result
        assert "New York" in result
        assert "London" in result
        assert "25.50ms" in result

    @pytest.mark.asyncio
    async def test_ping_no_results(self, mock_ripe_stat, mock_globalping):
        """Test ping with no results."""
        mock_globalping.ping = AsyncMock(
            return_value=_make_measurement_result(measurement_id="test-123", probes=[])
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.ping_from_global("8.8.8.8")

        assert "No ping results received" in result

    @pytest.mark.asyncio
    async def test_ping_with_packet_loss(self, mock_ripe_stat, mock_globalping):
        """Test ping showing packet loss."""
        mock_globalping.ping = AsyncMock(
            return_value=_make_measurement_result(
                measurement_id="test-123",
                probes=[
                    _make_probe_result(
                        city="Tokyo",
                        country="JP",
                        avg_latency=150.0,
                        packet_loss=25.0,
                    ),
                ],
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.ping_from_global("example.com")

        assert "Tokyo" in result
        assert "25.0% loss" in result

    @pytest.mark.asyncio
    async def test_ping_no_probes_available(self, mock_ripe_stat, mock_globalping):
        """Test ping when no probes are available in requested location."""
        mock_globalping.ping = AsyncMock(
            side_effect=ValueError(
                "No probes available in requested location(s): US. "
                "Try a different region like 'Europe', 'Asia', or specific countries like 'DE', 'GB', 'JP'."
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.ping_from_global("8.8.8.8", locations=["US"])

        # Should include error message and tell AI to ask user for alternatives
        assert "PROBE AVAILABILITY ERROR" in result
        assert "No probes available" in result
        assert "US" in result
        assert "MUST ask the user" in result
        assert "Suggest alternatives" in result


class TestTracerouteFromGlobal:
    """Tests for traceroute_from_global tool."""

    @pytest.fixture
    def mock_ripe_stat(self):
        """Create mock RIPE Stat client."""
        return AsyncMock()

    @pytest.fixture
    def mock_globalping(self):
        """Create mock Globalping client."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_traceroute_without_globalping(self, mock_ripe_stat):
        """Test traceroute when Globalping is not configured."""
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=None)

        result = await tools.traceroute_from_global("8.8.8.8")

        assert "Globalping is not configured" in result

    @pytest.mark.asyncio
    async def test_traceroute_success(self, mock_ripe_stat, mock_globalping):
        """Test successful traceroute measurement."""
        mock_globalping.traceroute = AsyncMock(
            return_value=_make_measurement_result(
                measurement_id="test-456",
                measurement_type="traceroute",
                probes=[
                    _make_probe_result(
                        city="Paris",
                        country="FR",
                        hops=[
                            {"hop": 1, "host": "192.168.1.1", "rtt": 1.5},
                            {"hop": 2, "host": "10.0.0.1", "rtt": 5.2},
                            {"hop": 3, "host": "8.8.8.8", "rtt": 15.0},
                        ],
                    ),
                ],
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.traceroute_from_global("8.8.8.8")

        assert "Global Traceroute Results: 8.8.8.8" in result
        assert "Measurement ID:** test-456" in result
        assert "Paris" in result
        assert "192.168.1.1" in result
        assert "1.50ms" in result

    @pytest.mark.asyncio
    async def test_traceroute_no_results(self, mock_ripe_stat, mock_globalping):
        """Test traceroute with no results."""
        mock_globalping.traceroute = AsyncMock(
            return_value=_make_measurement_result(
                measurement_id="test-456",
                measurement_type="traceroute",
                probes=[],
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.traceroute_from_global("8.8.8.8")

        assert "No traceroute results received" in result

    @pytest.mark.asyncio
    async def test_traceroute_with_missing_hops(self, mock_ripe_stat, mock_globalping):
        """Test traceroute with missing hops (asterisks)."""
        mock_globalping.traceroute = AsyncMock(
            return_value=_make_measurement_result(
                measurement_id="test-456",
                measurement_type="traceroute",
                probes=[
                    _make_probe_result(
                        city="Berlin",
                        country="DE",
                        hops=[
                            {"hop": 1, "host": "192.168.1.1", "rtt": 1.0},
                            {"hop": 2, "host": "*"},  # Missing hop
                            {"hop": 3, "host": "8.8.8.8", "rtt": 20.0},
                        ],
                    ),
                ],
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.traceroute_from_global("8.8.8.8")

        assert "Berlin" in result
        assert "2. *" in result  # Shows missing hop

    @pytest.mark.asyncio
    async def test_traceroute_no_probes_available(self, mock_ripe_stat, mock_globalping):
        """Test traceroute when no probes are available in requested location."""
        mock_globalping.traceroute = AsyncMock(
            side_effect=ValueError(
                "No probes available in requested location(s): US. "
                "Try a different region like 'Europe', 'Asia', or specific countries like 'DE', 'GB', 'JP'."
            )
        )
        tools = BGPTools(ripe_stat=mock_ripe_stat, globalping=mock_globalping)

        result = await tools.traceroute_from_global("8.8.8.8", locations=["US"])

        # Should include error message and tell AI to ask user for alternatives
        assert "PROBE AVAILABILITY ERROR" in result
        assert "No probes available" in result
        assert "US" in result
        assert "MUST ask the user" in result
        assert "Suggest alternatives" in result
