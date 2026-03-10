"""Tests for MCP server input validation and output consistency."""

from unittest.mock import AsyncMock, patch

import pytest

from bgp_explorer import mcp_server
from bgp_explorer.ai.tools import BGPTools


class TestGetRpkiStatus:
    """Tests for get_rpki_status MCP tool."""

    @pytest.mark.asyncio
    async def test_rpki_valid_shows_valid_not_ok(self):
        """Test that RPKI valid status shows 'VALID' not 'OK' for consistency."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation = AsyncMock(return_value="valid")

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("8.8.8.0/24", 15169)

        assert "VALID" in result
        assert "OK" not in result


class TestSearchAsn:
    """Tests for search_asn input validation."""

    @pytest.mark.asyncio
    async def test_mcp_empty_query_returns_error(self):
        """Test that empty query returns helpful error instead of 33k results."""
        result = await mcp_server.search_asn("")
        assert "non-empty" in result.lower() or "provide" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_whitespace_query_returns_error(self):
        """Test that whitespace-only query returns helpful error."""
        result = await mcp_server.search_asn("   ")
        assert "non-empty" in result.lower() or "provide" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_empty_query_returns_error(self):
        """Test that empty query returns helpful error in ai/tools.py."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.search_asn("")
        assert "non-empty" in result.lower() or "provide" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_whitespace_query_returns_error(self):
        """Test that whitespace-only query returns helpful error in ai/tools.py."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.search_asn("   ")
        assert "non-empty" in result.lower() or "provide" in result.lower()


class TestLookupPrefix:
    """Tests for lookup_prefix input validation."""

    @pytest.mark.asyncio
    async def test_mcp_rejects_prefix_without_cidr(self):
        """Test that prefix without CIDR slash is rejected."""
        result = await mcp_server.lookup_prefix("8.8.8.0")
        assert "CIDR" in result or "cidr" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_accepts_valid_cidr(self):
        """Test that valid CIDR prefix is accepted (doesn't hit the guard)."""
        mock_client = AsyncMock()
        mock_client.get_bgp_state = AsyncMock(return_value=[])

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.lookup_prefix("8.8.8.0/24")

        # Should not contain CIDR error
        assert "CIDR" not in result

    @pytest.mark.asyncio
    async def test_tools_rejects_prefix_without_cidr(self):
        """Test that prefix without CIDR slash is rejected in ai/tools.py."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.lookup_prefix("8.8.8.0")
        assert "CIDR" in result or "cidr" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_accepts_ipv6_cidr(self):
        """Test that valid IPv6 CIDR prefix is accepted."""
        mock_ripe = AsyncMock()
        mock_ripe.get_bgp_state = AsyncMock(return_value=[])
        tools = BGPTools(ripe_stat=mock_ripe, bgp_radar=AsyncMock())
        result = await tools.lookup_prefix("2001:db8::/32")
        assert "CIDR" not in result


class TestDateRangeValidation:
    """Tests for date range validation in routing history tools."""

    @pytest.mark.asyncio
    async def test_mcp_routing_history_reversed_dates(self):
        """Test that reversed dates are rejected in mcp get_routing_history."""
        result = await mcp_server.get_routing_history(
            "8.8.8.0/24", "2026-02-06", "2026-02-01"
        )
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_bgp_path_history_reversed_dates(self):
        """Test that reversed dates are rejected in mcp get_bgp_path_history."""
        result = await mcp_server.get_bgp_path_history(
            "8.8.8.0/24", "2026-02-06", "2026-02-01"
        )
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_routing_history_reversed_dates(self):
        """Test that reversed dates are rejected in ai/tools get_routing_history."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.get_routing_history(
            "8.8.8.0/24", "2026-02-06", "2026-02-01"
        )
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_bgp_path_history_reversed_dates(self):
        """Test that reversed dates are rejected in ai/tools get_bgp_path_history."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.get_bgp_path_history(
            "8.8.8.0/24", "2026-02-06", "2026-02-01"
        )
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_routing_history_valid_dates_accepted(self):
        """Test that valid date order is accepted."""
        mock_client = AsyncMock()
        mock_client.get_routing_history = AsyncMock(return_value={"by_origin": []})

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_routing_history(
                "8.8.8.0/24", "2026-02-01", "2026-02-06"
            )

        assert "invalid date range" not in result.lower()


class TestGetAsUpstreamsNonExistentAsn:
    """P2: get_as_upstreams should not say 'Tier 1' for non-existent ASNs."""

    @pytest.mark.asyncio
    async def test_nonexistent_asn_does_not_say_tier1(self):
        """Non-existent ASN with no relationships should not be called Tier 1."""
        mock_monocle = AsyncMock()
        # No upstreams
        mock_monocle.get_as_upstreams = AsyncMock(return_value=[])
        # No relationships of any kind (non-existent ASN)
        mock_monocle.get_as_relationships = AsyncMock(return_value=[])

        with patch.object(mcp_server, "get_monocle", return_value=mock_monocle):
            result = await mcp_server.get_as_upstreams(9999999)

        assert "tier 1" not in result.lower()
        assert "transit-free" not in result.lower()
        assert "no data" in result.lower() or "does not exist" in result.lower()

    @pytest.mark.asyncio
    async def test_real_tier1_still_says_transit_free(self):
        """A real Tier 1 (has peers/downstreams but no upstreams) should still get the message."""
        mock_monocle = AsyncMock()
        mock_monocle.get_as_upstreams = AsyncMock(return_value=[])
        # Has relationships (peers/downstreams exist)
        mock_monocle.get_as_relationships = AsyncMock(
            return_value=[AsyncMock(relationship_type="peer")]
        )

        with patch.object(mcp_server, "get_monocle", return_value=mock_monocle):
            result = await mcp_server.get_as_upstreams(3356)

        assert "transit-free" in result.lower() or "tier 1" in result.lower()


class TestGlobalpingBogonDetection:
    """P2: Globalping tools should reject bogon targets with clear message."""

    @pytest.mark.asyncio
    async def test_ping_bogon_returns_friendly_error(self):
        """Ping to bogon address should return user-friendly message."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.ping_from_global("192.0.2.1")

        assert "documentation" in result.lower() or "rfc" in result.lower() or "bogon" in result.lower()
        assert "cannot be probed" in result.lower() or "not routable" in result.lower()

    @pytest.mark.asyncio
    async def test_traceroute_bogon_returns_friendly_error(self):
        """Traceroute to bogon address should return user-friendly message."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.traceroute_from_global("192.0.2.1")

        assert "documentation" in result.lower() or "rfc" in result.lower() or "bogon" in result.lower()
        assert "cannot be probed" in result.lower() or "not routable" in result.lower()

    @pytest.mark.asyncio
    async def test_ping_test_net2_returns_friendly_error(self):
        """198.51.100.0/24 (TEST-NET-2) should also be caught."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.ping_from_global("198.51.100.1")

        assert "documentation" in result.lower() or "rfc" in result.lower() or "bogon" in result.lower()

    @pytest.mark.asyncio
    async def test_ping_test_net3_returns_friendly_error(self):
        """203.0.113.0/24 (TEST-NET-3) should also be caught."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.ping_from_global("203.0.113.1")

        assert "documentation" in result.lower() or "rfc" in result.lower() or "bogon" in result.lower()

    @pytest.mark.asyncio
    async def test_ping_valid_target_not_rejected(self):
        """Valid targets should not be rejected by bogon check."""
        mock_globalping = AsyncMock()
        mock_result = AsyncMock()
        mock_result.probes = []
        mock_globalping.ping = AsyncMock(return_value=mock_result)

        with patch.object(mcp_server, "get_globalping", return_value=mock_globalping):
            result = await mcp_server.ping_from_global("8.8.8.8")

        assert "rfc" not in result.lower()
        assert "bogon" not in result.lower()


class TestRpkiStatusNotFound:
    """P2: get_rpki_status should show NOT FOUND not UNKNOWN for missing ROAs."""

    @pytest.mark.asyncio
    async def test_rpki_not_found_shows_not_found_label(self):
        """When RIPE returns 'not-found', display should say NOT FOUND not UNKNOWN."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation = AsyncMock(return_value="not-found")

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("192.0.2.0/24", 1)

        assert "NOT FOUND" in result
        assert "UNKNOWN" not in result

    @pytest.mark.asyncio
    async def test_rpki_unknown_status_shows_not_found(self):
        """When RIPE returns 'unknown' (e.g. for bogon prefixes), show NOT FOUND."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation = AsyncMock(return_value="unknown")

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("192.0.2.0/24", 1)

        assert "NOT FOUND" in result
        assert "UNKNOWN" not in result

    @pytest.mark.asyncio
    async def test_rpki_unexpected_status_shows_unknown(self):
        """Truly unexpected status values should show UNKNOWN."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation = AsyncMock(return_value="something-unexpected")

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("8.8.8.0/24", 15169)

        assert "UNKNOWN" in result


class TestConnectivitySummaryPeerCount:
    """P2: get_as_connectivity_summary should clarify total peer counts."""

    @pytest.mark.asyncio
    async def test_peers_section_shows_total_count(self):
        """Peers section should show total count, not just the samples shown."""
        mock_monocle = AsyncMock()

        # Create 10 mock peers (more than the 5 shown)
        mock_peers = []
        for i in range(10):
            peer = AsyncMock()
            peer.asn = 100 + i
            peer.name = f"Peer{i}"
            peer.peers_percent = 50.0 - i
            mock_peers.append(peer)

        mock_connectivity = AsyncMock()
        mock_connectivity.total_neighbors = 100
        mock_connectivity.max_visibility = 1700
        mock_connectivity.upstreams = []
        mock_connectivity.peers = mock_peers
        mock_connectivity.downstreams = []
        mock_monocle.get_connectivity = AsyncMock(return_value=mock_connectivity)

        with patch.object(mcp_server, "get_monocle", return_value=mock_monocle):
            result = await mcp_server.get_as_connectivity_summary(15169)

        # Should show "10" (total count) in the Peers header, not just "5"
        assert "**Peers:** 10" in result or "Peers (10" in result
        # Should indicate top 5 are shown
        assert "showing top" in result.lower() or "... and 5 more" in result


class TestVerifyAspaPath:
    """Tests for verify_aspa_path MCP tool."""

    @pytest.mark.asyncio
    async def test_mcp_verify_aspa_path_valid(self):
        """Test that valid ASPA path shows VALID state and authorized hops."""
        from bgp_explorer.models.aspa import ASPAHopResult, ASPAState, ASPAValidationResult

        mock_validator = AsyncMock()
        mock_validator.validate_path = AsyncMock(
            return_value=ASPAValidationResult(
                as_path=[13335, 174, 15169],
                state=ASPAState.VALID,
                hop_results=[
                    ASPAHopResult(
                        asn=13335,
                        next_asn=174,
                        is_authorized_provider=True,
                        relationship_type="upstream",
                        data_source="monocle",
                        confidence=0.7,
                    ),
                    ASPAHopResult(
                        asn=174,
                        next_asn=15169,
                        is_authorized_provider=True,
                        relationship_type="upstream",
                        data_source="monocle",
                        confidence=0.7,
                    ),
                ],
                valley_free=True,
                issues=[],
                summary="Path is valid",
            )
        )

        with patch.object(
            mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)
        ):
            result = await mcp_server.verify_aspa_path("13335,174,15169")

        assert "VALID" in result
        assert "authorized" in result
        assert "AS13335" in result
        assert "AS174" in result
        assert "AS15169" in result

    @pytest.mark.asyncio
    async def test_mcp_verify_aspa_path_no_monocle(self):
        """Test that missing monocle returns helpful error message."""
        with patch.object(
            mcp_server, "get_aspa_validator", AsyncMock(return_value=None)
        ):
            result = await mcp_server.verify_aspa_path("13335,174,15169")

        assert "Monocle" in result
        assert "cargo install monocle" in result

    @pytest.mark.asyncio
    async def test_mcp_verify_aspa_path_invalid_format(self):
        """Test that non-numeric AS path returns format error."""
        from bgp_explorer.models.aspa import ASPAState, ASPAValidationResult

        # Validator must be non-None to pass the None check
        mock_validator = AsyncMock()
        mock_validator.validate_path = AsyncMock(
            return_value=ASPAValidationResult(
                as_path=[],
                state=ASPAState.UNKNOWN,
                hop_results=[],
                valley_free=True,
                issues=[],
                summary="",
            )
        )

        with patch.object(
            mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)
        ):
            result = await mcp_server.verify_aspa_path("abc,def")

        assert "Invalid AS path format" in result or "valid AS path" in result

    @pytest.mark.asyncio
    async def test_mcp_check_prefix_anomalies_includes_aspa(self):
        """Test that check_prefix_anomalies includes ASPA validation section."""
        from datetime import UTC, datetime

        from bgp_explorer.models.aspa import ASPAHopResult, ASPAState, ASPAValidationResult
        from bgp_explorer.models.route import BGPRoute

        # Create 12 routes (>= 10 for normal visibility)
        routes = [
            BGPRoute(
                prefix="8.8.8.0/24",
                origin_asn=15169,
                as_path=[3356, 15169],
                collector=f"rrc{i:02d}",
                timestamp=datetime.now(UTC),
                source="ripe_stat",
            )
            for i in range(12)
        ]

        mock_client = AsyncMock()
        mock_client.get_bgp_state = AsyncMock(return_value=routes)
        mock_client.get_rpki_validation = AsyncMock(return_value="valid")
        mock_client.get_routing_history = AsyncMock(
            return_value={"by_origin": [{"origin": "15169"}]}
        )

        mock_validator = AsyncMock()
        mock_validator.validate_path = AsyncMock(
            return_value=ASPAValidationResult(
                as_path=[3356, 15169],
                state=ASPAState.VALID,
                hop_results=[
                    ASPAHopResult(
                        asn=3356,
                        next_asn=15169,
                        is_authorized_provider=True,
                        relationship_type="upstream",
                        data_source="monocle",
                        confidence=0.7,
                    ),
                ],
                valley_free=True,
                issues=[],
                summary="Path is valid",
            )
        )

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(
                mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)
            ),
        ):
            result = await mcp_server.check_prefix_anomalies("8.8.8.0/24")

        assert "ASPA" in result
