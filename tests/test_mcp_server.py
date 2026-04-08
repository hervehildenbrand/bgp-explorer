"""Tests for MCP server input validation and output consistency."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer import mcp_server
from bgp_explorer.ai.tools import BGPTools


class TestGetRpkiStatus:
    """Tests for get_rpki_status MCP tool."""

    @pytest.mark.asyncio
    async def test_rpki_valid_shows_valid_not_ok(self):
        """Test that RPKI valid status shows 'VALID' not 'OK' for consistency."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "valid",
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "validating_roas": [{"origin": "15169", "prefix": "8.8.8.0/24", "max_length": 24}],
            }
        )

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
        result = await mcp_server.get_routing_history("8.8.8.0/24", "2026-02-06", "2026-02-01")
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_bgp_path_history_reversed_dates(self):
        """Test that reversed dates are rejected in mcp get_bgp_path_history."""
        result = await mcp_server.get_bgp_path_history("8.8.8.0/24", "2026-02-06", "2026-02-01")
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_routing_history_reversed_dates(self):
        """Test that reversed dates are rejected in ai/tools get_routing_history."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.get_routing_history("8.8.8.0/24", "2026-02-06", "2026-02-01")
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_tools_bgp_path_history_reversed_dates(self):
        """Test that reversed dates are rejected in ai/tools get_bgp_path_history."""
        tools = BGPTools(ripe_stat=AsyncMock(), bgp_radar=AsyncMock())
        result = await tools.get_bgp_path_history("8.8.8.0/24", "2026-02-06", "2026-02-01")
        assert "after" in result.lower() or "invalid date range" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_routing_history_valid_dates_accepted(self):
        """Test that valid date order is accepted."""
        mock_client = AsyncMock()
        mock_client.get_routing_history = AsyncMock(return_value={"by_origin": []})

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_routing_history("8.8.8.0/24", "2026-02-01", "2026-02-06")

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

        assert (
            "documentation" in result.lower()
            or "rfc" in result.lower()
            or "bogon" in result.lower()
        )
        assert "cannot be probed" in result.lower() or "not routable" in result.lower()

    @pytest.mark.asyncio
    async def test_traceroute_bogon_returns_friendly_error(self):
        """Traceroute to bogon address should return user-friendly message."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.traceroute_from_global("192.0.2.1")

        assert (
            "documentation" in result.lower()
            or "rfc" in result.lower()
            or "bogon" in result.lower()
        )
        assert "cannot be probed" in result.lower() or "not routable" in result.lower()

    @pytest.mark.asyncio
    async def test_ping_test_net2_returns_friendly_error(self):
        """198.51.100.0/24 (TEST-NET-2) should also be caught."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.ping_from_global("198.51.100.1")

        assert (
            "documentation" in result.lower()
            or "rfc" in result.lower()
            or "bogon" in result.lower()
        )

    @pytest.mark.asyncio
    async def test_ping_test_net3_returns_friendly_error(self):
        """203.0.113.0/24 (TEST-NET-3) should also be caught."""
        with patch.object(mcp_server, "get_globalping", return_value=AsyncMock()):
            result = await mcp_server.ping_from_global("203.0.113.1")

        assert (
            "documentation" in result.lower()
            or "rfc" in result.lower()
            or "bogon" in result.lower()
        )

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


class TestRpkiStatusRoaDetails:
    """Tests for get_rpki_status ROA detail output."""

    @pytest.mark.asyncio
    async def test_rpki_valid_shows_roa_details(self):
        """Test that RPKI valid status shows ROA maxLength details."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "valid",
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "validating_roas": [
                    {
                        "origin": "15169",
                        "prefix": "8.8.8.0/24",
                        "max_length": 24,
                        "validity": "valid",
                    }
                ],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("8.8.8.0/24", 15169)

        assert "VALID" in result
        assert "ROA" in result
        assert "maxLength" in result or "max_length" in result or "/24" in result

    @pytest.mark.asyncio
    async def test_rpki_valid_shows_subprefix_exposure_warning(self):
        """Test that ROA with maxLength > prefix shows sub-prefix exposure warning."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "valid",
                "prefix": "192.0.2.0/21",
                "origin_asn": 64496,
                "validating_roas": [
                    {
                        "origin": "64496",
                        "prefix": "192.0.2.0/21",
                        "max_length": 24,
                        "validity": "valid",
                    }
                ],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("192.0.2.0/21", 64496)

        assert "sub-prefix" in result.lower() or "Sub-prefix" in result

    @pytest.mark.asyncio
    async def test_rpki_not_found_no_roa_section(self):
        """Test that not-found status shows no ROA details section."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "not-found",
                "prefix": "10.0.0.0/8",
                "origin_asn": 64496,
                "validating_roas": [],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("10.0.0.0/8", 64496)

        assert "NOT FOUND" in result
        assert "No ROA found" in result


class TestCheckRpkiForAsnPerPrefix:
    """Tests for check_rpki_for_asn per-prefix breakdown."""

    @pytest.mark.asyncio
    async def test_shows_all_prefix_groups(self):
        """Test that all three status groups (valid/invalid/not-found) list prefixes."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(
            return_value=["8.8.8.0/24", "8.8.4.0/24", "1.2.3.0/24", "10.0.0.0/8"]
        )

        async def mock_detail(prefix, origin_asn):
            mapping = {
                "8.8.8.0/24": {
                    "status": "valid",
                    "prefix": "8.8.8.0/24",
                    "origin_asn": origin_asn,
                    "validating_roas": [
                        {"origin": str(origin_asn), "prefix": "8.8.8.0/24", "max_length": 24}
                    ],
                },
                "8.8.4.0/24": {
                    "status": "valid",
                    "prefix": "8.8.4.0/24",
                    "origin_asn": origin_asn,
                    "validating_roas": [
                        {"origin": str(origin_asn), "prefix": "8.8.4.0/24", "max_length": 24}
                    ],
                },
                "1.2.3.0/24": {
                    "status": "invalid",
                    "prefix": "1.2.3.0/24",
                    "origin_asn": origin_asn,
                    "validating_roas": [
                        {"origin": "99999", "prefix": "1.2.3.0/24", "max_length": 24}
                    ],
                },
                "10.0.0.0/8": {
                    "status": "not-found",
                    "prefix": "10.0.0.0/8",
                    "origin_asn": origin_asn,
                    "validating_roas": [],
                },
            }
            return mapping[prefix]

        mock_client.get_rpki_validation_detail = AsyncMock(side_effect=mock_detail)

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.check_rpki_for_asn(15169)

        # All three sections should exist
        assert "**VALID prefixes" in result
        assert "**INVALID prefixes" in result
        assert "**NOT FOUND prefixes" in result
        # Specific prefixes should appear in the right sections
        assert "8.8.8.0/24" in result
        assert "1.2.3.0/24" in result
        assert "10.0.0.0/8" in result
        # ROA maxLength should be shown for valid prefixes
        assert "/24" in result

    @pytest.mark.asyncio
    async def test_shows_roa_maxlength_per_prefix(self):
        """Test that valid prefixes show ROA maxLength."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(return_value=["8.8.8.0/24"])
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "valid",
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "validating_roas": [{"origin": "15169", "prefix": "8.8.8.0/24", "max_length": 24}],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.check_rpki_for_asn(15169)

        assert "maxLength" in result or "max_length" in result or "ROA" in result


class TestGetWhoisData:
    """Tests for get_whois_data MCP tool."""

    @pytest.mark.asyncio
    async def test_whois_asn_shows_registration(self):
        """Test WHOIS for ASN shows registration info."""
        mock_client = AsyncMock()
        mock_client.get_whois_data = AsyncMock(
            return_value={
                "records": [
                    [
                        {"key": "ASNumber", "value": "15169"},
                        {"key": "ASName", "value": "GOOGLE"},
                        {"key": "OrgName", "value": "Google LLC"},
                        {"key": "Country", "value": "US"},
                    ]
                ],
                "irr_records": [],
                "authorities": ["arin"],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_whois_data("AS15169")

        assert "GOOGLE" in result
        assert "Google LLC" in result or "15169" in result
        assert "arin" in result.lower() or "ARIN" in result

    @pytest.mark.asyncio
    async def test_whois_prefix_shows_irr_records(self):
        """Test WHOIS for prefix shows IRR route objects."""
        mock_client = AsyncMock()
        mock_client.get_whois_data = AsyncMock(
            return_value={
                "records": [
                    [
                        {"key": "inetnum", "value": "193.0.0.0 - 193.0.7.255"},
                        {"key": "netname", "value": "RIPE-NCC"},
                    ]
                ],
                "irr_records": [
                    [
                        {"key": "route", "value": "193.0.0.0/21"},
                        {"key": "origin", "value": "AS3333"},
                        {"key": "source", "value": "RIPE"},
                        {"key": "mnt-by", "value": "RIPE-NCC-MNT"},
                    ]
                ],
                "authorities": ["ripe"],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_whois_data("193.0.0.0/21")

        assert "193.0.0.0/21" in result
        assert "AS3333" in result
        assert "RIPE" in result
        assert "IRR" in result

    @pytest.mark.asyncio
    async def test_whois_empty_irr_records(self):
        """Test WHOIS with no IRR records shows none found."""
        mock_client = AsyncMock()
        mock_client.get_whois_data = AsyncMock(
            return_value={
                "records": [
                    [{"key": "ASNumber", "value": "64496"}, {"key": "ASName", "value": "EXAMPLE"}]
                ],
                "irr_records": [],
                "authorities": ["arin"],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_whois_data("AS64496")

        assert "none" in result.lower() or "no IRR" in result.lower() or "No IRR" in result

    @pytest.mark.asyncio
    async def test_whois_empty_resource_rejected(self):
        """Test that empty resource is rejected."""
        result = await mcp_server.get_whois_data("")
        assert "provide" in result.lower() or "non-empty" in result.lower()


class TestRpkiStatusNotFound:
    """P2: get_rpki_status should show NOT FOUND not UNKNOWN for missing ROAs."""

    @pytest.mark.asyncio
    async def test_rpki_not_found_shows_not_found_label(self):
        """When RIPE returns 'not-found', display should say NOT FOUND not UNKNOWN."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "not-found",
                "prefix": "192.0.2.0/24",
                "origin_asn": 1,
                "validating_roas": [],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("192.0.2.0/24", 1)

        assert "NOT FOUND" in result
        assert "UNKNOWN" not in result

    @pytest.mark.asyncio
    async def test_rpki_unknown_status_shows_not_found(self):
        """When RIPE returns 'unknown' (e.g. for bogon prefixes), show NOT FOUND."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "unknown",
                "prefix": "192.0.2.0/24",
                "origin_asn": 1,
                "validating_roas": [],
            }
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_rpki_status("192.0.2.0/24", 1)

        assert "NOT FOUND" in result
        assert "UNKNOWN" not in result

    @pytest.mark.asyncio
    async def test_rpki_unexpected_status_shows_unknown(self):
        """Truly unexpected status values should show UNKNOWN."""
        mock_client = AsyncMock()
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "something-unexpected",
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "validating_roas": [],
            }
        )

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

        with patch.object(mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)):
            result = await mcp_server.verify_aspa_path("13335,174,15169")

        assert "VALID" in result
        assert "authorized" in result
        assert "AS13335" in result
        assert "AS174" in result
        assert "AS15169" in result

    @pytest.mark.asyncio
    async def test_mcp_verify_aspa_path_no_monocle(self):
        """Test that missing monocle returns helpful error message."""
        with patch.object(mcp_server, "get_aspa_validator", AsyncMock(return_value=None)):
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

        with patch.object(mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)):
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
            patch.object(mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)),
        ):
            result = await mcp_server.check_prefix_anomalies("8.8.8.0/24")

        assert "ASPA" in result


class TestCheckMANRSReadiness:
    """Tests for check_manrs MCP tool."""

    @pytest.mark.asyncio
    async def test_basic_assessment(self):
        """Tool returns MANRS readiness assessment."""
        mock_ripe = AsyncMock()
        mock_ripe.get_announced_prefixes = AsyncMock(return_value=["1.0.0.0/24"])
        mock_ripe.get_rpki_validation = AsyncMock(return_value="valid")
        mock_ripe.get_bgp_state = AsyncMock(return_value=[])

        mock_rpki = AsyncMock()
        mock_rpki.has_aspa = AsyncMock(return_value=True)

        mock_peeringdb = MagicMock()
        mock_peeringdb.get_network_by_asn = MagicMock(
            return_value={"poc_set": [{"email": "noc@example.com"}]}
        )

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_ripe),
            patch.object(mcp_server, "get_rpki_console", return_value=mock_rpki),
            patch.object(mcp_server, "get_peeringdb", return_value=mock_peeringdb),
        ):
            result = await mcp_server.check_manrs(asn=64496)

        assert "MANRS" in result
        assert "AS64496" in result
        assert "Action 1" in result or "Filtering" in result

    @pytest.mark.asyncio
    async def test_json_output(self):
        """Tool returns valid JSON when requested."""
        mock_ripe = AsyncMock()
        mock_ripe.get_announced_prefixes = AsyncMock(return_value=[])

        mock_rpki = AsyncMock()
        mock_rpki.has_aspa = AsyncMock(return_value=False)

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_ripe),
            patch.object(mcp_server, "get_rpki_console", return_value=mock_rpki),
            patch.object(mcp_server, "get_peeringdb", return_value=None),
        ):
            result = await mcp_server.check_manrs(asn=64496, output_format="json")

        data = json.loads(result)
        assert data["asn"] == 64496
        assert "overall_readiness" in data
        assert "action_findings" in data


class TestGetMANRSStatus:
    """Tests for get_manrs_info MCP tool."""

    @pytest.mark.asyncio
    async def test_no_api_key(self):
        """Tool returns helpful message when no API key configured."""
        with patch.object(mcp_server, "get_manrs_client", return_value=None):
            result = await mcp_server.get_manrs_info(asn=13335)

        assert "MANRS_API_KEY" in result
        assert "check_manrs" in result

    @pytest.mark.asyncio
    async def test_participant_found(self):
        """Tool returns conformance data for a MANRS participant."""
        from bgp_explorer.models.manrs import MANRSConformance, MANRSReadiness

        mock_client = AsyncMock()
        mock_client.get_asn_conformance = AsyncMock(
            return_value=MANRSConformance(
                asn=13335,
                name="Cloudflare, Inc.",
                country="US",
                status="ready",
                action1_filtering=MANRSReadiness.READY,
                action2_anti_spoofing=MANRSReadiness.READY,
                action3_coordination=MANRSReadiness.READY,
                action4_validation=MANRSReadiness.READY,
                last_updated="2026-04-01",
                manrs_participant=True,
            )
        )

        with patch.object(mcp_server, "get_manrs_client", return_value=mock_client):
            result = await mcp_server.get_manrs_info(asn=13335)

        assert "AS13335" in result
        assert "Cloudflare" in result
        assert "READY" in result.upper()

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Tool returns appropriate message for non-participant."""
        mock_client = AsyncMock()
        mock_client.get_asn_conformance = AsyncMock(return_value=None)

        with patch.object(mcp_server, "get_manrs_client", return_value=mock_client):
            result = await mcp_server.get_manrs_info(asn=99999)

        assert "not found" in result.lower() or "not a MANRS" in result


class TestComplianceAuditMANRS:
    """Tests for MANRS support in run_compliance_audit."""

    @pytest.mark.asyncio
    async def test_manrs_framework(self):
        """run_compliance_audit accepts framework='manrs'."""
        mock_ripe = AsyncMock()
        mock_ripe.get_announced_prefixes = AsyncMock(return_value=["1.0.0.0/24"])
        mock_ripe.get_rpki_validation = AsyncMock(return_value="valid")
        mock_ripe.get_bgp_state = AsyncMock(return_value=[])
        mock_ripe.get_whois = AsyncMock(return_value={})

        mock_rpki = AsyncMock()
        mock_rpki.has_aspa = AsyncMock(return_value=False)

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_ripe),
            patch.object(mcp_server, "get_rpki_console", return_value=mock_rpki),
            patch.object(mcp_server, "get_peeringdb", return_value=None),
        ):
            result = await mcp_server.run_compliance_audit(asn=64496, framework="manrs")

        assert "MANRS" in result
        assert "AS64496" in result
