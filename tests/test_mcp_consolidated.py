"""Tests for consolidated MCP server tools (36 → 10 tool consolidation)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer import mcp_server
from bgp_explorer.mcp_server import parse_sections, build_response


# =============================================================================
# parse_sections tests
# =============================================================================


class TestParseSections:
    """Tests for the section parsing helper."""

    def test_none_returns_defaults(self):
        result = parse_sections(None, {"a", "b", "c"}, ["a"])
        assert result == ["a"]

    def test_valid_sections_accepted(self):
        result = parse_sections(["a", "c"], {"a", "b", "c"}, ["a"])
        assert result == ["a", "c"]

    def test_invalid_section_returns_error(self):
        """Invalid sections should return a string error, not raise."""
        result = parse_sections(["invalid"], {"a", "b"}, ["a"])
        assert isinstance(result, str)
        assert "invalid" in result.lower()

    def test_empty_list_returns_defaults(self):
        result = parse_sections([], {"a", "b"}, ["a"])
        assert result == ["a"]

    def test_preserves_order(self):
        result = parse_sections(["c", "a", "b"], {"a", "b", "c"}, ["a"])
        assert result == ["c", "a", "b"]

    def test_mixed_valid_invalid_returns_error(self):
        result = parse_sections(["a", "bogus"], {"a", "b"}, ["a"])
        assert isinstance(result, str)
        assert "bogus" in result.lower()


# =============================================================================
# build_response tests
# =============================================================================


class TestBuildResponse:
    """Tests for the response builder."""

    @pytest.mark.asyncio
    async def test_calls_handlers_in_order(self):
        call_order = []

        async def handler_a():
            call_order.append("a")
            return ["Section A"]

        async def handler_b():
            call_order.append("b")
            return ["Section B"]

        result = await build_response(["a", "b"], {"a": handler_a, "b": handler_b})
        assert call_order == ["a", "b"]
        assert "Section A" in result
        assert "Section B" in result

    @pytest.mark.asyncio
    async def test_skips_missing_handlers(self):
        async def handler_a():
            return ["Section A"]

        result = await build_response(["a", "missing"], {"a": handler_a})
        assert "Section A" in result

    @pytest.mark.asyncio
    async def test_joins_with_newlines(self):
        async def handler_a():
            return ["Line 1", "Line 2"]

        result = await build_response(["a"], {"a": handler_a})
        assert result == "Line 1\nLine 2"

    @pytest.mark.asyncio
    async def test_empty_sections(self):
        result = await build_response([], {})
        assert result == ""


# =============================================================================
# investigate_asn tests
# =============================================================================


def _mock_connectivity(upstreams=3, peers=10, downstreams=5):
    """Create a mock ASConnectivity object."""
    conn = MagicMock()
    conn.total_neighbors = upstreams + peers + downstreams
    conn.max_visibility = 1700
    conn.upstreams = [
        MagicMock(asn=100 + i, name=f"Upstream{i}", peers_percent=80.0 - i * 5)
        for i in range(upstreams)
    ]
    conn.peers = [
        MagicMock(asn=200 + i, name=f"Peer{i}", peers_percent=50.0 - i)
        for i in range(peers)
    ]
    conn.downstreams = [
        MagicMock(asn=300 + i, name=f"Downstream{i}", peers_percent=30.0 - i)
        for i in range(downstreams)
    ]
    return conn


class TestInvestigateAsn:
    """Tests for the investigate_asn composite tool."""

    @pytest.mark.asyncio
    async def test_summary_default_returns_overview(self):
        """Default (no sections) should return summary with prefix counts and connectivity."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(
            return_value=["8.8.8.0/24", "8.8.4.0/24", "2001:4860::/32"]
        )
        mock_client.get_as_overview = AsyncMock(
            return_value={"holder": "GOOGLE", "resource": "15169"}
        )

        mock_monocle = AsyncMock()
        mock_monocle.get_connectivity = AsyncMock(return_value=_mock_connectivity())

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_monocle", return_value=mock_monocle),
        ):
            result = await mcp_server.investigate_asn(15169)

        assert "AS15169" in result
        assert "3" in result  # total prefixes
        assert "IPv4" in result
        assert "IPv6" in result
        # Connectivity counts should be in summary
        assert "Upstream" in result or "upstream" in result
        assert "Peer" in result or "peer" in result

    @pytest.mark.asyncio
    async def test_invalid_section_returns_error(self):
        """Invalid section name should return helpful error."""
        result = await mcp_server.investigate_asn(15169, sections=["bogus"])
        assert "invalid" in result.lower() or "Invalid" in result

    @pytest.mark.asyncio
    async def test_connectivity_section(self):
        """Connectivity section should show full upstream/peer/downstream lists."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(return_value=["8.8.8.0/24"])
        mock_client.get_as_overview = AsyncMock(
            return_value={"holder": "GOOGLE", "resource": "15169"}
        )

        mock_monocle = AsyncMock()
        mock_monocle.get_connectivity = AsyncMock(return_value=_mock_connectivity())

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_monocle", return_value=mock_monocle),
        ):
            result = await mcp_server.investigate_asn(15169, sections=["connectivity"])

        assert "Upstream" in result
        assert "Peer" in result
        assert "Downstream" in result
        assert "visibility" in result.lower()

    @pytest.mark.asyncio
    async def test_whois_section(self):
        """Whois section should show registration data."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(return_value=["8.8.8.0/24"])
        mock_client.get_as_overview = AsyncMock(
            return_value={"holder": "GOOGLE", "resource": "15169"}
        )
        mock_client.get_whois_data = AsyncMock(
            return_value={
                "records": [[{"key": "ASName", "value": "GOOGLE"}]],
                "irr_records": [],
                "authorities": ["arin"],
            }
        )

        mock_monocle = AsyncMock()
        mock_monocle.get_connectivity = AsyncMock(return_value=_mock_connectivity())

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_monocle", return_value=mock_monocle),
        ):
            result = await mcp_server.investigate_asn(15169, sections=["whois"])

        assert "GOOGLE" in result
        assert "ARIN" in result or "arin" in result

    @pytest.mark.asyncio
    async def test_related_asn_shows_relationship(self):
        """related_asn parameter should show relationship info."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(return_value=["8.8.8.0/24"])
        mock_client.get_as_overview = AsyncMock(
            return_value={"holder": "GOOGLE", "resource": "15169"}
        )

        mock_monocle = AsyncMock()
        mock_monocle.get_connectivity = AsyncMock(return_value=_mock_connectivity())
        mock_rel = MagicMock()
        mock_rel.relationship_type = "peer"
        mock_rel.connected_pct = 85.0
        mock_rel.asn2_name = "Cogent"
        mock_rel.peer_pct = 80.0
        mock_rel.as1_upstream_pct = 10.0
        mock_rel.as2_upstream_pct = 10.0
        mock_monocle.check_relationship = AsyncMock(return_value=mock_rel)

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_monocle", return_value=mock_monocle),
        ):
            result = await mcp_server.investigate_asn(15169, related_asn=174)

        assert "174" in result
        assert "peer" in result.lower()

    @pytest.mark.asyncio
    async def test_multiple_sections(self):
        """Requesting multiple sections should include all of them."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(
            return_value=["8.8.8.0/24", "2001:4860::/32"]
        )
        mock_client.get_as_overview = AsyncMock(
            return_value={"holder": "GOOGLE", "resource": "15169"}
        )
        mock_client.get_whois_data = AsyncMock(
            return_value={
                "records": [[{"key": "ASName", "value": "GOOGLE"}]],
                "irr_records": [],
                "authorities": ["arin"],
            }
        )

        mock_monocle = AsyncMock()
        mock_monocle.get_connectivity = AsyncMock(return_value=_mock_connectivity())

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_monocle", return_value=mock_monocle),
        ):
            result = await mcp_server.investigate_asn(
                15169, sections=["summary", "whois"]
            )

        assert "AS15169" in result
        assert "GOOGLE" in result


# =============================================================================
# investigate_prefix tests
# =============================================================================


def _make_routes(prefix="8.8.8.0/24", origin=15169, count=12):
    """Create mock BGPRoute objects."""
    from datetime import UTC, datetime
    from bgp_explorer.models.route import BGPRoute

    return [
        BGPRoute(
            prefix=prefix,
            origin_asn=origin,
            as_path=[3356, 174, origin],
            collector=f"rrc{i:02d}",
            timestamp=datetime.now(UTC),
            source="ripe_stat",
        )
        for i in range(count)
    ]


class TestInvestigatePrefix:
    """Tests for the investigate_prefix composite tool."""

    @pytest.mark.asyncio
    async def test_summary_default(self):
        """Default should return origin, visibility, RPKI status."""
        mock_client = AsyncMock()
        mock_client.get_bgp_state = AsyncMock(return_value=_make_routes())
        mock_client.get_rpki_validation = AsyncMock(return_value="valid")

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.investigate_prefix("8.8.8.0/24")

        assert "8.8.8.0/24" in result
        assert "AS15169" in result
        assert "12" in result  # collector count
        assert "VALID" in result or "valid" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_prefix_format(self):
        """Should reject prefix without CIDR."""
        result = await mcp_server.investigate_prefix("8.8.8.0")
        assert "CIDR" in result or "cidr" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_section(self):
        """Invalid section should return error."""
        result = await mcp_server.investigate_prefix("8.8.8.0/24", sections=["bogus"])
        assert "invalid" in result.lower() or "Invalid" in result

    @pytest.mark.asyncio
    async def test_anomalies_section(self):
        """Anomalies section should check for MOAS and RPKI."""
        mock_client = AsyncMock()
        mock_client.get_bgp_state = AsyncMock(return_value=_make_routes())
        mock_client.get_rpki_validation = AsyncMock(return_value="valid")
        mock_client.get_routing_history = AsyncMock(
            return_value={"by_origin": [{"origin": "15169"}]}
        )

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_aspa_validator", AsyncMock(return_value=None)),
        ):
            result = await mcp_server.investigate_prefix(
                "8.8.8.0/24", sections=["anomalies"]
            )

        assert "RPKI" in result or "rpki" in result
        assert "origin" in result.lower() or "Origin" in result

    @pytest.mark.asyncio
    async def test_paths_section(self):
        """Paths section should show diversity metrics."""
        mock_client = AsyncMock()
        mock_client.get_bgp_state = AsyncMock(return_value=_make_routes())

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.investigate_prefix(
                "8.8.8.0/24", sections=["paths"]
            )

        assert "path" in result.lower() or "Path" in result


# =============================================================================
# check_rpki tests
# =============================================================================


class TestCheckRpki:
    """Tests for the check_rpki composite tool."""

    @pytest.mark.asyncio
    async def test_asn_mode_summary(self):
        """Integer target should trigger ASN mode with summary."""
        mock_client = AsyncMock()
        mock_client.get_announced_prefixes = AsyncMock(
            return_value=["8.8.8.0/24", "8.8.4.0/24"]
        )
        mock_client.get_rpki_validation_detail = AsyncMock(
            return_value={
                "status": "valid",
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "validating_roas": [{"origin": "15169", "prefix": "8.8.8.0/24", "max_length": 24}],
            }
        )

        with (
            patch.object(mcp_server, "get_ripe_stat", return_value=mock_client),
            patch.object(mcp_server, "get_rpki_console", return_value=None),
        ):
            result = await mcp_server.check_rpki(15169)

        assert "AS15169" in result
        assert "RPKI" in result or "ROA" in result

    @pytest.mark.asyncio
    async def test_path_mode(self):
        """String target should trigger path validation mode."""
        from bgp_explorer.models.aspa import ASPAHopResult, ASPAState, ASPAValidationResult

        mock_validator = AsyncMock()
        mock_validator.validate_path = AsyncMock(
            return_value=ASPAValidationResult(
                as_path=[3356, 174, 15169],
                state=ASPAState.VALID,
                hop_results=[
                    ASPAHopResult(
                        asn=3356, next_asn=174,
                        is_authorized_provider=True,
                        relationship_type="upstream",
                        data_source="monocle", confidence=0.7,
                    ),
                ],
                valley_free=True, issues=[], summary="Valid",
            )
        )

        with patch.object(
            mcp_server, "get_aspa_validator", AsyncMock(return_value=mock_validator)
        ):
            result = await mcp_server.check_rpki("3356 174 15169")

        assert "VALID" in result
        assert "AS3356" in result

    @pytest.mark.asyncio
    async def test_invalid_section(self):
        result = await mcp_server.check_rpki(15169, sections=["bogus"])
        assert "invalid" in result.lower() or "Invalid" in result


# =============================================================================
# get_routing_history tests (consolidated)
# =============================================================================


class TestGetRoutingHistoryConsolidated:
    """Tests for the consolidated get_routing_history tool."""

    @pytest.mark.asyncio
    async def test_summary_default(self):
        """Default should show origin count and stability info."""
        mock_client = AsyncMock()
        mock_client.get_routing_history = AsyncMock(
            return_value={"by_origin": [{"origin": "15169", "prefixes": []}]}
        )
        mock_client.get_bgp_update_activity = AsyncMock(
            return_value={"updates": []}
        )

        with patch.object(mcp_server, "get_ripe_stat", return_value=mock_client):
            result = await mcp_server.get_routing_history_v2(
                "8.8.8.0/24", "2026-01-01", "2026-01-31"
            )

        assert "8.8.8.0/24" in result
        assert "origin" in result.lower() or "Origin" in result

    @pytest.mark.asyncio
    async def test_reversed_dates(self):
        result = await mcp_server.get_routing_history_v2(
            "8.8.8.0/24", "2026-02-06", "2026-02-01"
        )
        assert "after" in result.lower() or "invalid" in result.lower()


# =============================================================================
# investigate_ixp tests
# =============================================================================


class TestInvestigateIxp:
    """Tests for the investigate_ixp composite tool."""

    @pytest.mark.asyncio
    async def test_asn_mode(self):
        """Integer target should show IXP presence for ASN."""
        mock_peeringdb = AsyncMock()
        presence = MagicMock()
        presence.ixp_name = "AMS-IX"
        presence.speed = 100000
        presence.ipaddr4 = "80.249.208.1"
        presence.ipaddr6 = "2001:7f8:1::1"
        mock_peeringdb.get_ixps_for_asn = MagicMock(return_value=[presence])

        with patch.object(mcp_server, "get_peeringdb", return_value=mock_peeringdb):
            result = await mcp_server.investigate_ixp(15169)

        assert "AMS-IX" in result

    @pytest.mark.asyncio
    async def test_ixp_mode(self):
        """String target should show IXP details."""
        mock_peeringdb = AsyncMock()
        ixp = MagicMock()
        ixp.name = "AMS-IX"
        ixp.city = "Amsterdam"
        ixp.country = "NL"
        ixp.participant_count = 900
        ixp.website = "https://ams-ix.net"
        ixp.id = 26
        mock_peeringdb.get_ixp_details = MagicMock(return_value=ixp)

        net = MagicMock()
        net.asn = 15169
        net.name = "Google"
        net.info_type = "NSP"
        mock_peeringdb.get_networks_at_ixp = MagicMock(return_value=[net])

        with patch.object(mcp_server, "get_peeringdb", return_value=mock_peeringdb):
            result = await mcp_server.investigate_ixp("AMS-IX")

        assert "AMS-IX" in result
        assert "Amsterdam" in result


# =============================================================================
# probe_network tests
# =============================================================================


class TestProbeNetwork:
    """Tests for the probe_network composite tool."""

    @pytest.mark.asyncio
    async def test_ping_default(self):
        """Default type should be ping."""
        mock_globalping = AsyncMock()
        mock_result = MagicMock()
        probe = MagicMock()
        probe.city = "Frankfurt"
        probe.country = "DE"
        probe.avg_latency = 5.2
        probe.packet_loss = 0
        mock_result.probes = [probe]
        mock_result.measurement_id = "test-123"
        mock_globalping.ping = AsyncMock(return_value=mock_result)

        with patch.object(mcp_server, "get_globalping", return_value=mock_globalping):
            result = await mcp_server.probe_network("8.8.8.8")

        assert "8.8.8.8" in result
        assert "Frankfurt" in result
        mock_globalping.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_traceroute_type(self):
        """type='traceroute' should call traceroute."""
        mock_globalping = AsyncMock()
        mock_result = MagicMock()
        probe = MagicMock()
        probe.city = "London"
        probe.country = "GB"
        probe.hops = [{"hop": 1, "resolvedAddress": "10.0.0.1", "timings": [{"rtt": 1.5}]}]
        mock_result.probes = [probe]
        mock_result.measurement_id = "test-456"
        mock_globalping.traceroute = AsyncMock(return_value=mock_result)

        with patch.object(mcp_server, "get_globalping", return_value=mock_globalping):
            result = await mcp_server.probe_network("8.8.8.8", type="traceroute")

        assert "8.8.8.8" in result
        mock_globalping.traceroute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bogon_rejected(self):
        """Bogon addresses should be rejected."""
        result = await mcp_server.probe_network("192.0.2.1")
        assert "documentation" in result.lower() or "rfc" in result.lower()


# =============================================================================
# run_audit tests
# =============================================================================


class TestRunAudit:
    """Tests for the run_audit composite tool."""

    @pytest.mark.asyncio
    async def test_invalid_section(self):
        result = await mcp_server.run_audit(15169, framework="bogus")
        assert "invalid" in result.lower() or "Invalid" in result or "Error" in result
