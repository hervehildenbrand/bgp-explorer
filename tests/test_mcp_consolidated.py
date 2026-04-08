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
