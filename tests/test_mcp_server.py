"""Tests for MCP server input validation and output consistency."""

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
