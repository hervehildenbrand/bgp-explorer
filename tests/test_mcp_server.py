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
