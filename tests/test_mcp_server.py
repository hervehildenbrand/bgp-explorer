"""Tests for MCP server input validation and output consistency."""

from unittest.mock import AsyncMock, patch

import pytest

from bgp_explorer import mcp_server


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
