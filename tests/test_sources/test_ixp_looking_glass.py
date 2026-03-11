"""Tests for IXP Looking Glass (Alice-LG) client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.ixp_looking_glass import (
    ALICE_LG_INSTANCES,
    IXPLookingGlassClient,
)


class TestIXPLookingGlassClient:
    """Tests for IXPLookingGlassClient."""

    @pytest.fixture
    def client(self):
        """Create an IXPLookingGlassClient instance."""
        return IXPLookingGlassClient()

    @pytest.mark.asyncio
    async def test_lookup_prefix_success(self, client):
        """Test prefix lookup on DE-CIX."""
        mock_response = {
            "routes": [
                {
                    "network": "8.8.8.0/24",
                    "gateway": "80.81.192.1",
                    "as_path": [15169],
                    "origin": "IGP",
                },
            ],
            "filtered_routes": [],
        }

        with aioresponses() as m:
            m.get(
                "https://lg.de-cix.net/api/v1/lookup/prefix?q=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                result = await client.lookup_prefix("8.8.8.0/24", ixp="de-cix")

            assert "routes" in result
            assert len(result["routes"]) == 1
            assert result["routes"][0]["network"] == "8.8.8.0/24"

    @pytest.mark.asyncio
    async def test_lookup_prefix_different_ixp(self, client):
        """Test prefix lookup on AMS-IX."""
        mock_response = {
            "routes": [
                {
                    "network": "1.1.1.0/24",
                    "gateway": "80.249.208.1",
                    "as_path": [13335],
                    "origin": "IGP",
                },
            ],
            "filtered_routes": [],
        }

        with aioresponses() as m:
            m.get(
                "https://lg.ams-ix.net/api/v1/lookup/prefix?q=1.1.1.0/24",
                payload=mock_response,
            )

            async with client:
                result = await client.lookup_prefix("1.1.1.0/24", ixp="ams-ix")

            assert "routes" in result
            assert result["routes"][0]["as_path"] == [13335]

    @pytest.mark.asyncio
    async def test_lookup_prefix_invalid_ixp(self, client):
        """Test that invalid IXP name raises ValueError."""
        async with client:
            with pytest.raises(ValueError, match="Unknown IXP"):
                await client.lookup_prefix("8.8.8.0/24", ixp="unknown-ixp")

    @pytest.mark.asyncio
    async def test_list_route_servers_success(self, client):
        """Test listing route servers at an IXP."""
        mock_response = {
            "routeservers": [
                {"id": "rs1", "name": "Route Server 1", "group": "primary"},
                {"id": "rs2", "name": "Route Server 2", "group": "secondary"},
            ]
        }

        with aioresponses() as m:
            m.get(
                "https://lg.de-cix.net/api/v1/routeservers",
                payload=mock_response,
            )

            async with client:
                result = await client.list_route_servers(ixp="de-cix")

            assert len(result) == 2
            assert result[0]["id"] == "rs1"
            assert result[1]["name"] == "Route Server 2"

    def test_list_supported_ixps(self):
        """Test listing supported IXPs."""
        result = IXPLookingGlassClient.list_supported_ixps()

        assert "de-cix" in result
        assert "ams-ix" in result
        assert "bcix" in result
        assert len(result) == len(ALICE_LG_INSTANCES)

    @pytest.mark.asyncio
    async def test_connect_disconnect(self, client):
        """Test session lifecycle."""
        assert client._session is None

        await client.connect()
        assert client._session is not None

        await client.disconnect()
        assert client._session is None

    @pytest.mark.asyncio
    async def test_is_available_success(self, client):
        """Test availability check when API is up."""
        mock_response = {"routeservers": []}

        with aioresponses() as m:
            m.get(
                "https://lg.de-cix.net/api/v1/routeservers",
                payload=mock_response,
            )

            async with client:
                available = await client.is_available()

            assert available is True

    @pytest.mark.asyncio
    async def test_is_available_failure(self, client):
        """Test availability check when API is down."""
        with aioresponses() as m:
            m.get(
                "https://lg.de-cix.net/api/v1/routeservers",
                status=500,
            )

            async with client:
                available = await client.is_available()

            assert available is False

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with IXPLookingGlassClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_caching(self, client):
        """Test that responses are cached."""
        mock_response = {"routes": [], "filtered_routes": []}

        with aioresponses() as m:
            # Only add one mock - second call should use cache
            m.get(
                "https://lg.de-cix.net/api/v1/lookup/prefix?q=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                # First call
                await client.lookup_prefix("8.8.8.0/24", ixp="de-cix")
                # Second call should use cache
                await client.lookup_prefix("8.8.8.0/24", ixp="de-cix")

            # If caching works, we only made one HTTP request
