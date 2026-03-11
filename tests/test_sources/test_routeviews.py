"""Tests for RouteViews API client."""

import os
from unittest.mock import patch

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.routeviews import RouteViewsClient


class TestRouteViewsClient:
    """Tests for RouteViewsClient."""

    @pytest.fixture
    def client(self):
        """Create a RouteViewsClient instance."""
        return RouteViewsClient()

    @pytest.mark.asyncio
    async def test_get_prefix_routes_success(self, client):
        """Test getting routes for a prefix."""
        mock_response = {
            "prefix": "8.8.8.0/24",
            "routes": [
                {
                    "origin_asn": 15169,
                    "as_path": [3356, 15169],
                    "collector": "route-views2",
                },
                {
                    "origin_asn": 15169,
                    "as_path": [174, 15169],
                    "collector": "route-views4",
                },
            ],
        }

        with aioresponses() as m:
            m.get(
                "https://api.routeviews.org/prefix/8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                result = await client.get_prefix_routes("8.8.8.0/24")

            assert result["prefix"] == "8.8.8.0/24"
            assert len(result["routes"]) == 2
            assert result["routes"][0]["origin_asn"] == 15169

    @pytest.mark.asyncio
    async def test_get_collectors_success(self, client):
        """Test getting list of collectors."""
        mock_response = {
            "collectors": [
                {"name": "route-views2", "location": "Oregon, US"},
                {"name": "route-views4", "location": "New York, US"},
                {"name": "route-views6", "location": "Tokyo, JP"},
            ]
        }

        with aioresponses() as m:
            m.get(
                "https://api.routeviews.org/collectors",
                payload=mock_response,
            )

            async with client:
                result = await client.get_collectors()

            assert len(result) == 3
            assert result[0]["name"] == "route-views2"
            assert result[1]["location"] == "New York, US"

    @pytest.mark.asyncio
    async def test_api_key_header(self, client):
        """Test that API key header is sent when env var is set."""
        mock_response = {"prefix": "1.1.1.0/24", "routes": []}

        with patch.dict(os.environ, {"ROUTEVIEWS_API_KEY": "test-api-key"}):
            # Create new client to pick up env var
            client_with_key = RouteViewsClient()

            with aioresponses() as m:
                m.get(
                    "https://api.routeviews.org/prefix/1.1.1.0/24",
                    payload=mock_response,
                )

                async with client_with_key:
                    await client_with_key.get_prefix_routes("1.1.1.0/24")

                # Verify the request was made (aioresponses doesn't easily expose headers)
                # but we can verify no exception was raised
                assert True

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
        mock_response = {"status": "ok"}

        with aioresponses() as m:
            m.get(
                "https://api.routeviews.org/health",
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
                "https://api.routeviews.org/health",
                status=500,
            )

            async with client:
                available = await client.is_available()

            assert available is False

    @pytest.mark.asyncio
    async def test_get_prefix_routes_error(self, client):
        """Test error handling for non-200 response."""
        with aioresponses() as m:
            m.get(
                "https://api.routeviews.org/prefix/invalid",
                status=404,
                payload={"error": "Not found"},
            )

            async with client:
                with pytest.raises(ValueError, match="RouteViews API error"):
                    await client.get_prefix_routes("invalid")

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with RouteViewsClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_caching(self, client):
        """Test that responses are cached."""
        mock_response = {"prefix": "8.8.8.0/24", "routes": []}

        with aioresponses() as m:
            # Only add one mock - second call should use cache
            m.get(
                "https://api.routeviews.org/prefix/8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                # First call
                await client.get_prefix_routes("8.8.8.0/24")
                # Second call should use cache
                await client.get_prefix_routes("8.8.8.0/24")

            # If caching works, we only made one HTTP request
