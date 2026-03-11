"""Tests for APNIC ROV client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.apnic_rov import APNICROVClient


class TestAPNICROVClient:
    """Tests for APNICROVClient."""

    @pytest.fixture
    def client(self):
        """Create an APNICROVClient instance."""
        return APNICROVClient()

    @pytest.mark.asyncio
    async def test_get_asn_rov_status_success(self, client):
        """Test getting ROV status for an ASN."""
        mock_response = {
            "asn": 15169,
            "name": "GOOGLE",
            "rov_filtering": {
                "percentage": 87.5,
                "sample_size": 1000,
                "measurement_date": "2024-01-01",
            },
            "rpki_status": {
                "valid_percentage": 95.2,
                "invalid_percentage": 0.5,
                "unknown_percentage": 4.3,
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stats.labs.apnic.net/rpki/AS15169?c=AU&m=json",
                payload=mock_response,
            )

            async with client:
                result = await client.get_asn_rov_status(15169)

            assert result["asn"] == 15169
            assert result["rov_filtering"]["percentage"] == 87.5
            assert result["rpki_status"]["valid_percentage"] == 95.2

    @pytest.mark.asyncio
    async def test_get_asn_rov_status_api_error(self, client):
        """Test graceful error handling when API is unavailable."""
        with aioresponses() as m:
            m.get(
                "https://stats.labs.apnic.net/rpki/AS64496?c=AU&m=json",
                status=500,
            )

            async with client:
                result = await client.get_asn_rov_status(64496)

            assert "error" in result
            assert result["error"] == "APNIC ROV data unavailable"
            assert result["asn"] == 64496

    @pytest.mark.asyncio
    async def test_get_asn_rov_status_not_found(self, client):
        """Test handling of non-existent ASN."""
        with aioresponses() as m:
            m.get(
                "https://stats.labs.apnic.net/rpki/AS99999?c=AU&m=json",
                status=404,
            )

            async with client:
                result = await client.get_asn_rov_status(99999)

            assert "error" in result
            assert result["asn"] == 99999

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
                "https://stats.labs.apnic.net/rpki/AS15169?c=AU&m=json",
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
                "https://stats.labs.apnic.net/rpki/AS15169?c=AU&m=json",
                status=500,
            )

            async with client:
                available = await client.is_available()

            assert available is False

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with APNICROVClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_caching(self, client):
        """Test that responses are cached with 7-day TTL."""
        mock_response = {
            "asn": 15169,
            "rov_filtering": {"percentage": 87.5},
        }

        with aioresponses() as m:
            # Only add one mock - second call should use cache
            m.get(
                "https://stats.labs.apnic.net/rpki/AS15169?c=AU&m=json",
                payload=mock_response,
            )

            async with client:
                # First call
                result1 = await client.get_asn_rov_status(15169)
                # Second call should use cache
                result2 = await client.get_asn_rov_status(15169)

            # Both results should be the same
            assert result1 == result2
            # If caching works, we only made one HTTP request
