"""Tests for MANRS Observatory API client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.models.manrs import MANRSReadiness
from bgp_explorer.sources.manrs import MANRS_API_URL, MANRSClient

SAMPLE_CONFORMANCE_RESPONSE = [
    {
        "asn": 13335,
        "name": "Cloudflare, Inc.",
        "country": "US",
        "status": "ready",
        "action_1": "ready",
        "action_2": "ready",
        "action_3": "ready",
        "action_4": "ready",
        "last_updated": "2026-04-01T00:00:00Z",
    },
    {
        "asn": 15169,
        "name": "Google LLC",
        "country": "US",
        "status": "ready",
        "action_1": "ready",
        "action_2": "aspiring",
        "action_3": "ready",
        "action_4": "ready",
        "last_updated": "2026-04-01T00:00:00Z",
    },
]

SAMPLE_ROA_RESPONSE = {
    "asn": 13335,
    "roa_count": 450,
    "roa_v4": 300,
    "roa_v6": 150,
}


class TestMANRSClient:
    @pytest.fixture
    def client(self):
        return MANRSClient(api_key="test-key-123", cache_ttl=3600)

    @pytest.fixture
    def client_no_key(self):
        return MANRSClient(api_key=None, cache_ttl=3600)

    @pytest.mark.asyncio
    async def test_has_api_key(self, client):
        assert client.has_api_key() is True

    @pytest.mark.asyncio
    async def test_has_api_key_false(self, client_no_key):
        assert client_no_key.has_api_key() is False

    @pytest.mark.asyncio
    async def test_get_asn_conformance(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                result = await client.get_asn_conformance(13335)

            assert result is not None
            assert result.asn == 13335
            assert result.name == "Cloudflare, Inc."
            assert result.action1_filtering == MANRSReadiness.READY
            assert result.action4_validation == MANRSReadiness.READY
            assert result.manrs_participant is True

    @pytest.mark.asyncio
    async def test_get_asn_conformance_not_found(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                result = await client.get_asn_conformance(99999)
            assert result is None

    @pytest.mark.asyncio
    async def test_get_asn_conformance_aspiring(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                result = await client.get_asn_conformance(15169)
            assert result is not None
            assert result.action2_anti_spoofing == MANRSReadiness.ASPIRING
            assert result.action1_filtering == MANRSReadiness.READY

    @pytest.mark.asyncio
    async def test_is_manrs_participant(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                assert await client.is_manrs_participant(13335) is True
                assert await client.is_manrs_participant(99999) is False

    @pytest.mark.asyncio
    async def test_get_asn_roas(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/roas/asn/13335",
                payload=SAMPLE_ROA_RESPONSE,
            )
            async with client:
                result = await client.get_asn_roas(13335)
            assert result is not None
            assert result["asn"] == 13335
            assert result["roa_count"] == 450

    @pytest.mark.asyncio
    async def test_connect_disconnect(self, client):
        assert client._session is None
        await client.connect()
        assert client._session is not None
        await client.disconnect()
        assert client._session is None

    @pytest.mark.asyncio
    async def test_context_manager(self):
        async with MANRSClient(api_key="test") as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_is_available_with_key(self, client):
        available = await client.is_available()
        assert available is True

    @pytest.mark.asyncio
    async def test_is_available_without_key(self, client_no_key):
        available = await client_no_key.is_available()
        assert available is False

    @pytest.mark.asyncio
    async def test_caching_avoids_refetch(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                await client.get_asn_conformance(13335)
                result = await client.get_asn_conformance(15169)
            assert result is not None
            assert result.asn == 15169

    @pytest.mark.asyncio
    async def test_no_api_key_returns_none(self, client_no_key):
        async with client_no_key:
            result = await client_no_key.get_asn_conformance(13335)
        assert result is None

    @pytest.mark.asyncio
    async def test_api_error_handling(self, client):
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                status=500,
            )
            async with client:
                result = await client.get_asn_conformance(13335)
            assert result is None

    @pytest.mark.asyncio
    async def test_unknown_readiness_parsed(self, client):
        weird_response = [
            {
                "asn": 64496,
                "name": "Test",
                "country": "XX",
                "status": "unknown",
                "action_1": "something_new",
                "action_2": "lagging",
                "action_3": "lagging",
                "action_4": "lagging",
                "last_updated": "",
            },
        ]
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=weird_response,
            )
            async with client:
                result = await client.get_asn_conformance(64496)
            assert result is not None
            assert result.action1_filtering == MANRSReadiness.UNKNOWN
