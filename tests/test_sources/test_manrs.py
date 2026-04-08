"""Tests for MANRS Observatory API client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.models.manrs import MANRSReadiness
from bgp_explorer.sources.manrs import MANRS_API_URL, MANRSClient

# Real MANRS API format: {"participants": [...]}
SAMPLE_CONFORMANCE_RESPONSE = {
    "participants": [
        {
            "id": 1001,
            "name": "Cloudflare, Inc.",
            "areas_served": ["US"],
            "ASNs": [13335],
            "member_since": "2020-01-15",
            "filtering": {"conformance": "conformant"},
            "anti_spoofing": {
                "conformance": "conformant",
                "score": {"value": 1, "severity": "ready"},
            },
            "coordination": {
                "conformance": "conformant",
                "score": {"value": 1, "severity": "ready"},
            },
            "routing_information": {
                "conformance": "conformant",
                "score_irr": {"value": 1, "severity": "ready"},
                "score_rpki": {"value": 1, "severity": "ready"},
            },
        },
        {
            "id": 1002,
            "name": "Google LLC",
            "areas_served": ["US"],
            "ASNs": [15169],
            "member_since": "2019-06-01",
            "filtering": {"conformance": "conformant"},
            "anti_spoofing": {
                "conformance": "conformant",
                "score": {"value": 0.5, "severity": "aspiring"},
            },
            "coordination": {
                "conformance": "conformant",
                "score": {"value": 1, "severity": "ready"},
            },
            "routing_information": {
                "conformance": "conformant",
                "score_irr": {"value": 1, "severity": "ready"},
                "score_rpki": {"value": 1, "severity": "ready"},
            },
        },
    ]
}

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
        """Test parsing unknown/unexpected readiness values."""
        weird_response = {
            "participants": [
                {
                    "name": "Test",
                    "areas_served": ["XX"],
                    "ASNs": [64496],
                    "member_since": "",
                    "filtering": {"conformance": "something_new"},
                    "anti_spoofing": {
                        "conformance": "non-conformant",
                        "score": {"value": 0, "severity": "lagging"},
                    },
                    "coordination": {
                        "conformance": "conformant",
                        "score": {"value": 0, "severity": "lagging"},
                    },
                    "routing_information": {
                        "conformance": "non-conformant",
                        "score_irr": {"value": 0, "severity": "lagging"},
                        "score_rpki": {"value": 0, "severity": "lagging"},
                    },
                },
            ]
        }
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=weird_response,
            )
            async with client:
                result = await client.get_asn_conformance(64496)
            assert result is not None
            assert result.action1_filtering == MANRSReadiness.UNKNOWN

    @pytest.mark.asyncio
    async def test_real_api_format(self, client):
        """Test parsing the real MANRS API response format."""
        with aioresponses() as m:
            m.get(
                f"{MANRS_API_URL}/conformance/net-ops",
                payload=SAMPLE_CONFORMANCE_RESPONSE,
            )
            async with client:
                result = await client.get_asn_conformance(13335)
            assert result is not None
            assert result.name == "Cloudflare, Inc."
            assert result.country == "US"
            assert result.action2_anti_spoofing == MANRSReadiness.READY
            assert result.action3_coordination == MANRSReadiness.READY
            assert result.action4_validation == MANRSReadiness.READY
