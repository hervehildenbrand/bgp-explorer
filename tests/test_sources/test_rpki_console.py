"""Tests for rpki-client console client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.models.rpki import ASPAObject, ROAObject
from bgp_explorer.sources.rpki_console import RPKI_JSON_URL, RpkiConsoleClient

# Sample rpki.json response matching real format from console.rpki-client.org
SAMPLE_RPKI_JSON = {
    "metadata": {
        "buildmachine": "test-machine",
        "buildtime": "2026-03-27T08:33:52Z",
        "roas": 3,
        "aspas": 2,
    },
    "roas": [
        {
            "asn": 13335,
            "prefix": "1.0.0.0/24",
            "maxLength": 24,
            "ta": "apnic",
            "expires": 1775000000,
        },
        {
            "asn": 13335,
            "prefix": "1.1.1.0/24",
            "maxLength": 24,
            "ta": "apnic",
            "expires": 1775000000,
        },
        {
            "asn": 15169,
            "prefix": "8.8.8.0/24",
            "maxLength": 24,
            "ta": "arin",
            "expires": 1775000000,
        },
    ],
    "aspas": [
        {"customer_asid": 64496, "providers": [174, 3356], "expires": 1775000000},
        {"customer_asid": 64497, "providers": [2914, 6939], "expires": 1775000000},
    ],
    "bgpsec_keys": [],
    "nonfunc_cas": [],
}


class TestRpkiConsoleClient:
    """Tests for RpkiConsoleClient."""

    @pytest.fixture
    def client(self):
        return RpkiConsoleClient(cache_ttl=3600)

    @pytest.mark.asyncio
    async def test_fetch_and_parse(self, client):
        """Test fetching and parsing rpki.json."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                has = await client.has_aspa(64496)

            assert has is True

    @pytest.mark.asyncio
    async def test_aspa_providers(self, client):
        """Test getting ASPA providers for a customer ASN."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                providers = await client.get_aspa_providers(64496)

            assert providers == frozenset({174, 3356})

    @pytest.mark.asyncio
    async def test_aspa_providers_not_found(self, client):
        """Test getting ASPA providers for an ASN without ASPA."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                providers = await client.get_aspa_providers(99999)

            assert providers == frozenset()

    @pytest.mark.asyncio
    async def test_has_aspa_false(self, client):
        """Test has_aspa returns False for ASN without ASPA."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                has = await client.has_aspa(99999)

            assert has is False

    @pytest.mark.asyncio
    async def test_get_aspa_object(self, client):
        """Test getting the full ASPA object."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                aspa = await client.get_aspa_object(64497)

            assert aspa is not None
            assert aspa.customer_asn == 64497
            assert aspa.provider_asns == frozenset({2914, 6939})
            assert aspa.expires == 1775000000

    @pytest.mark.asyncio
    async def test_get_aspa_object_not_found(self, client):
        """Test getting ASPA object for non-existent ASN."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                aspa = await client.get_aspa_object(99999)

            assert aspa is None

    @pytest.mark.asyncio
    async def test_get_all_aspa_objects(self, client):
        """Test getting all ASPA objects."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                all_aspas = await client.get_all_aspa_objects()

            assert len(all_aspas) == 2
            assert all(isinstance(a, ASPAObject) for a in all_aspas)

    @pytest.mark.asyncio
    async def test_aspa_count(self, client):
        """Test ASPA object count."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                count = await client.get_aspa_count()

            assert count == 2

    @pytest.mark.asyncio
    async def test_roas_for_origin(self, client):
        """Test getting ROAs by origin ASN."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                roas = await client.get_roas_for_origin(13335)

            assert len(roas) == 2
            assert all(isinstance(r, ROAObject) for r in roas)
            prefixes = {r.prefix for r in roas}
            assert prefixes == {"1.0.0.0/24", "1.1.1.0/24"}

    @pytest.mark.asyncio
    async def test_roas_for_origin_not_found(self, client):
        """Test getting ROAs for ASN with no ROAs."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                roas = await client.get_roas_for_origin(99999)

            assert roas == []

    @pytest.mark.asyncio
    async def test_roas_for_prefix(self, client):
        """Test getting ROAs by prefix."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                roas = await client.get_roas_for_prefix("8.8.8.0/24")

            assert len(roas) == 1
            assert roas[0].origin_asn == 15169
            assert roas[0].trust_anchor == "arin"

    @pytest.mark.asyncio
    async def test_roa_count(self, client):
        """Test ROA object count."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                count = await client.get_roa_count()

            assert count == 3

    @pytest.mark.asyncio
    async def test_dump_metadata(self, client):
        """Test getting dump metadata."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                meta = await client.get_dump_metadata()

            assert meta["generated"] == "2026-03-27T08:33:52Z"
            assert meta["source"] == "rpki-client-console"
            assert meta["roa_count"] == "3"
            assert meta["aspa_count"] == "2"

    @pytest.mark.asyncio
    async def test_caching_avoids_refetch(self, client):
        """Test that data is cached and not re-fetched within TTL."""
        with aioresponses() as m:
            # Only one mock — second call must use cache
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                await client.has_aspa(64496)
                # Second call should not trigger HTTP request
                providers = await client.get_aspa_providers(64496)

            assert providers == frozenset({174, 3356})

    @pytest.mark.asyncio
    async def test_connect_disconnect(self, client):
        """Test session lifecycle."""
        assert client._session is None
        await client.connect()
        assert client._session is not None
        await client.disconnect()
        assert client._session is None

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with RpkiConsoleClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_is_available_before_fetch(self, client):
        """Test is_available returns False before data is fetched."""
        available = await client.is_available()
        assert available is False

    @pytest.mark.asyncio
    async def test_is_available_after_fetch(self, client):
        """Test is_available returns True after data is fetched."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                await client.has_aspa(64496)  # trigger fetch
                available = await client.is_available()

            assert available is True

    @pytest.mark.asyncio
    async def test_parse_empty_dump(self, client):
        """Test parsing a dump with no ASPA or ROA entries."""
        empty_dump = {
            "metadata": {"buildtime": "2026-01-01T00:00:00Z"},
            "roas": [],
            "aspas": [],
        }

        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=empty_dump)

            async with client:
                count = await client.get_aspa_count()

            assert count == 0

    @pytest.mark.asyncio
    async def test_roa_fields_parsed_correctly(self, client):
        """Test that ROA fields are parsed with correct types."""
        with aioresponses() as m:
            m.get(RPKI_JSON_URL, payload=SAMPLE_RPKI_JSON)

            async with client:
                roas = await client.get_roas_for_prefix("1.0.0.0/24")

            assert len(roas) == 1
            roa = roas[0]
            assert roa.prefix == "1.0.0.0/24"
            assert roa.max_length == 24
            assert roa.origin_asn == 13335
            assert roa.trust_anchor == "apnic"
            assert roa.expires == 1775000000
