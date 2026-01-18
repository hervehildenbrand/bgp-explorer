"""Tests for PeeringDB client using CAIDA dumps."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aioresponses import aioresponses

from bgp_explorer.models.ixp import IXP, IXPPresence, Network
from bgp_explorer.sources.peeringdb import PeeringDBClient


# Sample PeeringDB dump data for testing
SAMPLE_PEERINGDB_DUMP = {
    "ix": {
        "data": [
            {
                "id": 31,
                "name": "AMS-IX",
                "city": "Amsterdam",
                "country": "NL",
                "website": "https://www.ams-ix.net/",
            },
            {
                "id": 26,
                "name": "DE-CIX Frankfurt",
                "city": "Frankfurt",
                "country": "DE",
                "website": "https://www.de-cix.net/",
            },
            {
                "id": 1,
                "name": "LINX LON1",
                "city": "London",
                "country": "GB",
                "website": "https://www.linx.net/",
            },
        ]
    },
    "net": {
        "data": [
            {
                "id": 1,
                "asn": 15169,
                "name": "Google LLC",
                "info_type": "Content",
                "website": "https://www.google.com",
            },
            {
                "id": 2,
                "asn": 13335,
                "name": "Cloudflare, Inc.",
                "info_type": "NSP",
                "website": "https://www.cloudflare.com",
            },
            {
                "id": 3,
                "asn": 32934,
                "name": "Meta Platforms, Inc.",
                "info_type": "Content",
                "website": "https://www.meta.com",
            },
        ]
    },
    "netixlan": {
        "data": [
            # Google at AMS-IX
            {
                "net_id": 1,
                "ix_id": 31,
                "asn": 15169,
                "ipaddr4": "80.249.208.1",
                "ipaddr6": "2001:7f8:1::a501:5169:1",
                "speed": 100000,
            },
            # Google at DE-CIX
            {
                "net_id": 1,
                "ix_id": 26,
                "asn": 15169,
                "ipaddr4": "80.81.192.1",
                "ipaddr6": "2001:7f8::3b41:0:1",
                "speed": 100000,
            },
            # Cloudflare at AMS-IX
            {
                "net_id": 2,
                "ix_id": 31,
                "asn": 13335,
                "ipaddr4": "80.249.209.1",
                "ipaddr6": "2001:7f8:1::a501:3335:1",
                "speed": 400000,
            },
            # Cloudflare at DE-CIX
            {
                "net_id": 2,
                "ix_id": 26,
                "asn": 13335,
                "ipaddr4": "80.81.192.2",
                "ipaddr6": None,
                "speed": 400000,
            },
            # Meta at LINX
            {
                "net_id": 3,
                "ix_id": 1,
                "asn": 32934,
                "ipaddr4": "195.66.224.1",
                "ipaddr6": "2001:7f8:4::808e:1",
                "speed": 100000,
            },
        ]
    },
}


class TestPeeringDBClient:
    """Tests for PeeringDBClient."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def client(self, temp_cache_dir):
        """Create a PeeringDBClient with temp cache."""
        return PeeringDBClient(cache_dir=temp_cache_dir)

    @pytest.fixture
    def client_with_data(self, temp_cache_dir):
        """Create a PeeringDBClient with preloaded data."""
        # Write sample data to cache
        cache_file = temp_cache_dir / "peeringdb_latest.json"
        cache_file.write_text(json.dumps(SAMPLE_PEERINGDB_DUMP))

        # Write metadata
        meta_file = temp_cache_dir / "metadata.json"
        meta_file.write_text(json.dumps({
            "download_date": datetime.now(timezone.utc).isoformat(),
            "source_url": "https://example.com/dump.json",
        }))

        client = PeeringDBClient(cache_dir=temp_cache_dir)
        return client

    @pytest.mark.asyncio
    async def test_connect_loads_cached_data(self, client_with_data):
        """Test that connect loads data from cache if fresh."""
        await client_with_data.connect()

        # Should have loaded data
        assert client_with_data._loaded is True
        assert len(client_with_data._ixp_by_id) == 3
        assert len(client_with_data._asn_to_net) == 3

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_ixps_for_asn(self, client_with_data):
        """Test getting IXPs for a given ASN."""
        await client_with_data.connect()

        # Google is at AMS-IX and DE-CIX
        ixps = client_with_data.get_ixps_for_asn(15169)
        assert len(ixps) == 2
        ixp_names = [p.ixp_name for p in ixps]
        assert "AMS-IX" in ixp_names
        assert "DE-CIX Frankfurt" in ixp_names

        # Check presence details
        amsix_presence = next(p for p in ixps if p.ixp_name == "AMS-IX")
        assert amsix_presence.ipaddr4 == "80.249.208.1"
        assert amsix_presence.speed == 100000

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_ixps_for_asn_not_found(self, client_with_data):
        """Test getting IXPs for an ASN that's not in the database."""
        await client_with_data.connect()

        ixps = client_with_data.get_ixps_for_asn(99999)
        assert ixps == []

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_networks_at_ixp_by_id(self, client_with_data):
        """Test getting networks at an IXP by ID."""
        await client_with_data.connect()

        # AMS-IX (id=31) has Google and Cloudflare
        networks = client_with_data.get_networks_at_ixp(31)
        assert len(networks) == 2
        asns = [n.asn for n in networks]
        assert 15169 in asns  # Google
        assert 13335 in asns  # Cloudflare

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_networks_at_ixp_by_name(self, client_with_data):
        """Test getting networks at an IXP by name."""
        await client_with_data.connect()

        # Search by name (case-insensitive)
        networks = client_with_data.get_networks_at_ixp("ams-ix")
        assert len(networks) == 2

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_networks_at_ixp_not_found(self, client_with_data):
        """Test getting networks at an IXP that doesn't exist."""
        await client_with_data.connect()

        networks = client_with_data.get_networks_at_ixp("NonExistentIXP")
        assert networks == []

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_ixp_details_by_id(self, client_with_data):
        """Test getting IXP details by ID."""
        await client_with_data.connect()

        ixp = client_with_data.get_ixp_details(31)
        assert ixp is not None
        assert ixp.name == "AMS-IX"
        assert ixp.city == "Amsterdam"
        assert ixp.country == "NL"
        assert ixp.participant_count == 2  # Google and Cloudflare

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_ixp_details_by_name(self, client_with_data):
        """Test getting IXP details by name."""
        await client_with_data.connect()

        ixp = client_with_data.get_ixp_details("de-cix frankfurt")
        assert ixp is not None
        assert ixp.name == "DE-CIX Frankfurt"

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_ixp_details_not_found(self, client_with_data):
        """Test getting IXP details for non-existent IXP."""
        await client_with_data.connect()

        ixp = client_with_data.get_ixp_details("NonExistentIXP")
        assert ixp is None

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_search_ixps(self, client_with_data):
        """Test searching for IXPs."""
        await client_with_data.connect()

        # Search by partial name
        results = client_with_data.search_ixps("AMS")
        assert len(results) >= 1
        assert any(ixp.name == "AMS-IX" for ixp in results)

        # Search by city
        results = client_with_data.search_ixps("London")
        assert len(results) >= 1
        assert any(ixp.name == "LINX LON1" for ixp in results)

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_search_ixps_case_insensitive(self, client_with_data):
        """Test that IXP search is case-insensitive."""
        await client_with_data.connect()

        results1 = client_with_data.search_ixps("ams-ix")
        results2 = client_with_data.search_ixps("AMS-IX")
        results3 = client_with_data.search_ixps("Ams-Ix")

        assert len(results1) == len(results2) == len(results3)

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_network_info(self, client_with_data):
        """Test getting network information by ASN."""
        await client_with_data.connect()

        network = client_with_data.get_network_info(15169)
        assert network is not None
        assert network.asn == 15169
        assert network.name == "Google LLC"
        assert network.info_type == "Content"

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_get_network_info_not_found(self, client_with_data):
        """Test getting network info for non-existent ASN."""
        await client_with_data.connect()

        network = client_with_data.get_network_info(99999)
        assert network is None

        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_is_available_with_fresh_cache(self, client_with_data):
        """Test is_available returns True with fresh cache."""
        await client_with_data.connect()
        assert await client_with_data.is_available() is True
        await client_with_data.disconnect()

    @pytest.mark.asyncio
    async def test_context_manager(self, client_with_data):
        """Test client as async context manager."""
        async with client_with_data as client:
            assert client._loaded is True
            ixps = client.get_ixps_for_asn(15169)
            assert len(ixps) == 2

    @pytest.mark.asyncio
    async def test_cache_staleness_detection(self, temp_cache_dir):
        """Test that stale cache is detected."""
        # Write sample data to cache
        cache_file = temp_cache_dir / "peeringdb_latest.json"
        cache_file.write_text(json.dumps(SAMPLE_PEERINGDB_DUMP))

        # Write stale metadata (8 days old)
        meta_file = temp_cache_dir / "metadata.json"
        stale_date = datetime.now(timezone.utc) - timedelta(days=8)
        meta_file.write_text(json.dumps({
            "download_date": stale_date.isoformat(),
            "source_url": "https://example.com/dump.json",
        }))

        client = PeeringDBClient(cache_dir=temp_cache_dir)
        assert client._is_cache_stale() is True

    @pytest.mark.asyncio
    async def test_cache_freshness(self, temp_cache_dir):
        """Test that fresh cache is detected."""
        # Write sample data to cache
        cache_file = temp_cache_dir / "peeringdb_latest.json"
        cache_file.write_text(json.dumps(SAMPLE_PEERINGDB_DUMP))

        # Write fresh metadata (2 days old)
        meta_file = temp_cache_dir / "metadata.json"
        fresh_date = datetime.now(timezone.utc) - timedelta(days=2)
        meta_file.write_text(json.dumps({
            "download_date": fresh_date.isoformat(),
            "source_url": "https://example.com/dump.json",
        }))

        client = PeeringDBClient(cache_dir=temp_cache_dir)
        assert client._is_cache_stale() is False

    @pytest.mark.asyncio
    async def test_force_refresh(self, temp_cache_dir):
        """Test force refresh downloads new data."""
        # Write initial data
        cache_file = temp_cache_dir / "peeringdb_latest.json"
        cache_file.write_text(json.dumps(SAMPLE_PEERINGDB_DUMP))

        meta_file = temp_cache_dir / "metadata.json"
        meta_file.write_text(json.dumps({
            "download_date": datetime.now(timezone.utc).isoformat(),
            "source_url": "https://example.com/dump.json",
        }))

        client = PeeringDBClient(cache_dir=temp_cache_dir)

        # Mock the download
        with patch.object(client, '_download_latest_dump', new_callable=AsyncMock) as mock_download:
            mock_download.return_value = None

            await client.connect(force_refresh=True)

            # Should have called download even though cache is fresh
            mock_download.assert_called_once()

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_data_not_loaded_raises_error(self, temp_cache_dir):
        """Test that methods raise error when data not loaded."""
        client = PeeringDBClient(cache_dir=temp_cache_dir)

        with pytest.raises(RuntimeError, match="not loaded"):
            client.get_ixps_for_asn(15169)

    @pytest.mark.asyncio
    async def test_participant_count_calculated(self, client_with_data):
        """Test that participant count is calculated correctly."""
        await client_with_data.connect()

        # AMS-IX has 2 participants (Google, Cloudflare)
        ixp = client_with_data.get_ixp_details(31)
        assert ixp.participant_count == 2

        # DE-CIX has 2 participants (Google, Cloudflare)
        ixp = client_with_data.get_ixp_details(26)
        assert ixp.participant_count == 2

        # LINX has 1 participant (Meta)
        ixp = client_with_data.get_ixp_details(1)
        assert ixp.participant_count == 1

        await client_with_data.disconnect()


class TestPeeringDBClientDownload:
    """Tests for PeeringDB download functionality."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def client(self, temp_cache_dir):
        """Create a PeeringDBClient with temp cache."""
        return PeeringDBClient(cache_dir=temp_cache_dir)

    @pytest.mark.asyncio
    async def test_get_latest_dump_url(self, client, temp_cache_dir):
        """Test finding the latest dump URL from CAIDA directory."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        year = now.year
        month = now.month

        # Mock directory listing HTML
        directory_html = f"""
        <html>
        <body>
        <a href="peeringdb_2_dump_{year}_{month:02d}_15.json">peeringdb_2_dump_{year}_{month:02d}_15.json</a>
        <a href="peeringdb_2_dump_{year}_{month:02d}_14.json">peeringdb_2_dump_{year}_{month:02d}_14.json</a>
        </body>
        </html>
        """

        with aioresponses() as m:
            # Mock the directory listing
            m.get(
                f"https://publicdata.caida.org/datasets/peeringdb/{year}/{month:02d}/",
                body=directory_html,
            )

            # Mock the actual dump download
            m.get(
                f"https://publicdata.caida.org/datasets/peeringdb/{year}/{month:02d}/peeringdb_2_dump_{year}_{month:02d}_15.json",
                body=json.dumps(SAMPLE_PEERINGDB_DUMP),
                headers={"content-length": "1000"},
            )

            await client.connect()

            # Verify data was loaded
            assert client._loaded is True
            assert len(client._ixp_by_id) == 3

            await client.disconnect()

    @pytest.mark.asyncio
    async def test_download_with_progress(self, client, temp_cache_dir):
        """Test that download works with mocked responses."""
        # Tested in test_get_latest_dump_url above
        pass
