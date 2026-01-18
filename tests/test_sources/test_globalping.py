"""Tests for Globalping API client."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.globalping import GlobalpingClient, MeasurementResult, ProbeResult


class TestGlobalpingClient:
    """Tests for GlobalpingClient."""

    @pytest.fixture
    def client(self):
        """Create a GlobalpingClient instance."""
        return GlobalpingClient()

    @pytest.mark.asyncio
    async def test_ping_success(self, client):
        """Test successful ping measurement."""
        # Mock create measurement response
        create_response = {
            "id": "test-measurement-id",
            "probesCount": 2,
        }

        # Mock get results response
        results_response = {
            "id": "test-measurement-id",
            "status": "finished",
            "results": [
                {
                    "probe": {
                        "continent": "EU",
                        "country": "DE",
                        "city": "Frankfurt",
                        "asn": 3356,
                        "network": "Level3",
                    },
                    "result": {
                        "status": "finished",
                        "rawOutput": "PING 8.8.8.8...",
                        "stats": {
                            "min": 10.5,
                            "avg": 12.3,
                            "max": 15.1,
                            "loss": 0.0,
                        },
                    },
                },
                {
                    "probe": {
                        "continent": "NA",
                        "country": "US",
                        "city": "New York",
                        "asn": 174,
                        "network": "Cogent",
                    },
                    "result": {
                        "status": "finished",
                        "rawOutput": "PING 8.8.8.8...",
                        "stats": {
                            "min": 5.2,
                            "avg": 7.8,
                            "max": 10.1,
                            "loss": 0.0,
                        },
                    },
                },
            ],
        }

        with aioresponses() as m:
            m.post(
                "https://api.globalping.io/v1/measurements",
                payload=create_response,
            )
            m.get(
                "https://api.globalping.io/v1/measurements/test-measurement-id",
                payload=results_response,
            )

            async with client:
                result = await client.ping("8.8.8.8", locations=[{"country": "DE"}, {"country": "US"}])

            assert result.measurement_id == "test-measurement-id"
            assert result.status == "finished"
            assert len(result.probes) == 2
            assert result.probes[0].country == "DE"
            assert result.probes[0].avg_latency == 12.3
            assert result.probes[1].country == "US"

    @pytest.mark.asyncio
    async def test_traceroute_success(self, client):
        """Test successful traceroute measurement."""
        create_response = {"id": "trace-id", "probesCount": 1}
        results_response = {
            "id": "trace-id",
            "status": "finished",
            "results": [
                {
                    "probe": {
                        "continent": "EU",
                        "country": "NL",
                        "city": "Amsterdam",
                        "asn": 1299,
                        "network": "Telia",
                    },
                    "result": {
                        "status": "finished",
                        "rawOutput": "traceroute to 8.8.8.8...",
                        "hops": [
                            {"hop": 1, "hosts": [{"ip": "10.0.0.1", "rtt": 1.5}]},
                            {"hop": 2, "hosts": [{"ip": "192.168.1.1", "rtt": 5.2}]},
                        ],
                    },
                },
            ],
        }

        with aioresponses() as m:
            m.post("https://api.globalping.io/v1/measurements", payload=create_response)
            m.get("https://api.globalping.io/v1/measurements/trace-id", payload=results_response)

            async with client:
                result = await client.traceroute("8.8.8.8", locations=[{"country": "NL"}])

            assert result.status == "finished"
            assert len(result.probes) == 1
            assert result.probes[0].hops is not None
            assert len(result.probes[0].hops) == 2

    @pytest.mark.asyncio
    async def test_mtr_success(self, client):
        """Test successful MTR measurement."""
        create_response = {"id": "mtr-id", "probesCount": 1}
        results_response = {
            "id": "mtr-id",
            "status": "finished",
            "results": [
                {
                    "probe": {
                        "continent": "AS",
                        "country": "JP",
                        "city": "Tokyo",
                        "asn": 2516,
                        "network": "KDDI",
                    },
                    "result": {
                        "status": "finished",
                        "rawOutput": "mtr report...",
                        "hops": [
                            {"hop": 1, "asn": [2516], "hosts": [{"ip": "10.0.0.1", "rtt": 2.0, "loss": 0}]},
                        ],
                    },
                },
            ],
        }

        with aioresponses() as m:
            m.post("https://api.globalping.io/v1/measurements", payload=create_response)
            m.get("https://api.globalping.io/v1/measurements/mtr-id", payload=results_response)

            async with client:
                result = await client.mtr("1.1.1.1", locations=[{"country": "JP"}])

            assert result.status == "finished"
            assert result.probes[0].country == "JP"

    @pytest.mark.asyncio
    async def test_dns_lookup_success(self, client):
        """Test successful DNS lookup."""
        create_response = {"id": "dns-id", "probesCount": 1}
        results_response = {
            "id": "dns-id",
            "status": "finished",
            "results": [
                {
                    "probe": {
                        "continent": "EU",
                        "country": "GB",
                        "city": "London",
                        "asn": 5400,
                        "network": "BT",
                    },
                    "result": {
                        "status": "finished",
                        "rawOutput": "google.com A 142.250.x.x",
                        "answers": [
                            {"type": "A", "value": "142.250.185.78", "ttl": 300},
                        ],
                    },
                },
            ],
        }

        with aioresponses() as m:
            m.post("https://api.globalping.io/v1/measurements", payload=create_response)
            m.get("https://api.globalping.io/v1/measurements/dns-id", payload=results_response)

            async with client:
                result = await client.dns("google.com", locations=[{"country": "GB"}])

            assert result.status == "finished"
            assert result.probes[0].dns_answers is not None

    @pytest.mark.asyncio
    async def test_is_available(self, client):
        """Test availability check."""
        with aioresponses() as m:
            m.get("https://api.globalping.io/v1/probes", payload={"count": 500})

            async with client:
                available = await client.is_available()

            assert available is True

    @pytest.mark.asyncio
    async def test_is_available_failure(self, client):
        """Test availability check when API is down."""
        with aioresponses() as m:
            m.get("https://api.globalping.io/v1/probes", status=500)

            async with client:
                available = await client.is_available()

            assert available is False

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with GlobalpingClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_locations_parsing(self, client):
        """Test various location formats."""
        # Test with country code - limit is added automatically
        loc1 = client._parse_locations([{"country": "US"}])
        assert loc1 == [{"country": "US", "limit": 3}]

        # Test with continent
        loc2 = client._parse_locations([{"continent": "EU"}])
        assert loc2 == [{"continent": "EU", "limit": 3}]

        # Test with ASN
        loc3 = client._parse_locations([{"asn": 15169}])
        assert loc3 == [{"asn": 15169, "limit": 3}]

        # Test with custom limit
        loc4 = client._parse_locations([{"country": "DE"}], limit=5)
        assert loc4 == [{"country": "DE", "limit": 5}]

        # Test with location that already has limit (should not override)
        loc5 = client._parse_locations([{"country": "FR", "limit": 10}])
        assert loc5 == [{"country": "FR", "limit": 10}]

    @pytest.mark.asyncio
    async def test_default_locations(self, client):
        """Test default global locations."""
        defaults = client._default_locations()
        assert len(defaults) > 0
        # Should include multiple continents
        continents = [loc.get("continent") for loc in defaults]
        assert "EU" in continents or "NA" in continents

    def test_probe_result_from_dict(self):
        """Test creating ProbeResult from API response."""
        data = {
            "probe": {
                "continent": "EU",
                "country": "DE",
                "city": "Berlin",
                "asn": 3320,
                "network": "Deutsche Telekom",
            },
            "result": {
                "status": "finished",
                "rawOutput": "ping output",
                "stats": {"min": 10, "avg": 15, "max": 20, "loss": 0},
            },
        }
        probe = ProbeResult.from_dict(data)
        assert probe.country == "DE"
        assert probe.city == "Berlin"
        assert probe.asn == 3320
        assert probe.avg_latency == 15
