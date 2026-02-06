"""Tests for Globalping API client."""

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.globalping import GlobalpingClient, ProbeResult


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
                result = await client.ping(
                    "8.8.8.8", locations=[{"country": "DE"}, {"country": "US"}]
                )

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
                            {
                                "hop": 1,
                                "asn": [2516],
                                "hosts": [{"ip": "10.0.0.1", "rtt": 2.0, "loss": 0}],
                            },
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
    async def test_locations_parsing_strings(self, client):
        """Test location parsing with string inputs (as AI might provide)."""
        # Test with continent name
        loc1 = client._parse_locations(["Europe"])
        assert loc1 == [{"continent": "EU", "limit": 3}]

        # Test with continent code
        loc2 = client._parse_locations(["EU"])
        assert loc2 == [{"continent": "EU", "limit": 3}]

        # Test with 2-letter country code (not in country_map)
        loc3 = client._parse_locations(["DE"])
        assert loc3 == [{"country": "DE", "limit": 3}]

        # Test mixed string and dict
        loc4 = client._parse_locations(["EU", {"country": "US"}])
        assert loc4 == [{"continent": "EU", "limit": 3}, {"country": "US", "limit": 3}]

        # Test multiple regions
        loc5 = client._parse_locations(["Europe", "Asia"])
        assert loc5 == [{"continent": "EU", "limit": 3}, {"continent": "AS", "limit": 3}]

    @pytest.mark.asyncio
    async def test_locations_parsing_country_names(self, client):
        """Test that country names/aliases are correctly parsed as countries, not continents.

        This is critical for user intent: "from the US" should mean United States probes only,
        not all of North America.
        """
        # "US" should map to country, not continent NA
        loc1 = client._parse_locations(["US"])
        assert loc1 == [{"country": "US", "limit": 3}]

        # "USA" should also map to country US
        loc2 = client._parse_locations(["USA"])
        assert loc2 == [{"country": "US", "limit": 3}]

        # "United States" should map to country US
        loc3 = client._parse_locations(["United States"])
        assert loc3 == [{"country": "US", "limit": 3}]

        # "UK" should map to country GB
        loc4 = client._parse_locations(["UK"])
        assert loc4 == [{"country": "GB", "limit": 3}]

        # "Germany" should map to country DE
        loc5 = client._parse_locations(["Germany"])
        assert loc5 == [{"country": "DE", "limit": 3}]

        # "Australia" should map to country AU, not continent OC
        loc6 = client._parse_locations(["Australia"])
        assert loc6 == [{"country": "AU", "limit": 3}]

        # Case insensitive
        loc7 = client._parse_locations(["us"])
        assert loc7 == [{"country": "US", "limit": 3}]

        loc8 = client._parse_locations(["Us"])
        assert loc8 == [{"country": "US", "limit": 3}]

        # Multiple countries
        loc9 = client._parse_locations(["US", "Germany", "Japan"])
        assert loc9 == [
            {"country": "US", "limit": 3},
            {"country": "DE", "limit": 3},
            {"country": "JP", "limit": 3},
        ]

    @pytest.mark.asyncio
    async def test_locations_parsing_continent_vs_country(self, client):
        """Test that continent and country filters are distinguished correctly."""
        # "North America" should be continent NA
        loc1 = client._parse_locations(["North America"])
        assert loc1 == [{"continent": "NA", "limit": 3}]

        # "NA" should be continent NA
        loc2 = client._parse_locations(["NA"])
        assert loc2 == [{"continent": "NA", "limit": 3}]

        # "US" should be country US (not continent NA)
        loc3 = client._parse_locations(["US"])
        assert loc3 == [{"country": "US", "limit": 3}]

        # Mixed continents and countries
        loc4 = client._parse_locations(["Europe", "US", "Japan"])
        assert loc4 == [
            {"continent": "EU", "limit": 3},
            {"country": "US", "limit": 3},
            {"country": "JP", "limit": 3},
        ]

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

    @pytest.mark.asyncio
    async def test_no_probes_available_error(self, client):
        """Test that 422 response for no probes raises a helpful ValueError."""
        error_response = {
            "error": {
                "type": "validation_error",
                "message": "No suitable probes found matching the provided criteria",
            }
        }

        with aioresponses() as m:
            m.post(
                "https://api.globalping.io/v1/measurements",
                payload=error_response,
                status=422,
            )

            async with client:
                with pytest.raises(ValueError) as exc_info:
                    await client.ping("8.8.8.8", locations=["US"])

                # Should have a helpful error message
                assert "No probes available" in str(exc_info.value)
                assert "US" in str(exc_info.value)
                assert "Try a different region" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_generic_422_error(self, client):
        """Test that other 422 errors are also handled."""
        error_response = {
            "error": {
                "type": "validation_error",
                "message": "Invalid target specified",
            }
        }

        with aioresponses() as m:
            m.post(
                "https://api.globalping.io/v1/measurements",
                payload=error_response,
                status=422,
            )

            async with client:
                with pytest.raises(ValueError) as exc_info:
                    await client.ping("invalid-target")

                assert "Invalid target specified" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_parse_locations_caps_total_probes(self, client):
        """Test that _parse_locations caps total probes to avoid Globalping API limits."""
        # 10 locations with limit=10 = 100 probes, should be capped to ~50
        locations = ["US", "DE", "JP", "BR", "AU", "SG", "ZA", "IN", "FR", "GB"]
        result = client._parse_locations(locations, limit=10)

        total_probes = sum(loc.get("limit", 0) for loc in result)
        assert total_probes <= 50
        assert len(result) == 10  # All locations preserved
        # Each location should have at least 1 probe
        for loc in result:
            assert loc["limit"] >= 1

    @pytest.mark.asyncio
    async def test_parse_locations_no_cap_when_under_limit(self, client):
        """Test that _parse_locations does NOT cap when total probes are reasonable."""
        # 3 locations with limit=3 = 9 probes, should not be capped
        locations = ["US", "DE", "JP"]
        result = client._parse_locations(locations, limit=3)

        total_probes = sum(loc.get("limit", 0) for loc in result)
        assert total_probes == 9  # No capping needed

    @pytest.mark.asyncio
    async def test_400_bad_request_error(self, client):
        """Test that 400 errors are handled with the error message."""
        error_response = {
            "error": {
                "type": "bad_request",
                "message": "Missing required field: target",
            }
        }

        with aioresponses() as m:
            m.post(
                "https://api.globalping.io/v1/measurements",
                payload=error_response,
                status=400,
            )

            async with client:
                with pytest.raises(ValueError) as exc_info:
                    await client.ping("")

                assert "Missing required field" in str(exc_info.value)
