"""Tests for RIPE Stat REST client."""

from datetime import UTC, datetime

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.ripe_stat import RipeStatClient


class TestRipeStatClient:
    """Tests for RipeStatClient."""

    @pytest.fixture
    def client(self):
        """Create a RipeStatClient instance."""
        return RipeStatClient()

    @pytest.mark.asyncio
    async def test_get_bgp_state_success(self, client):
        """Test getting BGP state for a prefix."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "bgp_state": [
                    {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc00",
                        "path": [3356, 15169],
                        "community": ["3356:123"],
                    },
                    {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc01",
                        "path": [174, 15169],
                        "community": [],
                    },
                ],
                "query_time": "2024-01-01T12:00:00",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/bgp-state/data.json?resource=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                routes = await client.get_bgp_state("8.8.8.0/24")

            assert len(routes) == 2
            assert routes[0].prefix == "8.8.8.0/24"
            assert routes[0].origin_asn == 15169
            assert routes[0].as_path == [3356, 15169]
            assert routes[0].collector == "rrc00"

    @pytest.mark.asyncio
    async def test_get_routing_status(self, client):
        """Test getting routing status for an ASN."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "AS15169",
                "first_seen": {
                    "prefix": "8.8.8.0/24",
                    "origin": 15169,
                    "time": "2010-01-01T00:00:00",
                },
                "announced_space": {
                    "v4": {"prefixes": 1000, "ips": 16000000},
                    "v6": {"prefixes": 500, "ips": 0},
                },
                "observed_peers": 100,
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/routing-status/data.json?resource=AS15169",
                payload=mock_response,
            )

            async with client:
                status = await client.get_routing_status(15169)

            assert status["resource"] == "AS15169"
            assert status["observed_peers"] == 100

    @pytest.mark.asyncio
    async def test_get_rpki_validation_valid(self, client):
        """Test RPKI validation returning valid status."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "15169",
                "prefix": "8.8.8.0/24",
                "validating_roas": [
                    {
                        "origin": "15169",
                        "prefix": "8.8.8.0/24",
                        "max_length": 24,
                        "validity": "valid",
                    }
                ],
                "status": "valid",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=15169&prefix=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                status = await client.get_rpki_validation("8.8.8.0/24", 15169)

            assert status == "valid"

    @pytest.mark.asyncio
    async def test_get_rpki_validation_invalid(self, client):
        """Test RPKI validation returning invalid status."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "64496",
                "prefix": "1.2.3.0/24",
                "validating_roas": [],
                "status": "invalid",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=64496&prefix=1.2.3.0/24",
                payload=mock_response,
            )

            async with client:
                status = await client.get_rpki_validation("1.2.3.0/24", 64496)

            assert status == "invalid"

    @pytest.mark.asyncio
    async def test_get_rpki_validation_invalid_asn(self, client):
        """Test RPKI validation normalizes 'invalid_asn' to 'invalid'."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "15169",
                "prefix": "1.1.1.0/24",
                "validating_roas": [],
                "status": "invalid_asn",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=15169&prefix=1.1.1.0/24",
                payload=mock_response,
            )

            async with client:
                status = await client.get_rpki_validation("1.1.1.0/24", 15169)

            assert status == "invalid"

    @pytest.mark.asyncio
    async def test_get_rpki_validation_invalid_length(self, client):
        """Test RPKI validation normalizes 'invalid_length' to 'invalid'."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "13335",
                "prefix": "1.1.1.0/25",
                "validating_roas": [],
                "status": "invalid_length",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=13335&prefix=1.1.1.0/25",
                payload=mock_response,
            )

            async with client:
                status = await client.get_rpki_validation("1.1.1.0/25", 13335)

            assert status == "invalid"

    @pytest.mark.asyncio
    async def test_get_rpki_validation_detail_valid(self, client):
        """Test RPKI validation detail returns ROA fields."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "15169",
                "prefix": "8.8.8.0/24",
                "validating_roas": [
                    {
                        "origin": "15169",
                        "prefix": "8.8.8.0/24",
                        "max_length": 24,
                        "validity": "valid",
                    }
                ],
                "status": "valid",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=15169&prefix=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                result = await client.get_rpki_validation_detail("8.8.8.0/24", 15169)

            assert result["status"] == "valid"
            assert result["prefix"] == "8.8.8.0/24"
            assert result["origin_asn"] == 15169
            assert len(result["validating_roas"]) == 1
            assert result["validating_roas"][0]["max_length"] == 24
            assert result["validating_roas"][0]["origin"] == "15169"

    @pytest.mark.asyncio
    async def test_get_rpki_validation_detail_not_found(self, client):
        """Test RPKI validation detail with no ROAs."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "64496",
                "prefix": "10.0.0.0/8",
                "validating_roas": [],
                "status": "not-found",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=64496&prefix=10.0.0.0/8",
                payload=mock_response,
            )

            async with client:
                result = await client.get_rpki_validation_detail("10.0.0.0/8", 64496)

            assert result["status"] == "not-found"
            assert result["validating_roas"] == []

    @pytest.mark.asyncio
    async def test_get_rpki_validation_detail_invalid_normalizes(self, client):
        """Test RPKI validation detail normalizes invalid_asn to invalid."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "64496",
                "prefix": "1.2.3.0/24",
                "validating_roas": [
                    {
                        "origin": "15169",
                        "prefix": "1.2.3.0/24",
                        "max_length": 24,
                        "validity": "invalid_asn",
                    }
                ],
                "status": "invalid_asn",
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/rpki-validation/data.json?resource=64496&prefix=1.2.3.0/24",
                payload=mock_response,
            )

            async with client:
                result = await client.get_rpki_validation_detail("1.2.3.0/24", 64496)

            assert result["status"] == "invalid"
            assert len(result["validating_roas"]) == 1

    @pytest.mark.asyncio
    async def test_get_whois_data_asn(self, client):
        """Test WHOIS data retrieval for an ASN."""
        mock_response = {
            "status": "ok",
            "data": {
                "records": [
                    [
                        {"key": "ASNumber", "value": "15169"},
                        {"key": "ASName", "value": "GOOGLE"},
                        {"key": "OrgName", "value": "Google LLC"},
                    ]
                ],
                "irr_records": [],
                "authorities": ["arin"],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/whois/data.json?resource=AS15169",
                payload=mock_response,
            )

            async with client:
                result = await client.get_whois_data("AS15169")

            assert len(result["records"]) == 1
            assert result["irr_records"] == []
            assert result["authorities"] == ["arin"]

    @pytest.mark.asyncio
    async def test_get_whois_data_prefix(self, client):
        """Test WHOIS data retrieval for a prefix."""
        mock_response = {
            "status": "ok",
            "data": {
                "records": [
                    [
                        {"key": "inetnum", "value": "193.0.0.0 - 193.0.7.255"},
                        {"key": "netname", "value": "RIPE-NCC"},
                    ]
                ],
                "irr_records": [
                    [
                        {"key": "route", "value": "193.0.0.0/21"},
                        {"key": "origin", "value": "AS3333"},
                        {"key": "source", "value": "RIPE"},
                    ]
                ],
                "authorities": ["ripe"],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/whois/data.json?resource=193.0.0.0/21",
                payload=mock_response,
            )

            async with client:
                result = await client.get_whois_data("193.0.0.0/21")

            assert len(result["records"]) == 1
            assert len(result["irr_records"]) == 1
            assert result["authorities"] == ["ripe"]

    @pytest.mark.asyncio
    async def test_get_routing_history(self, client):
        """Test getting routing history for a resource."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "by_origin": [
                    {
                        "origin": "15169",
                        "prefixes": [
                            {
                                "prefix": "8.8.8.0/24",
                                "timelines": [
                                    {
                                        "starttime": "2020-01-01T00:00:00",
                                        "endtime": "2024-01-01T00:00:00",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/routing-history/data.json?resource=8.8.8.0/24&starttime=2020-01-01T00:00:00&endtime=2024-01-01T00:00:00",
                payload=mock_response,
            )

            async with client:
                history = await client.get_routing_history(
                    "8.8.8.0/24",
                    start=datetime(2020, 1, 1, tzinfo=UTC),
                    end=datetime(2024, 1, 1, tzinfo=UTC),
                )

            assert history["resource"] == "8.8.8.0/24"
            assert len(history["by_origin"]) == 1

    @pytest.mark.asyncio
    async def test_get_announced_prefixes(self, client):
        """Test getting announced prefixes for an ASN."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "AS15169",
                "prefixes": [
                    {"prefix": "8.8.8.0/24", "timelines": []},
                    {"prefix": "8.8.4.0/24", "timelines": []},
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169",
                payload=mock_response,
            )

            async with client:
                prefixes = await client.get_announced_prefixes(15169)

            assert len(prefixes) == 2
            assert "8.8.8.0/24" in prefixes
            assert "8.8.4.0/24" in prefixes

    @pytest.mark.asyncio
    async def test_is_available(self, client):
        """Test availability check."""
        mock_response = {"status": "ok", "data": {}}

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/bgp-state/data.json?resource=1.1.1.0/24",
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
                "https://stat.ripe.net/data/bgp-state/data.json?resource=1.1.1.0/24",
                status=500,
            )

            async with client:
                available = await client.is_available()

            assert available is False

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test client as async context manager."""
        async with RipeStatClient() as client:
            assert client._session is not None

    @pytest.mark.asyncio
    async def test_caching(self, client):
        """Test that responses are cached."""
        mock_response = {
            "status": "ok",
            "data": {"resource": "8.8.8.0/24", "bgp_state": []},
        }

        with aioresponses() as m:
            # Only add one mock - second call should use cache
            m.get(
                "https://stat.ripe.net/data/bgp-state/data.json?resource=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                # First call
                await client.get_bgp_state("8.8.8.0/24")
                # Second call should use cache
                await client.get_bgp_state("8.8.8.0/24")

            # If caching works, we only made one HTTP request
