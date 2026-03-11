"""Tests for RIPE Stat update/looking-glass methods."""

from datetime import UTC, datetime

import pytest
from aioresponses import aioresponses

from bgp_explorer.sources.ripe_stat import RipeStatClient


class TestRipeStatUpdates:
    """Tests for RIPE Stat update and looking-glass methods."""

    @pytest.fixture
    def client(self):
        """Create a RipeStatClient instance."""
        return RipeStatClient()

    @pytest.mark.asyncio
    async def test_get_looking_glass_success(self, client):
        """Test getting looking glass data for a prefix."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "rrcs": [
                    {
                        "rrc": "rrc00",
                        "location": "Amsterdam",
                        "peers": [
                            {
                                "asn_origin": 15169,
                                "as_path": "3356 15169",
                                "community": "3356:123",
                                "peer_ip": "195.66.224.175",
                            }
                        ],
                    },
                    {
                        "rrc": "rrc01",
                        "location": "London",
                        "peers": [
                            {
                                "asn_origin": 15169,
                                "as_path": "174 15169",
                                "community": "",
                                "peer_ip": "195.66.236.56",
                            }
                        ],
                    },
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/looking-glass/data.json?resource=8.8.8.0/24",
                payload=mock_response,
            )

            async with client:
                data = await client.get_looking_glass("8.8.8.0/24")

            assert data["resource"] == "8.8.8.0/24"
            assert len(data["rrcs"]) == 2
            assert data["rrcs"][0]["rrc"] == "rrc00"
            assert data["rrcs"][0]["location"] == "Amsterdam"

    @pytest.mark.asyncio
    async def test_get_looking_glass_with_collector_filter(self, client):
        """Test getting looking glass data with collector filter."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "rrcs": [
                    {
                        "rrc": "rrc00",
                        "location": "Amsterdam",
                        "peers": [],
                    }
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/looking-glass/data.json?resource=8.8.8.0/24&rrcs=rrc00,rrc01",
                payload=mock_response,
            )

            async with client:
                data = await client.get_looking_glass("8.8.8.0/24", collector="rrc00,rrc01")

            assert data["resource"] == "8.8.8.0/24"
            assert len(data["rrcs"]) == 1

    @pytest.mark.asyncio
    async def test_get_bgp_update_activity_success(self, client):
        """Test getting BGP update activity with time buckets."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "sampling_period": 3600,
                "nr_samples": 24,
                "updates": [
                    {
                        "starttime": "2024-01-01T00:00:00",
                        "endtime": "2024-01-01T01:00:00",
                        "announcements": 5,
                        "withdrawals": 2,
                    },
                    {
                        "starttime": "2024-01-01T01:00:00",
                        "endtime": "2024-01-01T02:00:00",
                        "announcements": 3,
                        "withdrawals": 1,
                    },
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/bgp-update-activity/data.json"
                "?resource=8.8.8.0/24&starttime=2024-01-01T00:00:00&endtime=2024-01-02T00:00:00&min_sampling_period=3600",
                payload=mock_response,
            )

            async with client:
                data = await client.get_bgp_update_activity(
                    "8.8.8.0/24",
                    start=datetime(2024, 1, 1, tzinfo=UTC),
                    end=datetime(2024, 1, 2, tzinfo=UTC),
                    min_sampling_period=3600,
                )

            assert data["resource"] == "8.8.8.0/24"
            assert data["sampling_period"] == 3600
            assert len(data["updates"]) == 2
            assert data["updates"][0]["announcements"] == 5
            assert data["updates"][0]["withdrawals"] == 2

    @pytest.mark.asyncio
    async def test_get_bgp_updates_success(self, client):
        """Test getting BGP updates stream."""
        mock_response = {
            "status": "ok",
            "data": {
                "resource": "8.8.8.0/24",
                "updates": [
                    {
                        "type": "A",
                        "timestamp": "2024-01-01T00:05:00",
                        "attrs": {
                            "source_id": "rrc00",
                            "target_prefix": "8.8.8.0/24",
                            "path": [3356, 15169],
                            "community": ["3356:123"],
                        },
                    },
                    {
                        "type": "W",
                        "timestamp": "2024-01-01T00:10:00",
                        "attrs": {
                            "source_id": "rrc00",
                            "target_prefix": "8.8.8.0/24",
                        },
                    },
                    {
                        "type": "A",
                        "timestamp": "2024-01-01T00:15:00",
                        "attrs": {
                            "source_id": "rrc00",
                            "target_prefix": "8.8.8.0/24",
                            "path": [174, 15169],
                            "community": [],
                        },
                    },
                ],
            },
        }

        with aioresponses() as m:
            m.get(
                "https://stat.ripe.net/data/bgp-updates/data.json"
                "?resource=8.8.8.0/24&starttime=2024-01-01T00:00:00&endtime=2024-01-01T01:00:00",
                payload=mock_response,
            )

            async with client:
                data = await client.get_bgp_updates(
                    "8.8.8.0/24",
                    start=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
                    end=datetime(2024, 1, 1, 1, 0, 0, tzinfo=UTC),
                )

            assert data["resource"] == "8.8.8.0/24"
            assert len(data["updates"]) == 3
            # First is an announcement
            assert data["updates"][0]["type"] == "A"
            assert data["updates"][0]["attrs"]["path"] == [3356, 15169]
            # Second is a withdrawal
            assert data["updates"][1]["type"] == "W"
            # Third is an announcement with different path
            assert data["updates"][2]["type"] == "A"
            assert data["updates"][2]["attrs"]["path"] == [174, 15169]
