"""Tests for bgp-radar subprocess client."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.models.event import BGPEvent, EventType, Severity
from bgp_explorer.sources.bgp_radar import BgpRadarClient, BgpRadarError


class TestBgpRadarClient:
    """Tests for BgpRadarClient."""

    @pytest.fixture
    def client(self):
        """Create a BgpRadarClient instance."""
        return BgpRadarClient(binary_path="/usr/local/bin/bgp-radar")

    @pytest.mark.asyncio
    async def test_parse_event_hijack(self, client):
        """Test parsing a hijack event from JSON."""
        json_line = json.dumps({
            "type": "hijack",
            "severity": "high",
            "affected_prefix": "8.8.8.0/24",
            "affected_asn": 15169,
            "timestamp": "2024-01-01T12:00:00Z",
            "expected_origin": 15169,
            "observed_origin": 64496,
        })

        event = client._parse_event(json_line)

        assert event is not None
        assert event.type == EventType.HIJACK
        assert event.severity == Severity.HIGH
        assert event.affected_prefix == "8.8.8.0/24"
        assert event.affected_asn == 15169

    @pytest.mark.asyncio
    async def test_parse_event_leak(self, client):
        """Test parsing a route leak event."""
        json_line = json.dumps({
            "type": "leak",
            "severity": "medium",
            "affected_prefix": "1.1.1.0/24",
            "affected_asn": 13335,
            "timestamp": "2024-01-01T12:00:00Z",
        })

        event = client._parse_event(json_line)

        assert event is not None
        assert event.type == EventType.LEAK
        assert event.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_parse_event_blackhole(self, client):
        """Test parsing a blackhole event."""
        json_line = json.dumps({
            "type": "blackhole",
            "severity": "low",
            "affected_prefix": "192.0.2.0/24",
            "affected_asn": 64496,
            "timestamp": "2024-01-01T12:00:00Z",
        })

        event = client._parse_event(json_line)

        assert event is not None
        assert event.type == EventType.BLACKHOLE

    @pytest.mark.asyncio
    async def test_parse_event_invalid_json(self, client):
        """Test parsing invalid JSON returns None."""
        event = client._parse_event("not valid json")
        assert event is None

    @pytest.mark.asyncio
    async def test_parse_event_non_event_json(self, client):
        """Test parsing non-event JSON returns None."""
        json_line = json.dumps({"info": "connected", "collectors": ["rrc00"]})
        event = client._parse_event(json_line)
        assert event is None

    @pytest.mark.asyncio
    async def test_get_recent_anomalies_empty(self, client):
        """Test getting recent anomalies when cache is empty."""
        anomalies = await client.get_recent_anomalies()
        assert anomalies == []

    @pytest.mark.asyncio
    async def test_get_recent_anomalies_filtered_by_type(self, client):
        """Test filtering anomalies by type."""
        # Add some events to the cache
        event1 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(timezone.utc),
        )
        event2 = BGPEvent(
            type=EventType.LEAK,
            severity=Severity.MEDIUM,
            affected_prefix="1.1.1.0/24",
            detected_at=datetime.now(timezone.utc),
        )
        await client._event_cache.set("event1", event1)
        await client._event_cache.set("event2", event2)
        client._recent_events = [event1, event2]

        # Filter by type
        hijacks = await client.get_recent_anomalies(event_type=EventType.HIJACK)
        assert len(hijacks) == 1
        assert hijacks[0].type == EventType.HIJACK

    @pytest.mark.asyncio
    async def test_get_recent_anomalies_filtered_by_prefix(self, client):
        """Test filtering anomalies by prefix."""
        event1 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(timezone.utc),
        )
        event2 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="1.1.1.0/24",
            detected_at=datetime.now(timezone.utc),
        )
        client._recent_events = [event1, event2]

        filtered = await client.get_recent_anomalies(prefix="8.8.8.0/24")
        assert len(filtered) == 1
        assert filtered[0].affected_prefix == "8.8.8.0/24"

    @pytest.mark.asyncio
    async def test_get_recent_anomalies_filtered_by_asn(self, client):
        """Test filtering anomalies by ASN."""
        event1 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            affected_asn=15169,
            detected_at=datetime.now(timezone.utc),
        )
        event2 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="1.1.1.0/24",
            affected_asn=13335,
            detected_at=datetime.now(timezone.utc),
        )
        client._recent_events = [event1, event2]

        filtered = await client.get_recent_anomalies(asn=15169)
        assert len(filtered) == 1
        assert filtered[0].affected_asn == 15169

    @pytest.mark.asyncio
    async def test_binary_path_from_env(self):
        """Test binary path can be set from environment."""
        with patch.dict("os.environ", {"BGP_RADAR_PATH": "/custom/path/bgp-radar"}):
            client = BgpRadarClient()
            assert client._binary_path == "/custom/path/bgp-radar"

    @pytest.mark.asyncio
    async def test_is_available_binary_not_found(self, client):
        """Test is_available returns False when binary not found."""
        client._binary_path = "/nonexistent/path/bgp-radar"
        available = await client.is_available()
        assert available is False

    @pytest.mark.asyncio
    async def test_collectors_default(self, client):
        """Test default collectors."""
        assert client._collectors == ["rrc00"]

    @pytest.mark.asyncio
    async def test_collectors_custom(self):
        """Test custom collectors."""
        client = BgpRadarClient(collectors=["rrc00", "rrc01", "rrc21"])
        assert client._collectors == ["rrc00", "rrc01", "rrc21"]

    @pytest.mark.asyncio
    async def test_max_events_limit(self, client):
        """Test that recent events list doesn't grow unbounded."""
        client._max_recent_events = 5

        # Add more events than the limit
        for i in range(10):
            event = BGPEvent(
                type=EventType.HIJACK,
                severity=Severity.HIGH,
                affected_prefix=f"10.0.{i}.0/24",
                detected_at=datetime.now(timezone.utc),
            )
            await client._add_event(event)

        assert len(client._recent_events) == 5

    @pytest.mark.asyncio
    async def test_retry_count(self):
        """Test that retry count is configurable."""
        client = BgpRadarClient(max_retries=5)
        assert client._max_retries == 5

    @pytest.mark.asyncio
    async def test_stop_when_not_running(self, client):
        """Test stop when process is not running."""
        await client.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_is_running_false_when_not_started(self, client):
        """Test is_running returns False when not started."""
        assert client.is_running is False
