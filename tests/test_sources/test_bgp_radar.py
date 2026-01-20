"""Tests for bgp-radar subprocess client."""

import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from bgp_explorer.models.event import BGPEvent, EventType, Severity
from bgp_explorer.sources.bgp_radar import BgpRadarClient


class TestBgpRadarClient:
    """Tests for BgpRadarClient."""

    @pytest.fixture
    def client(self):
        """Create a BgpRadarClient instance."""
        return BgpRadarClient(binary_path="/usr/local/bin/bgp-radar")

    @pytest.mark.asyncio
    async def test_parse_event_hijack(self, client):
        """Test parsing a hijack event from bgp-radar log line."""
        event_json = json.dumps(
            {
                "type": "hijack",
                "severity": "high",
                "affected_prefix": "8.8.8.0/24",
                "affected_asn": 15169,
                "timestamp": "2024-01-01T12:00:00Z",
                "expected_origin": 15169,
                "observed_origin": 64496,
            }
        )
        log_line = f"2024/01/01 12:00:00 EVENT: {event_json}"

        event = client._parse_event(log_line)

        assert event is not None
        assert event.type == EventType.HIJACK
        assert event.severity == Severity.HIGH
        assert event.affected_prefix == "8.8.8.0/24"
        assert event.affected_asn == 15169

    @pytest.mark.asyncio
    async def test_parse_event_leak(self, client):
        """Test parsing a route leak event."""
        event_json = json.dumps(
            {
                "type": "leak",
                "severity": "medium",
                "affected_prefix": "1.1.1.0/24",
                "affected_asn": 13335,
                "timestamp": "2024-01-01T12:00:00Z",
            }
        )
        log_line = f"2024/01/01 12:00:00 EVENT: {event_json}"

        event = client._parse_event(log_line)

        assert event is not None
        assert event.type == EventType.LEAK
        assert event.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_parse_event_blackhole(self, client):
        """Test parsing a blackhole event."""
        event_json = json.dumps(
            {
                "type": "blackhole",
                "severity": "low",
                "affected_prefix": "192.0.2.0/24",
                "affected_asn": 64496,
                "timestamp": "2024-01-01T12:00:00Z",
            }
        )
        log_line = f"2024/01/01 12:00:00 EVENT: {event_json}"

        event = client._parse_event(log_line)

        assert event is not None
        assert event.type == EventType.BLACKHOLE

    @pytest.mark.asyncio
    async def test_parse_event_invalid_json(self, client):
        """Test parsing invalid JSON returns None."""
        event = client._parse_event("EVENT: not valid json")
        assert event is None

    @pytest.mark.asyncio
    async def test_parse_event_non_event_line(self, client):
        """Test parsing non-event log lines returns None."""
        # STATS line should be ignored
        event = client._parse_event("2024/01/01 12:00:00 STATS: updates=1000 (100/s)")
        assert event is None

        # Info line should be ignored
        event = client._parse_event("2024/01/01 12:00:00 bgp-radar starting...")
        assert event is None

    @pytest.mark.asyncio
    async def test_parse_event_without_prefix(self, client):
        """Test that raw JSON without EVENT: prefix returns None."""
        json_line = json.dumps({"type": "hijack", "severity": "high"})
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
            detected_at=datetime.now(UTC),
        )
        event2 = BGPEvent(
            type=EventType.LEAK,
            severity=Severity.MEDIUM,
            affected_prefix="1.1.1.0/24",
            detected_at=datetime.now(UTC),
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
            detected_at=datetime.now(UTC),
        )
        event2 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="1.1.1.0/24",
            detected_at=datetime.now(UTC),
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
            detected_at=datetime.now(UTC),
        )
        event2 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="1.1.1.0/24",
            affected_asn=13335,
            detected_at=datetime.now(UTC),
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
                detected_at=datetime.now(UTC),
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

    @pytest.mark.asyncio
    async def test_event_callback_invoked_on_add_event(self, client):
        """Test that event callback is invoked when an event is added."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)

        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(UTC),
        )
        await client._add_event(event)

        assert len(received_events) == 1
        assert received_events[0] == event

    @pytest.mark.asyncio
    async def test_event_callback_not_invoked_when_not_set(self, client):
        """Test that no error occurs when callback is not set."""
        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(UTC),
        )
        # Should not raise
        await client._add_event(event)
        assert len(client._recent_events) == 1

    @pytest.mark.asyncio
    async def test_event_callback_can_be_cleared(self, client):
        """Test that event callback can be cleared."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)
        client.set_event_callback(None)

        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(UTC),
        )
        await client._add_event(event)

        assert len(received_events) == 0

    @pytest.mark.asyncio
    async def test_event_filter_single_type(self, client):
        """Test filtering events by single type."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)
        client.set_event_filter({EventType.HIJACK})

        # Add hijack - should pass filter
        hijack = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=datetime.now(UTC),
        )
        await client._add_event(hijack)

        # Add leak - should be filtered out
        leak = BGPEvent(
            type=EventType.LEAK,
            severity=Severity.MEDIUM,
            affected_prefix="1.1.1.0/24",
            detected_at=datetime.now(UTC),
        )
        await client._add_event(leak)

        assert len(received_events) == 1
        assert received_events[0].type == EventType.HIJACK

    @pytest.mark.asyncio
    async def test_event_filter_multiple_types(self, client):
        """Test filtering events by multiple types."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)
        client.set_event_filter({EventType.HIJACK, EventType.LEAK})

        # Add all three types
        for event_type in [EventType.HIJACK, EventType.LEAK, EventType.BLACKHOLE]:
            event = BGPEvent(
                type=event_type,
                severity=Severity.HIGH,
                affected_prefix="8.8.8.0/24",
                detected_at=datetime.now(UTC),
            )
            await client._add_event(event)

        assert len(received_events) == 2
        assert {e.type for e in received_events} == {EventType.HIJACK, EventType.LEAK}

    @pytest.mark.asyncio
    async def test_event_filter_empty_passes_all(self, client):
        """Test that empty filter passes all events."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)
        client.set_event_filter(set())  # Empty filter = all events

        for event_type in [EventType.HIJACK, EventType.LEAK, EventType.BLACKHOLE]:
            event = BGPEvent(
                type=event_type,
                severity=Severity.HIGH,
                affected_prefix="8.8.8.0/24",
                detected_at=datetime.now(UTC),
            )
            await client._add_event(event)

        assert len(received_events) == 3

    @pytest.mark.asyncio
    async def test_event_filter_can_be_changed(self, client):
        """Test that filter can be changed while running."""
        received_events = []

        def callback(event: BGPEvent) -> None:
            received_events.append(event)

        client.set_event_callback(callback)
        client.set_event_filter({EventType.HIJACK})

        # Add hijack - passes
        await client._add_event(
            BGPEvent(
                type=EventType.HIJACK,
                severity=Severity.HIGH,
                affected_prefix="8.8.8.0/24",
                detected_at=datetime.now(UTC),
            )
        )

        # Change filter to leak only
        client.set_event_filter({EventType.LEAK})

        # Add leak - now passes
        await client._add_event(
            BGPEvent(
                type=EventType.LEAK,
                severity=Severity.MEDIUM,
                affected_prefix="1.1.1.0/24",
                detected_at=datetime.now(UTC),
            )
        )

        # Add hijack - now filtered out
        await client._add_event(
            BGPEvent(
                type=EventType.HIJACK,
                severity=Severity.HIGH,
                affected_prefix="2.2.2.0/24",
                detected_at=datetime.now(UTC),
            )
        )

        assert len(received_events) == 2
        assert received_events[0].type == EventType.HIJACK
        assert received_events[1].type == EventType.LEAK
