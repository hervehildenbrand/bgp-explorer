"""Tests for BGPEvent data model."""

from datetime import datetime, timezone

import pytest

from bgp_explorer.models.event import BGPEvent, EventType, Severity


class TestBGPEvent:
    """Tests for BGPEvent dataclass."""

    def test_create_hijack_event(self):
        """Test creating a hijack event."""
        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            affected_asn=15169,
            detected_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            details={"expected_origin": 15169, "observed_origin": 64496},
        )
        assert event.type == EventType.HIJACK
        assert event.severity == Severity.HIGH
        assert event.affected_prefix == "8.8.8.0/24"
        assert event.affected_asn == 15169

    def test_create_leak_event(self):
        """Test creating a route leak event."""
        event = BGPEvent(
            type=EventType.LEAK,
            severity=Severity.MEDIUM,
            affected_prefix="1.1.1.0/24",
            affected_asn=13335,
            detected_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            details={"leaking_asn": 64496, "path": [64496, 3356, 13335]},
        )
        assert event.type == EventType.LEAK
        assert event.severity == Severity.MEDIUM

    def test_create_blackhole_event(self):
        """Test creating a blackhole event."""
        event = BGPEvent(
            type=EventType.BLACKHOLE,
            severity=Severity.LOW,
            affected_prefix="192.0.2.0/24",
            affected_asn=64496,
            detected_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            details={"blackhole_community": "65535:666"},
        )
        assert event.type == EventType.BLACKHOLE
        assert event.severity == Severity.LOW

    def test_event_defaults(self):
        """Test event optional field defaults."""
        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="192.0.2.0/24",
            detected_at=datetime.now(timezone.utc),
        )
        assert event.affected_asn is None
        assert event.details == {}

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        event = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            affected_asn=15169,
            detected_at=ts,
            details={"key": "value"},
        )
        d = event.to_dict()
        assert d["type"] == "hijack"
        assert d["severity"] == "high"
        assert d["affected_prefix"] == "8.8.8.0/24"
        assert d["detected_at"] == "2024-01-01T12:00:00+00:00"

    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        data = {
            "type": "hijack",
            "severity": "high",
            "affected_prefix": "8.8.8.0/24",
            "affected_asn": 15169,
            "detected_at": "2024-01-01T12:00:00+00:00",
            "details": {},
        }
        event = BGPEvent.from_dict(data)
        assert event.type == EventType.HIJACK
        assert event.severity == Severity.HIGH
        assert event.affected_prefix == "8.8.8.0/24"

    def test_event_from_bgp_radar_json(self):
        """Test creating event from bgp-radar JSON output."""
        radar_json = {
            "type": "hijack",
            "severity": "high",
            "affected_prefix": "1.1.1.0/24",
            "affected_asn": 13335,
            "timestamp": "2024-01-01T12:00:00Z",
            "expected_origin": 13335,
            "observed_origin": 64496,
        }
        event = BGPEvent.from_bgp_radar(radar_json)
        assert event.type == EventType.HIJACK
        assert event.affected_prefix == "1.1.1.0/24"
        assert event.details["expected_origin"] == 13335
        assert event.details["observed_origin"] == 64496

    def test_event_type_from_string(self):
        """Test EventType enum from string."""
        assert EventType("hijack") == EventType.HIJACK
        assert EventType("leak") == EventType.LEAK
        assert EventType("blackhole") == EventType.BLACKHOLE

    def test_severity_from_string(self):
        """Test Severity enum from string."""
        assert Severity("low") == Severity.LOW
        assert Severity("medium") == Severity.MEDIUM
        assert Severity("high") == Severity.HIGH

    def test_event_equality(self):
        """Test event equality comparison."""
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        event1 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=ts,
        )
        event2 = BGPEvent(
            type=EventType.HIJACK,
            severity=Severity.HIGH,
            affected_prefix="8.8.8.0/24",
            detected_at=ts,
        )
        assert event1 == event2
