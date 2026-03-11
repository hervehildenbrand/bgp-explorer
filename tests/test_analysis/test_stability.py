"""Tests for BGP stability analysis module."""

import pytest

from bgp_explorer.analysis.stability import StabilityAnalyzer, StabilityReport


class TestStabilityReport:
    """Tests for StabilityReport dataclass."""

    def test_report_creation(self):
        """Test creating a stability report."""
        report = StabilityReport(
            resource="8.8.8.0/24",
            period_start="2024-01-01T00:00:00",
            period_end="2024-01-02T00:00:00",
            total_updates=50,
            announcements=30,
            withdrawals=20,
            flap_count=5,
            updates_per_day=50.0,
            withdrawal_ratio=0.4,
            stability_score=6.5,
            is_stable=False,
            is_flapping=False,
        )
        assert report.resource == "8.8.8.0/24"
        assert report.total_updates == 50
        assert report.stability_score == 6.5


class TestStabilityAnalyzer:
    """Tests for StabilityAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create StabilityAnalyzer instance."""
        return StabilityAnalyzer()

    def test_analyze_stable_prefix(self, analyzer):
        """Test analysis of a stable prefix with low updates."""
        # Simulate activity data with very few updates
        activity_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "endtime": "2024-01-01T01:00:00",
                    "announcements": 1,
                    "withdrawals": 0,
                },
                {
                    "starttime": "2024-01-01T01:00:00",
                    "endtime": "2024-01-01T02:00:00",
                    "announcements": 0,
                    "withdrawals": 0,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("8.8.8.0/24", activity_data)

        assert report.is_stable is True
        assert report.is_flapping is False
        assert report.stability_score >= 8.0  # High score for stable prefix
        assert report.total_updates == 1
        assert report.announcements == 1
        assert report.withdrawals == 0

    def test_analyze_flapping_prefix(self, analyzer):
        """Test analysis of a flapping prefix with many updates."""
        # Simulate activity data with many updates (flapping)
        activity_data = {
            "resource": "10.0.0.0/24",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "endtime": "2024-01-01T01:00:00",
                    "announcements": 100,
                    "withdrawals": 80,
                },
                {
                    "starttime": "2024-01-01T01:00:00",
                    "endtime": "2024-01-01T02:00:00",
                    "announcements": 120,
                    "withdrawals": 100,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("10.0.0.0/24", activity_data)

        assert report.is_flapping is True
        assert report.is_stable is False
        assert report.stability_score <= 5.0  # Low score for flapping
        assert report.total_updates == 400  # 100+80+120+100 = 400
        assert report.updates_per_day > 100

    def test_analyze_moderate_activity(self, analyzer):
        """Test analysis of prefix with moderate activity."""
        # Simulate moderate activity (not stable, not flapping)
        activity_data = {
            "resource": "192.168.0.0/24",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "endtime": "2024-01-01T12:00:00",
                    "announcements": 20,
                    "withdrawals": 10,
                },
                {
                    "starttime": "2024-01-01T12:00:00",
                    "endtime": "2024-01-02T00:00:00",
                    "announcements": 15,
                    "withdrawals": 5,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("192.168.0.0/24", activity_data)

        assert report.is_stable is False  # > 10 updates/day
        assert report.is_flapping is False  # < 100 updates/day
        assert report.total_updates == 50  # 20+10+15+5 = 50
        assert 5.0 < report.stability_score < 9.0  # Medium score

    def test_detect_flaps_finds_rapid_changes(self, analyzer):
        """Test flap detection finds rapid announcement/withdrawal sequences."""
        updates_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:00",
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [3356, 15169]},
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:00:30",  # 30 seconds later - flap!
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:45",  # 15 seconds later - another flap!
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [174, 15169]},
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:01:10",  # 25 seconds later - flap!
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        assert len(flaps) >= 2  # At least 2 flaps detected
        assert all(f["prefix"] == "8.8.8.0/24" for f in flaps)

    def test_detect_flaps_no_flaps(self, analyzer):
        """Test flap detection when updates are spread over time."""
        updates_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:00",
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [3356, 15169]},
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T02:00:00",  # 2 hours later - not a flap
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T04:00:00",  # 2 hours later - not a flap
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [174, 15169]},
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        assert len(flaps) == 0  # No flaps - updates too far apart

    def test_stability_score_perfect(self, analyzer):
        """Test perfect stability score with 0 updates."""
        score = analyzer.calculate_stability_score(
            updates_per_day=0.0,
            withdrawal_ratio=0.0,
            flap_count=0,
        )
        assert score == 10.0

    def test_stability_score_high_withdrawal_ratio(self, analyzer):
        """Test that high withdrawal ratio reduces score."""
        # Low updates but high withdrawal ratio
        score_low_withdrawal = analyzer.calculate_stability_score(
            updates_per_day=5.0,
            withdrawal_ratio=0.1,
            flap_count=0,
        )
        score_high_withdrawal = analyzer.calculate_stability_score(
            updates_per_day=5.0,
            withdrawal_ratio=0.5,
            flap_count=0,
        )
        assert score_high_withdrawal < score_low_withdrawal

    def test_withdrawal_ratio_zero_updates(self, analyzer):
        """Test that zero updates handles division by zero gracefully."""
        # Create activity data with zero updates
        activity_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "endtime": "2024-01-01T01:00:00",
                    "announcements": 0,
                    "withdrawals": 0,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("8.8.8.0/24", activity_data)

        # Should not raise division by zero error
        assert report.withdrawal_ratio == 0.0
        assert report.total_updates == 0
        assert report.stability_score == 10.0  # Perfect score with 0 updates

    def test_stability_score_with_flaps(self, analyzer):
        """Test that flaps reduce stability score."""
        score_no_flaps = analyzer.calculate_stability_score(
            updates_per_day=50.0,
            withdrawal_ratio=0.2,
            flap_count=0,
        )
        score_with_flaps = analyzer.calculate_stability_score(
            updates_per_day=50.0,
            withdrawal_ratio=0.2,
            flap_count=15,
        )
        assert score_with_flaps < score_no_flaps

    def test_stability_score_minimum_is_zero(self, analyzer):
        """Test that stability score doesn't go below 0."""
        # Extreme case: massive flapping
        score = analyzer.calculate_stability_score(
            updates_per_day=1000.0,
            withdrawal_ratio=0.9,
            flap_count=100,
        )
        assert score >= 0.0

    def test_flap_count_triggers_is_flapping(self, analyzer):
        """Test that high flap count alone can trigger is_flapping."""
        activity_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "endtime": "2024-01-01T12:00:00",
                    "announcements": 30,
                    "withdrawals": 20,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("8.8.8.0/24", activity_data, flap_count=15)

        # Even with moderate updates/day, high flap_count should trigger is_flapping
        assert report.is_flapping is True
