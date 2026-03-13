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
            withdrawals_per_day=20.0,
            withdrawal_ratio=0.4,
            stability_score=6.5,
            is_stable=False,
            is_flapping=False,
        )
        assert report.resource == "8.8.8.0/24"
        assert report.total_updates == 50
        assert report.withdrawals_per_day == 20.0
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
        """Test analysis of a flapping prefix with many withdrawals."""
        # Simulate activity data with many withdrawals (flapping)
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

        assert report.is_flapping is True  # 180 withdrawals/day > 30 threshold
        assert report.is_stable is False
        assert report.stability_score <= 5.0  # Low score for flapping
        assert report.total_updates == 400  # 100+80+120+100 = 400
        assert report.withdrawals_per_day > 30  # High withdrawal rate

    def test_analyze_none_values_in_buckets(self, analyzer):
        """Test that None values in update buckets are treated as 0."""
        activity_data = {
            "resource": "AS47957",
            "updates": [
                {
                    "starttime": "2024-01-01T00:00:00",
                    "announcements": 165,
                    "withdrawals": None,
                },
                {
                    "starttime": "2024-01-01T06:00:00",
                    "announcements": None,
                    "withdrawals": None,
                },
                {
                    "starttime": "2024-01-01T12:00:00",
                    "announcements": 200,
                    "withdrawals": 10,
                },
            ],
            "query_starttime": "2024-01-01T00:00:00",
            "query_endtime": "2024-01-02T00:00:00",
        }

        report = analyzer.analyze_update_activity("AS47957", activity_data)

        assert report.announcements == 365  # 165 + 0 + 200
        assert report.withdrawals == 10  # 0 + 0 + 10
        assert report.total_updates == 375

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

        assert report.is_stable is False  # 15 withdrawals/day > 5 threshold
        assert report.is_flapping is False  # 15 withdrawals/day < 30 threshold
        assert report.total_updates == 50  # 20+10+15+5 = 50
        assert report.withdrawals_per_day == 15.0
        assert 5.0 < report.stability_score < 9.0  # Medium score

    def test_detect_flaps_finds_withdraw_reannounce(self, analyzer):
        """Test flap detection finds W→A (withdraw then re-announce) sequences."""
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
                    "timestamp": "2024-01-01T00:00:30",
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:45",  # W→A = flap!
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [174, 15169]},
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:01:10",
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:01:20",  # W→A = another flap!
                    "attrs": {"target_prefix": "8.8.8.0/24", "path": [3356, 15169]},
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        # 2 W→A transitions: W@:30→A@:45 and W@1:10→A@1:20
        assert len(flaps) == 2
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
        """Test perfect stability score with 0 withdrawals."""
        score = analyzer.calculate_stability_score(
            withdrawals_per_day=0.0,
            withdrawal_ratio=0.0,
            flap_count=0,
        )
        assert score == 10.0

    def test_stability_score_high_withdrawal_ratio(self, analyzer):
        """Test that high withdrawal ratio reduces score."""
        score_low_withdrawal = analyzer.calculate_stability_score(
            withdrawals_per_day=5.0,
            withdrawal_ratio=0.1,
            flap_count=0,
        )
        score_high_withdrawal = analyzer.calculate_stability_score(
            withdrawals_per_day=5.0,
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
            withdrawals_per_day=15.0,
            withdrawal_ratio=0.2,
            flap_count=0,
        )
        score_with_flaps = analyzer.calculate_stability_score(
            withdrawals_per_day=15.0,
            withdrawal_ratio=0.2,
            flap_count=15,
        )
        assert score_with_flaps < score_no_flaps

    def test_stability_score_minimum_is_zero(self, analyzer):
        """Test that stability score doesn't go below 0."""
        # Extreme case: massive flapping
        score = analyzer.calculate_stability_score(
            withdrawals_per_day=200.0,
            withdrawal_ratio=0.9,
            flap_count=100,
        )
        assert score >= 0.0

    def test_detect_flaps_cross_peer_not_counted(self, analyzer):
        """Test that updates from different peers are NOT counted as flaps.

        This is the key correctness check: if peer A announces and peer B
        withdraws, that's two independent observations, not a flap.
        """
        updates_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:00",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc00-peer1",
                        "path": [3356, 15169],
                    },
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:00:10",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc01-peer2",
                    },
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:20",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc03-peer3",
                        "path": [174, 15169],
                    },
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:00:30",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc04-peer4",
                    },
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        # No flaps: each update is from a different peer
        assert len(flaps) == 0

    def test_detect_flaps_same_peer_wa_detected(self, analyzer):
        """Test that W→A from the SAME peer IS counted as a flap."""
        updates_data = {
            "resource": "8.8.8.0/24",
            "updates": [
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:00:00",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc00-peer1",
                    },
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:10",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc00-peer1",
                        "path": [3356, 15169],
                    },
                },
                {
                    "type": "A",
                    "timestamp": "2024-01-01T00:00:05",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc01-peer2",
                        "path": [174, 15169],
                    },
                },
                {
                    "type": "W",
                    "timestamp": "2024-01-01T00:00:15",
                    "attrs": {
                        "target_prefix": "8.8.8.0/24",
                        "source_id": "rrc03-peer3",
                    },
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        # Only 1 flap: the W→A from rrc00-peer1 (route disappeared then came back)
        assert len(flaps) == 1
        assert flaps[0]["peer"] == "rrc00-peer1"
        assert flaps[0]["prefix"] == "8.8.8.0/24"

    def test_detect_flaps_aw_not_counted(self, analyzer):
        """Test that A→W alone is NOT counted as a flap.

        A→W is just a withdrawal. Only W→A (route came back) is a flap.
        """
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
                    "timestamp": "2024-01-01T00:00:10",
                    "attrs": {"target_prefix": "8.8.8.0/24"},
                },
            ],
        }

        flaps = analyzer.detect_flaps(updates_data, window_seconds=60)

        # A→W is not a flap, it's just a withdrawal
        assert len(flaps) == 0

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
