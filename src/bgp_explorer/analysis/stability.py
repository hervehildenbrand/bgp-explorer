"""BGP stability analysis module.

Provides tools to analyze BGP update activity and detect route instability,
including flapping detection and stability scoring.
"""

import math
from dataclasses import dataclass
from datetime import datetime


@dataclass
class StabilityReport:
    """Report of BGP stability analysis.

    Contains metrics about route stability including update counts,
    flap detection, and a stability score.
    """

    resource: str
    period_start: str
    period_end: str
    total_updates: int
    announcements: int
    withdrawals: int
    flap_count: int
    updates_per_day: float
    withdrawals_per_day: float
    withdrawal_ratio: float
    stability_score: float  # 0-10 where 10 is most stable
    is_stable: bool
    is_flapping: bool


# Thresholds based on withdrawal rate (not total updates)
# Re-announcements (path changes) are normal BGP behavior, not instability.
STABLE_THRESHOLD = 5  # withdrawals/day - below this is considered stable
FLAPPING_THRESHOLD = 30  # withdrawals/day - above this is considered flapping
FLAP_COUNT_THRESHOLD = 10  # flaps - above this triggers is_flapping


class StabilityAnalyzer:
    """Analyzer for BGP route stability.

    Evaluates prefix or ASN stability based on:
    - Withdrawal rate (withdrawals per day — the true instability signal)
    - Withdrawal ratio (withdrawals / total updates)
    - Flap detection (W→A sequences from the same peer)

    Re-announcements (A→A path attribute changes) are normal BGP behavior
    for multi-homed networks and are NOT counted as instability.

    Scoring Model:
    - Base score of 10 (perfect stability)
    - Deductions for:
      - High withdrawal rate (up to -6 points)
      - High withdrawal ratio > 0.3 (up to -2 points)
      - Flaps detected (up to -4 points)
    """

    def analyze_update_activity(
        self,
        resource: str,
        activity_data: dict,
        flap_count: int = 0,
    ) -> StabilityReport:
        """Analyze BGP update activity data.

        Args:
            resource: The resource (prefix or ASN) being analyzed.
            activity_data: Raw data from get_bgp_update_activity().
            flap_count: Optional pre-computed flap count.

        Returns:
            StabilityReport with analysis results.
        """
        # Extract time range
        period_start = activity_data.get("query_starttime", "")
        period_end = activity_data.get("query_endtime", "")

        # Sum up all announcements and withdrawals
        total_announcements = 0
        total_withdrawals = 0

        for bucket in activity_data.get("updates", []):
            total_announcements += bucket.get("announcements") or 0
            total_withdrawals += bucket.get("withdrawals") or 0

        total_updates = total_announcements + total_withdrawals

        # Calculate withdrawal ratio (handle division by zero)
        if total_updates > 0:
            withdrawal_ratio = total_withdrawals / total_updates
        else:
            withdrawal_ratio = 0.0

        # Calculate rates per day
        updates_per_day = self._calculate_rate_per_day(
            total_updates, period_start, period_end
        )
        withdrawals_per_day = self._calculate_rate_per_day(
            total_withdrawals, period_start, period_end
        )

        # Calculate stability score based on withdrawal rate (not total updates)
        # Re-announcements are normal BGP path selection, not instability.
        stability_score = self.calculate_stability_score(
            withdrawals_per_day, withdrawal_ratio, flap_count
        )

        # Stability flags based on withdrawal rate
        is_stable = withdrawals_per_day < STABLE_THRESHOLD
        is_flapping = (
            withdrawals_per_day > FLAPPING_THRESHOLD
            or flap_count > FLAP_COUNT_THRESHOLD
        )

        return StabilityReport(
            resource=resource,
            period_start=period_start,
            period_end=period_end,
            total_updates=total_updates,
            announcements=total_announcements,
            withdrawals=total_withdrawals,
            flap_count=flap_count,
            updates_per_day=updates_per_day,
            withdrawals_per_day=withdrawals_per_day,
            withdrawal_ratio=withdrawal_ratio,
            stability_score=stability_score,
            is_stable=is_stable,
            is_flapping=is_flapping,
        )

    def detect_flaps(
        self,
        updates_data: dict,
        window_seconds: int = 60,
    ) -> list[dict]:
        """Detect route flaps in BGP update stream.

        A flap is a W→A (withdraw then re-announce) sequence from the same
        peer within the time window. This means the route disappeared and
        came back — genuine instability.

        NOT counted as flaps:
        - A→A (re-announcements / path changes) — normal BGP best-path selection
        - A→W alone — just a withdrawal, not a complete flap cycle
        - Cross-peer transitions — independent observations from different vantage points

        Args:
            updates_data: Raw data from get_bgp_updates().
            window_seconds: Time window in seconds to consider as a flap.

        Returns:
            List of flap events with prefix, peer, time, and update count.
        """
        updates = updates_data.get("updates", [])
        if not updates:
            return []

        flaps = []
        # Group updates by (prefix, peer) — only same-peer state changes are flaps
        keyed_updates: dict[tuple[str, str], list[dict]] = {}

        for update in updates:
            attrs = update.get("attrs", {})
            prefix = attrs.get("target_prefix", "")
            peer = attrs.get("source_id", "")
            if prefix:
                key = (prefix, peer)
                if key not in keyed_updates:
                    keyed_updates[key] = []
                keyed_updates[key].append(update)

        # Check each (prefix, peer) pair for flaps
        for (prefix, peer), update_list in keyed_updates.items():
            # Sort by timestamp
            sorted_updates = sorted(
                update_list,
                key=lambda u: u.get("timestamp", ""),
            )

            # Look for W→A sequences (withdraw then re-announce = true flap)
            for i in range(len(sorted_updates) - 1):
                current = sorted_updates[i]
                next_update = sorted_updates[i + 1]

                current_type = current.get("type", "")
                next_type = next_update.get("type", "")

                # Only W→A counts as a flap (route disappeared then came back)
                if current_type == "W" and next_type == "A":
                    # Parse timestamps and check window
                    current_time = self._parse_timestamp(current.get("timestamp", ""))
                    next_time = self._parse_timestamp(next_update.get("timestamp", ""))

                    if current_time and next_time:
                        delta = (next_time - current_time).total_seconds()
                        if 0 <= delta <= window_seconds:
                            # Count updates in this window
                            updates_in_window = self._count_updates_in_window(
                                sorted_updates, i, window_seconds
                            )
                            flaps.append(
                                {
                                    "prefix": prefix,
                                    "peer": peer,
                                    "flap_time": current.get("timestamp", ""),
                                    "updates_in_window": updates_in_window,
                                }
                            )

        return flaps

    def calculate_stability_score(
        self,
        withdrawals_per_day: float,
        withdrawal_ratio: float,
        flap_count: int,
    ) -> float:
        """Calculate a stability score from 0-10.

        Args:
            withdrawals_per_day: Average withdrawals per day (the instability signal).
            withdrawal_ratio: Ratio of withdrawals to total updates.
            flap_count: Number of W→A flaps detected.

        Returns:
            Stability score from 0 (unstable) to 10 (perfectly stable).
        """
        score = 10.0

        # Deduct for withdrawal frequency
        # 0 withdrawals = no deduction
        # 5 withdrawals/day (stable threshold) = 0.5 deduction
        # 30 withdrawals/day (flapping threshold) = 4 deduction
        # 60+ withdrawals/day = 6 deduction (max for frequency)
        if withdrawals_per_day > 0:
            if withdrawals_per_day <= STABLE_THRESHOLD:
                # Gentle deduction for stable range
                score -= withdrawals_per_day * 0.1
            elif withdrawals_per_day <= FLAPPING_THRESHOLD:
                # Steeper deduction as we approach flapping
                score -= 0.5 + (withdrawals_per_day - STABLE_THRESHOLD) * 0.14
            else:
                # Severe deduction for flapping
                score -= 4.0 + min(2.0, (withdrawals_per_day - FLAPPING_THRESHOLD) * 0.04)

        # Deduct for high withdrawal ratio (> 0.3)
        if withdrawal_ratio > 0.3:
            excess = withdrawal_ratio - 0.3
            score -= min(2.0, excess * 4.0)

        # Deduct for flaps (logarithmic scaling)
        if flap_count > 0:
            # log10(10)=1 → 1.0pt, log10(100)=2 → 2.0pt, log10(10000)=4 → 4.0pt
            score -= min(4.0, math.log10(max(flap_count, 1)) * 1.0)

        # Ensure score stays in valid range
        return max(0.0, min(10.0, score))

    def _calculate_rate_per_day(
        self,
        total_updates: int,
        period_start: str,
        period_end: str,
    ) -> float:
        """Calculate a count-per-day rate based on time period.

        Args:
            total_updates: Total count of events.
            period_start: Start time as ISO string.
            period_end: End time as ISO string.

        Returns:
            Events per day (float).
        """
        if total_updates == 0:
            return 0.0

        start_time = self._parse_timestamp(period_start)
        end_time = self._parse_timestamp(period_end)

        if not start_time or not end_time:
            # Default to 1 day if times can't be parsed
            return float(total_updates)

        delta = end_time - start_time
        days = delta.total_seconds() / 86400  # seconds in a day

        if days <= 0:
            return float(total_updates)

        return total_updates / days

    def _parse_timestamp(self, timestamp_str: str) -> datetime | None:
        """Parse a timestamp string to datetime.

        Args:
            timestamp_str: ISO format timestamp string.

        Returns:
            datetime object or None if parsing fails.
        """
        if not timestamp_str:
            return None

        try:
            # Handle various ISO formats
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            return None

    def _count_updates_in_window(
        self,
        updates: list[dict],
        start_index: int,
        window_seconds: int,
    ) -> int:
        """Count updates within a time window.

        Args:
            updates: List of sorted updates.
            start_index: Index to start counting from.
            window_seconds: Window size in seconds.

        Returns:
            Number of updates within the window.
        """
        if start_index >= len(updates):
            return 0

        start_time = self._parse_timestamp(updates[start_index].get("timestamp", ""))
        if not start_time:
            return 1

        count = 1
        for i in range(start_index + 1, len(updates)):
            update_time = self._parse_timestamp(updates[i].get("timestamp", ""))
            if update_time:
                delta = (update_time - start_time).total_seconds()
                if delta <= window_seconds:
                    count += 1
                else:
                    break

        return count
