"""AS path analysis utilities."""

from collections import Counter
from typing import Any

from bgp_explorer.models.route import BGPRoute


class PathAnalyzer:
    """Analyzer for BGP AS path data.

    Provides utilities for analyzing path diversity, detecting
    path changes, and extracting path statistics.
    """

    def get_unique_paths(self, routes: list[BGPRoute]) -> set[tuple[int, ...]]:
        """Extract unique AS paths from routes.

        Args:
            routes: List of BGP routes.

        Returns:
            Set of unique AS paths as tuples.
        """
        return {tuple(r.as_path) for r in routes if r.as_path}

    def get_origin_asns(self, routes: list[BGPRoute]) -> set[int]:
        """Extract unique origin ASNs from routes.

        Args:
            routes: List of BGP routes.

        Returns:
            Set of origin ASNs.
        """
        return {r.origin_asn for r in routes}

    def get_path_diversity(self, routes: list[BGPRoute]) -> dict[str, Any]:
        """Calculate path diversity metrics.

        Args:
            routes: List of BGP routes.

        Returns:
            Dictionary with diversity metrics.
        """
        if not routes:
            return {
                "unique_paths": 0,
                "unique_origins": 0,
                "collectors": 0,
                "min_path_length": 0,
                "max_path_length": 0,
                "avg_path_length": 0.0,
            }

        unique_paths = self.get_unique_paths(routes)
        path_lengths = [len(r.as_path) for r in routes if r.as_path]

        return {
            "unique_paths": len(unique_paths),
            "unique_origins": len(self.get_origin_asns(routes)),
            "collectors": len({r.collector for r in routes}),
            "min_path_length": min(path_lengths) if path_lengths else 0,
            "max_path_length": max(path_lengths) if path_lengths else 0,
            "avg_path_length": sum(path_lengths) / len(path_lengths) if path_lengths else 0.0,
        }

    def get_upstream_asns(self, routes: list[BGPRoute]) -> set[int]:
        """Extract upstream ASNs (directly connected to origin).

        For a path like [A, B, C] where C is origin, B is the upstream.

        Args:
            routes: List of BGP routes.

        Returns:
            Set of upstream ASNs.
        """
        upstreams = set()
        for route in routes:
            if len(route.as_path) >= 2:
                # Second to last ASN is the direct upstream
                upstreams.add(route.as_path[-2])
        return upstreams

    def get_transit_asns(self, routes: list[BGPRoute]) -> set[int]:
        """Extract transit ASNs (middle of path, not origin or edge).

        Args:
            routes: List of BGP routes.

        Returns:
            Set of transit ASNs.
        """
        transits = set()
        for route in routes:
            # Transit ASNs are those in the middle of the path
            if len(route.as_path) >= 3:
                for asn in route.as_path[1:-1]:
                    transits.add(asn)
        return transits

    def detect_path_changes(
        self,
        old_routes: list[BGPRoute],
        new_routes: list[BGPRoute],
    ) -> list[dict[str, Any]]:
        """Detect changes between two sets of routes.

        Args:
            old_routes: Previous route state.
            new_routes: Current route state.

        Returns:
            List of detected changes.
        """
        changes = []

        # Group routes by collector for comparison
        old_by_collector = {r.collector: r for r in old_routes}
        new_by_collector = {r.collector: r for r in new_routes}

        # Check for changes in each collector
        all_collectors = set(old_by_collector.keys()) | set(new_by_collector.keys())

        for collector in all_collectors:
            old_route = old_by_collector.get(collector)
            new_route = new_by_collector.get(collector)

            if old_route and new_route:
                # Check for origin change
                if old_route.origin_asn != new_route.origin_asn:
                    changes.append({
                        "type": "origin_change",
                        "collector": collector,
                        "old_origin": old_route.origin_asn,
                        "new_origin": new_route.origin_asn,
                        "prefix": new_route.prefix,
                    })

                # Check for path change
                if old_route.as_path != new_route.as_path:
                    changes.append({
                        "type": "path_change",
                        "collector": collector,
                        "old_path": old_route.as_path,
                        "new_path": new_route.as_path,
                        "prefix": new_route.prefix,
                    })

            elif old_route and not new_route:
                changes.append({
                    "type": "withdrawal",
                    "collector": collector,
                    "prefix": old_route.prefix,
                    "origin": old_route.origin_asn,
                })

            elif new_route and not old_route:
                changes.append({
                    "type": "announcement",
                    "collector": collector,
                    "prefix": new_route.prefix,
                    "origin": new_route.origin_asn,
                })

        return changes

    def get_path_prepending(self, routes: list[BGPRoute]) -> list[dict[str, Any]]:
        """Detect AS path prepending in routes.

        Args:
            routes: List of BGP routes.

        Returns:
            List of routes with prepending detected.
        """
        prepended = []
        for route in routes:
            if len(route.as_path) >= 2:
                # Count consecutive duplicates
                asn_counts = Counter(route.as_path)
                for asn, count in asn_counts.items():
                    if count > 1:
                        prepended.append({
                            "prefix": route.prefix,
                            "collector": route.collector,
                            "asn": asn,
                            "prepend_count": count,
                            "path": route.as_path,
                        })
                        break  # One prepend detection per route
        return prepended

    def compare_paths_across_collectors(
        self,
        routes: list[BGPRoute],
    ) -> dict[str, Any]:
        """Compare AS paths across different collectors.

        Args:
            routes: List of routes from multiple collectors.

        Returns:
            Comparison summary.
        """
        by_collector = {}
        for route in routes:
            by_collector[route.collector] = {
                "path": route.as_path,
                "origin": route.origin_asn,
                "path_length": len(route.as_path),
            }

        unique_paths = self.get_unique_paths(routes)
        unique_origins = self.get_origin_asns(routes)

        return {
            "collectors": list(by_collector.keys()),
            "collector_count": len(by_collector),
            "unique_paths": len(unique_paths),
            "unique_origins": len(unique_origins),
            "paths_consistent": len(unique_origins) == 1,
            "by_collector": by_collector,
        }
