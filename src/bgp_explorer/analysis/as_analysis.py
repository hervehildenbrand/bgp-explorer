"""AS (Autonomous System) analysis utilities."""

from typing import Any

from bgp_explorer.models.route import BGPRoute


class ASAnalyzer:
    """Analyzer for AS-level BGP data.

    Provides utilities for analyzing AS relationships, neighbors,
    and routing behavior.
    """

    def get_asn_neighbors(self, routes: list[BGPRoute], asn: int) -> set[int]:
        """Find ASNs that appear adjacent to the given ASN in paths.

        Args:
            routes: List of BGP routes.
            asn: ASN to find neighbors for.

        Returns:
            Set of neighboring ASNs.
        """
        neighbors = set()
        for route in routes:
            path = route.as_path
            for i, path_asn in enumerate(path):
                if path_asn == asn:
                    if i > 0:
                        neighbors.add(path[i - 1])
                    if i < len(path) - 1:
                        neighbors.add(path[i + 1])
        return neighbors

    def get_asn_position_stats(
        self,
        routes: list[BGPRoute],
        asn: int,
    ) -> dict[str, Any]:
        """Calculate position statistics for an ASN in paths.

        Args:
            routes: List of BGP routes.
            asn: ASN to analyze.

        Returns:
            Dictionary with position statistics.
        """
        positions = []
        as_origin = 0
        as_transit = 0
        as_edge = 0

        for route in routes:
            path = route.as_path
            if asn in path:
                idx = path.index(asn)
                positions.append(idx)

                if idx == len(path) - 1:
                    as_origin += 1
                elif idx == 0:
                    as_edge += 1
                else:
                    as_transit += 1

        return {
            "appearances": len(positions),
            "avg_position": sum(positions) / len(positions) if positions else 0,
            "as_origin": as_origin,
            "as_transit": as_transit,
            "as_edge": as_edge,
        }

    def infer_relationship(
        self,
        asn1: int,
        asn2: int,
        paths: list[list[int]],
    ) -> str:
        """Infer relationship between two ASNs based on path patterns.

        Uses valley-free routing assumption to infer relationships.

        Args:
            asn1: First ASN.
            asn2: Second ASN.
            paths: List of AS paths containing both ASNs.

        Returns:
            Inferred relationship: "provider", "customer", "peer", or "unknown".
        """
        asn1_before_asn2 = 0
        asn2_before_asn1 = 0

        for path in paths:
            if asn1 in path and asn2 in path:
                idx1 = path.index(asn1)
                idx2 = path.index(asn2)

                if idx1 < idx2:
                    asn1_before_asn2 += 1
                else:
                    asn2_before_asn1 += 1

        # Heuristic: if ASN1 is usually before ASN2 in paths,
        # ASN1 is likely a customer of ASN2 (traffic flows customer -> provider)
        if asn1_before_asn2 > asn2_before_asn1 * 2:
            return "customer"
        elif asn2_before_asn1 > asn1_before_asn2 * 2:
            return "provider"
        elif asn1_before_asn2 > 0 or asn2_before_asn1 > 0:
            return "peer"
        else:
            return "unknown"

    def get_asn_prefixes(self, routes: list[BGPRoute], asn: int) -> set[str]:
        """Get prefixes originated by an ASN.

        Args:
            routes: List of BGP routes.
            asn: ASN to find prefixes for.

        Returns:
            Set of prefixes originated by the ASN.
        """
        return {r.prefix for r in routes if r.origin_asn == asn}

    def get_upstream_providers(
        self,
        routes: list[BGPRoute],
        asn: int,
    ) -> set[int]:
        """Identify upstream providers for an ASN.

        Upstream providers are ASNs that appear immediately before
        the target ASN in paths (when looking from edge to origin).

        Args:
            routes: List of BGP routes.
            asn: ASN to find upstreams for.

        Returns:
            Set of upstream provider ASNs.
        """
        upstreams = set()
        for route in routes:
            path = route.as_path
            if asn in path:
                idx = path.index(asn)
                # Upstream is the ASN before this one (closer to edge)
                if idx > 0:
                    upstreams.add(path[idx - 1])
        return upstreams

    def get_downstream_customers(
        self,
        routes: list[BGPRoute],
        asn: int,
    ) -> set[int]:
        """Identify downstream customers for an ASN.

        Downstream customers are ASNs that appear immediately after
        the target ASN in paths (when looking from edge to origin).

        Args:
            routes: List of BGP routes.
            asn: ASN to find downstreams for.

        Returns:
            Set of downstream customer ASNs.
        """
        downstreams = set()
        for route in routes:
            path = route.as_path
            if asn in path:
                idx = path.index(asn)
                # Downstream is the ASN after this one (closer to origin)
                if idx < len(path) - 1:
                    downstreams.add(path[idx + 1])
        return downstreams

    def count_asn_appearances(self, routes: list[BGPRoute], asn: int) -> int:
        """Count how many paths contain an ASN.

        Args:
            routes: List of BGP routes.
            asn: ASN to count.

        Returns:
            Number of paths containing the ASN.
        """
        return sum(1 for r in routes if asn in r.as_path)

    def get_asn_summary(
        self,
        routes: list[BGPRoute],
        asn: int,
    ) -> dict[str, Any]:
        """Generate comprehensive summary for an ASN.

        Args:
            routes: List of BGP routes.
            asn: ASN to summarize.

        Returns:
            Dictionary with ASN summary.
        """
        prefixes = self.get_asn_prefixes(routes, asn)
        upstreams = self.get_upstream_providers(routes, asn)
        downstreams = self.get_downstream_customers(routes, asn)
        neighbors = self.get_asn_neighbors(routes, asn)
        position_stats = self.get_asn_position_stats(routes, asn)

        return {
            "asn": asn,
            "prefixes": list(prefixes),
            "prefix_count": len(prefixes),
            "upstream_asns": list(upstreams),
            "downstream_asns": list(downstreams),
            "neighbor_asns": list(neighbors),
            "appearances": position_stats["appearances"],
            "as_origin_count": position_stats["as_origin"],
            "as_transit_count": position_stats["as_transit"],
        }

    def get_common_upstreams(
        self,
        routes: list[BGPRoute],
        asn_list: list[int],
    ) -> set[int]:
        """Find common upstream providers for multiple ASNs.

        Args:
            routes: List of BGP routes.
            asn_list: List of ASNs to analyze.

        Returns:
            Set of ASNs that are upstream to all given ASNs.
        """
        if not asn_list:
            return set()

        upstream_sets = [
            self.get_upstream_providers(routes, asn)
            for asn in asn_list
        ]

        if not upstream_sets:
            return set()

        common = upstream_sets[0]
        for upstream_set in upstream_sets[1:]:
            common = common.intersection(upstream_set)

        return common
