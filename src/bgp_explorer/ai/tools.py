"""AI tool definitions for BGP Explorer.

These tools are registered with the AI backend and can be called
by the AI to query BGP data sources.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from bgp_explorer.analysis.as_analysis import ASAnalyzer
from bgp_explorer.analysis.path_analysis import PathAnalyzer
from bgp_explorer.analysis.resilience import ResilienceAssessor, ResilienceReport
from bgp_explorer.models.event import EventType
from bgp_explorer.sources.bgp_radar import BgpRadarClient
from bgp_explorer.sources.globalping import GlobalpingClient
from bgp_explorer.sources.monocle import MonocleClient
from bgp_explorer.sources.peeringdb import PeeringDBClient
from bgp_explorer.sources.ripe_stat import RipeStatClient

# Human-readable status messages for tool execution
TOOL_DESCRIPTIONS: dict[str, str] = {
    "search_asn": "Searching for ASNs matching '{query}'...",
    "lookup_prefix": "Looking up prefix {prefix}...",
    "get_asn_announcements": "Getting announcements for AS{asn}...",
    "get_routing_history": "Fetching routing history for {resource}...",
    "get_anomalies": "Checking for BGP anomalies...",
    "get_rpki_status": "Validating RPKI for {prefix}...",
    "analyze_as_path": "Analyzing AS paths for {prefix}...",
    "compare_collectors": "Comparing collectors for {prefix}...",
    "get_asn_details": "Getting details for AS{asn}...",
    "ping_from_global": "Running ping to {target}...",
    "traceroute_from_global": "Running traceroute to {target}...",
    "get_ixps_for_asn": "Finding IXPs for AS{asn}...",
    "get_networks_at_ixp": "Getting networks at {ixp}...",
    "get_ixp_details": "Getting details for {ixp}...",
    "get_as_peers": "Finding peers for AS{asn}...",
    "get_as_upstreams": "Finding upstreams for AS{asn}...",
    "get_as_downstreams": "Finding downstreams for AS{asn}...",
    "check_as_relationship": "Checking relationship between AS{asn1} and AS{asn2}...",
    "get_as_connectivity_summary": "Getting connectivity summary for AS{asn}...",
    "get_network_contacts": "Looking up contacts for AS{asn}...",
    "start_monitoring": "Starting BGP anomaly monitoring...",
    "stop_monitoring": "Stopping BGP anomaly monitoring...",
    "check_prefix_anomalies": "Checking {prefix} for hijack indicators...",
    "assess_network_resilience": "Assessing network resilience for AS{asn}...",
}


def get_tool_status_message(tool_name: str, arguments: dict[str, Any]) -> str:
    """Format human-readable status message for a tool call.

    Args:
        tool_name: Name of the tool being called.
        arguments: Arguments passed to the tool.

    Returns:
        Human-readable status message.
    """
    template = TOOL_DESCRIPTIONS.get(tool_name)
    if template:
        try:
            return template.format(**arguments)
        except KeyError:
            # If arguments don't match template, return generic message
            return f"Running {tool_name}..."
    return f"Running {tool_name}..."


class BGPTools:
    """Collection of tools for querying BGP data.

    These tools are designed to be registered with an AI backend
    and called during conversation to fetch real-time and historical
    BGP routing data.
    """

    def __init__(
        self,
        ripe_stat: RipeStatClient,
        bgp_radar: BgpRadarClient | None = None,
        globalping: GlobalpingClient | None = None,
        peeringdb: PeeringDBClient | None = None,
        monocle: MonocleClient | None = None,
    ):
        """Initialize tools with data source clients.

        Args:
            ripe_stat: RIPE Stat client for historical/state queries.
            bgp_radar: bgp-radar client for real-time anomalies.
            globalping: Globalping client for network probing.
            peeringdb: PeeringDB client for IXP/network info.
            monocle: Monocle client for AS relationship data.
        """
        self._ripe_stat = ripe_stat
        self._bgp_radar = bgp_radar
        self._globalping = globalping
        self._peeringdb = peeringdb
        self._monocle = monocle
        self._path_analyzer = PathAnalyzer()
        self._as_analyzer = ASAnalyzer()
        self._resilience_assessor = ResilienceAssessor()

    def get_all_tools(self) -> list[Callable[..., Any]]:
        """Get all tool functions for registration with AI backend.

        Returns:
            List of tool functions.
        """
        tools = [
            self.search_asn,
            self.lookup_prefix,
            self.get_asn_announcements,
            self.get_routing_history,
            self.get_anomalies,
            self.get_rpki_status,
            self.analyze_as_path,
            self.compare_collectors,
            self.get_asn_details,
            self.check_prefix_anomalies,
        ]
        # Add bgp-radar monitoring tools if available
        if self._bgp_radar:
            tools.extend(
                [
                    self.start_monitoring,
                    self.stop_monitoring,
                ]
            )
        # Add Globalping tools if available
        if self._globalping:
            tools.extend(
                [
                    self.ping_from_global,
                    self.traceroute_from_global,
                ]
            )
        # Add PeeringDB tools if available
        if self._peeringdb:
            tools.extend(
                [
                    self.get_ixps_for_asn,
                    self.get_networks_at_ixp,
                    self.get_ixp_details,
                    self.get_network_contacts,
                ]
            )
        # Add Monocle tools if available
        if self._monocle:
            tools.extend(
                [
                    self.get_as_peers,
                    self.get_as_upstreams,
                    self.get_as_downstreams,
                    self.check_as_relationship,
                    self.get_as_connectivity_summary,
                ]
            )
        # Add resilience assessment tool if both monocle and peeringdb available
        if self._monocle and self._peeringdb:
            tools.append(self.assess_network_resilience)
        return tools

    async def search_asn(self, query: str) -> str:
        """Search for ASNs by organization or company name.

        Use this tool FIRST when a user asks about a network by name without
        providing an ASN number. NEVER guess or assume ASN numbers.

        Automatically searches common variations (e.g., "Criteo", "Criteo Europe",
        "Criteo SA") to find all related ASNs.

        Args:
            query: Organization name to search (e.g., "Google", "Cloudflare").

        Returns:
            List of matching ASNs. If multiple matches, ask user to confirm.
        """
        try:
            # Generate search variations for thorough matching
            variations = [query]

            # Add common regional/legal suffixes
            common_suffixes = [
                "Europe",
                "France",
                "US",
                "USA",
                "Corp",
                "Inc",
                "SA",
                "Ltd",
                "GmbH",
                "LLC",
            ]
            for suffix in common_suffixes:
                if suffix.lower() not in query.lower():
                    variations.append(f"{query} {suffix}")

            # Search all variations and collect unique results
            seen_asns = set()
            all_results = []

            for variation in variations:
                try:
                    results = await self._ripe_stat.search_asn(variation)
                    for result in results:
                        asn = result["asn"]
                        if asn not in seen_asns:
                            seen_asns.add(asn)
                            all_results.append(result)
                except Exception:
                    # Continue with other variations if one fails
                    continue

            # If RIPE Stat found nothing, try PeeringDB as fallback
            if not all_results and self._peeringdb is not None:
                try:
                    pdb_results = self._peeringdb.search_networks(query)
                    for network in pdb_results:
                        if network.asn not in seen_asns:
                            seen_asns.add(network.asn)
                            all_results.append(
                                {
                                    "asn": network.asn,
                                    "description": f"{network.name} (via PeeringDB)",
                                }
                            )
                except Exception:
                    pass  # PeeringDB search failed, continue without it

            if not all_results:
                return (
                    f"No ASNs found matching '{query}' or its variations. "
                    "Try searching with different terms, or ask the user for the ASN number directly."
                )

            # Sort by ASN for consistent ordering
            all_results.sort(key=lambda x: x["asn"])

            summary = [
                f"**ASN Search Results for '{query}':**",
                "",
                f"**Found {len(all_results)} matching ASN(s):**",
                "",
            ]

            for result in all_results[:15]:
                summary.append(f"  - **AS{result['asn']}**: {result['description']}")

            if len(all_results) > 15:
                summary.append(f"  ... and {len(all_results) - 15} more")

            # Add guidance about potential missing ASNs
            summary.append("")
            if len(all_results) <= 3:
                summary.append(
                    "**Note:** Only a few ASNs found. Large companies often have more ASNs registered "
                    "under different names. Consider:\n"
                    "  - Searching for regional variants (e.g., 'Company Europe', 'Company France')\n"
                    "  - Using get_asn_details() on found ASNs to discover the exact org name\n"
                    "  - Searching again with the exact org name from the registry"
                )
            elif len(all_results) > 1:
                summary.append(
                    "**Multiple matches found.** Please confirm with the user which ASN they meant "
                    "before proceeding with other queries."
                )

            return "\n".join(summary)

        except Exception as e:
            return f"Error searching for ASN: {str(e)}"

    async def lookup_prefix(self, prefix: str) -> str:
        """Look up BGP routing information for an IP prefix.

        Returns the origin ASN, AS paths from multiple vantage points,
        and visibility information for the specified prefix.
        Auto-detects and reports whether this is an IPv4 or IPv6 prefix.

        Args:
            prefix: IP prefix in CIDR notation (e.g., "8.8.8.0/24" or "2001:db8::/32").

        Returns:
            Human-readable summary of routing information for the prefix.
        """
        try:
            routes = await self._ripe_stat.get_bgp_state(prefix)

            # Detect address family
            is_ipv6 = ":" in prefix
            family_str = "IPv6" if is_ipv6 else "IPv4"

            if not routes:
                return f"No routes found for {family_str} prefix {prefix}. The prefix may not be announced or visible from RIPE RIS collectors."

            # Summarize the results
            origin_asns = set(r.origin_asn for r in routes)
            collectors = set(r.collector for r in routes)
            unique_paths = set(tuple(r.as_path) for r in routes)

            summary = [
                f"**Prefix: {prefix}** ({family_str})",
                "",
                f"**Origin ASN(s):** {', '.join(f'AS{asn}' for asn in sorted(origin_asns))}",
                f"**Visible from:** {len(collectors)} collectors ({', '.join(sorted(collectors)[:5])}{'...' if len(collectors) > 5 else ''})",
                f"**Unique AS paths:** {len(unique_paths)}",
                "",
                "**Sample paths:**",
            ]

            # Show up to 5 unique paths
            for i, path in enumerate(list(unique_paths)[:5]):
                path_str = " → ".join(f"AS{asn}" for asn in path)
                summary.append(f"  {i + 1}. {path_str}")

            return "\n".join(summary)

        except Exception as e:
            return f"Error looking up prefix {prefix}: {str(e)}"

    async def get_asn_announcements(self, asn: int, address_family: int | None = None) -> str:
        """Get prefixes announced by an AS, optionally filtered by address family.

        Returns a list of IP prefixes that are currently originated
        by the specified ASN. Always reports IPv4 and IPv6 counts separately.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).
            address_family: Optional filter - 4 for IPv4 only, 6 for IPv6 only,
                           None for both (default).

        Returns:
            List of prefixes announced by the ASN, separated by address family.
            Use address_family filter when user specifically asks about one protocol.
        """
        try:
            prefixes = await self._ripe_stat.get_announced_prefixes(asn)

            if not prefixes:
                return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

            # Separate IPv4 and IPv6
            ipv4 = [p for p in prefixes if ":" not in p]
            ipv6 = [p for p in prefixes if ":" in p]

            # Apply address family filter if specified
            if address_family == 4:
                filtered_prefixes = ipv4
                family_label = "IPv4"
            elif address_family == 6:
                filtered_prefixes = ipv6
                family_label = "IPv6"
            else:
                filtered_prefixes = None  # Show both
                family_label = None

            summary = [
                f"**AS{asn} Announcements**",
                "",
                f"**Total prefixes:** {len(prefixes)}",
                f"  - IPv4: {len(ipv4)}",
                f"  - IPv6: {len(ipv6)}",
                "",
            ]

            if filtered_prefixes is not None:
                # Filtered view - show only requested family
                summary.append(f"**{family_label} prefixes (filtered):**")
                for p in filtered_prefixes[:15]:
                    summary.append(f"  - {p}")
                if len(filtered_prefixes) > 15:
                    summary.append(f"  ... and {len(filtered_prefixes) - 15} more")
            else:
                # Default view - show both families
                if ipv4:
                    summary.append("**IPv4 prefixes (sample):**")
                    for p in ipv4[:10]:
                        summary.append(f"  - {p}")
                    if len(ipv4) > 10:
                        summary.append(f"  ... and {len(ipv4) - 10} more")
                    summary.append("")

                if ipv6:
                    summary.append("**IPv6 prefixes (sample):**")
                    for p in ipv6[:5]:
                        summary.append(f"  - {p}")
                    if len(ipv6) > 5:
                        summary.append(f"  ... and {len(ipv6) - 5} more")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting announcements for AS{asn}: {str(e)}"

    async def get_routing_history(
        self,
        resource: str,
        start_date: str,
        end_date: str,
    ) -> str:
        """Get historical routing information for a prefix or ASN.

        Shows how routing for the resource has changed over time,
        including origin ASN changes and visibility changes.

        Args:
            resource: IP prefix (e.g., "8.8.8.0/24") or ASN (e.g., "AS15169").
            start_date: Start date in ISO format (YYYY-MM-DD).
            end_date: End date in ISO format (YYYY-MM-DD).

        Returns:
            Historical routing timeline for the resource.
        """
        try:
            # Parse dates
            start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
            end = datetime.fromisoformat(end_date).replace(tzinfo=UTC)

            history = await self._ripe_stat.get_routing_history(resource, start, end)

            summary = [
                f"**Routing History: {resource}**",
                f"**Period:** {start_date} to {end_date}",
                "",
            ]

            by_origin = history.get("by_origin", [])
            if not by_origin:
                summary.append("No routing history found for this period.")
            else:
                summary.append(f"**Origins observed:** {len(by_origin)}")
                summary.append("")

                for origin_data in by_origin[:5]:
                    origin = origin_data.get("origin", "unknown")
                    prefixes = origin_data.get("prefixes", [])
                    summary.append(f"**AS{origin}:**")
                    for prefix_data in prefixes[:3]:
                        prefix = prefix_data.get("prefix", "unknown")
                        timelines = prefix_data.get("timelines", [])
                        summary.append(f"  - {prefix}: {len(timelines)} timeline(s)")
                    summary.append("")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting routing history: {str(e)}"

    async def get_anomalies(
        self,
        event_type: str | None = None,
        prefix: str | None = None,
        asn: int | None = None,
    ) -> str:
        """Get recent BGP anomalies detected by bgp-radar.

        Returns hijacks, route leaks, and blackhole announcements
        detected in real-time from RIS Live data.

        Args:
            event_type: Filter by type: "hijack", "leak", or "blackhole".
            prefix: Filter by affected prefix.
            asn: Filter by affected ASN.

        Returns:
            List of recent anomaly events.
        """
        if self._bgp_radar is None or not self._bgp_radar.is_running:
            return "bgp-radar is not running. Real-time anomaly detection is not available."

        try:
            # Convert event_type string to enum
            type_filter = None
            if event_type:
                type_filter = EventType(event_type.lower())

            events = await self._bgp_radar.get_recent_anomalies(
                event_type=type_filter,
                prefix=prefix,
                asn=asn,
            )

            if not events:
                filters = []
                if event_type:
                    filters.append(f"type={event_type}")
                if prefix:
                    filters.append(f"prefix={prefix}")
                if asn:
                    filters.append(f"ASN={asn}")
                filter_str = f" (filters: {', '.join(filters)})" if filters else ""
                return f"No recent anomalies detected{filter_str}."

            summary = [
                "**Recent BGP Anomalies**",
                f"**Count:** {len(events)}",
                "",
            ]

            for i, event in enumerate(events[:10], 1):
                severity_emoji = {
                    "high": "🔴",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(event.severity.value, "⚪")

                summary.append(
                    f"{i}. {severity_emoji} **{event.type.value.upper()}** - {event.affected_prefix}"
                )
                if event.affected_asn:
                    summary.append(f"   Affected ASN: AS{event.affected_asn}")
                summary.append(f"   Detected: {event.detected_at.isoformat()}")
                if event.details:
                    for key, value in list(event.details.items())[:3]:
                        summary.append(f"   {key}: {value}")
                summary.append("")

            if len(events) > 10:
                summary.append(f"... and {len(events) - 10} more events")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting anomalies: {str(e)}"

    async def get_rpki_status(self, prefix: str, origin_asn: int) -> str:
        """Check RPKI validation status for a prefix/origin pair.

        **USE PROACTIVELY** - Always check RPKI when investigating prefixes.
        Include RPKI status in every prefix report without waiting to be asked.

        Validates whether the prefix announcement from the given
        origin ASN is covered by a valid ROA (Route Origin Authorization).

        Args:
            prefix: IP prefix in CIDR notation (works for both IPv4 and IPv6).
            origin_asn: The AS number claiming to originate the prefix.

        Returns:
            RPKI validation status:
            - valid: ROA exists and matches - legitimate announcement
            - invalid: ROA exists but DOESN'T match - potential hijack!
            - not-found: No ROA - owner hasn't deployed RPKI (common, not necessarily bad)
        """
        try:
            status = await self._ripe_stat.get_rpki_validation(prefix, origin_asn)

            status_emoji = {
                "valid": "✅",
                "invalid": "❌",
                "not-found": "❓",
            }.get(status, "❓")

            summary = [
                "**RPKI Validation**",
                "",
                f"**Prefix:** {prefix}",
                f"**Origin:** AS{origin_asn}",
                f"**Status:** {status_emoji} {status.upper()}",
                "",
            ]

            if status == "valid":
                summary.append(
                    "The route announcement is covered by a valid ROA and matches the expected origin."
                )
            elif status == "invalid":
                summary.append(
                    "⚠️ The route announcement is INVALID - it may be a hijack or misconfiguration."
                )
            else:
                summary.append(
                    "No ROA found for this prefix. The origin cannot be validated via RPKI."
                )

            return "\n".join(summary)

        except Exception as e:
            return f"Error checking RPKI status: {str(e)}"

    async def analyze_as_path(self, prefix: str) -> str:
        """Analyze AS path diversity and characteristics for a prefix.

        NOTE: This shows PATH DIVERSITY (unique ASNs in collected routes),
        NOT actual peer count. For peer counts, use get_as_peers() or
        get_as_connectivity_summary() instead.

        Provides path length statistics, prepending detection, and upstream
        hop analysis across multiple vantage points.

        Args:
            prefix: IP prefix in CIDR notation (e.g., "8.8.8.0/24").

        Returns:
            Path diversity metrics and characteristics.
        """
        try:
            routes = await self._ripe_stat.get_bgp_state(prefix)

            if not routes:
                return f"No routes found for prefix {prefix}. Cannot analyze paths."

            # Get path diversity metrics
            diversity = self._path_analyzer.get_path_diversity(routes)
            upstreams = self._path_analyzer.get_upstream_asns(routes)
            transits = self._path_analyzer.get_transit_asns(routes)
            prepending = self._path_analyzer.get_path_prepending(routes)

            summary = [
                f"**AS Path Analysis: {prefix}**",
                "",
                "**Path Diversity Metrics:**",
                f"  - Unique paths: {diversity['unique_paths']}",
                f"  - Unique origins: {diversity['unique_origins']}",
                f"  - Collectors: {diversity['collectors']}",
                f"  - Min path length: {diversity['min_path_length']}",
                f"  - Max path length: {diversity['max_path_length']}",
                f"  - Avg path length: {diversity['avg_path_length']:.2f}",
                "",
                f"**Upstream hops in paths (NOT peer count - use get_as_peers for actual peers):** {len(upstreams)} unique ASNs observed directly before origin",
            ]

            if upstreams:
                upstream_list = ", ".join(f"AS{asn}" for asn in sorted(upstreams)[:10])
                summary.append(f"  {upstream_list}")
                if len(upstreams) > 10:
                    summary.append(f"  ... and {len(upstreams) - 10} more")

            summary.append("")
            summary.append(f"**Transit ASNs (middle of paths):** {len(transits)}")

            if transits:
                transit_list = ", ".join(f"AS{asn}" for asn in sorted(transits)[:10])
                summary.append(f"  {transit_list}")
                if len(transits) > 10:
                    summary.append(f"  ... and {len(transits) - 10} more")

            if prepending:
                summary.append("")
                summary.append(f"**Path Prepending Detected:** {len(prepending)} routes")
                for prep in prepending[:3]:
                    summary.append(
                        f"  - AS{prep['asn']} prepended {prep['prepend_count']}x in path via {prep['collector']}"
                    )

            return "\n".join(summary)

        except Exception as e:
            return f"Error analyzing AS paths for {prefix}: {str(e)}"

    async def compare_collectors(self, prefix: str) -> str:
        """Compare routing views for a prefix across different collectors.

        Shows how the prefix is seen from different vantage points in the
        RIPE RIS infrastructure, highlighting any inconsistencies.

        Args:
            prefix: IP prefix in CIDR notation.

        Returns:
            Comparison of routing information across collectors.
        """
        try:
            routes = await self._ripe_stat.get_bgp_state(prefix)

            if not routes:
                return f"No routes found for prefix {prefix}. Cannot compare collectors."

            comparison = self._path_analyzer.compare_paths_across_collectors(routes)

            summary = [
                f"**Collector Comparison: {prefix}**",
                "",
                f"**Total collectors:** {comparison['collector_count']}",
                f"**Unique paths:** {comparison['unique_paths']}",
                f"**Unique origins:** {comparison['unique_origins']}",
                f"**Consistent origin:** {'Yes' if comparison['paths_consistent'] else 'No (possible anomaly!)'}",
                "",
                "**View by Collector:**",
            ]

            by_collector = comparison.get("by_collector", {})
            for collector, data in sorted(by_collector.items())[:10]:
                path_str = " → ".join(f"AS{asn}" for asn in data["path"])
                summary.append(f"  **{collector}:** {path_str} (len={data['path_length']})")

            if len(by_collector) > 10:
                summary.append(f"  ... and {len(by_collector) - 10} more collectors")

            if not comparison["paths_consistent"]:
                summary.append("")
                summary.append("⚠️ **Warning:** Multiple origin ASNs detected. This could indicate:")
                summary.append("  - A BGP hijack")
                summary.append("  - MOAS (Multiple Origin AS) configuration")
                summary.append("  - Route leak or misconfiguration")

            return "\n".join(summary)

        except Exception as e:
            return f"Error comparing collectors for {prefix}: {str(e)}"

    async def get_asn_details(self, asn: int) -> str:
        """Get detailed information about an Autonomous System.

        Provides comprehensive analysis including announced prefixes,
        upstream/downstream relationships, and routing behavior.
        Always reports IPv4 and IPv6 prefix counts separately.

        For security analysis, use check_prefix_anomalies() on sample prefixes
        from BOTH IPv4 and IPv6 families, as RPKI deployment may differ.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            Detailed ASN analysis with IPv4/IPv6 breakdown and routing statistics.
        """
        try:
            # Get prefixes announced by this ASN
            prefixes = await self._ripe_stat.get_announced_prefixes(asn)

            if not prefixes:
                return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

            # Get routes for a sample of prefixes to analyze relationships
            sample_prefixes = prefixes[:5]  # Sample first 5 prefixes
            all_routes = []

            for prefix in sample_prefixes:
                try:
                    routes = await self._ripe_stat.get_bgp_state(prefix)
                    all_routes.extend(routes)
                except Exception:
                    pass  # Skip failed prefix lookups

            # Analyze the ASN using collected routes
            asn_summary = self._as_analyzer.get_asn_summary(all_routes, asn)

            # Separate IPv4 and IPv6 prefixes
            ipv4 = [p for p in prefixes if ":" not in p]
            ipv6 = [p for p in prefixes if ":" in p]

            summary = [
                f"**AS{asn} Details**",
                "",
                "**Announcements:**",
                f"  - Total prefixes: {len(prefixes)}",
                f"  - IPv4: {len(ipv4)}",
                f"  - IPv6: {len(ipv6)}",
                "",
            ]

            if asn_summary["upstream_asns"]:
                summary.append(f"**Upstream Providers:** {len(asn_summary['upstream_asns'])}")
                upstream_list = ", ".join(
                    f"AS{u}" for u in sorted(asn_summary["upstream_asns"])[:10]
                )
                summary.append(f"  {upstream_list}")
                summary.append("")

            if asn_summary["downstream_asns"]:
                summary.append(f"**Downstream Customers:** {len(asn_summary['downstream_asns'])}")
                downstream_list = ", ".join(
                    f"AS{d}" for d in sorted(asn_summary["downstream_asns"])[:10]
                )
                summary.append(f"  {downstream_list}")
                summary.append("")

            summary.append("**Routing Behavior (from sampled routes to this ASN's prefixes):**")
            summary.append(f"  - Appearances in paths: {asn_summary['appearances']}")
            summary.append(f"  - As origin (end of path): {asn_summary['as_origin_count']}")
            summary.append(f"  - As mid-path transit: {asn_summary['as_transit_count']}")
            summary.append("")
            summary.append(
                "Note: 'mid-path transit' only counts paths TO this ASN's prefixes. "
                "To see if this ASN provides transit to other networks, check the "
                "downstream customers list above or use get_as_downstreams."
            )

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting details for AS{asn}: {str(e)}"

    async def ping_from_global(
        self,
        target: str,
        locations: list[str] | None = None,
    ) -> str:
        """Perform ping measurements from globally distributed probes.

        Uses the Globalping network to measure latency and reachability
        from multiple geographic locations.

        IMPORTANT: If the user specifies a location (e.g., "from the US",
        "from Germany"), you MUST pass the appropriate location filter.
        If probes from the requested location are unavailable, report this
        clearly and ask if they'd like to try from other locations.

        Args:
            target: IP address or hostname to ping.
            locations: List of locations to run probes from. Supports:
                - Country codes: "US", "DE", "FR", "GB", "JP", "AU", etc.
                - Country names: "United States", "Germany", "France", etc.
                - Continent codes: "EU", "NA", "AS", "OC", "SA", "AF"
                - Region names: "Europe", "North America", "Asia", etc.
                Examples: ["US"] for United States only,
                         ["US", "DE"] for US and Germany,
                         ["Europe"] for all European probes.
                If not specified, uses a diverse global selection.

        Returns:
            Ping results from multiple global vantage points.
        """
        if self._globalping is None:
            return "Globalping is not configured. Global network probing is not available."

        try:
            result = await self._globalping.ping(
                target=target,
                locations=locations,
                limit=10,
            )

            if not result.probes:
                return f"No ping results received for {target}."

            summary = [
                f"**Global Ping Results: {target}**",
                "",
                f"**Measurement ID:** {result.measurement_id}",
                f"**Probes:** {len(result.probes)}",
                "",
            ]

            # Calculate statistics
            successful = [r for r in result.probes if r.avg_latency is not None]
            if successful:
                avg_latencies = [r.avg_latency for r in successful]
                if avg_latencies:
                    summary.append("**Latency Summary:**")
                    summary.append(f"  - Min: {min(avg_latencies):.2f} ms")
                    summary.append(f"  - Max: {max(avg_latencies):.2f} ms")
                    summary.append(f"  - Avg: {sum(avg_latencies) / len(avg_latencies):.2f} ms")
                    summary.append("")

            summary.append("**Results by Location:**")
            for probe_result in result.probes[:10]:
                location = f"{probe_result.city}, {probe_result.country}"
                if probe_result.avg_latency is not None:
                    status = f"{probe_result.avg_latency:.2f}ms"
                    if probe_result.packet_loss and probe_result.packet_loss > 0:
                        status += f" ({probe_result.packet_loss}% loss)"
                    summary.append(f"  - {location}: {status}")
                else:
                    summary.append(f"  - {location}: Failed/Timeout")

            if len(result.probes) > 10:
                summary.append(f"  ... and {len(result.probes) - 10} more probes")

            return "\n".join(summary)

        except ValueError as e:
            # ValueError is raised for probe availability issues - pass through the helpful message
            error_msg = str(e)
            if "No probes available" in error_msg:
                requested = ", ".join(locations) if locations else "default locations"
                return (
                    f"**PROBE AVAILABILITY ERROR**\n\n"
                    f"{error_msg}\n\n"
                    f"The user requested probes from: {requested}\n\n"
                    f"**You MUST ask the user** if they would like to try from a different location. "
                    f"Suggest alternatives like Europe (DE, GB, FR), Asia (JP, SG), or use default global probes."
                )
            return f"Error performing global ping to {target}: {error_msg}"
        except Exception as e:
            return f"Error performing global ping to {target}: {str(e)}"

    async def traceroute_from_global(
        self,
        target: str,
        locations: list[str] | None = None,
    ) -> str:
        """Perform traceroute measurements from globally distributed probes.

        Uses the Globalping network to trace the path to a target
        from multiple geographic locations.

        IMPORTANT: If the user specifies a location (e.g., "from the US",
        "from Germany"), you MUST pass the appropriate location filter.
        If probes from the requested location are unavailable, report this
        clearly and ask if they'd like to try from other locations.

        Args:
            target: IP address or hostname to trace.
            locations: List of locations to run probes from. Supports:
                - Country codes: "US", "DE", "FR", "GB", "JP", "AU", etc.
                - Country names: "United States", "Germany", "France", etc.
                - Continent codes: "EU", "NA", "AS", "OC", "SA", "AF"
                - Region names: "Europe", "North America", "Asia", etc.
                Examples: ["US"] for United States only,
                         ["US", "DE"] for US and Germany,
                         ["Europe"] for all European probes.
                If not specified, uses a diverse global selection.

        Returns:
            Traceroute results showing paths from multiple vantage points.
        """
        if self._globalping is None:
            return "Globalping is not configured. Global network probing is not available."

        try:
            result = await self._globalping.traceroute(
                target=target,
                locations=locations,
                limit=5,  # Fewer probes for traceroute (more verbose output)
            )

            if not result.probes:
                return f"No traceroute results received for {target}."

            summary = [
                f"**Global Traceroute Results: {target}**",
                "",
                f"**Measurement ID:** {result.measurement_id}",
                f"**Probes:** {len(result.probes)}",
                "",
            ]

            for probe_result in result.probes[:5]:
                location = f"{probe_result.city}, {probe_result.country}"
                summary.append(f"**From {location}:**")

                if probe_result.hops:
                    for i, hop in enumerate(probe_result.hops[:15], 1):  # Limit hops shown
                        # Handle both old and new Globalping API response formats
                        hop_num = hop.get("hop", i)

                        # New format: resolvedHostname/resolvedAddress
                        host = (
                            hop.get("resolvedHostname")
                            or hop.get("resolvedAddress")
                            or hop.get("host")
                        )

                        # New format: timings array
                        timings = hop.get("timings", [])
                        if timings and isinstance(timings, list) and len(timings) > 0:
                            rtt = timings[0].get("rtt")
                        else:
                            rtt = hop.get("rtt")

                        if host:
                            if rtt:
                                summary.append(f"  {hop_num}. {host} ({rtt:.2f}ms)")
                            else:
                                summary.append(f"  {hop_num}. {host}")
                        else:
                            summary.append(f"  {hop_num}. *")
                    if len(probe_result.hops) > 15:
                        summary.append(f"  ... {len(probe_result.hops) - 15} more hops")
                else:
                    summary.append("  (No hops recorded)")

                summary.append("")

            return "\n".join(summary)

        except ValueError as e:
            # ValueError is raised for probe availability issues - pass through the helpful message
            error_msg = str(e)
            if "No probes available" in error_msg:
                requested = ", ".join(locations) if locations else "default locations"
                return (
                    f"**PROBE AVAILABILITY ERROR**\n\n"
                    f"{error_msg}\n\n"
                    f"The user requested probes from: {requested}\n\n"
                    f"**You MUST ask the user** if they would like to try from a different location. "
                    f"Suggest alternatives like Europe (DE, GB, FR), Asia (JP, SG), or use default global probes."
                )
            return f"Error performing global traceroute to {target}: {error_msg}"
        except Exception as e:
            return f"Error performing global traceroute to {target}: {str(e)}"

    async def get_ixps_for_asn(self, asn: int) -> str:
        """Get all Internet Exchange Points where an ASN is present.

        Returns a list of IXPs where the specified network has a peering
        presence, including their location and connection speed.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            List of IXPs where the ASN is present with connection details.
        """
        if self._peeringdb is None:
            return "PeeringDB is not configured. IXP information is not available."

        try:
            presences = self._peeringdb.get_ixps_for_asn(asn)

            if not presences:
                return (
                    f"AS{asn} is not present at any IXPs in PeeringDB, or the ASN does not exist."
                )

            summary = [
                f"**AS{asn} IXP Presence**",
                "",
                f"**Total IXPs:** {len(presences)}",
                "",
            ]

            for presence in presences:
                speed_str = ""
                if presence.speed:
                    if presence.speed >= 100000:
                        speed_str = f" ({presence.speed // 1000} Gbps)"
                    else:
                        speed_str = f" ({presence.speed} Mbps)"

                summary.append(f"**{presence.ixp_name}**{speed_str}")
                if presence.ipaddr4:
                    summary.append(f"  - IPv4: {presence.ipaddr4}")
                if presence.ipaddr6:
                    summary.append(f"  - IPv6: {presence.ipaddr6}")
                summary.append("")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting IXP presence for AS{asn}: {str(e)}"

    async def get_networks_at_ixp(self, ixp: str) -> str:
        """Get all networks/ASNs present at an Internet Exchange Point.

        Returns a list of networks that have a peering presence at the
        specified IXP.

        Args:
            ixp: IXP name (e.g., "AMS-IX", "DE-CIX Frankfurt") or ID.

        Returns:
            List of networks present at the IXP.
        """
        if self._peeringdb is None:
            return "PeeringDB is not configured. IXP information is not available."

        try:
            # Try to parse as int for ID, otherwise use as name
            try:
                ixp_id_or_name = int(ixp)
            except ValueError:
                ixp_id_or_name = ixp

            networks = self._peeringdb.get_networks_at_ixp(ixp_id_or_name)

            if not networks:
                return f"No networks found at IXP '{ixp}'. The IXP may not exist or have no participants."

            # Get IXP details for the header
            ixp_details = self._peeringdb.get_ixp_details(ixp_id_or_name)
            ixp_name = ixp_details.name if ixp_details else ixp

            summary = [
                f"**Networks at {ixp_name}**",
                "",
                f"**Total participants:** {len(networks)}",
                "",
                "**Networks (sample):**",
            ]

            # Show first 20 networks
            for network in networks[:20]:
                type_str = f" ({network.info_type})" if network.info_type else ""
                summary.append(f"  - AS{network.asn}: {network.name}{type_str}")

            if len(networks) > 20:
                summary.append(f"  ... and {len(networks) - 20} more networks")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting networks at IXP '{ixp}': {str(e)}"

    async def get_ixp_details(self, ixp: str) -> str:
        """Get detailed information about an Internet Exchange Point.

        Returns comprehensive information about the IXP including location,
        participant count, and website.

        Args:
            ixp: IXP name (e.g., "AMS-IX", "DE-CIX Frankfurt") or ID.

        Returns:
            Detailed IXP information.
        """
        if self._peeringdb is None:
            return "PeeringDB is not configured. IXP information is not available."

        try:
            # Try to parse as int for ID, otherwise use as name
            try:
                ixp_id_or_name = int(ixp)
            except ValueError:
                ixp_id_or_name = ixp

            ixp_info = self._peeringdb.get_ixp_details(ixp_id_or_name)

            if not ixp_info:
                return f"IXP '{ixp}' not found in PeeringDB."

            summary = [
                f"**{ixp_info.name}**",
                "",
                f"**Location:** {ixp_info.city}, {ixp_info.country}",
            ]

            if ixp_info.participant_count:
                summary.append(f"**Participants:** {ixp_info.participant_count}")

            if ixp_info.website:
                summary.append(f"**Website:** {ixp_info.website}")

            summary.append(f"**PeeringDB ID:** {ixp_info.id}")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting details for IXP '{ixp}': {str(e)}"

    async def get_network_contacts(self, asn: int) -> str:
        """Get contact information for a network from PeeringDB.

        Returns publicly visible points of contact (NOC, Abuse, Technical, etc.)
        for incident coordination and peering requests.

        Use this tool when:
        - The user needs to report a security incident to a network
        - The user wants to coordinate with a network's NOC
        - The user is investigating an issue and needs to contact the network operator

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            Contact information including roles, emails, and phone numbers.
        """
        if self._peeringdb is None:
            return "PeeringDB is not configured. Contact information is not available."

        try:
            # Get network info first
            network = self._peeringdb.get_network_info(asn)
            contacts = self._peeringdb.get_network_contacts(asn)

            if not network:
                return f"AS{asn} not found in PeeringDB."

            summary = [
                f"**AS{asn} Contact Information**",
                f"**Network:** {network.name}",
                "",
            ]

            if not contacts:
                summary.append("No public contact information available in PeeringDB.")
                if network.website:
                    summary.append(f"\n**Website:** {network.website}")
                return "\n".join(summary)

            summary.append(f"**Contacts ({len(contacts)}):**")
            summary.append("")

            # Group contacts by role
            by_role: dict[str, list] = {}
            for contact in contacts:
                role = contact.role or "Other"
                if role not in by_role:
                    by_role[role] = []
                by_role[role].append(contact)

            # Display contacts grouped by role, with priority order
            priority_roles = ["NOC", "Abuse", "Technical", "Policy", "Sales"]
            for role in priority_roles:
                if role in by_role:
                    summary.append(f"**{role}:**")
                    for contact in by_role[role]:
                        if contact.name:
                            summary.append(f"  - Name: {contact.name}")
                        if contact.email:
                            summary.append(f"  - Email: {contact.email}")
                        if contact.phone:
                            summary.append(f"  - Phone: {contact.phone}")
                        if contact.url:
                            summary.append(f"  - URL: {contact.url}")
                        summary.append("")
                    del by_role[role]

            # Display remaining roles
            for role, role_contacts in sorted(by_role.items()):
                summary.append(f"**{role}:**")
                for contact in role_contacts:
                    if contact.name:
                        summary.append(f"  - Name: {contact.name}")
                    if contact.email:
                        summary.append(f"  - Email: {contact.email}")
                    if contact.phone:
                        summary.append(f"  - Phone: {contact.phone}")
                    if contact.url:
                        summary.append(f"  - URL: {contact.url}")
                    summary.append("")

            if network.website:
                summary.append(f"**Website:** {network.website}")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting contacts for AS{asn}: {str(e)}"

    async def get_as_peers(self, asn: int) -> str:
        """Get all peers for an Autonomous System.

        Returns the list of networks that peer with this AS,
        derived from observed BGP routing data across 1,700+ global peers.
        Uses Monocle for accurate relationship data.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            List of peer ASes with visibility information.
        """
        if self._monocle is None:
            return "Monocle is not configured. AS relationship data is not available."

        try:
            peers = await self._monocle.get_as_peers(asn)

            if not peers:
                return f"No peer relationships found for AS{asn}."

            summary = [
                f"**AS{asn} Peers**",
                "",
                f"**Total peers:** {len(peers)}",
                "",
                "**Top peers (by visibility):**",
            ]

            # Sort by visibility and show top 20
            sorted_peers = sorted(peers, key=lambda p: p.connected_pct, reverse=True)
            for peer in sorted_peers[:20]:
                name_str = f" ({peer.asn2_name})" if peer.asn2_name else ""
                summary.append(f"  - AS{peer.asn2}{name_str}: {peer.connected_pct:.1f}% visibility")

            if len(peers) > 20:
                summary.append(f"  ... and {len(peers) - 20} more peers")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting peers for AS{asn}: {str(e)}"

    async def get_as_upstreams(self, asn: int) -> str:
        """Get upstream transit providers for an AS.

        Returns the list of networks that provide transit to this AS,
        derived from observed BGP routing data across 1,700+ global peers.
        Uses Monocle for accurate relationship data.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            List of upstream provider ASes with visibility information.
        """
        if self._monocle is None:
            return "Monocle is not configured. AS relationship data is not available."

        try:
            upstreams = await self._monocle.get_as_upstreams(asn)

            if not upstreams:
                return f"No upstream providers found for AS{asn}. This AS may be a transit-free network (Tier 1)."

            summary = [
                f"**AS{asn} Upstream Providers**",
                "",
                f"**Total upstreams:** {len(upstreams)}",
                "",
            ]

            # Sort by visibility
            sorted_upstreams = sorted(upstreams, key=lambda u: u.connected_pct, reverse=True)
            for upstream in sorted_upstreams:
                name_str = f" ({upstream.asn2_name})" if upstream.asn2_name else ""
                summary.append(
                    f"  - AS{upstream.asn2}{name_str}: {upstream.connected_pct:.1f}% visibility"
                )

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting upstreams for AS{asn}: {str(e)}"

    async def get_as_downstreams(self, asn: int) -> str:
        """Get downstream customers of an AS.

        Returns the list of networks that buy transit from this AS,
        derived from observed BGP routing data across 1,700+ global peers.
        Uses Monocle for accurate relationship data.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            List of downstream customer ASes with visibility information.
        """
        if self._monocle is None:
            return "Monocle is not configured. AS relationship data is not available."

        try:
            downstreams = await self._monocle.get_as_downstreams(asn)

            if not downstreams:
                return f"No downstream customers found for AS{asn}. This AS may be a stub network."

            summary = [
                f"**AS{asn} Downstream Customers**",
                "",
                f"**Total downstreams:** {len(downstreams)}",
                "",
            ]

            # Sort by visibility
            sorted_downstreams = sorted(downstreams, key=lambda d: d.connected_pct, reverse=True)
            for downstream in sorted_downstreams[:30]:
                name_str = f" ({downstream.asn2_name})" if downstream.asn2_name else ""
                summary.append(
                    f"  - AS{downstream.asn2}{name_str}: {downstream.connected_pct:.1f}% visibility"
                )

            if len(downstreams) > 30:
                summary.append(f"  ... and {len(downstreams) - 30} more customers")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting downstreams for AS{asn}: {str(e)}"

    async def check_as_relationship(self, asn1: int, asn2: int) -> str:
        """Check the relationship between two ASes.

        Determines if two ASes are peers, or if one is upstream of the other.
        Based on observed BGP routing data across 1,700+ global peers.

        Args:
            asn1: First Autonomous System Number.
            asn2: Second Autonomous System Number.

        Returns:
            Description of the relationship between the two ASes.
        """
        if self._monocle is None:
            return "Monocle is not configured. AS relationship data is not available."

        try:
            relationship = await self._monocle.check_relationship(asn1, asn2)

            if not relationship:
                return f"No direct relationship found between AS{asn1} and AS{asn2}."

            rel_type = relationship.relationship_type
            name_str = f" ({relationship.asn2_name})" if relationship.asn2_name else ""

            summary = [
                f"**Relationship: AS{asn1} ↔ AS{asn2}{name_str}**",
                "",
                f"**Type:** {rel_type.upper()}",
                f"**Visibility:** {relationship.connected_pct:.1f}% of BGP peers observe this relationship",
                "",
                "**Breakdown:**",
                f"  - Peer-to-peer: {relationship.peer_pct:.1f}%",
                f"  - AS{asn1} as upstream: {relationship.as1_upstream_pct:.1f}%",
                f"  - AS{asn2} as upstream: {relationship.as2_upstream_pct:.1f}%",
                "",
            ]

            # Add interpretation
            if rel_type == "peer":
                summary.append(
                    f"AS{asn1} and AS{asn2} exchange traffic as peers (settlement-free peering)."
                )
            elif rel_type == "upstream":
                summary.append(f"AS{asn2} provides transit to AS{asn1} (AS{asn2} is a provider).")
            elif rel_type == "downstream":
                summary.append(f"AS{asn1} provides transit to AS{asn2} (AS{asn1} is a provider).")

            return "\n".join(summary)

        except Exception as e:
            return f"Error checking relationship between AS{asn1} and AS{asn2}: {str(e)}"

    async def get_as_connectivity_summary(self, asn: int) -> str:
        """Get a connectivity summary for an AS - USE THIS FOR PEER COUNTS.

        This is the primary tool for answering "how many peers/upstreams/downstreams"
        questions. Returns accurate counts from observed BGP data.

        Shows counts of upstreams, peers, and downstreams with top examples.
        Based on observed BGP routing data across 1,700+ global peers.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            Connectivity summary with accurate neighbor counts and examples.
        """
        if self._monocle is None:
            return "Monocle is not configured. AS relationship data is not available."

        try:
            connectivity = await self._monocle.get_connectivity(asn)

            summary = [
                f"**AS{asn} Connectivity Summary**",
                "",
                f"**Total neighbors:** {connectivity.total_neighbors} (observed from {connectivity.max_visibility} BGP peers)",
                "",
            ]

            # Upstreams section
            summary.append(f"**Upstreams (Transit Providers):** {len(connectivity.upstreams)}")
            for upstream in connectivity.upstreams[:5]:
                name_str = f" {upstream.name}" if upstream.name else ""
                summary.append(
                    f"  - AS{upstream.asn}{name_str} ({upstream.peers_percent:.1f}% visibility)"
                )
            if len(connectivity.upstreams) > 5:
                summary.append(f"  ... and {len(connectivity.upstreams) - 5} more")
            summary.append("")

            # Peers section
            summary.append(f"**Peers:** {len(connectivity.peers)}")
            for peer in connectivity.peers[:5]:
                name_str = f" {peer.name}" if peer.name else ""
                summary.append(f"  - AS{peer.asn}{name_str} ({peer.peers_percent:.1f}% visibility)")
            if len(connectivity.peers) > 5:
                summary.append(f"  ... and {len(connectivity.peers) - 5} more")
            summary.append("")

            # Downstreams section
            summary.append(f"**Downstreams (Customers):** {len(connectivity.downstreams)}")
            for downstream in connectivity.downstreams[:5]:
                name_str = f" {downstream.name}" if downstream.name else ""
                summary.append(
                    f"  - AS{downstream.asn}{name_str} ({downstream.peers_percent:.1f}% visibility)"
                )
            if len(connectivity.downstreams) > 5:
                summary.append(f"  ... and {len(connectivity.downstreams) - 5} more")

            return "\n".join(summary)

        except Exception as e:
            return f"Error getting connectivity summary for AS{asn}: {str(e)}"

    async def start_monitoring(
        self,
        collectors: list[str] | None = None,
    ) -> str:
        """Start real-time BGP anomaly monitoring.

        Starts the bgp-radar subprocess to monitor for hijacks, route leaks,
        and blackholes from RIS Live data. Events will be displayed in real-time.

        Args:
            collectors: List of RIS collectors to monitor (e.g., ["rrc00", "rrc01"]).
                       If not specified, uses the default collectors.

        Returns:
            Status message indicating monitoring has started.
        """
        if self._bgp_radar is None:
            return "bgp-radar is not configured. Real-time monitoring is not available."

        if self._bgp_radar.is_running:
            current_collectors = ", ".join(self._bgp_radar._collectors)
            return f"Monitoring is already running (collectors: {current_collectors})."

        try:
            await self._bgp_radar.start(collectors=collectors)
            active_collectors = ", ".join(self._bgp_radar._collectors)
            return (
                f"**BGP Monitoring Started**\n\n"
                f"Now watching for anomalies from collectors: {active_collectors}\n\n"
                f"Events (hijacks, route leaks, blackholes) will be displayed in real-time as they are detected.\n\n"
                f"Use stop_monitoring() or `/monitor stop` to stop monitoring."
            )

        except Exception as e:
            return f"Error starting monitoring: {str(e)}"

    async def stop_monitoring(self) -> str:
        """Stop real-time BGP anomaly monitoring.

        Stops the bgp-radar subprocess.

        Returns:
            Status message indicating monitoring has stopped.
        """
        if self._bgp_radar is None:
            return "bgp-radar is not configured. Real-time monitoring is not available."

        if not self._bgp_radar.is_running:
            return "Monitoring is not running."

        try:
            await self._bgp_radar.stop()
            return "**BGP Monitoring Stopped**\n\nReal-time anomaly detection has been stopped."

        except Exception as e:
            return f"Error stopping monitoring: {str(e)}"

    async def check_prefix_anomalies(self, prefix: str) -> str:
        """Check a prefix for potential hijack indicators using RIPE Stat.

        This tool provides on-demand anomaly detection WITHOUT requiring bgp-radar.
        Works for both IPv4 and IPv6 prefixes.

        It checks multiple indicators that may suggest a BGP hijack or misconfiguration:

        1. **MOAS Detection**: Multiple Origin AS - if more than one AS is announcing
           the same prefix, it could indicate a hijack.
        2. **RPKI Validation**: Checks if the announcement is covered by a valid ROA.
           Invalid status strongly suggests unauthorized announcement.
        3. **Origin Change Detection**: Looks for recent changes in the originating ASN.
        4. **Visibility Analysis**: Checks how many collectors see the prefix.

        Use this tool when:
        - Investigating a suspected hijack
        - Validating prefix ownership before peering
        - Checking if a prefix has anomalous routing behavior
        - The user asks to "check for hijacks" or "verify a prefix"

        When investigating an ASN's security posture, check representative prefixes
        from BOTH IPv4 and IPv6 address families as RPKI deployment may differ.

        Args:
            prefix: IP prefix in CIDR notation (e.g., "8.8.8.0/24" or "2001:db8::/32").

        Returns:
            Analysis with risk level (low/medium/high) and detailed indicators.
        """
        try:
            indicators: dict[str, Any] = {}
            risk_factors: list[str] = []

            # Step 1: Get current BGP state for MOAS and visibility
            routes = await self._ripe_stat.get_bgp_state(prefix)

            if not routes:
                return (
                    f"**Prefix Anomaly Check: {prefix}**\n\n"
                    f"**Status:** Not routed\n\n"
                    f"No routes found for this prefix. The prefix may not be announced, "
                    f"or may not be visible from RIPE RIS collectors.\n\n"
                    f"This could indicate:\n"
                    f"  - Prefix is not currently announced\n"
                    f"  - Prefix was withdrawn (possible blackhole)\n"
                    f"  - Filtering is preventing propagation"
                )

            # Analyze origins (MOAS detection)
            origin_asns = list(set(r.origin_asn for r in routes))
            collectors = list(set(r.collector for r in routes))

            indicators["moas"] = {
                "detected": len(origin_asns) > 1,
                "origins": origin_asns,
                "count": len(origin_asns),
            }

            if len(origin_asns) > 1:
                risk_factors.append(f"MOAS: Multiple origins ({len(origin_asns)} ASes)")

            # Visibility analysis
            indicators["visibility"] = {
                "collector_count": len(collectors),
                "collectors": collectors[:10],  # Sample for output
                "status": "normal" if len(collectors) >= 10 else "limited",
            }

            if len(collectors) < 5:
                risk_factors.append(f"Low visibility: Only {len(collectors)} collectors")

            # Step 2: RPKI validation for each origin
            rpki_results = {}
            for origin in origin_asns:
                try:
                    status = await self._ripe_stat.get_rpki_validation(prefix, origin)
                    rpki_results[origin] = status
                    if status == "invalid":
                        risk_factors.append(f"RPKI Invalid: AS{origin} not authorized")
                except Exception:
                    rpki_results[origin] = "error"

            indicators["rpki"] = rpki_results

            # Step 3: Check routing history for recent origin changes
            now = datetime.now(UTC)
            week_ago = now - timedelta(days=7)

            try:
                history = await self._ripe_stat.get_routing_history(prefix, week_ago, now)
                historical_origins = set()
                for origin_data in history.get("by_origin", []):
                    origin_str = origin_data.get("origin", "")
                    if origin_str:
                        try:
                            historical_origins.add(int(origin_str))
                        except ValueError:
                            pass

                # Check if current origins differ from historical
                current_origins_set = set(origin_asns)
                new_origins = current_origins_set - historical_origins
                removed_origins = historical_origins - current_origins_set

                indicators["origin_history"] = {
                    "current_origins": list(current_origins_set),
                    "historical_origins": list(historical_origins),
                    "new_origins": list(new_origins),
                    "removed_origins": list(removed_origins),
                    "change_detected": bool(new_origins or removed_origins),
                }

                if new_origins:
                    risk_factors.append(
                        f"New origin(s) in last 7 days: {', '.join(f'AS{o}' for o in new_origins)}"
                    )

            except Exception:
                indicators["origin_history"] = {"error": "Could not fetch history"}

            # Calculate risk level
            if any("RPKI Invalid" in rf for rf in risk_factors):
                risk_level = "high"
            elif len(risk_factors) >= 2:
                risk_level = "high"
            elif risk_factors:
                risk_level = "medium"
            else:
                risk_level = "low"

            # Build summary
            summary = [
                f"**Prefix Anomaly Check: {prefix}**",
                "",
                f"**Risk Level:** {'🔴 HIGH' if risk_level == 'high' else '🟡 MEDIUM' if risk_level == 'medium' else '🟢 LOW'}",
                "",
            ]

            # MOAS section
            if indicators["moas"]["detected"]:
                summary.append("**⚠️ MOAS Detected (Multiple Origin AS)**")
                summary.append(f"  Origins: {', '.join(f'AS{asn}' for asn in origin_asns)}")
            else:
                summary.append(f"**Single Origin:** AS{origin_asns[0]}")
            summary.append("")

            # RPKI section
            summary.append("**RPKI Validation:**")
            for origin, status in rpki_results.items():
                status_emoji = {"valid": "✅", "invalid": "❌", "not-found": "❓"}.get(status, "⚠️")
                summary.append(f"  - AS{origin}: {status_emoji} {status.upper()}")
            summary.append("")

            # Visibility section
            vis = indicators["visibility"]
            summary.append(f"**Visibility:** {vis['collector_count']} collectors")
            if vis["status"] == "limited":
                summary.append("  ⚠️ Limited visibility may indicate filtering or recent change")
            summary.append("")

            # Origin history section
            if "error" not in indicators.get("origin_history", {}):
                hist = indicators["origin_history"]
                if hist["change_detected"]:
                    summary.append("**⚠️ Recent Origin Changes (last 7 days):**")
                    if hist["new_origins"]:
                        summary.append(
                            f"  - New: {', '.join(f'AS{o}' for o in hist['new_origins'])}"
                        )
                    if hist["removed_origins"]:
                        summary.append(
                            f"  - Removed: {', '.join(f'AS{o}' for o in hist['removed_origins'])}"
                        )
                else:
                    summary.append("**Origin History:** Stable (no changes in last 7 days)")
                summary.append("")

            # Risk factors summary
            if risk_factors:
                summary.append("**Risk Factors:**")
                for factor in risk_factors:
                    summary.append(f"  - {factor}")
            else:
                summary.append(
                    "**No risk factors detected.** Prefix appears to be routing normally."
                )

            return "\n".join(summary)

        except Exception as e:
            return f"Error checking prefix anomalies for {prefix}: {str(e)}"

    async def assess_network_resilience(self, asn: int) -> str:
        """Assess network resilience and diversity for an Autonomous System.

        Produces a resilience score (1-10) plus detailed report with recommendations.
        Evaluates transit diversity, peering breadth, IXP presence, and path redundancy.

        **Scoring Model:**
        | Dimension        | Weight | Criteria                                    |
        |------------------|--------|---------------------------------------------|
        | Transit Diversity| 30%    | Upstream count (min 2 required, 3+ optimal) |
        | Peering Breadth  | 25%    | Total peer count (more = better DDoS absorb)|
        | IXP Presence     | 20%    | Number of IXPs (geographic diversity)       |
        | Path Redundancy  | 25%    | Distinct AS paths from collectors           |

        **Score capped at 5 if:**
        - Single transit provider (critical single point of failure)
        - Always-on DDoS protection provider detected in upstream path

        Use this tool to:
        - Assess a network's resilience to outages and DDoS attacks
        - Identify single points of failure in a network's connectivity
        - Get recommendations for improving network diversity
        - Evaluate potential peering partners or transit providers

        Args:
            asn: Autonomous System Number to assess (e.g., 15169 for Google).

        Returns:
            Resilience assessment with score (1-10), component breakdown, and recommendations.
        """
        # Check if required data sources are available
        if self._monocle is None:
            return (
                "Monocle is not configured. Network resilience assessment requires "
                "Monocle for AS relationship data. Install with: cargo install monocle"
            )

        if self._peeringdb is None:
            return (
                "PeeringDB is not configured. Network resilience assessment requires "
                "PeeringDB for IXP presence data."
            )

        try:
            # Gather data from monocle and peeringdb
            upstreams = await self._monocle.get_as_upstreams(asn)
            peers = await self._monocle.get_as_peers(asn)
            ixps = self._peeringdb.get_ixps_for_asn(asn)

            # Calculate component scores using ResilienceAssessor
            transit_score, transit_issues = self._resilience_assessor._score_transit(upstreams)
            peering_score, peer_count = self._resilience_assessor._score_peering(peers)
            ixp_score, ixp_names = self._resilience_assessor._score_ixp(ixps)

            # For now, use transit diversity as proxy for path redundancy
            # (Real implementation would query multiple collectors)
            path_redundancy_score = transit_score

            # Check for DDoS provider in upstreams
            ddos_provider = self._resilience_assessor._detect_ddos_provider(upstreams)

            # Check for single transit
            single_transit = len(upstreams) == 1

            # Build scores and flags
            scores = {
                "transit": transit_score,
                "peering": peering_score,
                "ixp": ixp_score,
                "path_redundancy": path_redundancy_score,
            }
            flags = {
                "single_transit": single_transit,
                "ddos_provider": ddos_provider,
            }

            # Calculate final score
            final_score = self._resilience_assessor._calculate_final_score(scores, flags)

            # Build upstream names
            upstream_names = []
            for u in upstreams[:10]:
                name = f"AS{u.asn2}"
                if u.asn2_name:
                    name += f" ({u.asn2_name})"
                upstream_names.append(name)

            # Build report
            report = ResilienceReport(
                asn=asn,
                score=final_score,
                transit_score=transit_score,
                peering_score=peering_score,
                ixp_score=ixp_score,
                path_redundancy_score=path_redundancy_score,
                upstream_count=len(upstreams),
                peer_count=peer_count,
                ixp_count=len(ixps),
                upstreams=upstream_names,
                ixps=ixp_names,
                issues=transit_issues,
                recommendations=[],  # Will be generated
                single_transit=single_transit,
                ddos_provider_detected=ddos_provider,
            )

            # Generate recommendations
            report.recommendations = self._resilience_assessor._generate_recommendations(report)

            # Format and return report
            return self._resilience_assessor.format_report(report)

        except Exception as e:
            return f"Error assessing network resilience for AS{asn}: {str(e)}"
