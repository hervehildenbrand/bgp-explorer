"""AI tool definitions for BGP Explorer.

These tools are registered with the AI backend and can be called
by the AI to query BGP data sources.
"""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from bgp_explorer.analysis.as_analysis import ASAnalyzer
from bgp_explorer.analysis.path_analysis import PathAnalyzer
from bgp_explorer.models.event import EventType
from bgp_explorer.sources.bgp_radar import BgpRadarClient
from bgp_explorer.sources.globalping import GlobalpingClient
from bgp_explorer.sources.ripe_stat import RipeStatClient


class BGPTools:
    """Collection of tools for querying BGP data.

    These tools are designed to be registered with an AI backend
    and called during conversation to fetch real-time and historical
    BGP routing data.
    """

    def __init__(
        self,
        ripe_stat: RipeStatClient,
        bgp_radar: Optional[BgpRadarClient] = None,
        globalping: Optional[GlobalpingClient] = None,
    ):
        """Initialize tools with data source clients.

        Args:
            ripe_stat: RIPE Stat client for historical/state queries.
            bgp_radar: bgp-radar client for real-time anomalies.
            globalping: Globalping client for network probing.
        """
        self._ripe_stat = ripe_stat
        self._bgp_radar = bgp_radar
        self._globalping = globalping
        self._path_analyzer = PathAnalyzer()
        self._as_analyzer = ASAnalyzer()

    def get_all_tools(self) -> list[Callable[..., Any]]:
        """Get all tool functions for registration with AI backend.

        Returns:
            List of tool functions.
        """
        tools = [
            self.lookup_prefix,
            self.get_asn_announcements,
            self.get_routing_history,
            self.get_anomalies,
            self.get_rpki_status,
            self.analyze_as_path,
            self.compare_collectors,
            self.get_asn_details,
        ]
        # Add Globalping tools if available
        if self._globalping:
            tools.extend([
                self.ping_from_global,
                self.traceroute_from_global,
            ])
        return tools

    async def lookup_prefix(self, prefix: str) -> str:
        """Look up BGP routing information for an IP prefix.

        Returns the origin ASN, AS paths from multiple vantage points,
        and visibility information for the specified prefix.

        Args:
            prefix: IP prefix in CIDR notation (e.g., "8.8.8.0/24" or "2001:db8::/32").

        Returns:
            Human-readable summary of routing information for the prefix.
        """
        try:
            routes = await self._ripe_stat.get_bgp_state(prefix)

            if not routes:
                return f"No routes found for prefix {prefix}. The prefix may not be announced or visible from RIPE RIS collectors."

            # Summarize the results
            origin_asns = set(r.origin_asn for r in routes)
            collectors = set(r.collector for r in routes)
            unique_paths = set(tuple(r.as_path) for r in routes)

            summary = [
                f"**Prefix: {prefix}**",
                f"",
                f"**Origin ASN(s):** {', '.join(f'AS{asn}' for asn in sorted(origin_asns))}",
                f"**Visible from:** {len(collectors)} collectors ({', '.join(sorted(collectors)[:5])}{'...' if len(collectors) > 5 else ''})",
                f"**Unique AS paths:** {len(unique_paths)}",
                "",
                "**Sample paths:**",
            ]

            # Show up to 5 unique paths
            for i, path in enumerate(list(unique_paths)[:5]):
                path_str = " → ".join(f"AS{asn}" for asn in path)
                summary.append(f"  {i+1}. {path_str}")

            return "\n".join(summary)

        except Exception as e:
            return f"Error looking up prefix {prefix}: {str(e)}"

    async def get_asn_announcements(self, asn: int) -> str:
        """Get all prefixes announced by an Autonomous System.

        Returns a list of IP prefixes that are currently originated
        by the specified ASN.

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            List of prefixes announced by the ASN.
        """
        try:
            prefixes = await self._ripe_stat.get_announced_prefixes(asn)

            if not prefixes:
                return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

            # Separate IPv4 and IPv6
            ipv4 = [p for p in prefixes if ":" not in p]
            ipv6 = [p for p in prefixes if ":" in p]

            summary = [
                f"**AS{asn} Announcements**",
                "",
                f"**Total prefixes:** {len(prefixes)}",
                f"  - IPv4: {len(ipv4)}",
                f"  - IPv6: {len(ipv6)}",
                "",
            ]

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
            start = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            end = datetime.fromisoformat(end_date).replace(tzinfo=timezone.utc)

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
        event_type: Optional[str] = None,
        prefix: Optional[str] = None,
        asn: Optional[int] = None,
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
                f"**Recent BGP Anomalies**",
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

        Validates whether the prefix announcement from the given
        origin ASN is covered by a valid ROA (Route Origin Authorization).

        Args:
            prefix: IP prefix in CIDR notation.
            origin_asn: The AS number claiming to originate the prefix.

        Returns:
            RPKI validation status: valid, invalid, or not-found.
        """
        try:
            status = await self._ripe_stat.get_rpki_validation(prefix, origin_asn)

            status_emoji = {
                "valid": "✅",
                "invalid": "❌",
                "not-found": "❓",
            }.get(status, "❓")

            summary = [
                f"**RPKI Validation**",
                f"",
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

        Provides detailed analysis of path diversity, upstream providers,
        transit ASNs, and path length statistics across multiple vantage points.

        Args:
            prefix: IP prefix in CIDR notation (e.g., "8.8.8.0/24").

        Returns:
            Detailed path analysis including diversity metrics and path characteristics.
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
                f"**Upstream ASNs (direct peers of origin):** {len(upstreams)}",
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

        Args:
            asn: Autonomous System Number (e.g., 15169 for Google).

        Returns:
            Detailed ASN analysis and statistics.
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

            summary.append("**Routing Behavior (from sampled routes):**")
            summary.append(f"  - Appearances in paths: {asn_summary['appearances']}")
            summary.append(f"  - As origin: {asn_summary['as_origin_count']}")
            summary.append(f"  - As transit: {asn_summary['as_transit_count']}")

            # Classify ASN type based on behavior
            if asn_summary["as_transit_count"] > asn_summary["as_origin_count"] * 2:
                summary.append("")
                summary.append("**Classification:** Likely a transit provider")
            elif asn_summary["as_origin_count"] > asn_summary["as_transit_count"] * 2:
                summary.append("")
                summary.append("**Classification:** Likely a stub/edge network")

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

        Args:
            target: IP address or hostname to ping.
            locations: Optional list of locations (e.g., ["US", "Europe", "Asia"]).
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
                    summary.append(
                        f"  - Avg: {sum(avg_latencies) / len(avg_latencies):.2f} ms"
                    )
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

        Args:
            target: IP address or hostname to trace.
            locations: Optional list of locations (e.g., ["US", "Europe"]).
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
                    for hop in probe_result.hops[:15]:  # Limit hops shown
                        hop_num = hop.get("hop", "?")
                        host = hop.get("host", "*")
                        rtt = hop.get("rtt", None)
                        if rtt:
                            summary.append(f"  {hop_num}. {host} ({rtt:.2f}ms)")
                        else:
                            summary.append(f"  {hop_num}. {host}")
                    if len(probe_result.hops) > 15:
                        summary.append(f"  ... {len(probe_result.hops) - 15} more hops")
                else:
                    summary.append("  (No hops recorded)")

                summary.append("")

            return "\n".join(summary)

        except Exception as e:
            return f"Error performing global traceroute to {target}: {str(e)}"
