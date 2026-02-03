"""MCP server exposing BGP tools for Claude Code integration.

This module provides an MCP (Model Context Protocol) server that exposes
BGP Explorer's investigation tools. Users with Claude Code subscriptions
can use these tools without needing an API key.

Usage:
    # Add to Claude Code (use YOUR actual path)
    claude mcp add bgp-explorer -- uv run --directory /path/to/bgp-explorer bgp-explorer mcp

    # Example with home directory:
    claude mcp add bgp-explorer -- uv run --directory ~/Code/bgp-explorer bgp-explorer mcp

    # Verify it works:
    claude mcp list

    # Then use Claude Code normally
    claude

IMPORTANT: The 'bgp-explorer' command is NOT globally installed.
You must use 'uv run --directory' to specify the installation path.
"""

import logging
import sys
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from bgp_explorer.analysis.as_analysis import ASAnalyzer
from bgp_explorer.analysis.path_analysis import PathAnalyzer
from bgp_explorer.analysis.resilience import ResilienceAssessor, ResilienceReport
from bgp_explorer.sources.globalping import GlobalpingClient
from bgp_explorer.sources.monocle import MonocleClient
from bgp_explorer.sources.peeringdb import PeeringDBClient
from bgp_explorer.sources.ripe_stat import RipeStatClient

# Configure logging to stderr (NOT stdout - MCP uses stdout for protocol)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP(
    name="bgp-explorer",
    instructions="""BGP routing investigation tools for network operators.

Use these tools to investigate BGP routing, analyze AS relationships,
detect anomalies, and probe network connectivity from global vantage points.

Key guidelines:
- When investigating a network by name, use search_asn FIRST to find the ASN
- For peer counts, use get_as_peers (NOT path analysis metrics)
- For connectivity overview, use get_as_connectivity_summary
- For hijack detection, use check_prefix_anomalies
""",
)

# Lazy-initialized clients (created on first use)
_ripe_stat: RipeStatClient | None = None
_monocle: MonocleClient | None = None
_globalping: GlobalpingClient | None = None
_peeringdb: PeeringDBClient | None = None
_path_analyzer: PathAnalyzer | None = None
_as_analyzer: ASAnalyzer | None = None
_resilience_assessor: ResilienceAssessor | None = None


async def get_ripe_stat() -> RipeStatClient:
    """Get or create RipeStatClient (lazy initialization)."""
    global _ripe_stat
    if _ripe_stat is None:
        _ripe_stat = RipeStatClient()
        await _ripe_stat.connect()
    return _ripe_stat


async def get_monocle() -> MonocleClient | None:
    """Get or create MonocleClient (lazy initialization)."""
    global _monocle
    if _monocle is None:
        _monocle = MonocleClient()
        if not await _monocle.is_available():
            logger.warning("Monocle binary not found - AS relationship tools unavailable")
            return None
    return _monocle


async def get_globalping() -> GlobalpingClient | None:
    """Get or create GlobalpingClient (lazy initialization)."""
    global _globalping
    if _globalping is None:
        _globalping = GlobalpingClient()
        await _globalping.connect()
    return _globalping


async def get_peeringdb() -> PeeringDBClient | None:
    """Get or create PeeringDBClient (lazy initialization)."""
    global _peeringdb
    if _peeringdb is None:
        _peeringdb = PeeringDBClient()
        await _peeringdb.connect()
    return _peeringdb


def get_path_analyzer() -> PathAnalyzer:
    """Get or create PathAnalyzer."""
    global _path_analyzer
    if _path_analyzer is None:
        _path_analyzer = PathAnalyzer()
    return _path_analyzer


def get_as_analyzer() -> ASAnalyzer:
    """Get or create ASAnalyzer."""
    global _as_analyzer
    if _as_analyzer is None:
        _as_analyzer = ASAnalyzer()
    return _as_analyzer


def get_resilience_assessor() -> ResilienceAssessor:
    """Get or create ResilienceAssessor."""
    global _resilience_assessor
    if _resilience_assessor is None:
        _resilience_assessor = ResilienceAssessor()
    return _resilience_assessor


# =============================================================================
# RIPE Stat Tools (Core routing data)
# =============================================================================


@mcp.tool()
async def search_asn(
    query: Annotated[
        str, Field(description="Organization name to search (e.g., 'Google', 'Cloudflare')")
    ],
) -> str:
    """Search for ASNs by organization or company name.

    Use this tool FIRST when a user asks about a network by name without
    providing an ASN number. This helps find the correct ASN before using
    other tools.

    IMPORTANT: NEVER guess or assume ASN numbers. Always search first.

    The search automatically tries common variations of the company name
    (e.g., 'Criteo', 'Criteo Europe', 'Criteo SA') to find all related ASNs.

    Data source: RIPE Stat searchcomplete API, with PeeringDB fallback.
    """
    try:
        client = await get_ripe_stat()

        # Generate search variations for thorough matching
        variations = [query]
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
        seen_asns: set[int] = set()
        all_results: list[dict[str, Any]] = []

        for variation in variations:
            try:
                results = await client.search_asn(variation)
                for result in results:
                    asn = result["asn"]
                    if asn not in seen_asns:
                        seen_asns.add(asn)
                        all_results.append(result)
            except Exception:
                continue

        # If RIPE Stat found nothing, try PeeringDB as fallback
        if not all_results:
            try:
                peeringdb = await get_peeringdb()
                if peeringdb is not None:
                    pdb_results = peeringdb.search_networks(query)
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

        summary.append("")
        if len(all_results) <= 3:
            summary.append(
                "**Note:** Only a few ASNs found. Large companies often have more ASNs registered "
                "under different names."
            )
        elif len(all_results) > 1:
            summary.append(
                "**Multiple matches found.** Please confirm with the user which ASN they meant "
                "before proceeding with other queries."
            )

        return "\n".join(summary)

    except Exception as e:
        return f"Error searching for ASN: {e}"


@mcp.tool()
async def lookup_prefix(
    prefix: Annotated[
        str, Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24' or '2001:db8::/32')")
    ],
) -> str:
    """Look up BGP routing information for an IP prefix.

    Returns the origin ASN, AS paths from multiple vantage points,
    and visibility information for the specified prefix.
    Auto-detects and reports whether this is an IPv4 or IPv6 prefix.

    Data source: RIPE Stat BGP State API.
    """
    try:
        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        # Detect address family
        is_ipv6 = ":" in prefix
        family_str = "IPv6" if is_ipv6 else "IPv4"

        if not routes:
            return f"No routes found for {family_str} prefix {prefix}. The prefix may not be announced or visible from RIPE RIS collectors."

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

        for i, path in enumerate(list(unique_paths)[:5]):
            path_str = " -> ".join(f"AS{asn}" for asn in path)
            summary.append(f"  {i + 1}. {path_str}")

        return "\n".join(summary)

    except Exception as e:
        return f"Error looking up prefix {prefix}: {e}"


@mcp.tool()
async def get_asn_announcements(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 15169 for Google)")],
    address_family: Annotated[
        int | None,
        Field(
            description="Optional filter: 4 for IPv4 only, 6 for IPv6 only, omit for both",
            default=None,
        ),
    ] = None,
) -> str:
    """Get prefixes announced by an AS, optionally filtered by address family.

    Returns a list of IP prefixes that are currently originated
    by the specified ASN. Always reports IPv4 and IPv6 counts separately,
    as many networks handle the two address families differently.

    Use address_family filter when the user specifically asks about one protocol
    (e.g., "show only IPv6 prefixes").

    Data source: RIPE Stat announced-prefixes API.
    """
    try:
        client = await get_ripe_stat()
        prefixes = await client.get_announced_prefixes(asn)

        if not prefixes:
            return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

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
            filtered_prefixes = None
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
        return f"Error getting announcements for AS{asn}: {e}"


@mcp.tool()
async def get_routing_history(
    resource: Annotated[
        str, Field(description="IP prefix (e.g., '8.8.8.0/24') or ASN (e.g., 'AS15169')")
    ],
    start_date: Annotated[str, Field(description="Start date in ISO format (YYYY-MM-DD)")],
    end_date: Annotated[str, Field(description="End date in ISO format (YYYY-MM-DD)")],
) -> str:
    """Get historical ORIGIN ASN changes for a prefix or ASN.

    Shows which ASes originated the prefix over time. This tool tracks
    ORIGIN changes only - it does NOT show AS path changes or upstream
    provider changes.

    For detailed path-level history (upstream changes, path convergence),
    use get_bgp_path_history() instead.

    Data source: RIPE Stat routing-history API.
    """
    try:
        client = await get_ripe_stat()
        start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
        end = datetime.fromisoformat(end_date).replace(tzinfo=UTC)

        history = await client.get_routing_history(resource, start, end)

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
        return f"Error getting routing history: {e}"


@mcp.tool()
async def get_bgp_path_history(
    prefix: Annotated[
        str, Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24')")
    ],
    start_date: Annotated[str, Field(description="Start date in ISO format (YYYY-MM-DD)")],
    end_date: Annotated[str, Field(description="End date in ISO format (YYYY-MM-DD)")],
) -> str:
    """Get detailed AS path changes for a prefix over time.

    Shows how the AS paths (upstream providers, transit networks) changed
    over time. Use this to investigate:
    - Upstream provider changes during an outage
    - Path convergence after a routing change
    - Historical path diversity analysis

    For simple origin ASN changes only, use get_routing_history() instead.

    Data source: RIPE Stat BGPlay API.
    """
    try:
        client = await get_ripe_stat()
        start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
        end = datetime.fromisoformat(end_date).replace(tzinfo=UTC)

        data = await client.get_bgp_events(prefix, start, end)

        summary = [
            f"**AS Path History: {prefix}**",
            f"**Period:** {start_date} to {end_date}",
            "",
        ]

        # Extract initial state
        initial_state = data.get("initial_state", [])
        if initial_state:
            summary.append(f"**Initial paths:** {len(initial_state)}")
            unique_initial_paths: set[tuple[int, ...]] = set()
            for entry in initial_state:
                path = tuple(entry.get("path", []))
                if path:
                    unique_initial_paths.add(path)
            summary.append(f"**Unique initial paths:** {len(unique_initial_paths)}")
            for i, path in enumerate(list(unique_initial_paths)[:5]):
                path_str = " -> ".join(f"AS{asn}" for asn in path)
                summary.append(f"  {i + 1}. {path_str}")
            if len(unique_initial_paths) > 5:
                summary.append(f"  ... and {len(unique_initial_paths) - 5} more")
            summary.append("")

        # Extract events (path changes)
        events = data.get("events", [])
        if not events:
            summary.append("**No path changes detected during this period.**")
            summary.append("")
            summary.append(
                "This means the AS paths remained stable. For origin-only changes, "
                "use get_routing_history()."
            )
        else:
            announcements = [e for e in events if e.get("type") == "A"]
            withdrawals = [e for e in events if e.get("type") == "W"]

            summary.append("**Path Events:**")
            summary.append(f"  - Announcements: {len(announcements)}")
            summary.append(f"  - Withdrawals: {len(withdrawals)}")
            summary.append("")

            summary.append("**Recent path changes (last 10):**")
            for event in events[-10:]:
                event_type = event.get("type", "?")
                timestamp = event.get("timestamp", "")
                path = event.get("path", [])
                source_id = event.get("source_id", "unknown")

                type_label = "ANNOUNCE" if event_type == "A" else "WITHDRAW"
                if path:
                    path_str = " -> ".join(f"AS{asn}" for asn in path)
                    summary.append(f"  [{timestamp}] {type_label}: {path_str}")
                else:
                    summary.append(f"  [{timestamp}] {type_label} (from {source_id})")

            unique_paths_in_events: set[tuple[int, ...]] = set()
            for event in events:
                if event.get("type") == "A":
                    path = tuple(event.get("path", []))
                    if path:
                        unique_paths_in_events.add(path)

            if unique_paths_in_events:
                summary.append("")
                summary.append(f"**Unique paths observed in changes:** {len(unique_paths_in_events)}")
                upstream_asns: set[int] = set()
                for path in unique_paths_in_events:
                    if len(path) >= 2:
                        upstream_asns.add(path[-2])
                if upstream_asns:
                    summary.append(
                        f"**Upstream ASes observed:** {', '.join(f'AS{asn}' for asn in sorted(upstream_asns))}"
                    )

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting BGP path history: {e}"


@mcp.tool()
async def get_rpki_status(
    prefix: Annotated[str, Field(description="IP prefix in CIDR notation (IPv4 or IPv6)")],
    origin_asn: Annotated[int, Field(description="The AS number claiming to originate the prefix")],
) -> str:
    """Check RPKI validation status for a prefix/origin pair.

    **USE PROACTIVELY** - Always check RPKI when investigating prefixes.
    Include RPKI status in every prefix report without waiting to be asked.

    Validates whether the prefix announcement from the given
    origin ASN is covered by a valid ROA (Route Origin Authorization).

    Returns:
    - valid: ROA exists and matches - legitimate announcement
    - invalid: ROA exists but DOESN'T match - potential hijack!
    - not-found: No ROA - owner hasn't deployed RPKI (common, not necessarily bad)
    """
    try:
        client = await get_ripe_stat()
        status = await client.get_rpki_validation(prefix, origin_asn)

        status_emoji = {"valid": "OK", "invalid": "INVALID", "not-found": "NOT FOUND"}.get(
            status, "UNKNOWN"
        )

        summary = [
            "**RPKI Validation**",
            "",
            f"**Prefix:** {prefix}",
            f"**Origin:** AS{origin_asn}",
            f"**Status:** {status_emoji}",
            "",
        ]

        if status == "valid":
            summary.append(
                "The route announcement is covered by a valid ROA and matches the expected origin."
            )
        elif status == "invalid":
            summary.append(
                "WARNING: The route announcement is INVALID - it may be a hijack or misconfiguration."
            )
        else:
            summary.append("No ROA found for this prefix. The origin cannot be validated via RPKI.")

        return "\n".join(summary)

    except Exception as e:
        return f"Error checking RPKI status: {e}"


@mcp.tool()
async def analyze_as_path(
    prefix: Annotated[str, Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24')")],
) -> str:
    """Analyze AS path diversity and characteristics for a prefix.

    NOTE: This shows PATH DIVERSITY metrics (unique ASNs in collected routes),
    NOT actual peer count. For peer counts, use get_as_peers() or
    get_as_connectivity_summary() instead.

    Provides detailed analysis of path diversity, upstream providers,
    transit ASNs, and path length statistics across multiple vantage points.

    Data source: RIPE Stat BGP State API.
    """
    try:
        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        if not routes:
            return f"No routes found for prefix {prefix}. Cannot analyze paths."

        analyzer = get_path_analyzer()
        diversity = analyzer.get_path_diversity(routes)
        upstreams = analyzer.get_upstream_asns(routes)
        transits = analyzer.get_transit_asns(routes)
        prepending = analyzer.get_path_prepending(routes)

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
            f"**Upstream hops in paths:** {len(upstreams)} unique ASNs observed directly before origin",
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
        return f"Error analyzing AS paths for {prefix}: {e}"


@mcp.tool()
async def compare_collectors(
    prefix: Annotated[str, Field(description="IP prefix in CIDR notation")],
) -> str:
    """Compare routing views for a prefix across different collectors.

    Shows how the prefix is seen from different vantage points in the
    RIPE RIS infrastructure, highlighting any inconsistencies.

    Useful for detecting routing anomalies like MOAS or inconsistent announcements.

    Data source: RIPE Stat BGP State API.
    """
    try:
        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        if not routes:
            return f"No routes found for prefix {prefix}. Cannot compare collectors."

        analyzer = get_path_analyzer()
        comparison = analyzer.compare_paths_across_collectors(routes)

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
            path_str = " -> ".join(f"AS{asn}" for asn in data["path"])
            summary.append(f"  **{collector}:** {path_str} (len={data['path_length']})")

        if len(by_collector) > 10:
            summary.append(f"  ... and {len(by_collector) - 10} more collectors")

        if not comparison["paths_consistent"]:
            summary.append("")
            summary.append("WARNING: Multiple origin ASNs detected. This could indicate:")
            summary.append("  - A BGP hijack")
            summary.append("  - MOAS (Multiple Origin AS) configuration")
            summary.append("  - Route leak or misconfiguration")

        return "\n".join(summary)

    except Exception as e:
        return f"Error comparing collectors for {prefix}: {e}"


@mcp.tool()
async def get_asn_details(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 15169 for Google)")],
) -> str:
    """Get detailed information about an Autonomous System.

    Provides comprehensive analysis including announced prefixes,
    upstream/downstream relationships, and routing behavior.
    Always reports IPv4 and IPv6 prefix counts separately.

    For security analysis, use check_prefix_anomalies on sample prefixes
    from BOTH IPv4 and IPv6 families, as RPKI deployment may differ.

    Data source: RIPE Stat.
    """
    try:
        client = await get_ripe_stat()
        prefixes = await client.get_announced_prefixes(asn)

        if not prefixes:
            return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

        # Get routes for a sample of prefixes to analyze relationships
        sample_prefixes = prefixes[:5]
        all_routes = []

        for prefix in sample_prefixes:
            try:
                routes = await client.get_bgp_state(prefix)
                all_routes.extend(routes)
            except Exception:
                pass

        # Analyze the ASN using collected routes
        analyzer = get_as_analyzer()
        asn_summary = analyzer.get_asn_summary(all_routes, asn)

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
            upstream_list = ", ".join(f"AS{u}" for u in sorted(asn_summary["upstream_asns"])[:10])
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
        summary.append(f"  - As origin (end of path): {asn_summary['as_origin_count']}")
        summary.append(f"  - As mid-path transit: {asn_summary['as_transit_count']}")

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting details for AS{asn}: {e}"


@mcp.tool()
async def check_prefix_anomalies(
    prefix: Annotated[
        str, Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24' or '2001:db8::/32')")
    ],
) -> str:
    """Check a prefix for potential hijack indicators.

    This tool provides on-demand anomaly detection by checking multiple
    indicators that may suggest a BGP hijack or misconfiguration.
    Works for both IPv4 and IPv6 prefixes.

    Checks performed:
    1. MOAS Detection: Multiple Origin AS announcing the same prefix
    2. RPKI Validation: Checks if the announcement is covered by a valid ROA
    3. Origin Change Detection: Looks for recent changes in the originating ASN
    4. Visibility Analysis: Checks how many collectors see the prefix

    Use this when investigating a suspected hijack or validating prefix ownership.
    When checking an ASN's security posture, check prefixes from BOTH IPv4 and IPv6.

    Data source: RIPE Stat.
    """
    try:
        client = await get_ripe_stat()
        indicators: dict[str, Any] = {}
        risk_factors: list[str] = []

        # Get current BGP state for MOAS and visibility
        routes = await client.get_bgp_state(prefix)

        if not routes:
            return (
                f"**Prefix Anomaly Check: {prefix}**\n\n"
                f"**Status:** Not routed\n\n"
                f"No routes found for this prefix. The prefix may not be announced, "
                f"or may not be visible from RIPE RIS collectors."
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
            "collectors": collectors[:10],
            "status": "normal" if len(collectors) >= 10 else "limited",
        }

        if len(collectors) < 5:
            risk_factors.append(f"Low visibility: Only {len(collectors)} collectors")

        # RPKI validation for each origin
        rpki_results = {}
        for origin in origin_asns:
            try:
                status = await client.get_rpki_validation(prefix, origin)
                rpki_results[origin] = status
                if status == "invalid":
                    risk_factors.append(f"RPKI Invalid: AS{origin} not authorized")
            except Exception:
                rpki_results[origin] = "error"

        indicators["rpki"] = rpki_results

        # Check routing history for recent origin changes
        now = datetime.now(UTC)
        week_ago = now - timedelta(days=7)

        try:
            history = await client.get_routing_history(prefix, week_ago, now)
            historical_origins: set[int] = set()
            for origin_data in history.get("by_origin", []):
                origin_str = origin_data.get("origin", "")
                if origin_str:
                    try:
                        historical_origins.add(int(origin_str))
                    except ValueError:
                        pass

            current_origins_set = set(origin_asns)
            new_origins = current_origins_set - historical_origins
            indicators["origin_history"] = {
                "current_origins": list(current_origins_set),
                "historical_origins": list(historical_origins),
                "new_origins": list(new_origins),
                "change_detected": bool(new_origins),
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
            f"**Risk Level:** {'HIGH' if risk_level == 'high' else 'MEDIUM' if risk_level == 'medium' else 'LOW'}",
            "",
        ]

        if indicators["moas"]["detected"]:
            summary.append("**MOAS Detected (Multiple Origin AS)**")
            summary.append(f"  Origins: {', '.join(f'AS{asn}' for asn in origin_asns)}")
        else:
            summary.append(f"**Single Origin:** AS{origin_asns[0]}")
        summary.append("")

        summary.append("**RPKI Validation:**")
        for origin, status in rpki_results.items():
            summary.append(f"  - AS{origin}: {status.upper()}")
        summary.append("")

        summary.append(f"**Visibility:** {len(collectors)} collectors")
        if indicators["visibility"]["status"] == "limited":
            summary.append("  Warning: Limited visibility may indicate filtering or recent change")
        summary.append("")

        if risk_factors:
            summary.append("**Risk Factors:**")
            for factor in risk_factors:
                summary.append(f"  - {factor}")
        else:
            summary.append("**No risk factors detected.** Prefix appears to be routing normally.")

        return "\n".join(summary)

    except Exception as e:
        return f"Error checking prefix anomalies for {prefix}: {e}"


# =============================================================================
# Monocle Tools (AS Relationships - requires monocle binary)
# =============================================================================


@mcp.tool()
async def get_as_peers(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 15169 for Google)")],
) -> str:
    """Get all peers for an Autonomous System.

    Returns the list of networks that peer with this AS, derived from
    observed BGP routing data across 1,700+ global peers.

    Data source: Monocle (BGPKIT AS relationship data).

    Requires the monocle binary to be installed.
    """
    monocle = await get_monocle()
    if monocle is None:
        return "Monocle is not configured. Install it with: cargo install monocle"

    try:
        peers = await monocle.get_as_peers(asn)

        if not peers:
            return f"No peer relationships found for AS{asn}."

        summary = [
            f"**AS{asn} Peers**",
            "",
            f"**Total peers:** {len(peers)}",
            "",
            "**Top peers (by visibility):**",
        ]

        sorted_peers = sorted(peers, key=lambda p: p.connected_pct, reverse=True)
        for peer in sorted_peers[:20]:
            name_str = f" ({peer.asn2_name})" if peer.asn2_name else ""
            summary.append(f"  - AS{peer.asn2}{name_str}: {peer.connected_pct:.1f}% visibility")

        if len(peers) > 20:
            summary.append(f"  ... and {len(peers) - 20} more peers")

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting peers for AS{asn}: {e}"


@mcp.tool()
async def get_as_upstreams(
    asn: Annotated[int, Field(description="Autonomous System Number")],
) -> str:
    """Get upstream transit providers for an AS.

    Returns the list of networks that provide transit to this AS,
    derived from observed BGP routing data.

    Data source: Monocle (BGPKIT AS relationship data).

    Requires the monocle binary to be installed.
    """
    monocle = await get_monocle()
    if monocle is None:
        return "Monocle is not configured. Install it with: cargo install monocle"

    try:
        upstreams = await monocle.get_as_upstreams(asn)

        if not upstreams:
            return f"No upstream providers found for AS{asn}. This AS may be a transit-free network (Tier 1)."

        summary = [
            f"**AS{asn} Upstream Providers**",
            "",
            f"**Total upstreams:** {len(upstreams)}",
            "",
        ]

        sorted_upstreams = sorted(upstreams, key=lambda u: u.connected_pct, reverse=True)
        for upstream in sorted_upstreams:
            name_str = f" ({upstream.asn2_name})" if upstream.asn2_name else ""
            summary.append(
                f"  - AS{upstream.asn2}{name_str}: {upstream.connected_pct:.1f}% visibility"
            )

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting upstreams for AS{asn}: {e}"


@mcp.tool()
async def get_as_downstreams(
    asn: Annotated[int, Field(description="Autonomous System Number")],
) -> str:
    """Get downstream customers of an AS.

    Returns the list of networks that buy transit from this AS,
    derived from observed BGP routing data.

    Data source: Monocle (BGPKIT AS relationship data).

    Requires the monocle binary to be installed.
    """
    monocle = await get_monocle()
    if monocle is None:
        return "Monocle is not configured. Install it with: cargo install monocle"

    try:
        downstreams = await monocle.get_as_downstreams(asn)

        if not downstreams:
            return f"No downstream customers found for AS{asn}. This AS may be a stub network."

        summary = [
            f"**AS{asn} Downstream Customers**",
            "",
            f"**Total downstreams:** {len(downstreams)}",
            "",
        ]

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
        return f"Error getting downstreams for AS{asn}: {e}"


@mcp.tool()
async def check_as_relationship(
    asn1: Annotated[int, Field(description="First Autonomous System Number")],
    asn2: Annotated[int, Field(description="Second Autonomous System Number")],
) -> str:
    """Check the relationship between two ASes.

    Determines if two ASes are peers, or if one is upstream of the other.
    Based on observed BGP routing data.

    Data source: Monocle (BGPKIT AS relationship data).

    Requires the monocle binary to be installed.
    """
    monocle = await get_monocle()
    if monocle is None:
        return "Monocle is not configured. Install it with: cargo install monocle"

    try:
        relationship = await monocle.check_relationship(asn1, asn2)

        if not relationship:
            return f"No direct relationship found between AS{asn1} and AS{asn2}."

        rel_type = relationship.relationship_type
        name_str = f" ({relationship.asn2_name})" if relationship.asn2_name else ""

        summary = [
            f"**Relationship: AS{asn1} <-> AS{asn2}{name_str}**",
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
        return f"Error checking relationship between AS{asn1} and AS{asn2}: {e}"


@mcp.tool()
async def get_as_connectivity_summary(
    asn: Annotated[int, Field(description="Autonomous System Number")],
) -> str:
    """Get a connectivity summary for an AS - USE THIS FOR PEER COUNTS.

    This is the primary tool for answering "how many peers/upstreams/downstreams"
    questions. Returns accurate counts from observed BGP data.

    Shows counts of upstreams, peers, and downstreams with top examples.
    Provides a comprehensive view of the AS's position in the Internet topology.

    Data source: Monocle (BGPKIT AS relationship data from 1,700+ global peers).

    Requires the monocle binary to be installed.
    """
    monocle = await get_monocle()
    if monocle is None:
        return "Monocle is not configured. Install it with: cargo install monocle"

    try:
        connectivity = await monocle.get_connectivity(asn)

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
        return f"Error getting connectivity summary for AS{asn}: {e}"


# =============================================================================
# Globalping Tools (Network probing)
# =============================================================================


@mcp.tool()
async def ping_from_global(
    target: Annotated[str, Field(description="IP address or hostname to ping")],
    locations: Annotated[
        list[str] | None,
        Field(
            description="List of locations to run probes from. Supports country codes (US, DE), "
            "continent codes (EU, NA), or region names (Europe). Default: diverse global selection.",
            default=None,
        ),
    ] = None,
) -> str:
    """Perform ping measurements from globally distributed probes.

    Uses the Globalping network to measure latency and reachability
    from multiple geographic locations.

    IMPORTANT: If the user specifies a location (e.g., "from the US",
    "from Germany"), you MUST pass the appropriate location filter.

    Location examples:
    - Country codes: "US", "DE", "FR", "GB", "JP", "AU", "BR", "SG"
    - Country names: "United States", "Germany", "France"
    - Continent codes: "EU", "NA", "AS", "OC", "SA", "AF"
    - Regions: "Europe", "North America", "Asia"

    Data source: Globalping API.
    """
    globalping = await get_globalping()
    if globalping is None:
        return "Globalping is not configured."

    try:
        result = await globalping.ping(target=target, locations=locations, limit=10)

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
        error_msg = str(e)
        if "No probes available" in error_msg:
            requested = ", ".join(locations) if locations else "default locations"
            return (
                f"**PROBE AVAILABILITY ERROR**\n\n"
                f"{error_msg}\n\n"
                f"Requested probes from: {requested}\n\n"
                f"Try a different location like Europe (DE, GB, FR), Asia (JP, SG), or use default global probes."
            )
        return f"Error performing global ping to {target}: {error_msg}"
    except Exception as e:
        return f"Error performing global ping to {target}: {e}"


@mcp.tool()
async def traceroute_from_global(
    target: Annotated[str, Field(description="IP address or hostname to trace")],
    locations: Annotated[
        list[str] | None,
        Field(
            description="List of locations to run probes from. Default: diverse global selection.",
            default=None,
        ),
    ] = None,
) -> str:
    """Perform traceroute measurements from globally distributed probes.

    Uses the Globalping network to trace the path to a target
    from multiple geographic locations.

    IMPORTANT: If the user specifies a location (e.g., "from the US",
    "from Germany"), you MUST pass the appropriate location filter.

    Location examples:
    - Country codes: "US", "DE", "FR", "GB", "JP", "AU", "BR", "SG"
    - Continent codes: "EU", "NA", "AS", "OC", "SA", "AF"

    Data source: Globalping API.
    """
    globalping = await get_globalping()
    if globalping is None:
        return "Globalping is not configured."

    try:
        result = await globalping.traceroute(target=target, locations=locations, limit=5)

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
                for i, hop in enumerate(probe_result.hops[:15], 1):
                    hop_num = hop.get("hop", i)
                    host = (
                        hop.get("resolvedHostname") or hop.get("resolvedAddress") or hop.get("host")
                    )
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
        error_msg = str(e)
        if "No probes available" in error_msg:
            requested = ", ".join(locations) if locations else "default locations"
            return (
                f"**PROBE AVAILABILITY ERROR**\n\n"
                f"{error_msg}\n\n"
                f"Requested probes from: {requested}\n\n"
                f"Try a different location like Europe (DE, GB, FR), Asia (JP, SG), or use default global probes."
            )
        return f"Error performing global traceroute to {target}: {error_msg}"
    except Exception as e:
        return f"Error performing global traceroute to {target}: {e}"


# =============================================================================
# PeeringDB Tools (IXP and network info)
# =============================================================================


@mcp.tool()
async def get_ixps_for_asn(
    asn: Annotated[int, Field(description="Autonomous System Number")],
) -> str:
    """Get all Internet Exchange Points where an ASN is present.

    Returns a list of IXPs where the specified network has a peering
    presence, including their location and connection speed.

    Data source: PeeringDB.
    """
    peeringdb = await get_peeringdb()
    if peeringdb is None:
        return "PeeringDB is not configured."

    try:
        presences = peeringdb.get_ixps_for_asn(asn)

        if not presences:
            return f"AS{asn} is not present at any IXPs in PeeringDB, or the ASN does not exist."

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
        return f"Error getting IXP presence for AS{asn}: {e}"


@mcp.tool()
async def get_networks_at_ixp(
    ixp: Annotated[str, Field(description="IXP name (e.g., 'AMS-IX', 'DE-CIX Frankfurt') or ID")],
) -> str:
    """Get all networks/ASNs present at an Internet Exchange Point.

    Returns a list of networks that have a peering presence at the
    specified IXP. Useful for identifying potential peering partners.

    Data source: PeeringDB.
    """
    peeringdb = await get_peeringdb()
    if peeringdb is None:
        return "PeeringDB is not configured."

    try:
        # Try to parse as int for ID, otherwise use as name
        try:
            ixp_id_or_name: int | str = int(ixp)
        except ValueError:
            ixp_id_or_name = ixp

        networks = peeringdb.get_networks_at_ixp(ixp_id_or_name)

        if not networks:
            return f"No networks found at IXP '{ixp}'. The IXP may not exist or have no participants."

        # Get IXP details for the header
        ixp_details = peeringdb.get_ixp_details(ixp_id_or_name)
        ixp_name = ixp_details.name if ixp_details else ixp

        summary = [
            f"**Networks at {ixp_name}**",
            "",
            f"**Total participants:** {len(networks)}",
            "",
            "**Networks (sample):**",
        ]

        for network in networks[:20]:
            type_str = f" ({network.info_type})" if network.info_type else ""
            summary.append(f"  - AS{network.asn}: {network.name}{type_str}")

        if len(networks) > 20:
            summary.append(f"  ... and {len(networks) - 20} more networks")

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting networks at IXP '{ixp}': {e}"


@mcp.tool()
async def get_ixp_details(
    ixp: Annotated[str, Field(description="IXP name (e.g., 'AMS-IX', 'DE-CIX Frankfurt') or ID")],
) -> str:
    """Get detailed information about an Internet Exchange Point.

    Returns comprehensive information about the IXP including location,
    participant count, and website.

    Data source: PeeringDB.
    """
    peeringdb = await get_peeringdb()
    if peeringdb is None:
        return "PeeringDB is not configured."

    try:
        # Try to parse as int for ID, otherwise use as name
        try:
            ixp_id_or_name: int | str = int(ixp)
        except ValueError:
            ixp_id_or_name = ixp

        ixp_info = peeringdb.get_ixp_details(ixp_id_or_name)

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
        return f"Error getting details for IXP '{ixp}': {e}"


@mcp.tool()
async def get_network_contacts(
    asn: Annotated[int, Field(description="Autonomous System Number")],
) -> str:
    """Get contact information for a network from PeeringDB.

    Returns publicly visible points of contact (NOC, Abuse, Technical, etc.)
    for incident coordination and peering requests.

    Use this tool when:
    - The user needs to report a security incident to a network
    - The user wants to coordinate with a network's NOC
    - The user is investigating an issue and needs to contact the operator
    - RPKI validation shows an invalid announcement - contact the NOC

    Data source: PeeringDB.
    """
    peeringdb = await get_peeringdb()
    if peeringdb is None:
        return "PeeringDB is not configured."

    try:
        network = peeringdb.get_network_info(asn)
        contacts = peeringdb.get_network_contacts(asn)

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
                    summary.append("")
                del by_role[role]

        for role, role_contacts in sorted(by_role.items()):
            summary.append(f"**{role}:**")
            for contact in role_contacts:
                if contact.name:
                    summary.append(f"  - Name: {contact.name}")
                if contact.email:
                    summary.append(f"  - Email: {contact.email}")
                summary.append("")

        if network.website:
            summary.append(f"**Website:** {network.website}")

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting contacts for AS{asn}: {e}"


# =============================================================================
# Resilience Assessment Tools
# =============================================================================


@mcp.tool()
async def assess_network_resilience(
    asn: Annotated[int, Field(description="Autonomous System Number to assess (e.g., 15169 for Google)")],
) -> str:
    """Assess network resilience and diversity for an Autonomous System.

    Produces a resilience score (1-10) plus detailed report with recommendations.
    Evaluates transit diversity, peering breadth, IXP presence, and path redundancy.

    Scoring Model:
    | Dimension        | Weight | Criteria                                    |
    |------------------|--------|---------------------------------------------|
    | Transit Diversity| 30%    | Upstream count (min 2 required, 3+ optimal) |
    | Peering Breadth  | 25%    | Total peer count (more = better DDoS absorb)|
    | IXP Presence     | 20%    | Number of IXPs (geographic diversity)       |
    | Path Redundancy  | 25%    | Distinct AS paths from collectors           |

    Score capped at 5 if:
    - Single transit provider (critical single point of failure)
    - Always-on DDoS protection provider detected in upstream path

    Use this tool to:
    - Assess a network's resilience to outages and DDoS attacks
    - Identify single points of failure in a network's connectivity
    - Get recommendations for improving network diversity
    - Evaluate potential peering partners or transit providers

    Requires: monocle binary and PeeringDB data.
    """
    monocle = await get_monocle()
    if monocle is None:
        return (
            "Monocle is not configured. Network resilience assessment requires "
            "Monocle for AS relationship data. Install with: cargo install monocle"
        )

    peeringdb = await get_peeringdb()
    if peeringdb is None:
        return (
            "PeeringDB is not configured. Network resilience assessment requires "
            "PeeringDB for IXP presence data."
        )

    try:
        assessor = get_resilience_assessor()

        # Gather data from monocle and peeringdb
        upstreams = await monocle.get_as_upstreams(asn)
        peers = await monocle.get_as_peers(asn)
        ixps = peeringdb.get_ixps_for_asn(asn)

        # Calculate component scores
        transit_score, transit_issues = assessor._score_transit(upstreams)
        peering_score, peer_count = assessor._score_peering(peers)
        ixp_score, ixp_names = assessor._score_ixp(ixps)

        # Use transit diversity as proxy for path redundancy
        path_redundancy_score = transit_score

        # Check for DDoS provider in upstreams
        ddos_provider = assessor._detect_ddos_provider(upstreams)

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
        final_score = assessor._calculate_final_score(scores, flags)

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
            recommendations=[],
            single_transit=single_transit,
            ddos_provider_detected=ddos_provider,
        )

        # Generate recommendations
        report.recommendations = assessor._generate_recommendations(report)

        # Format and return report
        return assessor.format_report(report)

    except Exception as e:
        return f"Error assessing network resilience for AS{asn}: {e}"


# =============================================================================
# Server Entry Point
# =============================================================================


def main():
    """Run the MCP server."""
    logger.info("Starting bgp-explorer MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
