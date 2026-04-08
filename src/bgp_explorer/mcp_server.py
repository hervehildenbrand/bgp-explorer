"""MCP server exposing BGP tools for Claude Code integration.

This module provides an MCP (Model Context Protocol) server that exposes
BGP Explorer's investigation tools. Users with Claude Code subscriptions
can use these tools without needing an API key.

Usage:
    # Install bgp-explorer globally (from the repo directory)
    cd /path/to/bgp-explorer
    uv tool install .

    # Add to Claude Code
    claude mcp add bgp-explorer -- bgp-explorer mcp

    # Verify it works
    claude mcp list

    # Then use Claude Code normally
    claude
"""

import ipaddress
import logging
import sys
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from bgp_explorer.analysis.as_analysis import ASAnalyzer
from bgp_explorer.analysis.aspa_validation import ASPAValidator, create_aspa_validator
from bgp_explorer.analysis.compliance import ComplianceAuditor
from bgp_explorer.analysis.manrs_conformance import MANRSReadinessAssessor
from bgp_explorer.analysis.path_analysis import PathAnalyzer
from bgp_explorer.analysis.resilience import ResilienceAssessor, ResilienceReport
from bgp_explorer.analysis.rov_coverage import ROVCoverageAnalyzer
from bgp_explorer.analysis.stability import StabilityAnalyzer
from bgp_explorer.sources.globalping import GlobalpingClient
from bgp_explorer.sources.manrs import MANRSClient
from bgp_explorer.sources.monocle import MonocleClient
from bgp_explorer.sources.peeringdb import PeeringDBClient
from bgp_explorer.sources.ripe_stat import RipeStatClient
from bgp_explorer.sources.rpki_console import RpkiConsoleClient

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
- For WHOIS/IRR data (route objects, aut-num, abuse contacts), use get_whois_data
- For route stability/flapping, use get_prefix_stability
- For ROV deployment coverage, use analyze_rov_coverage
- For ASPA status (published ASPA objects), use get_aspa_status
- For ROA guidance (missing ROAs, maxLength issues), use get_roa_guidance
- For ASPA guidance (recommended provider set), use get_aspa_guidance
- For combined ROV+ASPA per-route validation, use validate_prefix_routes
- For looking glass queries (vantage point routing), use query_looking_glass
- For MANRS readiness self-assessment (no API key needed), use check_manrs_readiness
- For official MANRS Observatory conformance data, use get_manrs_status
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
_aspa_validator: ASPAValidator | None = None
_stability_analyzer: StabilityAnalyzer | None = None
_rov_coverage_analyzer: ROVCoverageAnalyzer | None = None
_compliance_auditor: ComplianceAuditor | None = None
_rpki_console: RpkiConsoleClient | None = None
_manrs_assessor: MANRSReadinessAssessor | None = None
_manrs_client: MANRSClient | None = None


def get_stability_analyzer() -> StabilityAnalyzer:
    """Get or create StabilityAnalyzer."""
    global _stability_analyzer
    if _stability_analyzer is None:
        _stability_analyzer = StabilityAnalyzer()
    return _stability_analyzer


def get_rov_coverage_analyzer() -> ROVCoverageAnalyzer:
    """Get or create ROVCoverageAnalyzer."""
    global _rov_coverage_analyzer
    if _rov_coverage_analyzer is None:
        _rov_coverage_analyzer = ROVCoverageAnalyzer()
    return _rov_coverage_analyzer


def get_compliance_auditor() -> ComplianceAuditor:
    """Get or create ComplianceAuditor."""
    global _compliance_auditor
    if _compliance_auditor is None:
        _compliance_auditor = ComplianceAuditor()
    return _compliance_auditor


def get_manrs_assessor() -> MANRSReadinessAssessor:
    """Get or create MANRSReadinessAssessor."""
    global _manrs_assessor
    if _manrs_assessor is None:
        _manrs_assessor = MANRSReadinessAssessor()
    return _manrs_assessor


async def get_manrs_client() -> MANRSClient | None:
    """Get or create MANRSClient (lazy initialization)."""
    global _manrs_client
    if _manrs_client is None:
        _manrs_client = MANRSClient()
        if not _manrs_client.has_api_key():
            return None
        try:
            await _manrs_client.connect()
        except Exception:
            logger.warning("Failed to connect to MANRS Observatory API")
            return None
    return _manrs_client


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


async def get_rpki_console() -> RpkiConsoleClient | None:
    """Get or create RpkiConsoleClient (lazy initialization)."""
    global _rpki_console
    if _rpki_console is None:
        _rpki_console = RpkiConsoleClient()
        try:
            await _rpki_console.connect()
        except Exception:
            logger.warning("Failed to connect to rpki-client console")
            return None
    return _rpki_console


async def get_aspa_validator() -> ASPAValidator | None:
    """Get or create ASPAValidator (lazy initialization).

    Tries sources in priority order:
    1. rpki-client console (real ASPA objects) — confidence 1.0
    2. Monocle (fallback) — confidence 0.7
    """
    global _aspa_validator
    if _aspa_validator is None:
        rpki_console = await get_rpki_console()
        monocle = await get_monocle()
        _aspa_validator = create_aspa_validator(
            rpki_console=rpki_console,
            monocle=monocle,
        )
    return _aspa_validator


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
        if not query or not query.strip():
            return "Please provide a non-empty search query (e.g., 'Google', 'Cloudflare')."

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
        if "/" not in prefix:
            return (
                f"Invalid prefix format: '{prefix}'. "
                f"Please use CIDR notation (e.g., '8.8.8.0/24' or '2001:db8::/32')."
            )

        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        # Detect address family
        is_ipv6 = ":" in prefix
        family_str = "IPv6" if is_ipv6 else "IPv4"

        if not routes:
            msg = f"No routes found for {family_str} prefix {prefix}."
            msg += " The prefix may not be announced as an aggregate, or may not be visible from RIPE RIS collectors."
            if is_ipv6:
                msg += (
                    " For IPv6, many networks announce more-specific prefixes"
                    " (e.g., /48s) instead of the aggregate block."
                )
            msg += (
                " Try using get_asn_announcements to see what prefixes an ASN actually announces."
            )
            return msg

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
    full_list: Annotated[
        bool,
        Field(
            description="When True, return ALL prefixes without truncation. Use for audits.",
            default=False,
        ),
    ] = False,
) -> str:
    """Get prefixes announced by an AS, optionally filtered by address family.

    Returns a list of IP prefixes that are currently originated
    by the specified ASN. Always reports IPv4 and IPv6 counts separately,
    as many networks handle the two address families differently.

    Use address_family filter when the user specifically asks about one protocol
    (e.g., "show only IPv6 prefixes").

    Set full_list=True to return all prefixes without truncation (useful for audits).

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
            label = f"**{family_label} prefixes (filtered):**"
            summary.append(label)
            if full_list:
                for p in filtered_prefixes:
                    summary.append(f"  - {p}")
            else:
                for p in filtered_prefixes[:15]:
                    summary.append(f"  - {p}")
                if len(filtered_prefixes) > 15:
                    summary.append(f"  ... and {len(filtered_prefixes) - 15} more")
        else:
            # Default view - show both families
            if ipv4:
                summary.append("**IPv4 prefixes:**" if full_list else "**IPv4 prefixes (sample):**")
                if full_list:
                    for p in ipv4:
                        summary.append(f"  - {p}")
                else:
                    for p in ipv4[:10]:
                        summary.append(f"  - {p}")
                    if len(ipv4) > 10:
                        summary.append(f"  ... and {len(ipv4) - 10} more")
                summary.append("")

            if ipv6:
                summary.append("**IPv6 prefixes:**" if full_list else "**IPv6 prefixes (sample):**")
                if full_list:
                    for p in ipv6:
                        summary.append(f"  - {p}")
                else:
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
        start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
        end = datetime.fromisoformat(end_date).replace(tzinfo=UTC)

        if start > end:
            return f"Invalid date range: start_date ({start_date}) is after end_date ({end_date}). Please swap them."

        client = await get_ripe_stat()
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
    prefix: Annotated[str, Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24')")],
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
        start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
        end = datetime.fromisoformat(end_date).replace(tzinfo=UTC)

        if start > end:
            return f"Invalid date range: start_date ({start_date}) is after end_date ({end_date}). Please swap them."

        client = await get_ripe_stat()
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
                summary.append(
                    f"**Unique paths observed in changes:** {len(unique_paths_in_events)}"
                )
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
        detail = await client.get_rpki_validation_detail(prefix, origin_asn)
        status = detail["status"]

        status_label = {
            "valid": "VALID",
            "invalid": "INVALID",
            "not-found": "NOT FOUND",
            "unknown": "NOT FOUND",
        }.get(status, "UNKNOWN")

        summary = [
            "**RPKI Validation**",
            "",
            f"**Prefix:** {prefix}",
            f"**Origin:** AS{origin_asn}",
            f"**Status:** {status_label}",
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

        # Add ROA details if available
        roas = detail.get("validating_roas", [])
        if roas:
            summary.append("")
            summary.append("**ROA Details:**")
            prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 0
            for roa in roas:
                max_len = roa.get("max_length", prefix_len)
                summary.append(
                    f"  - ROA prefix: {roa.get('prefix', prefix)}, "
                    f"maxLength: /{max_len}, origin: AS{roa.get('origin', '?')}"
                )
                if max_len > prefix_len:
                    summary.append(
                        f"  - Sub-prefix exposure: prefixes up to /{max_len} can be announced"
                    )
                else:
                    summary.append("  - Sub-prefix exposure: NONE (maxLength matches announcement)")

        return "\n".join(summary)

    except Exception as e:
        return f"Error checking RPKI status: {e}"


@mcp.tool()
async def check_rpki_for_asn(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 15169 for Google)")],
) -> str:
    """Check RPKI validation status for ALL prefixes announced by an ASN.

    Bulk RPKI check: fetches all announced prefixes for the ASN, validates
    each against RPKI, and returns an aggregated summary with per-prefix
    breakdown showing ROA details for each prefix.

    Use this for network audits instead of checking prefixes one by one.

    Data source: RIPE Stat announced-prefixes + rpki-validation APIs.
    """
    import asyncio

    try:
        client = await get_ripe_stat()
        prefixes = await client.get_announced_prefixes(asn)

        if not prefixes:
            return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

        # Validate all prefixes with concurrency limit
        semaphore = asyncio.Semaphore(10)
        results: dict[str, list[dict]] = {"valid": [], "invalid": [], "not-found": []}

        async def check_one(prefix: str) -> None:
            async with semaphore:
                try:
                    detail = await client.get_rpki_validation_detail(prefix, asn)
                    status = detail["status"]
                    bucket = status if status in results else "not-found"
                    results[bucket].append(detail)
                except Exception:
                    results["not-found"].append(
                        {
                            "status": "not-found",
                            "prefix": prefix,
                            "origin_asn": asn,
                            "validating_roas": [],
                        }
                    )

        await asyncio.gather(*(check_one(p) for p in prefixes))

        summary = [
            f"**AS{asn} RPKI Validation Summary**",
            "",
            f"**Total prefixes checked:** {len(prefixes)}",
            f"  - VALID: {len(results['valid'])}",
            f"  - INVALID: {len(results['invalid'])}",
            f"  - NOT FOUND (no ROA): {len(results['not-found'])}",
            "",
        ]

        if results["valid"]:
            summary.append("**VALID prefixes:**")
            for detail in results["valid"]:
                roas = detail.get("validating_roas", [])
                if roas:
                    max_len = roas[0].get("max_length", "?")
                    summary.append(f"  - {detail['prefix']} (ROA maxLength: /{max_len})")
                else:
                    summary.append(f"  - {detail['prefix']}")
            summary.append("")

        if results["invalid"]:
            summary.append("**INVALID prefixes (potential hijack or misconfiguration):**")
            for detail in results["invalid"]:
                roas = detail.get("validating_roas", [])
                if roas:
                    roa_origin = roas[0].get("origin", "?")
                    summary.append(f"  - {detail['prefix']} (ROA origin: AS{roa_origin})")
                else:
                    summary.append(f"  - {detail['prefix']}")
            summary.append("")

        if results["not-found"]:
            summary.append("**NOT FOUND prefixes (no ROA):**")
            for detail in results["not-found"]:
                summary.append(f"  - {detail['prefix']}")
            summary.append("")

        coverage = len(results["valid"]) + len(results["invalid"])
        coverage_pct = (coverage / len(prefixes) * 100) if prefixes else 0
        summary.append(
            f"**RPKI coverage:** {coverage_pct:.1f}% ({coverage}/{len(prefixes)} prefixes have ROAs)"
        )

        # Add ASPA status
        try:
            rpki_console = await get_rpki_console()
            if rpki_console is not None:
                has_aspa = await rpki_console.has_aspa(asn)
                summary.append("")
                if has_aspa:
                    aspa_obj = await rpki_console.get_aspa_object(asn)
                    if aspa_obj:
                        providers_str = ", ".join(f"AS{p}" for p in sorted(aspa_obj.provider_asns))
                        summary.append(
                            f"**ASPA:** Published (authorized providers: {providers_str})"
                        )
                else:
                    summary.append("**ASPA:** Not published (no ASPA object found for this ASN)")
        except Exception:
            pass  # ASPA status is supplementary, don't fail the whole tool

        return "\n".join(summary)

    except Exception as e:
        return f"Error checking RPKI for AS{asn}: {e}"


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
            summary.append(
                f"**Observed Upstream ASNs (from sampled routes):** {len(asn_summary['upstream_asns'])}"
            )
            upstream_list = ", ".join(f"AS{u}" for u in sorted(asn_summary["upstream_asns"])[:10])
            summary.append(f"  {upstream_list}")
            summary.append(
                "  Note: These are ASNs seen before this AS in paths, not necessarily transit providers."
                " Use get_as_upstreams for authoritative relationship data."
            )
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

        # ASPA validation on unique AS paths (if available)
        aspa_indicators = {"checked": 0, "valid": 0, "invalid": 0, "unknown": 0}
        validator = await get_aspa_validator()
        if validator:
            try:
                seen_paths: set[tuple[int, ...]] = set()
                has_non_tier1_invalid = False
                for route in routes:
                    if route.as_path:
                        path_tuple = tuple(route.as_path)
                        if path_tuple not in seen_paths and len(seen_paths) < 5:
                            seen_paths.add(path_tuple)
                            aspa_result = await validator.validate_path(list(path_tuple))
                            aspa_indicators["checked"] += 1
                            aspa_indicators[aspa_result.state.value] += 1
                            if aspa_result.state.value == "invalid":
                                # Check if invalidity involves only Tier-1 peering hops
                                tier1_only = all(
                                    h.asn in ASPAValidator.TIER1_ASNS
                                    and h.next_asn in ASPAValidator.TIER1_ASNS
                                    for h in aspa_result.hop_results
                                    if h.relationship_type == "peer-or-lateral"
                                )
                                if not tier1_only:
                                    has_non_tier1_invalid = True
                if has_non_tier1_invalid:
                    risk_factors.append("ASPA Invalid: route leak detected in AS path")
                if aspa_indicators["invalid"] > 0 and not has_non_tier1_invalid:
                    aspa_indicators["note"] = (
                        "ASPA invalid results involve Tier-1 peering hops which are expected"
                    )
            except Exception:
                pass

        indicators["aspa"] = aspa_indicators

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

        # ASPA section
        aspa = indicators["aspa"]
        if aspa["checked"] > 0:
            summary.append(
                f"**ASPA Path Validation:** {aspa['checked']} paths checked "
                f"({aspa['valid']} valid, {aspa['invalid']} invalid, "
                f"{aspa['unknown']} unknown)"
            )
            if aspa["invalid"] > 0:
                summary.append("  Warning: ASPA violations detected - possible route leak")
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
            # Check if ASN has any relationships at all to distinguish
            # real transit-free networks from non-existent ASNs
            all_rels = await monocle.get_as_relationships(asn)
            if not all_rels:
                return (
                    f"No data found for AS{asn}. "
                    f"This ASN may not exist or may have no visible routes in global BGP data."
                )

            # Fallback: use connectivity data which has its own classification
            try:
                connectivity = await monocle.get_connectivity(asn)
                if connectivity.upstreams and len(connectivity.upstreams) > 0:
                    summary = [
                        f"**AS{asn} Upstream Providers** (from connectivity data)",
                        "",
                        f"**Total upstreams:** {len(connectivity.upstreams)}",
                        "",
                    ]
                    for upstream in connectivity.upstreams:
                        name_str = f" {upstream.name}" if upstream.name else ""
                        summary.append(
                            f"  - AS{upstream.asn}{name_str} ({upstream.peers_percent:.1f}% visibility)"
                        )
                    summary.append("")
                    summary.append(
                        "_Note: Data from connectivity analysis (relationship classification may differ from as2rel)._"
                    )
                    return "\n".join(summary)
            except Exception:
                pass

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
        peer_count = len(connectivity.peers)
        if peer_count > 5:
            summary.append(f"**Peers:** {peer_count} (showing top 5)")
        else:
            summary.append(f"**Peers:** {peer_count}")
        for peer in connectivity.peers[:5]:
            name_str = f" {peer.name}" if peer.name else ""
            summary.append(f"  - AS{peer.asn}{name_str} ({peer.peers_percent:.1f}% visibility)")
        if peer_count > 5:
            summary.append(f"  ... and {peer_count - 5} more")
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

# RFC 5737 documentation prefixes and other non-routable ranges
_BOGON_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
]


def _check_bogon_target(target: str) -> str | None:
    """Check if a target IP is in a bogon/documentation range.

    Returns a user-friendly error message if bogon, None otherwise.
    """
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return None  # Hostname, not an IP — let Globalping handle it

    for network in _BOGON_NETWORKS:
        if addr in network:
            return (
                f"Target {target} is in a documentation/test range ({network}, RFC 5737) "
                f"and cannot be probed. These addresses are not routable on the public Internet."
            )

    return None


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
    bogon_msg = _check_bogon_target(target)
    if bogon_msg:
        return bogon_msg

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
    bogon_msg = _check_bogon_target(target)
    if bogon_msg:
        return bogon_msg

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
            return (
                f"No networks found at IXP '{ixp}'. The IXP may not exist or have no participants."
            )

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
    except RuntimeError as e:
        return f"Error retrieving PeeringDB data for AS{asn}: {e}"
    except Exception as e:
        return f"Error retrieving PeeringDB data for AS{asn}: {e}"

    try:
        if not network:
            return f"AS{asn} not found in PeeringDB. The ASN may not be registered or may not participate in PeeringDB."

        summary = [
            f"**AS{asn} Contact Information**",
            f"**Network:** {network.name}",
            "",
        ]

        if not contacts:
            summary.append(f"No public contact information published for AS{asn} in PeeringDB.")
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
    asn: Annotated[
        int, Field(description="Autonomous System Number to assess (e.g., 15169 for Google)")
    ],
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
        # Get peer/downstream counts first for Tier 1 detection in transit scoring
        peering_score, peer_count = assessor._score_peering(peers)
        downstreams = await monocle.get_as_downstreams(asn)
        transit_score, transit_issues = assessor._score_transit(
            upstreams, peer_count=peer_count, downstream_count=len(downstreams)
        )
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
# ASPA Validation Tools
# =============================================================================


@mcp.tool()
async def verify_aspa_path(
    as_path: Annotated[
        str,
        Field(
            description="Comma-separated AS path to validate (e.g., '13335,174,15169'). "
            "Order: origin AS first, collector-side AS last."
        ),
    ],
) -> str:
    """Verify ASPA (AS Provider Authorization) for a BGP AS path.

    Checks whether each hop in the path represents an authorized
    customer-provider relationship, and whether the path follows
    valley-free routing (no route leaks).

    This complements RPKI ROA validation: ROA checks origin authorization,
    ASPA checks path authorization (route leak detection).

    Data sources (in priority order):
    1. Real RPKI ASPA objects from rpki-client console (cryptographically signed)
    2. CAIDA AS Relationships (inferred, updated monthly)
    3. Monocle AS relationship data (inferred, on-demand fallback)
    """
    validator = await get_aspa_validator()
    if validator is None:
        return (
            "ASPA validation requires at least one data source. "
            "The rpki-client console may be unreachable, and Monocle is not installed. "
            "Install Monocle with: cargo install monocle"
        )

    try:
        asns = []
        for part in as_path.split(","):
            part = part.strip()
            if part:
                asns.append(int(part))

        if not asns:
            return "Please provide a valid AS path (e.g., '13335,174,15169')."

        result = await validator.validate_path(asns)

        path_str = " -> ".join(f"AS{asn}" for asn in result.as_path)
        state_label = {
            "valid": "VALID",
            "invalid": "INVALID",
            "unknown": "UNKNOWN",
            "unverifiable": "UNVERIFIABLE",
        }.get(result.state.value, "ERROR")

        summary = [
            f"**ASPA Path Verification: {path_str}**",
            "",
            f"**State:** {state_label}",
            f"**Valley-free:** {'Yes' if result.valley_free else 'No (possible route leak)'}",
            "",
        ]

        if result.hop_results:
            summary.append("**Per-hop analysis:**")
            for hop in result.hop_results:
                auth_str = {
                    True: "authorized",
                    False: "not authorized",
                    None: "unknown",
                }[hop.is_authorized_provider]
                # Show data source tag
                source_tag = {
                    "rpki-aspa": "[RPKI-ASPA]",
                    "caida": "[inferred/CAIDA]",
                    "monocle": "[inferred/monocle]",
                }.get(hop.data_source, f"[{hop.data_source}]")
                summary.append(
                    f"  - AS{hop.asn} -> AS{hop.next_asn}: "
                    f"{auth_str} ({hop.relationship_type}) "
                    f"{source_tag} confidence={hop.confidence:.0%}"
                )
            summary.append("")

        if result.issues:
            summary.append("**Issues:**")
            for issue in result.issues:
                summary.append(f"  - {issue}")
        else:
            summary.append("**No issues detected.** Path authorization looks good.")

        # Check if any hop used real ASPA data
        has_real_aspa = any(h.data_source == "rpki-aspa" for h in result.hop_results)
        if not has_real_aspa and result.hop_results:
            summary.append("")
            summary.append(
                "**Note:** No real RPKI ASPA objects found for ASes in this path. "
                "Results based on inferred relationships. ~0.5% of ASes have "
                "published ASPA objects as of early 2026."
            )

        return "\n".join(summary)

    except ValueError:
        return "Invalid AS path format. Use comma-separated ASNs (e.g., '13335,174,15169')."
    except Exception as e:
        return f"Error verifying ASPA path: {e}"


@mcp.tool()
async def get_whois_data(
    resource: Annotated[
        str,
        Field(description="ASN (e.g., 'AS15169') or IP prefix (e.g., '193.0.0.0/21') to look up"),
    ],
) -> str:
    """Get WHOIS and IRR data for an ASN or IP prefix.

    Returns registration details, IRR route objects, and abuse contacts.
    Use this to verify route objects, check aut-num policies, or find abuse contacts.

    Data source: RIPE Stat WHOIS API.
    """
    if not resource or not resource.strip():
        return "Please provide a non-empty resource (ASN like 'AS15169' or prefix like '193.0.0.0/21')."

    try:
        client = await get_ripe_stat()
        data = await client.get_whois_data(resource.strip())

        records = data.get("records", [])
        irr_records = data.get("irr_records", [])
        authorities = data.get("authorities", [])

        summary = [f"**WHOIS Data for {resource.strip()}**", ""]

        if authorities:
            summary.append(f"**Registry:** {', '.join(a.upper() for a in authorities)}")
            summary.append("")

        # Parse registration records
        if records:
            summary.append("**Registration:**")
            for record_group in records:
                for entry in record_group:
                    key = entry.get("key", "")
                    value = entry.get("value", "")
                    if key and value:
                        summary.append(f"  - {key}: {value}")
            summary.append("")

        # Parse IRR records
        if irr_records:
            summary.append(f"**IRR Route Objects ({len(irr_records)}):**")
            for i, record_group in enumerate(irr_records, 1):
                parts = []
                for entry in record_group:
                    key = entry.get("key", "")
                    value = entry.get("value", "")
                    if key and value:
                        parts.append(f"{key}: {value}")
                if parts:
                    summary.append(f"  {i}. {' | '.join(parts)}")
        else:
            summary.append("**IRR Records:** No IRR route objects found")

        return "\n".join(summary)

    except Exception as e:
        return f"Error getting WHOIS data: {e}"


# =============================================================================
# Looking Glass, Stability, and ROV Coverage Tools
# =============================================================================


@mcp.tool()
async def query_looking_glass(
    prefix: Annotated[
        str,
        Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24')"),
    ],
    vantage_point: Annotated[
        str | None,
        Field(description="Optional RRC collector filter (e.g., 'rrc00' or 'rrc00,rrc01')"),
    ] = None,
) -> str:
    """Query BGP tables from specific RIPE RIS vantage points.

    Shows how a prefix is seen from RIPE RIS collectors — the AS paths,
    communities, and peer details for each collector seeing the prefix.

    Use this to see how a prefix is routed from different parts of the Internet,
    compare routing across collectors, or debug routing differences.

    Data source: RIPE Stat Looking Glass API.
    """
    try:
        client = await get_ripe_stat()
        data = await client.get_looking_glass(prefix, collector=vantage_point)

        rrcs = data.get("rrcs", [])
        if not rrcs:
            return f"No looking glass data found for {prefix}."

        summary = [f"**Looking Glass: {prefix}**", ""]

        for rrc in rrcs:
            rrc_name = rrc.get("rrc", "unknown")
            location = rrc.get("location", "")
            peers = rrc.get("peers", [])

            header = f"**{rrc_name}**"
            if location:
                header += f" ({location})"
            header += f" — {len(peers)} peers"
            summary.append(header)

            for peer in peers[:5]:
                asn = peer.get("asn_origin", peer.get("asn", ""))
                as_path = peer.get("as_path", "")
                community = peer.get("community", "")
                line = f"  - AS{asn}"
                if as_path:
                    line += f" | path: {as_path}"
                if community:
                    line += f" | comm: {community}"
                summary.append(line)

            if len(peers) > 5:
                summary.append(f"  ... and {len(peers) - 5} more peers")
            summary.append("")

        return "\n".join(summary)

    except Exception as e:
        return f"Error querying looking glass for {prefix}: {e}"


@mcp.tool()
async def get_prefix_stability(
    prefix: Annotated[
        str,
        Field(description="IP prefix in CIDR notation (e.g., '1.1.1.0/24')"),
    ],
    start_date: Annotated[
        str,
        Field(description="Start date in YYYY-MM-DD format (e.g., '2025-01-01')"),
    ],
    end_date: Annotated[
        str,
        Field(description="End date in YYYY-MM-DD format (e.g., '2025-01-31')"),
    ],
) -> str:
    """Analyze BGP stability for a prefix over a time period.

    Shows update frequency, flap detection, withdrawal ratio, and a stability
    score (0-10). Use this to identify unstable prefixes experiencing routing issues.

    Score: 10 = perfectly stable, 0 = highly unstable.
    Status: STABLE (<10 updates/day), FLAPPING (>100 updates/day or >10 flaps).

    Data source: RIPE Stat BGP Update Activity + BGP Updates APIs.
    """
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=UTC)
        end = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=UTC)

        client = await get_ripe_stat()
        analyzer = get_stability_analyzer()

        activity_data = await client.get_bgp_update_activity(prefix, start, end)

        flap_count = 0
        try:
            updates_data = await client.get_bgp_updates(prefix, start, end)
            flaps = analyzer.detect_flaps(updates_data)
            flap_count = len(flaps)
        except Exception:
            pass

        report = analyzer.analyze_update_activity(prefix, activity_data, flap_count=flap_count)

        if report.stability_score >= 8:
            score_label = "Excellent"
        elif report.stability_score >= 6:
            score_label = "Good"
        elif report.stability_score >= 4:
            score_label = "Fair"
        else:
            score_label = "Poor"

        summary = [
            f"**BGP Stability Report: {prefix}**",
            f"**Period:** {report.period_start} to {report.period_end}",
            "",
            f"**Stability Score:** {report.stability_score:.1f}/10 ({score_label})",
            "",
            f"**Updates:** {report.total_updates:,} total "
            f"({report.announcements:,} announcements, "
            f"{report.withdrawals:,} withdrawals)",
            f"**Updates/Day:** {report.updates_per_day:.1f} total, "
            f"{report.withdrawals_per_day:.1f} withdrawals",
            f"**Withdrawal Ratio:** {report.withdrawal_ratio:.1%}",
            f"**Flaps Detected (W→A):** {report.flap_count}",
            "",
        ]

        if report.is_flapping:
            summary.append(
                "**Status: FLAPPING** — This prefix is experiencing significant route instability."
            )
        elif report.is_stable:
            summary.append("**Status: STABLE** — This prefix has minimal route changes.")
        else:
            summary.append(
                "**Status: MODERATE** — Some route activity detected, but within normal range."
            )

        return "\n".join(summary)

    except ValueError:
        return "Invalid date format. Use YYYY-MM-DD (e.g., '2025-01-01')."
    except Exception as e:
        return f"Error analyzing stability for {prefix}: {e}"


@mcp.tool()
async def get_bgp_update_activity(
    resource: Annotated[
        str,
        Field(description="IP prefix or ASN (e.g., '8.8.8.0/24' or 'AS15169')"),
    ],
    start_date: Annotated[
        str,
        Field(description="Start date in YYYY-MM-DD format"),
    ],
    end_date: Annotated[
        str,
        Field(description="End date in YYYY-MM-DD format"),
    ],
    sampling_hours: Annotated[
        int,
        Field(description="Bucket size in hours (default 1)"),
    ] = 1,
) -> str:
    """Get raw BGP update activity time series for a resource.

    Returns time-bucketed announcement and withdrawal counts. Use this for
    understanding update patterns over time.

    Data source: RIPE Stat BGP Update Activity API.
    """
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=UTC)
        end = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=UTC)

        client = await get_ripe_stat()
        data = await client.get_bgp_update_activity(
            resource,
            start,
            end,
            min_sampling_period=sampling_hours * 3600,
        )

        activity = data.get("updates", [])
        if not activity:
            return f"No update activity found for {resource} in the specified period."

        summary = [
            f"**BGP Update Activity: {resource}**",
            f"**Period:** {start_date} to {end_date}",
            f"**Bucket size:** {sampling_hours}h",
            "",
        ]

        total_a = 0
        total_w = 0
        for bucket in activity:
            a = bucket.get("announcements", 0)
            w = bucket.get("withdrawals", 0)
            total_a += a
            total_w += w
            ts = bucket.get("starttime", "")
            if a > 0 or w > 0:
                summary.append(f"  {ts}: {a} announcements, {w} withdrawals")

        summary.append("")
        summary.append(
            f"**Totals:** {total_a} announcements, {total_w} withdrawals "
            f"({total_a + total_w} total)"
        )

        return "\n".join(summary)

    except ValueError:
        return "Invalid date format. Use YYYY-MM-DD (e.g., '2025-01-01')."
    except Exception as e:
        return f"Error getting update activity for {resource}: {e}"


@mcp.tool()
async def analyze_rov_coverage(
    prefix: Annotated[
        str,
        Field(description="IP prefix in CIDR notation (e.g., '185.199.108.0/22')"),
    ],
) -> str:
    """Analyze RPKI ROV deployment coverage for a prefix.

    Estimates what percentage of Internet paths to a prefix traverse networks
    that enforce ROV (Route Origin Validation). Higher coverage means better
    protection against BGP hijacks with RPKI-invalid origins.

    Also checks ASPA deployment status of the origin ASN and computes
    a combined ASPA+ROV protection score.

    Protection levels:
    - HIGH: >=80% path coverage AND >=60% Tier-1 coverage
    - MEDIUM: >=50% path coverage
    - LOW: <50% path coverage

    Combined protection:
    - FULL: ROA valid + ASPA published + HIGH ROV coverage
    - PARTIAL: ROA valid + (ASPA or medium/high ROV)
    - MINIMAL: Missing ROA or low coverage

    Data source: RIPE Stat BGP State + ROV enforcer database + rpki-client console.
    """
    try:
        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        if not routes:
            return f"No routes found for {prefix}. Cannot analyze ROV coverage."

        analyzer = get_rov_coverage_analyzer()
        report = analyzer.analyze_prefix_coverage(prefix, routes)

        summary = [
            f"**ROV Coverage Analysis: {prefix}**",
            "",
            f"**Protection Level:** {report.protection_level.upper()}",
            f"**Path Coverage:** {report.path_coverage:.0%} "
            f"({report.paths_with_rov_enforcer}/{report.total_paths} paths)",
            f"**Tier-1 Coverage:** {report.tier1_coverage:.0%}",
            "",
            report.summary,
            "",
        ]

        if report.rov_enforcers_in_paths:
            summary.append("**ROV Enforcers in Paths:**")
            for enforcer in report.rov_enforcers_in_paths[:10]:
                cat = enforcer["category"].upper()
                summary.append(
                    f"  - AS{enforcer['asn']} ({enforcer['name']}) "
                    f"[{cat}] — in {enforcer['path_count']} paths"
                )
            if len(report.rov_enforcers_in_paths) > 10:
                summary.append(f"  ... and {len(report.rov_enforcers_in_paths) - 10} more")

        # Add ASPA + ROA + combined analysis from rpki-client console
        try:
            rpki_console = await get_rpki_console()
            if rpki_console is not None:
                # Get origin ASN from routes
                origin_asn = routes[0].origin_asn if routes else None
                has_roa = False
                has_aspa = False

                if origin_asn:
                    # Check ASPA status
                    has_aspa = await rpki_console.has_aspa(origin_asn)
                    # Check ROA from rpki-client dump
                    roas = await rpki_console.get_roas_for_prefix(prefix)
                    roa_analysis = analyzer.analyze_roa_for_prefix(prefix, roas, origin_asn)
                    has_roa = roa_analysis.has_roa and roa_analysis.rpki_status == "valid"

                    summary.append("")
                    summary.append(f"**Origin AS{origin_asn} RPKI Status:**")
                    if roa_analysis.has_roa:
                        ml_status = (
                            "OK"
                            if roa_analysis.max_length_ok
                            else f"WARN: maxLength /{roa_analysis.max_length} > /{roa_analysis.prefix_length}"
                        )
                        summary.append(
                            f"  - ROA: {roa_analysis.rpki_status.upper()} (maxLength: {ml_status})"
                        )
                    else:
                        summary.append("  - ROA: NOT FOUND (no ROA for this prefix)")

                    if has_aspa:
                        aspa_obj = await rpki_console.get_aspa_object(origin_asn)
                        if aspa_obj:
                            providers_str = ", ".join(
                                f"AS{p}" for p in sorted(aspa_obj.provider_asns)
                            )
                            summary.append(f"  - ASPA: PUBLISHED (providers: {providers_str})")
                    else:
                        summary.append("  - ASPA: NOT PUBLISHED")

                    # Combined score
                    combined = analyzer.compute_combined_protection(
                        report.protection_level, has_roa, has_aspa
                    )
                    summary.append(f"  - **Combined Protection: {combined.upper()}**")
        except Exception:
            pass  # ASPA/ROA enrichment is supplementary

        return "\n".join(summary)

    except Exception as e:
        return f"Error analyzing ROV coverage for {prefix}: {e}"


# =============================================================================
# Compliance Auditing
# =============================================================================


@mcp.tool()
async def run_compliance_audit(
    asn: Annotated[
        int, Field(description="Autonomous System Number to audit (e.g., 15169 for Google)")
    ],
    framework: Annotated[
        str,
        Field(
            description="Compliance framework: 'dora', 'nis2', 'manrs', or 'both' (default: 'both'). 'both' = DORA+NIS2."
        ),
    ] = "both",
    output_format: Annotated[
        str,
        Field(description="Output format: 'text' or 'json' (default: 'text')"),
    ] = "text",
) -> str:
    """Run a DORA, NIS 2, or MANRS compliance audit on a network's BGP routing.

    Maps BGP analysis results to regulatory/industry requirements:
    - DORA (2022/2554): ICT risk management for financial entities
    - NIS 2 (2022/2555): Cybersecurity for critical infrastructure operators
    - MANRS: Mutually Agreed Norms for Routing Security (4 Actions)

    Checks include:
    - Transit concentration risk (single point of failure)
    - Network resilience scoring
    - RPKI/ROV deployment coverage
    - Route stability and flapping
    - Third-party provider concentration
    - Business continuity (geographic diversity via IXPs)
    - Incident detection capability

    Scoring: 0-100, where >=80 is COMPLIANT, >=50 is PARTIAL, <50 is NON_COMPLIANT.

    Requires: monocle binary and PeeringDB data for DORA/NIS2 (same as assess_network_resilience).
    MANRS audits do not require monocle.
    """
    try:
        fw = framework.lower()

        # MANRS doesn't require monocle — handle separately
        if fw == "manrs":
            auditor = get_compliance_auditor()
            client = await get_ripe_stat()

            # Gather prefixes
            prefixes = []
            try:
                prefixes = await client.get_announced_prefixes(asn)
            except Exception:
                logger.debug("Could not fetch prefixes for AS%d", asn)

            # RPKI coverage
            rpki_coverage = None
            try:
                if prefixes:
                    valid_count = 0
                    checked = 0
                    # Limit to 20 prefixes to avoid timeout on large ASNs
                    for prefix in prefixes[:20]:
                        try:
                            status = await client.get_rpki_validation(prefix, asn)
                            checked += 1
                            if status == "valid":
                                valid_count += 1
                        except Exception:
                            pass
                    if checked > 0:
                        rpki_coverage = valid_count / checked
            except Exception:
                logger.debug("Could not fetch RPKI data for AS%d", asn)

            # ASPA status
            has_aspa = None
            try:
                rpki_console = await get_rpki_console()
                if rpki_console is not None:
                    has_aspa = await rpki_console.has_aspa(asn)
            except Exception:
                logger.debug("Could not check ASPA for AS%d", asn)

            # ROV coverage
            rov_report = None
            try:
                if prefixes:
                    routes = await client.get_bgp_state(prefixes[0])
                    if routes:
                        rov_analyzer = get_rov_coverage_analyzer()
                        rov_report = rov_analyzer.analyze_prefix_coverage(prefixes[0], routes)
            except Exception:
                logger.debug("Could not fetch ROV data for AS%d", asn)

            # Contacts from PeeringDB
            contacts = None
            try:
                peeringdb = await get_peeringdb()
                if peeringdb is not None:
                    net = peeringdb.get_network_by_asn(asn)
                    if net:
                        contacts = net
            except Exception:
                logger.debug("Could not fetch contacts for AS%d", asn)

            # WHOIS data from RIPE Stat
            whois_data = None
            try:
                whois_data = await client.get_whois(str(asn))
            except Exception:
                logger.debug("Could not fetch WHOIS data for AS%d", asn)

            report = auditor.audit_manrs(
                asn=asn,
                rpki_coverage=rpki_coverage,
                has_aspa=has_aspa,
                rov_report=rov_report,
                contacts=contacts,
                whois_data=whois_data,
            )
            if output_format == "json":
                import json

                return json.dumps(report.to_dict(), indent=2)
            return auditor.format_report(report)

        # DORA/NIS2/both require monocle
        monocle = await get_monocle()
        if monocle is None:
            return (
                "Monocle is not configured. Compliance audit requires "
                "Monocle for AS relationship data. Install with: cargo install monocle"
            )

        peeringdb = await get_peeringdb()
        if peeringdb is None:
            return (
                "PeeringDB is not configured. Compliance audit requires "
                "PeeringDB for IXP presence data."
            )
        # --- Gather resilience data (required) ---
        assessor = get_resilience_assessor()

        upstreams = await monocle.get_as_upstreams(asn)
        peers = await monocle.get_as_peers(asn)
        downstreams = await monocle.get_as_downstreams(asn)
        ixps = peeringdb.get_ixps_for_asn(asn)

        peering_score, peer_count = assessor._score_peering(peers)
        transit_score, transit_issues = assessor._score_transit(
            upstreams, peer_count=peer_count, downstream_count=len(downstreams)
        )
        ixp_score, ixp_names = assessor._score_ixp(ixps)
        path_redundancy_score = transit_score
        ddos_provider = assessor._detect_ddos_provider(upstreams)
        single_transit = len(upstreams) == 1

        scores = {
            "transit": transit_score,
            "peering": peering_score,
            "ixp": ixp_score,
            "path_redundancy": path_redundancy_score,
        }
        flags = {"single_transit": single_transit, "ddos_provider": ddos_provider}
        final_score = assessor._calculate_final_score(scores, flags)

        upstream_names = []
        for u in upstreams[:10]:
            name = f"AS{u.asn2}"
            if u.asn2_name:
                name += f" ({u.asn2_name})"
            upstream_names.append(name)

        resilience_report = ResilienceReport(
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

        # --- Fetch announced prefixes (used by stability, RPKI, and ROV) ---
        prefixes = []
        try:
            client = await get_ripe_stat()
            prefixes = await client.get_announced_prefixes(asn)
        except Exception:
            logger.debug("Could not fetch prefixes for AS%d", asn)

        # --- Gather stability data (optional, per-prefix) ---
        stability_report = None
        try:
            if prefixes:
                client = await get_ripe_stat()
                now = datetime.now(UTC)
                start = now - timedelta(days=7)
                first_prefix = prefixes[0]
                activity_data = await client.get_bgp_update_activity(first_prefix, start, now)
                analyzer = get_stability_analyzer()
                stability_report = analyzer.analyze_update_activity(first_prefix, activity_data)
        except Exception:
            logger.debug("Could not fetch stability data for AS%d", asn)

        # --- Gather RPKI coverage (optional) ---
        rpki_coverage = None
        try:
            if prefixes:
                client = await get_ripe_stat()
                valid_count = 0
                checked = 0
                for prefix in prefixes:
                    try:
                        status = await client.get_rpki_validation(prefix, asn)
                        checked += 1
                        if status == "valid":
                            valid_count += 1
                    except Exception:
                        pass
                if checked > 0:
                    rpki_coverage = valid_count / checked
        except Exception:
            logger.debug("Could not fetch RPKI data for AS%d", asn)

        # --- Gather ROV data (optional) ---
        rov_report = None
        try:
            if prefixes:
                client = await get_ripe_stat()
                first_prefix = prefixes[0]
                routes = await client.get_bgp_state(first_prefix)
                if routes:
                    rov_analyzer = get_rov_coverage_analyzer()
                    rov_report = rov_analyzer.analyze_prefix_coverage(first_prefix, routes)
        except Exception:
            logger.debug("Could not fetch ROV data for AS%d", asn)

        # --- Check ASPA status (optional) ---
        has_aspa: bool | None = None
        try:
            rpki_console = await get_rpki_console()
            if rpki_console is not None:
                has_aspa = await rpki_console.has_aspa(asn)
        except Exception:
            logger.debug("Could not check ASPA status for AS%d", asn)

        # --- Run audit ---
        auditor = get_compliance_auditor()

        if fw == "dora":
            report = auditor.audit_dora(
                asn,
                resilience_report,
                stability_report,
                rov_report,
                rpki_coverage=rpki_coverage,
                has_aspa=has_aspa,
            )
            if output_format == "json":
                import json

                return json.dumps(report.to_dict(), indent=2)
            return auditor.format_report(report)

        elif fw == "nis2":
            report = auditor.audit_nis2(
                asn,
                resilience_report,
                stability_report,
                rov_report,
                rpki_coverage=rpki_coverage,
                has_aspa=has_aspa,
            )
            if output_format == "json":
                import json

                return json.dumps(report.to_dict(), indent=2)
            return auditor.format_report(report)

        else:  # "both"
            dora_report, nis2_report = auditor.audit_both(
                asn,
                resilience_report,
                stability_report,
                rov_report,
                rpki_coverage=rpki_coverage,
                has_aspa=has_aspa,
            )
            if output_format == "json":
                import json

                return json.dumps(
                    {
                        "dora": dora_report.to_dict(),
                        "nis2": nis2_report.to_dict(),
                    },
                    indent=2,
                )
            return (
                auditor.format_report(dora_report)
                + "\n\n---\n\n"
                + auditor.format_report(nis2_report)
            )

    except Exception as e:
        return f"Error running compliance audit for AS{asn}: {e}"


# =============================================================================
# RPKI ASPA Tools
# =============================================================================


@mcp.tool()
async def get_aspa_status(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 13335 for Cloudflare)")],
) -> str:
    """Check if an ASN has published ASPA (AS Provider Authorization) objects.

    ASPA objects are cryptographically signed RPKI records that authorize
    a set of upstream providers for a customer ASN. They complement ROAs
    by enabling route leak detection via path validation.

    Returns the ASPA status, authorized provider list, and inferred
    upstreams for comparison.

    Data source: rpki-client console (console.rpki-client.org) — free, no auth.
    """
    try:
        rpki_console = await get_rpki_console()
        if rpki_console is None:
            return "rpki-client console is unavailable. Cannot check ASPA status."

        has_aspa = await rpki_console.has_aspa(asn)

        summary = [f"**ASPA Status for AS{asn}**", ""]

        if has_aspa:
            aspa_obj = await rpki_console.get_aspa_object(asn)
            if aspa_obj:
                providers_str = ", ".join(f"AS{p}" for p in sorted(aspa_obj.provider_asns))
                summary.append("**Status:** PUBLISHED")
                summary.append(f"**Authorized Providers:** {providers_str}")
                summary.append(f"**Provider Count:** {len(aspa_obj.provider_asns)}")
        else:
            summary.append("**Status:** NOT PUBLISHED")
            summary.append("")
            summary.append(
                "This ASN has not published any ASPA objects in the RPKI. "
                "Consider creating one at your RIR portal to protect against "
                "route leaks."
            )

            # Try to show inferred upstreams for guidance
            monocle = await get_monocle()
            if monocle is not None:
                try:
                    upstreams = await monocle.get_as_upstreams(asn)
                    if upstreams:
                        upstream_strs = []
                        for u in upstreams[:15]:
                            name = f"AS{u.asn2}"
                            if u.asn2_name:
                                name += f" ({u.asn2_name})"
                            upstream_strs.append(name)
                        summary.append("")
                        summary.append("**Inferred Upstreams (from BGP data):**")
                        for u in upstream_strs:
                            summary.append(f"  - {u}")
                        summary.append("")
                        summary.append(
                            "These are potential providers to include in an ASPA object. "
                            "Verify with your actual transit agreements before publishing."
                        )
                except Exception:
                    pass

        # Add global context
        try:
            total = await rpki_console.get_aspa_count()
            meta = await rpki_console.get_dump_metadata()
            summary.append("")
            summary.append(f"**Global ASPA Deployment:** {total} ASes have published ASPA objects")
            summary.append(f"**Data Source:** rpki-client console (as of {meta['generated']})")
        except Exception:
            pass

        return "\n".join(summary)

    except Exception as e:
        return f"Error checking ASPA status for AS{asn}: {e}"


@mcp.tool()
async def get_roa_guidance(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 13335 for Cloudflare)")],
) -> str:
    """Get ROA (Route Origin Authorization) guidance for an ASN.

    Analyzes current prefix announcements against existing ROAs to identify:
    - Prefixes missing ROA coverage
    - ROAs with overly permissive maxLength (security risk)
    - Recommended ROA configuration

    Best practice: maxLength should equal the announced prefix length to
    prevent sub-prefix hijacks.

    Data source: RIPE Stat (announcements) + rpki-client console (ROAs).
    """
    try:
        rpki_console = await get_rpki_console()
        if rpki_console is None:
            return "rpki-client console is unavailable. Cannot analyze ROA coverage."

        client = await get_ripe_stat()
        prefixes = await client.get_announced_prefixes(asn)

        if not prefixes:
            return f"AS{asn} is not announcing any prefixes, or the ASN does not exist."

        roas = await rpki_console.get_roas_for_origin(asn)

        missing_roas = []
        permissive_max_length = []
        valid_roas = []

        for prefix in prefixes:
            prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 0
            matching = [r for r in roas if r.prefix == prefix]

            if not matching:
                missing_roas.append(prefix)
            else:
                for r in matching:
                    if r.max_length > prefix_len:
                        permissive_max_length.append(
                            {
                                "prefix": prefix,
                                "max_length": r.max_length,
                                "prefix_length": prefix_len,
                            }
                        )
                    else:
                        valid_roas.append(prefix)

        summary = [
            f"**ROA Guidance for AS{asn}**",
            "",
            f"**Announced Prefixes:** {len(prefixes)}",
            f"**Existing ROAs:** {len(roas)}",
            "",
        ]

        coverage_pct = (len(valid_roas) + len(permissive_max_length)) / len(prefixes) * 100
        summary.append(f"**ROA Coverage:** {coverage_pct:.0f}%")
        summary.append("")

        if valid_roas:
            summary.append(f"**Correctly Configured ({len(valid_roas)}):**")
            for p in valid_roas[:10]:
                summary.append(f"  - {p}")
            if len(valid_roas) > 10:
                summary.append(f"  ... and {len(valid_roas) - 10} more")
            summary.append("")

        if permissive_max_length:
            summary.append(f"**Overly Permissive maxLength ({len(permissive_max_length)}):**")
            for item in permissive_max_length[:10]:
                summary.append(
                    f"  - {item['prefix']}: maxLength=/{item['max_length']} "
                    f"(should be /{item['prefix_length']})"
                )
            summary.append("")
            summary.append(
                "  RECOMMENDATION: Set maxLength to match the announced prefix "
                "length to prevent sub-prefix hijack attacks."
            )
            summary.append("")

        if missing_roas:
            summary.append(f"**Missing ROAs ({len(missing_roas)}):**")
            for p in missing_roas[:15]:
                prefix_len = int(p.split("/")[1]) if "/" in p else 0
                summary.append(f"  - {p} → create ROA: origin AS{asn}, maxLength /{prefix_len}")
            if len(missing_roas) > 15:
                summary.append(f"  ... and {len(missing_roas) - 15} more")
            summary.append("")
            summary.append(
                "  RECOMMENDATION: Create ROAs for all announced prefixes at your "
                "RIR portal (RIPE, ARIN, APNIC, etc.)."
            )

        if not missing_roas and not permissive_max_length:
            summary.append("All prefixes are covered by correctly configured ROAs.")

        return "\n".join(summary)

    except Exception as e:
        return f"Error generating ROA guidance for AS{asn}: {e}"


@mcp.tool()
async def get_aspa_guidance(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 13335 for Cloudflare)")],
) -> str:
    """Get ASPA (AS Provider Authorization) guidance for an ASN.

    Compares the published ASPA object (if any) with inferred upstream
    providers to identify gaps or stale entries. Outputs a recommended
    provider set for creating or updating the ASPA object at the RIR portal.

    Data source: rpki-client console (ASPA) + Monocle (inferred upstreams).
    """
    try:
        rpki_console = await get_rpki_console()
        if rpki_console is None:
            return "rpki-client console is unavailable. Cannot generate ASPA guidance."

        has_aspa = await rpki_console.has_aspa(asn)
        aspa_providers: frozenset[int] = frozenset()
        if has_aspa:
            aspa_obj = await rpki_console.get_aspa_object(asn)
            if aspa_obj:
                aspa_providers = aspa_obj.provider_asns

        # Get inferred upstreams
        inferred_upstreams: list[tuple[int, str]] = []
        monocle = await get_monocle()
        if monocle is not None:
            try:
                upstreams = await monocle.get_as_upstreams(asn)
                for u in upstreams:
                    name = u.asn2_name or ""
                    inferred_upstreams.append((u.asn2, name))
            except Exception:
                pass

        inferred_asns = {asn for asn, _ in inferred_upstreams}

        summary = [f"**ASPA Guidance for AS{asn}**", ""]

        if has_aspa:
            summary.append("**Current ASPA Object:**")
            providers_str = ", ".join(f"AS{p}" for p in sorted(aspa_providers))
            summary.append(f"  Authorized providers: {providers_str}")
            summary.append("")

            # Find gaps
            missing_in_aspa = inferred_asns - aspa_providers
            extra_in_aspa = aspa_providers - inferred_asns

            if missing_in_aspa:
                summary.append("**Potentially Missing Providers:**")
                for missing_asn in sorted(missing_in_aspa):
                    name = next((n for a, n in inferred_upstreams if a == missing_asn), "")
                    label = f"AS{missing_asn}"
                    if name:
                        label += f" ({name})"
                    summary.append(f"  - {label} — seen as upstream in BGP data but not in ASPA")
                summary.append("")

            if extra_in_aspa:
                summary.append("**Providers in ASPA Not Seen in BGP:**")
                for extra_asn in sorted(extra_in_aspa):
                    summary.append(
                        f"  - AS{extra_asn} — in ASPA but not observed as upstream "
                        "(may be backup transit or recently depeered)"
                    )
                summary.append("")

            if not missing_in_aspa and not extra_in_aspa:
                summary.append("ASPA object matches observed upstreams. No changes needed.")
        else:
            summary.append("**No ASPA object published.**")
            summary.append("")

            if inferred_upstreams:
                summary.append("**Recommended Provider Set (based on observed BGP upstreams):**")
                for upstream_asn, name in sorted(inferred_upstreams, key=lambda x: x[0]):
                    label = f"AS{upstream_asn}"
                    if name:
                        label += f" ({name})"
                    summary.append(f"  - {label}")
                summary.append("")
                summary.append(
                    "To create an ASPA object, log in to your RIR portal "
                    "(RIPE NCC, ARIN, APNIC) and add these ASNs as authorized "
                    "providers for your AS. Verify against your actual transit "
                    "agreements before publishing."
                )
            else:
                summary.append(
                    "No upstream data available. Install Monocle "
                    "(cargo install monocle) to infer upstreams from BGP data."
                )

        return "\n".join(summary)

    except Exception as e:
        return f"Error generating ASPA guidance for AS{asn}: {e}"


@mcp.tool()
async def validate_prefix_routes(
    prefix: Annotated[
        str,
        Field(description="IP prefix in CIDR notation (e.g., '8.8.8.0/24')"),
    ],
) -> str:
    """Validate all routes for a prefix with combined ROV + ASPA status.

    For each observed route to the prefix, validates:
    - **ROV**: Is the origin ASN authorized by a ROA? (valid/invalid/unknown)
    - **ASPA**: Does the AS path comply with published ASPA objects? (valid/invalid/unknown)

    Produces per-route tags and aggregate statistics, similar to bgproutes.io.

    This is the most comprehensive single-prefix security analysis tool,
    combining origin validation (ROV) with path validation (ASPA).

    Data sources: RIPE Stat (routes + ROV), rpki-client console (ASPA objects).
    """
    import asyncio

    try:
        client = await get_ripe_stat()
        routes = await client.get_bgp_state(prefix)

        if not routes:
            return f"No routes found for {prefix}."

        rpki_console = await get_rpki_console()
        validator = await get_aspa_validator()

        # Pre-compute ROV for this prefix (same for all routes with same prefix)
        roa_cache: dict[str, list] = {}
        if rpki_console is not None:
            roa_cache[prefix] = await rpki_console.get_roas_for_prefix(prefix)
        prefix_len = int(prefix.split("/")[1]) if "/" in prefix else 0

        # Deduplicate paths for ASPA validation (many routes share same AS path)
        unique_paths: dict[str, str] = {}  # "asn1 asn2 asn3" -> aspa_status

        async def validate_path_cached(as_path: list[int]) -> str:
            path_key = " ".join(str(a) for a in as_path)
            if path_key in unique_paths:
                return unique_paths[path_key]
            if validator is not None and len(as_path) >= 2:
                try:
                    result = await validator.validate_path(as_path)
                    status = result.state.value
                except Exception:
                    status = "unknown"
            elif len(as_path) < 2:
                status = "unverifiable"
            else:
                status = "unknown"
            unique_paths[path_key] = status
            return status

        # Validate unique paths first (much faster than per-route)
        unique_as_paths = {tuple(r.as_path) for r in routes}
        semaphore = asyncio.Semaphore(20)

        async def validate_one(path_tuple: tuple[int, ...]) -> None:
            async with semaphore:
                await validate_path_cached(list(path_tuple))

        await asyncio.gather(*(validate_one(p) for p in unique_as_paths))

        # Now build results using cached data
        rov_stats = {"valid": 0, "invalid": 0, "unknown": 0}
        aspa_stats = {"valid": 0, "invalid": 0, "unknown": 0, "unverifiable": 0}
        route_details: list[dict] = []

        for route in routes:
            # ROV validation (uses pre-fetched ROA data)
            rov_status = "unknown"
            roas = roa_cache.get(route.prefix, [])
            if roas:
                origin_match = any(r.origin_asn == route.origin_asn for r in roas)
                length_ok = any(
                    r.origin_asn == route.origin_asn and prefix_len <= r.max_length for r in roas
                )
                if origin_match and length_ok:
                    rov_status = "valid"
                else:
                    rov_status = "invalid"
            rov_stats[rov_status] += 1

            # ASPA validation (uses cached path results)
            path_key = " ".join(str(a) for a in route.as_path)
            aspa_status = unique_paths.get(path_key, "unknown")
            if aspa_status in aspa_stats:
                aspa_stats[aspa_status] += 1

            route_details.append(
                {
                    "path": path_key,
                    "origin": route.origin_asn,
                    "rov": rov_status,
                    "aspa": aspa_status,
                    "collector": route.collector or "",
                }
            )

        total = len(routes)
        origin_asn = routes[0].origin_asn

        # Build output
        summary = [
            f"**ROV + ASPA Validation: {prefix}**",
            f"**Origin:** AS{origin_asn}",
            f"**Total routes analyzed:** {total}",
            "",
        ]

        # ROV stats
        summary.append("**ROV (Route Origin Validation):**")
        for status in ["valid", "invalid", "unknown"]:
            count = rov_stats[status]
            pct = count / total * 100 if total else 0
            label = {"valid": "Valid", "invalid": "INVALID", "unknown": "Unknown (no ROA)"}[status]
            summary.append(f"  - {label}: {count} ({pct:.1f}%)")

        summary.append("")

        # ASPA stats
        summary.append("**ASPA (Path Authorization):**")
        for status in ["valid", "invalid", "unknown", "unverifiable"]:
            count = aspa_stats[status]
            if count == 0:
                continue
            pct = count / total * 100 if total else 0
            label = {
                "valid": "Valid",
                "invalid": "INVALID",
                "unknown": "Unknown",
                "unverifiable": "Unverifiable",
            }[status]
            summary.append(f"  - {label}: {count} ({pct:.1f}%)")

        summary.append("")

        # ASPA object status for origin
        if rpki_console is not None:
            has_aspa = await rpki_console.has_aspa(origin_asn)
            if has_aspa:
                aspa_obj = await rpki_console.get_aspa_object(origin_asn)
                if aspa_obj:
                    providers = ", ".join(f"AS{p}" for p in sorted(aspa_obj.provider_asns))
                    summary.append(
                        f"**Origin ASPA:** AS{origin_asn} has published ASPA "
                        f"(providers: {providers})"
                    )
            else:
                summary.append(f"**Origin ASPA:** AS{origin_asn} has NOT published ASPA objects")
            summary.append("")

        # Show sample routes (first 10 with most interesting status)
        # Prioritize invalid routes
        invalid_routes = [
            r for r in route_details if r["rov"] == "invalid" or r["aspa"] == "invalid"
        ]
        valid_routes = [r for r in route_details if r["rov"] == "valid" and r["aspa"] == "valid"]
        other_routes = [
            r for r in route_details if r not in invalid_routes and r not in valid_routes
        ]

        sample = invalid_routes[:5] + valid_routes[:3] + other_routes[:2]

        if sample:
            summary.append("**Sample Routes:**")
            for r in sample:
                rov_tag = {
                    "valid": "ROV:Valid",
                    "invalid": "ROV:INVALID",
                    "unknown": "ROV:Unknown",
                }[r["rov"]]
                aspa_tag = {
                    "valid": "ASPA:Valid",
                    "invalid": "ASPA:INVALID",
                    "unknown": "ASPA:Unknown",
                    "unverifiable": "ASPA:Unverifiable",
                }.get(r["aspa"], f"ASPA:{r['aspa']}")
                summary.append(f"  - [{rov_tag}] [{aspa_tag}] path: {r['path']}")

        # Security assessment
        summary.append("")
        rov_invalid_pct = rov_stats["invalid"] / total * 100 if total else 0
        aspa_invalid_pct = aspa_stats["invalid"] / total * 100 if total else 0

        if rov_invalid_pct > 0 or aspa_invalid_pct > 0:
            summary.append("**Security Concerns:**")
            if rov_invalid_pct > 0:
                summary.append(
                    f"  - {rov_stats['invalid']} routes ({rov_invalid_pct:.1f}%) have "
                    f"INVALID ROV status — potential hijack or misconfiguration"
                )
            if aspa_invalid_pct > 0:
                summary.append(
                    f"  - {aspa_stats['invalid']} routes ({aspa_invalid_pct:.1f}%) have "
                    f"INVALID ASPA status — potential route leak"
                )
        else:
            summary.append(
                "**No security concerns detected.** All routes pass ROV and ASPA checks."
            )

        return "\n".join(summary)

    except Exception as e:
        return f"Error validating routes for {prefix}: {e}"


# =============================================================================
# MANRS Readiness Assessment
# =============================================================================


@mcp.tool()
async def check_manrs_readiness(
    asn: Annotated[
        int, Field(description="Autonomous System Number to assess (e.g., 13335 for Cloudflare)")
    ],
    output_format: Annotated[
        str,
        Field(description="Output format: 'text' or 'json' (default: 'text')"),
    ] = "text",
) -> str:
    """Assess MANRS (Mutually Agreed Norms for Routing Security) readiness.

    Evaluates the 4 MANRS Actions using locally available data:
    - Action 1 (Filtering): Proxy via ROV coverage and RPKI deployment
    - Action 2 (Anti-Spoofing): Cannot be verified externally (marked unknown)
    - Action 3 (Coordination): Contact info in PeeringDB/WHOIS
    - Action 4 (Validation): RPKI ROA/ASPA deployment

    This is a self-assessment tool — shows what can be verified externally.
    Use get_manrs_status for official MANRS Observatory conformance data.

    Does NOT require MANRS API key — uses existing data sources only.
    """
    try:
        client = await get_ripe_stat()

        # Gather RPKI coverage
        rpki_coverage = None
        prefixes = []
        try:
            prefixes = await client.get_announced_prefixes(asn)
            if prefixes:
                valid_count = 0
                checked = 0
                # Limit to 20 prefixes to avoid timeout on large ASNs
                for prefix in prefixes[:20]:
                    try:
                        status = await client.get_rpki_validation(prefix, asn)
                        checked += 1
                        if status == "valid":
                            valid_count += 1
                    except Exception:
                        pass
                if checked > 0:
                    rpki_coverage = valid_count / checked
        except Exception:
            logger.debug("Could not fetch RPKI data for AS%d", asn)

        # Check ASPA status
        has_aspa: bool | None = None
        try:
            rpki_console = await get_rpki_console()
            if rpki_console is not None:
                has_aspa = await rpki_console.has_aspa(asn)
        except Exception:
            logger.debug("Could not check ASPA for AS%d", asn)

        # Gather ROV coverage
        rov_report = None
        try:
            if prefixes:
                routes = await client.get_bgp_state(prefixes[0])
                if routes:
                    rov_analyzer = get_rov_coverage_analyzer()
                    rov_report = rov_analyzer.analyze_prefix_coverage(prefixes[0], routes)
        except Exception:
            logger.debug("Could not fetch ROV data for AS%d", asn)

        # Gather contacts
        contacts = None
        try:
            peeringdb = await get_peeringdb()
            if peeringdb is not None:
                net = peeringdb.get_network_by_asn(asn)
                if net:
                    contacts = net
        except Exception:
            logger.debug("Could not fetch PeeringDB contacts for AS%d", asn)

        # Run assessment
        assessor = get_manrs_assessor()
        report = assessor.assess(
            asn=asn,
            rpki_coverage=rpki_coverage,
            has_aspa=has_aspa,
            rov_report=rov_report,
            contacts=contacts,
        )

        if output_format == "json":
            import json

            return json.dumps(report.to_dict(), indent=2)
        return assessor.format_report(report)

    except Exception as e:
        return f"Error assessing MANRS readiness for AS{asn}: {e}"


@mcp.tool()
async def get_manrs_status(
    asn: Annotated[int, Field(description="Autonomous System Number (e.g., 13335 for Cloudflare)")],
) -> str:
    """Get official MANRS Observatory conformance status for an ASN.

    Returns the official MANRS scoring from the MANRS Observatory:
    - Participation status (whether ASN has joined MANRS)
    - Per-action readiness: Ready/Aspiring/Lagging
    - Organization and country info

    Requires: MANRS_API_KEY environment variable.

    For a self-assessment using local data (no API key needed),
    use check_manrs_readiness instead.
    """
    try:
        client = await get_manrs_client()
        if client is None:
            return (
                "MANRS API key not configured. Set MANRS_API_KEY environment variable.\n"
                "Register free at https://manrs.org/resources/api/\n\n"
                "Tip: Use check_manrs_readiness for a local assessment without the API."
            )

        conformance = await client.get_asn_conformance(asn)
        if conformance is None:
            return (
                f"AS{asn} not found in MANRS Observatory data.\n"
                f"This ASN may not be a MANRS participant.\n\n"
                f"Use check_manrs_readiness for a local self-assessment instead."
            )

        lines = [
            f"**MANRS Observatory Status: AS{asn}**",
            f"**Organization:** {conformance.name}",
            f"**Country:** {conformance.country}",
            "**MANRS Participant:** Yes",
            f"**Overall Status:** {conformance.status.upper()}",
            "",
            "**Per-Action Readiness:**",
            f"  - Action 1 (Filtering): {conformance.action1_filtering.value.upper()}",
            f"  - Action 2 (Anti-Spoofing): {conformance.action2_anti_spoofing.value.upper()}",
            f"  - Action 3 (Coordination): {conformance.action3_coordination.value.upper()}",
            f"  - Action 4 (Validation): {conformance.action4_validation.value.upper()}",
            "",
            f"**Last Updated:** {conformance.last_updated}",
            "",
            "Data source: MANRS Observatory (observatory.manrs.org)",
        ]
        return "\n".join(lines)

    except Exception as e:
        return f"Error fetching MANRS status for AS{asn}: {e}"


# =============================================================================
# Server Entry Point
# =============================================================================


def main():
    """Run the MCP server."""
    logger.info("Starting bgp-explorer MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
