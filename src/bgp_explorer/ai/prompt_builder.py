"""Dynamic system prompt builder for BGP Explorer.

This module builds context-aware system prompts based on available tools
and data sources, reducing token usage by ~30% compared to static prompts.
"""

from dataclasses import dataclass


@dataclass
class AvailableTools:
    """Tracks which optional data sources are available.

    Attributes:
        bgp_radar: Real-time anomaly detection via bgp-radar.
        globalping: Global network probing via Globalping.
        peeringdb: IXP and network information via PeeringDB.
        monocle: AS relationship data via BGPKIT Monocle.
    """

    bgp_radar: bool = False
    globalping: bool = False
    peeringdb: bool = False
    monocle: bool = False


# Core prompt - always included (~400 tokens)
CORE_PROMPT = """You are an expert BGP network analyst assistant helping network operators investigate routing incidents.

**CRITICAL: ALWAYS USE TOOLS**
- NEVER answer from training data - BGP routing changes constantly
- Use search_asn() FIRST when given company names, NEVER guess ASNs
- For peer counts, use get_as_peers() or get_as_connectivity_summary() - NOT path analysis
- Ask clarifying questions when intent is unclear

**Investigation Methodology:**
1. Identify entities - resolve company names to ASNs with search_asn()
2. Gather data - use multiple tools to collect routing information
3. Cross-reference - compare data from multiple sources
4. Synthesize - highlight security concerns and provide actionable insights"""


# Conditional sections - only included when relevant tools are available

MONOCLE_SECTION = """
**AS Relationship Data (Monocle - from observed BGP data):**
- get_as_peers(asn) - Get actual peer count and list
- get_as_upstreams(asn) - Transit providers
- get_as_downstreams(asn) - Customers (determines if AS provides transit)
- get_as_connectivity_summary(asn) - Complete connectivity overview
- check_as_relationship(asn1, asn2) - Check relationship between two ASes

**CRITICAL - Path Analysis vs Peer Count:**
- analyze_as_path() shows "upstream hops in paths" - this is PATH DIVERSITY, not peers
- For actual peer counts, ALWAYS use monocle tools (get_as_peers, get_as_connectivity_summary)
- NEVER report path diversity metrics as "peers" or "connectivity"
"""

BGP_RADAR_SECTION = """
**Real-time Monitoring (bgp-radar available):**
- start_monitoring(collectors) - Watch for anomalies in real-time
- stop_monitoring() - Stop monitoring
- get_anomalies() - Query recent detected anomalies
Note: Monitoring is opt-in. Start when user wants live events.
"""

GLOBALPING_SECTION = """
**Global Network Testing (Globalping available):**
- ping_from_global(target, locations) - Ping from worldwide vantage points
- traceroute_from_global(target, locations) - Traceroute from multiple locations
If probes unavailable in requested region, ask if user wants another location.
"""

PEERINGDB_SECTION = """
**IXP Information (PeeringDB available):**
- get_ixps_for_asn(asn) - IXPs where a network peers
- get_networks_at_ixp(ixp) - Networks at an IXP
- get_ixp_details(ixp) - IXP location and participants
- get_network_contacts(asn) - NOC/abuse contacts for incident response
"""


# Fallback messages for unavailable tools

MONOCLE_UNAVAILABLE = """
**Note:** Monocle is unavailable - AS relationship data (peers, upstreams, downstreams) cannot be queried.
"""

BGP_RADAR_UNAVAILABLE = """
**Note:** bgp-radar is unavailable - real-time anomaly monitoring not available.
Use check_prefix_anomalies() for on-demand hijack detection via RIPE Stat.
"""

GLOBALPING_UNAVAILABLE = """
**Note:** Globalping is unavailable - global ping/traceroute probing not available.
"""

PEERINGDB_UNAVAILABLE = """
**Note:** PeeringDB is unavailable - IXP presence and contact information not available.
"""


class PromptBuilder:
    """Builds dynamic system prompts based on available tools.

    Reduces token usage by only including guidance for tools that
    are actually available in the current session.
    """

    def build(self, available: AvailableTools) -> str:
        """Build a system prompt based on available tools.

        Args:
            available: AvailableTools instance indicating which sources are ready.

        Returns:
            Complete system prompt string.
        """
        sections = [CORE_PROMPT]

        # Add monocle section (required for accurate relationship data)
        if available.monocle:
            sections.append(MONOCLE_SECTION)
        else:
            sections.append(MONOCLE_UNAVAILABLE)

        # Add optional tool sections based on availability
        if available.bgp_radar:
            sections.append(BGP_RADAR_SECTION)
        else:
            sections.append(BGP_RADAR_UNAVAILABLE)

        if available.globalping:
            sections.append(GLOBALPING_SECTION)
        else:
            sections.append(GLOBALPING_UNAVAILABLE)

        if available.peeringdb:
            sections.append(PEERINGDB_SECTION)
        else:
            sections.append(PEERINGDB_UNAVAILABLE)

        return "\n".join(sections)

    def estimate_tokens(self, prompt: str) -> int:
        """Estimate token count for a prompt.

        Uses a simple heuristic of ~4 characters per token.
        Actual tokenization varies by model.

        Args:
            prompt: The prompt string.

        Returns:
            Estimated token count.
        """
        return len(prompt) // 4
