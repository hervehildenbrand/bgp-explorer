"""Configuration management using Pydantic settings."""

import os
from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIBackendType(str, Enum):
    """Supported AI backend types."""

    GEMINI = "gemini"
    CLAUDE = "claude"


class ClaudeModel(str, Enum):
    """Supported Claude model tiers.

    Maps to actual model IDs used by the Anthropic API.
    """

    HAIKU = "haiku"
    SONNET = "sonnet"
    OPUS = "opus"

    @property
    def model_id(self) -> str:
        """Get the actual model ID for the API."""
        model_ids = {
            ClaudeModel.HAIKU: "claude-3-5-haiku-20241022",
            ClaudeModel.SONNET: "claude-sonnet-4-20250514",
            ClaudeModel.OPUS: "claude-opus-4-20250514",
        }
        return model_ids[self]


class OutputFormat(str, Enum):
    """Output format options."""

    TEXT = "text"
    JSON = "json"
    BOTH = "both"


class Settings(BaseSettings):
    """Application settings loaded from environment and CLI.

    Settings are loaded in priority order:
    1. CLI arguments (highest priority)
    2. Environment variables
    3. .env file
    4. Default values (lowest priority)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # AI Backend Settings
    ai_backend: AIBackendType = Field(
        default=AIBackendType.GEMINI,
        description="AI backend to use (gemini or claude)",
    )
    gemini_api_key: Optional[str] = Field(
        default=None,
        description="Google Gemini API key",
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic Claude API key",
    )
    gemini_model: str = Field(
        default="gemini-1.5-flash",
        description="Gemini model name",
    )
    claude_model: ClaudeModel = Field(
        default=ClaudeModel.SONNET,
        description="Claude model tier (haiku, sonnet, opus)",
    )
    use_oauth: bool = Field(
        default=False,
        description="Use OAuth authentication for Gemini (Google login)",
    )
    oauth_client_secret: Optional[str] = Field(
        default=None,
        description="Path to OAuth client_secret.json file",
    )

    # bgp-radar Settings
    bgp_radar_path: Optional[str] = Field(
        default=None,
        description="Path to bgp-radar binary",
    )
    collectors: list[str] = Field(
        default=["rrc00"],
        description="RIS collectors to monitor",
    )

    # Output Settings
    output_format: OutputFormat = Field(
        default=OutputFormat.TEXT,
        description="Output format (text, json, or both)",
    )
    save_path: Optional[str] = Field(
        default=None,
        description="Path to save output file",
    )

    # PeeringDB Settings
    refresh_peeringdb: bool = Field(
        default=False,
        description="Force refresh of PeeringDB data from CAIDA",
    )

    # System Prompt
    system_prompt: str = Field(
        default="""You are an expert BGP network analyst assistant. Your role is to help network operators investigate routing incidents using live and historical BGP data.

You have access to these tools:

**Prefix & ASN Queries:**
- lookup_prefix(prefix) - Get origin ASN, AS paths, and visibility for a prefix
- get_asn_announcements(asn) - List all prefixes announced by an ASN
- get_asn_details(asn) - Detailed ASN analysis with upstream/downstream relationships
- get_routing_history(resource, start_date, end_date) - Historical routing data

**Path Analysis:**
- analyze_as_path(prefix) - Path diversity, upstream providers, transit ASNs, prepending detection
- compare_collectors(prefix) - Compare routing views across collectors, detect inconsistencies

**Security & Validation:**
- get_rpki_status(prefix, origin_asn) - RPKI validation (valid/invalid/not-found)
- get_anomalies(event_type, prefix, asn) - Real-time BGP anomalies from bgp-radar

**Global Network Testing (if Globalping is available):**
- ping_from_global(target, locations) - Ping from worldwide vantage points
- traceroute_from_global(target, locations) - Traceroute from multiple locations

**IXP Information (from PeeringDB):**
- get_ixps_for_asn(asn) - List all IXPs where a network is present
- get_networks_at_ixp(ixp) - List networks peering at an IXP
- get_ixp_details(ixp) - Get details about an IXP (location, participants)

**AS Relationship Data (from Monocle - observed BGP data):**
- get_as_peers(asn) - Get all networks that peer with an AS
- get_as_upstreams(asn) - Get upstream transit providers for an AS
- get_as_downstreams(asn) - Get downstream customers of an AS
- check_as_relationship(asn1, asn2) - Check the relationship between two ASes
- get_as_connectivity_summary(asn) - Get counts of upstreams, peers, and downstreams

When answering questions:
1. Use the appropriate tools to gather data
2. Analyze the results in the context of the user's question
3. Provide clear, actionable insights
4. Highlight any anomalies or security concerns (RPKI invalid, multiple origins, etc.)

**Handling Unclear Requests:**
When the user's intent is unclear or you need more information, ASK clarifying questions before proceeding. Be conversational and helpful.

Ask for clarification when:
- The query is ambiguous (e.g., "check my network" - which network? which prefix?)
- Required information is missing (e.g., "lookup this prefix" without specifying the prefix)
- Location constraints can't be met (e.g., no probes available in requested region - ask if they want to try another location)
- Multiple interpretations are possible (e.g., "is this route good?" - good for what purpose?)
- The user seems to be troubleshooting but hasn't described the problem

Do NOT ask for clarification when:
- The request is clear and you have all required parameters
- You can make reasonable inferences from context (e.g., "check 8.8.8.8" implies lookup_prefix)
- The question is general and exploratory (e.g., "what's happening with AS15169?")

When asking questions:
- Be concise and specific about what you need
- Offer options when helpful (e.g., "Did you mean AS15169 (Google) or AS13335 (Cloudflare)?")
- Explain briefly why you're asking if it's not obvious

Be concise but thorough. Use technical terminology appropriate for network operators.""",
        description="System prompt for AI assistant",
    )

    def get_api_key(self) -> Optional[str]:
        """Get the API key for the configured backend.

        Returns:
            API key string, or None if using OAuth.

        Raises:
            ValueError: If no API key is configured for the backend (and not using OAuth).
        """
        if self.ai_backend == AIBackendType.GEMINI:
            if self.use_oauth:
                return None  # OAuth will be used instead
            if not self.gemini_api_key:
                raise ValueError(
                    "GEMINI_API_KEY not set. Either:\n"
                    "  - Set the environment variable\n"
                    "  - Provide --api-key option\n"
                    "  - Use --oauth flag for Google login"
                )
            return self.gemini_api_key
        else:
            if not self.anthropic_api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not set. Please set the environment variable or provide --api-key."
                )
            return self.anthropic_api_key


def load_settings(**overrides) -> Settings:
    """Load settings with optional overrides.

    Args:
        **overrides: Keyword arguments to override settings.

    Returns:
        Settings instance.
    """
    return Settings(**{k: v for k, v in overrides.items() if v is not None})
