"""Configuration management using Pydantic settings."""

from enum import Enum

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ClaudeModel(str, Enum):
    """Supported Claude model tiers.

    Maps to actual model IDs used by the Anthropic API.
    Note: Only Sonnet and Opus support extended thinking, which is required.
    """

    SONNET = "sonnet"
    OPUS = "opus"

    @property
    def model_id(self) -> str:
        """Get the actual model ID for the API."""
        model_ids = {
            ClaudeModel.SONNET: "claude-sonnet-4-5-20250929",
            ClaudeModel.OPUS: "claude-opus-4-5-20251124",
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

    # AI Backend Settings (Claude only)
    anthropic_api_key: str | None = Field(
        default=None,
        description="Anthropic Claude API key",
    )
    claude_model: ClaudeModel = Field(
        default=ClaudeModel.SONNET,
        description="Claude model tier (sonnet, opus) - both support extended thinking",
    )

    # bgp-radar Settings
    bgp_radar_path: str | None = Field(
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
    save_path: str | None = Field(
        default=None,
        description="Path to save output file",
    )

    # PeeringDB Settings
    refresh_peeringdb: bool = Field(
        default=False,
        description="Force refresh of PeeringDB data from CAIDA",
    )

    # AI Thinking Settings
    thinking_budget: int = Field(
        default=8000,
        description="Maximum tokens for extended thinking (Claude uses what it needs)",
    )
    max_tokens: int = Field(
        default=32000,
        description="Maximum tokens in AI response (must be > thinking_budget)",
    )

    # Note: system_prompt is now built dynamically by PromptBuilder
    # based on available tools. See bgp_explorer.ai.prompt_builder

    def get_api_key(self) -> str:
        """Get the Anthropic API key.

        Returns:
            API key string.

        Raises:
            ValueError: If no API key is configured.
        """
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
