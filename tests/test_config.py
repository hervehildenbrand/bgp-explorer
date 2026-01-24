"""Tests for configuration management."""

import os
from unittest.mock import patch

import pytest

from bgp_explorer.config import (
    ClaudeModel,
    OutputFormat,
    Settings,
    load_settings,
)


class TestClaudeModel:
    """Tests for ClaudeModel enum.

    Note: Only Sonnet and Opus are supported as they have extended thinking capability.
    """

    def test_sonnet_value(self):
        """Test Sonnet enum value."""
        assert ClaudeModel.SONNET.value == "sonnet"

    def test_opus_value(self):
        """Test Opus enum value."""
        assert ClaudeModel.OPUS.value == "opus"

    def test_model_id_sonnet(self):
        """Test Sonnet model ID."""
        assert ClaudeModel.SONNET.model_id == "claude-sonnet-4-5-20250929"

    def test_model_id_opus(self):
        """Test Opus model ID."""
        assert ClaudeModel.OPUS.model_id == "claude-opus-4-5-20251124"


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_text_value(self):
        """Test text format value."""
        assert OutputFormat.TEXT.value == "text"

    def test_json_value(self):
        """Test JSON format value."""
        assert OutputFormat.JSON.value == "json"

    def test_both_value(self):
        """Test both format value."""
        assert OutputFormat.BOTH.value == "both"


class TestSettings:
    """Tests for Settings class."""

    @patch.dict(os.environ, {}, clear=True)
    def test_default_values(self):
        """Test default settings values (with env cleared)."""
        settings = Settings(
            _env_file=None,  # Don't load .env file
        )

        assert settings.anthropic_api_key is None
        assert settings.claude_model == ClaudeModel.SONNET
        assert settings.bgp_radar_path is None
        assert settings.collectors == ["rrc00"]
        assert settings.output_format == OutputFormat.TEXT
        assert settings.save_path is None
        # Note: system_prompt is now built dynamically by PromptBuilder

    def test_custom_values(self):
        """Test settings with custom values."""
        settings = Settings(
            anthropic_api_key="test-key",
            claude_model=ClaudeModel.OPUS,
            collectors=["rrc00", "rrc01"],
            output_format=OutputFormat.JSON,
        )

        assert settings.anthropic_api_key == "test-key"
        assert settings.claude_model == ClaudeModel.OPUS
        assert settings.collectors == ["rrc00", "rrc01"]
        assert settings.output_format == OutputFormat.JSON

    def test_get_api_key(self):
        """Test getting API key."""
        settings = Settings(
            anthropic_api_key="claude-test-key",
        )

        assert settings.get_api_key() == "claude-test-key"

    @patch.dict(os.environ, {}, clear=True)
    def test_get_api_key_missing(self):
        """Test error when API key is missing."""
        settings = Settings(
            _env_file=None,  # Don't load .env file
        )

        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY not set"):
            settings.get_api_key()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-anthropic-key"})
    def test_load_from_environment(self):
        """Test loading settings from environment."""
        settings = Settings()

        assert settings.anthropic_api_key == "env-anthropic-key"


class TestLoadSettings:
    """Tests for load_settings function."""

    def test_load_with_overrides(self):
        """Test load_settings with overrides."""
        settings = load_settings(
            claude_model=ClaudeModel.OPUS,
            collectors=["rrc01", "rrc21"],
        )

        assert settings.claude_model == ClaudeModel.OPUS
        assert settings.collectors == ["rrc01", "rrc21"]

    def test_load_with_none_values(self):
        """Test that None values are ignored."""
        settings = load_settings(
            claude_model=None,
            collectors=None,
        )

        # Should use defaults
        assert settings.claude_model == ClaudeModel.SONNET
        assert settings.collectors == ["rrc00"]

    def test_load_mixed_overrides(self):
        """Test load with mix of None and actual values."""
        settings = load_settings(
            claude_model=ClaudeModel.OPUS,
            collectors=None,  # Should be ignored
            anthropic_api_key="test-key",
        )

        assert settings.claude_model == ClaudeModel.OPUS
        assert settings.collectors == ["rrc00"]  # Default
        assert settings.anthropic_api_key == "test-key"
