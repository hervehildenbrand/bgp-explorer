"""Tests for configuration management."""

import os
from unittest.mock import patch

import pytest

from bgp_explorer.config import (
    AIBackendType,
    OutputFormat,
    Settings,
    load_settings,
)


class TestAIBackendType:
    """Tests for AIBackendType enum."""

    def test_gemini_value(self):
        """Test Gemini enum value."""
        assert AIBackendType.GEMINI.value == "gemini"

    def test_claude_value(self):
        """Test Claude enum value."""
        assert AIBackendType.CLAUDE.value == "claude"


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
        # Create settings without loading from env
        settings = Settings(
            _env_file=None,  # Don't load .env file
        )

        assert settings.ai_backend == AIBackendType.GEMINI
        assert settings.gemini_api_key is None
        assert settings.anthropic_api_key is None
        assert settings.gemini_model == "gemini-1.5-flash"
        assert settings.bgp_radar_path is None
        assert settings.collectors == ["rrc00"]
        assert settings.output_format == OutputFormat.TEXT
        assert settings.save_path is None
        assert "BGP network analyst" in settings.system_prompt

    def test_custom_values(self):
        """Test settings with custom values."""
        settings = Settings(
            ai_backend=AIBackendType.CLAUDE,
            anthropic_api_key="test-key",
            collectors=["rrc00", "rrc01"],
            output_format=OutputFormat.JSON,
        )

        assert settings.ai_backend == AIBackendType.CLAUDE
        assert settings.anthropic_api_key == "test-key"
        assert settings.collectors == ["rrc00", "rrc01"]
        assert settings.output_format == OutputFormat.JSON

    def test_get_api_key_gemini(self):
        """Test getting Gemini API key."""
        settings = Settings(
            ai_backend=AIBackendType.GEMINI,
            gemini_api_key="gemini-test-key",
        )

        assert settings.get_api_key() == "gemini-test-key"

    def test_get_api_key_claude(self):
        """Test getting Claude API key."""
        settings = Settings(
            ai_backend=AIBackendType.CLAUDE,
            anthropic_api_key="claude-test-key",
        )

        assert settings.get_api_key() == "claude-test-key"

    def test_get_api_key_gemini_missing(self):
        """Test error when Gemini API key is missing."""
        settings = Settings(ai_backend=AIBackendType.GEMINI)

        with pytest.raises(ValueError, match="GEMINI_API_KEY not set"):
            settings.get_api_key()

    @patch.dict(os.environ, {}, clear=True)
    def test_get_api_key_claude_missing(self):
        """Test error when Claude API key is missing."""
        settings = Settings(
            ai_backend=AIBackendType.CLAUDE,
            _env_file=None,  # Don't load .env file
        )

        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY not set"):
            settings.get_api_key()

    @patch.dict(os.environ, {"GEMINI_API_KEY": "env-gemini-key"})
    def test_load_from_environment(self):
        """Test loading settings from environment."""
        settings = Settings()

        assert settings.gemini_api_key == "env-gemini-key"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-anthropic-key"})
    def test_load_anthropic_from_environment(self):
        """Test loading Anthropic key from environment."""
        settings = Settings()

        assert settings.anthropic_api_key == "env-anthropic-key"


class TestLoadSettings:
    """Tests for load_settings function."""

    def test_load_with_overrides(self):
        """Test load_settings with overrides."""
        settings = load_settings(
            ai_backend=AIBackendType.CLAUDE,
            collectors=["rrc01", "rrc21"],
        )

        assert settings.ai_backend == AIBackendType.CLAUDE
        assert settings.collectors == ["rrc01", "rrc21"]

    def test_load_with_none_values(self):
        """Test that None values are ignored."""
        settings = load_settings(
            ai_backend=None,
            collectors=None,
        )

        # Should use defaults
        assert settings.ai_backend == AIBackendType.GEMINI
        assert settings.collectors == ["rrc00"]

    def test_load_mixed_overrides(self):
        """Test load with mix of None and actual values."""
        settings = load_settings(
            ai_backend=AIBackendType.CLAUDE,
            collectors=None,  # Should be ignored
            gemini_api_key="test-key",
        )

        assert settings.ai_backend == AIBackendType.CLAUDE
        assert settings.collectors == ["rrc00"]  # Default
        assert settings.gemini_api_key == "test-key"
