"""Tests for CLI commands."""

import pytest
from click.testing import CliRunner

from bgp_explorer.cli import cli


class TestAssessCommand:
    """Tests for the 'assess' CLI command."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    def test_assess_command_exists(self, runner):
        """Test that assess command is registered."""
        result = runner.invoke(cli, ["assess", "--help"])
        assert result.exit_code == 0
        assert "resilience" in result.output.lower()

    def test_assess_requires_asn_argument(self, runner):
        """Test that assess requires an ASN argument."""
        result = runner.invoke(cli, ["assess"])
        assert result.exit_code != 0
        # Should show missing argument error
        assert "Missing argument" in result.output or "Error" in result.output

    def test_assess_rejects_invalid_asn(self, runner):
        """Test that assess rejects non-numeric ASN."""
        result = runner.invoke(cli, ["assess", "not-a-number"])
        # Should fail with invalid value error (click type validation)
        assert result.exit_code != 0
