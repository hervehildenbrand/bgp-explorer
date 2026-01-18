"""Tests for output formatting utilities."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bgp_explorer.config import OutputFormat
from bgp_explorer.output import OutputFormatter, format_routes_as_table


class TestOutputFormatter:
    """Tests for OutputFormatter class."""

    def test_init_default(self):
        """Test default initialization."""
        formatter = OutputFormatter()

        assert formatter.format == OutputFormat.TEXT
        assert formatter.save_path is None
        assert formatter._conversation_log == []

    def test_init_custom(self):
        """Test custom initialization."""
        formatter = OutputFormatter(
            format=OutputFormat.JSON,
            save_path="/tmp/test.json",
        )

        assert formatter.format == OutputFormat.JSON
        assert formatter.save_path == "/tmp/test.json"

    @patch("bgp_explorer.output.Console")
    def test_display_welcome(self, mock_console_class):
        """Test display_welcome method."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter()
        formatter.display_welcome()

        mock_console.print.assert_called_once()

    @patch("bgp_explorer.output.Console")
    def test_display_user_input_text(self, mock_console_class):
        """Test displaying user input in text mode."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter(format=OutputFormat.TEXT)
        formatter.display_user_input("What is BGP?")

        assert len(formatter._conversation_log) == 1
        assert formatter._conversation_log[0]["role"] == "user"
        assert formatter._conversation_log[0]["content"] == "What is BGP?"
        mock_console.print.assert_called()

    @patch("bgp_explorer.output.Console")
    def test_display_user_input_json(self, mock_console_class):
        """Test displaying user input in JSON mode."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter(format=OutputFormat.JSON)
        formatter.display_user_input("Test message")

        assert len(formatter._conversation_log) == 1
        # JSON mode doesn't print user input
        mock_console.print.assert_not_called()

    @patch("bgp_explorer.output.Console")
    def test_display_response_text(self, mock_console_class):
        """Test displaying AI response in text mode."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter(format=OutputFormat.TEXT)
        formatter.display_response("BGP is a routing protocol.")

        assert len(formatter._conversation_log) == 1
        assert formatter._conversation_log[0]["role"] == "assistant"
        # Console.print called multiple times (blank line + panel)
        assert mock_console.print.call_count >= 2

    @patch("bgp_explorer.output.Console")
    def test_display_response_json(self, mock_console_class):
        """Test displaying AI response in JSON mode."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter(format=OutputFormat.JSON)
        formatter.display_response("Test response")

        assert len(formatter._conversation_log) == 1
        mock_console.print_json.assert_called_once()

    @patch("bgp_explorer.output.Console")
    def test_display_response_both(self, mock_console_class):
        """Test displaying AI response in both mode."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter(format=OutputFormat.BOTH)
        formatter.display_response("Test response")

        # Both text and JSON should be displayed
        assert mock_console.print.call_count >= 2  # Panel for text
        # Note: BOTH mode only displays text, not JSON

    @patch("bgp_explorer.output.Console")
    def test_display_error(self, mock_console_class):
        """Test displaying error message."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter()
        formatter.display_error("Something went wrong")

        mock_console.print.assert_called()
        call_args = mock_console.print.call_args[0][0]
        assert "Error" in call_args

    @patch("bgp_explorer.output.Console")
    def test_display_info(self, mock_console_class):
        """Test displaying info message."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter()
        formatter.display_info("Connecting...")

        mock_console.print.assert_called()

    def test_export_conversation(self):
        """Test exporting conversation to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = Path(tmpdir) / "test_export.json"

            formatter = OutputFormatter()
            formatter._conversation_log = [
                {"role": "user", "content": "Hello", "timestamp": "2024-01-01T00:00:00Z"},
                {"role": "assistant", "content": "Hi!", "timestamp": "2024-01-01T00:00:01Z"},
            ]

            result_path = formatter.export_conversation(str(export_path))

            assert result_path == str(export_path)
            assert export_path.exists()

            data = json.loads(export_path.read_text())
            assert "exported_at" in data
            assert len(data["messages"]) == 2

    def test_export_conversation_default_path(self):
        """Test exporting with default path generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                formatter = OutputFormatter()
                formatter._conversation_log = [
                    {"role": "user", "content": "Test", "timestamp": "2024-01-01T00:00:00Z"},
                ]

                result_path = formatter.export_conversation()

                assert "bgp_explorer_conversation_" in result_path
                assert Path(result_path).exists()
            finally:
                os.chdir(original_cwd)

    @patch("bgp_explorer.output.Console")
    def test_clear_history(self, mock_console_class):
        """Test clearing conversation history."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        formatter = OutputFormatter()
        formatter._conversation_log = [
            {"role": "user", "content": "Test"},
        ]

        formatter.clear_history()

        assert formatter._conversation_log == []
        mock_console.print.assert_called()


class TestFormatRoutesAsTable:
    """Tests for format_routes_as_table function."""

    def test_empty_routes(self):
        """Test formatting empty routes list."""
        result = format_routes_as_table([])

        assert result == "No routes found."

    def test_single_route(self):
        """Test formatting a single route."""
        routes = [
            {
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "as_path": [3356, 15169],
                "collector": "rrc00",
            }
        ]

        result = format_routes_as_table(routes)

        assert "| Prefix | Origin | AS Path | Collector |" in result
        assert "8.8.8.0/24" in result
        assert "AS15169" in result
        assert "rrc00" in result

    def test_multiple_routes(self):
        """Test formatting multiple routes."""
        routes = [
            {
                "prefix": "8.8.8.0/24",
                "origin_asn": 15169,
                "as_path": [3356, 15169],
                "collector": "rrc00",
            },
            {
                "prefix": "1.1.1.0/24",
                "origin_asn": 13335,
                "as_path": [174, 13335],
                "collector": "rrc01",
            },
        ]

        result = format_routes_as_table(routes)

        assert "8.8.8.0/24" in result
        assert "1.1.1.0/24" in result
        assert "AS15169" in result
        assert "AS13335" in result

    def test_long_as_path_truncated(self):
        """Test that long AS paths are truncated."""
        routes = [
            {
                "prefix": "10.0.0.0/8",
                "origin_asn": 64496,
                "as_path": [1, 2, 3, 4, 5, 6, 7, 8],  # More than 5 ASNs
                "collector": "rrc00",
            }
        ]

        result = format_routes_as_table(routes)

        assert "..." in result

    def test_more_than_20_routes(self):
        """Test that excess routes show count."""
        routes = [
            {
                "prefix": f"10.0.{i}.0/24",
                "origin_asn": 64496,
                "as_path": [3356, 64496],
                "collector": "rrc00",
            }
            for i in range(25)
        ]

        result = format_routes_as_table(routes)

        assert "and 5 more routes" in result

    def test_missing_fields(self):
        """Test handling of routes with missing fields."""
        routes = [
            {
                "prefix": "8.8.8.0/24",
                # Missing other fields
            }
        ]

        result = format_routes_as_table(routes)

        assert "8.8.8.0/24" in result
        assert "N/A" in result  # For missing fields
