"""Tests for consolidated MCP server tools (36 → 10 tool consolidation)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.mcp_server import parse_sections, build_response


# =============================================================================
# parse_sections tests
# =============================================================================


class TestParseSections:
    """Tests for the section parsing helper."""

    def test_none_returns_defaults(self):
        result = parse_sections(None, {"a", "b", "c"}, ["a"])
        assert result == ["a"]

    def test_valid_sections_accepted(self):
        result = parse_sections(["a", "c"], {"a", "b", "c"}, ["a"])
        assert result == ["a", "c"]

    def test_invalid_section_returns_error(self):
        """Invalid sections should return a string error, not raise."""
        result = parse_sections(["invalid"], {"a", "b"}, ["a"])
        assert isinstance(result, str)
        assert "invalid" in result.lower()

    def test_empty_list_returns_defaults(self):
        result = parse_sections([], {"a", "b"}, ["a"])
        assert result == ["a"]

    def test_preserves_order(self):
        result = parse_sections(["c", "a", "b"], {"a", "b", "c"}, ["a"])
        assert result == ["c", "a", "b"]

    def test_mixed_valid_invalid_returns_error(self):
        result = parse_sections(["a", "bogus"], {"a", "b"}, ["a"])
        assert isinstance(result, str)
        assert "bogus" in result.lower()


# =============================================================================
# build_response tests
# =============================================================================


class TestBuildResponse:
    """Tests for the response builder."""

    @pytest.mark.asyncio
    async def test_calls_handlers_in_order(self):
        call_order = []

        async def handler_a():
            call_order.append("a")
            return ["Section A"]

        async def handler_b():
            call_order.append("b")
            return ["Section B"]

        result = await build_response(["a", "b"], {"a": handler_a, "b": handler_b})
        assert call_order == ["a", "b"]
        assert "Section A" in result
        assert "Section B" in result

    @pytest.mark.asyncio
    async def test_skips_missing_handlers(self):
        async def handler_a():
            return ["Section A"]

        result = await build_response(["a", "missing"], {"a": handler_a})
        assert "Section A" in result

    @pytest.mark.asyncio
    async def test_joins_with_newlines(self):
        async def handler_a():
            return ["Line 1", "Line 2"]

        result = await build_response(["a"], {"a": handler_a})
        assert result == "Line 1\nLine 2"

    @pytest.mark.asyncio
    async def test_empty_sections(self):
        result = await build_response([], {})
        assert result == ""
