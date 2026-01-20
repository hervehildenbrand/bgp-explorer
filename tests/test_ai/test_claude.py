"""Tests for Claude AI backend."""

from unittest.mock import MagicMock, patch

import pytest

from bgp_explorer.ai.base import Message, Role
from bgp_explorer.ai.claude import ClaudeBackend


class TestClaudeBackend:
    """Tests for ClaudeBackend."""

    @pytest.fixture
    def mock_anthropic(self):
        """Create a mock anthropic module."""
        with patch("bgp_explorer.ai.claude.anthropic") as mock:
            yield mock

    def test_init_with_api_key(self, mock_anthropic):
        """Test initialization with API key."""
        ClaudeBackend(api_key="test-key")
        mock_anthropic.Anthropic.assert_called_once_with(api_key="test-key")

    def test_init_from_env(self, mock_anthropic):
        """Test initialization from environment variable."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "env-key"}):
            ClaudeBackend()
            mock_anthropic.Anthropic.assert_called_once_with(api_key="env-key")

    def test_init_missing_api_key(self, mock_anthropic):
        """Test initialization fails without API key."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                ClaudeBackend()

    def test_register_tool(self, mock_anthropic):
        """Test registering a tool."""
        backend = ClaudeBackend(api_key="test-key")

        def sample_tool(prefix: str) -> str:
            """Look up a prefix."""
            return f"Result for {prefix}"

        backend.register_tool(sample_tool)
        assert "sample_tool" in backend._tools

    def test_register_multiple_tools(self, mock_anthropic):
        """Test registering multiple tools."""
        backend = ClaudeBackend(api_key="test-key")

        def tool1(x: str) -> str:
            """Tool 1."""
            return x

        def tool2(y: int) -> int:
            """Tool 2."""
            return y

        backend.register_tool(tool1)
        backend.register_tool(tool2)

        assert len(backend._tools) == 2

    def test_conversation_history_empty(self, mock_anthropic):
        """Test conversation history starts empty."""
        backend = ClaudeBackend(api_key="test-key")
        assert backend.history == []

    def test_clear_history(self, mock_anthropic):
        """Test clearing conversation history."""
        backend = ClaudeBackend(api_key="test-key")
        backend._history = [Message(role=Role.USER, content="test")]
        backend.clear_history()
        assert backend.history == []

    def test_system_prompt(self, mock_anthropic):
        """Test setting system prompt."""
        backend = ClaudeBackend(
            api_key="test-key",
            system_prompt="You are a BGP expert.",
        )
        assert backend._system_prompt == "You are a BGP expert."

    def _create_mock_stream(self, text_content: str, stop_reason: str = "end_turn"):
        """Helper to create mock streaming events."""
        # Create mock events for streaming
        events = [
            # Text content block
            MagicMock(
                type="content_block_start",
                content_block=MagicMock(type="text"),
            ),
            MagicMock(
                type="content_block_delta",
                delta=MagicMock(type="text_delta", text=text_content),
            ),
            MagicMock(type="content_block_stop"),
            # Message complete
            MagicMock(
                type="message_delta",
                delta=MagicMock(stop_reason=stop_reason),
            ),
            MagicMock(type="message_stop"),
        ]
        return events

    @pytest.mark.asyncio
    async def test_chat_simple_response(self, mock_anthropic):
        """Test simple chat response without tool calls."""
        # Set up mock streaming response
        mock_stream = MagicMock()
        mock_stream.__enter__ = MagicMock(return_value=mock_stream)
        mock_stream.__exit__ = MagicMock(return_value=False)
        mock_stream.__iter__ = MagicMock(return_value=iter(self._create_mock_stream("Hello!")))

        mock_client = MagicMock()
        mock_client.messages.stream = MagicMock(return_value=mock_stream)
        mock_anthropic.Anthropic.return_value = mock_client

        backend = ClaudeBackend(api_key="test-key")
        response = await backend.chat("Hi")

        assert response == "Hello!"
        assert len(backend.history) == 2  # user + assistant

    @pytest.mark.asyncio
    async def test_chat_adds_to_history(self, mock_anthropic):
        """Test that chat adds messages to history."""
        # Set up mock streaming response
        mock_stream = MagicMock()
        mock_stream.__enter__ = MagicMock(return_value=mock_stream)
        mock_stream.__exit__ = MagicMock(return_value=False)
        mock_stream.__iter__ = MagicMock(return_value=iter(self._create_mock_stream("Response")))

        mock_client = MagicMock()
        mock_client.messages.stream = MagicMock(return_value=mock_stream)
        mock_anthropic.Anthropic.return_value = mock_client

        backend = ClaudeBackend(api_key="test-key")
        await backend.chat("Hello")

        assert backend.history[0].role == Role.USER
        assert backend.history[0].content == "Hello"
        assert backend.history[1].role == Role.ASSISTANT
        assert backend.history[1].content == "Response"

    def test_model_name_default(self, mock_anthropic):
        """Test default model name."""
        backend = ClaudeBackend(api_key="test-key")
        assert backend._model_name == "claude-sonnet-4-5-20250929"

    def test_model_name_custom(self, mock_anthropic):
        """Test custom model name."""
        backend = ClaudeBackend(api_key="test-key", model="claude-opus-4-5-20251124")
        assert backend._model_name == "claude-opus-4-5-20251124"

    def test_max_iterations(self, mock_anthropic):
        """Test max iterations for tool loop."""
        backend = ClaudeBackend(api_key="test-key", max_iterations=5)
        assert backend._max_iterations == 5

    def test_max_iterations_default(self, mock_anthropic):
        """Test default max iterations."""
        backend = ClaudeBackend(api_key="test-key")
        assert backend._max_iterations == 20
