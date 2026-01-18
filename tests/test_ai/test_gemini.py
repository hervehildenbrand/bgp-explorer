"""Tests for Gemini AI backend."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.ai.base import Message, Role, ToolCall
from bgp_explorer.ai.gemini import GeminiBackend


class TestGeminiBackend:
    """Tests for GeminiBackend."""

    @pytest.fixture
    def mock_genai(self):
        """Create a mock google.generativeai module."""
        with patch("bgp_explorer.ai.gemini.genai") as mock:
            yield mock

    def test_init_with_api_key(self, mock_genai):
        """Test initialization with API key."""
        backend = GeminiBackend(api_key="test-key")
        mock_genai.configure.assert_called_once_with(api_key="test-key")

    def test_init_from_env(self, mock_genai):
        """Test initialization from environment variable."""
        with patch.dict("os.environ", {"GEMINI_API_KEY": "env-key"}):
            backend = GeminiBackend()
            mock_genai.configure.assert_called_once_with(api_key="env-key")

    def test_init_missing_api_key(self, mock_genai):
        """Test initialization fails without API key."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="GEMINI_API_KEY"):
                GeminiBackend()

    def test_register_tool(self, mock_genai):
        """Test registering a tool."""
        backend = GeminiBackend(api_key="test-key")

        def sample_tool(prefix: str) -> str:
            """Look up a prefix."""
            return f"Result for {prefix}"

        backend.register_tool(sample_tool)
        assert "sample_tool" in backend._tools

    def test_register_multiple_tools(self, mock_genai):
        """Test registering multiple tools."""
        backend = GeminiBackend(api_key="test-key")

        def tool1(x: str) -> str:
            """Tool 1."""
            return x

        def tool2(y: int) -> int:
            """Tool 2."""
            return y

        backend.register_tool(tool1)
        backend.register_tool(tool2)

        assert len(backend._tools) == 2

    def test_conversation_history_empty(self, mock_genai):
        """Test conversation history starts empty."""
        backend = GeminiBackend(api_key="test-key")
        assert backend.history == []

    def test_clear_history(self, mock_genai):
        """Test clearing conversation history."""
        backend = GeminiBackend(api_key="test-key")
        backend._history = [Message(role=Role.USER, content="test")]
        backend.clear_history()
        assert backend.history == []

    def test_system_prompt(self, mock_genai):
        """Test setting system prompt."""
        backend = GeminiBackend(
            api_key="test-key",
            system_prompt="You are a BGP expert.",
        )
        assert backend._system_prompt == "You are a BGP expert."

    @pytest.mark.asyncio
    async def test_chat_simple_response(self, mock_genai):
        """Test simple chat response without tool calls."""
        # Set up mock response
        mock_response = MagicMock()
        mock_response.candidates = [MagicMock()]
        mock_response.candidates[0].content.parts = [MagicMock(text="Hello!")]
        mock_response.candidates[0].content.parts[0].function_call = None

        mock_model = MagicMock()
        mock_model.generate_content_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model

        backend = GeminiBackend(api_key="test-key")
        response = await backend.chat("Hi")

        assert response == "Hello!"
        assert len(backend.history) == 2  # user + assistant

    @pytest.mark.asyncio
    async def test_chat_adds_to_history(self, mock_genai):
        """Test that chat adds messages to history."""
        mock_response = MagicMock()
        mock_response.candidates = [MagicMock()]
        mock_response.candidates[0].content.parts = [MagicMock(text="Response")]
        mock_response.candidates[0].content.parts[0].function_call = None

        mock_model = MagicMock()
        mock_model.generate_content_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model

        backend = GeminiBackend(api_key="test-key")
        await backend.chat("Hello")

        assert backend.history[0].role == Role.USER
        assert backend.history[0].content == "Hello"
        assert backend.history[1].role == Role.ASSISTANT
        assert backend.history[1].content == "Response"

    def test_model_name_default(self, mock_genai):
        """Test default model name."""
        backend = GeminiBackend(api_key="test-key")
        assert backend._model_name == "gemini-1.5-flash"

    def test_model_name_custom(self, mock_genai):
        """Test custom model name."""
        backend = GeminiBackend(api_key="test-key", model="gemini-1.5-pro")
        assert backend._model_name == "gemini-1.5-pro"

    def test_max_iterations(self, mock_genai):
        """Test max iterations for tool loop."""
        backend = GeminiBackend(api_key="test-key", max_iterations=5)
        assert backend._max_iterations == 5

    def test_max_iterations_default(self, mock_genai):
        """Test default max iterations."""
        backend = GeminiBackend(api_key="test-key")
        assert backend._max_iterations == 10
