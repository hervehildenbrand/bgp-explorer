"""Tests for AI backend base class."""

import pytest

from bgp_explorer.ai.base import AIBackend, Message, Role, ToolCall, ToolResult


class TestMessage:
    """Tests for Message dataclass."""

    def test_create_user_message(self):
        """Test creating a user message."""
        msg = Message(role=Role.USER, content="Hello")
        assert msg.role == Role.USER
        assert msg.content == "Hello"
        assert msg.tool_calls is None

    def test_create_assistant_message(self):
        """Test creating an assistant message."""
        msg = Message(role=Role.ASSISTANT, content="Hi there!")
        assert msg.role == Role.ASSISTANT

    def test_create_message_with_tool_calls(self):
        """Test creating a message with tool calls."""
        tool_calls = [ToolCall(id="1", name="lookup_prefix", arguments={"prefix": "8.8.8.0/24"})]
        msg = Message(role=Role.ASSISTANT, content=None, tool_calls=tool_calls)
        assert msg.tool_calls == tool_calls

    def test_message_to_dict(self):
        """Test converting message to dictionary."""
        msg = Message(role=Role.USER, content="Hello")
        d = msg.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "Hello"


class TestToolCall:
    """Tests for ToolCall dataclass."""

    def test_create_tool_call(self):
        """Test creating a tool call."""
        tc = ToolCall(id="123", name="lookup_prefix", arguments={"prefix": "8.8.8.0/24"})
        assert tc.id == "123"
        assert tc.name == "lookup_prefix"
        assert tc.arguments["prefix"] == "8.8.8.0/24"


class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_create_tool_result(self):
        """Test creating a tool result."""
        tr = ToolResult(tool_call_id="123", output="Result data")
        assert tr.tool_call_id == "123"
        assert tr.output == "Result data"
        assert tr.error is None

    def test_create_tool_result_with_error(self):
        """Test creating a tool result with error."""
        tr = ToolResult(tool_call_id="123", output=None, error="Something went wrong")
        assert tr.error == "Something went wrong"


class TestAIBackendAbstract:
    """Tests for AIBackend abstract class."""

    def test_cannot_instantiate_abstract(self):
        """Test that AIBackend cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AIBackend()
