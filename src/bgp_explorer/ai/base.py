"""Abstract base class for AI backends."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class Role(str, Enum):
    """Message roles in conversation."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


@dataclass
class ToolCall:
    """Represents a tool call requested by the AI."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Result of executing a tool call."""

    tool_call_id: str
    output: str | None = None
    error: str | None = None


@dataclass
class ThinkingBlock:
    """Represents Claude's extended thinking."""

    thinking: str
    signature: str | None = None  # For redacted thinking


@dataclass
class Message:
    """A message in the conversation history."""

    role: Role
    content: str | None = None
    tool_calls: list[ToolCall] | None = None
    tool_results: list[ToolResult] | None = None
    thinking_blocks: list[ThinkingBlock] | None = None  # For extended thinking

    def to_dict(self) -> dict[str, Any]:
        """Convert message to dictionary."""
        d: dict[str, Any] = {"role": self.role.value}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                for tc in self.tool_calls
            ]
        if self.tool_results:
            d["tool_results"] = [
                {"tool_call_id": tr.tool_call_id, "output": tr.output, "error": tr.error}
                for tr in self.tool_results
            ]
        return d


@dataclass
class ChatEvent:
    """Event emitted during chat processing for live UI updates."""

    type: Literal["thinking", "thinking_summary", "tool_start", "tool_end", "text_delta", "complete", "error"]
    data: dict[str, Any] = field(default_factory=dict)


ChatCallback = Callable[[ChatEvent], None]


class AIBackend(ABC):
    """Abstract base class for AI backends.

    Implementations should handle:
    - Tool registration and execution
    - Conversation history management
    - Chat message processing
    """

    @abstractmethod
    async def chat(
        self, message: str, on_event: ChatCallback | None = None
    ) -> str:
        """Send a message and get a response.

        This method handles the full tool execution loop:
        1. Send message to AI
        2. If AI requests tool calls, execute them
        3. Send results back to AI
        4. Repeat until AI returns final text response

        Args:
            message: User message.
            on_event: Optional callback for live UI updates.

        Returns:
            Final text response from the AI.
        """
        pass

    @abstractmethod
    def register_tool(self, func: Callable[..., Any]) -> None:
        """Register a tool function for the AI to use.

        The function's docstring is used as the tool description.
        Type hints are used to generate the parameter schema.

        Args:
            func: The tool function to register.
        """
        pass

    @abstractmethod
    def clear_history(self) -> None:
        """Clear the conversation history."""
        pass

    def set_thinking_budget(self, budget: int) -> None:  # noqa: B027
        """Set the thinking budget for extended thinking.

        Args:
            budget: New thinking budget in tokens.

        Note:
            Not all backends support this. Default implementation does nothing.
        """
        pass

    @property
    @abstractmethod
    def history(self) -> list[Message]:
        """Get the conversation history."""
        pass
