"""Anthropic Claude AI backend implementation."""

import asyncio
import inspect
import json
import os
from collections.abc import Callable
from typing import Any, get_type_hints

import anthropic

from bgp_explorer.ai.base import (
    AIBackend,
    ChatCallback,
    ChatEvent,
    Message,
    Role,
    ThinkingBlock,
    ToolCall,
    ToolResult,
)
from bgp_explorer.ai.tools import get_tool_status_message


class ClaudeBackend(AIBackend):
    """Anthropic Claude AI backend.

    Uses the anthropic SDK to interact with Claude models.
    Supports tool calling and maintains conversation history.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        system_prompt: str | None = None,
        max_iterations: int = 20,
        max_tokens: int = 16000,
        thinking_budget: int = 32000,
    ):
        """Initialize the Claude backend.

        Args:
            api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model name to use.
            system_prompt: System prompt for the conversation.
            max_iterations: Maximum tool execution iterations.
            max_tokens: Maximum tokens in response.
            thinking_budget: Maximum tokens for extended thinking (Claude uses what it needs).

        Raises:
            ValueError: If no API key is provided or found.
        """
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. Provide api_key or set ANTHROPIC_API_KEY env var."
            )

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model_name = model
        self._system_prompt = system_prompt
        self._max_iterations = max_iterations
        self._max_tokens = max_tokens
        self._thinking_budget = thinking_budget
        self._tools: dict[str, Callable[..., Any]] = {}
        self._tool_schemas: list[dict[str, Any]] = []
        self._history: list[Message] = []

    @property
    def history(self) -> list[Message]:
        """Get the conversation history."""
        return self._history.copy()

    def clear_history(self) -> None:
        """Clear the conversation history."""
        self._history.clear()

    def register_tool(self, func: Callable[..., Any]) -> None:
        """Register a tool function.

        Args:
            func: The function to register as a tool.
        """
        self._tools[func.__name__] = func

        # Build tool schema from signature
        sig = inspect.signature(func)
        hints = get_type_hints(func)

        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            param_type = hints.get(param_name, str)
            json_type = self._python_type_to_json(param_type)

            properties[param_name] = {
                "type": json_type,
                "description": f"Parameter {param_name}",
            }

            if param.default == inspect.Parameter.empty:
                required.append(param_name)

        schema = {
            "name": func.__name__,
            "description": func.__doc__ or f"Function {func.__name__}",
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }
        self._tool_schemas.append(schema)

    def _python_type_to_json(self, python_type: type) -> str:
        """Convert Python type to JSON Schema type."""
        import types
        from typing import Union, get_args, get_origin

        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }

        # Handle Union types (e.g., list[str] | None or Union[list[str], None])
        # For Python 3.10+ union syntax (X | Y)
        if isinstance(python_type, types.UnionType):
            args = get_args(python_type)
            # Filter out NoneType and use the first real type
            non_none_types = [t for t in args if t is not type(None)]
            if non_none_types:
                python_type = non_none_types[0]

        # Handle typing.Union (e.g., Union[list[str], None])
        origin = get_origin(python_type)
        if origin is Union:
            args = get_args(python_type)
            non_none_types = [t for t in args if t is not type(None)]
            if non_none_types:
                python_type = non_none_types[0]
                origin = get_origin(python_type)

        # Handle generic types like list[str], dict[str, int]
        if origin is not None:
            python_type = origin

        return type_map.get(python_type, "string")

    async def chat(
        self, message: str, on_event: ChatCallback | None = None
    ) -> str:
        """Send a message and get a response.

        Handles the tool execution loop automatically.

        Args:
            message: User message.
            on_event: Optional callback for live UI updates.

        Returns:
            Final text response.
        """
        # Emit thinking event
        if on_event:
            on_event(ChatEvent(type="thinking"))

        # Add user message to history
        self._history.append(Message(role=Role.USER, content=message))

        # Build messages for API
        messages = self._build_messages()

        iterations = 0
        while iterations < self._max_iterations:
            iterations += 1

            # Call the model with extended thinking
            kwargs = {
                "model": self._model_name,
                "max_tokens": self._max_tokens,
                "messages": messages,
                "thinking": {
                    "type": "enabled",
                    "budget_tokens": self._thinking_budget,
                },
            }

            if self._system_prompt:
                kwargs["system"] = self._system_prompt

            if self._tool_schemas:
                kwargs["tools"] = self._tool_schemas

            response = self._client.messages.create(**kwargs)

            # Process response - capture thinking blocks for history
            tool_calls = []
            text_parts = []
            thinking_blocks = []

            for block in response.content:
                if block.type == "thinking":
                    # Extended thinking - must be preserved in history
                    thinking_blocks.append(ThinkingBlock(
                        thinking=block.thinking,
                        signature=getattr(block, 'signature', None),
                    ))
                    # Emit thinking summary for display
                    if on_event and block.thinking:
                        summary = self._extract_thinking_summary(block.thinking)
                        if summary:
                            on_event(ChatEvent(
                                type="thinking_summary",
                                data={"summary": summary, "iteration": iterations},
                            ))
                elif block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_calls.append(
                        ToolCall(
                            id=block.id,
                            name=block.name,
                            arguments=block.input,
                        )
                    )

            if tool_calls and response.stop_reason == "tool_use":
                # Execute tools and continue loop
                tool_results = await self._execute_tools(tool_calls, on_event)

                # Add assistant message with tool calls and thinking blocks
                self._history.append(
                    Message(
                        role=Role.ASSISTANT,
                        content=None,
                        tool_calls=tool_calls,
                        thinking_blocks=thinking_blocks if thinking_blocks else None,
                    )
                )

                # Add tool results
                self._history.append(
                    Message(role=Role.TOOL, content=None, tool_results=tool_results)
                )

                # Update messages for next iteration
                messages = self._build_messages()
            else:
                # No tool calls or end of turn - return text response
                response_text = "".join(text_parts)
                self._history.append(
                    Message(
                        role=Role.ASSISTANT,
                        content=response_text,
                        thinking_blocks=thinking_blocks if thinking_blocks else None,
                    )
                )
                if on_event:
                    on_event(ChatEvent(type="complete"))
                return response_text

        return "Max iterations reached without final response."

    def _extract_thinking_summary(self, thinking_text: str, max_length: int = 200) -> str | None:
        """Extract a concise summary from extended thinking text.

        Looks for key phrases that indicate the model's intent and extracts
        a human-readable summary for display. Handles multi-line thoughts by
        continuing to read until a complete sentence is formed.

        Args:
            thinking_text: The full extended thinking text.
            max_length: Maximum length of the summary.

        Returns:
            A concise summary string, or None if no meaningful summary found.
        """
        if not thinking_text:
            return None

        # Key phrases that indicate intent (prioritized)
        key_phrases = [
            "I need to",
            "I should",
            "Let me",
            "First,",
            "Next,",
            "Now I",
            "I'll",
            "I will",
            "To answer",
            "To investigate",
            "To find",
            "Looking at",
            "Checking",
            "Analyzing",
        ]

        lines = thinking_text.split("\n")

        # Find the first line containing a key phrase and build complete thought
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            for phrase in key_phrases:
                if phrase.lower() in line.lower():
                    # Start building summary from this line
                    summary = line

                    # Remove leading phrases like "Okay, " or "Alright, "
                    for prefix in ["Okay, ", "Alright, ", "Ok, ", "So, ", "Well, "]:
                        if summary.startswith(prefix):
                            summary = summary[len(prefix):]

                    # If line ends mid-sentence, continue reading subsequent lines
                    # A sentence is complete if it ends with terminal punctuation
                    # Note: colon excluded because it often introduces lists
                    terminal_punctuation = (".", "!", "?", ")")
                    j = i + 1
                    while (
                        not summary.rstrip().endswith(terminal_punctuation)
                        and j < len(lines)
                        and len(summary) < max_length
                    ):
                        next_line = lines[j].strip()
                        j += 1
                        if not next_line:
                            # Empty line = paragraph break, stop here
                            break
                        # Append with space
                        summary = summary + " " + next_line

                    # Truncate if too long, trying to break at word boundary
                    if len(summary) > max_length:
                        truncated = summary[: max_length - 3]
                        # Try to break at last space
                        last_space = truncated.rfind(" ")
                        if last_space > max_length // 2:
                            truncated = truncated[:last_space]
                        summary = truncated + "..."

                    return summary

        # Fallback: use the first non-empty line if it's meaningful
        for line in lines[:5]:
            line = line.strip()
            if line and len(line) > 20:
                if len(line) > max_length:
                    line = line[: max_length - 3] + "..."
                return line

        return None

    async def _execute_tools(
        self,
        tool_calls: list[ToolCall],
        on_event: ChatCallback | None = None,
    ) -> list[ToolResult]:
        """Execute tool calls and return results.

        Args:
            tool_calls: List of tool calls to execute.
            on_event: Optional callback for live UI updates.

        Returns:
            List of tool results.
        """
        results = []

        for tc in tool_calls:
            # Emit tool_start event
            if on_event:
                status_msg = get_tool_status_message(tc.name, tc.arguments)
                on_event(ChatEvent(
                    type="tool_start",
                    data={"tool": tc.name, "message": status_msg},
                ))

            func = self._tools.get(tc.name)
            if func is None:
                results.append(
                    ToolResult(
                        tool_call_id=tc.id,
                        error=f"Unknown tool: {tc.name}",
                    )
                )
                if on_event:
                    on_event(ChatEvent(
                        type="tool_end",
                        data={"tool": tc.name, "error": f"Unknown tool: {tc.name}"},
                    ))
                continue

            try:
                # Check if function is async
                if asyncio.iscoroutinefunction(func):
                    output = await func(**tc.arguments)
                else:
                    output = func(**tc.arguments)

                # Convert output to string
                if not isinstance(output, str):
                    output = json.dumps(output, default=str)

                results.append(ToolResult(tool_call_id=tc.id, output=output))

                # Emit tool_end event
                if on_event:
                    on_event(ChatEvent(
                        type="tool_end",
                        data={"tool": tc.name},
                    ))

            except Exception as e:
                results.append(
                    ToolResult(tool_call_id=tc.id, error=str(e))
                )
                if on_event:
                    on_event(ChatEvent(
                        type="tool_end",
                        data={"tool": tc.name, "error": str(e)},
                    ))

        return results

    def _build_messages(self) -> list[dict[str, Any]]:
        """Build messages list for Claude API from history.

        Returns:
            List of message dictionaries.
        """
        messages = []

        for msg in self._history:
            if msg.role == Role.USER:
                messages.append({"role": "user", "content": msg.content})

            elif msg.role == Role.ASSISTANT:
                content = []

                # Add thinking blocks first (required by API when thinking is enabled)
                if msg.thinking_blocks:
                    for tb in msg.thinking_blocks:
                        content.append({
                            "type": "thinking",
                            "thinking": tb.thinking,
                            "signature": tb.signature,
                        })

                # Add tool calls
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        content.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        })

                # Add text content
                if msg.content:
                    content.append({
                        "type": "text",
                        "text": msg.content,
                    })

                if content:
                    messages.append({"role": "assistant", "content": content})

            elif msg.role == Role.TOOL:
                if msg.tool_results:
                    content = []
                    for tr in msg.tool_results:
                        content.append({
                            "type": "tool_result",
                            "tool_use_id": tr.tool_call_id,
                            "content": tr.output or tr.error,
                            "is_error": tr.error is not None,
                        })
                    messages.append({"role": "user", "content": content})

        return messages
