"""Anthropic Claude AI backend implementation."""

import asyncio
import inspect
import json
import os
from typing import Any, Callable, Optional, get_type_hints

import anthropic

from bgp_explorer.ai.base import (
    AIBackend,
    ChatCallback,
    ChatEvent,
    Message,
    Role,
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
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        system_prompt: Optional[str] = None,
        max_iterations: int = 10,
        max_tokens: int = 4096,
    ):
        """Initialize the Claude backend.

        Args:
            api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model name to use.
            system_prompt: System prompt for the conversation.
            max_iterations: Maximum tool execution iterations.
            max_tokens: Maximum tokens in response.

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
        self, message: str, on_event: Optional[ChatCallback] = None
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

            # Call the model
            kwargs = {
                "model": self._model_name,
                "max_tokens": self._max_tokens,
                "messages": messages,
            }

            if self._system_prompt:
                kwargs["system"] = self._system_prompt

            if self._tool_schemas:
                kwargs["tools"] = self._tool_schemas

            response = self._client.messages.create(**kwargs)

            # Process response
            tool_calls = []
            text_parts = []

            for block in response.content:
                if block.type == "text":
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

                # Add assistant message with tool calls
                self._history.append(
                    Message(role=Role.ASSISTANT, content=None, tool_calls=tool_calls)
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
                    Message(role=Role.ASSISTANT, content=response_text)
                )
                if on_event:
                    on_event(ChatEvent(type="complete"))
                return response_text

        return "Max iterations reached without final response."

    async def _execute_tools(
        self,
        tool_calls: list[ToolCall],
        on_event: Optional[ChatCallback] = None,
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
                if msg.tool_calls:
                    # Assistant message with tool use
                    content = []
                    for tc in msg.tool_calls:
                        content.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        })
                    messages.append({"role": "assistant", "content": content})
                elif msg.content:
                    messages.append({"role": "assistant", "content": msg.content})

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
