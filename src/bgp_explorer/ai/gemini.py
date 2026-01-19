"""Google Gemini AI backend implementation."""

import asyncio
import inspect
import json
import os
from typing import Any, Callable, Optional, get_type_hints

import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool
from google.oauth2.credentials import Credentials

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


class GeminiBackend(AIBackend):
    """Google Gemini AI backend.

    Uses the google-generativeai SDK to interact with Gemini models.
    Supports tool calling and maintains conversation history.
    Supports both API key and OAuth authentication.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        credentials: Optional[Credentials] = None,
        model: str = "gemini-1.5-flash",
        system_prompt: Optional[str] = None,
        max_iterations: int = 10,
    ):
        """Initialize the Gemini backend.

        Args:
            api_key: Gemini API key. Falls back to GEMINI_API_KEY env var.
            credentials: OAuth credentials (alternative to api_key).
            model: Model name to use.
            system_prompt: System prompt for the conversation.
            max_iterations: Maximum tool execution iterations.

        Raises:
            ValueError: If neither API key nor OAuth credentials are provided.
        """
        if credentials:
            # Use OAuth credentials
            genai.configure(credentials=credentials)
        else:
            # Use API key
            api_key = api_key or os.environ.get("GEMINI_API_KEY")
            if not api_key:
                raise ValueError(
                    "No authentication provided. Either:\n"
                    "  - Set GEMINI_API_KEY environment variable\n"
                    "  - Use --oauth flag for Google login"
                )
            genai.configure(api_key=api_key)

        self._model_name = model
        self._system_prompt = system_prompt
        self._max_iterations = max_iterations
        self._tools: dict[str, Callable[..., Any]] = {}
        self._tool_declarations: list[FunctionDeclaration] = []
        self._history: list[Message] = []
        self._model: Optional[genai.GenerativeModel] = None

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

        # Build function declaration from signature
        sig = inspect.signature(func)
        hints = get_type_hints(func)

        parameters = {
            "type": "object",
            "properties": {},
            "required": [],
        }

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            param_type = hints.get(param_name, str)
            json_type = self._python_type_to_json(param_type)

            parameters["properties"][param_name] = {
                "type": json_type,
                "description": f"Parameter {param_name}",
            }

            if param.default == inspect.Parameter.empty:
                parameters["required"].append(param_name)

        declaration = FunctionDeclaration(
            name=func.__name__,
            description=func.__doc__ or f"Function {func.__name__}",
            parameters=parameters,
        )
        self._tool_declarations.append(declaration)

        # Reset model to pick up new tools
        self._model = None

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

    def _get_model(self) -> genai.GenerativeModel:
        """Get or create the generative model."""
        if self._model is None:
            tools = None
            if self._tool_declarations:
                tools = [Tool(function_declarations=self._tool_declarations)]

            self._model = genai.GenerativeModel(
                self._model_name,
                tools=tools,
                system_instruction=self._system_prompt,
            )
        return self._model

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

        model = self._get_model()

        # Build contents for API
        contents = self._build_contents()

        iterations = 0
        while iterations < self._max_iterations:
            iterations += 1

            # Call the model
            response = await model.generate_content_async(contents)

            if not response.candidates:
                return "No response generated."

            candidate = response.candidates[0]
            parts = candidate.content.parts

            # Check for tool calls
            tool_calls = []
            text_parts = []

            for part in parts:
                if hasattr(part, "function_call") and part.function_call:
                    fc = part.function_call
                    tool_calls.append(
                        ToolCall(
                            id=fc.name,  # Gemini uses name as ID
                            name=fc.name,
                            arguments=dict(fc.args) if fc.args else {},
                        )
                    )
                elif hasattr(part, "text") and part.text:
                    text_parts.append(part.text)

            if tool_calls:
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

                # Update contents for next iteration
                contents = self._build_contents()
            else:
                # No tool calls - return text response
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

    def _build_contents(self) -> list[dict[str, Any]]:
        """Build contents list for Gemini API from history.

        Returns:
            List of content dictionaries.
        """
        contents = []

        for msg in self._history:
            if msg.role == Role.USER:
                contents.append({"role": "user", "parts": [msg.content]})

            elif msg.role == Role.ASSISTANT:
                if msg.tool_calls:
                    # Assistant message with function calls
                    parts = []
                    for tc in msg.tool_calls:
                        parts.append(
                            genai.protos.Part(
                                function_call=genai.protos.FunctionCall(
                                    name=tc.name,
                                    args=tc.arguments,
                                )
                            )
                        )
                    contents.append({"role": "model", "parts": parts})
                elif msg.content:
                    contents.append({"role": "model", "parts": [msg.content]})

            elif msg.role == Role.TOOL:
                if msg.tool_results:
                    parts = []
                    for tr in msg.tool_results:
                        parts.append(
                            genai.protos.Part(
                                function_response=genai.protos.FunctionResponse(
                                    name=tr.tool_call_id,
                                    response={"result": tr.output or tr.error},
                                )
                            )
                        )
                    contents.append({"role": "user", "parts": parts})

        return contents
