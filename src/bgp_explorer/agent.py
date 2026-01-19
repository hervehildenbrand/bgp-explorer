"""Agent orchestration for BGP Explorer.

The agent coordinates between the AI backend, data sources, and output formatting.
"""

import asyncio
from typing import Optional

from bgp_explorer.ai.base import AIBackend, ChatCallback
from bgp_explorer.ai.claude import ClaudeBackend
from bgp_explorer.ai.gemini import GeminiBackend
from bgp_explorer.ai.tools import BGPTools
from bgp_explorer.config import AIBackendType, Settings
from bgp_explorer.output import OutputFormatter
from bgp_explorer.sources.bgp_radar import BgpRadarClient
from bgp_explorer.sources.globalping import GlobalpingClient
from bgp_explorer.sources.monocle import MonocleClient
from bgp_explorer.sources.peeringdb import PeeringDBClient
from bgp_explorer.sources.ripe_stat import RipeStatClient


class BGPExplorerAgent:
    """Main agent that orchestrates BGP exploration.

    Manages:
    - AI backend initialization and tool registration
    - Data source lifecycle (RIPE Stat, bgp-radar)
    - Message routing and response handling
    """

    def __init__(
        self,
        settings: Settings,
        output: OutputFormatter,
    ):
        """Initialize the agent.

        Args:
            settings: Application settings.
            output: Output formatter for display.
        """
        self._settings = settings
        self._output = output
        self._ai: Optional[AIBackend] = None
        self._ripe_stat: Optional[RipeStatClient] = None
        self._bgp_radar: Optional[BgpRadarClient] = None
        self._globalping: Optional[GlobalpingClient] = None
        self._peeringdb: Optional[PeeringDBClient] = None
        self._monocle: Optional[MonocleClient] = None
        self._tools: Optional[BGPTools] = None
        self._running = False

    async def initialize(self) -> None:
        """Initialize the agent and all components.

        Starts data sources and configures the AI backend with tools.
        """
        self._output.display_info("Initializing BGP Explorer...")

        # Initialize RIPE Stat client
        self._ripe_stat = RipeStatClient()
        await self._ripe_stat.connect()
        self._output.display_info("✓ Connected to RIPE Stat")

        # Initialize bgp-radar client (optional)
        try:
            self._bgp_radar = BgpRadarClient(
                binary_path=self._settings.bgp_radar_path,
                collectors=self._settings.collectors,
            )
            if await self._bgp_radar.is_available():
                await self._bgp_radar.start()
                self._output.display_info(
                    f"✓ Started bgp-radar (collectors: {', '.join(self._settings.collectors)})"
                )
            else:
                self._output.display_info(
                    "⚠ bgp-radar not found - real-time anomaly detection disabled"
                )
                self._bgp_radar = None
        except Exception as e:
            self._output.display_info(f"⚠ bgp-radar unavailable: {e}")
            self._bgp_radar = None

        # Initialize Globalping client (optional)
        try:
            self._globalping = GlobalpingClient()
            await self._globalping.connect()
            self._output.display_info("✓ Connected to Globalping")
        except Exception as e:
            self._output.display_info(f"⚠ Globalping unavailable: {e}")
            self._globalping = None

        # Initialize PeeringDB client (optional)
        try:
            self._peeringdb = PeeringDBClient()
            await self._peeringdb.connect(force_refresh=self._settings.refresh_peeringdb)
            self._output.display_info("✓ PeeringDB data loaded")
        except Exception as e:
            self._output.display_info(f"⚠ PeeringDB unavailable: {e}")
            self._peeringdb = None

        # Initialize Monocle client (optional)
        try:
            self._monocle = MonocleClient()
            if await self._monocle.is_available():
                self._output.display_info("✓ Monocle available (AS relationship data)")
            else:
                self._output.display_info(
                    "⚠ Monocle not found - AS relationship data disabled"
                )
                self._monocle = None
        except Exception as e:
            self._output.display_info(f"⚠ Monocle unavailable: {e}")
            self._monocle = None

        # Initialize AI backend
        self._ai = self._create_ai_backend()
        backend_info = self._settings.ai_backend.value
        if self._settings.ai_backend == AIBackendType.CLAUDE:
            backend_info = f"claude/{self._settings.claude_model.value}"
        self._output.display_info(f"✓ AI backend ready ({backend_info})")

        # Initialize and register tools
        self._tools = BGPTools(
            ripe_stat=self._ripe_stat,
            bgp_radar=self._bgp_radar,
            globalping=self._globalping,
            peeringdb=self._peeringdb,
            monocle=self._monocle,
        )
        for tool in self._tools.get_all_tools():
            self._ai.register_tool(tool)
        self._output.display_info(f"✓ Registered {len(self._tools.get_all_tools())} tools")

        self._running = True
        self._output.display_info("")

    def _create_ai_backend(self) -> AIBackend:
        """Create the appropriate AI backend based on settings.

        Returns:
            Configured AI backend instance.

        Raises:
            ValueError: If backend type is not supported.
        """
        if self._settings.ai_backend == AIBackendType.GEMINI:
            if self._settings.use_oauth:
                # Use OAuth authentication
                from bgp_explorer.ai.oauth import get_oauth_credentials

                credentials = get_oauth_credentials(
                    client_secret_path=self._settings.oauth_client_secret
                )
                return GeminiBackend(
                    credentials=credentials,
                    model=self._settings.gemini_model,
                    system_prompt=self._settings.system_prompt,
                )
            else:
                # Use API key authentication
                return GeminiBackend(
                    api_key=self._settings.get_api_key(),
                    model=self._settings.gemini_model,
                    system_prompt=self._settings.system_prompt,
                )
        elif self._settings.ai_backend == AIBackendType.CLAUDE:
            return ClaudeBackend(
                api_key=self._settings.get_api_key(),
                model=self._settings.claude_model.model_id,
                system_prompt=self._settings.system_prompt,
            )
        else:
            raise ValueError(f"Unknown AI backend: {self._settings.ai_backend}")

    async def chat(
        self, message: str, on_event: Optional[ChatCallback] = None
    ) -> str:
        """Process a user message and return the response.

        Args:
            message: User message.
            on_event: Optional callback for live UI updates.

        Returns:
            AI response.

        Raises:
            RuntimeError: If agent is not initialized.
        """
        if not self._running or not self._ai:
            raise RuntimeError("Agent not initialized. Call initialize() first.")

        return await self._ai.chat(message, on_event=on_event)

    async def handle_command(self, command: str) -> bool:
        """Handle special commands.

        Args:
            command: Command string (without leading /).

        Returns:
            True if command was handled, False otherwise.
        """
        parts = command.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else None

        if cmd == "export":
            path = self._output.export_conversation(args)
            self._output.display_info(f"Conversation exported to: {path}")
            return True

        elif cmd == "clear":
            if self._ai:
                self._ai.clear_history()
            self._output.clear_history()
            return True

        elif cmd == "help":
            self._output.display_welcome()
            return True

        return False

    async def shutdown(self) -> None:
        """Shutdown the agent and cleanup resources."""
        self._running = False

        if self._bgp_radar:
            await self._bgp_radar.stop()

        if self._globalping:
            await self._globalping.disconnect()

        if self._peeringdb:
            await self._peeringdb.disconnect()

        if self._monocle:
            await self._monocle.disconnect()

        if self._ripe_stat:
            await self._ripe_stat.disconnect()

        self._output.display_info("BGP Explorer stopped.")

    @property
    def is_running(self) -> bool:
        """Check if agent is running."""
        return self._running
