"""Agent orchestration for BGP Explorer.

The agent coordinates between the AI backend, data sources, and output formatting.
"""

from bgp_explorer.ai.base import AIBackend, ChatCallback
from bgp_explorer.ai.claude import ClaudeBackend
from bgp_explorer.ai.tools import BGPTools
from bgp_explorer.config import Settings
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
        self._ai: AIBackend | None = None
        self._ripe_stat: RipeStatClient | None = None
        self._bgp_radar: BgpRadarClient | None = None
        self._globalping: GlobalpingClient | None = None
        self._peeringdb: PeeringDBClient | None = None
        self._monocle: MonocleClient | None = None
        self._tools: BGPTools | None = None
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

        # Initialize bgp-radar client (optional - for real-time monitoring)
        bgp_radar = BgpRadarClient(
            binary_path=self._settings.bgp_radar_path,
            collectors=self._settings.collectors,
        )
        if await bgp_radar.is_available():
            self._bgp_radar = bgp_radar
            # Wire up event callback for real-time display
            self._bgp_radar.set_event_callback(self._on_bgp_event)
            self._output.display_info(
                "✓ bgp-radar available (use /monitor start or ask to begin monitoring)"
            )
        else:
            self._output.display_info("⚠ bgp-radar not found - real-time monitoring unavailable")

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

        # Initialize Monocle client (required)
        self._monocle = MonocleClient()
        if not await self._monocle.is_available():
            raise RuntimeError(
                "monocle is required but not found. Install from: https://github.com/bgpkit/monocle"
            )
        self._output.display_info("✓ Monocle available (AS relationship data)")

        # Initialize AI backend (Claude)
        self._ai = ClaudeBackend(
            api_key=self._settings.get_api_key(),
            model=self._settings.claude_model.model_id,
            system_prompt=self._settings.system_prompt,
            thinking_budget=self._settings.thinking_budget,
            max_tokens=self._settings.max_tokens,
        )
        self._output.display_info(
            f"✓ AI backend ready (claude/{self._settings.claude_model.value})"
        )

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

    async def chat(self, message: str, on_event: ChatCallback | None = None) -> str:
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
            import click

            # Clear terminal screen
            click.clear()
            # Clear conversation history
            if self._ai:
                self._ai.clear_history()
            self._output.clear_history()
            # Re-display welcome after clear
            self._output.display_welcome()
            return True

        elif cmd == "help":
            self._output.display_welcome()
            return True

        elif cmd == "monitor":
            await self._handle_monitor_command(args)
            return True

        elif cmd == "thinking":
            self._handle_thinking_command(args)
            return True

        return False

    def _handle_thinking_command(self, args: str | None) -> None:
        """Handle /thinking command to view or set thinking budget.

        Args:
            args: Optional new budget value (1024-16000).
        """
        if not self._ai:
            self._output.display_error("AI backend not initialized.")
            return

        if not args:
            # Show current budget
            current = self._settings.thinking_budget
            self._output.display_info(
                f"Current thinking budget: {current:,} tokens\n"
                f"Usage: /thinking <budget>  (range: 1024-16000)\n"
                f"Example: /thinking 4000"
            )
            return

        try:
            new_budget = int(args.strip())
            if new_budget < 1024 or new_budget > 16000:
                self._output.display_error("Thinking budget must be between 1024 and 16000 tokens.")
                return

            # Update settings and AI backend
            self._settings.thinking_budget = new_budget
            self._ai.set_thinking_budget(new_budget)
            self._output.display_info(f"Thinking budget updated to {new_budget:,} tokens")
        except ValueError:
            self._output.display_error(
                f"Invalid budget value: '{args}'. Must be a number between 1024 and 16000."
            )

    async def _handle_monitor_command(self, args: str | None) -> None:
        """Handle /monitor subcommands.

        Args:
            args: Subcommand and arguments (start, stop, status, filter).
        """
        from bgp_explorer.models.event import EventType

        if self._bgp_radar is None:
            self._output.display_error(
                "bgp-radar is not available. Real-time monitoring requires bgp-radar to be installed."
            )
            return

        parts = (args or "").strip().lower().split()
        subcommand = parts[0] if parts else ""
        type_args = parts[1:] if len(parts) > 1 else []

        # Parse event types from arguments
        def parse_event_types(type_names: list[str]) -> set[EventType]:
            valid_types = {
                "hijack": EventType.HIJACK,
                "leak": EventType.LEAK,
                "blackhole": EventType.BLACKHOLE,
            }
            result = set()
            for name in type_names:
                if name in valid_types:
                    result.add(valid_types[name])
            return result

        def format_filter(event_filter: set[EventType]) -> str:
            if not event_filter:
                return "all events"
            return ", ".join(sorted(t.value for t in event_filter))

        if subcommand == "start":
            if self._bgp_radar.is_running:
                self._output.display_info(
                    f"Monitoring is already running (collectors: {', '.join(self._bgp_radar._collectors)})"
                )
            else:
                # Apply filter if specified
                event_filter = parse_event_types(type_args)
                self._bgp_radar.set_event_filter(event_filter)
                await self._bgp_radar.start()
                # Enable split terminal mode for event display
                self._output.enable_monitoring_mode()
                filter_msg = f"filter: {format_filter(event_filter)}"
                self._output.display_info(
                    f"✓ Started BGP monitoring (collectors: {', '.join(self._bgp_radar._collectors)}, {filter_msg})\n"
                    "  Events will be displayed in real-time as they are detected."
                )

        elif subcommand == "stop":
            if not self._bgp_radar.is_running:
                self._output.display_info("Monitoring is not running.")
            else:
                await self._bgp_radar.stop()
                # Disable split terminal mode
                self._output.disable_monitoring_mode()
                self._output.display_info("✓ BGP monitoring stopped.")

        elif subcommand == "status":
            if self._bgp_radar.is_running:
                current_filter = self._bgp_radar.event_filter
                filter_msg = format_filter(current_filter)
                self._output.display_info(
                    f"Monitoring is running\n"
                    f"  Collectors: {', '.join(self._bgp_radar._collectors)}\n"
                    f"  Filter: {filter_msg}"
                )
            else:
                self._output.display_info("Monitoring is not running.")

        elif subcommand == "filter":
            if not self._bgp_radar.is_running:
                self._output.display_info("Monitoring is not running. Use /monitor start first.")
            else:
                event_filter = parse_event_types(type_args)
                self._bgp_radar.set_event_filter(event_filter)
                self._output.display_info(f"✓ Filter updated: {format_filter(event_filter)}")

        else:
            self._output.display_info(
                "Usage: /monitor <start|stop|status|filter> [types...]\n"
                "  start [types]  - Start monitoring (optionally filter by type)\n"
                "  stop           - Stop monitoring\n"
                "  status         - Check monitoring status and current filter\n"
                "  filter [types] - Change filter while running (no types = all)\n"
                "\n"
                "Event types: hijack, leak, blackhole\n"
                "Examples:\n"
                "  /monitor start           - Watch all events\n"
                "  /monitor start hijack    - Only hijacks\n"
                "  /monitor filter leak     - Switch to only leaks"
            )

    def _on_bgp_event(self, event) -> None:
        """Callback invoked when a BGP event is detected.

        Args:
            event: BGPEvent from bgp-radar.
        """
        monitoring_status = self.get_monitoring_status()
        self._output.display_bgp_event(event, monitoring_status)

    def get_monitoring_status(self) -> str | None:
        """Get current monitoring status for display.

        Returns:
            Status string if monitoring is active, None otherwise.
        """
        if not self._bgp_radar or not self._bgp_radar.is_running:
            return None

        event_filter = self._bgp_radar.event_filter
        if not event_filter:
            return "all events"
        return ", ".join(sorted(t.value for t in event_filter))

    async def shutdown(self) -> None:
        """Shutdown the agent and cleanup resources."""
        self._running = False

        # Disable split terminal mode before cleanup
        self._output.disable_monitoring_mode()

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
