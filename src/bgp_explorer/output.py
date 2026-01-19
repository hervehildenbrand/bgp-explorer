"""Output formatting and display utilities."""

import json
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.status import Status

from bgp_explorer.config import OutputFormat
from bgp_explorer.models.event import BGPEvent, Severity


class OutputFormatter:
    """Handles output formatting for CLI display and file export.

    Supports multiple output modes:
    - text: Rich formatted markdown output
    - json: Structured JSON output
    - both: Display text and save JSON
    """

    def __init__(
        self,
        format: OutputFormat = OutputFormat.TEXT,
        save_path: str | None = None,
    ):
        """Initialize the formatter.

        Args:
            format: Output format mode.
            save_path: Optional path to save output.
        """
        self.format = format
        self.save_path = save_path
        self.console = Console()
        self._conversation_log: list[dict[str, Any]] = []
        self._monitoring_mode = False

    def display_welcome(self) -> None:
        """Display welcome message."""
        welcome = """
# BGP Explorer

AI-powered assistant for BGP routing investigation.

## What You Can Do

**Prefix & ASN Lookups**
- Who originates 8.8.8.0/24?
- What prefixes does AS15169 announce?
- Give me details about AS13335

**Path Analysis**
- Analyze the AS paths to 1.1.1.0/24
- Compare how different collectors see 8.8.8.0/24
- What are the upstream providers for AS64496?

**Security & Validation**
- Check RPKI status for 1.1.1.0/24 from AS13335
- Are there any BGP hijacks right now?
- Show me recent route leaks

**Real-time Monitoring** (requires bgp-radar)
- Start watching for BGP anomalies
- `/monitor start` - Watch all events
- `/monitor start hijack` - Watch only hijacks
- `/monitor filter leak blackhole` - Change filter while running

**Global Network Testing** (requires Globalping)
- Ping 8.8.8.8 from multiple locations worldwide
- Run a traceroute to cloudflare.com from Europe and Asia

**IXP Information** (from PeeringDB)
- What IXPs is AS15169 present at?
- What networks peer at DE-CIX Frankfurt?
- Tell me about AMS-IX

**AS Relationships** (from Monocle - observed BGP data)
- How many peers does Cloudflare have?
- Who are the upstream providers for Google?
- Is AS13335 a peer of AS3356?
- Show downstream customers of Level3

**Historical Analysis** (requires BGPStream)
- What happened to 1.2.3.0/24 on January 15th?
- Show routing history for AS64496 last week

## Commands
- `/monitor start [types]` - Start monitoring (types: hijack, leak, blackhole)
- `/monitor stop` - Stop monitoring
- `/monitor status` - Check status and current filter
- `/monitor filter [types]` - Change filter while running
- `/export [path]` - Export conversation to JSON
- `/clear` - Clear conversation history
- `/help` - Show this message
- `exit` - Exit the application

*Tip: Use Tab for command autocomplete*
"""
        self.console.print(Markdown(welcome))

    def display_input_box(self, monitoring_status: str | None = None) -> None:
        """Display input box with top and bottom lines, cursor positioned for input.

        Args:
            monitoring_status: Optional monitoring status string to display as badge.
        """
        width = self.console.size.width

        # Build top line with optional monitoring badge
        if monitoring_status:
            badge = f"[bold red]● MONITORING[/bold red] [dim]({monitoring_status})[/dim]"
            # Calculate visible length (without Rich markup)
            visible_len = len(f"● MONITORING ({monitoring_status})")
            padding = width - visible_len - 2  # 2 for spacing
            if padding > 0:
                top_line = f" {badge} [dim]{'─' * padding}[/dim]"
            else:
                top_line = f" {badge}"
        else:
            top_line = f"[dim]{'─' * width}[/dim]"

        self.console.print(f"\n{top_line}")  # top line with optional badge
        self.console.print("")                # empty line for input
        self.console.print(f"[dim]{'─' * width}[/dim]")  # bottom line
        # Move cursor up 2 lines to the empty input line
        print("\033[2A", end="", flush=True)

    def enable_monitoring_mode(self) -> None:
        """Enable monitoring mode flag.

        In monitoring mode, events are displayed by clearing and redrawing
        the input area to maintain CLI integrity.
        """
        self._monitoring_mode = True

    def disable_monitoring_mode(self) -> None:
        """Disable monitoring mode."""
        self._monitoring_mode = False

    def display_user_input(self, message: str) -> None:
        """Display user input.

        Args:
            message: User message.
        """
        self._conversation_log.append({
            "role": "user",
            "content": message,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        if self.format in (OutputFormat.TEXT, OutputFormat.BOTH):
            self.console.print(f"\n[bold blue]You:[/bold blue] {message}")

    def display_response(self, response: str) -> None:
        """Display AI response.

        Args:
            response: AI response text.
        """
        self._conversation_log.append({
            "role": "assistant",
            "content": response,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        if self.format in (OutputFormat.TEXT, OutputFormat.BOTH):
            self.console.print()
            self.console.print(
                Panel(
                    Markdown(response),
                    title="[bold green]BGP Explorer[/bold green]",
                    border_style="green",
                )
            )

        if self.format == OutputFormat.JSON:
            self.console.print_json(json.dumps({
                "role": "assistant",
                "content": response,
            }))

    def display_error(self, error: str) -> None:
        """Display error message.

        Args:
            error: Error message.
        """
        self.console.print(f"\n[bold red]Error:[/bold red] {error}")

    def display_info(self, info: str) -> None:
        """Display informational message.

        Args:
            info: Info message.
        """
        self.console.print(f"[dim]{info}[/dim]")

    def display_commands_help(self) -> None:
        """Display available slash commands."""
        from rich.table import Table

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Command", style="bold")
        table.add_column("Description", style="dim")

        table.add_row("/monitor start [types]", "Start real-time BGP monitoring")
        table.add_row("/monitor stop", "Stop monitoring")
        table.add_row("/monitor status", "Check monitoring status")
        table.add_row("/monitor filter [types]", "Change event filter")
        table.add_row("/export [path]", "Export conversation to JSON")
        table.add_row("/clear", "Clear conversation history")
        table.add_row("/help", "Show full help message")
        table.add_row("exit", "Exit the application")

        self.console.print("\n[bold cyan]Available Commands:[/bold cyan]\n")
        self.console.print(table)
        self.console.print()

    def _print_above_input_box(self, print_func: callable) -> None:
        """Print content above the input box, keeping input box at bottom.

        Args:
            print_func: A callable that does the actual printing.
        """
        # Move cursor to beginning of line and clear it
        print("\r\033[K", end="", flush=True)

        # Move up past the input box (3 lines: top border, input line, bottom border)
        print("\033[3A", end="", flush=True)
        # Clear from cursor to end of screen
        print("\033[J", end="", flush=True)

        # Do the actual printing
        print_func()

        # Redraw the input box at bottom
        self.display_input_box()
        print("> ", end="", flush=True)

    def display_status_above_input(self, message: str) -> None:
        """Display a status message above the input box.

        Args:
            message: Status message to display.
        """
        def do_print():
            # Print status with cyan color
            self.console.print(f"[bold cyan]⠋ {message}[/bold cyan]")

        self._print_above_input_box(do_print)

    def display_thinking_summary(self, summary: str, iteration: int) -> None:
        """Display a thinking summary from Claude's extended thinking.

        Shows what Claude is thinking about during multi-step investigations.
        Prints above the input box which stays at the bottom.

        Args:
            summary: The extracted thinking summary.
            iteration: The current iteration number.
        """
        def do_print():
            self.console.print(f"[dim italic]Step {iteration}: {summary}[/dim italic]")
            # Also show the spinner below the step
            self.console.print("[bold cyan]⠋ Thinking...[/bold cyan]")

        self._print_above_input_box(do_print)

    def display_content_above_input(self, content: str, style: str = "") -> None:
        """Display any content above the input box.

        Args:
            content: Content to display.
            style: Optional Rich style.
        """
        def do_print():
            if style:
                self.console.print(f"[{style}]{content}[/{style}]")
            else:
                self.console.print(content)

        self._print_above_input_box(do_print)

    def start_processing_with_input_box(self) -> None:
        """Start processing mode - show input box with initial spinner above it."""
        # Print initial spinner
        self.console.print("[bold cyan]⠋ Thinking...[/bold cyan]")
        # Draw input box below
        self.display_input_box()
        print("> ", end="", flush=True)

    def finish_processing(self) -> None:
        """Finish processing - clear the input box area for response display."""
        # Move cursor to beginning of line and clear it
        print("\r\033[K", end="", flush=True)
        # Move up past the input box (3 lines)
        print("\033[3A", end="", flush=True)
        # Clear from cursor to end of screen
        print("\033[J", end="", flush=True)

    def display_bgp_event(self, event: BGPEvent, monitoring_status: str | None = None) -> None:
        """Display a real-time BGP anomaly event.

        Uses Rich Panel with severity-based styling.

        Args:
            event: BGPEvent from bgp-radar.
            monitoring_status: Current monitoring filter status for redrawing input box.
        """
        # Severity-based styling
        severity_styles = {
            Severity.HIGH: ("red", "bold red"),
            Severity.MEDIUM: ("yellow", "bold yellow"),
            Severity.LOW: ("green", "bold green"),
        }
        border_style, title_style = severity_styles.get(
            event.severity, ("white", "bold white")
        )

        # Event type emoji
        type_emoji = {
            "hijack": "🚨",
            "leak": "⚠️",
            "blackhole": "🕳️",
        }.get(event.type.value, "📢")

        # Build content
        lines = [
            f"[bold]{type_emoji} {event.type.value.upper()}[/bold]",
            "",
            f"[bold]Prefix:[/bold] {event.affected_prefix}",
        ]

        if event.affected_asn:
            lines.append(f"[bold]ASN:[/bold] AS{event.affected_asn}")

        lines.append(f"[bold]Time:[/bold] {event.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Add key details
        if event.details:
            lines.append("")
            for key, value in list(event.details.items())[:5]:
                # Format key nicely
                display_key = key.replace("_", " ").title()
                lines.append(f"[dim]{display_key}:[/dim] {value}")

        content = "\n".join(lines)

        # Clear current input line and move up to make room for event
        # Move cursor to beginning of line and clear it
        print("\r\033[K", end="", flush=True)

        # Move up past the input box (3 lines: top border, input, bottom border)
        # and clear those lines
        print("\033[3A", end="", flush=True)  # Move up 3 lines
        print("\033[J", end="", flush=True)   # Clear from cursor to end of screen

        # Print the event panel
        self.console.print(
            Panel(
                content,
                title=f"[{title_style}]BGP Anomaly Detected[/{title_style}]",
                border_style=border_style,
                expand=False,
            )
        )

        # Redraw the input box
        self.display_input_box(monitoring_status)
        print("> ", end="", flush=True)

    @contextmanager
    def thinking_status(
        self, message: str = "Thinking..."
    ) -> Generator[Status, None, None]:
        """Show spinner with status message.

        Args:
            message: Initial status message to display.

        Yields:
            Rich Status object that can be updated.
        """
        with Status(
            f"[bold cyan]{message}[/bold cyan]",
            console=self.console,
            spinner="dots",
        ) as status:
            yield status

    def update_status(self, status: Status, message: str) -> None:
        """Update status message.

        Args:
            status: Rich Status object from thinking_status().
            message: New status message.
        """
        status.update(f"[bold cyan]{message}[/bold cyan]")

    def export_conversation(self, path: str | None = None) -> str:
        """Export conversation to JSON file.

        Args:
            path: Optional path override.

        Returns:
            Path to saved file.
        """
        export_path = path or self.save_path
        if not export_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = f"bgp_explorer_conversation_{timestamp}.json"

        export_data = {
            "exported_at": datetime.now(UTC).isoformat(),
            "messages": self._conversation_log,
        }

        Path(export_path).write_text(json.dumps(export_data, indent=2))
        return export_path

    def clear_history(self) -> None:
        """Clear conversation log."""
        self._conversation_log.clear()
        self.console.print("[dim]Conversation history cleared.[/dim]")


def format_routes_as_table(routes: list[dict[str, Any]]) -> str:
    """Format routes as a markdown table.

    Args:
        routes: List of route dictionaries.

    Returns:
        Markdown table string.
    """
    if not routes:
        return "No routes found."

    lines = [
        "| Prefix | Origin | AS Path | Collector |",
        "|--------|--------|---------|-----------|",
    ]

    for route in routes[:20]:
        prefix = route.get("prefix", "N/A")
        origin = f"AS{route.get('origin_asn', 'N/A')}"
        path = " → ".join(str(asn) for asn in route.get("as_path", [])[:5])
        if len(route.get("as_path", [])) > 5:
            path += "..."
        collector = route.get("collector", "N/A")
        lines.append(f"| {prefix} | {origin} | {path} | {collector} |")

    if len(routes) > 20:
        lines.append(f"\n*... and {len(routes) - 20} more routes*")

    return "\n".join(lines)
