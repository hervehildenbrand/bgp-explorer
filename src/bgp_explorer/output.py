"""Output formatting and display utilities."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from bgp_explorer.config import OutputFormat


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
        save_path: Optional[str] = None,
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

**Global Network Testing** (requires Globalping)
- Ping 8.8.8.8 from multiple locations worldwide
- Run a traceroute to cloudflare.com from Europe and Asia

**IXP Information** (from PeeringDB)
- What IXPs is AS15169 present at?
- What networks peer at DE-CIX Frankfurt?
- Tell me about AMS-IX

**AS Relationships** (from Monocle - observed BGP data)
- How many peers does AS47957 have?
- Who are the upstream providers for Google?
- Is AS13335 a peer of AS3356?
- Show downstream customers of Level3

**Historical Analysis** (requires BGPStream)
- What happened to 1.2.3.0/24 on January 15th?
- Show routing history for AS64496 last week

## Commands
- `/export [path]` - Export conversation to JSON
- `/clear` - Clear conversation history
- `/help` - Show this message
- `exit` - Exit the application
"""
        self.console.print(Markdown(welcome))

    def display_user_input(self, message: str) -> None:
        """Display user input.

        Args:
            message: User message.
        """
        self._conversation_log.append({
            "role": "user",
            "content": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

    def export_conversation(self, path: Optional[str] = None) -> str:
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
            "exported_at": datetime.now(timezone.utc).isoformat(),
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
