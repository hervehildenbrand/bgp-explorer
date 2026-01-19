"""CLI entrypoint for BGP Explorer."""

import asyncio
import shutil
import subprocess
import sys

import click
from dotenv import load_dotenv

# Enable readline for arrow key history navigation and tab completion
try:
    import readline
except ImportError:
    readline = None  # readline not available on some platforms


class CommandCompleter:
    """Tab completion for / commands."""

    # Command tree: command -> subcommands -> options
    COMMANDS = {
        "monitor": {
            "start": ["hijack", "leak", "blackhole"],
            "stop": [],
            "status": [],
            "filter": ["hijack", "leak", "blackhole"],
        },
        "export": [],
        "clear": [],
        "help": [],
    }

    def __init__(self):
        self.matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        """Readline completion function.

        Args:
            text: Current word being typed.
            state: Index of completion to return.

        Returns:
            Completion string or None.
        """
        if state == 0:
            # Get the full line buffer
            line = readline.get_line_buffer() if readline else ""
            self.matches = self._get_completions(line, text)

        return self.matches[state] if state < len(self.matches) else None

    def _get_completions(self, line: str, text: str) -> list[str]:
        """Get list of completions for current input.

        Args:
            line: Full line buffer.
            text: Current word being typed.

        Returns:
            List of matching completions.
        """
        # Only complete if line starts with /
        if not line.startswith("/"):
            return []

        # Remove leading /
        line_without_slash = line[1:].lstrip()
        parts = line_without_slash.split()

        # Completing the command itself (e.g., "/mon<tab>")
        if len(parts) == 0 or (len(parts) == 1 and not line_without_slash.endswith(" ")):
            prefix = text.lstrip("/")
            return [f"/{cmd} " for cmd in self.COMMANDS if cmd.startswith(prefix)]

        command = parts[0]
        if command not in self.COMMANDS:
            return []

        subcommands = self.COMMANDS[command]

        # Command has no subcommands
        if isinstance(subcommands, list):
            return []

        # Completing subcommand (e.g., "/monitor st<tab>")
        if len(parts) == 1 or (len(parts) == 2 and not line_without_slash.endswith(" ")):
            prefix = parts[1] if len(parts) > 1 else ""
            return [f"{sub} " for sub in subcommands if sub.startswith(prefix)]

        # Completing options for subcommand (e.g., "/monitor start hi<tab>")
        subcommand = parts[1]
        if subcommand not in subcommands:
            return []

        options = subcommands[subcommand]
        if not options:
            return []

        # Get already-used options to avoid duplicates
        used_options = set(parts[2:])
        prefix = text if text else ""

        return [f"{opt} " for opt in options if opt.startswith(prefix) and opt not in used_options]


def setup_readline_completion():
    """Configure readline for tab completion."""
    if readline is None:
        return

    completer = CommandCompleter()
    readline.set_completer(completer.complete)

    # Use tab for completion
    # macOS uses libedit which needs different binding
    if "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

    # Don't complete on empty input
    readline.set_completer_delims(" \t\n")

from bgp_explorer.agent import BGPExplorerAgent
from bgp_explorer.ai.base import ChatEvent
from bgp_explorer.config import ClaudeModel, OutputFormat, load_settings
from bgp_explorer.output import OutputFormatter


@click.group()
@click.version_option(package_name="bgp-explorer")
def cli():
    """BGP Explorer - AI-powered BGP routing investigation tool."""
    pass


@cli.command("install-deps")
def install_deps():
    """Install required external dependencies (bgp-radar, monocle).

    This command installs the external tools that BGP Explorer uses:

    - bgp-radar: Real-time BGP anomaly detection (requires Go)
    - monocle: AS relationship data from BGPKIT (requires Rust/Cargo)

    Both tools will be installed to your Go/Cargo bin directories,
    which should be in your PATH.
    """
    click.echo("Installing BGP Explorer dependencies...\n")

    success_count = 0
    total_deps = 2

    # Install bgp-radar (Go)
    click.echo("=" * 50)
    click.echo("Installing bgp-radar (Go)...")
    click.echo("=" * 50)

    if shutil.which("go"):
        try:
            result = subprocess.run(
                ["go", "install", "github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                # Verify installation
                if shutil.which("bgp-radar"):
                    click.echo(click.style("✓ bgp-radar installed successfully", fg="green"))
                    success_count += 1
                else:
                    click.echo(click.style("✓ bgp-radar built successfully", fg="green"))
                    click.echo(click.style("  Note: Ensure $GOPATH/bin is in your PATH", fg="yellow"))
                    success_count += 1
            else:
                click.echo(click.style(f"✗ Failed to install bgp-radar", fg="red"))
                if result.stderr:
                    click.echo(f"  Error: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            click.echo(click.style("✗ Installation timed out", fg="red"))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
    else:
        click.echo(click.style("✗ Go is not installed", fg="red"))
        click.echo("  Install Go from: https://go.dev/doc/install")

    click.echo()

    # Install monocle (Rust/Cargo)
    click.echo("=" * 50)
    click.echo("Installing monocle (Rust/Cargo)...")
    click.echo("=" * 50)

    if shutil.which("cargo"):
        try:
            result = subprocess.run(
                ["cargo", "install", "monocle"],
                capture_output=True,
                text=True,
                timeout=600,  # Rust builds can take longer
            )
            if result.returncode == 0:
                # Verify installation
                if shutil.which("monocle"):
                    click.echo(click.style("✓ monocle installed successfully", fg="green"))
                    success_count += 1
                else:
                    click.echo(click.style("✓ monocle built successfully", fg="green"))
                    click.echo(click.style("  Note: Ensure ~/.cargo/bin is in your PATH", fg="yellow"))
                    success_count += 1
            else:
                click.echo(click.style(f"✗ Failed to install monocle", fg="red"))
                if result.stderr:
                    # Cargo outputs to stderr even on success, filter errors
                    error_lines = [l for l in result.stderr.split('\n') if 'error' in l.lower()]
                    if error_lines:
                        click.echo(f"  Error: {error_lines[0]}")
        except subprocess.TimeoutExpired:
            click.echo(click.style("✗ Installation timed out", fg="red"))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
    else:
        click.echo(click.style("✗ Rust/Cargo is not installed", fg="red"))
        click.echo("  Install Rust from: https://rustup.rs/")

    click.echo()

    # Summary
    click.echo("=" * 50)
    click.echo("Summary")
    click.echo("=" * 50)

    if success_count == total_deps:
        click.echo(click.style(f"✓ All {total_deps} dependencies installed successfully!", fg="green"))
    elif success_count > 0:
        click.echo(click.style(f"⚠ {success_count}/{total_deps} dependencies installed", fg="yellow"))
        click.echo("  Some features may not be available.")
    else:
        click.echo(click.style(f"✗ No dependencies could be installed", fg="red"))
        click.echo("  Please install Go and/or Rust first.")

    click.echo()
    click.echo("To verify installation, run:")
    click.echo("  bgp-radar --help")
    click.echo("  monocle --help")


@cli.command()
@click.option(
    "--model",
    type=click.Choice(["haiku", "sonnet", "opus"]),
    default="sonnet",
    help="Claude model tier (default: sonnet)",
)
@click.option(
    "--api-key",
    envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key",
)
@click.option(
    "--bgp-radar-path",
    envvar="BGP_RADAR_PATH",
    help="Path to bgp-radar binary",
)
@click.option(
    "--collectors",
    default="rrc00",
    help="Comma-separated list of RIS collectors",
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "both"]),
    default="text",
    help="Output format",
)
@click.option(
    "--save",
    "save_path",
    type=click.Path(),
    help="Path to save conversation output",
)
@click.option(
    "--refresh-peeringdb",
    is_flag=True,
    help="Force refresh of PeeringDB data from CAIDA",
)
def chat(
    model: str,
    api_key: str | None,
    bgp_radar_path: str | None,
    collectors: str,
    output_format: str,
    save_path: str | None,
    refresh_peeringdb: bool,
):
    """Start an interactive chat session."""
    # Load environment variables from .env file
    load_dotenv()

    # Parse collectors
    collector_list = [c.strip() for c in collectors.split(",")]

    # Build settings
    settings_kwargs = {
        "claude_model": ClaudeModel(model),
        "anthropic_api_key": api_key,
        "bgp_radar_path": bgp_radar_path,
        "collectors": collector_list,
        "output_format": OutputFormat(output_format),
        "save_path": save_path,
        "refresh_peeringdb": refresh_peeringdb,
    }

    try:
        settings = load_settings(**settings_kwargs)
    except Exception as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(1)

    # Create output formatter
    output = OutputFormatter(
        format=settings.output_format,
        save_path=settings.save_path,
    )

    # Run the async chat loop
    try:
        asyncio.run(run_chat(settings, output))
    except KeyboardInterrupt:
        click.echo("\nGoodbye!")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


async def run_chat(settings, output: OutputFormatter) -> None:
    """Run the interactive chat loop.

    Args:
        settings: Application settings.
        output: Output formatter.
    """
    # Enable tab completion for / commands
    setup_readline_completion()

    agent = BGPExplorerAgent(settings, output)

    try:
        await agent.initialize()
        output.display_welcome()

        while True:
            try:
                # Get user input with decorative box (show monitoring badge if active)
                monitoring_status = agent.get_monitoring_status()
                output.display_input_box(monitoring_status)
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("> ")
                )
                user_input = user_input.strip()

                if not user_input:
                    continue

                # Check for exit
                if user_input.lower() in ("exit", "quit", "bye"):
                    break

                # Check for commands
                if user_input.startswith("/"):
                    command = user_input[1:]
                    if await agent.handle_command(command):
                        continue
                    else:
                        output.display_error(f"Unknown command: {command}")
                        continue

                # Process message
                output.display_user_input(user_input)

                try:
                    with output.thinking_status("Thinking...") as status:
                        # Event handler to update status during processing
                        def handle_event(event: ChatEvent) -> None:
                            if event.type == "tool_start":
                                message = event.data.get("message", "Running tool...")
                                output.update_status(status, message)
                            elif event.type == "tool_end":
                                output.update_status(status, "Thinking...")
                            elif event.type == "thinking_summary":
                                # Display thinking summary - stop spinner briefly
                                summary = event.data.get("summary", "")
                                iteration = event.data.get("iteration", 1)
                                status.stop()
                                output.display_thinking_summary(summary, iteration)
                                status.start()

                        response = await agent.chat(user_input, on_event=handle_event)
                    output.display_response(response)
                except Exception as e:
                    output.display_error(f"AI error: {e}")

            except EOFError:
                break

    finally:
        await agent.shutdown()

        # Auto-save if path specified
        if settings.save_path:
            output.export_conversation()


def main():
    """Main entrypoint."""
    cli()


if __name__ == "__main__":
    main()
