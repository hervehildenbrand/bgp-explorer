"""CLI entrypoint for BGP Explorer."""

import asyncio
import os
import shutil
import subprocess
import sys

import click
from dotenv import load_dotenv
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style

from bgp_explorer.agent import BGPExplorerAgent
from bgp_explorer.ai.base import ChatEvent
from bgp_explorer.analysis.resilience import ResilienceAssessor
from bgp_explorer.config import ClaudeModel, OutputFormat, load_settings
from bgp_explorer.output import OutputFormatter
from bgp_explorer.sources.monocle import MonocleClient
from bgp_explorer.sources.peeringdb import PeeringDBClient

# Command definitions with descriptions
COMMANDS = {
    "/clear": "Clear screen and conversation",
    "/export": "Export conversation to file",
    "/help": "Show help",
    "/thinking": "Set thinking budget (1024-16000)",
    "/monitor start": "Start BGP monitoring",
    "/monitor stop": "Stop monitoring",
    "/monitor status": "Show monitoring status",
    "/monitor filter": "Set event filter",
}

# Thinking budget cycle values for Shift+Tab
THINKING_BUDGET_VALUES = [1024, 2048, 4096, 8000, 12000, 16000]


class SlashCommandCompleter(Completer):
    """Completer that shows commands when / is typed."""

    def get_completions(self, document, complete_event):
        """Get completions for the current input."""
        text = document.text_before_cursor

        # Only show completions if text starts with /
        if not text.startswith("/"):
            return

        # Show all commands when just "/" is typed
        for cmd, description in COMMANDS.items():
            if cmd.startswith(text):
                # Show the command without the part already typed
                yield Completion(
                    cmd,
                    start_position=-len(text),
                    display=cmd,
                    display_meta=description,
                )


# Style for prompt_toolkit
PROMPT_STYLE = Style.from_dict(
    {
        "completion-menu.completion": "bg:#333333 #ffffff",
        "completion-menu.completion.current": "bg:#00aa00 #ffffff",
        "completion-menu.meta.completion": "bg:#333333 #888888",
        "completion-menu.meta.completion.current": "bg:#00aa00 #ffffff",
        "bottom-toolbar": "bg:#333333 #aaaaaa",
    }
)


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

    # Check for go, also check common locations if not in PATH
    go_path = shutil.which("go")
    if not go_path:
        home = os.path.expanduser("~")
        go_candidates = [
            os.path.join(home, "go", "bin", "go"),
            os.path.join(home, ".local", "go", "bin", "go"),
            "/usr/local/go/bin/go",
        ]
        for candidate in go_candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                go_path = candidate
                break

    if go_path:
        try:
            # Set GOPATH for installation
            home = os.path.expanduser("~")
            env = os.environ.copy()
            env["GOPATH"] = os.path.join(home, "go")
            env["PATH"] = f"{os.path.join(home, 'go', 'bin')}:{env.get('PATH', '')}"

            result = subprocess.run(
                [go_path, "install", "github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest"],
                capture_output=True,
                text=True,
                timeout=300,
                env=env,
            )
            if result.returncode == 0:
                # Check for bgp-radar in PATH and common locations
                bgp_radar_path = shutil.which("bgp-radar")
                if not bgp_radar_path:
                    bgp_radar_candidate = os.path.join(home, "go", "bin", "bgp-radar")
                    if os.path.isfile(bgp_radar_candidate):
                        bgp_radar_path = bgp_radar_candidate

                if bgp_radar_path:
                    click.echo(click.style("✓ bgp-radar installed successfully", fg="green"))
                    success_count += 1
                else:
                    click.echo(click.style("✓ bgp-radar built successfully", fg="green"))
                    click.echo(click.style("  Note: Ensure ~/go/bin is in your PATH", fg="yellow"))
                    success_count += 1
            else:
                click.echo(click.style("✗ Failed to install bgp-radar", fg="red"))
                if result.stderr:
                    click.echo(f"  Error: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            click.echo(click.style("✗ Installation timed out", fg="red"))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
    else:
        # Go not installed - offer to install it
        click.echo(click.style("Go is not installed.", fg="yellow"))
        click.echo()

        if click.confirm("Would you like to install Go automatically?", default=True):
            click.echo("Installing Go...")
            try:
                # Detect architecture
                import platform

                machine = platform.machine().lower()
                if machine in ("x86_64", "amd64"):
                    arch = "amd64"
                elif machine in ("aarch64", "arm64"):
                    arch = "arm64"
                else:
                    click.echo(click.style(f"✗ Unsupported architecture: {machine}", fg="red"))
                    arch = None

                system = platform.system().lower()
                if system == "darwin":
                    os_name = "darwin"
                elif system == "linux":
                    os_name = "linux"
                else:
                    click.echo(click.style(f"✗ Unsupported OS: {system}", fg="red"))
                    os_name = None

                if arch and os_name:
                    # Get latest Go version and download
                    go_version = "1.23.5"  # Recent stable version
                    go_tarball = f"go{go_version}.{os_name}-{arch}.tar.gz"
                    go_url = f"https://go.dev/dl/{go_tarball}"

                    home = os.path.expanduser("~")
                    go_install_dir = os.path.join(home, ".local")
                    os.makedirs(go_install_dir, exist_ok=True)

                    # Download and extract Go
                    click.echo(f"  Downloading Go {go_version}...")
                    result = subprocess.run(
                        ["sh", "-c", f"curl -sL {go_url} | tar -xz -C {go_install_dir}"],
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )

                    if result.returncode == 0:
                        go_path = os.path.join(go_install_dir, "go", "bin", "go")
                        if os.path.isfile(go_path):
                            click.echo(click.style("✓ Go installed successfully", fg="green"))

                            # Now install bgp-radar
                            click.echo("  Installing bgp-radar...")
                            env = os.environ.copy()
                            env["GOPATH"] = os.path.join(home, "go")
                            env["GOROOT"] = os.path.join(go_install_dir, "go")
                            env["PATH"] = (
                                f"{os.path.join(home, 'go', 'bin')}:{os.path.join(go_install_dir, 'go', 'bin')}:{env.get('PATH', '')}"
                            )

                            result = subprocess.run(
                                [
                                    go_path,
                                    "install",
                                    "github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest",
                                ],
                                capture_output=True,
                                text=True,
                                timeout=300,
                                env=env,
                            )
                            if result.returncode == 0:
                                click.echo(
                                    click.style("✓ bgp-radar installed successfully", fg="green")
                                )
                                click.echo(
                                    click.style(
                                        "  Note: Add ~/.local/go/bin and ~/go/bin to your PATH",
                                        fg="yellow",
                                    )
                                )
                                success_count += 1
                            else:
                                click.echo(click.style("✗ Failed to install bgp-radar", fg="red"))
                                if result.stderr:
                                    click.echo(f"  Error: {result.stderr.strip()[:200]}")
                        else:
                            click.echo(
                                click.style("✗ Go binary not found after extraction", fg="red")
                            )
                    else:
                        click.echo(click.style("✗ Failed to download/extract Go", fg="red"))
                        if result.stderr:
                            click.echo(f"  Error: {result.stderr.strip()[:200]}")

            except subprocess.TimeoutExpired:
                click.echo(click.style("✗ Installation timed out", fg="red"))
            except Exception as e:
                click.echo(click.style(f"✗ Error: {e}", fg="red"))
        else:
            click.echo("  Install Go manually from: https://go.dev/doc/install")
            click.echo("  Then run 'bgp-explorer install-deps' again")

    click.echo()

    # Install monocle (Rust/Cargo)
    click.echo("=" * 50)
    click.echo("Installing monocle (Rust/Cargo)...")
    click.echo("=" * 50)

    # Check for cargo, also check common locations if not in PATH
    cargo_path = shutil.which("cargo")
    if not cargo_path:
        # Check common cargo locations
        home = os.path.expanduser("~")
        cargo_candidates = [
            os.path.join(home, ".cargo", "bin", "cargo"),
        ]
        for candidate in cargo_candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                cargo_path = candidate
                break

    if cargo_path:
        try:
            # Use the found cargo path
            result = subprocess.run(
                [cargo_path, "install", "monocle"],
                capture_output=True,
                text=True,
                timeout=600,  # Rust builds can take longer
            )
            if result.returncode == 0:
                # Check for monocle in PATH and common locations
                monocle_path = shutil.which("monocle")
                if not monocle_path:
                    home = os.path.expanduser("~")
                    monocle_candidate = os.path.join(home, ".cargo", "bin", "monocle")
                    if os.path.isfile(monocle_candidate):
                        monocle_path = monocle_candidate

                if monocle_path:
                    click.echo(click.style("✓ monocle installed successfully", fg="green"))
                    success_count += 1
                else:
                    click.echo(click.style("✓ monocle built successfully", fg="green"))
                    click.echo(
                        click.style("  Note: Ensure ~/.cargo/bin is in your PATH", fg="yellow")
                    )
                    success_count += 1
            else:
                click.echo(click.style("✗ Failed to install monocle", fg="red"))
                if result.stderr:
                    # Cargo outputs to stderr even on success, filter errors
                    error_lines = [
                        line for line in result.stderr.split("\n") if "error" in line.lower()
                    ]
                    if error_lines:
                        click.echo(f"  Error: {error_lines[0]}")
        except subprocess.TimeoutExpired:
            click.echo(click.style("✗ Installation timed out", fg="red"))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
    else:
        # Rust not installed - offer to install it
        click.echo(click.style("Rust/Cargo is not installed.", fg="yellow"))
        click.echo()

        if click.confirm("Would you like to install Rust automatically?", default=True):
            click.echo("Installing Rust via rustup...")
            try:
                # Download and run rustup installer
                result = subprocess.run(
                    [
                        "sh",
                        "-c",
                        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    click.echo(click.style("✓ Rust installed successfully", fg="green"))

                    # Now install monocle with the new cargo
                    home = os.path.expanduser("~")
                    cargo_path = os.path.join(home, ".cargo", "bin", "cargo")

                    if os.path.isfile(cargo_path):
                        click.echo("Installing monocle...")
                        result = subprocess.run(
                            [cargo_path, "install", "monocle"],
                            capture_output=True,
                            text=True,
                            timeout=600,
                        )
                        if result.returncode == 0:
                            click.echo(click.style("✓ monocle installed successfully", fg="green"))
                            success_count += 1
                        else:
                            click.echo(click.style("✗ Failed to install monocle", fg="red"))
                    else:
                        click.echo(click.style("✗ Cargo not found after Rust install", fg="red"))
                else:
                    click.echo(click.style("✗ Failed to install Rust", fg="red"))
                    if result.stderr:
                        click.echo(f"  Error: {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                click.echo(click.style("✗ Installation timed out", fg="red"))
            except Exception as e:
                click.echo(click.style(f"✗ Error: {e}", fg="red"))
        else:
            click.echo("  Install Rust manually from: https://rustup.rs/")
            click.echo("  Then run 'bgp-explorer install-deps' again")

    click.echo()

    # Summary
    click.echo("=" * 50)
    click.echo("Summary")
    click.echo("=" * 50)

    if success_count == total_deps:
        click.echo(
            click.style(f"✓ All {total_deps} dependencies installed successfully!", fg="green")
        )
    elif success_count > 0:
        click.echo(
            click.style(f"⚠ {success_count}/{total_deps} dependencies installed", fg="yellow")
        )
        click.echo("  Some features may not be available.")
    else:
        click.echo(click.style("✗ No dependencies could be installed", fg="red"))
        click.echo("  Please install Go and/or Rust first.")

    click.echo()
    click.echo("To verify installation, run:")
    click.echo("  bgp-radar --help")
    click.echo("  monocle --help")


@cli.command()
def mcp():
    """Start MCP server for Claude Code integration.

    This allows you to use BGP Explorer tools with Claude Code (Pro/Max
    subscription) without needing a separate API key.

    Setup:

        cd /path/to/bgp-explorer
        uv tool install .                              # Install globally
        claude mcp add bgp-explorer -- bgp-explorer mcp

    To verify: claude mcp list

    Then use Claude Code normally - BGP tools are available!
    """
    from bgp_explorer.mcp_server import main as run_mcp

    run_mcp()


@cli.command()
@click.argument("asn", type=int)
def assess(asn: int):
    """Assess network resilience for an ASN.

    Produces a resilience score (1-10) plus detailed report with recommendations.
    Evaluates transit diversity, peering breadth, IXP presence, and path redundancy.

    Example:
        bgp-explorer assess 15169  # Assess Google's resilience
        bgp-explorer assess 13335  # Assess Cloudflare (should detect self-DDoS)

    Requires:
        - monocle: For AS relationship data (install with: cargo install monocle)
        - PeeringDB: For IXP presence data (downloaded automatically)
    """
    # Load environment
    load_dotenv()

    try:
        result = asyncio.run(run_assess(asn))
        click.echo(result)
    except KeyboardInterrupt:
        click.echo("\nAssessment cancelled.")
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)


async def run_assess(asn: int) -> str:
    """Run the resilience assessment for an ASN.

    Args:
        asn: Autonomous System Number to assess.

    Returns:
        Formatted resilience report.
    """
    from rich.console import Console

    console = Console()

    # Initialize Monocle
    monocle = MonocleClient()
    if not await monocle.is_available():
        return (
            "Error: Monocle is not installed or not in PATH.\n"
            "Install with: cargo install monocle\n"
            "Or run: bgp-explorer install-deps"
        )

    # Initialize PeeringDB
    peeringdb = PeeringDBClient(console=console)
    try:
        await peeringdb.connect()
    except Exception as e:
        return f"Error connecting to PeeringDB: {e}"

    try:
        # Get data from sources
        console.print(f"[cyan]Fetching data for AS{asn}...[/cyan]")

        upstreams = await monocle.get_as_upstreams(asn)
        peers = await monocle.get_as_peers(asn)
        ixps = peeringdb.get_ixps_for_asn(asn)

        # Create assessor and run assessment
        assessor = ResilienceAssessor()

        # Calculate component scores
        transit_score, transit_issues = assessor._score_transit(upstreams)
        peering_score, peer_count = assessor._score_peering(peers)
        ixp_score, ixp_names = assessor._score_ixp(ixps)

        # Use transit diversity as proxy for path redundancy
        path_redundancy_score = transit_score

        # Check for DDoS provider
        ddos_provider = assessor._detect_ddos_provider(upstreams)

        # Check for single transit
        single_transit = len(upstreams) == 1

        # Build scores and flags
        scores = {
            "transit": transit_score,
            "peering": peering_score,
            "ixp": ixp_score,
            "path_redundancy": path_redundancy_score,
        }
        flags = {
            "single_transit": single_transit,
            "ddos_provider": ddos_provider,
        }

        # Calculate final score
        final_score = assessor._calculate_final_score(scores, flags)

        # Build upstream names
        upstream_names = []
        for u in upstreams[:10]:
            name = f"AS{u.asn2}"
            if u.asn2_name:
                name += f" ({u.asn2_name})"
            upstream_names.append(name)

        # Build report
        from bgp_explorer.analysis.resilience import ResilienceReport

        report = ResilienceReport(
            asn=asn,
            score=final_score,
            transit_score=transit_score,
            peering_score=peering_score,
            ixp_score=ixp_score,
            path_redundancy_score=path_redundancy_score,
            upstream_count=len(upstreams),
            peer_count=peer_count,
            ixp_count=len(ixps),
            upstreams=upstream_names,
            ixps=ixp_names,
            issues=transit_issues,
            recommendations=[],
            single_transit=single_transit,
            ddos_provider_detected=ddos_provider,
        )

        # Generate recommendations
        report.recommendations = assessor._generate_recommendations(report)

        # Format and return report
        return assessor.format_report(report)

    finally:
        await peeringdb.disconnect()


@cli.command()
@click.option(
    "--model",
    type=click.Choice(["sonnet", "opus"]),
    default="sonnet",
    help="Claude model tier (default: sonnet) - both support extended thinking",
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
@click.option(
    "--thinking-budget",
    type=int,
    default=8000,
    help="Max tokens for AI thinking (default: 8000, range: 1024-16000)",
)
def chat(
    model: str,
    api_key: str | None,
    bgp_radar_path: str | None,
    collectors: str,
    output_format: str,
    save_path: str | None,
    refresh_peeringdb: bool,
    thinking_budget: int,
):
    """Start an interactive chat session."""
    # Load environment variables from .env file
    load_dotenv()

    # Parse collectors
    collector_list = [c.strip() for c in collectors.split(",")]

    # Validate thinking budget
    if thinking_budget < 1024 or thinking_budget > 16000:
        click.echo("Error: --thinking-budget must be between 1024 and 16000", err=True)
        sys.exit(1)

    # Build settings
    settings_kwargs = {
        "claude_model": ClaudeModel(model),
        "anthropic_api_key": api_key,
        "bgp_radar_path": bgp_radar_path,
        "collectors": collector_list,
        "output_format": OutputFormat(output_format),
        "save_path": save_path,
        "refresh_peeringdb": refresh_peeringdb,
        "thinking_budget": thinking_budget,
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


def format_toolbar(model: str, thinking_budget: int, monitoring_status: str | None = None) -> HTML:
    """Format the bottom toolbar with model, thinking budget, and optional monitoring status."""
    # Format thinking budget with commas
    budget_formatted = f"{thinking_budget:,}"

    # Build the toolbar parts
    parts = [f"<b>{model}</b>", f"thinking: {budget_formatted} tokens"]

    if monitoring_status:
        parts.append(f"<style fg='red'>●</style> <b>MONITORING</b> ({monitoring_status})")

    toolbar_text = " │ ".join(parts)
    return HTML(f" {toolbar_text}")


async def run_chat(settings, output: OutputFormatter) -> None:
    """Run the interactive chat loop.

    Args:
        settings: Application settings.
        output: Output formatter.
    """
    agent = BGPExplorerAgent(settings, output)

    # Create toolbar function that captures settings and agent
    def get_toolbar():
        monitoring_status = agent.get_monitoring_status()
        return format_toolbar(
            model=settings.claude_model.value,
            thinking_budget=settings.thinking_budget,
            monitoring_status=monitoring_status,
        )

    # Create key bindings
    kb = KeyBindings()

    @kb.add("s-tab")
    def cycle_thinking_budget(event):
        """Cycle through thinking budget values on Shift+Tab."""
        current = settings.thinking_budget
        try:
            idx = THINKING_BUDGET_VALUES.index(current)
            next_idx = (idx + 1) % len(THINKING_BUDGET_VALUES)
        except ValueError:
            next_idx = 0

        new_budget = THINKING_BUDGET_VALUES[next_idx]
        settings.thinking_budget = new_budget

        # Sync with AI backend
        if agent._ai:
            agent._ai.set_thinking_budget(new_budget)

        # Refresh toolbar
        event.app.invalidate()

    # Create prompt session with command completer and bottom toolbar
    session: PromptSession = PromptSession(
        completer=SlashCommandCompleter(),
        complete_while_typing=True,
        history=InMemoryHistory(),
        style=PROMPT_STYLE,
        bottom_toolbar=get_toolbar,
        key_bindings=kb,
    )

    try:
        await agent.initialize()
        output.display_welcome()

        while True:
            try:
                # Get user input with prompt_toolkit (shows completions as you type)
                user_input = await session.prompt_async("❯ ")

                user_input = user_input.strip()

                if not user_input:
                    continue

                # Check for exit
                if user_input.lower() in ("exit", "quit", "bye"):
                    break

                # Check for commands
                if user_input.startswith("/"):
                    command = user_input[1:].strip()

                    # Show available commands if just "/" or "/?" or "/help"
                    if not command or command in ("?", "help"):
                        output.display_commands_help()
                        continue

                    if await agent.handle_command(command):
                        continue
                    else:
                        output.display_error(f"Unknown command: /{command}")
                        output.display_commands_help()
                        continue

                # Process message
                output.display_user_input(user_input)

                try:
                    # Event handler to update status during processing
                    def handle_event(event: ChatEvent) -> None:
                        if event.type == "tool_start":
                            message = event.data.get("message", "Running tool...")
                            print(f"\r\033[K  {message}", end="", flush=True)
                        elif event.type == "tool_end":
                            print("\r\033[K  Thinking...", end="", flush=True)
                        elif event.type == "thinking_summary":
                            summary = event.data.get("summary", "")
                            if summary:
                                # Truncate long summaries
                                if len(summary) > 80:
                                    summary = summary[:77] + "..."
                                print(f"\r\033[K  💭 {summary}", end="", flush=True)

                    print("  Thinking...", end="", flush=True)
                    response = await agent.chat(user_input, on_event=handle_event)

                    # Clear the status line
                    print("\r\033[K", end="", flush=True)
                    output.display_response(response)
                except Exception as e:
                    print("\r\033[K", end="", flush=True)
                    output.display_error(f"AI error: {e}")

            except EOFError:
                break
            except KeyboardInterrupt:
                # Ctrl+C during input - just show new prompt
                print()
                continue

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
