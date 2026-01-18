"""CLI entrypoint for BGP Explorer."""

import asyncio
import sys
from typing import Optional

import click
from dotenv import load_dotenv

from bgp_explorer.agent import BGPExplorerAgent
from bgp_explorer.config import AIBackendType, OutputFormat, load_settings
from bgp_explorer.output import OutputFormatter


@click.group()
@click.version_option(package_name="bgp-explorer")
def cli():
    """BGP Explorer - AI-powered BGP routing investigation tool."""
    pass


@cli.command()
@click.option(
    "--backend",
    type=click.Choice(["gemini", "claude"]),
    default="gemini",
    help="AI backend to use",
)
@click.option(
    "--api-key",
    envvar=["GEMINI_API_KEY", "ANTHROPIC_API_KEY"],
    help="API key for the AI backend",
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
def chat(
    backend: str,
    api_key: Optional[str],
    bgp_radar_path: Optional[str],
    collectors: str,
    output_format: str,
    save_path: Optional[str],
):
    """Start an interactive chat session."""
    # Load environment variables from .env file
    load_dotenv()

    # Parse collectors
    collector_list = [c.strip() for c in collectors.split(",")]

    # Build settings
    settings_kwargs = {
        "ai_backend": AIBackendType(backend),
        "bgp_radar_path": bgp_radar_path,
        "collectors": collector_list,
        "output_format": OutputFormat(output_format),
        "save_path": save_path,
    }

    # Handle API key based on backend
    if api_key:
        if backend == "gemini":
            settings_kwargs["gemini_api_key"] = api_key
        else:
            settings_kwargs["anthropic_api_key"] = api_key

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
    agent = BGPExplorerAgent(settings, output)

    try:
        await agent.initialize()
        output.display_welcome()

        while True:
            try:
                # Get user input
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("\n> ")
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
                    response = await agent.chat(user_input)
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
