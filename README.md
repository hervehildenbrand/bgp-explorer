# BGP Explorer

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/hervehildenbrand/bgp-explorer/actions/workflows/test.yml/badge.svg)](https://github.com/hervehildenbrand/bgp-explorer/actions/workflows/test.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Anthropic](https://img.shields.io/badge/AI-Claude-blueviolet)](https://www.anthropic.com/)

AI-powered CLI for querying live and historical internet routing data using natural language.

![BGP Explorer Demo](demo/output/bgp-explorer-github.gif)

## Features

- **Natural Language Queries**: Ask questions about BGP routing in plain English
- **Multi-Step Agentic Investigation**: Claude autonomously decides which tools to call based on your question
- **Multiple Data Sources**:
  - RIPE Stat API for historical and current BGP state
  - bgp-radar for real-time anomaly detection (hijacks, leaks, blackholes)
  - Globalping for worldwide network testing (ping, traceroute)
  - PeeringDB for network and contact information
  - Monocle for AS relationship data (peers, upstreams, downstreams)
  - BGPStream for historical BGP archives
- **AI-Powered Analysis**: Claude AI analyzes routing data and provides insights
- **Thinking Summaries**: See Claude's reasoning process as it investigates
- **Contact Lookup**: Find NOC contacts from PeeringDB for incident coordination
- **Path Analysis**: AS path diversity, upstream/downstream relationships, prepending detection
- **RPKI Validation**: Check route origin validation status
- **Anomaly Detection**: Real-time hijack, route leak, and blackhole detection
- **On-Demand Hijack Detection**: Check any prefix for potential hijacks without bgp-radar (MOAS, RPKI, origin changes)

## Quick Start

```bash
git clone https://github.com/hervehildenbrand/bgp-explorer.git
cd bgp-explorer
uv sync
uv run bgp-explorer install-deps  # Auto-installs Go + Rust + binaries
uv run bgp-explorer chat          # All 23 tools ready!
```

## Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** - Fast Python package manager
- **Anthropic API Key** from [Anthropic Console](https://console.anthropic.com/)

### External Dependencies (Auto-installed)

The `install-deps` command automatically installs:

- **Go** (if missing) - Downloads and extracts to `~/.local/go`
- **Rust** (if missing) - Installs via rustup
- **bgp-radar** - Real-time BGP anomaly detection (`go install`)
- **monocle** - AS relationship data from BGPKIT (`cargo install`)

Binaries are auto-detected in `~/go/bin` and `~/.cargo/bin`.

### Manual Installation (Alternative)

If you prefer to install dependencies manually:

```bash
# bgp-radar (requires Go)
go install github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest

# monocle (requires Rust)
cargo install monocle
```

### Optional Dependencies

```bash
# For BGPStream support (requires libBGPStream)
brew install bgpstream  # macOS
uv sync --extra bgpstream
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env`:
```bash
# AI Backend
ANTHROPIC_API_KEY=your_anthropic_key_here

# Optional: bgp-radar path (defaults to PATH lookup)
BGP_RADAR_PATH=/path/to/bgp-radar
```

## Usage

### Start Interactive Chat

```bash
uv run bgp-explorer chat
```

### CLI Options

```bash
uv run bgp-explorer chat [OPTIONS]

Options:
  --model [sonnet|opus]      Claude model tier (default: sonnet)
  --api-key TEXT             API key for the AI backend
  --bgp-radar-path TEXT      Path to bgp-radar binary
  --collectors TEXT          Comma-separated list of RIS collectors (default: rrc00)
  --output [text|json|both]  Output format (default: text)
  --save PATH                Path to save conversation output
  --thinking-budget INT      Max tokens for AI thinking (default: 8000, range: 1024-16000)
```

## What You Can Do

### Prefix & ASN Lookups
```
> Who originates 8.8.8.0/24?
> What prefixes does AS15169 announce?
> Give me details about AS13335
```

### Path Analysis
```
> Analyze the AS paths to 1.1.1.0/24
> Compare how different collectors see 8.8.8.0/24
> What are the upstream providers for AS64496?
```

### Security & Validation
```
> Check RPKI status for 1.1.1.0/24 from AS13335
> Are there any BGP hijacks right now?
> Show me recent route leaks
> Check if 203.0.113.0/24 is being hijacked
```

### Global Network Testing
```
> Ping 8.8.8.8 from multiple locations worldwide
> Run a traceroute to cloudflare.com from Europe and Asia
```

### Historical Analysis
```
> Show routing history for 8.8.8.0/24 from 2024-01-01 to 2024-01-31
> What happened to 1.2.3.0/24 last week?
```

### AS Relationships & Contacts
```
> What are the upstream providers for AS64496?
> Show me all peers of Cloudflare
> Who do I contact about AS15169?
> Is AS12345 a legitimate provider?
```

### Incident Investigation
```
> Our customers can't reach our prefix 203.0.113.0/24
> Why is traffic taking weird paths to 8.8.8.0/24?
> Should we peer with AS64496?
```

## Available Tools (23 total)

| Tool | Description |
|------|-------------|
| `lookup_prefix` | Get origin ASN, AS paths, and visibility for a prefix |
| `get_asn_announcements` | List all prefixes announced by an ASN |
| `get_asn_details` | Detailed ASN analysis with upstream/downstream relationships |
| `get_routing_history` | Historical routing data for a resource |
| `analyze_as_path` | Path diversity, upstream providers, transit ASNs, prepending detection |
| `compare_collectors` | Compare routing views across collectors, detect inconsistencies |
| `get_rpki_status` | RPKI validation (valid/invalid/not-found) |
| `check_prefix_anomalies` | On-demand hijack detection (MOAS, RPKI, origin changes, visibility) |
| `get_anomalies` | Real-time BGP anomalies from bgp-radar |
| `ping_from_global` | Ping from worldwide vantage points |
| `traceroute_from_global` | Traceroute from multiple locations |
| `get_as_relationships` | Get all relationships for an AS (peers, upstreams, downstreams) |
| `get_as_connectivity` | Get connectivity summary for an AS |
| `check_as_relationship` | Check relationship between two specific ASes |
| `get_network_contacts` | Get NOC/abuse contacts from PeeringDB |
| `search_asn` | Search for ASN by name or description |
| `get_ixp_presence` | Get IXP presence for an ASN |

## Commands

### CLI Commands
```bash
uv run bgp-explorer install-deps  # Auto-install Go, Rust, bgp-radar, monocle
uv run bgp-explorer chat          # Start interactive chat
```

### Chat Commands
- `/monitor start` - Start real-time BGP monitoring
- `/monitor stop` - Stop monitoring
- `/monitor status` - Check monitoring status
- `/thinking [budget]` - View or set AI thinking budget (1024-16000 tokens)
- `/export [path]` - Export conversation to JSON
- `/clear` - Clear conversation history
- `/help` - Show help message
- `exit` - Exit the application

## Architecture

```
User → CLI (cli.py) → Agent (agent.py) → AI Backend (claude)
                                              ↓
                                        Tools (ai/tools.py)
                                              ↓
                    ┌─────────────┬───────────┴───────────┬─────────────┐
                    ↓             ↓                       ↓             ↓
              bgp-radar      RIPE Stat              Globalping    BGPStream
            [real-time]    [state/history]          [probing]    [archives]
```

## Data Sources

| Source | Type | Data Provided |
|--------|------|---------------|
| **RIPE Stat** | REST API | Current BGP state, routing history, RPKI validation |
| **bgp-radar** | Subprocess | Real-time anomaly detection (hijacks, leaks, blackholes) |
| **Globalping** | REST API | Global ping, traceroute, MTR, DNS measurements |
| **PeeringDB** | CAIDA dump | Network info, IXP presence, NOC contacts |
| **Monocle** | CLI | AS relationships (peers, upstreams, downstreams) from BGP data |
| **BGPStream** | Library | Historical BGP data from RouteViews and RIPE RIS |

## Development

```bash
# Install with dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=bgp_explorer

# Run linter
uv run ruff check src/

# Run specific test file
uv run pytest tests/test_models/test_route.py -v
```

## Project Structure

```
src/bgp_explorer/
├── cli.py           # Click CLI entrypoint
├── agent.py         # AI agent orchestration
├── config.py        # Pydantic settings
├── output.py        # Output formatting
├── models/          # Data models (BGPRoute, BGPEvent)
├── cache/           # TTL cache implementation
├── sources/         # Data source clients
│   ├── ripe_stat.py   # RIPE Stat REST API
│   ├── bgp_radar.py   # bgp-radar subprocess
│   ├── globalping.py  # Globalping REST API
│   └── bgpstream.py   # BGPStream wrapper
├── analysis/        # Analysis utilities
│   ├── path_analysis.py  # AS path analysis
│   └── as_analysis.py    # ASN relationship analysis
└── ai/              # AI backends
    ├── base.py      # Abstract base class
    ├── claude.py    # Claude implementation
    └── tools.py     # Tool definitions
```

## License

MIT
