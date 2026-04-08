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
- **Network Resilience Assessment**: Score (1-10) any network's resilience based on transit diversity, peering, IXP presence

## Quick Start

```bash
git clone https://github.com/hervehildenbrand/bgp-explorer.git
cd bgp-explorer
uv sync
uv run bgp-explorer install-deps  # Auto-installs Go + Rust + binaries
uv run bgp-explorer chat          # All 8 investigation tools ready!
```

## Use with Claude Code (No API Key Needed)

If you have a **Claude Code subscription** (Pro/Max), you can use BGP Explorer tools directly in Claude Code without needing an Anthropic API key:

```bash
# 1. Clone and install globally
git clone https://github.com/hervehildenbrand/bgp-explorer.git
cd bgp-explorer
uv sync
uv run bgp-explorer install-deps
uv tool install .  # Installs bgp-explorer globally

# 2. Add as MCP server
claude mcp add bgp-explorer -- bgp-explorer mcp

# 3. Use Claude Code normally - BGP tools are available!
claude
> Search for Cloudflare's ASNs and show their peers
> Check if 8.8.8.0/24 is being hijacked
> Ping 1.1.1.1 from Asia
```

### Fix Broken MCP Installation

If MCP isn't working ("Failed to reconnect"), reinstall globally:

```bash
cd /path/to/bgp-explorer  # Go to your clone
uv tool install .
claude mcp remove bgp-explorer 2>/dev/null
claude mcp add bgp-explorer -- bgp-explorer mcp
```

**How it works:** The MCP server exposes 8 composite BGP investigation tools. Each returns a summary by default, with a `sections` parameter for detail. All AI processing uses your Claude Code subscription - no separate API costs.

See [Claude Code Integration](https://github.com/hervehildenbrand/bgp-explorer/wiki/Claude-Code-Integration) in the wiki for details.

## Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** - Fast Python package manager
- **Anthropic API Key** from [Anthropic Console](https://console.anthropic.com/)

### External Dependencies (Auto-installed)

The `install-deps` command automatically installs:

- **Rust** (if missing) - Installs via rustup
- **monocle** (required) - AS relationship data from BGPKIT (`cargo install`)
- **Go** (if missing) - Downloads and extracts to `~/.local/go`
- **bgp-radar** (optional) - Real-time BGP anomaly detection (`go install`)

**Note:** The app works without bgp-radar installed. Real-time monitoring (`/monitor start`) requires bgp-radar. On-demand hijack detection (`investigate_prefix` with anomalies section) works without it.

Binaries are auto-detected in `~/go/bin` and `~/.cargo/bin`.

### Manual Installation (Alternative)

If you prefer to install dependencies manually:

```bash
# monocle (required - requires Rust)
cargo install monocle

# bgp-radar (optional - requires Go, for real-time monitoring)
go install github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest
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

# Optional: MANRS Observatory API key (for official conformance data)
# Register free at https://manrs.org/resources/api/
MANRS_API_KEY=your_manrs_api_key_here
```

### Claude Desktop MCP Setup

When using bgp-explorer as an MCP server in Claude Desktop, API keys must be added
to the Claude Desktop config (`.env` is not read by the MCP process):

```json
// ~/Library/Application Support/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "bgp-explorer": {
      "command": "/path/to/bgp-explorer/.venv/bin/bgp-explorer",
      "args": ["mcp"],
      "env": {
        "MANRS_API_KEY": "your-manrs-api-key-here"
      }
    }
  }
}
```

> **Note:** Restart Claude Desktop after changing this file.

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

### Network Resilience Assessment
```
> Assess the resilience of AS15169
> How resilient is Cloudflare's network?
> Check if AS64496 has good transit diversity
```

### Incident Investigation
```
> Our customers can't reach our prefix 203.0.113.0/24
> Why is traffic taking weird paths to 8.8.8.0/24?
> Should we peer with AS64496?
```

## Available Tools (8 composite tools)

Each tool returns a **summary by default**. Use the `sections` parameter to expand specific areas.

| Tool | Purpose | Sections |
|------|---------|----------|
| `search_asn` | Find ASNs by organization name | — |
| `investigate_asn` | Everything about an ASN | summary, connectivity, announcements, contacts, resilience, whois |
| `investigate_prefix` | Everything about a prefix | summary, routing, anomalies, paths, collectors, looking_glass |
| `check_rpki` | RPKI/ROA/ASPA analysis | summary, roa_coverage, roa_guidance, aspa_status, aspa_guidance, rov_coverage (+ AS path validation mode) |
| `get_routing_history_v2` | Historical routing and stability | summary, origins, paths, stability, updates |
| `investigate_ixp` | IXP presence or details | Auto-detects: ASN → presence, IXP name → details + members |
| `probe_network` | Ping/traceroute from global probes | type: ping (default) or traceroute |
| `run_audit` | DORA/NIS2/MANRS compliance | framework: dora, nis2, manrs, or all (default) |

### MANRS Audit Details

The `run_audit(framework='manrs')` assesses 3 of the 4 MANRS Actions:

| Action | What we measure | Operator must verify |
|--------|----------------|---------------------|
| **Action 1: Filtering** | Indirect proxy: ROA coverage + ROV enforcer paths | Enable ROV on eBGP sessions, apply IRR prefix filters, set max-prefix limits |
| **Action 2: Anti-Spoofing** | *Excluded — cannot be verified externally* | Deploy uRPF/BCP38 on customer-facing interfaces, self-test via [CAIDA Spoofer](https://spoofer.caida.org/) |
| **Action 3: Coordination** | PeeringDB NOC contacts + WHOIS abuse contact | Ensure contacts are monitored and responsive |
| **Action 4: Validation** | ROA coverage % + ASPA object published | Create missing ROAs at RIR portal, publish ASPA object |

## Commands

### CLI Commands
```bash
uv run bgp-explorer install-deps  # Auto-install Go, Rust, bgp-radar, monocle
uv run bgp-explorer chat          # Start interactive chat (requires API key)
uv run bgp-explorer assess <asn>  # Assess network resilience for an ASN
uv run bgp-explorer mcp           # Start MCP server for Claude Code integration
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
              ┌──────────┬──────────┬─────────┴────────┬──────────┬──────────┐
              ↓          ↓          ↓                  ↓          ↓          ↓
        bgp-radar    RIPE Stat   rpki-client       Globalping  Monocle   CAIDA
        [realtime]  [state/hist] [ASPA+ROA]        [probing]   [AS rel]  [AS rel]
```

## Data Sources

| Source | Type | Data Provided | Auth |
|--------|------|---------------|------|
| **RIPE Stat** | REST API | Current BGP state, routing history, RPKI validation | Free, no key |
| **rpki-client console** | REST API | Validated ROA (~825K) + ASPA (~1,472) objects from global RPKI | Free, no key |
| **CAIDA Relationships** | HTTP | Inferred AS relationships (provider-customer, peering) | Free, no key |
| **bgp-radar** | Subprocess | Real-time anomaly detection (hijacks, leaks, blackholes) | Local binary |
| **Globalping** | REST API | Global ping, traceroute, MTR, DNS measurements | Free tier |
| **PeeringDB** | CAIDA dump | Network info, IXP presence, NOC contacts | Free, no key |
| **Monocle** | CLI | AS relationships (peers, upstreams, downstreams) from BGP data | Local binary |
| **MANRS Observatory** | REST API | Official MANRS conformance scores per ASN | Free, key required |
| **BGPStream** | Library | Historical BGP data from RouteViews and RIPE RIS | Free, no key |

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
├── mcp_server.py    # MCP server (8 composite tools)
├── sources/         # Data source clients
│   ├── ripe_stat.py      # RIPE Stat REST API
│   ├── bgp_radar.py      # bgp-radar subprocess
│   ├── globalping.py     # Globalping REST API
│   ├── rpki_console.py   # rpki-client console (ROA + ASPA)
│   ├── manrs.py          # MANRS Observatory API
│   ├── monocle.py        # Monocle CLI wrapper
│   ├── peeringdb.py      # PeeringDB network data
│   └── bgpstream.py      # BGPStream wrapper
├── analysis/        # Analysis utilities
│   ├── path_analysis.py       # AS path analysis
│   ├── as_analysis.py         # ASN relationship analysis
│   ├── resilience.py          # Network resilience assessment
│   ├── aspa_validation.py     # ASPA path validation
│   ├── rov_coverage.py        # ROV coverage analysis
│   ├── compliance.py          # DORA/NIS2/MANRS compliance auditing
│   ├── manrs_conformance.py   # MANRS readiness assessment
│   └── stability.py           # Route stability analysis
└── ai/              # AI backends
    ├── base.py      # Abstract base class
    ├── claude.py    # Claude implementation
    └── tools.py     # Tool definitions (standalone CLI)
```

## License

MIT
