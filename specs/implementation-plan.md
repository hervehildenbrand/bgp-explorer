# BGP Explorer - Implementation Plan

## Overview

**Project:** bgp-explorer
**Location:** `/Users/hervehildenbrand/Code/bgp-explorer`
**Purpose:** AI-powered CLI for querying live and historical internet routing data using natural language

### Prerequisite: bgp-radar

**Repository:** https://github.com/hervehildenbrand/bgp-radar
**Location:** `/Users/hervehildenbrand/Code/bgp-radar`
**Purpose:** Real-time BGP anomaly detection (hijacks, route leaks, blackholes) via RIPE RIS Live

## Summary of Decisions

| Decision | Choice |
|----------|--------|
| Project type | New standalone project |
| Target users | Network operators investigating incidents |
| Python version | 3.11+ |
| Data sources | bgp-radar (required), RIPE Stat, Globalping |
| bgp-radar integration | Read JSON from stdout (pipe) |
| bgp-radar binary | PATH lookup, override via `--bgp-radar-path` or `BGP_RADAR_PATH` env |
| bgp-radar failure | Retry 3 times, then exit with error |
| AI backends | Both Gemini and Claude (configurable) |
| AI requirement | Required - no offline mode |
| Data storage | In-memory cache with TTL |
| Interface | CLI chat only |
| Output formats | Conversational text, JSON export, save to file |
| Tooling | uv + pyproject.toml |
| RPKI | Yes - validate routes |
| Delivery | Incremental milestones |

---

## Project Structure

```
/Users/hervehildenbrand/Code/bgp-explorer/
├── pyproject.toml
├── README.md
├── .env.example
├── .gitignore
├── src/bgp_explorer/
│   ├── __init__.py
│   ├── cli.py                    # Click CLI entrypoint
│   ├── agent.py                  # AI agent orchestration
│   ├── config.py                 # Pydantic configuration
│   ├── models/
│   │   ├── __init__.py
│   │   ├── route.py              # BGPRoute dataclass
│   │   └── rpki.py               # RPKI validation models
│   ├── cache/
│   │   ├── __init__.py
│   │   └── ttl_cache.py          # TTL-based in-memory cache
│   ├── sources/
│   │   ├── __init__.py
│   │   ├── base.py               # Abstract base class
│   │   ├── bgp_radar.py          # bgp-radar client (real-time anomalies)
│   │   ├── ripe_stat.py          # RIPE Stat REST API (state + history)
│   │   ├── globalping.py         # Globalping API (network probing)
│   │   └── bgpstream.py          # CAIDA BGPStream wrapper (optional)
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── base.py               # Abstract AI backend
│   │   ├── gemini.py             # Google Gemini backend
│   │   ├── claude.py             # Anthropic Claude backend
│   │   └── tools.py              # Tool definitions for AI
│   └── analysis/
│       ├── __init__.py
│       ├── prefix_lookup.py
│       ├── as_analysis.py
│       ├── path_analysis.py
│       └── rpki_validator.py
└── tests/
    ├── conftest.py
    ├── test_models/
    ├── test_cache/
    ├── test_sources/
    └── test_ai/
```

---

## Phase 1: MVP (RIS Live + RIPE Stat + Gemini)

### Step 1.1: Project Scaffolding
- [ ] Create directory structure
- [ ] Initialize `pyproject.toml` with uv
- [ ] Create `.gitignore`, `.env.example`
- [ ] Set up pytest configuration

### Step 1.2: Core Data Models
- [ ] `models/route.py` - BGPRoute dataclass with fields:
  - prefix, origin_asn, as_path, next_hop, origin
  - collector, peer_ip, peer_asn, timestamp, source
  - rpki_status (optional)
- [ ] Write unit tests for route model

### Step 1.3: TTL Cache Implementation
- [ ] `cache/ttl_cache.py` - Async-safe TTL cache
- [ ] Support configurable TTL (default 5 minutes)
- [ ] Cleanup method for expired entries
- [ ] Write unit tests

### Step 1.4: RIPE Stat REST Client
- [ ] `sources/ripe_stat.py` - Implement:
  - `get_routes_for_prefix(prefix)` via `/bgp-state/`
  - `get_routes_for_asn(asn)` via `/routing-status/`
  - `get_rpki_validation(prefix, origin)` via `/rpki-validation/`
  - `get_looking_glass(resource)`
  - `get_routing_history(resource, starttime, endtime)` via `/routing-history/`
  - `get_bgp_events(resource, starttime, endtime)` via `/bgplay/`
  - `get_first_last_seen(resource)` via `/ris-first-last-seen/`
- [ ] Parse responses into BGPRoute objects
- [ ] Write integration tests with mocked responses

### Step 1.5: bgp-radar Client (Real-time Anomalies)
- [ ] `sources/bgp_radar.py` - Implement:
  - Spawn bgp-radar subprocess and read JSON from stdout pipe
  - `start(collectors)` - Start bgp-radar process with specified collectors
  - `stop()` - Gracefully terminate bgp-radar process
  - `get_recent_anomalies(type, prefix, asn)` - Query cached events
  - `stream_anomalies()` async iterator for live events
  - Parse event types: hijack, leak, blackhole
- [ ] Buffer events in TTL cache for recent event queries
- [ ] Handle process lifecycle (restart on crash)
- [ ] Write tests with mocked subprocess output

### Step 1.6: Gemini AI Backend
- [ ] `ai/base.py` - Abstract AIBackend class
- [ ] `ai/gemini.py` - Google Gemini implementation:
  - Initialize with API key
  - Register tools as callable functions
  - Handle tool execution loop
  - Maintain conversation history
- [ ] Write basic tests

### Step 1.7: AI Tools (Basic Set)
- [ ] `ai/tools.py` - Implement:
  - `lookup_prefix(prefix)` - Origin ASN, AS paths, visibility
  - `get_asn_announcements(asn)` - Prefixes announced by ASN
- [ ] Connect tools to data sources

### Step 1.8: CLI Chat Interface
- [ ] `cli.py` - Click CLI with:
  - `--backend` option (gemini/claude)
  - `--api-key` option (or env var)
  - `--bgp-radar-path` option (or `BGP_RADAR_PATH` env, default: lookup in PATH)
  - `--collectors` option for bgp-radar (default: rrc00)
  - `--output` option (text/json/both)
  - `--save` option to export results to file
  - `chat` command for interactive session
- [ ] `agent.py` - Orchestration:
  - Initialize bgp-radar subprocess and data sources
  - Route user messages through AI
  - Execute tool calls and return results
  - Format output based on user preference
- [ ] `output.py` - Output formatting:
  - Conversational text (default)
  - JSON structured data
  - Save/export to file with timestamp

### Step 1.9: Testing & Documentation
- [ ] Run full test suite
- [ ] Basic README with usage instructions
- [ ] `.env.example` with required keys

**Phase 1 Dependencies:**
```toml
[project]
requires-python = ">=3.11"

dependencies = [
    "click>=8.1",
    "aiohttp>=3.9",
    "google-generativeai>=0.8",
    "pydantic>=2.0",
    "python-dotenv>=1.0",
    "rich>=13.0",              # Pretty terminal output
]
```

---

## Phase 2: Claude Backend + BGPStream

### Step 2.1: Claude AI Backend
- [ ] `ai/claude.py` - Anthropic implementation:
  - Convert Python functions to Claude tool schema
  - Handle tool_use response blocks
  - Execute tools and continue conversation
- [ ] Backend selection in config/CLI

### Step 2.2: BGPStream Client
- [ ] `sources/bgpstream.py` - pybgpstream wrapper:
  - Wrap sync library with asyncio executor
  - `get_routes_for_prefix(prefix)`
  - `get_routes_for_asn(asn)`
  - Support RIB and update queries
- [ ] Note: Requires libBGPStream C library (optional dep)

### Step 2.3: Enhanced Tools
- [ ] `analyze_as_path(prefix)` - Path diversity analysis
- [ ] `compare_collectors(prefix, collectors)` - Cross-collector view
- [ ] `detect_routing_changes(prefix, time_window)`

### Step 2.4: Analysis Modules
- [ ] `analysis/path_analysis.py` - AS path utilities
- [ ] `analysis/as_analysis.py` - ASN relationship analysis

### Step 2.5: Globalping Integration (Network Probing)
- [ ] `sources/globalping.py` - Implement:
  - `ping_prefix(target, locations)` - Ping from global probes
  - `traceroute_prefix(target, locations)` - Traceroute from multiple vantage points
  - `mtr_prefix(target, locations)` - Combined MTR analysis
  - `dns_lookup(domain, locations)` - DNS resolution from global probes
- [ ] Parse measurement results into unified format
- [ ] Write tests with mocked API responses

**Phase 2 Additional Dependencies:**
```toml
dependencies = [
    "anthropic>=0.40",
]
[project.optional-dependencies]
bgpstream = ["pybgpstream>=2.0"]
```

---

## Phase 3: RPKI + Advanced Features

### Step 3.1: RPKI Validation
- [ ] `analysis/rpki_validator.py` - Validation logic
- [ ] `check_rpki_status(prefix, origin_asn)` tool
- [ ] Integrate RPKI status into route lookups

### Step 3.2: Advanced Analysis Tools
- [ ] `get_upstream_providers(asn)` - Transit relationship detection
- [ ] Enhanced anomaly detection in routing changes

### Step 3.3: Documentation & Polish
- [ ] Comprehensive README with examples
- [ ] Example queries documentation
- [ ] Configuration file support (YAML)

---

## Key Data Models

### BGPRoute (Unified Route Representation)
```python
@dataclass
class BGPRoute:
    prefix: str              # "192.0.2.0/24"
    origin_asn: int          # Originating AS
    as_path: List[int]       # Full AS path
    next_hop: str            # Next hop IP
    origin: str              # "igp", "egp", "incomplete"
    communities: List[str]   # BGP communities
    collector: str           # "rrc21", "route-views2"
    peer_ip: str             # Peer that sent this
    peer_asn: int            # Peer ASN
    timestamp: datetime      # When received
    source: str              # "ris_live", "ripe_stat", "bgpstream"
    rpki_status: Optional[str]  # "valid", "invalid", "not-found"
```

---

## AI Tools Summary

| Tool | Description | Phase |
|------|-------------|-------|
| `lookup_prefix(prefix)` | Get origin ASN, paths, visibility | 1 |
| `get_asn_announcements(asn)` | List prefixes announced by ASN | 1 |
| `get_routing_history(resource, start, end)` | Historical routing timelines for prefix/ASN | 1 |
| `get_bgp_events(resource, start, end)` | BGP announcements/withdrawals in time window | 1 |
| `get_anomalies(type, prefix, asn)` | Real-time anomalies from bgp-radar | 1 |
| `analyze_as_path(prefix)` | Path diversity across collectors | 2 |
| `compare_collectors(prefix)` | Compare routing views | 2 |
| `detect_routing_changes(prefix)` | Recent announcements/withdrawals | 2 |
| `ping_from_global(target, locations)` | Ping target from global probes (Globalping) | 2 |
| `traceroute_from_global(target, locations)` | Traceroute from multiple vantage points | 2 |
| `check_rpki_status(prefix, asn)` | ROA validation status | 3 |
| `get_upstream_providers(asn)` | Transit provider analysis | 3 |

---

## External APIs Reference

### bgp-radar (Prerequisite)
- **Repository:** https://github.com/hervehildenbrand/bgp-radar
- **Install:** `go install github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest`
- **Run:** `bgp-radar -collectors=rrc00,rrc01` (JSON to stdout)
- **With DB:** `bgp-radar -collectors=rrc00 -database=postgres://... -redis=redis://...`
- **Event format:**
  ```json
  {"type": "hijack", "severity": "high", "affected_prefix": "1.1.1.0/24", "affected_asn": 13335, ...}
  ```
- **Anomaly types:** `hijack` (origin changes), `leak` (Tier1→SmallAS→Tier1), `blackhole` (RFC7999)

### RIPE Stat
- **Base:** `https://stat.ripe.net/data/`
- **Docs:** https://stat.ripe.net/docs/02.data-api/
- **Current State Endpoints:**
  - `/bgp-state/data.json?resource=<prefix>`
  - `/routing-status/data.json?resource=AS<asn>`
  - `/rpki-validation/data.json?resource=<prefix>&origin=<asn>`
  - `/looking-glass/data.json?resource=<prefix>`
- **Historical Data Endpoints:**
  - `/routing-history/data.json?resource=<prefix|ASN>&starttime=<ISO8601>&endtime=<ISO8601>`
    - Returns: timelines of announcement periods by origin ASN
    - Params: `max_rows`, `min_peers`, `include_first_hop`, `normalise_visibility`
  - `/bgplay/data.json?resource=<prefix>&starttime=<ISO8601>&endtime=<ISO8601>`
    - Returns: initial_state, BGP events, AS nodes, collector sources
    - Params: `rrcs` (collector filter), `unix_timestamps`
    - Note: Only data after January 2024 is indexed
  - `/ris-first-last-seen/data.json?resource=<prefix>`
    - Returns: first and last observation timestamps for prefix visibility
- **Availability Check:** `/data/<endpoint>/meta/availability` - returns starttime/endtime of available data
- **Rate Limits:** Max 8 concurrent requests per IP, no hard limits but registration recommended for >1000 req/day

### BGPStream (via pybgpstream)
- Projects: `ris-live`, `routeviews`, `ris`
- Record types: `ribs`, `updates`

### Globalping (Network Probing)
- **Repository:** https://github.com/jsdelivr/globalping
- **API:** `https://api.globalping.io/v1/measurements`
- **CLI:** `brew install globalping` / `apt install globalping`
- **Tests:** ping, traceroute, MTR, DNS, HTTP
- **Probes:** Hundreds of globally distributed servers
- **Rate Limits:** Free tier with limits; register at globalping.io for higher quotas
- **Request format:**
  ```json
  POST /v1/measurements
  {"type": "ping", "target": "1.1.1.0", "locations": [{"country": "US"}, {"country": "DE"}]}
  ```

---

## Verification Plan

### Phase 1 Verification
```bash
# 1. Install and setup
cd /Users/hervehildenbrand/Code/bgp-explorer
uv sync
cp .env.example .env
# Edit .env with GEMINI_API_KEY

# 2. Run tests
uv run pytest

# 3. Test CLI
uv run bgp-explorer chat

# 4. Test queries
> Who originates 8.8.8.0/24?
> What prefixes does AS15169 announce?
> exit
```

### Phase 2 Verification
```bash
# Test with Claude backend
ANTHROPIC_API_KEY=... uv run bgp-explorer --backend claude chat

# Test BGPStream (if libBGPStream installed)
uv sync --extra bgpstream
> Compare 8.8.8.0/24 across collectors
```

### Phase 3 Verification
```bash
# Test RPKI validation
> Is 8.8.8.0/24 from AS15169 RPKI valid?
> Check RPKI status for 1.1.1.0/24 from AS13335
```

---

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| pybgpstream requires C library | Make optional dependency, document installation |
| RIS Live high volume | Filter on subscribe, buffer with overflow handling |
| RIPE Stat rate limits | Request throttling, aggressive caching |
| AI tool execution loops | Max iterations limit, timeout |
| Different source formats | Unified BGPRoute normalizes all data |

---

## Progress

### Current Status
> Phase 1 MVP Complete

### Completed
- [x] Requirements gathering
- [x] Architecture design
- [x] Phase breakdown
- [x] Phase 1 Implementation:
  - [x] Step 1.1: Project scaffolding (pyproject.toml, .gitignore, .env.example)
  - [x] Step 1.2: Core data models (BGPRoute, BGPEvent)
  - [x] Step 1.3: TTL cache implementation
  - [x] Step 1.4: RIPE Stat REST client
  - [x] Step 1.5: bgp-radar subprocess client
  - [x] Step 1.6: Gemini AI backend
  - [x] Step 1.7: AI tools (lookup_prefix, get_asn_announcements, get_routing_history, get_anomalies, get_rpki_status)
  - [x] Step 1.8: CLI chat interface
  - [x] Step 1.9: Testing & documentation

### Test Results
- 95 tests passing
- All core functionality verified

### Next Steps
1. Phase 2: Claude backend + BGPStream
2. Phase 3: RPKI + Advanced features
