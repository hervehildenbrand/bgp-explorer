"""BGPKIT Monocle CLI client for AS relationship data.

Monocle analyzes BGP routing tables from 1,762+ global peers to provide
accurate peer/upstream/downstream relationships derived from real BGP data.

See: https://github.com/bgpkit/monocle
"""

import asyncio
import json
import os
import shutil

from bgp_explorer.models.as_relationship import (
    ASConnectivity,
    ASRelationship,
)
from bgp_explorer.sources.base import DataSource


class MonocleClient(DataSource):
    """Client for BGPKIT Monocle CLI.

    Provides access to AS relationship data derived from BGP routing tables:
    - Peer relationships: Networks that exchange traffic directly
    - Upstream/downstream: Transit provider/customer relationships
    - Connectivity summaries: Overview of an AS's network position

    Unlike other data sources, Monocle is a one-shot CLI tool, not a
    long-running service. Each method executes a subprocess command.
    """

    def __init__(
        self,
        binary_path: str | None = None,
        timeout: float = 30.0,
        use_cache: bool = True,
    ):
        """Initialize the Monocle client.

        Args:
            binary_path: Path to monocle binary. If not specified,
                         uses MONOCLE_PATH env var or searches PATH.
            timeout: Command execution timeout in seconds.
            use_cache: If True, uses --no-refresh for faster cached results.
        """
        self._binary_path = binary_path or os.environ.get("MONOCLE_PATH") or self._find_binary()
        self._timeout = timeout
        self._use_cache = use_cache

    @staticmethod
    def _find_binary() -> str | None:
        """Find monocle binary in PATH or common locations.

        Returns:
            Path to monocle binary, or None if not found.
        """
        # Check PATH first
        path_binary = shutil.which("monocle")
        if path_binary:
            return path_binary

        # Check common Cargo install locations
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, ".cargo", "bin", "monocle"),
        ]

        for candidate in candidates:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    async def connect(self) -> None:
        """No-op for Monocle (one-shot CLI tool)."""
        pass

    async def disconnect(self) -> None:
        """No-op for Monocle (one-shot CLI tool)."""
        pass

    async def is_available(self) -> bool:
        """Check if monocle binary exists and is executable.

        Returns:
            True if monocle is available.
        """
        if not self._binary_path:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                self._binary_path,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=5.0)
            return process.returncode == 0
        except Exception:
            return False

    async def _run_command(self, args: list[str]) -> dict:
        """Execute a monocle command and parse JSON output.

        Args:
            args: Command arguments (without binary path).

        Returns:
            Parsed JSON response.

        Raises:
            RuntimeError: If binary not available or command fails.
            TimeoutError: If command exceeds timeout.
        """
        if not self._binary_path:
            raise RuntimeError("Monocle binary not found. Install with: cargo install monocle")

        cmd = [self._binary_path] + args + ["--json"]
        if self._use_cache:
            cmd.append("--no-refresh")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self._timeout,
            )
        except TimeoutError:
            process.kill()
            raise TimeoutError(f"Monocle command timed out after {self._timeout}s")

        if process.returncode != 0:
            error_msg = stderr.decode().strip() if stderr else "Unknown error"
            raise RuntimeError(f"Monocle command failed: {error_msg}")

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Monocle JSON output: {e}")

    async def get_as_relationships(
        self,
        asn: int,
        min_visibility: float | None = None,
        relationship_filter: str | None = None,
    ) -> list[ASRelationship]:
        """Get all relationships for an Autonomous System.

        Args:
            asn: Autonomous System Number to query.
            min_visibility: Minimum visibility percentage (0-100) to include.
            relationship_filter: Filter by type: "peer", "upstream", or "downstream".

        Returns:
            List of ASRelationship objects for the AS's neighbors.
        """
        data = await self._run_command(["as2rel", str(asn), "--show-name"])

        relationships = []
        for item in data.get("results", []):
            rel = ASRelationship.from_dict(item)

            # Apply visibility filter
            if min_visibility is not None and rel.connected_pct < min_visibility:
                continue

            # Apply relationship type filter
            if relationship_filter is not None:
                if rel.relationship_type != relationship_filter:
                    continue

            relationships.append(rel)

        return relationships

    async def get_as_peers(
        self, asn: int, min_visibility: float | None = None
    ) -> list[ASRelationship]:
        """Get all peer relationships for an AS.

        Args:
            asn: Autonomous System Number to query.
            min_visibility: Minimum visibility percentage to include.

        Returns:
            List of peer ASRelationship objects.
        """
        return await self.get_as_relationships(
            asn, min_visibility=min_visibility, relationship_filter="peer"
        )

    async def get_as_upstreams(
        self, asn: int, min_visibility: float | None = None
    ) -> list[ASRelationship]:
        """Get upstream providers for an AS.

        Args:
            asn: Autonomous System Number to query.
            min_visibility: Minimum visibility percentage to include.

        Returns:
            List of upstream ASRelationship objects.
        """
        return await self.get_as_relationships(
            asn, min_visibility=min_visibility, relationship_filter="upstream"
        )

    async def get_as_downstreams(
        self, asn: int, min_visibility: float | None = None
    ) -> list[ASRelationship]:
        """Get downstream customers of an AS.

        Args:
            asn: Autonomous System Number to query.
            min_visibility: Minimum visibility percentage to include.

        Returns:
            List of downstream ASRelationship objects.
        """
        return await self.get_as_relationships(
            asn, min_visibility=min_visibility, relationship_filter="downstream"
        )

    async def check_relationship(
        self,
        asn1: int,
        asn2: int,
    ) -> ASRelationship | None:
        """Check the relationship between two specific ASes.

        Args:
            asn1: First Autonomous System Number.
            asn2: Second Autonomous System Number.

        Returns:
            ASRelationship if a relationship exists, None otherwise.
        """
        data = await self._run_command(["as2rel", str(asn1), str(asn2), "--show-name"])

        results = data.get("results", [])
        if not results:
            return None

        return ASRelationship.from_dict(results[0])

    async def get_connectivity(self, asn: int) -> ASConnectivity:
        """Get connectivity summary for an AS.

        Provides counts and top examples of upstreams, peers, and downstreams.

        Args:
            asn: Autonomous System Number to query.

        Returns:
            ASConnectivity summary with neighbor categories.
        """
        data = await self._run_command(["inspect", str(asn), "--show", "connectivity"])

        # Navigate to the connectivity data
        queries = data.get("queries", [])
        if not queries:
            raise RuntimeError(f"No data returned for AS{asn}")

        query = queries[0]
        connectivity = query.get("connectivity", {})
        summary = connectivity.get("summary", {})

        if not summary:
            raise RuntimeError(f"No connectivity data for AS{asn}")

        # Get max_peers from the as2rel response pattern if available
        # For inspect, we use the summary data
        max_peers = 0
        upstreams = summary.get("upstreams", {})
        if upstreams.get("top"):
            max_peers = max(n.get("peers_count", 0) for n in upstreams.get("top", [{}]))
        peers = summary.get("peers", {})
        if peers.get("top"):
            max_peers = max(max_peers, max(n.get("peers_count", 0) for n in peers.get("top", [{}])))

        return ASConnectivity.from_dict(summary, asn, max_peers)
