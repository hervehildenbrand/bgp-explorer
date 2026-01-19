"""Globalping API client for global network probing.

Globalping provides distributed network measurements from hundreds of
probes worldwide, enabling ping, traceroute, MTR, DNS, and HTTP tests
from multiple vantage points.

See: https://github.com/jsdelivr/globalping
API Docs: https://globalping.io/docs/api
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from bgp_explorer.sources.base import DataSource


@dataclass
class ProbeResult:
    """Result from a single probe."""

    continent: str
    country: str
    city: str
    asn: int
    network: str
    status: str
    raw_output: str
    # Ping/MTR stats
    min_latency: float | None = None
    avg_latency: float | None = None
    max_latency: float | None = None
    packet_loss: float | None = None
    # Traceroute/MTR hops
    hops: list[dict[str, Any]] | None = None
    # DNS answers
    dns_answers: list[dict[str, Any]] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProbeResult":
        """Create ProbeResult from API response."""
        probe = data.get("probe", {})
        result = data.get("result", {})
        stats = result.get("stats", {})

        return cls(
            continent=probe.get("continent", ""),
            country=probe.get("country", ""),
            city=probe.get("city", ""),
            asn=probe.get("asn", 0),
            network=probe.get("network", ""),
            status=result.get("status", "unknown"),
            raw_output=result.get("rawOutput", ""),
            min_latency=stats.get("min"),
            avg_latency=stats.get("avg"),
            max_latency=stats.get("max"),
            packet_loss=stats.get("loss"),
            hops=result.get("hops"),
            dns_answers=result.get("answers"),
        )


@dataclass
class MeasurementResult:
    """Result of a Globalping measurement."""

    measurement_id: str
    measurement_type: str
    target: str
    status: str
    probes: list[ProbeResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "measurement_id": self.measurement_id,
            "type": self.measurement_type,
            "target": self.target,
            "status": self.status,
            "probes": [
                {
                    "country": p.country,
                    "city": p.city,
                    "asn": p.asn,
                    "network": p.network,
                    "avg_latency": p.avg_latency,
                    "packet_loss": p.packet_loss,
                }
                for p in self.probes
            ],
        }


class GlobalpingClient(DataSource):
    """Client for Globalping API.

    Provides access to global network measurement capabilities:
    - Ping: Latency measurements from global probes
    - Traceroute: Path analysis from multiple vantage points
    - MTR: Combined ping/traceroute with statistics
    - DNS: DNS resolution from different locations

    See: https://globalping.io/docs/api
    """

    BASE_URL = "https://api.globalping.io/v1"

    def __init__(
        self,
        api_token: str | None = None,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        max_polls: int = 60,
    ):
        """Initialize the client.

        Args:
            api_token: Optional API token for higher rate limits.
            timeout: HTTP request timeout in seconds.
            poll_interval: Interval between polling for results.
            max_polls: Maximum polling attempts before timeout.
        """
        self._api_token = api_token
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._max_polls = max_polls
        self._session: aiohttp.ClientSession | None = None

    async def connect(self) -> None:
        """Create HTTP session."""
        headers = {"Content-Type": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        self._session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self._timeout),
        )

    async def disconnect(self) -> None:
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        """Check if Globalping API is available."""
        try:
            if not self._session:
                return False
            async with self._session.get(f"{self.BASE_URL}/probes") as response:
                return response.status == 200
        except Exception:
            return False

    def _parse_locations(
        self,
        locations: list[dict[str, Any] | str] | None = None,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Parse and validate location specifications.

        Args:
            locations: List of location specs. Can be dicts with keys like
                'country', 'continent', 'asn', or simple strings like
                'EU', 'US', 'Europe', 'Asia' which will be converted to
                country or continent filters as appropriate.
            limit: Number of probes per location when using defaults.

        Returns:
            Validated location list.
        """
        if not locations:
            return self._default_locations(limit)

        # Map common country names/aliases to ISO country codes
        # These take priority over continent matching
        country_map = {
            "us": "US",
            "usa": "US",
            "united states": "US",
            "uk": "GB",
            "united kingdom": "GB",
            "britain": "GB",
            "germany": "DE",
            "france": "FR",
            "japan": "JP",
            "australia": "AU",
            "canada": "CA",
            "brazil": "BR",
            "india": "IN",
            "china": "CN",
            "singapore": "SG",
            "netherlands": "NL",
            "holland": "NL",
        }

        # Map common region names to continent codes
        region_map = {
            "europe": "EU",
            "eu": "EU",
            "north america": "NA",
            "na": "NA",
            "asia": "AS",
            "as": "AS",
            "oceania": "OC",
            "oc": "OC",
            "south america": "SA",
            "sa": "SA",
            "africa": "AF",
            "af": "AF",
        }

        result = []
        for loc in locations:
            if isinstance(loc, str):
                # Convert string to location dict
                loc_lower = loc.lower().strip()

                # First check for country names/aliases
                if loc_lower in country_map:
                    loc = {"country": country_map[loc_lower], "limit": limit}
                # Then check for continent/region names
                elif loc_lower in region_map:
                    loc = {"continent": region_map[loc_lower], "limit": limit}
                elif len(loc) == 2:
                    # Assume 2-letter code is a country code (ISO 3166-1 alpha-2)
                    loc = {"country": loc.upper(), "limit": limit}
                else:
                    # Try as continent code or country name
                    loc = {"continent": loc.upper(), "limit": limit}
            elif isinstance(loc, dict):
                if "limit" not in loc:
                    loc = {**loc, "limit": limit}
            result.append(loc)
        return result

    def _default_locations(self, limit: int = 3) -> list[dict[str, Any]]:
        """Get default global probe locations.

        Args:
            limit: Number of probes per location.

        Returns:
            List of location specifications with limits.
        """
        return [
            {"continent": "EU", "limit": limit},
            {"continent": "NA", "limit": limit},
            {"continent": "AS", "limit": limit},
            {"continent": "OC", "limit": max(1, limit // 2)},
            {"continent": "SA", "limit": max(1, limit // 2)},
        ]

    async def _create_measurement(
        self,
        measurement_type: str,
        target: str,
        locations: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        limit: int = 3,
    ) -> str:
        """Create a new measurement.

        Args:
            measurement_type: Type of measurement (ping, traceroute, mtr, dns, http).
            target: Target host or IP.
            locations: List of probe locations.
            options: Measurement-specific options.
            limit: Number of probes per location.

        Returns:
            Measurement ID.

        Raises:
            RuntimeError: If session not connected.
            aiohttp.ClientError: On API errors.
        """
        if not self._session:
            raise RuntimeError("Client not connected. Use 'async with' or call connect().")

        payload: dict[str, Any] = {
            "type": measurement_type,
            "target": target,
            "locations": self._parse_locations(locations, limit),
        }

        if options:
            payload["measurementOptions"] = options

        async with self._session.post(
            f"{self.BASE_URL}/measurements",
            json=payload,
        ) as response:
            if response.status == 422:
                # Validation error - usually means no probes available in requested locations
                error_data = await response.json()
                error_msg = error_data.get("error", {}).get("message", "")
                error_type = error_data.get("error", {}).get("type", "")

                # Check if it's a probe availability issue
                if "no suitable probes" in error_msg.lower() or "probes" in error_msg.lower():
                    requested_locs = ", ".join(
                        str(loc.get("country") or loc.get("continent"))
                        for loc in payload.get("locations", [])
                    )
                    raise ValueError(
                        f"No probes available in requested location(s): {requested_locs}. "
                        f"Try a different region like 'Europe', 'Asia', or specific countries like 'DE', 'GB', 'JP'."
                    )
                raise ValueError(f"Globalping API error: {error_msg or error_type}")

            if response.status == 400:
                error_data = await response.json()
                error_msg = error_data.get("error", {}).get("message", "Bad request")
                raise ValueError(f"Globalping API error: {error_msg}")

            response.raise_for_status()
            data = await response.json()
            return data["id"]

    async def _get_results(self, measurement_id: str) -> dict[str, Any]:
        """Poll for measurement results.

        Args:
            measurement_id: The measurement ID to poll.

        Returns:
            Complete measurement results.

        Raises:
            TimeoutError: If max polls exceeded.
        """
        if not self._session:
            raise RuntimeError("Client not connected.")

        for _ in range(self._max_polls):
            async with self._session.get(
                f"{self.BASE_URL}/measurements/{measurement_id}"
            ) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("status") in ("finished", "failed"):
                    return data

            await asyncio.sleep(self._poll_interval)

        raise TimeoutError(f"Measurement {measurement_id} did not complete in time")

    async def _run_measurement(
        self,
        measurement_type: str,
        target: str,
        locations: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
        limit: int = 3,
    ) -> MeasurementResult:
        """Run a complete measurement cycle.

        Args:
            measurement_type: Type of measurement.
            target: Target host.
            locations: Probe locations.
            options: Measurement options.
            limit: Number of probes per location.

        Returns:
            MeasurementResult with all probe results.
        """
        measurement_id = await self._create_measurement(
            measurement_type, target, locations, options, limit
        )

        data = await self._get_results(measurement_id)

        probes = [
            ProbeResult.from_dict(r)
            for r in data.get("results", [])
        ]

        return MeasurementResult(
            measurement_id=measurement_id,
            measurement_type=measurement_type,
            target=target,
            status=data.get("status", "unknown"),
            probes=probes,
        )

    async def ping(
        self,
        target: str,
        locations: list[dict[str, Any]] | None = None,
        packets: int = 3,
        limit: int = 3,
    ) -> MeasurementResult:
        """Run ping measurement from global probes.

        Args:
            target: Target IP or hostname.
            locations: List of probe locations (default: global spread).
            packets: Number of ping packets (default: 3).
            limit: Number of probes per location (default: 3).

        Returns:
            MeasurementResult with latency data from each probe.
        """
        options = {"packets": packets}
        return await self._run_measurement("ping", target, locations, options, limit)

    async def traceroute(
        self,
        target: str,
        locations: list[dict[str, Any]] | None = None,
        protocol: str = "ICMP",
        port: int | None = None,
        limit: int = 3,
    ) -> MeasurementResult:
        """Run traceroute from global probes.

        Args:
            target: Target IP or hostname.
            locations: List of probe locations.
            protocol: Protocol to use (ICMP, UDP, TCP). ICMP is the default
                     and works well for most destinations.
            port: Port for TCP/UDP traceroute.
            limit: Number of probes per location (default: 3).

        Returns:
            MeasurementResult with hop data from each probe.
        """
        options: dict[str, Any] = {"protocol": protocol}
        if port:
            options["port"] = port
        return await self._run_measurement("traceroute", target, locations, options, limit)

    async def mtr(
        self,
        target: str,
        locations: list[dict[str, Any]] | None = None,
        packets: int = 3,
        protocol: str = "ICMP",
        limit: int = 3,
    ) -> MeasurementResult:
        """Run MTR (My Traceroute) from global probes.

        MTR combines ping and traceroute, providing per-hop latency
        and packet loss statistics.

        Args:
            target: Target IP or hostname.
            locations: List of probe locations.
            packets: Number of packets per hop.
            protocol: Protocol to use (ICMP, UDP, TCP). ICMP is the default.
            limit: Number of probes per location (default: 3).

        Returns:
            MeasurementResult with detailed hop statistics.
        """
        options = {"packets": packets, "protocol": protocol}
        return await self._run_measurement("mtr", target, locations, options, limit)

    async def dns(
        self,
        domain: str,
        locations: list[dict[str, Any]] | None = None,
        query_type: str = "A",
        resolver: str | None = None,
        limit: int = 3,
    ) -> MeasurementResult:
        """Run DNS lookup from global probes.

        Args:
            domain: Domain name to resolve.
            locations: List of probe locations.
            query_type: DNS record type (A, AAAA, MX, etc.).
            resolver: Custom DNS resolver to use.
            limit: Number of probes per location (default: 3).

        Returns:
            MeasurementResult with DNS answers from each probe.
        """
        options: dict[str, Any] = {"query": {"type": query_type}}
        if resolver:
            options["resolver"] = resolver
        return await self._run_measurement("dns", domain, locations, options, limit)
