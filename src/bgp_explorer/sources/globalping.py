"""Globalping API client for global network probing.

Globalping provides distributed network measurements from hundreds of
probes worldwide, enabling ping, traceroute, MTR, DNS, and HTTP tests
from multiple vantage points.

See: https://github.com/jsdelivr/globalping
API Docs: https://globalping.io/docs/api
"""

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

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
    min_latency: Optional[float] = None
    avg_latency: Optional[float] = None
    max_latency: Optional[float] = None
    packet_loss: Optional[float] = None
    # Traceroute/MTR hops
    hops: Optional[list[dict[str, Any]]] = None
    # DNS answers
    dns_answers: Optional[list[dict[str, Any]]] = None

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
        api_token: Optional[str] = None,
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
        self._session: Optional[aiohttp.ClientSession] = None

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
        locations: Optional[list[dict[str, Any]]] = None,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Parse and validate location specifications.

        Args:
            locations: List of location dicts with keys like 'country', 'continent', 'asn'.
            limit: Number of probes per location when using defaults.

        Returns:
            Validated location list.
        """
        if not locations:
            return self._default_locations(limit)
        # Add limit to each location if not specified
        result = []
        for loc in locations:
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
        locations: Optional[list[dict[str, Any]]] = None,
        options: Optional[dict[str, Any]] = None,
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
        locations: Optional[list[dict[str, Any]]] = None,
        options: Optional[dict[str, Any]] = None,
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
        locations: Optional[list[dict[str, Any]]] = None,
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
        locations: Optional[list[dict[str, Any]]] = None,
        protocol: str = "UDP",
        port: Optional[int] = None,
        limit: int = 3,
    ) -> MeasurementResult:
        """Run traceroute from global probes.

        Args:
            target: Target IP or hostname.
            locations: List of probe locations.
            protocol: Protocol to use (UDP, ICMP, TCP). UDP is default as it
                     works through more firewalls than ICMP.
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
        locations: Optional[list[dict[str, Any]]] = None,
        packets: int = 3,
        protocol: str = "UDP",
        limit: int = 3,
    ) -> MeasurementResult:
        """Run MTR (My Traceroute) from global probes.

        MTR combines ping and traceroute, providing per-hop latency
        and packet loss statistics.

        Args:
            target: Target IP or hostname.
            locations: List of probe locations.
            packets: Number of packets per hop.
            protocol: Protocol to use (UDP, ICMP, TCP). UDP is default.
            limit: Number of probes per location (default: 3).

        Returns:
            MeasurementResult with detailed hop statistics.
        """
        options = {"packets": packets, "protocol": protocol}
        return await self._run_measurement("mtr", target, locations, options, limit)

    async def dns(
        self,
        domain: str,
        locations: Optional[list[dict[str, Any]]] = None,
        query_type: str = "A",
        resolver: Optional[str] = None,
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
