"""RIPE Stat REST API client."""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiohttp

from bgp_explorer.cache.ttl_cache import TTLCache
from bgp_explorer.models.route import BGPRoute
from bgp_explorer.sources.base import DataSource


class RipeStatClient(DataSource):
    """Client for RIPE Stat REST API.

    Provides access to BGP routing data including:
    - Current BGP state
    - Routing status for ASNs
    - RPKI validation
    - Routing history
    - Announced prefixes

    See: https://stat.ripe.net/docs/02.data-api/
    """

    BASE_URL = "https://stat.ripe.net/data"

    def __init__(self, cache_ttl: timedelta = timedelta(minutes=5)):
        """Initialize the client.

        Args:
            cache_ttl: TTL for cached responses.
        """
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache = TTLCache(default_ttl=cache_ttl)

    async def connect(self) -> None:
        """Create HTTP session."""
        if self._session is None:
            self._session = aiohttp.ClientSession()

    async def disconnect(self) -> None:
        """Close HTTP session."""
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        """Check if RIPE Stat API is available."""
        try:
            # Use a simple query to test availability
            await self._request("bgp-state", {"resource": "1.1.1.0/24"})
            return True
        except Exception:
            return False

    async def _request(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Make a request to the RIPE Stat API.

        Args:
            endpoint: API endpoint name (e.g., "bgp-state").
            params: Query parameters.

        Returns:
            Response data dictionary.

        Raises:
            aiohttp.ClientError: On network errors.
            ValueError: On API errors.
        """
        # Check cache first
        cache_key = f"{endpoint}:{sorted(params.items())}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached

        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' or call connect().")

        url = f"{self.BASE_URL}/{endpoint}/data.json"
        async with self._session.get(url, params=params) as response:
            response.raise_for_status()
            data = await response.json()

            if data.get("status") != "ok":
                raise ValueError(f"RIPE Stat API error: {data.get('status')}")

            # Cache the response
            await self._cache.set(cache_key, data["data"])
            return data["data"]

    async def get_bgp_state(self, prefix: str) -> list[BGPRoute]:
        """Get current BGP state for a prefix.

        Args:
            prefix: IP prefix in CIDR notation.

        Returns:
            List of BGPRoute objects representing current routing state.
        """
        data = await self._request("bgp-state", {"resource": prefix})

        routes = []
        query_time = data.get("query_time", datetime.now(timezone.utc).isoformat())
        if isinstance(query_time, str):
            try:
                timestamp = datetime.fromisoformat(query_time.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        for entry in data.get("bgp_state", []):
            as_path = entry.get("path", [])
            origin_asn = as_path[-1] if as_path else 0

            route = BGPRoute(
                prefix=entry.get("target_prefix", prefix),
                origin_asn=origin_asn,
                as_path=as_path,
                collector=entry.get("source_id", "unknown"),
                timestamp=timestamp,
                source="ripe_stat",
                communities=entry.get("community", []),
            )
            routes.append(route)

        return routes

    async def get_routing_status(self, asn: int) -> dict[str, Any]:
        """Get routing status for an ASN.

        Args:
            asn: Autonomous System Number.

        Returns:
            Dictionary with routing status information.
        """
        data = await self._request("routing-status", {"resource": f"AS{asn}"})
        return data

    async def get_rpki_validation(self, prefix: str, origin_asn: int) -> str:
        """Get RPKI validation status for a prefix/origin pair.

        Args:
            prefix: IP prefix in CIDR notation.
            origin_asn: Origin AS number.

        Returns:
            RPKI status: "valid", "invalid", or "not-found".
        """
        data = await self._request(
            "rpki-validation",
            {"resource": origin_asn, "prefix": prefix},
        )
        return data.get("status", "not-found")

    async def get_routing_history(
        self,
        resource: str,
        start: datetime,
        end: datetime,
    ) -> dict[str, Any]:
        """Get routing history for a resource.

        Args:
            resource: IP prefix or ASN.
            start: Start time for history query.
            end: End time for history query.

        Returns:
            Dictionary with routing history data.
        """
        params = {
            "resource": resource,
            "starttime": start.strftime("%Y-%m-%dT%H:%M:%S"),
            "endtime": end.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        data = await self._request("routing-history", params)
        return data

    async def get_announced_prefixes(self, asn: int) -> list[str]:
        """Get prefixes announced by an ASN.

        Args:
            asn: Autonomous System Number.

        Returns:
            List of prefix strings.
        """
        data = await self._request("announced-prefixes", {"resource": f"AS{asn}"})
        prefixes = [p["prefix"] for p in data.get("prefixes", [])]
        return prefixes

    async def get_bgp_events(
        self,
        resource: str,
        start: datetime,
        end: datetime,
    ) -> dict[str, Any]:
        """Get BGP events (announcements/withdrawals) for a resource.

        Uses the BGPlay endpoint for detailed event data.

        Args:
            resource: IP prefix.
            start: Start time.
            end: End time.

        Returns:
            Dictionary with BGP event data.
        """
        params = {
            "resource": resource,
            "starttime": start.strftime("%Y-%m-%dT%H:%M:%S"),
            "endtime": end.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        data = await self._request("bgplay", params)
        return data
