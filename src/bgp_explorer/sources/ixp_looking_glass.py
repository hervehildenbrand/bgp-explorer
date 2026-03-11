"""IXP Looking Glass (Alice-LG) client."""

from datetime import timedelta
from typing import Any

import aiohttp

from bgp_explorer.cache.ttl_cache import TTLCache
from bgp_explorer.sources.base import DataSource

ALICE_LG_INSTANCES: dict[str, str] = {
    "de-cix": "https://lg.de-cix.net/api/v1",
    "ams-ix": "https://lg.ams-ix.net/api/v1",
    "bcix": "https://lg.bcix.de/api/v1",
}


class IXPLookingGlassClient(DataSource):
    """Client for IXP Looking Glass APIs (Alice-LG).

    Provides access to route server data at major Internet Exchange Points.

    Supported IXPs:
    - de-cix: DE-CIX Frankfurt
    - ams-ix: AMS-IX Amsterdam
    - bcix: BCIX Berlin

    See: https://github.com/alice-lg/alice-lg
    """

    def __init__(self, cache_ttl: timedelta = timedelta(minutes=5)):
        """Initialize the client.

        Args:
            cache_ttl: TTL for cached responses.
        """
        self._session: aiohttp.ClientSession | None = None
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
        """Check if Looking Glass API is available (uses DE-CIX as default)."""
        try:
            if self._session is None:
                raise RuntimeError("Client not connected. Use 'async with' or call connect().")

            url = f"{ALICE_LG_INSTANCES['de-cix']}/routeservers"
            async with self._session.get(url) as response:
                return response.status == 200
        except Exception:
            return False

    def _get_base_url(self, ixp: str) -> str:
        """Get base URL for an IXP.

        Args:
            ixp: IXP name (e.g., "de-cix", "ams-ix").

        Returns:
            Base URL for the IXP's Looking Glass API.

        Raises:
            ValueError: If IXP is not supported.
        """
        if ixp not in ALICE_LG_INSTANCES:
            supported = ", ".join(ALICE_LG_INSTANCES.keys())
            raise ValueError(f"Unknown IXP: {ixp}. Supported IXPs: {supported}")
        return ALICE_LG_INSTANCES[ixp]

    async def _request(self, ixp: str, endpoint: str) -> dict[str, Any]:
        """Make a request to an IXP Looking Glass API.

        Args:
            ixp: IXP name.
            endpoint: API endpoint path.

        Returns:
            Response data dictionary.

        Raises:
            RuntimeError: If client is not connected.
            ValueError: On API errors or unknown IXP.
        """
        base_url = self._get_base_url(ixp)

        # Check cache first
        cache_key = f"ixp:{ixp}:{endpoint}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached

        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' or call connect().")

        url = f"{base_url}{endpoint}"
        async with self._session.get(url) as response:
            if response.status != 200:
                raise ValueError(
                    f"IXP Looking Glass API error: HTTP {response.status} for {ixp}{endpoint}"
                )

            data = await response.json()

            # Cache the response
            await self._cache.set(cache_key, data)
            return data

    async def lookup_prefix(self, prefix: str, ixp: str = "de-cix") -> dict[str, Any]:
        """Look up routes for a prefix at an IXP.

        Args:
            prefix: IP prefix in CIDR notation.
            ixp: IXP name (default: "de-cix").

        Returns:
            Dictionary with route data from the IXP's route servers.
        """
        return await self._request(ixp, f"/lookup/prefix?q={prefix}")

    async def list_route_servers(self, ixp: str = "de-cix") -> list[dict[str, Any]]:
        """List route servers at an IXP.

        Args:
            ixp: IXP name (default: "de-cix").

        Returns:
            List of route server info dictionaries.
        """
        data = await self._request(ixp, "/routeservers")
        return data.get("routeservers", [])

    @staticmethod
    def list_supported_ixps() -> list[str]:
        """List supported IXP names.

        Returns:
            List of supported IXP names.
        """
        return list(ALICE_LG_INSTANCES.keys())
