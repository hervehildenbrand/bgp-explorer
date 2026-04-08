"""RouteViews API client."""

import os
from datetime import timedelta
from typing import Any

import aiohttp

from bgp_explorer.cache.ttl_cache import TTLCache
from bgp_explorer.sources.base import DataSource


class RouteViewsClient(DataSource):
    """Client for RouteViews API.

    Provides access to BGP routing data from RouteViews collectors.

    See: https://api.routeviews.org
    """

    BASE_URL = "https://api.routeviews.org"

    def __init__(self, cache_ttl: timedelta = timedelta(minutes=5)):
        """Initialize the client.

        Args:
            cache_ttl: TTL for cached responses.
        """
        self._session: aiohttp.ClientSession | None = None
        self._cache = TTLCache(default_ttl=cache_ttl)
        self._api_key = os.environ.get("ROUTEVIEWS_API_KEY")

    async def connect(self) -> None:
        """Create HTTP session."""
        if self._session is None:
            headers = {}
            if self._api_key:
                headers["X-API-Key"] = self._api_key
            self._session = aiohttp.ClientSession(headers=headers)

    async def disconnect(self) -> None:
        """Close HTTP session."""
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        """Check if RouteViews API is available."""
        try:
            if self._session is None:
                raise RuntimeError("Client not connected. Use 'async with' or call connect().")

            url = f"{self.BASE_URL}/health"
            async with self._session.get(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def _request(self, endpoint: str) -> dict[str, Any]:
        """Make a request to the RouteViews API.

        Args:
            endpoint: API endpoint path (e.g., "/prefix/8.8.8.0/24").

        Returns:
            Response data dictionary.

        Raises:
            RuntimeError: If client is not connected.
            ValueError: On API errors.
        """
        # Check cache first
        cache_key = f"routeviews:{endpoint}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached

        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' or call connect().")

        url = f"{self.BASE_URL}{endpoint}"
        async with self._session.get(url) as response:
            if response.status != 200:
                raise ValueError(f"RouteViews API error: HTTP {response.status} for {endpoint}")

            data = await response.json()

            # Cache the response
            await self._cache.set(cache_key, data)
            return data

    async def get_prefix_routes(self, prefix: str) -> dict[str, Any]:
        """Get routes for a prefix from RouteViews collectors.

        Args:
            prefix: IP prefix in CIDR notation.

        Returns:
            Dictionary with prefix route data.
        """
        return await self._request(f"/prefix/{prefix}")

    async def get_collectors(self) -> list[dict[str, Any]]:
        """Get list of RouteViews collectors.

        Returns:
            List of collector info dictionaries.
        """
        data = await self._request("/collectors")
        return data.get("collectors", [])
