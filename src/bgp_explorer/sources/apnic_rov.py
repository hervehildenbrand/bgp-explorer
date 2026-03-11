"""APNIC ROV (Route Origin Validation) client."""

from datetime import timedelta
from typing import Any

import aiohttp

from bgp_explorer.cache.ttl_cache import TTLCache
from bgp_explorer.sources.base import DataSource


class APNICROVClient(DataSource):
    """Client for APNIC ROV statistics.

    Provides access to RPKI Route Origin Validation adoption data
    measured by APNIC Labs.

    See: https://stats.labs.apnic.net/rpki
    """

    BASE_URL = "https://stats.labs.apnic.net/rpki"

    def __init__(self, cache_ttl: timedelta = timedelta(days=7)):
        """Initialize the client.

        Args:
            cache_ttl: TTL for cached responses (default: 7 days for APNIC measurement window).
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
        """Check if APNIC ROV API is available."""
        try:
            if self._session is None:
                raise RuntimeError("Client not connected. Use 'async with' or call connect().")

            # Use a well-known ASN to test availability
            url = f"{self.BASE_URL}/AS15169?c=AU&m=json"
            async with self._session.get(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def get_asn_rov_status(self, asn: int) -> dict[str, Any]:
        """Get ROV filtering status for an ASN.

        Args:
            asn: Autonomous System Number.

        Returns:
            Dictionary with ROV filtering percentage data.
            On error, returns {"error": "APNIC ROV data unavailable", "asn": asn}.
        """
        # Check cache first
        cache_key = f"apnic_rov:AS{asn}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached

        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' or call connect().")

        url = f"{self.BASE_URL}/AS{asn}?c=AU&m=json"
        try:
            async with self._session.get(url) as response:
                if response.status != 200:
                    return {"error": "APNIC ROV data unavailable", "asn": asn}

                data = await response.json()

                # Cache the response
                await self._cache.set(cache_key, data)
                return data
        except Exception:
            return {"error": "APNIC ROV data unavailable", "asn": asn}
