"""Client for MANRS Observatory API.

Fetches official MANRS conformance data for network operators.
Requires an API key from https://manrs.org/resources/api/.

The conformance data is cached in memory with a configurable TTL.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import aiohttp

from bgp_explorer.models.manrs import MANRSConformance, MANRSReadiness
from bgp_explorer.sources.base import DataSource

logger = logging.getLogger(__name__)

MANRS_API_URL = "https://api.manrs.org"
USER_AGENT = "bgp-explorer/0.1.0 (+https://github.com/hervehildenbrand/bgp-explorer)"
CACHE_TTL_SECONDS = 3600  # 1 hour


def _parse_readiness(value: str) -> MANRSReadiness:
    """Parse a MANRS readiness string to enum, defaulting to UNKNOWN."""
    try:
        return MANRSReadiness(value.lower())
    except (ValueError, AttributeError):
        return MANRSReadiness.UNKNOWN


class MANRSClient(DataSource):
    """Client for the MANRS Observatory API.

    Fetches official conformance data, ROA statistics, and participant
    information. Requires an API key set via constructor or MANRS_API_KEY
    environment variable.
    """

    def __init__(
        self,
        api_key: str | None = None,
        cache_ttl: int = CACHE_TTL_SECONDS,
    ) -> None:
        # Only check env var if api_key was not explicitly passed
        if api_key is None:
            self._api_key = os.environ.get("MANRS_API_KEY")
        else:
            self._api_key = api_key
        self._cache_ttl = cache_ttl
        self._session: aiohttp.ClientSession | None = None

        # Cache for conformance data
        self._conformance_cache: list[MANRSConformance] | None = None
        self._conformance_fetched: float = 0.0

    def has_api_key(self) -> bool:
        """Check if an API key is configured."""
        return self._api_key is not None and len(self._api_key) > 0

    async def connect(self) -> None:
        if self._session is None:
            headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            self._session = aiohttp.ClientSession(headers=headers)

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        return self.has_api_key()

    async def _fetch_json(self, endpoint: str) -> Any | None:
        """Fetch JSON from MANRS API. Returns None on error."""
        if not self.has_api_key():
            return None

        if self._session is None:
            await self.connect()
        assert self._session is not None

        url = f"{MANRS_API_URL}{endpoint}"
        try:
            async with self._session.get(url) as response:
                if response.status != 200:
                    logger.warning("MANRS API returned %d for %s", response.status, endpoint)
                    return None
                return await response.json(content_type=None)
        except Exception as e:
            logger.warning("MANRS API error for %s: %s", endpoint, e)
            return None

    async def _ensure_conformance(self) -> list[MANRSConformance]:
        """Ensure conformance data is loaded and fresh."""
        now = time.time()
        if (
            self._conformance_cache is not None
            and (now - self._conformance_fetched) < self._cache_ttl
        ):
            return self._conformance_cache

        data = await self._fetch_json("/conformance/net-ops")
        if data is None:
            return []

        self._conformance_cache = [self._parse_conformance(entry) for entry in data]
        self._conformance_fetched = time.time()
        logger.info("Loaded %d MANRS conformance entries", len(self._conformance_cache))
        return self._conformance_cache

    @staticmethod
    def _parse_conformance(entry: dict[str, Any]) -> MANRSConformance:
        """Parse a single conformance entry from the API."""
        return MANRSConformance(
            asn=int(entry.get("asn", 0)),
            name=entry.get("name", ""),
            country=entry.get("country", ""),
            status=entry.get("status", "unknown"),
            action1_filtering=_parse_readiness(entry.get("action_1", "")),
            action2_anti_spoofing=_parse_readiness(entry.get("action_2", "")),
            action3_coordination=_parse_readiness(entry.get("action_3", "")),
            action4_validation=_parse_readiness(entry.get("action_4", "")),
            last_updated=entry.get("last_updated", ""),
            manrs_participant=True,
        )

    async def get_asn_conformance(self, asn: int) -> MANRSConformance | None:
        """Get MANRS conformance data for a specific ASN.

        Returns None if the ASN is not a MANRS participant or API unavailable.
        """
        entries = await self._ensure_conformance()
        for entry in entries:
            if entry.asn == asn:
                return entry
        return None

    async def is_manrs_participant(self, asn: int) -> bool:
        """Check if an ASN is a MANRS participant."""
        result = await self.get_asn_conformance(asn)
        return result is not None

    async def get_asn_roas(self, asn: int) -> dict | None:
        """Get ROA data for an ASN from MANRS perspective."""
        return await self._fetch_json(f"/roas/asn/{asn}")
