"""Client for rpki-client console RPKI data.

Downloads and indexes the rpki.json dump from console.rpki-client.org,
providing access to validated ROA and ASPA objects without authentication.

The dump is cached in memory with a configurable TTL (default 2 hours).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from bgp_explorer.models.rpki import ASPAObject, ROAObject, RPKIDump
from bgp_explorer.sources.base import DataSource

logger = logging.getLogger(__name__)

# rpki-client console public endpoints (no auth required)
RPKI_JSON_URL = "https://console.rpki-client.org/rpki.json"
USER_AGENT = "bgp-explorer/0.1.0 (+https://github.com/hervehildenbrand/bgp-explorer)"
CACHE_TTL_SECONDS = 2 * 3600  # 2 hours


class RpkiConsoleClient(DataSource):
    """Client for the rpki-client console public JSON data.

    Downloads rpki.json from console.rpki-client.org which contains all
    validated ROA and ASPA objects from the global RPKI repositories.
    Builds in-memory indexes for fast lookups by ASN and prefix.
    """

    def __init__(self, cache_ttl: int = CACHE_TTL_SECONDS) -> None:
        self._cache_ttl = cache_ttl
        self._session: aiohttp.ClientSession | None = None
        self._dump: RPKIDump | None = None
        self._last_fetch: float = 0.0

        # Indexes built from the dump
        self._aspa_by_customer: dict[int, ASPAObject] = {}
        self._roas_by_origin: dict[int, list[ROAObject]] = {}
        self._roas_by_prefix: dict[str, list[ROAObject]] = {}

    async def connect(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": USER_AGENT}
            )

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        return self._dump is not None and len(self._dump.aspas) > 0

    async def _ensure_data(self) -> RPKIDump:
        """Ensure data is loaded and fresh, fetching if needed."""
        now = time.time()
        if self._dump is not None and (now - self._last_fetch) < self._cache_ttl:
            return self._dump

        await self._fetch_and_index()
        assert self._dump is not None
        return self._dump

    async def _fetch_and_index(self) -> None:
        """Download rpki.json and build indexes."""
        if self._session is None:
            await self.connect()
        assert self._session is not None

        logger.info("Fetching RPKI data from %s", RPKI_JSON_URL)
        async with self._session.get(RPKI_JSON_URL) as response:
            response.raise_for_status()
            data: dict[str, Any] = await response.json(content_type=None)

        self._dump = self._parse_dump(data)
        self._last_fetch = time.time()
        self._build_indexes()
        logger.info(
            "Loaded %d ROAs and %d ASPAs from rpki-client console",
            len(self._dump.roas),
            len(self._dump.aspas),
        )

    @staticmethod
    def _parse_dump(data: dict[str, Any]) -> RPKIDump:
        """Parse raw JSON into RPKIDump."""
        metadata = data.get("metadata", {})

        aspas = []
        for entry in data.get("aspas", []):
            customer = entry.get("customer_asid")
            providers = entry.get("providers", [])
            if customer is not None:
                aspas.append(ASPAObject(
                    customer_asn=int(customer),
                    provider_asns=frozenset(int(p) for p in providers),
                    expires=entry.get("expires", 0),
                ))

        roas = []
        for entry in data.get("roas", []):
            prefix = entry.get("prefix")
            asn = entry.get("asn")
            if prefix is not None and asn is not None:
                roas.append(ROAObject(
                    prefix=prefix,
                    max_length=entry.get("maxLength", 0),
                    origin_asn=int(asn),
                    trust_anchor=entry.get("ta", ""),
                    expires=entry.get("expires", 0),
                ))

        return RPKIDump(
            roas=roas,
            aspas=aspas,
            generated=metadata.get("buildtime", ""),
            source="rpki-client-console",
        )

    def _build_indexes(self) -> None:
        """Build in-memory indexes for fast lookups."""
        assert self._dump is not None

        self._aspa_by_customer.clear()
        self._roas_by_origin.clear()
        self._roas_by_prefix.clear()

        for aspa in self._dump.aspas:
            self._aspa_by_customer[aspa.customer_asn] = aspa

        for roa in self._dump.roas:
            self._roas_by_origin.setdefault(roa.origin_asn, []).append(roa)
            self._roas_by_prefix.setdefault(roa.prefix, []).append(roa)

    # --- ASPA queries ---

    async def has_aspa(self, asn: int) -> bool:
        """Check if an ASN has published ASPA objects."""
        await self._ensure_data()
        return asn in self._aspa_by_customer

    async def get_aspa_providers(self, customer_asn: int) -> frozenset[int]:
        """Get the set of authorized provider ASNs for a customer ASN.

        Returns an empty frozenset if the ASN has no ASPA published.
        """
        await self._ensure_data()
        aspa = self._aspa_by_customer.get(customer_asn)
        if aspa is None:
            return frozenset()
        return aspa.provider_asns

    async def get_aspa_object(self, customer_asn: int) -> ASPAObject | None:
        """Get the full ASPA object for a customer ASN."""
        await self._ensure_data()
        return self._aspa_by_customer.get(customer_asn)

    async def get_all_aspa_objects(self) -> list[ASPAObject]:
        """Get all ASPA objects."""
        dump = await self._ensure_data()
        return dump.aspas

    async def get_aspa_count(self) -> int:
        """Get the total number of ASPA objects."""
        dump = await self._ensure_data()
        return len(dump.aspas)

    # --- ROA queries ---

    async def get_roas_for_origin(self, origin_asn: int) -> list[ROAObject]:
        """Get all ROAs authorizing a given origin ASN."""
        await self._ensure_data()
        return self._roas_by_origin.get(origin_asn, [])

    async def get_roas_for_prefix(self, prefix: str) -> list[ROAObject]:
        """Get all ROAs covering a given prefix."""
        await self._ensure_data()
        return self._roas_by_prefix.get(prefix, [])

    async def get_roa_count(self) -> int:
        """Get the total number of ROA objects."""
        dump = await self._ensure_data()
        return len(dump.roas)

    async def get_dump_metadata(self) -> dict[str, str]:
        """Get metadata about the current dump."""
        dump = await self._ensure_data()
        return {
            "generated": dump.generated,
            "source": dump.source,
            "roa_count": str(len(dump.roas)),
            "aspa_count": str(len(dump.aspas)),
        }
