"""Client for CAIDA AS Relationships data.

Downloads the serial-2 AS relationship dataset from CAIDA, which provides
inferred provider-customer and peering relationships between ASes.
Data is updated monthly and freely available without authentication.

Format: <as1>|<as2>|<relationship>|<source>
  -1 = as1 is provider of as2 (p2c)
   0 = as1 and as2 are peers (p2p)
"""

from __future__ import annotations

import bz2
import logging
import re
import time

import aiohttp

from bgp_explorer.sources.base import DataSource

logger = logging.getLogger(__name__)

CAIDA_BASE_URL = "https://publicdata.caida.org/datasets/as-relationships/serial-2/"
USER_AGENT = "bgp-explorer/0.1.0 (+https://github.com/hervehildenbrand/bgp-explorer)"
CACHE_TTL_SECONDS = 24 * 3600  # 24 hours (data updates monthly)


class CAIDARelationshipsClient(DataSource):
    """Client for CAIDA AS Relationships serial-2 dataset.

    Provides provider-customer and peering relationships inferred from
    observed BGP routing data. More authoritative than live Monocle queries
    for relationship inference.
    """

    def __init__(self, cache_ttl: int = CACHE_TTL_SECONDS) -> None:
        self._cache_ttl = cache_ttl
        self._session: aiohttp.ClientSession | None = None
        self._last_fetch: float = 0.0

        # provider_of[asn] = set of ASNs that asn provides transit to
        self._provider_of: dict[int, set[int]] = {}
        # upstreams[asn] = set of ASNs that are providers of asn
        self._upstreams: dict[int, set[int]] = {}
        # peers[asn] = set of ASNs that peer with asn
        self._peers: dict[int, set[int]] = {}

    async def connect(self) -> None:
        if self._session is None:
            self._session = aiohttp.ClientSession(headers={"User-Agent": USER_AGENT})

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        return len(self._upstreams) > 0

    async def _ensure_data(self) -> None:
        """Ensure data is loaded and fresh."""
        now = time.time()
        if self._upstreams and (now - self._last_fetch) < self._cache_ttl:
            return
        await self._fetch_and_parse()

    async def _find_latest_file_url(self) -> str:
        """Find the URL of the latest CAIDA relationships file."""
        if self._session is None:
            await self.connect()
        assert self._session is not None

        async with self._session.get(CAIDA_BASE_URL) as response:
            response.raise_for_status()
            html = await response.text()

        # Find all .as-rel2.txt.bz2 files
        files = re.findall(r'href="(\d{8}\.as-rel2\.txt\.bz2)"', html)
        if not files:
            raise RuntimeError("No CAIDA relationship files found")

        latest = sorted(files)[-1]
        return CAIDA_BASE_URL + latest

    async def _fetch_and_parse(self) -> None:
        """Download and parse the latest CAIDA relationships file."""
        if self._session is None:
            await self.connect()
        assert self._session is not None

        url = await self._find_latest_file_url()
        logger.info("Fetching CAIDA relationships from %s", url)

        async with self._session.get(url) as response:
            response.raise_for_status()
            compressed = await response.read()

        data = bz2.decompress(compressed).decode("utf-8")
        self._parse_relationships(data)
        self._last_fetch = time.time()
        total_rels = sum(len(v) for v in self._upstreams.values())
        logger.info("Loaded CAIDA relationships: %d provider-customer pairs", total_rels)

    def _parse_relationships(self, data: str) -> None:
        """Parse serial-2 format into indexes."""
        self._provider_of.clear()
        self._upstreams.clear()
        self._peers.clear()

        for line in data.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            try:
                as1 = int(parts[0])
                as2 = int(parts[1])
                rel = int(parts[2])
            except ValueError:
                continue

            if rel == -1:
                # as1 is provider of as2
                self._provider_of.setdefault(as1, set()).add(as2)
                self._upstreams.setdefault(as2, set()).add(as1)
            elif rel == 0:
                # as1 and as2 are peers
                self._peers.setdefault(as1, set()).add(as2)
                self._peers.setdefault(as2, set()).add(as1)

    async def get_upstreams(self, asn: int) -> set[int]:
        """Get the set of upstream providers for an ASN."""
        await self._ensure_data()
        return self._upstreams.get(asn, set())

    async def get_downstreams(self, asn: int) -> set[int]:
        """Get the set of downstream customers for an ASN."""
        await self._ensure_data()
        return self._provider_of.get(asn, set())

    async def get_peers(self, asn: int) -> set[int]:
        """Get the set of peering ASNs for an ASN."""
        await self._ensure_data()
        return self._peers.get(asn, set())

    async def get_relationship(self, as1: int, as2: int) -> str:
        """Get the relationship between two ASes.

        Returns one of: "provider" (as1 provides to as2), "customer"
        (as1 is customer of as2), "peer", or "unknown".
        """
        await self._ensure_data()

        if as2 in self._provider_of.get(as1, set()):
            return "provider"
        if as1 in self._provider_of.get(as2, set()):
            return "customer"
        if as2 in self._peers.get(as1, set()):
            return "peer"
        return "unknown"
