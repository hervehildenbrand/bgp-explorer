"""PeeringDB client using CAIDA public dumps.

Uses daily JSON dumps from CAIDA to avoid API rate limits.
See: https://publicdata.caida.org/datasets/peeringdb/
"""

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TextColumn

from bgp_explorer.models.ixp import IXP, IXPPresence, Network, NetworkContact
from bgp_explorer.sources.base import DataSource

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "bgp-explorer" / "peeringdb"

# CAIDA PeeringDB dump base URL
CAIDA_BASE_URL = "https://publicdata.caida.org/datasets/peeringdb"

# Cache freshness threshold (days)
CACHE_MAX_AGE_DAYS = 7


class PeeringDBClient(DataSource):
    """Client for PeeringDB data using CAIDA dumps.

    Downloads and caches PeeringDB JSON dumps from CAIDA, then builds
    in-memory indexes for fast lookups of IXP and network information.

    Features:
    - Automatic weekly refresh of cached data
    - Force refresh option via connect(force_refresh=True)
    - Fast in-memory lookups by ASN, IXP ID, or IXP name
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        console: Console | None = None,
    ):
        """Initialize the client.

        Args:
            cache_dir: Directory for cached PeeringDB data. Defaults to
                      ~/.cache/bgp-explorer/peeringdb/
            console: Rich console for progress output. Creates one if not provided.
        """
        self._cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self._console = console or Console()
        self._session: aiohttp.ClientSession | None = None
        self._loaded = False

        # In-memory indexes
        self._ixp_by_id: dict[int, IXP] = {}
        self._ixp_by_name: dict[str, IXP] = {}  # lowercase name -> IXP
        self._asn_to_ixps: dict[int, list[IXPPresence]] = {}
        self._ixp_to_asns: dict[int, list[Network]] = {}
        self._asn_to_net: dict[int, Network] = {}
        self._asn_to_contacts: dict[int, list[NetworkContact]] = {}

    @property
    def cache_file(self) -> Path:
        """Path to cached PeeringDB dump."""
        return self._cache_dir / "peeringdb_latest.json"

    @property
    def metadata_file(self) -> Path:
        """Path to cache metadata file."""
        return self._cache_dir / "metadata.json"

    async def connect(self, force_refresh: bool = False) -> None:
        """Load PeeringDB data, downloading if necessary.

        Args:
            force_refresh: If True, download fresh data even if cache is valid.
        """
        # Create cache directory
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Create HTTP session
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)  # 5 min timeout for large downloads
        )

        # Check if we need to refresh
        need_refresh = force_refresh or self._is_cache_stale() or not self.cache_file.exists()

        if need_refresh and self.cache_file.exists():
            if force_refresh:
                self._console.print("[cyan]Refreshing PeeringDB data from CAIDA...[/cyan]")
            else:
                self._console.print(
                    "[yellow]PeeringDB cache is >7 days old, refreshing...[/yellow]"
                )

        if need_refresh:
            try:
                await self._download_latest_dump()
            except Exception as e:
                # If download fails but we have cached data, use it
                if self.cache_file.exists():
                    self._console.print(
                        f"[yellow]Download failed ({e}), using cached data[/yellow]"
                    )
                else:
                    raise RuntimeError(f"Failed to download PeeringDB data: {e}") from e

        # Load data from cache
        await self._load_data()
        self._loaded = True

    async def disconnect(self) -> None:
        """Close HTTP session and cleanup."""
        if self._session:
            await self._session.close()
            self._session = None

    async def is_available(self) -> bool:
        """Check if PeeringDB data is loaded."""
        return self._loaded

    def _is_cache_stale(self) -> bool:
        """Check if cache is older than CACHE_MAX_AGE_DAYS."""
        if not self.metadata_file.exists():
            return True

        try:
            meta = json.loads(self.metadata_file.read_text())
            download_date = datetime.fromisoformat(meta["download_date"])
            age = datetime.now(UTC) - download_date
            return age > timedelta(days=CACHE_MAX_AGE_DAYS)
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    async def _download_latest_dump(self) -> None:
        """Download the latest PeeringDB dump from CAIDA."""
        if not self._session:
            raise RuntimeError("Client not connected")

        # Find the latest dump URL
        dump_url = await self._get_latest_dump_url()

        # Download with progress
        await self._download_file(dump_url, self.cache_file)

        # Save metadata
        self.metadata_file.write_text(
            json.dumps(
                {
                    "download_date": datetime.now(UTC).isoformat(),
                    "source_url": dump_url,
                }
            )
        )

    async def _get_latest_dump_url(self) -> str:
        """Find the URL of the most recent PeeringDB dump.

        CAIDA publishes daily dumps at:
        /datasets/peeringdb/{year}/{month}/peeringdb_2_dump_YYYY_MM_DD.json

        Returns:
            Full URL to the latest dump file.
        """
        if not self._session:
            raise RuntimeError("Client not connected")

        # Try current month first, then previous month
        now = datetime.now(UTC)
        for month_offset in range(3):  # Try current month and 2 previous
            check_date = now - timedelta(days=month_offset * 30)
            year = check_date.year
            month = check_date.month

            dir_url = f"{CAIDA_BASE_URL}/{year}/{month:02d}/"

            try:
                async with self._session.get(dir_url) as response:
                    if response.status != 200:
                        continue

                    html = await response.text()
                    # Find all dump files
                    pattern = r"peeringdb_2_dump_\d{4}_\d{2}_\d{2}\.json"
                    matches = re.findall(pattern, html)

                    if matches:
                        # Sort to get the latest
                        matches.sort(reverse=True)
                        return f"{dir_url}{matches[0]}"

            except aiohttp.ClientError:
                continue

        raise RuntimeError("Could not find any PeeringDB dumps on CAIDA")

    async def _download_file(self, url: str, dest: Path) -> None:
        """Download a file with progress display.

        Args:
            url: URL to download.
            dest: Destination path.
        """
        if not self._session:
            raise RuntimeError("Client not connected")

        # Download to temp file first, then rename (atomic)
        temp_dest = dest.with_suffix(".tmp")

        async with self._session.get(url) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                console=self._console,
            ) as progress:
                task = progress.add_task("Downloading PeeringDB dump...", total=total)

                with open(temp_dest, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))

        # Atomic rename
        temp_dest.rename(dest)
        self._console.print("[green]Downloaded PeeringDB data[/green]")

    async def _load_data(self) -> None:
        """Load and parse PeeringDB data from cache file."""
        if not self.cache_file.exists():
            raise RuntimeError("Cache file does not exist")

        # Parse JSON
        data = json.loads(self.cache_file.read_text())

        # Build IXP index
        self._ixp_by_id.clear()
        self._ixp_by_name.clear()

        for ix_data in data.get("ix", {}).get("data", []):
            ixp = IXP(
                id=ix_data["id"],
                name=ix_data["name"],
                city=ix_data.get("city", ""),
                country=ix_data.get("country", ""),
                website=ix_data.get("website"),
                participant_count=None,  # Will be calculated after loading netixlan
            )
            self._ixp_by_id[ixp.id] = ixp
            self._ixp_by_name[ixp.name.lower()] = ixp

        # Build network index
        self._asn_to_net.clear()
        net_id_to_asn: dict[int, int] = {}

        for net_data in data.get("net", {}).get("data", []):
            network = Network(
                asn=net_data["asn"],
                name=net_data["name"],
                info_type=net_data.get("info_type"),
                website=net_data.get("website"),
            )
            self._asn_to_net[network.asn] = network
            net_id_to_asn[net_data["id"]] = network.asn

        # Build netixlan indexes (ASN -> IXPs and IXP -> ASNs)
        self._asn_to_ixps.clear()
        self._ixp_to_asns.clear()
        ixp_participant_count: dict[int, set[int]] = {}  # ixp_id -> set of ASNs

        for netixlan in data.get("netixlan", {}).get("data", []):
            ix_id = netixlan["ix_id"]
            asn = netixlan.get("asn")

            # Skip if we don't have the IXP
            if ix_id not in self._ixp_by_id:
                continue

            ixp = self._ixp_by_id[ix_id]

            # Create IXP presence record
            presence = IXPPresence(
                asn=asn,
                ixp_id=ix_id,
                ixp_name=ixp.name,
                ipaddr4=netixlan.get("ipaddr4"),
                ipaddr6=netixlan.get("ipaddr6"),
                speed=netixlan.get("speed"),
            )

            # Add to ASN -> IXPs index
            if asn not in self._asn_to_ixps:
                self._asn_to_ixps[asn] = []
            self._asn_to_ixps[asn].append(presence)

            # Add to IXP -> ASNs index
            if ix_id not in self._ixp_to_asns:
                self._ixp_to_asns[ix_id] = []
            if asn in self._asn_to_net:
                network = self._asn_to_net[asn]
                # Only add if not already present
                if not any(n.asn == asn for n in self._ixp_to_asns[ix_id]):
                    self._ixp_to_asns[ix_id].append(network)

            # Track participant count
            if ix_id not in ixp_participant_count:
                ixp_participant_count[ix_id] = set()
            ixp_participant_count[ix_id].add(asn)

        # Update participant counts
        for ix_id, asns in ixp_participant_count.items():
            if ix_id in self._ixp_by_id:
                # Create new IXP with updated count
                old_ixp = self._ixp_by_id[ix_id]
                updated_ixp = IXP(
                    id=old_ixp.id,
                    name=old_ixp.name,
                    city=old_ixp.city,
                    country=old_ixp.country,
                    website=old_ixp.website,
                    participant_count=len(asns),
                )
                self._ixp_by_id[ix_id] = updated_ixp
                self._ixp_by_name[old_ixp.name.lower()] = updated_ixp

        # Build POC (point of contact) index for networks
        self._asn_to_contacts.clear()

        for poc_data in data.get("poc", {}).get("data", []):
            net_id = poc_data.get("net_id")
            if net_id is None or net_id not in net_id_to_asn:
                continue

            # Only include visible contacts
            if not poc_data.get("visible", "Public") == "Public":
                continue

            asn = net_id_to_asn[net_id]
            contact = NetworkContact(
                role=poc_data.get("role", ""),
                name=poc_data.get("name", ""),
                email=poc_data.get("email", ""),
                phone=poc_data.get("phone", ""),
                url=poc_data.get("url", ""),
                visible=True,
            )

            if asn not in self._asn_to_contacts:
                self._asn_to_contacts[asn] = []
            self._asn_to_contacts[asn].append(contact)

        count_ixps = len(self._ixp_by_id)
        count_networks = len(self._asn_to_net)
        count_contacts = sum(len(c) for c in self._asn_to_contacts.values())
        self._console.print(
            f"[green]PeeringDB data loaded ({count_ixps} IXPs, {count_networks} networks, {count_contacts} contacts)[/green]"
        )

    def _ensure_loaded(self) -> None:
        """Ensure data is loaded before queries."""
        if not self._loaded:
            raise RuntimeError("PeeringDB data not loaded. Call connect() first.")

    def get_ixps_for_asn(self, asn: int) -> list[IXPPresence]:
        """Get all IXPs where an ASN is present.

        Args:
            asn: Autonomous System Number.

        Returns:
            List of IXPPresence records for this ASN.
        """
        self._ensure_loaded()
        return self._asn_to_ixps.get(asn, [])

    def get_networks_at_ixp(self, ixp_id_or_name: int | str) -> list[Network]:
        """Get all networks present at an IXP.

        Args:
            ixp_id_or_name: IXP ID (int) or name (str, case-insensitive).

        Returns:
            List of Network records at this IXP.
        """
        self._ensure_loaded()

        # Resolve to IXP ID
        ixp_id = self._resolve_ixp_id(ixp_id_or_name)
        if ixp_id is None:
            return []

        return self._ixp_to_asns.get(ixp_id, [])

    def get_ixp_details(self, ixp_id_or_name: int | str) -> IXP | None:
        """Get detailed information about an IXP.

        Args:
            ixp_id_or_name: IXP ID (int) or name (str, case-insensitive).

        Returns:
            IXP record or None if not found.
        """
        self._ensure_loaded()

        if isinstance(ixp_id_or_name, int):
            return self._ixp_by_id.get(ixp_id_or_name)

        # Search by name (case-insensitive)
        name_lower = str(ixp_id_or_name).lower()
        return self._ixp_by_name.get(name_lower)

    def search_ixps(self, query: str) -> list[IXP]:
        """Search for IXPs by name or city.

        Args:
            query: Search query (case-insensitive).

        Returns:
            List of matching IXP records.
        """
        self._ensure_loaded()

        query_lower = query.lower()
        results = []

        for ixp in self._ixp_by_id.values():
            if query_lower in ixp.name.lower() or query_lower in ixp.city.lower():
                results.append(ixp)

        return results

    def search_networks(self, query: str) -> list[Network]:
        """Search for networks by organization name.

        Args:
            query: Search query (case-insensitive, partial match).

        Returns:
            List of matching Network records.
        """
        self._ensure_loaded()

        query_lower = query.lower()
        results = []

        for network in self._asn_to_net.values():
            if query_lower in network.name.lower():
                results.append(network)

        return results

    def get_network_info(self, asn: int) -> Network | None:
        """Get network information by ASN.

        Args:
            asn: Autonomous System Number.

        Returns:
            Network record or None if not found.
        """
        self._ensure_loaded()
        return self._asn_to_net.get(asn)

    def get_network_contacts(self, asn: int) -> list[NetworkContact]:
        """Get contact information for a network.

        Returns publicly visible points of contact (NOC, Abuse, Technical, etc.)
        for the specified ASN from PeeringDB.

        Args:
            asn: Autonomous System Number.

        Returns:
            List of NetworkContact records for this ASN (may be empty).
        """
        self._ensure_loaded()
        return self._asn_to_contacts.get(asn, [])

    def _resolve_ixp_id(self, ixp_id_or_name: int | str) -> int | None:
        """Resolve an IXP identifier to an IXP ID.

        Args:
            ixp_id_or_name: IXP ID (int) or name (str).

        Returns:
            IXP ID or None if not found.
        """
        if isinstance(ixp_id_or_name, int):
            return ixp_id_or_name if ixp_id_or_name in self._ixp_by_id else None

        # Try exact name match first (case-insensitive)
        name_lower = str(ixp_id_or_name).lower()
        ixp = self._ixp_by_name.get(name_lower)
        if ixp:
            return ixp.id

        # Try partial match
        for ixp in self._ixp_by_id.values():
            if name_lower in ixp.name.lower():
                return ixp.id

        return None
