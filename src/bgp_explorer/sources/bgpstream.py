"""BGPStream client for historical and real-time BGP data.

BGPStream provides access to historical BGP data from RouteViews and RIPE RIS
collectors, as well as real-time data streams.

Requires: libBGPStream C library and pybgpstream Python bindings.
Install: `brew install bgpstream` (macOS) or build from source.
"""

from datetime import UTC, datetime

from bgp_explorer.models.route import BGPRoute
from bgp_explorer.sources.base import DataSource

# Optional import - pybgpstream requires libBGPStream C library
try:
    import pybgpstream

    BGPSTREAM_AVAILABLE = True
except ImportError:
    BGPSTREAM_AVAILABLE = False
    pybgpstream = None


class BGPStreamError(Exception):
    """Exception raised for BGPStream errors."""

    pass


class BGPStreamClient(DataSource):
    """Client for accessing BGP data via BGPStream.

    BGPStream provides access to:
    - Historical BGP data from RouteViews and RIPE RIS
    - Real-time BGP update streams
    - Filtering by prefix, ASN, collector, and time range

    Note: Requires libBGPStream C library to be installed.
    """

    def __init__(self):
        """Initialize the client."""
        if not BGPSTREAM_AVAILABLE:
            raise BGPStreamError(
                "pybgpstream not available. Install with: "
                "CFLAGS='-I/opt/homebrew/include' LDFLAGS='-L/opt/homebrew/lib' "
                "pip install pybgpstream"
            )
        self._connected = False

    @classmethod
    def is_available(cls) -> bool:
        """Check if BGPStream is available.

        Returns:
            True if pybgpstream is installed and usable.
        """
        return BGPSTREAM_AVAILABLE

    async def connect(self) -> None:
        """Mark client as connected."""
        self._connected = True

    async def disconnect(self) -> None:
        """Mark client as disconnected."""
        self._connected = False

    def get_historical_updates(
        self,
        start_time: datetime,
        end_time: datetime,
        collectors: list[str] | None = None,
        prefix_filter: str | None = None,
        asn_filter: int | None = None,
        record_type: str = "updates",
    ) -> list[BGPRoute]:
        """Get historical BGP updates for a time range.

        Args:
            start_time: Start of time range (UTC).
            end_time: End of time range (UTC).
            collectors: List of collectors (e.g., ["rrc00", "route-views2"]).
            prefix_filter: Filter by prefix (e.g., "8.8.8.0/24").
            asn_filter: Filter by origin ASN.
            record_type: "updates" or "ribs".

        Returns:
            List of BGPRoute objects.
        """
        stream = pybgpstream.BGPStream(
            from_time=int(start_time.timestamp()),
            until_time=int(end_time.timestamp()),
            record_type=record_type,
        )

        # Add collectors
        if collectors:
            for collector in collectors:
                stream.add_filter("collector", collector)

        # Add prefix filter
        if prefix_filter:
            stream.add_filter("prefix", prefix_filter)

        # Add ASN filter (origin)
        if asn_filter:
            stream.add_filter("aspath", f"_{asn_filter}$")

        routes = []
        for rec in stream.records():
            for elem in rec:
                route = self._elem_to_route(elem, rec)
                if route:
                    routes.append(route)

        return routes

    def get_rib_snapshot(
        self,
        timestamp: datetime,
        collectors: list[str] | None = None,
        prefix_filter: str | None = None,
    ) -> list[BGPRoute]:
        """Get a RIB snapshot at a specific time.

        Args:
            timestamp: Time for the snapshot (UTC).
            collectors: List of collectors to query.
            prefix_filter: Filter by prefix.

        Returns:
            List of BGPRoute objects representing the RIB state.
        """
        # RIB dumps are typically every 2 hours, so we search in a window
        start = datetime.fromtimestamp(timestamp.timestamp() - 7200, tz=UTC)
        end = datetime.fromtimestamp(timestamp.timestamp() + 7200, tz=UTC)

        stream = pybgpstream.BGPStream(
            from_time=int(start.timestamp()),
            until_time=int(end.timestamp()),
            record_type="ribs",
        )

        if collectors:
            for collector in collectors:
                stream.add_filter("collector", collector)

        if prefix_filter:
            stream.add_filter("prefix", prefix_filter)

        routes = []
        seen_prefixes = set()

        for rec in stream.records():
            for elem in rec:
                route = self._elem_to_route(elem, rec)
                if route:
                    # Dedupe by prefix+collector (keep first/latest)
                    key = (route.prefix, route.collector)
                    if key not in seen_prefixes:
                        seen_prefixes.add(key)
                        routes.append(route)

        return routes

    def stream_updates(
        self,
        collectors: list[str] | None = None,
        prefix_filter: str | None = None,
        asn_filter: int | None = None,
    ):
        """Stream real-time BGP updates.

        Args:
            collectors: List of collectors to monitor.
            prefix_filter: Filter by prefix.
            asn_filter: Filter by origin ASN.

        Yields:
            BGPRoute objects as updates arrive.

        Note:
            This is a blocking generator. For async usage, run in a thread.
        """
        stream = pybgpstream.BGPStream(
            project="ris-live",
            record_type="updates",
        )

        if collectors:
            for collector in collectors:
                stream.add_filter("collector", collector)

        if prefix_filter:
            stream.add_filter("prefix", prefix_filter)

        if asn_filter:
            stream.add_filter("aspath", f"_{asn_filter}$")

        for rec in stream.records():
            for elem in rec:
                route = self._elem_to_route(elem, rec)
                if route:
                    yield route

    def _elem_to_route(self, elem, rec) -> BGPRoute | None:
        """Convert a BGPStream element to a BGPRoute.

        Args:
            elem: BGPStream element.
            rec: BGPStream record.

        Returns:
            BGPRoute or None if conversion fails.
        """
        try:
            # Get element type (announcement or withdrawal)
            elem_type = elem.type

            # Skip withdrawals for now (we focus on announcements)
            if elem_type == "W":
                return None

            # Extract fields
            prefix = elem.fields.get("prefix", "")
            as_path_str = elem.fields.get("as-path", "")
            next_hop = elem.fields.get("next-hop", "")

            # Parse AS path
            as_path = []
            if as_path_str:
                for asn_str in as_path_str.split():
                    # Handle AS sets {1,2,3}
                    if asn_str.startswith("{"):
                        asn_str = asn_str.strip("{}")
                        # Take first ASN from set
                        asn_str = asn_str.split(",")[0]
                    try:
                        as_path.append(int(asn_str))
                    except ValueError:
                        continue

            # Origin ASN is last in path
            origin_asn = as_path[-1] if as_path else 0

            # Get collector and peer info
            collector = rec.collector
            peer_asn = elem.peer_asn
            peer_ip = elem.peer_address

            # Timestamp
            timestamp = datetime.fromtimestamp(rec.time, tz=UTC)

            # Communities
            communities_str = elem.fields.get("communities", "")
            communities = None
            if communities_str:
                communities = communities_str.split()

            return BGPRoute(
                prefix=prefix,
                origin_asn=origin_asn,
                as_path=as_path,
                collector=collector,
                timestamp=timestamp,
                source="bgpstream",
                next_hop=next_hop if next_hop else None,
                peer_asn=peer_asn,
                peer_ip=peer_ip,
                communities=communities,
            )

        except Exception:
            return None

    def get_prefix_events(
        self,
        prefix: str,
        start_time: datetime,
        end_time: datetime,
        collectors: list[str] | None = None,
    ) -> list[dict]:
        """Get all BGP events for a prefix in a time range.

        Useful for investigating routing incidents.

        Args:
            prefix: IP prefix to query.
            start_time: Start of time range.
            end_time: End of time range.
            collectors: Optional list of collectors.

        Returns:
            List of event dictionaries with type, timestamp, and details.
        """
        stream = pybgpstream.BGPStream(
            from_time=int(start_time.timestamp()),
            until_time=int(end_time.timestamp()),
            record_type="updates",
        )

        stream.add_filter("prefix", prefix)

        if collectors:
            for collector in collectors:
                stream.add_filter("collector", collector)

        events = []
        for rec in stream.records():
            for elem in rec:
                event = {
                    "type": "announcement" if elem.type == "A" else "withdrawal",
                    "timestamp": datetime.fromtimestamp(rec.time, tz=UTC),
                    "collector": rec.collector,
                    "peer_asn": elem.peer_asn,
                    "peer_ip": elem.peer_address,
                    "prefix": elem.fields.get("prefix", prefix),
                }

                if elem.type == "A":
                    event["as_path"] = elem.fields.get("as-path", "")
                    event["next_hop"] = elem.fields.get("next-hop", "")
                    event["communities"] = elem.fields.get("communities", "")

                events.append(event)

        return events
