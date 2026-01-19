"""BGPRoute data model representing a BGP routing announcement."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BGPRoute:
    """Unified representation of a BGP route from any data source.

    Attributes:
        prefix: IP prefix in CIDR notation (e.g., "192.0.2.0/24")
        origin_asn: The originating AS number
        as_path: Full AS path as list of ASNs
        collector: BGP collector name (e.g., "rrc00", "route-views2")
        timestamp: When the route was observed
        source: Data source identifier ("ris_live", "ripe_stat", "bgpstream")
        next_hop: Next hop IP address
        origin: BGP origin attribute ("igp", "egp", "incomplete")
        communities: List of BGP communities
        peer_ip: IP of the peer that advertised this route
        peer_asn: ASN of the peer
        rpki_status: RPKI validation status ("valid", "invalid", "not-found")
    """

    prefix: str
    origin_asn: int
    as_path: list[int]
    collector: str
    timestamp: datetime
    source: str
    next_hop: str | None = None
    origin: str | None = None
    communities: list[str] = field(default_factory=list)
    peer_ip: str | None = None
    peer_asn: int | None = None
    rpki_status: str | None = None

    @property
    def as_path_length(self) -> int:
        """Return the length of the AS path."""
        return len(self.as_path)

    @property
    def is_ipv6(self) -> bool:
        """Return True if this is an IPv6 prefix."""
        return ":" in self.prefix

    def to_dict(self) -> dict:
        """Convert route to dictionary for JSON serialization."""
        return {
            "prefix": self.prefix,
            "origin_asn": self.origin_asn,
            "as_path": self.as_path,
            "collector": self.collector,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "next_hop": self.next_hop,
            "origin": self.origin,
            "communities": self.communities,
            "peer_ip": self.peer_ip,
            "peer_asn": self.peer_asn,
            "rpki_status": self.rpki_status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BGPRoute":
        """Create a BGPRoute from a dictionary."""
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        return cls(
            prefix=data["prefix"],
            origin_asn=data["origin_asn"],
            as_path=data["as_path"],
            collector=data["collector"],
            timestamp=timestamp,
            source=data["source"],
            next_hop=data.get("next_hop"),
            origin=data.get("origin"),
            communities=data.get("communities", []),
            peer_ip=data.get("peer_ip"),
            peer_asn=data.get("peer_asn"),
            rpki_status=data.get("rpki_status"),
        )
