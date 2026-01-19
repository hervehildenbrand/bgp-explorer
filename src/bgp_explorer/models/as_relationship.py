"""AS relationship data models for Monocle integration.

Monocle analyzes BGP routing tables from global peers to derive
actual AS-to-AS relationships (peer, upstream, downstream).
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ASRelationship:
    """Relationship between two Autonomous Systems.

    Derived from BGP routing table analysis by Monocle.

    Attributes:
        asn1: First AS number (the queried AS).
        asn2: Second AS number (the neighbor).
        asn2_name: Human-readable name for asn2.
        connected_pct: Percentage of BGP peers that see this relationship.
        peer_pct: Percentage where relationship is peer-to-peer.
        as1_upstream_pct: Percentage where asn1 is upstream (provider to asn2).
        as2_upstream_pct: Percentage where asn2 is upstream (provider to asn1).
    """

    asn1: int
    asn2: int
    asn2_name: Optional[str]
    connected_pct: float
    peer_pct: float
    as1_upstream_pct: float
    as2_upstream_pct: float

    @property
    def relationship_type(self) -> str:
        """Determine the primary relationship type.

        Returns:
            "peer" if primarily peering,
            "upstream" if asn2 is upstream of asn1,
            "downstream" if asn2 is downstream of asn1,
            "unknown" if unclear.
        """
        # If peer percentage is high, it's primarily a peering relationship
        if self.peer_pct > 20:
            return "peer"
        # If as2 provides transit to as1 more than vice versa, as2 is upstream
        if self.as2_upstream_pct > self.as1_upstream_pct + 5:
            return "upstream"
        # If as1 provides transit to as2 more than vice versa, as2 is downstream
        elif self.as1_upstream_pct > self.as2_upstream_pct + 5:
            return "downstream"
        # Default to peer for roughly equal upstream percentages
        elif abs(self.as1_upstream_pct - self.as2_upstream_pct) < 5:
            return "peer"
        else:
            return "unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "asn1": self.asn1,
            "asn2": self.asn2,
            "asn2_name": self.asn2_name,
            "connected_pct": self.connected_pct,
            "peer_pct": self.peer_pct,
            "as1_upstream_pct": self.as1_upstream_pct,
            "as2_upstream_pct": self.as2_upstream_pct,
            "relationship_type": self.relationship_type,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ASRelationship":
        """Create an ASRelationship from Monocle JSON output.

        Args:
            data: Dictionary from monocle as2rel --json output.

        Returns:
            ASRelationship instance.
        """
        # Parse percentage strings like "47.7%" to float
        def parse_pct(value: str | float) -> float:
            if isinstance(value, (int, float)):
                return float(value)
            return float(value.rstrip("%"))

        return cls(
            asn1=data["asn1"],
            asn2=data["asn2"],
            asn2_name=data.get("asn2_name"),
            connected_pct=parse_pct(data.get("connected", 0)),
            peer_pct=parse_pct(data.get("peer", 0)),
            as1_upstream_pct=parse_pct(data.get("as1_upstream", 0)),
            as2_upstream_pct=parse_pct(data.get("as2_upstream", 0)),
        )


@dataclass
class ASNeighbor:
    """A neighbor AS with visibility information.

    Attributes:
        asn: Autonomous System Number.
        name: Human-readable AS name.
        peers_count: Number of BGP peers observing this relationship.
        peers_percent: Visibility percentage (out of max peers).
    """

    asn: int
    name: Optional[str]
    peers_count: int
    peers_percent: float

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "asn": self.asn,
            "name": self.name,
            "peers_count": self.peers_count,
            "peers_percent": self.peers_percent,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ASNeighbor":
        """Create an ASNeighbor from Monocle JSON output.

        Args:
            data: Dictionary from connectivity top list.

        Returns:
            ASNeighbor instance.
        """
        return cls(
            asn=data["asn"],
            name=data.get("name"),
            peers_count=data.get("peers_count", 0),
            peers_percent=data.get("peers_percent", 0.0),
        )


@dataclass
class ASConnectivity:
    """Connectivity summary for an Autonomous System.

    Provides counts and top examples of upstreams, peers, and downstreams.

    Attributes:
        asn: The queried Autonomous System Number.
        total_neighbors: Total number of observed neighbor ASes.
        max_visibility: Maximum number of BGP peers that could observe.
        upstreams: List of upstream providers (transit).
        peers: List of peering ASes.
        downstreams: List of downstream customers.
    """

    asn: int
    total_neighbors: int
    max_visibility: int
    upstreams: list[ASNeighbor] = field(default_factory=list)
    peers: list[ASNeighbor] = field(default_factory=list)
    downstreams: list[ASNeighbor] = field(default_factory=list)

    @property
    def upstream_count(self) -> int:
        """Number of upstream providers."""
        return len(self.upstreams)

    @property
    def peer_count(self) -> int:
        """Number of peering ASes."""
        return len(self.peers)

    @property
    def downstream_count(self) -> int:
        """Number of downstream customers."""
        return len(self.downstreams)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "asn": self.asn,
            "total_neighbors": self.total_neighbors,
            "max_visibility": self.max_visibility,
            "upstreams": [u.to_dict() for u in self.upstreams],
            "peers": [p.to_dict() for p in self.peers],
            "downstreams": [d.to_dict() for d in self.downstreams],
        }

    @classmethod
    def from_dict(cls, data: dict, asn: int, max_peers: int) -> "ASConnectivity":
        """Create ASConnectivity from Monocle inspect --show connectivity output.

        Args:
            data: The 'connectivity.summary' dict from monocle output.
            asn: The queried ASN.
            max_peers: Maximum peer count from response.

        Returns:
            ASConnectivity instance.
        """
        upstreams_data = data.get("upstreams", {})
        peers_data = data.get("peers", {})
        downstreams_data = data.get("downstreams", {})

        upstreams = [
            ASNeighbor.from_dict(n) for n in upstreams_data.get("top", [])
        ]
        peers = [
            ASNeighbor.from_dict(n) for n in peers_data.get("top", [])
        ]
        downstreams = [
            ASNeighbor.from_dict(n) for n in downstreams_data.get("top", [])
        ]

        # Calculate total neighbors from counts
        total = (
            upstreams_data.get("count", 0)
            + peers_data.get("count", 0)
            + downstreams_data.get("count", 0)
        )

        return cls(
            asn=asn,
            total_neighbors=total,
            max_visibility=max_peers,
            upstreams=upstreams,
            peers=peers,
            downstreams=downstreams,
        )
