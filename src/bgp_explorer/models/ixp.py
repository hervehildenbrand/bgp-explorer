"""IXP (Internet Exchange Point) data models for PeeringDB integration."""

from dataclasses import dataclass


@dataclass
class IXP:
    """Internet Exchange Point information.

    Attributes:
        id: PeeringDB IXP ID
        name: IXP name (e.g., "DE-CIX Frankfurt", "AMS-IX")
        city: City where the IXP is located
        country: ISO 3166-1 alpha-2 country code
        website: IXP website URL
        participant_count: Number of networks present at this IXP
    """

    id: int
    name: str
    city: str
    country: str
    website: str | None = None
    participant_count: int | None = None

    def to_dict(self) -> dict:
        """Convert IXP to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "city": self.city,
            "country": self.country,
            "website": self.website,
            "participant_count": self.participant_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IXP":
        """Create an IXP from a dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            city=data["city"],
            country=data["country"],
            website=data.get("website"),
            participant_count=data.get("participant_count"),
        )


@dataclass
class Network:
    """Network/ASN information from PeeringDB.

    Attributes:
        asn: Autonomous System Number
        name: Network name (e.g., "Google LLC", "Cloudflare, Inc.")
        info_type: Network type (e.g., "NSP", "Content", "Enterprise")
        website: Network website URL
    """

    asn: int
    name: str
    info_type: str | None = None
    website: str | None = None

    def to_dict(self) -> dict:
        """Convert Network to dictionary for JSON serialization."""
        return {
            "asn": self.asn,
            "name": self.name,
            "info_type": self.info_type,
            "website": self.website,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Network":
        """Create a Network from a dictionary."""
        return cls(
            asn=data["asn"],
            name=data["name"],
            info_type=data.get("info_type"),
            website=data.get("website"),
        )


@dataclass
class IXPPresence:
    """A network's presence at an IXP (from netixlan records).

    Attributes:
        asn: Network's AS number
        ixp_id: PeeringDB IXP ID
        ixp_name: IXP name for convenience
        ipaddr4: IPv4 peering address at this IXP
        ipaddr6: IPv6 peering address at this IXP
        speed: Port speed in Mbps
    """

    asn: int
    ixp_id: int
    ixp_name: str
    ipaddr4: str | None = None
    ipaddr6: str | None = None
    speed: int | None = None

    def to_dict(self) -> dict:
        """Convert IXPPresence to dictionary for JSON serialization."""
        return {
            "asn": self.asn,
            "ixp_id": self.ixp_id,
            "ixp_name": self.ixp_name,
            "ipaddr4": self.ipaddr4,
            "ipaddr6": self.ipaddr6,
            "speed": self.speed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IXPPresence":
        """Create an IXPPresence from a dictionary."""
        return cls(
            asn=data["asn"],
            ixp_id=data["ixp_id"],
            ixp_name=data["ixp_name"],
            ipaddr4=data.get("ipaddr4"),
            ipaddr6=data.get("ipaddr6"),
            speed=data.get("speed"),
        )
