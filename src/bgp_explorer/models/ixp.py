"""IXP (Internet Exchange Point) data models for PeeringDB integration."""

from dataclasses import dataclass, field


@dataclass
class NetworkContact:
    """Contact information for a network from PeeringDB.

    Attributes:
        role: Contact role (e.g., "Abuse", "NOC", "Policy", "Technical", "Sales")
        name: Contact name (may be empty)
        email: Contact email address
        phone: Contact phone number (may be empty)
        url: Contact URL (may be empty)
        visible: Whether contact is publicly visible
    """

    role: str
    name: str = ""
    email: str = ""
    phone: str = ""
    url: str = ""
    visible: bool = True

    def to_dict(self) -> dict:
        """Convert NetworkContact to dictionary for JSON serialization."""
        return {
            "role": self.role,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "url": self.url,
            "visible": self.visible,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkContact":
        """Create a NetworkContact from a dictionary."""
        return cls(
            role=data.get("role", ""),
            name=data.get("name", ""),
            email=data.get("email", ""),
            phone=data.get("phone", ""),
            url=data.get("url", ""),
            visible=data.get("visible", True),
        )


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
        contacts: List of network contacts (NOC, Abuse, etc.)
    """

    asn: int
    name: str
    info_type: str | None = None
    website: str | None = None
    contacts: list["NetworkContact"] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert Network to dictionary for JSON serialization."""
        return {
            "asn": self.asn,
            "name": self.name,
            "info_type": self.info_type,
            "website": self.website,
            "contacts": [c.to_dict() for c in self.contacts],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Network":
        """Create a Network from a dictionary."""
        return cls(
            asn=data["asn"],
            name=data["name"],
            info_type=data.get("info_type"),
            website=data.get("website"),
            contacts=[NetworkContact.from_dict(c) for c in data.get("contacts", [])],
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
