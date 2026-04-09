"""RPKI data models for ROA and ASPA objects.

Represents validated RPKI payloads as returned by relying party software
(rpki-client, Routinator). These are cryptographically signed objects
from the global RPKI repositories.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ASPAObject:
    """A validated ASPA (AS Provider Authorization) payload.

    Represents a signed RPKI object that authorizes a set of provider ASNs
    for a customer ASN. Corresponds to the ASPA profile
    (draft-ietf-sidrops-aspa-profile).

    Attributes:
        customer_asn: The customer AS that published this ASPA.
        provider_asns: Set of ASNs authorized as upstream providers.
        expires: Unix timestamp when this object expires.
    """

    customer_asn: int
    provider_asns: frozenset[int]
    expires: int = 0


@dataclass(frozen=True)
class ROAObject:
    """A validated ROA (Route Origin Authorization) payload.

    Represents a signed RPKI object that authorizes an origin ASN to
    announce a prefix up to a maximum length.

    Attributes:
        prefix: The IP prefix in CIDR notation.
        max_length: Maximum prefix length allowed.
        origin_asn: The AS authorized to originate this prefix.
        trust_anchor: The trust anchor (RIR) that issued this object.
        expires: Unix timestamp when this object expires.
    """

    prefix: str
    max_length: int
    origin_asn: int
    trust_anchor: str = ""
    expires: int = 0


@dataclass
class RPKIDump:
    """Container for a full RPKI dump from a relying party.

    Holds lists of validated ROA and ASPA objects along with metadata
    about when the dump was generated.

    Attributes:
        roas: List of validated ROA objects.
        aspas: List of validated ASPA objects.
        generated: ISO8601 timestamp of when the dump was produced.
        source: Identifier of the relying party that produced this dump.
    """

    roas: list[ROAObject] = field(default_factory=list)
    aspas: list[ASPAObject] = field(default_factory=list)
    generated: str = ""
    source: str = ""
