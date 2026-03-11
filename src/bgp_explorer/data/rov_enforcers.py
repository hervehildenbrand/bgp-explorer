"""Static list of known ROV (Route Origin Validation) enforcing networks.

This list contains ASNs of networks known to perform ROV filtering,
which means they drop RPKI-invalid routes. Having routes pass through
ROV-enforcing networks provides protection against route hijacks.

Categories:
- TIER1_ROV_ENFORCERS: Major transit providers that enforce ROV
- MAJOR_ROV_ENFORCERS: Large CDN, cloud, and eyeball networks that enforce ROV
"""

from typing import Any

# 15 confirmed Tier-1 ROV enforcers
TIER1_ROV_ENFORCERS: dict[int, str] = {
    174: "Cogent",
    209: "CenturyLink/Lumen",
    286: "KPN",
    701: "Verizon",
    1239: "Sprint",
    1299: "Arelion/Telia",
    2914: "NTT",
    3257: "GTT",
    3320: "DTAG",
    3356: "Lumen/Level3",
    5511: "Orange",
    6453: "Tata",
    6461: "Zayo",
    6762: "Telecom Italia/Sparkle",
    7018: "AT&T",
}


# ~50 major CDN/cloud/eyeball networks known to enforce ROV filtering
MAJOR_ROV_ENFORCERS: dict[int, str] = {
    # Cloud providers
    15169: "Google",
    16509: "Amazon/AWS",
    8075: "Microsoft",
    13335: "Cloudflare",
    14618: "Amazon",
    36492: "Google",
    # CDN providers
    20940: "Akamai",
    54113: "Fastly",
    22822: "Limelight",
    2906: "Netflix",
    # US eyeball networks
    7922: "Comcast",
    20115: "Charter",
    22773: "Cox",
    11351: "Charter",
    6128: "Cablevision",
    11427: "Charter",
    20001: "Charter",
    33588: "Charter",
    # European networks
    6805: "Telefonica DE",
    12322: "Free/Proxad",
    15557: "Bouygues",
    3215: "Orange FR",
    1136: "KPN NL",
    6830: "Liberty Global",
    # Asia-Pacific networks
    4766: "Korea Telecom",
    2516: "KDDI",
    4713: "NTT OCN Japan",
    7679: "QTNet Japan",
    17676: "Softbank",
    # Additional major ISPs
    9808: "China Mobile",
    4837: "China Unicom",
    4134: "Chinanet",
    9121: "Turk Telekom",
    12389: "Rostelecom",
    8402: "Vimpelcom",
    9498: "Bharti Airtel",
    45609: "Airtel India",
    # Hosting/cloud
    24940: "Hetzner",
    16276: "OVH",
    # Social/tech companies
    32934: "Facebook/Meta",
    714: "Apple",
    46489: "Twitch",
    19679: "Dropbox",
    40027: "Digital Ocean",
}


def is_known_rov_enforcer(asn: int) -> bool:
    """Check if an ASN is a known ROV enforcer.

    Args:
        asn: Autonomous System Number to check.

    Returns:
        True if the ASN is known to enforce ROV filtering.
    """
    return asn in TIER1_ROV_ENFORCERS or asn in MAJOR_ROV_ENFORCERS


def get_rov_enforcer_info(asn: int) -> dict[str, Any] | None:
    """Get information about a ROV enforcer.

    Args:
        asn: Autonomous System Number to look up.

    Returns:
        Dictionary with asn, name, and category if known, None otherwise.
    """
    if asn in TIER1_ROV_ENFORCERS:
        return {"asn": asn, "name": TIER1_ROV_ENFORCERS[asn], "category": "tier1"}
    if asn in MAJOR_ROV_ENFORCERS:
        return {"asn": asn, "name": MAJOR_ROV_ENFORCERS[asn], "category": "major"}
    return None
