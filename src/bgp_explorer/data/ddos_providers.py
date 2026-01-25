"""Static list of known DDoS protection provider ASNs.

This list is used for network resilience assessments to detect
always-on DDoS protection services in the upstream path.

Note: Having a DDoS provider in the path is not inherently bad,
but it indicates a dependency on a third-party for traffic delivery.
"""

DDOS_PROVIDERS: dict[str, list[int]] = {
    "Cloudflare": [
        13335,  # Main ASN
        14789,  # Asia Pacific
        132892,  # Australia
        133877,  # China
        202623,  # Europe
        203898,  # Additional
        209242,  # Additional
        394536,  # US Gov
        395747,  # Additional
    ],
    "Akamai": [
        12222,  # Akamai Technologies
        16625,  # Akamai Technologies
        16702,  # Akamai Technologies
        17204,  # Akamai Technologies
        18680,  # Akamai Technologies
        18717,  # Akamai Technologies
        20189,  # Akamai Technologies
        20940,  # Akamai International
        21342,  # Akamai Technologies
        21357,  # Akamai Technologies
        21399,  # Akamai Technologies
        22207,  # Akamai Technologies
        22452,  # Akamai Technologies
        23454,  # Akamai Technologies
        23455,  # Akamai Technologies
    ],
    "Prolexic": [
        32787,  # Main
        49846,  # Europe
        213120,  # Additional
        393234,  # Additional
    ],
    "Fastly": [
        895,  # Legacy
        54113,  # Main
        149097,  # Additional
        394192,  # Additional
    ],
    "Imperva": [
        19551,  # Incapsula (now Imperva)
        62571,  # Imperva Inc
    ],
    "Radware": [
        15823,  # Radware
        25773,  # Radware
        48851,  # Radware
        198949,  # Radware
        213232,  # Radware
    ],
    "Neustar": [
        19907,  # Neustar
        19910,  # Neustar
        32978,  # Neustar
        32979,  # Neustar
        32980,  # Neustar
        32981,  # Neustar
        38347,  # Neustar
        46823,  # Neustar UltraDNS
    ],
    "Netscout": [
        10690,  # Arbor Networks
        26743,  # Netscout
        134060,  # Additional
    ],
    "Sucuri": [
        30148,  # Sucuri
    ],
    "Link11": [
        34309,  # Link11
    ],
    "Qrator": [
        200449,  # Qrator Labs
        209671,  # Qrator
        211112,  # Qrator
    ],
    "DDoS-Guard": [
        57724,  # DDoS-Guard
    ],
    "StormWall": [
        59796,  # StormWall
    ],
    "Voxility": [
        3223,  # Voxility
        39743,  # Voxility
    ],
}


def get_all_ddos_asns() -> set[int]:
    """Get a set of all known DDoS provider ASNs.

    Returns:
        Set of ASNs belonging to DDoS protection providers.
    """
    all_asns: set[int] = set()
    for asns in DDOS_PROVIDERS.values():
        all_asns.update(asns)
    return all_asns


def find_ddos_provider(asn: int) -> str | None:
    """Find which DDoS provider (if any) owns an ASN.

    Args:
        asn: Autonomous System Number to check.

    Returns:
        Provider name if ASN belongs to a known DDoS provider, None otherwise.
    """
    for provider, asns in DDOS_PROVIDERS.items():
        if asn in asns:
            return provider
    return None
