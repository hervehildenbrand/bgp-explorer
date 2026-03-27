"""ASPA (AS Provider Authorization) validation for BGP AS paths.

Supports multiple data sources for ASPA authorization:
1. Real RPKI ASPA objects (from rpki-client console) — cryptographically signed
2. CAIDA AS Relationships — inferred from observed BGP data (daily updates)
3. Monocle — inferred from observed BGP data (on-demand, fallback)

Valley-free routing rule: In a valid BGP path, the AS path goes
customer->provider (uphill), then optionally through peers, then
provider->customer (downhill). A "valley" occurs when the path goes
downhill then uphill again, indicating a route leak.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from bgp_explorer.models.aspa import ASPAHopResult, ASPAState, ASPAValidationResult
from bgp_explorer.sources.monocle import MonocleClient

logger = logging.getLogger(__name__)


@runtime_checkable
class ASPADataProvider(Protocol):
    """Abstract interface for ASPA authorization data."""

    async def get_authorized_providers(self, asn: int) -> list[int]:
        """Get list of ASNs authorized as providers for the given ASN."""
        ...

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        """Check if provider_asn is an authorized provider for asn.

        Returns True/False if known, None if no data available.
        """
        ...

    @property
    def source_name(self) -> str:
        """Name of the data source."""
        ...


class MonocleASPAProvider:
    """Uses Monocle AS relationship data as proxy for ASPA objects.

    Monocle provides observed upstream/downstream relationships from BGP
    routing tables. While not the same as cryptographically signed ASPA
    objects, it provides a good approximation for validation.
    """

    def __init__(self, monocle: MonocleClient):
        self._monocle = monocle
        self._upstream_cache: dict[int, list[int]] = {}

    async def get_authorized_providers(self, asn: int) -> list[int]:
        """Get upstream providers for an ASN from Monocle data."""
        if asn in self._upstream_cache:
            return self._upstream_cache[asn]

        upstreams = await self._monocle.get_as_upstreams(asn)
        provider_asns = [u.asn2 for u in upstreams]
        self._upstream_cache[asn] = provider_asns
        return provider_asns

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        """Check if provider_asn is an upstream of asn per Monocle data.

        Returns True/False if relationship data exists, None if ASN has
        no data in Monocle.
        """
        providers = await self.get_authorized_providers(asn)
        if not providers:
            # No data — could be unknown ASN or stub with no observed upstreams
            rel = await self._monocle.check_relationship(asn, provider_asn)
            if rel is None:
                return None
            return rel.relationship_type == "upstream"
        return provider_asn in providers

    @property
    def source_name(self) -> str:
        return "monocle"


class RpkiClientASPAProvider:
    """Uses real RPKI ASPA objects from the rpki-client console.

    Fetches cryptographically validated ASPA objects from
    console.rpki-client.org. These are signed RPKI objects published
    by ASN holders at their RIR, providing authoritative provider
    authorization data.
    """

    def __init__(self, rpki_console: "RpkiConsoleClient") -> None:
        from bgp_explorer.sources.rpki_console import RpkiConsoleClient

        self._rpki_console: RpkiConsoleClient = rpki_console

    async def get_authorized_providers(self, asn: int) -> list[int]:
        providers = await self._rpki_console.get_aspa_providers(asn)
        return list(providers)

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        providers = await self._rpki_console.get_aspa_providers(asn)
        if not providers:
            return None  # No ASPA published for this ASN
        return provider_asn in providers

    @property
    def source_name(self) -> str:
        return "rpki-aspa"


class CAIDAASPAProvider:
    """Uses CAIDA AS Relationships as a proxy for ASPA objects.

    CAIDA provides inferred provider-customer relationships from
    observed BGP data, updated monthly. More authoritative than
    live Monocle queries for bulk analysis.
    """

    def __init__(self, caida: "CAIDARelationshipsClient") -> None:
        from bgp_explorer.sources.caida_relationships import CAIDARelationshipsClient

        self._caida: CAIDARelationshipsClient = caida

    async def get_authorized_providers(self, asn: int) -> list[int]:
        upstreams = await self._caida.get_upstreams(asn)
        return list(upstreams)

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        upstreams = await self._caida.get_upstreams(asn)
        if not upstreams:
            rel = await self._caida.get_relationship(asn, provider_asn)
            if rel == "unknown":
                return None
            return rel == "customer"  # asn is customer of provider_asn
        return provider_asn in upstreams

    @property
    def source_name(self) -> str:
        return "caida"


class CompositeASPAProvider:
    """Tries multiple ASPA data sources in priority order.

    Falls through to the next provider when a source returns None
    (no data). Real RPKI ASPA objects take priority over inferred
    relationships.
    """

    def __init__(self, providers: list[ASPADataProvider]) -> None:
        self._providers = providers

    async def get_authorized_providers(self, asn: int) -> list[int]:
        for provider in self._providers:
            try:
                result = await provider.get_authorized_providers(asn)
                if result:
                    return result
            except Exception:
                logger.debug(
                    "Provider %s failed for ASN %d, trying next",
                    provider.source_name,
                    asn,
                )
                continue
        return []

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        for provider in self._providers:
            try:
                result = await provider.is_authorized_provider(asn, provider_asn)
                if result is not None:
                    return result
            except Exception:
                logger.debug(
                    "Provider %s failed for ASN %d, trying next",
                    provider.source_name,
                    asn,
                )
                continue
        return None

    @property
    def source_name(self) -> str:
        names = [p.source_name for p in self._providers]
        return f"composite({','.join(names)})"


class ASPAValidator:
    """Validates AS paths against ASPA authorization data.

    Checks two properties:
    1. Provider authorization: Each hop should represent an authorized relationship.
    2. Valley-free: Path should follow customer->provider->peer->provider->customer.
    """

    def __init__(self, provider: ASPADataProvider):
        self._provider = provider

    async def validate_path(self, as_path: list[int]) -> ASPAValidationResult:
        """Validate an AS path against ASPA data.

        Args:
            as_path: List of ASNs in the path (ordered origin to collector).

        Returns:
            ASPAValidationResult with per-hop details.
        """
        cleaned = self._remove_prepending(as_path)

        if len(cleaned) < 2:
            return ASPAValidationResult(
                as_path=cleaned,
                state=ASPAState.UNVERIFIABLE,
                summary="Path too short to validate (need at least 2 distinct ASNs).",
            )

        hop_results = []
        has_invalid = False
        has_unknown = False
        issues = []

        for i in range(len(cleaned) - 1):
            hop = await self._validate_hop(cleaned[i], cleaned[i + 1])
            hop_results.append(hop)

            if hop.is_authorized_provider is False:
                has_invalid = True
                issues.append(
                    f"AS{hop.asn} -> AS{hop.next_asn}: "
                    f"not an authorized provider ({hop.relationship_type})"
                )
            elif hop.is_authorized_provider is None:
                has_unknown = True

        valley_free = self._check_valley_free(hop_results)
        if not valley_free:
            issues.append("Path violates valley-free routing (possible route leak)")

        # Determine overall state
        if has_invalid or not valley_free:
            state = ASPAState.INVALID
        elif has_unknown:
            state = ASPAState.UNKNOWN
        else:
            state = ASPAState.VALID

        summary = self._build_summary(cleaned, state, hop_results, valley_free, issues)

        return ASPAValidationResult(
            as_path=cleaned,
            state=state,
            hop_results=hop_results,
            valley_free=valley_free,
            issues=issues,
            summary=summary,
        )

    # Confidence scores by data source type
    CONFIDENCE_SCORES: dict[str, float] = {
        "rpki-aspa": 1.0,       # Cryptographically signed ASPA objects
        "caida": 0.8,           # Inferred from observed BGP data (monthly)
        "monocle": 0.7,         # Inferred from observed BGP data (on-demand)
    }

    async def _validate_hop(self, asn: int, next_asn: int) -> ASPAHopResult:
        """Check if next_asn is an authorized provider for asn."""
        is_authorized = await self._provider.is_authorized_provider(asn, next_asn)

        if is_authorized is True:
            rel_type = "upstream"
        elif is_authorized is False:
            # Check reverse: maybe asn is the provider
            reverse = await self._provider.is_authorized_provider(next_asn, asn)
            if reverse is True:
                rel_type = "downstream"
            elif reverse is None:
                rel_type = "unknown"
            else:
                rel_type = "peer-or-lateral"
        else:
            rel_type = "unknown"

        source_name = self._provider.source_name
        # For composite providers, extract the actual source used
        base_source = source_name.split("(")[0] if "(" in source_name else source_name
        confidence = 0.0 if is_authorized is None else self.CONFIDENCE_SCORES.get(base_source, 0.7)

        return ASPAHopResult(
            asn=asn,
            next_asn=next_asn,
            is_authorized_provider=is_authorized,
            relationship_type=rel_type,
            data_source=source_name,
            confidence=confidence,
        )

    # Well-known Tier-1 transit-free ASNs whose inter-provider peering is
    # expected and should not trigger valley-free violations.
    TIER1_ASNS: set[int] = {
        174, 209, 286, 701, 1239, 1299, 2914, 3257, 3320, 3356,
        5511, 6453, 6461, 6762, 6830, 7018, 12956,
    }

    @staticmethod
    def _check_valley_free(hop_results: list[ASPAHopResult]) -> bool:
        """Check if the path follows valley-free routing.

        Valley-free: the path goes uphill (customer->provider), optionally
        through a peer link, then downhill (provider->customer). A valley
        occurs when the path goes downhill then back uphill.

        Peer-or-lateral hops between two Tier-1 ASNs are treated as neutral
        (they don't set went_down) because Tier-1 inter-provider peering is
        normal and expected.
        """
        if not hop_results:
            return True

        # Track direction: "up" = customer->provider, "down" = provider->customer
        # "peer" = peer link, "unknown" = can't determine
        went_down = False

        for hop in hop_results:
            if hop.relationship_type == "upstream":
                # Going uphill — not allowed after going downhill
                if went_down:
                    return False
            elif hop.relationship_type == "downstream":
                went_down = True
            elif hop.relationship_type == "peer-or-lateral":
                # Tier-1 inter-provider peering is expected — treat as neutral
                if hop.asn in ASPAValidator.TIER1_ASNS and hop.next_asn in ASPAValidator.TIER1_ASNS:
                    pass  # Don't set went_down for Tier-1 peering
                else:
                    # Regular peer link: after this, should only go down
                    went_down = True
            # "unknown" hops don't change direction tracking

        return True

    @staticmethod
    def _remove_prepending(as_path: list[int]) -> list[int]:
        """Remove consecutive duplicate ASNs (AS path prepending)."""
        if not as_path:
            return []
        result = [as_path[0]]
        for asn in as_path[1:]:
            if asn != result[-1]:
                result.append(asn)
        return result

    @staticmethod
    def _build_summary(
        as_path: list[int],
        state: ASPAState,
        hop_results: list[ASPAHopResult],
        valley_free: bool,
        issues: list[str],
    ) -> str:
        """Build human-readable summary."""
        path_str = " -> ".join(f"AS{asn}" for asn in as_path)
        lines = [f"ASPA validation for path: {path_str}"]
        lines.append(f"State: {state.value.upper()}")
        lines.append(f"Valley-free: {'Yes' if valley_free else 'No'}")

        if issues:
            lines.append("Issues:")
            for issue in issues:
                lines.append(f"  - {issue}")

        return "\n".join(lines)


def create_aspa_validator(
    monocle: MonocleClient | None = None,
    rpki_console: "RpkiConsoleClient | None" = None,
    caida: "CAIDARelationshipsClient | None" = None,
) -> ASPAValidator | None:
    """Factory function to create an ASPA validator.

    Creates a composite provider that tries sources in priority order:
    1. rpki-client console (real ASPA objects) — confidence 1.0
    2. CAIDA AS Relationships — confidence 0.8
    3. Monocle (fallback) — confidence 0.7

    Args:
        monocle: MonocleClient for Monocle-based validation.
        rpki_console: RpkiConsoleClient for real RPKI ASPA objects.
        caida: CAIDARelationshipsClient for CAIDA relationship data.

    Returns:
        ASPAValidator if at least one data provider is available, None otherwise.
    """
    providers: list[ASPADataProvider] = []

    if rpki_console is not None:
        providers.append(RpkiClientASPAProvider(rpki_console))

    if caida is not None:
        providers.append(CAIDAASPAProvider(caida))

    if monocle is not None:
        providers.append(MonocleASPAProvider(monocle))

    if not providers:
        return None

    if len(providers) == 1:
        return ASPAValidator(providers[0])

    return ASPAValidator(CompositeASPAProvider(providers))
