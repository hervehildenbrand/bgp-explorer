"""ASPA (AS Provider Authorization) validation for BGP AS paths.

Uses Monocle relationship data as a proxy for ASPA objects. When real
RPKI ASPA objects become widely deployed, swap in RealASPAProvider.

Valley-free routing rule: In a valid BGP path, the AS path goes
customer->provider (uphill), then optionally through peers, then
provider->customer (downhill). A "valley" occurs when the path goes
downhill then uphill again, indicating a route leak.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from bgp_explorer.models.aspa import ASPAHopResult, ASPAState, ASPAValidationResult
from bgp_explorer.sources.monocle import MonocleClient


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


class RealASPAProvider:
    """Placeholder for real RPKI ASPA objects.

    When RPKI ASPA objects become widely deployed, implement this class
    to fetch and validate against signed ASPA records.
    """

    async def get_authorized_providers(self, asn: int) -> list[int]:
        raise NotImplementedError("Real ASPA objects not yet supported")

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        raise NotImplementedError("Real ASPA objects not yet supported")

    @property
    def source_name(self) -> str:
        return "rpki-aspa"


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

        confidence = 0.0 if is_authorized is None else 0.7

        return ASPAHopResult(
            asn=asn,
            next_asn=next_asn,
            is_authorized_provider=is_authorized,
            relationship_type=rel_type,
            data_source=self._provider.source_name,
            confidence=confidence,
        )

    @staticmethod
    def _check_valley_free(hop_results: list[ASPAHopResult]) -> bool:
        """Check if the path follows valley-free routing.

        Valley-free: the path goes uphill (customer->provider), optionally
        through a peer link, then downhill (provider->customer). A valley
        occurs when the path goes downhill then back uphill.
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
                # Peer link: after this, should only go down
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
    use_real_aspa: bool = False,
) -> ASPAValidator | None:
    """Factory function to create an ASPA validator.

    Args:
        monocle: MonocleClient for Monocle-based validation.
        use_real_aspa: If True, use real RPKI ASPA objects (not yet supported).

    Returns:
        ASPAValidator if a data provider is available, None otherwise.
    """
    if use_real_aspa:
        return ASPAValidator(RealASPAProvider())
    if monocle is not None:
        return ASPAValidator(MonocleASPAProvider(monocle))
    return None
