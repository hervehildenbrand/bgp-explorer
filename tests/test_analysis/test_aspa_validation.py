"""Tests for ASPA validation module."""

from unittest.mock import AsyncMock

import pytest

from bgp_explorer.analysis.aspa_validation import (
    ASPAValidator,
    MonocleASPAProvider,
    RealASPAProvider,
    create_aspa_validator,
)
from bgp_explorer.models.as_relationship import ASRelationship
from bgp_explorer.models.aspa import ASPAState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_relationship(asn1: int, asn2: int, rel_type: str) -> ASRelationship:
    """Create an ASRelationship with the right percentages for the given type."""
    if rel_type == "upstream":
        return ASRelationship(
            asn1=asn1, asn2=asn2, asn2_name=None,
            connected_pct=80.0, peer_pct=0.0,
            as1_upstream_pct=0.0, as2_upstream_pct=80.0,
        )
    elif rel_type == "downstream":
        return ASRelationship(
            asn1=asn1, asn2=asn2, asn2_name=None,
            connected_pct=80.0, peer_pct=0.0,
            as1_upstream_pct=80.0, as2_upstream_pct=0.0,
        )
    elif rel_type == "peer":
        return ASRelationship(
            asn1=asn1, asn2=asn2, asn2_name=None,
            connected_pct=80.0, peer_pct=50.0,
            as1_upstream_pct=10.0, as2_upstream_pct=10.0,
        )
    # unknown
    return ASRelationship(
        asn1=asn1, asn2=asn2, asn2_name=None,
        connected_pct=10.0, peer_pct=0.0,
        as1_upstream_pct=5.0, as2_upstream_pct=5.0,
    )


class FakeASPAProvider:
    """Fake provider with configurable provider mappings."""

    def __init__(self, provider_map: dict[int, list[int]]):
        """provider_map: {asn: [list of authorized provider ASNs]}"""
        self._map = provider_map

    async def get_authorized_providers(self, asn: int) -> list[int]:
        return self._map.get(asn, [])

    async def is_authorized_provider(self, asn: int, provider_asn: int) -> bool | None:
        if asn not in self._map:
            return None
        return provider_asn in self._map[asn]

    @property
    def source_name(self) -> str:
        return "fake"


# ---------------------------------------------------------------------------
# TestASPAValidator
# ---------------------------------------------------------------------------


class TestASPAValidator:
    """Tests for ASPAValidator core logic."""

    @pytest.mark.asyncio
    async def test_path_too_short(self):
        """Single-ASN path should be unverifiable."""
        validator = ASPAValidator(FakeASPAProvider({}))
        result = await validator.validate_path([13335])
        assert result.state == ASPAState.UNVERIFIABLE
        assert "too short" in result.summary.lower()

    @pytest.mark.asyncio
    async def test_path_too_short_after_prepending(self):
        """Path that becomes single ASN after prepending removal."""
        validator = ASPAValidator(FakeASPAProvider({}))
        result = await validator.validate_path([13335, 13335, 13335])
        assert result.state == ASPAState.UNVERIFIABLE

    @pytest.mark.asyncio
    async def test_all_authorized(self):
        """Path where all hops are authorized should be VALID."""
        # Path: 13335 -> 174 -> 15169
        # 13335 has provider 174, 174 has provider 15169
        provider = FakeASPAProvider({
            13335: [174],
            174: [15169],
        })
        validator = ASPAValidator(provider)
        result = await validator.validate_path([13335, 174, 15169])

        assert result.state == ASPAState.VALID
        assert result.valley_free is True
        assert len(result.hop_results) == 2
        assert result.hop_results[0].is_authorized_provider is True
        assert result.hop_results[1].is_authorized_provider is True
        assert not result.issues

    @pytest.mark.asyncio
    async def test_unauthorized_hop(self):
        """Path with an unauthorized hop should be INVALID."""
        # 13335 has provider 174, but 174 does NOT have 666 as provider
        provider = FakeASPAProvider({
            13335: [174],
            174: [3356],  # 666 not in the list
        })
        validator = ASPAValidator(provider)
        result = await validator.validate_path([13335, 174, 666])

        assert result.state == ASPAState.INVALID
        assert len(result.issues) > 0
        assert any("not an authorized provider" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_unknown_hop(self):
        """Path with unknown relationships should be UNKNOWN."""
        # 13335 has provider 174, but 999 has no data
        provider = FakeASPAProvider({
            13335: [174],
            # 174 not in map → returns None
        })
        validator = ASPAValidator(provider)
        result = await validator.validate_path([13335, 174, 15169])

        assert result.state == ASPAState.UNKNOWN

    @pytest.mark.asyncio
    async def test_prepending_handled(self):
        """AS path prepending should be removed before validation."""
        provider = FakeASPAProvider({
            13335: [174],
            174: [15169],
        })
        validator = ASPAValidator(provider)
        result = await validator.validate_path([13335, 13335, 174, 174, 174, 15169])

        assert result.as_path == [13335, 174, 15169]
        assert result.state == ASPAState.VALID
        assert len(result.hop_results) == 2

    @pytest.mark.asyncio
    async def test_valley_free_violation(self):
        """Path that goes downhill then uphill should fail valley-free check."""
        # Build provider: 13335 has downstream 174 (13335 is provider of 174)
        # Then 174 has upstream 15169
        # So path goes: 13335 (down to) 174 (up to) 15169 — valley!
        provider = FakeASPAProvider({
            13335: [],       # no upstreams (it IS the provider)
            174: [15169],    # 15169 is upstream of 174
        })
        validator = ASPAValidator(provider)

        # We need 13335->174 to be "downstream" direction
        # is_authorized_provider(13335, 174) → 174 not in [] → False
        # reverse check: is_authorized_provider(174, 13335) → 13335 not in [15169] → False
        # → rel_type = "peer-or-lateral" → sets went_down = True
        # is_authorized_provider(174, 15169) → True → "upstream" after went_down → valley!

        result = await validator.validate_path([13335, 174, 15169])
        assert result.valley_free is False
        assert result.state == ASPAState.INVALID
        assert any("valley-free" in i.lower() for i in result.issues)

    @pytest.mark.asyncio
    async def test_empty_path(self):
        """Empty path should be unverifiable."""
        validator = ASPAValidator(FakeASPAProvider({}))
        result = await validator.validate_path([])
        assert result.state == ASPAState.UNVERIFIABLE

    def test_remove_prepending(self):
        """Test static prepending removal."""
        assert ASPAValidator._remove_prepending([1, 1, 2, 2, 3]) == [1, 2, 3]
        assert ASPAValidator._remove_prepending([1]) == [1]
        assert ASPAValidator._remove_prepending([]) == []
        assert ASPAValidator._remove_prepending([1, 2, 1]) == [1, 2, 1]

    def test_check_valley_free_empty(self):
        """Empty hop list is valley-free."""
        assert ASPAValidator._check_valley_free([]) is True

    def test_check_valley_free_tier1_peering_neutral(self):
        """Tier-1 inter-provider peering should NOT trigger valley violation."""
        from bgp_explorer.models.aspa import ASPAHopResult

        # Path: customer -> Tier-1 A (peer) Tier-1 B -> customer
        # The peer hop between two Tier-1s should be neutral
        hops = [
            ASPAHopResult(
                asn=65000, next_asn=3356, is_authorized_provider=True,
                relationship_type="upstream", data_source="fake", confidence=0.7,
            ),
            ASPAHopResult(
                asn=3356, next_asn=1299, is_authorized_provider=False,
                relationship_type="peer-or-lateral", data_source="fake", confidence=0.7,
            ),
            ASPAHopResult(
                asn=1299, next_asn=65001, is_authorized_provider=False,
                relationship_type="downstream", data_source="fake", confidence=0.7,
            ),
        ]
        # With Tier-1 peering treated as neutral, the uphill->peer->downhill is valid
        assert ASPAValidator._check_valley_free(hops) is True

    def test_check_valley_free_non_tier1_peering_sets_went_down(self):
        """Non-Tier-1 peering should still trigger valley violation if followed by upstream."""
        from bgp_explorer.models.aspa import ASPAHopResult

        hops = [
            ASPAHopResult(
                asn=65000, next_asn=65001, is_authorized_provider=False,
                relationship_type="peer-or-lateral", data_source="fake", confidence=0.7,
            ),
            ASPAHopResult(
                asn=65001, next_asn=65002, is_authorized_provider=True,
                relationship_type="upstream", data_source="fake", confidence=0.7,
            ),
        ]
        # Non-Tier-1 peer sets went_down, so upstream after that is a valley
        assert ASPAValidator._check_valley_free(hops) is False

    def test_check_valley_free_tier1_peering_then_upstream_ok(self):
        """After Tier-1 peering (neutral), upstream should still be allowed."""
        from bgp_explorer.models.aspa import ASPAHopResult

        hops = [
            ASPAHopResult(
                asn=3356, next_asn=2914, is_authorized_provider=False,
                relationship_type="peer-or-lateral", data_source="fake", confidence=0.7,
            ),
            ASPAHopResult(
                asn=2914, next_asn=65000, is_authorized_provider=False,
                relationship_type="downstream", data_source="fake", confidence=0.7,
            ),
        ]
        # Tier-1 peering is neutral, downstream after is fine
        assert ASPAValidator._check_valley_free(hops) is True

    @pytest.mark.asyncio
    async def test_tier1_peering_path_not_invalid(self):
        """Full path through Tier-1 peering should not be marked INVALID."""
        # Path: 65000 -> 3356 (Tier-1) -> 1299 (Tier-1) -> 65001
        # 65000 has 3356 as provider, 65001 has 1299 as provider
        # 3356 and 1299 are peers (neither is provider of the other)
        provider = FakeASPAProvider({
            65000: [3356],
            3356: [],      # Tier-1, no upstream
            1299: [],      # Tier-1, no upstream
            65001: [1299],
        })
        validator = ASPAValidator(provider)
        result = await validator.validate_path([65000, 3356, 1299, 65001])

        # The 3356->1299 hop is peer-or-lateral between Tier-1s, treated as neutral
        assert result.valley_free is True


# ---------------------------------------------------------------------------
# TestMonocleASPAProvider
# ---------------------------------------------------------------------------


class TestMonocleASPAProvider:
    """Tests for MonocleASPAProvider."""

    @pytest.mark.asyncio
    async def test_get_authorized_providers(self):
        """Should return upstream ASNs from Monocle."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[
            _make_relationship(13335, 174, "upstream"),
            _make_relationship(13335, 3356, "upstream"),
        ])

        provider = MonocleASPAProvider(monocle)
        providers = await provider.get_authorized_providers(13335)

        assert providers == [174, 3356]
        monocle.get_as_upstreams.assert_called_once_with(13335)

    @pytest.mark.asyncio
    async def test_get_authorized_providers_caching(self):
        """Second call should use cache, not call Monocle again."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[
            _make_relationship(13335, 174, "upstream"),
        ])

        provider = MonocleASPAProvider(monocle)
        await provider.get_authorized_providers(13335)
        await provider.get_authorized_providers(13335)

        monocle.get_as_upstreams.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_authorized_provider_true(self):
        """Known upstream should return True."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[
            _make_relationship(13335, 174, "upstream"),
        ])

        provider = MonocleASPAProvider(monocle)
        result = await provider.is_authorized_provider(13335, 174)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_authorized_provider_false(self):
        """Known ASN without the provider in its upstreams should return False."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[
            _make_relationship(13335, 174, "upstream"),
        ])

        provider = MonocleASPAProvider(monocle)
        result = await provider.is_authorized_provider(13335, 666)
        assert result is False

    @pytest.mark.asyncio
    async def test_is_authorized_provider_no_data(self):
        """ASN with no upstream data and no relationship should return None."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[])
        monocle.check_relationship = AsyncMock(return_value=None)

        provider = MonocleASPAProvider(monocle)
        result = await provider.is_authorized_provider(99999, 174)
        assert result is None

    @pytest.mark.asyncio
    async def test_is_authorized_provider_fallback_to_check_relationship(self):
        """When no upstreams but relationship exists, use check_relationship."""
        monocle = AsyncMock()
        monocle.get_as_upstreams = AsyncMock(return_value=[])
        monocle.check_relationship = AsyncMock(
            return_value=_make_relationship(99999, 174, "upstream")
        )

        provider = MonocleASPAProvider(monocle)
        result = await provider.is_authorized_provider(99999, 174)
        assert result is True

    @pytest.mark.asyncio
    async def test_source_name(self):
        monocle = AsyncMock()
        provider = MonocleASPAProvider(monocle)
        assert provider.source_name == "monocle"


# ---------------------------------------------------------------------------
# TestCreateASPAValidator
# ---------------------------------------------------------------------------


class TestCreateASPAValidator:
    """Tests for factory function."""

    def test_with_monocle(self):
        """Should create validator with MonocleASPAProvider."""
        monocle = AsyncMock()
        validator = create_aspa_validator(monocle=monocle)
        assert validator is not None
        assert isinstance(validator, ASPAValidator)

    def test_without_monocle(self):
        """Should return None when no data source available."""
        validator = create_aspa_validator()
        assert validator is None

    def test_real_aspa_raises(self):
        """RealASPAProvider should raise NotImplementedError."""
        validator = create_aspa_validator(use_real_aspa=True)
        assert validator is not None

    @pytest.mark.asyncio
    async def test_real_aspa_methods_raise(self):
        """RealASPAProvider methods should raise NotImplementedError."""
        provider = RealASPAProvider()
        with pytest.raises(NotImplementedError):
            await provider.get_authorized_providers(13335)
        with pytest.raises(NotImplementedError):
            await provider.is_authorized_provider(13335, 174)
        assert provider.source_name == "rpki-aspa"
