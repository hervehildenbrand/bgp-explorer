"""Tests for network resilience assessment module."""

import pytest

from bgp_explorer.analysis.resilience import ResilienceAssessor, ResilienceReport
from bgp_explorer.data.ddos_providers import DDOS_PROVIDERS
from bgp_explorer.models.as_relationship import ASRelationship
from bgp_explorer.models.ixp import IXPPresence


def make_upstream(asn1: int, asn2: int, name: str, connected_pct: float = 80.0) -> ASRelationship:
    """Create an ASRelationship representing an upstream provider."""
    return ASRelationship(
        asn1=asn1,
        asn2=asn2,
        asn2_name=name,
        connected_pct=connected_pct,
        peer_pct=0.0,
        as1_upstream_pct=0.0,  # asn1 is NOT the upstream
        as2_upstream_pct=100.0,  # asn2 IS the upstream (provider to asn1)
    )


def make_peer(asn1: int, asn2: int, name: str, connected_pct: float = 50.0) -> ASRelationship:
    """Create an ASRelationship representing a peer."""
    return ASRelationship(
        asn1=asn1,
        asn2=asn2,
        asn2_name=name,
        connected_pct=connected_pct,
        peer_pct=100.0,  # High peer percentage
        as1_upstream_pct=0.0,
        as2_upstream_pct=0.0,
    )


class TestDDoSProviders:
    """Tests for DDoS provider ASN list."""

    def test_ddos_providers_not_empty(self):
        """Test that DDoS providers list is populated."""
        assert len(DDOS_PROVIDERS) > 0

    def test_cloudflare_asns_present(self):
        """Test that Cloudflare ASNs are in the list."""
        assert "Cloudflare" in DDOS_PROVIDERS
        # Main Cloudflare ASN
        assert 13335 in DDOS_PROVIDERS["Cloudflare"]

    def test_akamai_asns_present(self):
        """Test that Akamai/Prolexic ASNs are in the list."""
        assert "Akamai" in DDOS_PROVIDERS
        assert "Prolexic" in DDOS_PROVIDERS

    def test_all_asns_are_integers(self):
        """Test that all ASNs in the list are integers."""
        for provider, asns in DDOS_PROVIDERS.items():
            for asn in asns:
                assert isinstance(asn, int), f"{provider} has non-integer ASN: {asn}"


class TestResilienceAssessor:
    """Tests for ResilienceAssessor class."""

    @pytest.fixture
    def assessor(self):
        """Create ResilienceAssessor instance."""
        return ResilienceAssessor()

    def test_score_transit_single_upstream_fails(self, assessor):
        """Test that single transit provider gets poor score."""
        upstreams = [make_upstream(64496, 3356, "Lumen")]
        score, issues = assessor._score_transit(upstreams)
        assert score < 0.5  # Less than 50% of weight
        assert any("single" in issue.lower() for issue in issues)

    def test_score_transit_multiple_upstreams_good(self, assessor):
        """Test that 3+ transit providers gets good score."""
        upstreams = [
            make_upstream(64496, 3356, "Lumen"),
            make_upstream(64496, 174, "Cogent", 70.0),
            make_upstream(64496, 6939, "Hurricane Electric", 60.0),
        ]
        score, issues = assessor._score_transit(upstreams)
        assert score >= 0.8  # Good score
        assert len(issues) == 0 or not any("single" in issue.lower() for issue in issues)

    def test_score_peering_low_peer_count(self, assessor):
        """Test that low peer count gets poor peering score."""
        peers = [make_peer(64496, 64497, "Peer1")]
        score, peer_count = assessor._score_peering(peers)
        assert score < 0.5  # Low score for few peers
        assert peer_count == 1

    def test_score_peering_high_peer_count(self, assessor):
        """Test that high peer count gets good peering score."""
        # Create 100 peers
        peers = [make_peer(64496, 64500 + i, f"Peer{i}") for i in range(100)]
        score, peer_count = assessor._score_peering(peers)
        assert score >= 0.8  # Good score for many peers
        assert peer_count == 100

    def test_score_ixp_no_presence(self, assessor):
        """Test that no IXP presence gets poor score."""
        ixps: list[IXPPresence] = []
        score, ixp_list = assessor._score_ixp(ixps)
        assert score == 0.0
        assert len(ixp_list) == 0

    def test_score_ixp_good_presence(self, assessor):
        """Test that presence at multiple IXPs gets good score."""
        ixps = [
            IXPPresence(asn=64496, ixp_id=1, ixp_name="AMS-IX", speed=10000),
            IXPPresence(asn=64496, ixp_id=2, ixp_name="DE-CIX Frankfurt", speed=10000),
            IXPPresence(asn=64496, ixp_id=3, ixp_name="LINX LON1", speed=10000),
            IXPPresence(asn=64496, ixp_id=4, ixp_name="Equinix Ashburn", speed=10000),
            IXPPresence(asn=64496, ixp_id=5, ixp_name="NYIIX", speed=10000),
        ]
        score, ixp_list = assessor._score_ixp(ixps)
        assert score >= 0.8  # Good score for 5 IXPs
        assert len(ixp_list) == 5

    def test_detect_ddos_provider_in_upstreams(self, assessor):
        """Test detection of DDoS provider in upstreams."""
        # Cloudflare AS13335 is a known DDoS provider
        upstreams = [
            make_upstream(64496, 13335, "Cloudflare"),  # Cloudflare
            make_upstream(64496, 3356, "Lumen", 70.0),
        ]
        detected = assessor._detect_ddos_provider(upstreams)
        assert detected is not None
        assert "Cloudflare" in detected

    def test_detect_ddos_provider_none_present(self, assessor):
        """Test no detection when no DDoS provider present."""
        upstreams = [
            make_upstream(64496, 3356, "Lumen"),
            make_upstream(64496, 174, "Cogent", 70.0),
        ]
        detected = assessor._detect_ddos_provider(upstreams)
        assert detected is None

    def test_calculate_final_score_capped_single_transit(self, assessor):
        """Test that score is capped at 5 with single transit."""
        scores = {
            "transit": 0.3,  # Poor transit
            "peering": 1.0,  # Great peering
            "ixp": 1.0,  # Great IXP
            "path_redundancy": 1.0,  # Great paths
        }
        flags = {
            "single_transit": True,
            "ddos_provider": None,
        }
        final_score = assessor._calculate_final_score(scores, flags)
        assert final_score <= 5.0

    def test_calculate_final_score_capped_ddos_provider(self, assessor):
        """Test that score is capped at 5 with always-on DDoS provider."""
        scores = {
            "transit": 1.0,
            "peering": 1.0,
            "ixp": 1.0,
            "path_redundancy": 1.0,
        }
        flags = {
            "single_transit": False,
            "ddos_provider": "Cloudflare",
        }
        final_score = assessor._calculate_final_score(scores, flags)
        assert final_score <= 5.0

    def test_calculate_final_score_high_resilience(self, assessor):
        """Test high score for fully resilient network."""
        scores = {
            "transit": 1.0,
            "peering": 1.0,
            "ixp": 1.0,
            "path_redundancy": 1.0,
        }
        flags = {
            "single_transit": False,
            "ddos_provider": None,
        }
        final_score = assessor._calculate_final_score(scores, flags)
        assert final_score > 8.0


class TestResilienceReport:
    """Tests for ResilienceReport dataclass."""

    def test_report_creation(self):
        """Test creating a resilience report."""
        report = ResilienceReport(
            asn=64496,
            score=7.5,
            transit_score=0.8,
            peering_score=0.7,
            ixp_score=0.6,
            path_redundancy_score=0.9,
            upstream_count=3,
            peer_count=50,
            ixp_count=4,
            upstreams=["AS3356 (Lumen)", "AS174 (Cogent)", "AS6939 (HE)"],
            ixps=["AMS-IX", "DE-CIX", "LINX", "Equinix"],
            issues=[],
            recommendations=["Consider adding more IXP presence"],
            single_transit=False,
            ddos_provider_detected=None,
        )
        assert report.asn == 64496
        assert report.score == 7.5
        assert report.upstream_count == 3
        assert len(report.ixps) == 4

    def test_report_with_issues(self):
        """Test report with identified issues."""
        report = ResilienceReport(
            asn=64496,
            score=4.0,
            transit_score=0.3,
            peering_score=0.5,
            ixp_score=0.2,
            path_redundancy_score=0.6,
            upstream_count=1,
            peer_count=10,
            ixp_count=1,
            upstreams=["AS3356 (Lumen)"],
            ixps=["AMS-IX"],
            issues=["Single transit provider - critical SPOF"],
            recommendations=[
                "Add at least one more transit provider",
                "Increase IXP presence for geographic diversity",
            ],
            single_transit=True,
            ddos_provider_detected=None,
        )
        assert report.single_transit is True
        assert len(report.issues) == 1
        assert len(report.recommendations) == 2
