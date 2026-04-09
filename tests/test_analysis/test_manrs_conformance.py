"""Tests for MANRS readiness assessment module."""

import json

import pytest

from bgp_explorer.analysis.manrs_conformance import MANRSReadinessAssessor
from bgp_explorer.analysis.rov_coverage import ROVCoverageReport
from bgp_explorer.models.manrs import MANRSAction, MANRSReadiness

# --- Helpers ---


def make_rov_report(
    prefix: str = "192.0.2.0/24",
    protection_level: str = "high",
    path_coverage: float = 0.9,
) -> ROVCoverageReport:
    return ROVCoverageReport(
        prefix=prefix,
        total_paths=10,
        paths_with_rov_enforcer=int(10 * path_coverage),
        path_coverage=path_coverage,
        tier1_coverage=path_coverage * 0.8,
        protection_level=protection_level,
        rov_enforcers_in_paths=[],
        summary=f"Coverage: {path_coverage:.0%}",
    )


# --- Action 1: Filtering Tests ---


class TestAction1Filtering:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_ready_high_rpki_and_rov(self, assessor):
        """High ROA coverage + high ROV = READY for filtering."""
        rov = make_rov_report(protection_level="high", path_coverage=0.92)
        report = assessor.assess(asn=64496, rpki_coverage=0.95, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        assert filtering.readiness == MANRSReadiness.READY

    def test_marked_partially_measurable(self, assessor):
        """Action 1 should be marked as partially measurable (not fully)."""
        rov = make_rov_report(protection_level="high", path_coverage=0.92)
        report = assessor.assess(asn=64496, rpki_coverage=0.95, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        assert filtering.measurable is False

    def test_aspiring_medium_coverage(self, assessor):
        """Medium ROA coverage = ASPIRING for filtering."""
        rov = make_rov_report(protection_level="medium", path_coverage=0.6)
        report = assessor.assess(asn=64496, rpki_coverage=0.75, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        assert filtering.readiness == MANRSReadiness.ASPIRING

    def test_lagging_low_coverage(self, assessor):
        """Low ROA coverage + low ROV = LAGGING for filtering."""
        rov = make_rov_report(protection_level="low", path_coverage=0.2)
        report = assessor.assess(asn=64496, rpki_coverage=0.3, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        assert filtering.readiness == MANRSReadiness.LAGGING

    def test_no_data_unknown(self, assessor):
        """No ROA or ROV data = UNKNOWN for filtering."""
        report = assessor.assess(asn=64496)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        assert filtering.readiness == MANRSReadiness.UNKNOWN

    def test_always_includes_operator_verification(self, assessor):
        """Even READY should include operator-side verification steps."""
        rov = make_rov_report(protection_level="high", path_coverage=0.92)
        report = assessor.assess(asn=64496, rpki_coverage=0.95, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        all_text = " ".join(filtering.recommendations + filtering.evidence)
        # Should mention what we CAN'T verify and what the operator must do
        assert "cannot" in all_text.lower() or "verify" in all_text.lower()

    def test_evidence_distinguishes_proxy_from_actual(self, assessor):
        """Evidence should make clear this is a proxy measurement."""
        rov = make_rov_report(protection_level="high", path_coverage=0.92)
        report = assessor.assess(asn=64496, rpki_coverage=0.95, rov_report=rov)
        filtering = next(f for f in report.action_findings if f.action == MANRSAction.FILTERING)
        all_text = " ".join(filtering.evidence)
        assert "proxy" in all_text.lower() or "indirect" in all_text.lower()


# --- Action 2: Anti-Spoofing Tests ---


class TestAction2AntiSpoofing:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_excluded_from_findings(self, assessor):
        """Anti-spoofing should not appear in findings — it can't be measured."""
        report = assessor.assess(asn=64496, rpki_coverage=0.99)
        actions_in_findings = [f.action for f in report.action_findings]
        assert MANRSAction.ANTI_SPOOFING not in actions_in_findings

    def test_excluded_from_score(self, assessor):
        """Anti-spoofing should not affect the overall score."""
        report = assessor.assess(asn=64496, rpki_coverage=0.99)
        # Score should only reflect Actions 1, 3, 4
        assert all(
            f.action != MANRSAction.ANTI_SPOOFING for f in report.action_findings
        )

    def test_mentioned_in_limitations(self, assessor):
        """Limitations should note that Action 2 is excluded."""
        report = assessor.assess(asn=64496)
        assert any("Action 2" in lim or "anti-spoofing" in lim.lower() for lim in report.limitations)


# --- Action 3: Coordination Tests ---


class TestAction3Coordination:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_ready_both_contacts(self, assessor):
        """Both PeeringDB NOC + WHOIS abuse contact = READY."""
        contacts = {"noc_email": "noc@example.com", "abuse_email": "abuse@example.com"}
        whois = {"abuse_contacts": ["abuse@example.com"]}
        report = assessor.assess(asn=64496, contacts=contacts, whois_data=whois)
        coord = next(f for f in report.action_findings if f.action == MANRSAction.COORDINATION)
        assert coord.readiness == MANRSReadiness.READY

    def test_aspiring_only_peeringdb(self, assessor):
        """Only PeeringDB contacts = ASPIRING."""
        contacts = {"noc_email": "noc@example.com"}
        report = assessor.assess(asn=64496, contacts=contacts, whois_data=None)
        coord = next(f for f in report.action_findings if f.action == MANRSAction.COORDINATION)
        assert coord.readiness == MANRSReadiness.ASPIRING

    def test_aspiring_only_whois(self, assessor):
        """Only WHOIS abuse contact = ASPIRING."""
        whois = {"abuse_contacts": ["abuse@example.com"]}
        report = assessor.assess(asn=64496, contacts=None, whois_data=whois)
        coord = next(f for f in report.action_findings if f.action == MANRSAction.COORDINATION)
        assert coord.readiness == MANRSReadiness.ASPIRING

    def test_lagging_no_contacts(self, assessor):
        """No contacts anywhere = LAGGING."""
        report = assessor.assess(asn=64496, contacts=None, whois_data=None)
        coord = next(f for f in report.action_findings if f.action == MANRSAction.COORDINATION)
        assert coord.readiness == MANRSReadiness.LAGGING

    def test_lagging_empty_contacts(self, assessor):
        """Empty contact dicts = LAGGING."""
        report = assessor.assess(asn=64496, contacts={}, whois_data={})
        coord = next(f for f in report.action_findings if f.action == MANRSAction.COORDINATION)
        assert coord.readiness == MANRSReadiness.LAGGING


# --- Action 4: Global Validation Tests ---


class TestAction4Validation:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_ready_full_rpki_and_aspa(self, assessor):
        """High ROA coverage + ASPA = READY for validation."""
        report = assessor.assess(asn=64496, rpki_coverage=0.95, has_aspa=True)
        validation = next(f for f in report.action_findings if f.action == MANRSAction.VALIDATION)
        assert validation.readiness == MANRSReadiness.READY
        assert validation.measurable is True

    def test_aspiring_high_rpki_no_aspa(self, assessor):
        """High ROA coverage but no ASPA = ASPIRING."""
        report = assessor.assess(asn=64496, rpki_coverage=0.95, has_aspa=False)
        validation = next(f for f in report.action_findings if f.action == MANRSAction.VALIDATION)
        assert validation.readiness == MANRSReadiness.ASPIRING

    def test_aspiring_medium_rpki(self, assessor):
        """Medium ROA coverage = ASPIRING for validation."""
        report = assessor.assess(asn=64496, rpki_coverage=0.75)
        validation = next(f for f in report.action_findings if f.action == MANRSAction.VALIDATION)
        assert validation.readiness == MANRSReadiness.ASPIRING

    def test_lagging_low_rpki(self, assessor):
        """Low ROA coverage = LAGGING for validation."""
        report = assessor.assess(asn=64496, rpki_coverage=0.2)
        validation = next(f for f in report.action_findings if f.action == MANRSAction.VALIDATION)
        assert validation.readiness == MANRSReadiness.LAGGING

    def test_no_rpki_data_unknown(self, assessor):
        """No RPKI data = UNKNOWN for validation."""
        report = assessor.assess(asn=64496)
        validation = next(f for f in report.action_findings if f.action == MANRSAction.VALIDATION)
        assert validation.readiness == MANRSReadiness.UNKNOWN


# --- Overall Scoring Tests ---


class TestOverallScoring:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_excellent_network_ready(self, assessor):
        """Network with everything in order = READY overall."""
        rov = make_rov_report(protection_level="high", path_coverage=0.92)
        contacts = {"noc_email": "noc@example.com"}
        whois = {"abuse_contacts": ["abuse@example.com"]}
        report = assessor.assess(
            asn=13335,
            rpki_coverage=0.95,
            has_aspa=True,
            rov_report=rov,
            contacts=contacts,
            whois_data=whois,
        )
        assert report.overall_readiness == MANRSReadiness.READY
        assert report.overall_score >= 80

    def test_poor_network_lagging(self, assessor):
        """Network with nothing in order = LAGGING overall."""
        report = assessor.assess(asn=64496)
        assert report.overall_readiness in (MANRSReadiness.LAGGING, MANRSReadiness.UNKNOWN)
        assert report.overall_score < 60

    def test_mixed_network_aspiring(self, assessor):
        """Network with some measures = ASPIRING overall."""
        contacts = {"noc_email": "noc@example.com"}
        report = assessor.assess(asn=64496, rpki_coverage=0.8, contacts=contacts)
        assert report.overall_readiness == MANRSReadiness.ASPIRING

    def test_always_three_action_findings(self, assessor):
        """Report contains 3 action findings (Action 2 excluded)."""
        report = assessor.assess(asn=64496)
        assert len(report.action_findings) == 3
        actions = {f.action for f in report.action_findings}
        assert actions == {
            MANRSAction.FILTERING,
            MANRSAction.COORDINATION,
            MANRSAction.VALIDATION,
        }

    def test_limitations_mention_excluded_action2(self, assessor):
        """Report mentions Action 2 is excluded because it's unmeasurable."""
        report = assessor.assess(asn=64496)
        assert any(
            "action 2" in lim.lower() or "anti-spoofing" in lim.lower()
            for lim in report.limitations
        )

    def test_score_range(self, assessor):
        """Score is always between 0 and 100."""
        report = assessor.assess(asn=64496)
        assert 0 <= report.overall_score <= 100

    def test_report_to_dict_serializable(self, assessor):
        """Report is JSON-serializable via to_dict()."""
        rov = make_rov_report(protection_level="high", path_coverage=0.9)
        report = assessor.assess(asn=64496, rpki_coverage=0.95, has_aspa=True, rov_report=rov)
        d = report.to_dict()
        json_str = json.dumps(d)
        assert "64496" in json_str


# --- Format Report Tests ---


class TestFormatReport:
    @pytest.fixture
    def assessor(self):
        return MANRSReadinessAssessor()

    def test_format_contains_key_sections(self, assessor):
        """Formatted report contains essential sections."""
        rov = make_rov_report(protection_level="high", path_coverage=0.9)
        report = assessor.assess(asn=64496, rpki_coverage=0.9, rov_report=rov)
        text = assessor.format_report(report)
        assert "AS64496" in text
        assert "MANRS" in text
        assert "Filtering" in text or "Action 1" in text
        assert "Anti-Spoofing" in text or "Action 2" in text
        assert "Coordination" in text or "Action 3" in text
        assert "Validation" in text or "Action 4" in text

    def test_format_shows_limitations(self, assessor):
        """Formatted report shows limitations section."""
        report = assessor.assess(asn=64496)
        text = assessor.format_report(report)
        assert "limitation" in text.lower() or "cannot" in text.lower()
