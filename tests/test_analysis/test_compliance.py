"""Tests for DORA & NIS 2 compliance auditing module."""

import json

import pytest

from bgp_explorer.analysis.compliance import (
    ComplianceAuditor,
    ComplianceAuditReport,
    ComplianceCategoryReport,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceLevel,
    Severity,
)
from bgp_explorer.analysis.resilience import ResilienceReport
from bgp_explorer.analysis.rov_coverage import ROVCoverageReport
from bgp_explorer.analysis.stability import StabilityReport

# --- Helpers ---


def make_resilience_report(
    asn: int = 64496,
    score: float = 8.0,
    upstream_count: int = 3,
    peer_count: int = 50,
    ixp_count: int = 4,
    single_transit: bool = False,
    ddos_provider_detected: str | None = None,
    path_redundancy_score: float = 0.8,
) -> ResilienceReport:
    return ResilienceReport(
        asn=asn,
        score=score,
        transit_score=0.8,
        peering_score=0.5,
        ixp_score=0.8,
        path_redundancy_score=path_redundancy_score,
        upstream_count=upstream_count,
        peer_count=peer_count,
        ixp_count=ixp_count,
        upstreams=[f"AS{i}" for i in range(upstream_count)],
        ixps=[f"IXP-{i}" for i in range(ixp_count)],
        issues=[],
        recommendations=[],
        single_transit=single_transit,
        ddos_provider_detected=ddos_provider_detected,
    )


def make_stability_report(
    resource: str = "AS64496",
    updates_per_day: float = 5.0,
    is_stable: bool = True,
    is_flapping: bool = False,
) -> StabilityReport:
    return StabilityReport(
        resource=resource,
        period_start="2026-03-06T00:00:00",
        period_end="2026-03-13T00:00:00",
        total_updates=35,
        announcements=30,
        withdrawals=5,
        flap_count=0 if not is_flapping else 15,
        updates_per_day=updates_per_day,
        withdrawal_ratio=0.14,
        stability_score=9.0 if is_stable else 3.0,
        is_stable=is_stable,
        is_flapping=is_flapping,
    )


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


# --- Dataclass Tests ---


class TestDataclasses:
    def test_compliance_finding_creation(self):
        finding = ComplianceFinding(
            article="Art. 5",
            requirement="ICT risk management framework",
            status=ComplianceLevel.COMPLIANT,
            severity=Severity.HIGH,
            evidence="3 transit providers detected",
            recommendation="None needed",
            data_source="resilience",
        )
        assert finding.article == "Art. 5"
        assert finding.status == ComplianceLevel.COMPLIANT
        assert finding.severity == Severity.HIGH

    def test_compliance_category_report_creation(self):
        report = ComplianceCategoryReport(
            category="ICT Risk Management",
            articles=["Art. 5", "Art. 6"],
            findings=[],
            score=0.85,
            level=ComplianceLevel.COMPLIANT,
        )
        assert report.score == 0.85
        assert report.level == ComplianceLevel.COMPLIANT

    def test_compliance_audit_report_to_dict(self):
        report = ComplianceAuditReport(
            asn=64496,
            framework=ComplianceFramework.DORA,
            timestamp="2026-03-13T00:00:00",
            overall_score=85.0,
            overall_level=ComplianceLevel.COMPLIANT,
            categories=[],
            critical_findings=[],
            summary="All good",
        )
        d = report.to_dict()
        assert d["asn"] == 64496
        assert d["framework"] == "DORA"
        assert d["overall_level"] == "COMPLIANT"
        assert d["overall_score"] == 85.0
        # Verify it's JSON-serializable
        json_str = json.dumps(d)
        assert "DORA" in json_str

    def test_to_dict_with_findings(self):
        finding = ComplianceFinding(
            article="Art. 5",
            requirement="Transit diversity",
            status=ComplianceLevel.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            evidence="Single transit provider",
            recommendation="Add more upstreams",
            data_source="resilience",
        )
        cat = ComplianceCategoryReport(
            category="ICT Risk Management",
            articles=["Art. 5"],
            findings=[finding],
            score=0.2,
            level=ComplianceLevel.NON_COMPLIANT,
        )
        report = ComplianceAuditReport(
            asn=64496,
            framework=ComplianceFramework.DORA,
            timestamp="2026-03-13T00:00:00",
            overall_score=20.0,
            overall_level=ComplianceLevel.NON_COMPLIANT,
            categories=[cat],
            critical_findings=[finding],
            summary="Issues found",
        )
        d = report.to_dict()
        assert len(d["categories"]) == 1
        assert d["categories"][0]["findings"][0]["severity"] == "CRITICAL"
        assert len(d["critical_findings"]) == 1
        json.dumps(d)  # Must be serializable


# --- DORA Compliance Tests ---


class TestDORACompliance:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_single_transit_critical_finding(self, auditor):
        """Single transit provider triggers CRITICAL finding under DORA Art. 5-16."""
        resilience = make_resilience_report(
            upstream_count=1, single_transit=True, score=3.0
        )
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        assert report.framework == ComplianceFramework.DORA
        # Must have a CRITICAL finding about transit concentration
        critical = [
            f for f in report.critical_findings if f.severity == Severity.CRITICAL
        ]
        assert len(critical) >= 1
        assert any("transit" in f.evidence.lower() for f in critical)
        assert report.overall_level != ComplianceLevel.COMPLIANT

    def test_good_resilience_compliant(self, auditor):
        """Good resilience scores lead to COMPLIANT status."""
        resilience = make_resilience_report(
            score=8.5, upstream_count=4, peer_count=80, ixp_count=5
        )
        stability = make_stability_report(is_stable=True)
        rov = make_rov_report(protection_level="high", path_coverage=0.9)
        report = auditor.audit_dora(
            asn=64496,
            resilience_report=resilience,
            stability_report=stability,
            rov_report=rov,
            rpki_coverage=0.95,
        )
        assert report.overall_level == ComplianceLevel.COMPLIANT
        assert report.overall_score >= 80

    def test_low_resilience_high_finding(self, auditor):
        """Low resilience score triggers HIGH finding."""
        resilience = make_resilience_report(score=3.0, upstream_count=2)
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        high_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if f.severity == Severity.HIGH
            and f.status == ComplianceLevel.NON_COMPLIANT
        ]
        assert len(high_findings) >= 1

    def test_low_roa_deployment_high_finding(self, auditor):
        """Low ROA coverage (ASN's own deployment) triggers HIGH finding."""
        resilience = make_resilience_report()
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, rpki_coverage=0.3
        )
        roa_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "roa" in f.requirement.lower() and f.status == ComplianceLevel.NON_COMPLIANT
        ]
        assert len(roa_findings) >= 1
        assert any(f.severity == Severity.HIGH for f in roa_findings)

    def test_high_roa_low_rov_info_only(self, auditor):
        """High ROA coverage but low ROV enforcement is INFO (not the ASN's fault)."""
        resilience = make_resilience_report()
        rov = make_rov_report(protection_level="low", path_coverage=0.3)
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, rpki_coverage=0.9, rov_report=rov
        )
        # ROA deployment should be COMPLIANT
        roa_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "roa" in f.requirement.lower()
        ]
        assert any(f.status == ComplianceLevel.COMPLIANT for f in roa_findings)
        # ROV enforcement should be INFO (ecosystem issue, no penalty)
        rov_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "rov" in f.requirement.lower() and "enforcement" in f.requirement.lower()
        ]
        assert len(rov_findings) >= 1
        assert all(f.severity == Severity.INFO for f in rov_findings)

    def test_rpki_not_deployed_high_finding(self, auditor):
        """Low RPKI/ROV protection triggers HIGH finding when no rpki_coverage provided."""
        resilience = make_resilience_report()
        rov = make_rov_report(protection_level="low", path_coverage=0.1)
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, rov_report=rov
        )
        rpki_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "roa" in f.requirement.lower() or "rov" in f.requirement.lower()
        ]
        assert len(rpki_findings) >= 1
        assert any(f.status == ComplianceLevel.NON_COMPLIANT for f in rpki_findings)

    def test_route_instability_medium_finding(self, auditor):
        """Route flapping triggers MEDIUM finding."""
        resilience = make_resilience_report()
        stability = make_stability_report(is_flapping=True, is_stable=False)
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, stability_report=stability
        )
        flap_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if f.severity == Severity.MEDIUM
            and "flap" in f.evidence.lower()
        ]
        assert len(flap_findings) >= 1

    def test_provider_concentration_critical(self, auditor):
        """Less than 2 upstreams triggers CRITICAL third-party risk."""
        resilience = make_resilience_report(upstream_count=1, single_transit=True, score=3.0)
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        third_party_cats = [
            c for c in report.categories if "third" in c.category.lower()
        ]
        assert len(third_party_cats) >= 1
        critical = [f for f in third_party_cats[0].findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_ddos_provider_as_only_diversity_critical(self, auditor):
        """DDoS provider as only second upstream = effective single transit."""
        resilience = make_resilience_report(
            upstream_count=2, single_transit=False, score=5.0,
            ddos_provider_detected="Radware",
        )
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        # Should trigger CRITICAL transit concentration (effective single transit)
        critical = [
            f for f in report.critical_findings if f.severity == Severity.CRITICAL
        ]
        assert len(critical) >= 1
        assert any("transit" in f.evidence.lower() or "ddos" in f.evidence.lower() for f in critical)
        assert report.overall_level != ComplianceLevel.COMPLIANT

    def test_ddos_provider_with_multiple_real_upstreams_ok(self, auditor):
        """DDoS provider with 3+ upstreams = still diverse enough."""
        resilience = make_resilience_report(
            upstream_count=3, single_transit=False, score=7.0,
            ddos_provider_detected="Cloudflare",
        )
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        # Should NOT trigger CRITICAL transit concentration
        critical_transit = [
            f for f in report.critical_findings
            if f.severity == Severity.CRITICAL and "transit" in f.requirement.lower()
        ]
        assert len(critical_transit) == 0

    def test_low_peering_medium_finding(self, auditor):
        """Low peer count triggers MEDIUM finding."""
        resilience = make_resilience_report(peer_count=10)
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        peer_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "peer" in f.requirement.lower()
        ]
        assert len(peer_findings) >= 1

    def test_no_stability_data_high_incident_finding(self, auditor):
        """Missing stability data triggers HIGH incident management finding."""
        resilience = make_resilience_report()
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, stability_report=None
        )
        incident_cats = [
            c for c in report.categories if "incident" in c.category.lower()
        ]
        assert len(incident_cats) >= 1
        high = [f for f in incident_cats[0].findings if f.severity == Severity.HIGH]
        assert len(high) >= 1


# --- NIS 2 Compliance Tests ---


class TestNIS2Compliance:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_low_rov_supply_chain_finding(self, auditor):
        """Low ROV coverage triggers supply chain finding under NIS 2."""
        resilience = make_resilience_report()
        rov = make_rov_report(protection_level="low", path_coverage=0.1)
        report = auditor.audit_nis2(
            asn=64496, resilience_report=resilience, rov_report=rov
        )
        assert report.framework == ComplianceFramework.NIS2
        supply_chain_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "supply chain" in f.requirement.lower()
            or "rpki" in f.requirement.lower()
            or "rov" in f.requirement.lower()
        ]
        assert len(supply_chain_findings) >= 1

    def test_ddos_provider_effective_single_transit_continuity(self, auditor):
        """DDoS provider as only second upstream triggers business continuity finding."""
        resilience = make_resilience_report(
            upstream_count=2, ixp_count=3, single_transit=False,
            ddos_provider_detected="Radware",
        )
        report = auditor.audit_nis2(asn=64496, resilience_report=resilience)
        continuity_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "continuity" in f.requirement.lower()
            or "business" in f.requirement.lower()
        ]
        assert len(continuity_findings) >= 1
        assert any(f.severity == Severity.HIGH for f in continuity_findings)

    def test_business_continuity_check(self, auditor):
        """Insufficient upstreams or IXPs triggers business continuity finding."""
        resilience = make_resilience_report(upstream_count=1, ixp_count=1, single_transit=True, score=3.0)
        report = auditor.audit_nis2(asn=64496, resilience_report=resilience)
        continuity_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "continuity" in f.requirement.lower()
            or "business" in f.requirement.lower()
        ]
        assert len(continuity_findings) >= 1
        assert any(f.severity == Severity.HIGH for f in continuity_findings)

    def test_good_network_compliant(self, auditor):
        """Good network scores lead to COMPLIANT NIS 2 status."""
        resilience = make_resilience_report(
            score=8.5, upstream_count=4, peer_count=80, ixp_count=5
        )
        stability = make_stability_report(is_stable=True)
        rov = make_rov_report(protection_level="high", path_coverage=0.9)
        report = auditor.audit_nis2(
            asn=64496,
            resilience_report=resilience,
            stability_report=stability,
            rov_report=rov,
            rpki_coverage=0.95,
        )
        assert report.overall_level == ComplianceLevel.COMPLIANT
        assert report.overall_score >= 80

    def test_no_stability_incident_detection_finding(self, auditor):
        """Missing stability data triggers incident detection finding."""
        resilience = make_resilience_report()
        report = auditor.audit_nis2(
            asn=64496, resilience_report=resilience, stability_report=None
        )
        incident_cats = [
            c for c in report.categories if "incident" in c.category.lower()
        ]
        assert len(incident_cats) >= 1
        high = [f for f in incident_cats[0].findings if f.severity == Severity.HIGH]
        assert len(high) >= 1


# --- Scoring Model Tests ---


class TestScoringModel:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_severity_weights(self, auditor):
        """Verify severity weights are applied correctly."""
        assert auditor.SEVERITY_WEIGHTS[Severity.CRITICAL] == 40
        assert auditor.SEVERITY_WEIGHTS[Severity.HIGH] == 25
        assert auditor.SEVERITY_WEIGHTS[Severity.MEDIUM] == 15
        assert auditor.SEVERITY_WEIGHTS[Severity.LOW] == 5
        assert auditor.SEVERITY_WEIGHTS[Severity.INFO] == 0

    def test_category_score_no_findings(self, auditor):
        """Category with no findings scores 1.0."""
        score = auditor._calculate_category_score([])
        assert score == 1.0

    def test_category_score_critical_finding(self, auditor):
        """CRITICAL finding deducts 40 points from category."""
        findings = [
            ComplianceFinding(
                article="Art. 5",
                requirement="Test",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.CRITICAL,
                evidence="",
                recommendation="",
                data_source="test",
            )
        ]
        score = auditor._calculate_category_score(findings)
        assert score == 0.6  # 100 - 40 = 60 -> 0.6

    def test_category_score_floor_at_zero(self, auditor):
        """Score cannot go below 0."""
        findings = [
            ComplianceFinding(
                article="Art. 5",
                requirement="Test",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.CRITICAL,
                evidence="",
                recommendation="",
                data_source="test",
            )
            for _ in range(5)  # 5 x 40 = 200 > 100
        ]
        score = auditor._calculate_category_score(findings)
        assert score == 0.0

    def test_not_assessed_no_penalty(self, auditor):
        """NOT_ASSESSED findings don't penalize the score."""
        findings = [
            ComplianceFinding(
                article="Art. 5",
                requirement="Test",
                status=ComplianceLevel.NOT_ASSESSED,
                severity=Severity.HIGH,
                evidence="",
                recommendation="",
                data_source="test",
            )
        ]
        score = auditor._calculate_category_score(findings)
        assert score == 1.0  # No deduction

    def test_compliance_level_thresholds(self, auditor):
        """Verify compliance level threshold mapping."""
        assert auditor._score_to_level(85) == ComplianceLevel.COMPLIANT
        assert auditor._score_to_level(80) == ComplianceLevel.COMPLIANT
        assert auditor._score_to_level(79) == ComplianceLevel.PARTIAL
        assert auditor._score_to_level(50) == ComplianceLevel.PARTIAL
        assert auditor._score_to_level(49) == ComplianceLevel.NON_COMPLIANT
        assert auditor._score_to_level(0) == ComplianceLevel.NON_COMPLIANT


# --- audit_both Tests ---


class TestAuditBoth:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_audit_both_returns_two_reports(self, auditor):
        """audit_both returns a tuple of DORA and NIS2 reports."""
        resilience = make_resilience_report()
        dora_report, nis2_report = auditor.audit_both(
            asn=64496, resilience_report=resilience
        )
        assert dora_report.framework == ComplianceFramework.DORA
        assert nis2_report.framework == ComplianceFramework.NIS2


# --- Format Report Tests ---


class TestFormatReport:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_format_report_contains_key_elements(self, auditor):
        """Formatted report contains essential sections."""
        resilience = make_resilience_report(
            upstream_count=1, single_transit=True, score=3.0
        )
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        text = auditor.format_report(report)
        assert "AS64496" in text
        assert "DORA" in text
        assert "Score" in text or "score" in text
        # Should mention critical findings
        assert "CRITICAL" in text or "Critical" in text

    def test_format_report_compliant(self, auditor):
        """Compliant report shows positive status."""
        resilience = make_resilience_report(
            score=8.5, upstream_count=4, peer_count=80, ixp_count=5
        )
        stability = make_stability_report(is_stable=True)
        rov = make_rov_report(protection_level="high", path_coverage=0.9)
        report = auditor.audit_dora(
            asn=64496,
            resilience_report=resilience,
            stability_report=stability,
            rov_report=rov,
            rpki_coverage=0.95,
        )
        text = auditor.format_report(report)
        assert "COMPLIANT" in text


# --- Missing Optional Data Tests ---


class TestMissingOptionalData:
    @pytest.fixture
    def auditor(self):
        return ComplianceAuditor()

    def test_missing_stability_not_assessed(self, auditor):
        """Missing stability data produces NOT_ASSESSED findings in relevant checks."""
        resilience = make_resilience_report()
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, stability_report=None
        )
        # Should still produce a report
        assert report.overall_score is not None
        # Stability-dependent checks produce findings (either NOT_ASSESSED or HIGH)
        incident_cats = [c for c in report.categories if "incident" in c.category.lower()]
        assert len(incident_cats) == 1

    def test_missing_rov_not_assessed(self, auditor):
        """Missing ROV and RPKI data produces NOT_ASSESSED findings."""
        resilience = make_resilience_report()
        report = auditor.audit_dora(
            asn=64496, resilience_report=resilience, rov_report=None, rpki_coverage=None
        )
        roa_findings = [
            f
            for cat in report.categories
            for f in cat.findings
            if "roa" in f.requirement.lower()
            and f.status == ComplianceLevel.NOT_ASSESSED
        ]
        assert len(roa_findings) >= 1

    def test_all_optional_missing_still_works(self, auditor):
        """Audit works with only resilience report (minimum required)."""
        resilience = make_resilience_report()
        report = auditor.audit_dora(asn=64496, resilience_report=resilience)
        assert report.asn == 64496
        assert isinstance(report.overall_score, float)
        assert report.overall_level in ComplianceLevel
