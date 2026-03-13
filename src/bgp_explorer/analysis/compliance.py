"""DORA & NIS 2 compliance auditing module.

Maps BGP routing analysis results to EU regulatory requirements:
- DORA (2022/2554): ICT risk management for financial entities
- NIS 2 (2022/2555): Cybersecurity for critical infrastructure operators

The auditor wraps existing analyzers (resilience, stability, ROV coverage)
and maps findings to specific regulatory articles.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from bgp_explorer.analysis.resilience import ResilienceReport
from bgp_explorer.analysis.rov_coverage import ROVCoverageReport
from bgp_explorer.analysis.stability import StabilityReport


class ComplianceFramework(Enum):
    DORA = "DORA"
    NIS2 = "NIS2"


class ComplianceLevel(Enum):
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ComplianceFinding:
    article: str
    requirement: str
    status: ComplianceLevel
    severity: Severity
    evidence: str
    recommendation: str
    data_source: str


@dataclass
class ComplianceCategoryReport:
    category: str
    articles: list[str]
    findings: list[ComplianceFinding]
    score: float  # 0.0-1.0
    level: ComplianceLevel


@dataclass
class ComplianceAuditReport:
    asn: int
    framework: ComplianceFramework
    timestamp: str
    overall_score: float  # 0-100
    overall_level: ComplianceLevel
    categories: list[ComplianceCategoryReport]
    critical_findings: list[ComplianceFinding]
    summary: str

    def to_dict(self) -> dict:
        return {
            "asn": self.asn,
            "framework": self.framework.value,
            "timestamp": self.timestamp,
            "overall_score": self.overall_score,
            "overall_level": self.overall_level.value,
            "categories": [
                {
                    "category": c.category,
                    "articles": c.articles,
                    "score": c.score,
                    "level": c.level.value,
                    "findings": [
                        {
                            "article": f.article,
                            "requirement": f.requirement,
                            "status": f.status.value,
                            "severity": f.severity.value,
                            "evidence": f.evidence,
                            "recommendation": f.recommendation,
                            "data_source": f.data_source,
                        }
                        for f in c.findings
                    ],
                }
                for c in self.categories
            ],
            "critical_findings": [
                {
                    "article": f.article,
                    "requirement": f.requirement,
                    "status": f.status.value,
                    "severity": f.severity.value,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "data_source": f.data_source,
                }
                for f in self.critical_findings
            ],
            "summary": self.summary,
        }


class ComplianceAuditor:
    """Auditor that maps BGP analysis results to DORA and NIS 2 requirements.

    Receives pre-computed reports from existing analyzers and maps findings
    to specific regulatory articles. Does NOT re-run analysis.
    """

    SEVERITY_WEIGHTS: dict[Severity, int] = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 25,
        Severity.MEDIUM: 15,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }

    # --- Public API ---

    def audit_dora(
        self,
        asn: int,
        resilience_report: ResilienceReport,
        stability_report: StabilityReport | None = None,
        rov_report: ROVCoverageReport | None = None,
        contacts: dict | None = None,
    ) -> ComplianceAuditReport:
        categories = [
            self._check_dora_ict_risk(resilience_report, stability_report, rov_report),
            self._check_dora_third_party(resilience_report),
            self._check_dora_incident_mgmt(stability_report, contacts),
        ]
        return self._build_report(asn, ComplianceFramework.DORA, categories)

    def audit_nis2(
        self,
        asn: int,
        resilience_report: ResilienceReport,
        stability_report: StabilityReport | None = None,
        rov_report: ROVCoverageReport | None = None,
        aspa_results: list[dict] | None = None,
    ) -> ComplianceAuditReport:
        categories = [
            self._check_nis2_risk_mgmt(resilience_report, rov_report, aspa_results),
            self._check_nis2_incident_reporting(stability_report),
        ]
        return self._build_report(asn, ComplianceFramework.NIS2, categories)

    def audit_both(
        self,
        asn: int,
        resilience_report: ResilienceReport,
        stability_report: StabilityReport | None = None,
        rov_report: ROVCoverageReport | None = None,
        aspa_results: list[dict] | None = None,
        contacts: dict | None = None,
    ) -> tuple[ComplianceAuditReport, ComplianceAuditReport]:
        dora = self.audit_dora(asn, resilience_report, stability_report, rov_report, contacts)
        nis2 = self.audit_nis2(asn, resilience_report, stability_report, rov_report, aspa_results)
        return dora, nis2

    def format_report(self, report: ComplianceAuditReport) -> str:
        lines = [
            f"**{report.framework.value} Compliance Audit: AS{report.asn}**",
            f"Timestamp: {report.timestamp}",
            "",
            f"**Overall Score:** {report.overall_score:.0f}/100 — {report.overall_level.value}",
            "",
        ]

        for cat in report.categories:
            lines.append(f"### {cat.category}")
            lines.append(f"Articles: {', '.join(cat.articles)}")
            lines.append(f"Score: {cat.score * 100:.0f}/100 — {cat.level.value}")

            if cat.findings:
                for f in cat.findings:
                    icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": ".", "INFO": "i"}
                    marker = icon.get(f.severity.value, "")
                    lines.append(
                        f"  [{f.severity.value}] {f.article}: {f.requirement} "
                        f"— {f.status.value} {marker}"
                    )
                    if f.evidence:
                        lines.append(f"    Evidence: {f.evidence}")
                    if f.recommendation and f.status != ComplianceLevel.COMPLIANT:
                        lines.append(f"    Recommendation: {f.recommendation}")
            else:
                lines.append("  No findings.")
            lines.append("")

        if report.critical_findings:
            lines.append("### Critical Findings")
            for f in report.critical_findings:
                lines.append(f"  - {f.article}: {f.evidence}")
                lines.append(f"    {f.recommendation}")
            lines.append("")

        lines.append(f"**Summary:** {report.summary}")
        return "\n".join(lines)

    # --- Scoring ---

    def _calculate_category_score(self, findings: list[ComplianceFinding]) -> float:
        deductions = sum(
            self.SEVERITY_WEIGHTS[f.severity]
            for f in findings
            if f.status not in (ComplianceLevel.COMPLIANT, ComplianceLevel.NOT_ASSESSED)
        )
        return max(0.0, (100 - deductions) / 100)

    def _score_to_level(self, score: float) -> ComplianceLevel:
        if score >= 80:
            return ComplianceLevel.COMPLIANT
        if score >= 50:
            return ComplianceLevel.PARTIAL
        return ComplianceLevel.NON_COMPLIANT

    def _build_report(
        self,
        asn: int,
        framework: ComplianceFramework,
        categories: list[ComplianceCategoryReport],
    ) -> ComplianceAuditReport:
        # Overall score: weighted average (equal weights)
        if categories:
            overall_score = sum(c.score for c in categories) / len(categories) * 100
        else:
            overall_score = 100.0

        overall_level = self._score_to_level(overall_score)

        critical_findings = [
            f
            for c in categories
            for f in c.findings
            if f.severity == Severity.CRITICAL
            and f.status == ComplianceLevel.NON_COMPLIANT
        ]

        # Build summary
        total_findings = sum(len(c.findings) for c in categories)
        non_compliant = sum(
            1 for c in categories
            for f in c.findings
            if f.status == ComplianceLevel.NON_COMPLIANT
        )
        summary = (
            f"{framework.value} audit for AS{asn}: "
            f"{overall_score:.0f}/100 ({overall_level.value}). "
            f"{total_findings} checks performed, {non_compliant} non-compliant."
        )

        return ComplianceAuditReport(
            asn=asn,
            framework=framework,
            timestamp=datetime.now(UTC).isoformat(),
            overall_score=overall_score,
            overall_level=overall_level,
            categories=categories,
            critical_findings=critical_findings,
            summary=summary,
        )

    # --- DORA Checks ---

    def _check_dora_ict_risk(
        self,
        resilience: ResilienceReport,
        stability: StabilityReport | None,
        rov: ROVCoverageReport | None,
    ) -> ComplianceCategoryReport:
        findings: list[ComplianceFinding] = []

        # Transit concentration (CRITICAL)
        if resilience.single_transit:
            findings.append(ComplianceFinding(
                article="Art. 6(8)",
                requirement="ICT concentration risk - transit diversity",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.CRITICAL,
                evidence=f"Single transit provider detected ({resilience.upstream_count} upstream)",
                recommendation="Add at least one more transit provider to eliminate single point of failure",
                data_source="resilience",
            ))
        else:
            findings.append(ComplianceFinding(
                article="Art. 6(8)",
                requirement="ICT concentration risk - transit diversity",
                status=ComplianceLevel.COMPLIANT,
                severity=Severity.CRITICAL,
                evidence=f"{resilience.upstream_count} transit providers detected",
                recommendation="",
                data_source="resilience",
            ))

        # Low resilience score (HIGH)
        if resilience.score < 5:
            findings.append(ComplianceFinding(
                article="Art. 5",
                requirement="ICT risk management framework",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence=f"Network resilience score {resilience.score:.1f}/10 (below threshold of 5)",
                recommendation="Improve network diversity: add transit providers, expand peering, join IXPs",
                data_source="resilience",
            ))

        # RPKI/ROV deployment (HIGH)
        if rov is not None:
            if rov.protection_level == "low":
                findings.append(ComplianceFinding(
                    article="Art. 9(2)",
                    requirement="RPKI/ROV deployment for route origin validation",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    evidence=f"Low ROV protection: {rov.path_coverage:.0%} path coverage",
                    recommendation="Deploy RPKI ROAs and encourage upstream providers to enforce ROV",
                    data_source="rov_coverage",
                ))
            elif rov.protection_level == "medium":
                findings.append(ComplianceFinding(
                    article="Art. 9(2)",
                    requirement="RPKI/ROV deployment for route origin validation",
                    status=ComplianceLevel.PARTIAL,
                    severity=Severity.MEDIUM,
                    evidence=f"Medium ROV protection: {rov.path_coverage:.0%} path coverage",
                    recommendation="Increase ROV coverage by working with transit providers",
                    data_source="rov_coverage",
                ))
        else:
            findings.append(ComplianceFinding(
                article="Art. 9(2)",
                requirement="RPKI/ROV deployment for route origin validation",
                status=ComplianceLevel.NOT_ASSESSED,
                severity=Severity.HIGH,
                evidence="ROV coverage data not available",
                recommendation="Run ROV coverage analysis to assess RPKI deployment",
                data_source="rov_coverage",
            ))

        # Route instability (MEDIUM)
        if stability is not None:
            if stability.is_flapping:
                findings.append(ComplianceFinding(
                    article="Art. 10",
                    requirement="ICT system stability monitoring",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    evidence=f"Route flapping detected: {stability.updates_per_day:.0f} updates/day, {stability.flap_count} flaps",
                    recommendation="Investigate route instability and implement route dampening",
                    data_source="stability",
                ))

        # Low path redundancy (MEDIUM)
        if resilience.path_redundancy_score < 0.5:
            findings.append(ComplianceFinding(
                article="Art. 11(1)",
                requirement="ICT path redundancy",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.MEDIUM,
                evidence=f"Path redundancy score {resilience.path_redundancy_score:.0%} (below 50%)",
                recommendation="Ensure multiple upstream paths are advertised for redundancy",
                data_source="resilience",
            ))

        score = self._calculate_category_score(findings)
        return ComplianceCategoryReport(
            category="ICT Risk Management",
            articles=["Art. 5-16"],
            findings=findings,
            score=score,
            level=self._score_to_level(score * 100),
        )

    def _check_dora_third_party(
        self,
        resilience: ResilienceReport,
    ) -> ComplianceCategoryReport:
        findings: list[ComplianceFinding] = []

        # Provider concentration (CRITICAL)
        if resilience.upstream_count < 2:
            findings.append(ComplianceFinding(
                article="Art. 28(1)",
                requirement="ICT third-party provider concentration risk",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.CRITICAL,
                evidence=f"Only {resilience.upstream_count} upstream provider(s) — critical concentration risk",
                recommendation="Diversify transit providers to reduce third-party concentration",
                data_source="resilience",
            ))

        # Geographic concentration / IXP presence (HIGH)
        if resilience.ixp_count < 2:
            findings.append(ComplianceFinding(
                article="Art. 28(5)",
                requirement="Geographic diversification of ICT services",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence=f"Only {resilience.ixp_count} IXP(s) — limited geographic diversity",
                recommendation="Join additional IXPs in different locations for geographic diversity",
                data_source="resilience",
            ))

        # DDoS provider dependency (MEDIUM info)
        if resilience.ddos_provider_detected:
            findings.append(ComplianceFinding(
                article="Art. 29(2)",
                requirement="DDoS mitigation provider dependency",
                status=ComplianceLevel.PARTIAL,
                severity=Severity.MEDIUM,
                evidence=f"DDoS provider detected in upstream path: {resilience.ddos_provider_detected}",
                recommendation="Ensure direct paths are available as backup to DDoS mitigation provider",
                data_source="resilience",
            ))

        # Limited peering (MEDIUM)
        if resilience.peer_count < 20:
            findings.append(ComplianceFinding(
                article="Art. 30(2)",
                requirement="Peering relationship breadth",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.MEDIUM,
                evidence=f"Only {resilience.peer_count} peers — limited DDoS absorption capacity",
                recommendation="Expand peering relationships for improved resilience and traffic optimization",
                data_source="resilience",
            ))

        score = self._calculate_category_score(findings)
        return ComplianceCategoryReport(
            category="ICT Third-Party Risk",
            articles=["Art. 28-30"],
            findings=findings,
            score=score,
            level=self._score_to_level(score * 100),
        )

    def _check_dora_incident_mgmt(
        self,
        stability: StabilityReport | None,
        contacts: dict | None,
    ) -> ComplianceCategoryReport:
        findings: list[ComplianceFinding] = []

        # No stability monitoring (HIGH)
        if stability is None:
            findings.append(ComplianceFinding(
                article="Art. 17",
                requirement="ICT incident detection capability",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence="No stability monitoring data available — cannot detect routing incidents",
                recommendation="Implement BGP monitoring to detect routing anomalies and incidents",
                data_source="stability",
            ))
        else:
            # High incident rate (MEDIUM)
            if stability.updates_per_day > 100:
                findings.append(ComplianceFinding(
                    article="Art. 19(1)",
                    requirement="ICT incident rate monitoring",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    evidence=f"High routing update rate: {stability.updates_per_day:.0f} updates/day",
                    recommendation="Investigate high update frequency and establish baseline thresholds",
                    data_source="stability",
                ))

        # No abuse contact (MEDIUM)
        if contacts is not None and not contacts:
            findings.append(ComplianceFinding(
                article="Art. 20(1)",
                requirement="Incident reporting contacts",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.MEDIUM,
                evidence="No abuse contact information found",
                recommendation="Register abuse contact in WHOIS/RIR database",
                data_source="contacts",
            ))

        score = self._calculate_category_score(findings)
        return ComplianceCategoryReport(
            category="ICT Incident Management",
            articles=["Art. 17-23"],
            findings=findings,
            score=score,
            level=self._score_to_level(score * 100),
        )

    # --- NIS 2 Checks ---

    def _check_nis2_risk_mgmt(
        self,
        resilience: ResilienceReport,
        rov: ROVCoverageReport | None,
        aspa_results: list[dict] | None,
    ) -> ComplianceCategoryReport:
        findings: list[ComplianceFinding] = []

        # Network resilience (HIGH)
        if resilience.score < 5:
            findings.append(ComplianceFinding(
                article="Art. 21(2)(a)",
                requirement="Risk analysis and information system security",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence=f"Network resilience score {resilience.score:.1f}/10 (below threshold of 5)",
                recommendation="Improve network diversity and redundancy",
                data_source="resilience",
            ))

        # Business continuity (HIGH)
        if resilience.upstream_count < 2 or resilience.ixp_count < 2:
            issues = []
            if resilience.upstream_count < 2:
                issues.append(f"{resilience.upstream_count} upstream(s)")
            if resilience.ixp_count < 2:
                issues.append(f"{resilience.ixp_count} IXP(s)")
            findings.append(ComplianceFinding(
                article="Art. 21(2)(c)",
                requirement="Business continuity and crisis management",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence=f"Insufficient redundancy: {', '.join(issues)}",
                recommendation="Add transit providers and join additional IXPs for business continuity",
                data_source="resilience",
            ))

        # Supply chain RPKI (HIGH)
        if rov is not None:
            if rov.protection_level == "low":
                findings.append(ComplianceFinding(
                    article="Art. 21(2)(d)",
                    requirement="Supply chain security — RPKI/ROV coverage",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    evidence=f"Low ROV coverage: {rov.path_coverage:.0%} of paths protected",
                    recommendation="Deploy RPKI ROAs and work with providers to enforce ROV filtering",
                    data_source="rov_coverage",
                ))
        else:
            findings.append(ComplianceFinding(
                article="Art. 21(2)(d)",
                requirement="Supply chain security — RPKI/ROV coverage",
                status=ComplianceLevel.NOT_ASSESSED,
                severity=Severity.HIGH,
                evidence="ROV coverage data not available",
                recommendation="Run ROV coverage analysis to assess supply chain routing security",
                data_source="rov_coverage",
            ))

        # Route leak vulnerability via ASPA (MEDIUM)
        if aspa_results is not None:
            invalid_paths = [r for r in aspa_results if r.get("valid") is False]
            if invalid_paths:
                findings.append(ComplianceFinding(
                    article="Art. 21(2)(d)",
                    requirement="Route leak vulnerability (ASPA validation)",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    evidence=f"{len(invalid_paths)} invalid AS paths detected via ASPA validation",
                    recommendation="Investigate and remediate invalid routing paths",
                    data_source="aspa",
                ))

        # Routing security — RPKI (HIGH)
        if rov is not None and rov.protection_level == "low":
            findings.append(ComplianceFinding(
                article="Art. 21(2)(e)",
                requirement="Routing security — network and information systems",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence=f"RPKI not effectively deployed: {rov.path_coverage:.0%} coverage",
                recommendation="Implement RPKI for all announced prefixes",
                data_source="rov_coverage",
            ))

        score = self._calculate_category_score(findings)
        return ComplianceCategoryReport(
            category="Risk Management Measures",
            articles=["Art. 21"],
            findings=findings,
            score=score,
            level=self._score_to_level(score * 100),
        )

    def _check_nis2_incident_reporting(
        self,
        stability: StabilityReport | None,
    ) -> ComplianceCategoryReport:
        findings: list[ComplianceFinding] = []

        # Incident detection capability (HIGH)
        if stability is None:
            findings.append(ComplianceFinding(
                article="Art. 23(1)",
                requirement="Incident detection capability",
                status=ComplianceLevel.NON_COMPLIANT,
                severity=Severity.HIGH,
                evidence="No stability monitoring data — cannot detect and report incidents",
                recommendation="Implement BGP monitoring for incident detection and reporting",
                data_source="stability",
            ))
        else:
            # Baseline monitoring (MEDIUM)
            if not stability.is_stable:
                findings.append(ComplianceFinding(
                    article="Art. 23(4)",
                    requirement="Baseline monitoring for incident reporting",
                    status=ComplianceLevel.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    evidence=f"Route instability detected: {stability.updates_per_day:.0f} updates/day",
                    recommendation="Establish baseline monitoring thresholds and investigate instability",
                    data_source="stability",
                ))

        score = self._calculate_category_score(findings)
        return ComplianceCategoryReport(
            category="Incident Reporting Capability",
            articles=["Art. 23"],
            findings=findings,
            score=score,
            level=self._score_to_level(score * 100),
        )
