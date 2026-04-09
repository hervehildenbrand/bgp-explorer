"""Tests for MANRS data models."""

import json

from bgp_explorer.models.manrs import (
    MANRSAction,
    MANRSActionFinding,
    MANRSConformance,
    MANRSReadiness,
    MANRSReadinessReport,
)


class TestMANRSEnums:
    def test_manrs_action_values(self):
        assert MANRSAction.FILTERING.value == "filtering"
        assert MANRSAction.ANTI_SPOOFING.value == "anti_spoofing"
        assert MANRSAction.COORDINATION.value == "coordination"
        assert MANRSAction.VALIDATION.value == "validation"

    def test_manrs_readiness_values(self):
        assert MANRSReadiness.READY.value == "ready"
        assert MANRSReadiness.ASPIRING.value == "aspiring"
        assert MANRSReadiness.LAGGING.value == "lagging"
        assert MANRSReadiness.UNKNOWN.value == "unknown"


class TestMANRSConformance:
    def test_creation(self):
        c = MANRSConformance(
            asn=13335,
            name="Cloudflare",
            country="US",
            status="ready",
            action1_filtering=MANRSReadiness.READY,
            action2_anti_spoofing=MANRSReadiness.READY,
            action3_coordination=MANRSReadiness.READY,
            action4_validation=MANRSReadiness.READY,
            last_updated="2026-04-01",
            manrs_participant=True,
        )
        assert c.asn == 13335
        assert c.manrs_participant is True
        assert c.action1_filtering == MANRSReadiness.READY

    def test_non_participant(self):
        c = MANRSConformance(
            asn=64496,
            name="Example Net",
            country="XX",
            status="unknown",
            action1_filtering=MANRSReadiness.UNKNOWN,
            action2_anti_spoofing=MANRSReadiness.UNKNOWN,
            action3_coordination=MANRSReadiness.UNKNOWN,
            action4_validation=MANRSReadiness.UNKNOWN,
            last_updated="",
            manrs_participant=False,
        )
        assert c.manrs_participant is False


class TestMANRSActionFinding:
    def test_creation(self):
        f = MANRSActionFinding(
            action=MANRSAction.VALIDATION,
            readiness=MANRSReadiness.READY,
            evidence=["ROA coverage: 95%", "ASPA published"],
            measurable=True,
            recommendations=[],
            data_sources_used=["rpki_console", "ripe_stat"],
        )
        assert f.action == MANRSAction.VALIDATION
        assert f.measurable is True
        assert len(f.evidence) == 2

    def test_unmeasurable_action(self):
        f = MANRSActionFinding(
            action=MANRSAction.ANTI_SPOOFING,
            readiness=MANRSReadiness.UNKNOWN,
            evidence=[],
            measurable=False,
            recommendations=["Self-verify BCP38/uRPF implementation"],
            data_sources_used=[],
        )
        assert f.measurable is False
        assert f.readiness == MANRSReadiness.UNKNOWN


class TestMANRSReadinessReport:
    def test_creation(self):
        finding = MANRSActionFinding(
            action=MANRSAction.FILTERING,
            readiness=MANRSReadiness.ASPIRING,
            evidence=["ROV coverage: 75%"],
            measurable=True,
            recommendations=["Improve ROA deployment"],
            data_sources_used=["rov_coverage"],
        )
        report = MANRSReadinessReport(
            asn=64496,
            timestamp="2026-04-08T00:00:00Z",
            overall_readiness=MANRSReadiness.ASPIRING,
            overall_score=65.0,
            action_findings=[finding],
            summary="MANRS readiness: ASPIRING",
            limitations=["Anti-spoofing cannot be verified externally"],
        )
        assert report.asn == 64496
        assert report.overall_score == 65.0

    def test_to_dict(self):
        finding = MANRSActionFinding(
            action=MANRSAction.VALIDATION,
            readiness=MANRSReadiness.READY,
            evidence=["ROA coverage: 95%"],
            measurable=True,
            recommendations=[],
            data_sources_used=["rpki_console"],
        )
        report = MANRSReadinessReport(
            asn=13335,
            timestamp="2026-04-08T00:00:00Z",
            overall_readiness=MANRSReadiness.READY,
            overall_score=90.0,
            action_findings=[finding],
            summary="MANRS readiness: READY",
            limitations=[],
        )
        d = report.to_dict()
        assert d["asn"] == 13335
        assert d["overall_readiness"] == "ready"
        assert d["overall_score"] == 90.0
        assert d["action_findings"][0]["action"] == "validation"
        assert d["action_findings"][0]["measurable"] is True
        json_str = json.dumps(d)
        assert "ready" in json_str

    def test_to_dict_with_limitations(self):
        report = MANRSReadinessReport(
            asn=64496,
            timestamp="2026-04-08T00:00:00Z",
            overall_readiness=MANRSReadiness.ASPIRING,
            overall_score=55.0,
            action_findings=[],
            summary="MANRS readiness: ASPIRING",
            limitations=["Anti-spoofing not measurable", "Filtering is proxy only"],
        )
        d = report.to_dict()
        assert len(d["limitations"]) == 2
        json.dumps(d)
