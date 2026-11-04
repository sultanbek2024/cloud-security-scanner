"""
Қауіпсіздік ұпайларын және рейтингті есептеуді тексеруге арналған тесттер (Scoring unit tests).
"""
import pytest
from core.models import Finding, Severity
from core.scoring import calculate_score, group_findings_by_severity


def make_dummy_finding(rule_id: str, severity: Severity, resource: str = "test-res") -> Finding:
    """Тестілеу үшін үлгі ретінде Finding объектісін жасау."""
    return Finding(
        rule_id=rule_id,
        title="Тесттік тақырып",
        resource=resource,
        severity=severity,
        description="Тесттік сипаттама",
        recommendation="Тесттік ұсыныс",
        standard="CIS AWS Benchmark",
    )


def test_calculate_score_clean():
    """Ешқандай осалдық табылмаған жағдайда ең жоғары балл (100, 'A') қайтарылуы керек."""
    score, grade = calculate_score([], total_checks=15)
    assert score == 100
    assert grade == "A"


def test_calculate_score_single_high():
    """
    15 тексеру кезінде 1 HIGH осалдық (салмағы 7):
    Сыйымдылық = 84.
    7 / 84 * 100 = 8.33% айыппұл.
    Қорытынды балл: 100 - 8 = 92 ('A' рейтингі).
    """
    findings = [make_dummy_finding("EC2-001", Severity.HIGH)]
    score, grade = calculate_score(findings, total_checks=15)
    assert score == 92
    assert grade == "A"


def test_calculate_score_single_critical():
    """
    1 CRITICAL осалдық (салмағы 10):
    10 / 84 * 100 = 11.9% -> 12 балл шегеріледі.
    Қорытынды балл: 100 - 12 = 88 ('B' рейтингі).
    """
    findings = [make_dummy_finding("IAM-002", Severity.CRITICAL)]
    score, grade = calculate_score(findings, total_checks=15)
    assert score == 88
    assert grade == "B"


def test_calculate_score_diminishing_penalty():
    """
    Бірдей ереже бойынша 5 ресурс табылғанда шекті кему заңы (diminishing return)
    арқасында айыппұл сызықтық 20 емес, 8.0 салмақпен есептелуі тиіс.
    """
    findings = [
        make_dummy_finding("EC2-002", Severity.MEDIUM, resource=f"vol-{i}")
        for i in range(5)
    ]
    # 4 * (1 + 0.25 * 4) = 8.0 айыппұл салмағы
    # 8.0 / 84 * 100 = 9.52% -> 10 балл шегеріледі
    score, grade = calculate_score(findings, total_checks=15)
    assert score == 90
    assert grade == "A"


def test_calculate_score_floor_zero():
    """Аса көп сыни қауіптер болғанда балл 0-ден төмен түспеуі және 'F' болуы керек."""
    findings = [
        make_dummy_finding(f"CRIT-{i}", Severity.CRITICAL)
        for i in range(12)
    ]
    # 12 * 10 = 120 -> 142% -> 0
    score, grade = calculate_score(findings, total_checks=15)
    assert score == 0
    assert grade == "F"


def test_group_findings_by_severity():
    """Осалдықтарды қауіптілік деңгейлері бойынша топтастыруды тексеру."""
    findings = [
        make_dummy_finding("EC2-001", Severity.HIGH),
        make_dummy_finding("IAM-001", Severity.MEDIUM),
        make_dummy_finding("EC2-002", Severity.MEDIUM),
        make_dummy_finding("LOW-001", Severity.LOW),
        make_dummy_finding("RDS-001", Severity.CRITICAL),
    ]
    grouped = group_findings_by_severity(findings)

    assert len(grouped[Severity.CRITICAL]) == 1
    assert len(grouped[Severity.HIGH]) == 1
    assert len(grouped[Severity.MEDIUM]) == 2
    assert len(grouped[Severity.LOW]) == 1
