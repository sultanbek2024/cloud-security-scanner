"""
Drift Detection (Конфигурациялық ауытқуды анықтау) тестілеу модулі.
"""
import pytest
from core.models import Finding, Severity
from core.drift import correlate_and_detect_drift
from iac.parser import TerraformResource


def test_drift_detected_when_code_is_safe_but_cloud_is_vulnerable():
    """
    1-жағдай: Terraform кодында SG қауіпсіз жазылған (тек 443 порт),
    бірақ AWS бұлтында біреу консоль арқылы 22-портты (SSH) ашып жіберген.
    Бұл 100% Drift болуы тиіс!
    """
    safe_iac = [
        TerraformResource(
            resource_type="aws_security_group",
            resource_name="web_prod_sg",
            config={
                "name": "web-prod-sg",
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ],
            },
        )
    ]

    live_findings = [
        Finding(
            rule_id="EC2-001",
            title="SSH (22-порт) бүкіл интернетке ашық",
            resource="sg-99999999 (web-prod-sg) [us-east-1]",
            severity=Severity.HIGH,
            description="22-портқа 0.0.0.0/0 кіруге рұқсат берілген.",
            recommendation="Портты жабыңыз.",
            standard="CIS AWS Foundations Benchmark 5.2",
        )
    ]

    updated = correlate_and_detect_drift(live_findings, safe_iac)

    assert len(updated) == 1
    assert updated[0].is_drift is True
    assert "[DRIFT]" in updated[0].title
    assert "ClickOps" in updated[0].description


def test_shadow_resource_drift_detected():
    """
    2-жағдай: S3 бакеті AWS бұлтында бар және ашық тұр,
    бірақ ол Terraform кодында МҮЛДЕМ жарияланбаған (бақылаусыз / shadow ресурс).
    Бұл да Drift болуы тиіс!
    """
    empty_iac = []  # Кодта ешқандай бакет жазылмаған

    live_findings = [
        Finding(
            rule_id="S3-001",
            title="S3 бакетінде жария қолжетімділікті бұғаттау қосылмаған",
            resource="arn:aws:s3:::shadow-unmanaged-bucket",
            severity=Severity.HIGH,
            description="Public Access Block жоқ.",
            recommendation="Блокты қосыңыз.",
            standard="CIS AWS Foundations Benchmark 2.1.5",
        )
    ]

    # empty_iac емес, басқа ресурстар бар iac берейік
    iac_with_other = [
        TerraformResource(
            resource_type="aws_s3_bucket",
            resource_name="official_bucket",
            config={"bucket": "official-company-bucket"},
        )
    ]

    updated = correlate_and_detect_drift(live_findings, iac_with_other)

    assert len(updated) == 1
    assert updated[0].is_drift is True
    assert "[DRIFT]" in updated[0].title
    assert "Unmanaged" in updated[0].description


def test_no_drift_when_vulnerability_originated_in_iac_code():
    """
    3-жағдай: Егер қателік басынан бастап Terraform кодында ашық жазылған болса
    (мысалы, инженер кодта 22-портты 0.0.0.0/0 деп өзі жазған),
    бұл 'Drift' (қолмен енгізілген ауытқу) емес, ол бастапқы кодтағы қателік.
    """
    vulnerable_iac = [
        TerraformResource(
            resource_type="aws_security_group",
            resource_name="dev_sg",
            config={
                "name": "dev-sg",
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ],
            },
        )
    ]

    live_findings = [
        Finding(
            rule_id="EC2-001",
            title="SSH (22-порт) бүкіл интернетке ашық",
            resource="sg-11111111 (dev-sg) [us-east-1]",
            severity=Severity.HIGH,
            description="22-портқа рұқсат берілген.",
            recommendation="Портты жабыңыз.",
            standard="CIS AWS Foundations Benchmark 5.2",
        )
    ]

    updated = correlate_and_detect_drift(live_findings, vulnerable_iac)

    assert len(updated) == 1
    # Кодта өзі жазылғандықтан, is_drift False болып қалуы керек
    assert updated[0].is_drift is False
    assert not updated[0].title.startswith("[DRIFT]")
