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


def test_exact_sg_name_match_avoids_substring_false_positive():
    """
    4-жағдай: 'web' атауы бар SG 'web-legacy-admin' сияқты басқа топпен шатаспауы тиіс.
    Егер кодта 'web' қауіпсіз болса, ал бұлтта 'web-legacy-admin' тұрса,
    ол оған қате Drift байламай, кодта жоқ Shadow ресурс деп тануы керек.
    """
    iac = [
        TerraformResource(
            resource_type="aws_security_group",
            resource_name="web",
            config={
                "name": "web",
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
            resource="sg-55555555 (web-legacy-admin) [us-east-1]",
            severity=Severity.HIGH,
            description="22-порт ашық.",
            recommendation="Жабыңыз.",
            standard="CIS AWS Foundations Benchmark 5.2",
        )
    ]

    updated = correlate_and_detect_drift(live_findings, iac)
    assert len(updated) == 1
    # Бұл 'web' емес, бөлек 'web-legacy-admin', сондықтан Shadow деп танылуы керек
    assert updated[0].is_drift is True
    assert "Shadow / Unmanaged" in updated[0].description


def test_shadow_rds_drift_detected():
    """
    5-жағдай: Бұлтта ашық RDS инстансы бар, бірақ Terraform кодында мүлдем жазылмаған.
    Ол Shadow Database ретінде Drift деп белгіленуі тиіс.
    """
    empty_iac = []
    live_findings = [
        Finding(
            rule_id="RDS-001",
            title="RDS инстансы бүкіл интернетке ашық",
            resource="mydb-prod.c1234567890.us-east-1.rds.amazonaws.com",
            severity=Severity.CRITICAL,
            description="RDS инстансы PubliclyAccessible=True болып тұр.",
            recommendation="Қоғамдық қолжетімділікті өшіріңіз.",
            standard="CIS AWS Foundations Benchmark 2.3.1",
        )
    ]

    updated = correlate_and_detect_drift(live_findings, [
        TerraformResource(
            resource_type="aws_s3_bucket",
            resource_name="some_bucket",
            config={"bucket": "some-bucket"}
        )
    ])
    assert len(updated) == 1
    assert updated[0].is_drift is True
    assert "Shadow Database" in updated[0].description


def test_terraform_demo_three_clickops_drift_events():
    """
    6-жағдай: terraform_demo макетіндегі 3 қауіпсіз жазылған ресурс (SG, S3, RDS)
    бұлтта қолмен өзгертілгенде (ClickOps) нақты 3 ClickOps Drift анықталуы тиіс.
    """
    from iac.scanner import get_declared_resources
    import os

    demo_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "terraform_demo")
    iac_res = get_declared_resources(demo_dir)

    live_findings = [
        Finding(
            rule_id="EC2-001",
            title="SSH (22-порт) бүкіл интернетке ашық",
            resource="sg-12345678 (vulnerable-ssh-sg) [us-east-1]",
            severity=Severity.HIGH,
            description="22-порт ашық.",
            recommendation="Жабыңыз.",
            standard="CIS AWS Foundations Benchmark 5.2",
        ),
        Finding(
            rule_id="S3-001",
            title="S3 бакетінде жария қолжетімділікті бұғаттау толық қосылмаған",
            resource="arn:aws:s3:::vulnerable-public-bucket",
            severity=Severity.HIGH,
            description="PAB өшірілген.",
            recommendation="Қосыңыз.",
            standard="CIS AWS Foundations Benchmark 2.1.4",
        ),
        Finding(
            rule_id="RDS-001",
            title="Жалпыға ашық RDS инстансы",
            resource="arn:aws:rds:us-east-1:123456789012:db:vulnerable-public-db",
            severity=Severity.CRITICAL,
            description="PubliclyAccessible=True.",
            recommendation="Жабыңыз.",
            standard="CIS AWS Foundations Benchmark 2.3.2",
        ),
        Finding(
            rule_id="EC2-004",
            title="Security Group барлық трафикке ашық",
            resource="sg-99999999 (vulnerable-allports-sg) [us-east-1]",
            severity=Severity.HIGH,
            description="Барлық порттар ашық.",
            recommendation="Жабыңыз.",
            standard="CIS AWS Foundations Benchmark 5.4",
        ),
    ]

    correlated = correlate_and_detect_drift(live_findings, iac_res)

    # 3 ClickOps drift + 1 Shadow Resource
    clickops_findings = [f for f in correlated if "ClickOps" in f.description]
    shadow_findings = [f for f in correlated if "Shadow" in f.description]

    assert len(clickops_findings) == 3
    assert len(shadow_findings) == 1
    assert all(f.is_drift for f in correlated)


