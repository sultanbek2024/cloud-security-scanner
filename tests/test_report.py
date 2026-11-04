"""
Есептерді жасауды (HTML және JSON) тексеруге арналған тесттер.
"""
import json
import os
import tempfile
from core.models import Finding, Severity
from report.html_report import generate_html_report
from report.json_report import generate_json_report


def sample_findings():
    return [
        Finding(
            rule_id="EC2-001",
            title="SSH (22-порт) бүкіл интернетке ашық",
            resource="sg-12345678 (web-sg)",
            severity=Severity.HIGH,
            description="22-портқа 0.0.0.0/0 мекенжайынан кіруге рұқсат берілген.",
            recommendation="Қолжетімділікті нақты IP мекенжайлармен шектеңіз.",
            standard="CIS AWS Foundations Benchmark 5.2",
        ),
        Finding(
            rule_id="IAM-001",
            title="Консольге кіру рұқсаты бар пайдаланушыда MFA қосылмаған",
            resource="arn:aws:iam::123456789012:user/admin",
            severity=Severity.MEDIUM,
            description="Пайдаланушыда құпиясөз бар, бірақ MFA жоқ.",
            recommendation="MFA құрылғысын қосыңыз.",
            standard="CIS AWS Foundations Benchmark 1.10",
        ),
    ]


def test_generate_json_report():
    findings = sample_findings()
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = os.path.join(tmp_dir, "test_report.json")
        generate_json_report(
            findings=findings,
            score=89,
            grade="B",
            output_path=out_path,
            provider="aws",
            region="us-east-1",
        )

        assert os.path.exists(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["summary"]["score"] == 89
        assert data["summary"]["grade"] == "B"
        assert len(data["findings"]) == 2
        assert data["findings"][0]["rule_id"] == "EC2-001"
        assert data["findings"][0]["severity_display"] == "Жоғары"


def test_generate_html_report():
    findings = sample_findings()
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = os.path.join(tmp_dir, "test_report.html")
        generate_html_report(
            findings=findings,
            score=89,
            grade="B",
            output_path=out_path,
            provider="aws",
            region="us-east-1",
        )

        assert os.path.exists(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert '<html lang="kk">' in content
        assert "EC2-001" in content
        assert "SSH (22-порт) бүкіл интернетке ашық" in content
        assert "Қауіпсіздік деңгейі" in content
