"""
CLI интерфейсін (scanner.py) тестілеу.
"""
import pytest
from scanner import build_parser


def test_cli_parser_defaults():
    """Әдепкі аргументтердің дұрыс талдануын тексереді."""
    parser = build_parser()
    args = parser.parse_args([])

    assert args.provider == "aws"
    assert args.region == "us-east-1"
    assert args.all_regions is False
    assert args.web is False
    assert args.port == 8000


def test_cli_parser_custom_args():
    """Арнайы аргументтердің (endpoint-url, iac, json-output) талдануын тексереді."""
    parser = build_parser()
    args = parser.parse_args([
        "--region", "eu-central-1",
        "--all-regions",
        "--endpoint-url", "http://localhost:4566",
        "--output", "custom_report.html",
        "--json-output", "custom_report.json",
        "--iac", "./terraform_demo",
    ])

    assert args.region == "eu-central-1"
    assert args.all_regions is True
    assert args.endpoint_url == "http://localhost:4566"
    assert args.output == "custom_report.html"
    assert args.json_output == "custom_report.json"
    assert args.iac == "./terraform_demo"


def test_create_boto3_session_with_endpoint():
    """Endpoint-url көрсетілген кезде boto3 сессиясының клиенттері дұрыс бапталуын тексереді."""
    from scanner import create_boto3_session

    session = create_boto3_session(
        profile=None,
        region="us-east-1",
        endpoint_url="http://localhost:4566",
        all_regions=False,
    )
    assert session is not None
    client = session.client("s3")
    assert client.meta.endpoint_url == "http://localhost:4566"


def test_print_summary(capsys):
    """Консольге басып шығару көмекші функциясын тексереді."""
    from scanner import print_summary
    from core.models import Finding, Severity

    f = Finding(
        rule_id="EC2-001",
        title="Тест ашық SSH",
        resource="sg-test",
        severity=Severity.HIGH,
        description="Сынақ сипаттамасы",
        recommendation="Сынақ түзетуі",
        standard="CIS AWS 5.2",
    )
    print_summary(
        findings=[f],
        score=85,
        grade="B",
        total_checks=15,
        output_path="report.html",
        provider="aws",
        region="us-east-1",
    )
    captured = capsys.readouterr()
    assert "85 / 100" in captured.out
    assert "B" in captured.out
    assert "15" in captured.out


def test_scanner_main_execution_mocked(tmp_path, monkeypatch):
    """scanner.py main() функциясын мок-сессиямен толық орындалуын тексереді."""
    import scanner
    from moto import mock_aws

    with mock_aws():
        out_html = tmp_path / "test_report.html"
        out_json = tmp_path / "test_report.json"

        test_args = [
            "scanner.py",
            "--region", "us-east-1",
            "--output", str(out_html),
            "--json-output", str(out_json),
        ]
        monkeypatch.setattr("sys.argv", test_args)

        ret = scanner.main()
        # Security scanner returns 0 (clean) or 1 (findings detected)
        assert ret in (0, 1)
        assert out_html.exists()
        assert out_json.exists()


def test_scanner_main_with_min_severity_filter(tmp_path, monkeypatch):
    """--min-severity сүзгісімен scanner.py main() орындалуын тексереді."""
    import scanner
    from moto import mock_aws

    with mock_aws():
        out_html = tmp_path / "high_only.html"
        test_args = [
            "scanner.py",
            "--region", "us-east-1",
            "--min-severity", "CRITICAL",
            "--output", str(out_html),
        ]
        monkeypatch.setattr("sys.argv", test_args)

        ret = scanner.main()
        assert ret in (0, 1)
        assert out_html.exists()

