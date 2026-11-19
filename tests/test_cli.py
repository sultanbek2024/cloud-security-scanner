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
