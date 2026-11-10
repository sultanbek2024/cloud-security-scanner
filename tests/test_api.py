"""
FastAPI REST API эндпоинттерін тестілеу модулі.
"""
from fastapi.testclient import TestClient
import pytest
from api.main import app

client = TestClient(app)

SAMPLE_IAC = """
resource "aws_security_group" "api_test_sg" {
  name        = "api-test-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_rules_endpoint():
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) >= 15
    rule_ids = [r["rule_id"] for r in rules]
    assert "EC2-001" in rule_ids
    assert "S3-001" in rule_ids


def test_dashboard_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "CloudSec Auditor" in response.text


def test_run_scan_with_iac_content():
    response = client.post(
        "/api/v1/scan",
        json={
            "provider": "aws",
            "region": "us-east-1",
            "iac_content": SAMPLE_IAC,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert "findings" in data
    assert len(data["findings"]) >= 1

    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "IAC-EC2-001" in rule_ids
