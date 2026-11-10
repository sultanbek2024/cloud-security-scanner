"""
IaC (Terraform) сканерін тестілеу модулі.
"""
import os
import tempfile
import pytest
from core.models import Severity
from iac.parser import parse_terraform_file, parse_terraform_dir
from iac.scanner import scan_terraform, get_declared_resources


VULNERABLE_TF = """
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Open SSH SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["::/0"]
  }
}

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "company-secret-files"
  acl    = "public-read"
}

resource "aws_ebs_volume" "vulnerable_ebs" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_db_instance" "vulnerable_db" {
  allocated_storage   = 20
  engine              = "postgres"
  publicly_accessible = true
}
"""

SAFE_TF = """
resource "aws_security_group" "safe_sg" {
  name        = "safe-sg"
  description = "Closed SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "safe_bucket" {
  bucket = "safe-encrypted-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "safe_pab" {
  bucket                  = aws_s3_bucket.safe_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "safe_ebs" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

resource "aws_db_instance" "safe_db" {
  allocated_storage   = 20
  engine              = "postgres"
  publicly_accessible = false
}
"""


def test_parse_terraform_file():
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False, encoding="utf-8") as f:
        f.write(VULNERABLE_TF)
        f_path = f.name

    try:
        resources = parse_terraform_file(f_path)
        assert len(resources) == 4
        res_types = [r.resource_type for r in resources]
        assert "aws_security_group" in res_types
        assert "aws_s3_bucket" in res_types
        assert "aws_ebs_volume" in res_types
        assert "aws_db_instance" in res_types
    finally:
        os.remove(f_path)


def test_scan_vulnerable_terraform():
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False, encoding="utf-8") as f:
        f.write(VULNERABLE_TF)
        f_path = f.name

    try:
        findings = scan_terraform(f_path)
        assert len(findings) >= 5

        rule_ids = [find.rule_id for find in findings]
        assert "IAC-EC2-001" in rule_ids  # Open SSH
        assert "IAC-EC2-002" in rule_ids  # Open RDP
        assert "IAC-S3-001" in rule_ids   # Public ACL S3
        assert "IAC-EBS-001" in rule_ids  # Unencrypted EBS
        assert "IAC-RDS-001" in rule_ids  # Public RDS

        for item in findings:
            assert item.remediation_terraform != ""
    finally:
        os.remove(f_path)


def test_scan_safe_terraform():
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False, encoding="utf-8") as f:
        f.write(SAFE_TF)
        f_path = f.name

    try:
        findings = scan_terraform(f_path)
        # Қауіпсіз файлда ешқандай қателік табылмауы керек
        assert len(findings) == 0
    finally:
        os.remove(f_path)
