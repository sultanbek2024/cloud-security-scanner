"""
S3, IAM, RDS және CloudTrail тексерулерін moto кітапханасымен тестілеу.
"""
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch
import boto3
import pytest
from moto import mock_aws

from checks.cloudtrail import check_ct_001_active_cloudtrail, check_ct_002_log_validation
from checks.iam import (
    check_iam_001_console_mfa,
    check_iam_002_root_mfa,
    check_iam_003_old_access_keys,
    check_iam_004_admin_privileges_policy,
    check_iam_005_password_policy,
)
from checks.rds import check_rds_001_public_instance
from checks.s3 import (
    check_s3_001_public_access_block,
    check_s3_002_default_encryption,
    check_s3_003_bucket_versioning,
)
from core.models import Severity


@pytest.fixture
def aws_session():
    return boto3.Session(
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


# --- S3 Тексерулері ---

@mock_aws
def test_s3_001_missing_public_access_block(aws_session):
    """S3 бакетінде Public Access Block жоқ болғанда S3-001 анықталуы тиіс."""
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="vulnerable-bucket")

    findings = check_s3_001_public_access_block(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-001"
    assert findings[0].severity == Severity.HIGH
    assert "vulnerable-bucket" in findings[0].resource


@mock_aws
def test_s3_002_default_encryption_missing(aws_session):
    """S3 бакетінде әдепкі шифрлау жоқ болғанда S3-002 анықталуы тиіс."""
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="unencrypted-bkt")

    findings = check_s3_002_default_encryption(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-002"
    assert findings[0].severity == Severity.MEDIUM
    assert "unencrypted-bkt" in findings[0].resource


@mock_aws
def test_s3_003_bucket_versioning_missing(aws_session):
    """S3 бакетінде нұсқалылық (Versioning) өшірулі болғанда S3-003 анықталуы тиіс."""
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="no-versioning-bkt")

    findings = check_s3_003_bucket_versioning(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "S3-003"
    assert findings[0].severity == Severity.LOW
    assert "no-versioning-bkt" in findings[0].resource


# --- IAM Тексерулері ---

@mock_aws
def test_iam_001_user_console_without_mfa(aws_session):
    """Консольге құпиясөзі бар, бірақ MFA жоқ пайдаланушыны IAM-001 анықтауы тиіс."""
    iam = aws_session.client("iam")
    iam.create_user(UserName="admin_user")
    iam.create_login_profile(UserName="admin_user", Password="StrongPassword123!")

    iam.create_user(UserName="api_user")

    findings = check_iam_001_console_mfa(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"
    assert findings[0].severity == Severity.MEDIUM
    assert "admin_user" in findings[0].resource


@mock_aws
def test_iam_002_root_mfa(aws_session):
    """Moto-да root аккаунтта әдепкі бойынша MFA өшірулі, сондықтан IAM-002 табылуы тиіс."""
    findings = check_iam_002_root_mfa(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-002"
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_iam_003_old_access_keys_with_date_mock(aws_session):
    """Уақытты 100 күнге алға жылжыту (mock) арқылы ескірген кілтті анықтауды тексеру."""
    iam = aws_session.client("iam")
    iam.create_user(UserName="dev_user")
    iam.create_access_key(UserName="dev_user")

    # Уақытты 100 күн алға жылжыту
    future_time = datetime.now(timezone.utc) + timedelta(days=100)
    with patch("checks.iam._get_utc_now", return_value=future_time):
        findings = check_iam_003_old_access_keys(aws_session)

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-003"
    assert findings[0].severity == Severity.MEDIUM
    assert "dev_user" in findings[0].resource


@mock_aws
def test_iam_004_admin_wildcard_policy(aws_session):
    """Action: * және Resource: * саясатын IAM-004 анықтауы тиіс."""
    iam = aws_session.client("iam")
    admin_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam.create_policy(PolicyName="DangerousAdminPolicy", PolicyDocument=json.dumps(admin_doc))

    safe_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::safe/*"}],
    }
    iam.create_policy(PolicyName="SafePolicy", PolicyDocument=json.dumps(safe_doc))

    findings = check_iam_004_admin_privileges_policy(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-004"
    assert findings[0].severity == Severity.CRITICAL
    assert "DangerousAdminPolicy" in findings[0].resource


@mock_aws
def test_iam_005_password_policy(aws_session):
    """Әлсіз құпиясөз саясатын немесе саясаттың жоқтығын IAM-005 анықтауы тиіс."""
    findings = check_iam_005_password_policy(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-005"
    assert findings[0].severity == Severity.LOW


# --- RDS Тексерулері ---

@mock_aws
def test_rds_001_public_instance(aws_session):
    """PubliclyAccessible: True болған RDS данасын анықтау."""
    rds = aws_session.client("rds")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        PubliclyAccessible=True,
    )
    rds.create_db_instance(
        DBInstanceIdentifier="private-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        PubliclyAccessible=False,
    )

    findings = check_rds_001_public_instance(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "RDS-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "public-db" in findings[0].resource


# --- CloudTrail Тексерулері ---

@mock_aws
def test_ct_001_no_cloudtrail(aws_session):
    """CloudTrail трейлі болмаған жағдайда CT-001 анықталуы тиіс."""
    findings = check_ct_001_active_cloudtrail(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-001"
    assert findings[0].severity == Severity.HIGH


@mock_aws
def test_ct_002_log_validation_disabled(aws_session):
    """LogFileValidationEnabled: False трейлін CT-002 анықтауы тиіс."""
    ct = aws_session.client("cloudtrail")
    s3 = aws_session.client("s3")
    s3.create_bucket(Bucket="ct-test-bkt")

    ct.create_trail(
        Name="unvalidated-trail",
        S3BucketName="ct-test-bkt",
        EnableLogFileValidation=False,
    )

    findings = check_ct_002_log_validation(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "CT-002"
    assert findings[0].severity == Severity.LOW
    assert "unvalidated-trail" in findings[0].resource
