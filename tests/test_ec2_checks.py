"""
EC2 тексерулерін moto кітапханасымен тестілеу (EC2 checks tests with moto).
"""
import boto3
import pytest
from moto import mock_aws

from checks.ec2 import (
    check_ec2_001_open_ssh,
    check_ec2_002_unencrypted_ebs,
    check_ec2_003_open_rdp,
    check_ec2_004_all_ports_open,
)
from core.models import Severity


@pytest.fixture
def aws_session():
    """Moto үшін жалған AWS сессиясын құру."""
    return boto3.Session(
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


@mock_aws
def test_ec2_001_open_ssh_detected(aws_session):
    """
    EC2-001: 0.0.0.0/0 үшін 22-портты ашқан Security Group-ты дұрыс анықтайтынын тексеру.
    """
    ec2 = aws_session.client("ec2")

    vulnerable_sg = ec2.create_security_group(
        GroupName="vulnerable-sg",
        Description="SG with open SSH to internet",
    )
    vulnerable_sg_id = vulnerable_sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=vulnerable_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    safe_sg = ec2.create_security_group(
        GroupName="safe-sg",
        Description="Safe SG with restricted IP",
    )
    safe_sg_id = safe_sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=safe_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "192.168.1.50/32"}],
            },
        ],
    )

    findings = check_ec2_001_open_ssh(aws_session)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "EC2-001"
    assert finding.severity == Severity.HIGH
    assert vulnerable_sg_id in finding.resource
    assert safe_sg_id not in finding.resource


@mock_aws
def test_ec2_002_unencrypted_ebs_detected(aws_session):
    """
    EC2-002: Шифрланбаған EBS томын анықтайтынын және шифрланған томды өткізіп жіберетінін тексеру.
    """
    ec2 = aws_session.client("ec2")

    unencrypted_vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=10,
        Encrypted=False,
    )
    unencrypted_id = unencrypted_vol["VolumeId"]

    encrypted_vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=10,
        Encrypted=True,
    )
    encrypted_id = encrypted_vol["VolumeId"]

    findings = check_ec2_002_unencrypted_ebs(aws_session)

    detected_ids = [f.resource for f in findings]
    assert any(unencrypted_id in res for res in detected_ids)
    assert not any(encrypted_id in res for res in detected_ids)

    for f in findings:
        if unencrypted_id in f.resource:
            assert f.rule_id == "EC2-002"
            assert f.severity == Severity.MEDIUM


@mock_aws
def test_ec2_003_open_rdp_detected(aws_session):
    """
    EC2-003: 0.0.0.0/0 үшін 3389-портты (RDP) ашқан Security Group-ты анықтау.
    """
    ec2 = aws_session.client("ec2")

    rdp_sg = ec2.create_security_group(
        GroupName="rdp-open-sg",
        Description="SG with open RDP",
    )
    rdp_sg_id = rdp_sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=rdp_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = check_ec2_003_open_rdp(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "EC2-003"
    assert findings[0].severity == Severity.HIGH
    assert rdp_sg_id in findings[0].resource


@mock_aws
def test_ec2_004_all_ports_open_detected(aws_session):
    """
    EC2-004: Барлық трафикті (-1) 0.0.0.0/0 үшін ашқан қауіпті топты анықтау.
    """
    ec2 = aws_session.client("ec2")

    all_sg = ec2.create_security_group(
        GroupName="all-traffic-sg",
        Description="SG with all traffic open",
    )
    all_sg_id = all_sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=all_sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = check_ec2_004_all_ports_open(aws_session)
    assert len(findings) == 1
    assert findings[0].rule_id == "EC2-004"
    assert findings[0].severity == Severity.HIGH
    assert all_sg_id in findings[0].resource
