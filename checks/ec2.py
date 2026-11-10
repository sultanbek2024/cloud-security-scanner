"""
EC2, Security Groups және EBS ресурстарының қауіпсіздігін тексеру ережелері.
"""
import logging
from typing import List
import boto3
from botocore.exceptions import ClientError

from core.models import Finding, Severity
from core.registry import register_check

logger = logging.getLogger(__name__)


def _get_target_regions(session: boto3.Session) -> List[str]:
    """Сессиядан мақсатты аймақтар тізімін алу."""
    return getattr(session, "target_regions", [session.region_name or "us-east-1"])


@register_check("EC2-001")
def check_ec2_001_open_ssh(session: boto3.Session) -> List[Finding]:
    """
    EC2-001: Security Group-та SSH (22-порт) 0.0.0.0/0 үшін ашық екенін тексереді.
    Стандарт: CIS AWS Foundations Benchmark 5.2
    Қауіптілік: HIGH
    """
    findings: List[Finding] = []
    regions = _get_target_regions(session)

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId", "Белгісіз")
                    sg_name = sg.get("GroupName", "Белгісіз")

                    for perm in sg.get("IpPermissions", []):
                        ip_protocol = perm.get("IpProtocol")
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        is_ssh_exposed = False
                        if ip_protocol == "-1":
                            is_ssh_exposed = True
                        elif ip_protocol == "tcp":
                            if from_port is not None and to_port is not None:
                                if from_port <= 22 <= to_port:
                                    is_ssh_exposed = True

                        if not is_ssh_exposed:
                            continue

                        has_open_ipv4 = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", []))
                        has_open_ipv6 = any(ip.get("CidrIpv6") == "::/0" for ip in perm.get("Ipv6Ranges", []))

                        if has_open_ipv4 or has_open_ipv6:
                            findings.append(
                                Finding(
                                    rule_id="EC2-001",
                                    title="SSH (22-порт) бүкіл интернетке ашық",
                                    resource=f"{sg_id} ({sg_name}) [{region}]",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"'{sg_name}' ({sg_id}) Security Group құрамында 22-портқа (SSH) "
                                        f"кез келген интернет торабынан (0.0.0.0/0 немесе ::/0) кіруге рұқсат берілген. "
                                        f"Бұл серверді автоматтандырылған брутфорс шабуылдарына ұшыратады."
                                    ),
                                    recommendation=(
                                        "SSH портына қолжетімділікті нақты сенімді IP мекенжайлармен немесе ішкі VPN арқылы шектеңіз. "
                                        "Сондай-ақ AWS Systems Manager Session Manager қызметін пайдалану ұсынылады."
                                    ),
                                    standard="CIS AWS Foundations Benchmark 5.2",
                                    remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                                    remediation_terraform=(
                                        f'# Security Group ({sg_name}) ішіндегі 0.0.0.0/0 орнына тек сенімді IP көрсетіңіз:\n'
                                        'ingress {\n'
                                        '  from_port   = 22\n'
                                        '  to_port     = 22\n'
                                        '  protocol    = "tcp"\n'
                                        '  cidr_blocks = ["YOUR_OFFICE_IP/32"]\n'
                                        '}'
                                    ),
                                )
                            )
                            break
        except ClientError as exc:
            logger.error("EC2 Security Groups тексеру кезінде қате [%s]: %s", region, exc)

    return findings


@register_check("EC2-002")
def check_ec2_002_unencrypted_ebs(session: boto3.Session) -> List[Finding]:
    """
    EC2-002: Незашифрованный EBS-томдарды анықтайды.
    Стандарт: CIS AWS Foundations Benchmark 2.2.1
    Қауіптілік: MEDIUM
    """
    findings: List[Finding] = []
    regions = _get_target_regions(session)

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    vol_id = volume.get("VolumeId", "Белгісіз")
                    is_encrypted = volume.get("Encrypted", False)

                    if not is_encrypted:
                        findings.append(
                            Finding(
                                rule_id="EC2-002",
                                title="EBS томы шифрланбаған",
                                resource=f"{vol_id} [{region}]",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"EBS томы '{vol_id}' демалыс кезінде (at-rest) шифрланбаған. "
                                    f"Бұл сақталған деректердің құпиялылығы мен қауіпсіздігіне тікелей қатер төндіреді."
                                ),
                                recommendation=(
                                    "EBS томы үшін AWS KMS кілттерін пайдаланып шифрлауды қосыңыз (EBS Encryption). "
                                    "Сондай-ақ аймақ деңгейінде әдепкі шифрлауды (Encryption by default) белсендіріңіз."
                                ),
                                standard="CIS AWS Foundations Benchmark 2.2.1",
                                remediation_cli=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                                remediation_terraform=(
                                    'resource "aws_ebs_encryption_by_default" "example" {\n'
                                    '  enabled = true\n'
                                    '}'
                                ),
                            )
                        )
        except ClientError as exc:
            logger.error("EBS томдарын тексеру кезінде қате [%s]: %s", region, exc)

    return findings


@register_check("EC2-003")
def check_ec2_003_open_rdp(session: boto3.Session) -> List[Finding]:
    """
    EC2-003: Security Group құрамында ашық RDP (3389-порт) 0.0.0.0/0 бар-жоғын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 5.3
    Қауіптілік: HIGH
    """
    findings: List[Finding] = []
    regions = _get_target_regions(session)

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId", "Белгісіз")
                    sg_name = sg.get("GroupName", "Белгісіз")

                    for perm in sg.get("IpPermissions", []):
                        ip_protocol = perm.get("IpProtocol")
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        is_rdp_exposed = False
                        if ip_protocol == "-1":
                            is_rdp_exposed = True
                        elif ip_protocol == "tcp":
                            if from_port is not None and to_port is not None:
                                if from_port <= 3389 <= to_port:
                                    is_rdp_exposed = True

                        if not is_rdp_exposed:
                            continue

                        has_open_ipv4 = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", []))
                        has_open_ipv6 = any(ip.get("CidrIpv6") == "::/0" for ip in perm.get("Ipv6Ranges", []))

                        if has_open_ipv4 or has_open_ipv6:
                            findings.append(
                                Finding(
                                    rule_id="EC2-003",
                                    title="RDP (3389-порт) бүкіл интернетке ашық",
                                    resource=f"{sg_id} ({sg_name}) [{region}]",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"'{sg_name}' ({sg_id}) Security Group құрамында 3389-портқа (Windows RDP) "
                                        f"бүкіл интернеттен (0.0.0.0/0 немесе ::/0) қосылуға рұқсат берілген. "
                                        f"Бұл жүйені қашықтан басқару осалдықтарына және BlueKeep сияқты эксплойттерге ұшыратады."
                                    ),
                                    recommendation=(
                                        "3389 (RDP) портына қолжетімділікті нақты сенімді корпоративтік IP мекенжайлармен шектеңіз "
                                        "немесе AWS Systems Manager Fleet Manager пайдаланыңыз."
                                    ),
                                    standard="CIS AWS Foundations Benchmark 5.3",
                                    remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0",
                                    remediation_terraform=(
                                        f'# Security Group ({sg_name}) 3389 (RDP) портын жабыңыз немесе шектеңіз:\n'
                                        'ingress {\n'
                                        '  from_port   = 3389\n'
                                        '  to_port     = 3389\n'
                                        '  protocol    = "tcp"\n'
                                        '  cidr_blocks = ["YOUR_OFFICE_IP/32"]\n'
                                        '}'
                                    ),
                                )
                            )
                            break
        except ClientError as exc:
            logger.error("EC2 RDP тексеру кезінде қате [%s]: %s", region, exc)

    return findings


@register_check("EC2-004")
def check_ec2_004_all_ports_open(session: boto3.Session) -> List[Finding]:
    """
    EC2-004: Security Group барлық трафикті (-1) немесе барлық порттарды (0-65535) 0.0.0.0/0 үшін ашық қалдырғанын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 5.1
    Қауіптілік: HIGH
    """
    findings: List[Finding] = []
    regions = _get_target_regions(session)

    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId", "Белгісіз")
                    sg_name = sg.get("GroupName", "Белгісіз")

                    for perm in sg.get("IpPermissions", []):
                        ip_protocol = perm.get("IpProtocol")
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        is_all_open = False
                        if ip_protocol == "-1":
                            is_all_open = True
                        elif from_port in (0, 1) and to_port == 65535:
                            is_all_open = True

                        if not is_all_open:
                            continue

                        has_open_ipv4 = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", []))
                        has_open_ipv6 = any(ip.get("CidrIpv6") == "::/0" for ip in perm.get("Ipv6Ranges", []))

                        if has_open_ipv4 or has_open_ipv6:
                            findings.append(
                                Finding(
                                    rule_id="EC2-004",
                                    title="Security Group барлық трафикті интернетке ашық қалдырған",
                                    resource=f"{sg_id} ({sg_name}) [{region}]",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"'{sg_name}' ({sg_id}) Security Group барлық желілік порттар мен хаттамаларға "
                                        f"(0.0.0.0/0 немесе ::/0) шектеусіз кіруге рұқсат берген. "
                                        f"Бұл желілік қауіпсіздік деңгейін күрт төмендетеді."
                                    ),
                                    recommendation=(
                                        "Барлық трафикке рұқсат беретін (0.0.0.0/0 All Traffic) ережені дереу өшіріп, "
                                        "тек нақты қажетті порттар мен IP мекенжайларды ғана рұқсат етіңіз."
                                    ),
                                    standard="CIS AWS Foundations Benchmark 5.1",
                                    remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol -1 --cidr 0.0.0.0/0",
                                    remediation_terraform=(
                                        f'# Security Group ({sg_name}) ішіндегі protocol = "-1" немесе 0.0.0.0/0 ережесін өшіріңіз'
                                    ),
                                )
                            )
                            break
        except ClientError as exc:
            logger.error("EC2 All Ports тексеру кезінде қате [%s]: %s", region, exc)

    return findings
