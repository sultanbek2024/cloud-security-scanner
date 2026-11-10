"""
Terraform (IaC) ресурстарын статикалық қауіпсіздік ережелері бойынша тексеру ережелері.
CIS AWS Foundations Benchmark және қауіпсіздік стандарттарына сәйкес жасалған.
"""
from typing import List, Dict, Any
from core.models import Finding, Severity
from iac.parser import TerraformResource


def check_iac_security_groups(resources: List[TerraformResource]) -> List[Finding]:
    """
    Terraform-дағы Security Group және Ingress ережелерінде қауіпті порттардың ашық болуын тексереді.
    """
    findings: List[Finding] = []

    for res in resources:
        if res.resource_type == "aws_security_group":
            ingress_list = res.config.get("ingress", [])
            if isinstance(ingress_list, dict):
                ingress_list = [ingress_list]

            for ing in ingress_list:
                if not isinstance(ing, dict):
                    continue

                cidr_blocks = ing.get("cidr_blocks", [])
                if isinstance(cidr_blocks, (str, int)):
                    cidr_blocks = [cidr_blocks]

                clean_cidrs = [str(c).strip('"\'') for c in cidr_blocks]
                is_public = any(cidr in ("0.0.0.0/0", "::/0") for cidr in clean_cidrs)
                if not is_public:
                    continue

                protocol = str(ing.get("protocol", "")).strip('"\'').lower()
                from_port = ing.get("from_port")
                to_port = ing.get("to_port")
                try:
                    if from_port is not None:
                        from_port = int(str(from_port).strip('"\''))
                    if to_port is not None:
                        to_port = int(str(to_port).strip('"\''))
                except (ValueError, TypeError):
                    pass

                # 1. SSH (22)
                if protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                    findings.append(
                        Finding(
                            rule_id="IAC-EC2-001",
                            title="Terraform: SSH (22-порт) бүкіл интернетке ашық етіп жарияланған",
                            resource=f"resource.aws_security_group.{res.resource_name} ({res.file_path})",
                            severity=Severity.HIGH,
                            description=(
                                f"'{res.resource_name}' Security Group кодында SSH (22-порт) "
                                f"кез келген интернет торабынан (0.0.0.0/0) кіруге рұқсат берілген."
                            ),
                            recommendation="Кодта 0.0.0.0/0 орнына нақты корпоративтік сенімді IP-ді көрсетіңіз.",
                            standard="CIS AWS Foundations Benchmark 5.2",
                            remediation_terraform='cidr_blocks = ["YOUR_COMPANY_IP/32"]',
                        )
                    )

                # 2. RDP (3389)
                if protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port):
                    findings.append(
                        Finding(
                            rule_id="IAC-EC2-002",
                            title="Terraform: RDP (3389-порт) бүкіл интернетке ашық",
                            resource=f"resource.aws_security_group.{res.resource_name} ({res.file_path})",
                            severity=Severity.HIGH,
                            description=(
                                f"'{res.resource_name}' Security Group кодында RDP (3389-порт) "
                                f"0.0.0.0/0 үшін ашық жазылған."
                            ),
                            recommendation="3389 портын кодтан алып тастаңыз немесе VPN желісімен шектеңіз.",
                            standard="CIS AWS Foundations Benchmark 5.3",
                            remediation_terraform='cidr_blocks = ["YOUR_COMPANY_IP/32"]',
                        )
                    )

                # 3. All Ports Open
                if protocol == "-1" or (from_port in (0, 1) and to_port == 65535):
                    findings.append(
                        Finding(
                            rule_id="IAC-EC2-003",
                            title="Terraform: Security Group барлық трафикке (0-65535) ашық",
                            resource=f"resource.aws_security_group.{res.resource_name} ({res.file_path})",
                            severity=Severity.HIGH,
                            description=(
                                f"'{res.resource_name}' Security Group құрамында барлық порттар мен хаттамаларға "
                                f"0.0.0.0/0 үшін толық рұқсат берілген."
                            ),
                            recommendation="Барлық трафикке рұқсат беретін ingress блогын өшіріңіз.",
                            standard="CIS AWS Foundations Benchmark 5.1",
                            remediation_terraform='# Барлық порттарға рұқсат беретін ingress ережесін жойыңыз',
                        )
                    )

        elif res.resource_type == "aws_security_group_rule":
            rule_type = str(res.config.get("type", "")).strip('"\'')
            if rule_type == "ingress":
                cidr_blocks = res.config.get("cidr_blocks", [])
                if isinstance(cidr_blocks, (str, int)):
                    cidr_blocks = [cidr_blocks]

                clean_cidrs = [str(c).strip('"\'') for c in cidr_blocks]
                if any(cidr in ("0.0.0.0/0", "::/0") for cidr in clean_cidrs):
                    from_port = res.config.get("from_port")
                    to_port = res.config.get("to_port")
                    try:
                        if from_port is not None:
                            from_port = int(str(from_port).strip('"\''))
                        if to_port is not None:
                            to_port = int(str(to_port).strip('"\''))
                    except (ValueError, TypeError):
                        pass

                    protocol = str(res.config.get("protocol", "")).strip('"\'').lower()

                    if protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                        findings.append(
                            Finding(
                                rule_id="IAC-EC2-001",
                                title="Terraform: Ingress ережесінде SSH (22) ашық",
                                resource=f"resource.aws_security_group_rule.{res.resource_name} ({res.file_path})",
                                severity=Severity.HIGH,
                                description="aws_security_group_rule құрамында 22-порт 0.0.0.0/0 үшін ашылған.",
                                recommendation="cidr_blocks параметрін қауіпсіз жеке IP-ге өзгертіңіз.",
                                standard="CIS AWS Foundations Benchmark 5.2",
                                remediation_terraform='cidr_blocks = ["YOUR_COMPANY_IP/32"]',
                            )
                        )

    return findings


def check_iac_s3_buckets(resources: List[TerraformResource]) -> List[Finding]:
    """
    Terraform-дағы S3 бакеттерінің конфигурациясын тексереді (Public ACL, Public Access Block).
    """
    findings: List[Finding] = []
    bucket_names = set()
    pab_buckets = set()

    for res in resources:
        if res.resource_type == "aws_s3_bucket":
            bucket_names.add(res.resource_name)
            acl = str(res.config.get("acl", "")).strip('"\'')
            if acl in ("public-read", "public-read-write"):
                findings.append(
                    Finding(
                        rule_id="IAC-S3-001",
                        title="Terraform: S3 бакеті жария ACL (public-read) арқылы жарияланған",
                        resource=f"resource.aws_s3_bucket.{res.resource_name} ({res.file_path})",
                        severity=Severity.HIGH,
                        description=(
                            f"'{res.resource_name}' S3 бакетінде acl = '{acl}' көрсетілген. "
                            f"Бұл бакетті интернетке толықтай ашық етеді."
                        ),
                        recommendation="acl мәнін 'private' деп өзгертіңіз.",
                        standard="CIS AWS Foundations Benchmark 2.1.5",
                        remediation_terraform='acl = "private"',
                    )
                )

        elif res.resource_type == "aws_s3_bucket_public_access_block":
            b_ref = str(res.config.get("bucket", ""))
            # Егер aws_s3_bucket.name.id сияқты сілтеме болса:
            for b_name in bucket_names:
                if b_name in b_ref:
                    pab_buckets.add(b_name)
            pab_buckets.add(res.resource_name)

    # Public Access Block ресурсы жазылмаған бакеттерді тексеру
    for res in resources:
        if res.resource_type == "aws_s3_bucket":
            if res.resource_name not in pab_buckets:
                findings.append(
                    Finding(
                        rule_id="IAC-S3-002",
                        title="Terraform: S3 бакеті үшін aws_s3_bucket_public_access_block анықталмаған",
                        resource=f"resource.aws_s3_bucket.{res.resource_name} ({res.file_path})",
                        severity=Severity.HIGH,
                        description=(
                            f"'{res.resource_name}' S3 бакетіне арналған aws_s3_bucket_public_access_block "
                            f"ресурсы кодта жоқ. Бұл бакетті кездейсоқ жарияланудан қорғамайды."
                        ),
                        recommendation="Бакет үшін aws_s3_bucket_public_access_block ресурсын қосыңыз.",
                        standard="CIS AWS Foundations Benchmark 2.1.5",
                        remediation_terraform=(
                            f'resource "aws_s3_bucket_public_access_block" "pab_{res.resource_name}" {{\n'
                            f'  bucket                  = aws_s3_bucket.{res.resource_name}.id\n'
                            '  block_public_acls       = true\n'
                            '  block_public_policy     = true\n'
                            '  ignore_public_acls      = true\n'
                            '  restrict_public_buckets = true\n'
                            '}'
                        ),
                    )
                )

    return findings


def check_iac_ebs_volumes(resources: List[TerraformResource]) -> List[Finding]:
    """
    Terraform-дағы EBS томдарының шифрланғанын тексереді.
    """
    findings: List[Finding] = []

    for res in resources:
        if res.resource_type == "aws_ebs_volume":
            encrypted = res.config.get("encrypted", False)
            if str(encrypted).lower() != "true":
                findings.append(
                    Finding(
                        rule_id="IAC-EBS-001",
                        title="Terraform: EBS томы шифрланбаған күйде сипатталған",
                        resource=f"resource.aws_ebs_volume.{res.resource_name} ({res.file_path})",
                        severity=Severity.MEDIUM,
                        description=f"'{res.resource_name}' EBS томында 'encrypted = true' бапталмаған.",
                        recommendation="EBS томының конфигурациясына 'encrypted = true' параметрін қосыңыз.",
                        standard="CIS AWS Foundations Benchmark 2.2.1",
                        remediation_terraform="encrypted = true",
                    )
                )

    return findings


def check_iac_rds_instances(resources: List[TerraformResource]) -> List[Finding]:
    """
    Terraform-дағы RDS деректер базасының интернетке ашықтығын тексереді.
    """
    findings: List[Finding] = []

    for res in resources:
        if res.resource_type == "aws_db_instance":
            publicly_accessible = res.config.get("publicly_accessible", False)
            if str(publicly_accessible).lower() == "true":
                findings.append(
                    Finding(
                        rule_id="IAC-RDS-001",
                        title="Terraform: RDS дерекқор инстансы жария интернетке ашық (publicly_accessible)",
                        resource=f"resource.aws_db_instance.{res.resource_name} ({res.file_path})",
                        severity=Severity.HIGH,
                        description=(
                            f"'{res.resource_name}' мәліметтер қорында publicly_accessible = true бапталған. "
                            f"Бұл дерекқорды сыртқы шабуылдарға осал етеді."
                        ),
                        recommendation="publicly_accessible параметрін false етіп өзгертіңіз.",
                        standard="CIS AWS Foundations Benchmark 2.3.1",
                        remediation_terraform="publicly_accessible = false",
                    )
                )

    return findings
