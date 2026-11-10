"""
Terraform (IaC) қауіпсіздік сканерінің атқарушы қозғалтқышы (Scanner Engine).
"""
import os
from typing import List
from core.models import Finding
from iac.parser import parse_terraform_dir, parse_terraform_file, TerraformResource
from iac.rules import (
    check_iac_security_groups,
    check_iac_s3_buckets,
    check_iac_ebs_volumes,
    check_iac_rds_instances,
)


def scan_terraform(target_path: str) -> List[Finding]:
    """
    Берілген файл немесе папка бойынша барлық Terraform ресурстарын жинап,
    барлық IaC қауіпсіздік ережелері бойынша статикалық талдау (Shift-Left) жүргізеді.

    :param target_path: .tf файлы немесе .tf файлдары бар папка жолы
    :return: Анықталған қауіпсіздік кемшіліктері (List[Finding])
    """
    if os.path.isfile(target_path):
        resources = parse_terraform_file(target_path)
    elif os.path.isdir(target_path):
        resources = parse_terraform_dir(target_path)
    else:
        return []

    findings: List[Finding] = []

    # Барлық ережелерді орындау
    findings.extend(check_iac_security_groups(resources))
    findings.extend(check_iac_s3_buckets(resources))
    findings.extend(check_iac_ebs_volumes(resources))
    findings.extend(check_iac_rds_instances(resources))

    return findings


def get_declared_resources(target_path: str) -> List[TerraformResource]:
    """
    Drift Detection үшін Terraform-да жарияланған барлық ресурстар тізімін қайтарады.
    """
    if os.path.isfile(target_path):
        return parse_terraform_file(target_path)
    elif os.path.isdir(target_path):
        return parse_terraform_dir(target_path)
    return []
