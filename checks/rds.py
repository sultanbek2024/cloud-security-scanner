"""
Amazon RDS (Relational Database Service) ресурстарының қауіпсіздігін тексеру ережелері.
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


@register_check("RDS-001")
def check_rds_001_public_instance(session: boto3.Session) -> List[Finding]:
    """
    RDS-001: Интернетке жария қолжетімді (PubliclyAccessible: True) RDS деректер қоры даналарын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 2.3.1
    Қауіптілік: CRITICAL
    """
    findings: List[Finding] = []
    regions = _get_target_regions(session)

    for region in regions:
        try:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db.get("DBInstanceIdentifier", "Белгісіз")
                    db_arn = db.get("DBInstanceArn", db_id)
                    is_public = db.get("PubliclyAccessible", False)

                    if is_public:
                        engine = db.get("Engine", "Белгісіз")
                        findings.append(
                            Finding(
                                rule_id="RDS-001",
                                title="RDS деректер қоры интернетке жария қолжетімді (Publicly Accessible)",
                                resource=f"{db_arn} [{region}]",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"'{db_id}' ({engine}) RDS деректер қоры данасында 'Publicly Accessible' баптауы "
                                    f"қосылған. Бұл деректер қорына интернеттен тікелей қол жеткізуге мүмкіндік береді "
                                    f"және деректердің сыртқа таралып кетуі немесе шабуылдаушылардың басып алу қаупін тудырады."
                                ),
                                recommendation=(
                                    "Деректер қорының қасиеттерінен 'Publicly Accessible' мәнін 'No' етіп өзгертіңіз "
                                    "және оны тек жеке ішкі желіге (Private Subnet) орналастырып, тек рұқсат етілген "
                                    "қолданбалы серверлерден ғана қосылуға рұқсат беріңіз."
                                ),
                                standard="CIS AWS Foundations Benchmark 2.3.1",
                            )
                        )
        except ClientError as exc:
            logger.error("RDS тексеру кезінде қате [%s]: %s", region, exc)

    return findings
