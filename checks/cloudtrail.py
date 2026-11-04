"""
AWS CloudTrail журналдау қызметінің қауіпсіздігін тексеру ережелері.
"""
import logging
from typing import List
import boto3
from botocore.exceptions import ClientError

from core.models import Finding, Severity
from core.registry import register_check

logger = logging.getLogger(__name__)


@register_check("CT-001")
def check_ct_001_active_cloudtrail(session: boto3.Session) -> List[Finding]:
    """
    CT-001: Есептік жазбада оқиғаларды жазатын белсенді CloudTrail трейлінің бар-жоғын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 3.1
    Қауіптілік: HIGH
    """
    findings: List[Finding] = []
    ct = session.client("cloudtrail")

    try:
        response = ct.describe_trails()
        trails = response.get("trailList", [])

        has_active_trail = False

        if trails:
            for trail in trails:
                trail_arn = trail.get("TrailARN") or trail.get("Name")
                if not trail_arn:
                    continue

                try:
                    status = ct.get_trail_status(Name=trail_arn)
                    if status.get("IsLogging") is True:
                        has_active_trail = True
                        break
                except ClientError as exc:
                    logger.warning("CloudTrail күйін тексеру қатесі [%s]: %s", trail_arn, exc)

        if not has_active_trail:
            findings.append(
                Finding(
                    rule_id="CT-001",
                    title="Белсенді CloudTrail трейлі табылмады немесе журналдау өшірілген",
                    resource="AWS:CloudTrail",
                    severity=Severity.HIGH,
                    description=(
                        "Бұл AWS есептік жазбасында журналдау жүргізетін белсенді CloudTrail трейлі анықталмады. "
                        "CloudTrail өшірулі болғанда, жүйедегі барлық API шақырулары мен пайдаланушы әрекеттері тіркелмейді, "
                        "бұл қауіпсіздік инциденттерін тергеуді және бақылауды мүмкін етпейді."
                    ),
                    recommendation=(
                        "Барлық аймақтардағы оқиғаларды жазатын (multi-region trail) CloudTrail трейлін қосыңыз және "
                        "журналдарды қорғалған, шифрланған S3 бакетіне бағыттаңыз."
                    ),
                    standard="CIS AWS Foundations Benchmark 3.1",
                )
            )

    except ClientError as exc:
        logger.error("CloudTrail тексеру кезінде ClientError орын алды: %s", exc)

    return findings


@register_check("CT-002")
def check_ct_002_log_validation(session: boto3.Session) -> List[Finding]:
    """
    CT-002: CloudTrail трейлінде лог-файлдардың тұтастығын тексеру (Log File Validation) қосулы екенін тексереді.
    Стандарт: CIS AWS Foundations Benchmark 3.2
    Қауіптілік: LOW
    """
    findings: List[Finding] = []
    ct = session.client("cloudtrail")

    try:
        response = ct.describe_trails()
        trails = response.get("trailList", [])

        for trail in trails:
            trail_name = trail.get("Name", "Белгісіз")
            trail_arn = trail.get("TrailARN", trail_name)
            is_validation_enabled = trail.get("LogFileValidationEnabled", False)

            if not is_validation_enabled:
                findings.append(
                    Finding(
                        rule_id="CT-002",
                        title="CloudTrail трейлінде лог-файлдардың тұтастығын тексеру (Log Validation) өшірілген",
                        resource=trail_arn,
                        severity=Severity.LOW,
                        description=(
                            f"'{trail_name}' CloudTrail трейлінде журнал файлдарының тұтастығын тексеру "
                            f"(Log File Validation) мүмкіндігі өшірілген. Бұл журналдардың қолдан өзгертілуі немесе "
                            f"өшірілуі орын алған жағдайда оны дер кезінде анықтауға кедергі келтіреді."
                        ),
                        recommendation=(
                            "Трейл баптауларында 'Enable log file validation' опциясын қосыңыз. "
                            "Бұл журналдардың өзгертілмегенін дәлелдейтін криптографиялық хэштерді сақтауды қамтамасыз етеді."
                        ),
                        standard="CIS AWS Foundations Benchmark 3.2",
                    )
                )

    except ClientError as exc:
        logger.error("CloudTrail журнал тұтастығын тексеру кезінде қате (CT-002): %s", exc)

    return findings
