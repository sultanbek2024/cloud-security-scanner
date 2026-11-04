"""
S3 (Simple Storage Service) ресурстарының қауіпсіздігін тексеру ережелері.
"""
import logging
from typing import List
import boto3
from botocore.exceptions import ClientError

from core.models import Finding, Severity
from core.registry import register_check

logger = logging.getLogger(__name__)


@register_check("S3-001")
def check_s3_001_public_access_block(session: boto3.Session) -> List[Finding]:
    """
    S3-001: S3 бакетінде жария қолжетімділікті бұғаттау (Public Access Block) бапталмағанын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 2.1.5
    Қауіптілік: HIGH
    """
    findings: List[Finding] = []
    s3 = session.client("s3")

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            is_vulnerable = False
            missing_reasons: List[str] = []

            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})

                flags = [
                    ("BlockPublicAcls", config.get("BlockPublicAcls")),
                    ("IgnorePublicAcls", config.get("IgnorePublicAcls")),
                    ("BlockPublicPolicy", config.get("BlockPublicPolicy")),
                    ("RestrictPublicBuckets", config.get("RestrictPublicBuckets")),
                ]

                disabled_flags = [name for name, val in flags if val is not True]
                if disabled_flags:
                    is_vulnerable = True
                    missing_reasons.append(f"Өшірілген параметрлер: {', '.join(disabled_flags)}")

            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    is_vulnerable = True
                    missing_reasons.append("Public Access Block конфигурациясы мүлдем орнатылмаған")
                elif error_code in ("AccessDenied", "AllAccessDisabled"):
                    logger.warning("S3 бакетіне қолжетімділік жоқ [%s]: %s", bucket_name, exc)
                    continue
                else:
                    logger.error("S3 бакетін тексеру кезінде күтпеген қате [%s]: %s", bucket_name, exc)
                    continue

            if is_vulnerable:
                reason_str = "; ".join(missing_reasons)
                findings.append(
                    Finding(
                        rule_id="S3-001",
                        title="S3 бакетінде жария қолжетімділікті бұғаттау толық қосылмаған",
                        resource=f"arn:aws:s3:::{bucket_name}",
                        severity=Severity.HIGH,
                        description=(
                            f"'{bucket_name}' S3 бакетінде Amazon S3 Block Public Access параметрлері толық қосылмаған "
                            f"({reason_str}). Бұл бакеттегі файлдардың кездейсоқ ашық интернетке жариялану қаупін тудырады."
                        ),
                        recommendation=(
                            "S3 бакеті үшін 'Block all public access' баптауын толықтай қосыңыз "
                            "(BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets = True)."
                        ),
                        standard="CIS AWS Foundations Benchmark 2.1.5",
                    )
                )

    except ClientError as exc:
        logger.error("S3 бакеттерінің тізімін алу кезінде қате орын алды: %s", exc)

    return findings


@register_check("S3-002")
def check_s3_002_default_encryption(session: boto3.Session) -> List[Finding]:
    """
    S3-002: S3 бакетінде әдепкі шифрлау (Default Encryption - SSE-S3 немесе SSE-KMS) қосылмағанын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 2.1.1
    Қауіптілік: MEDIUM
    """
    findings: List[Finding] = []
    s3 = session.client("s3")

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            is_encrypted = True
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if not rules:
                    is_encrypted = False
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"):
                    is_encrypted = False
                elif error_code in ("AccessDenied", "AllAccessDisabled"):
                    logger.warning("S3 шифрлауын тексеруге рұқсат жоқ [%s]: %s", bucket_name, exc)
                    continue
                else:
                    logger.error("S3 шифрлауын тексеру кезінде қате [%s]: %s", bucket_name, exc)
                    continue

            if not is_encrypted:
                findings.append(
                    Finding(
                        rule_id="S3-002",
                        title="S3 бакетінде әдепкі шифрлау (Default Encryption) қосылмаған",
                        resource=f"arn:aws:s3:::{bucket_name}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"'{bucket_name}' S3 бакетінде серверлік әдепкі шифрлау бапталмаған. "
                            f"Бұл сақталатын объектілердің құпиялылығы мен қауіпсіздік талаптарына қайшы келеді."
                        ),
                        recommendation=(
                            "S3 бакеті үшін AWS KMS (SSE-KMS) немесе Amazon S3 (SSE-S3) кілттерін пайдаланып "
                            "әдепкі шифрлауды қосыңыз (Default Encryption)."
                        ),
                        standard="CIS AWS Foundations Benchmark 2.1.1",
                    )
                )
    except ClientError as exc:
        logger.error("S3 бакеттерінің тізімін алу қатесі (S3-002): %s", exc)

    return findings


@register_check("S3-003")
def check_s3_003_bucket_versioning(session: boto3.Session) -> List[Finding]:
    """
    S3-003: S3 бакетінде нұсқалылық (Versioning) қосылмағанын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 2.1.3
    Қауіптілік: LOW
    """
    findings: List[Finding] = []
    s3 = session.client("s3")

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            try:
                ver = s3.get_bucket_versioning(Bucket=bucket_name)
                status = ver.get("Status")

                if status != "Enabled":
                    findings.append(
                        Finding(
                            rule_id="S3-003",
                            title="S3 бакетінде нұсқалылық (Versioning) қосылмаған",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            severity=Severity.LOW,
                            description=(
                                f"'{bucket_name}' S3 бакетінде нұсқалылық (Versioning) белсенді емес "
                                f"(ағымдағы күйі: '{status or 'Disabled'}'). Нұсқалылықсыз файлдарды кездейсоқ өшіру "
                                f"немесе зиянды бағдарламалар арқылы қайта жазу кезінде деректерді қалпына келтіру мүмкін болмайды."
                            ),
                            recommendation=(
                                "Деректердің тұтастығын сақтау және кездейсоқ жойылудан қорғау үшін S3 бакетінде "
                                "Versioning мүмкіндігін қосыңыз."
                            ),
                            standard="CIS AWS Foundations Benchmark 2.1.3",
                        )
                    )
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDenied", "AllAccessDisabled"):
                    continue
                logger.error("S3 нұсқалылығын тексеру қатесі [%s]: %s", bucket_name, exc)
    except ClientError as exc:
        logger.error("S3 бакеттерінің тізімін алу қатесі (S3-003): %s", exc)

    return findings
