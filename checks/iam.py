"""
IAM (Identity and Access Management) ресурстарының қауіпсіздігін тексеру ережелері.
"""
from datetime import datetime, timezone
import json
import logging
from typing import List, Union
import boto3
from botocore.exceptions import ClientError

from core.models import Finding, Severity
from core.registry import register_check

logger = logging.getLogger(__name__)


@register_check("IAM-001")
def check_iam_001_console_mfa(session: boto3.Session) -> List[Finding]:
    """
    IAM-001: AWS Management Console-ға кіру құпиясөзі бар, бірақ MFA қосылмаған пайдаланушыларды тексереді.
    Стандарт: CIS AWS Foundations Benchmark 1.10
    Қауіптілік: MEDIUM
    """
    findings: List[Finding] = []
    iam = session.client("iam")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user.get("UserName")
                user_arn = user.get("Arn", user_name)

                if not user_name:
                    continue

                has_console_password = False
                try:
                    iam.get_login_profile(UserName=user_name)
                    has_console_password = True
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code == "NoSuchEntity":
                        has_console_password = False
                    else:
                        logger.warning("Пайдаланушының кіру бейінін тексеру қатесі [%s]: %s", user_name, exc)
                        continue

                if not has_console_password:
                    continue

                try:
                    mfa_response = iam.list_mfa_devices(UserName=user_name)
                    mfa_devices = mfa_response.get("MFADevices", [])

                    if len(mfa_devices) == 0:
                        findings.append(
                            Finding(
                                rule_id="IAM-001",
                                title="Консольге кіру рұқсаты бар пайдаланушыда MFA қосылмаған",
                                resource=user_arn,
                                severity=Severity.MEDIUM,
                                description=(
                                    f"'{user_name}' IAM пайдаланушысында AWS басқару консоліне (AWS Management Console) "
                                    f"кіруге арналған белсенді құпиясөз бар, бірақ көпфакторлы аутентификация (MFA) орнатылмаған. "
                                    f"Бұл құпиясөз қолды болған жағдайда есептік жазбаның бұзылу қаупін айтарлықтай арттырады."
                                ),
                                recommendation=(
                                    f"'{user_name}' пайдаланушысы үшін міндетті түрде виртуалды (Google Authenticator және т.б.) "
                                    f"немесе аппараттық FIDO/U2F қауіпсіздік кілтін (MFA) байланыстырыңыз."
                                ),
                                standard="CIS AWS Foundations Benchmark 1.10",
                            )
                        )
                except ClientError as exc:
                    logger.error("MFA құрылғыларын тексеру кезінде қате орын алды [%s]: %s", user_name, exc)

    except ClientError as exc:
        logger.error("IAM пайдаланушылар тізімін алу кезінде қате орын алды: %s", exc)

    return findings


@register_check("IAM-002")
def check_iam_002_root_mfa(session: boto3.Session) -> List[Finding]:
    """
    IAM-002: AWS root-аккаунтында MFA қосылғанын тексереді.
    Стандарт: CIS AWS Foundations Benchmark 1.5
    Қауіптілік: CRITICAL
    """
    findings: List[Finding] = []
    iam = session.client("iam")

    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)

        if mfa_enabled == 0:
            findings.append(
                Finding(
                    rule_id="IAM-002",
                    title="Root есептік жазбасында MFA қосылмаған",
                    resource="AWS:Account:Root",
                    severity=Severity.CRITICAL,
                    description=(
                        "AWS есептік жазбасының түбірлік пайдаланушысында (root account) көпфакторлы "
                        "аутентификация (MFA) өшірулі тұр. Root аккаунты бұлттық жүйенің барлық ресурстарына "
                        "шексіз құқыққа ие, сондықтан оны MFA-сыз пайдалану аса жоғары қауіп төндіреді."
                    ),
                    recommendation=(
                        "Root пайдаланушысы үшін дереу аппараттық (FIDO2/U2F) немесе виртуалды MFA құрылғысын "
                        "қосыңыз және күнделікті жұмыс үшін тек жеке IAM рөлдерін пайдаланыңыз."
                    ),
                    standard="CIS AWS Foundations Benchmark 1.5",
                )
            )
    except ClientError as exc:
        logger.error("Root MFA тексеру кезінде қате (IAM-002): %s", exc)

    return findings


def _get_utc_now() -> datetime:
    """Ағымдағы UTC уақытын алу (тесттерде mocking жасауға ыңғайлы)."""
    return datetime.now(timezone.utc)


@register_check("IAM-003")
def check_iam_003_old_access_keys(session: boto3.Session) -> List[Finding]:
    """
    IAM-003: 90 күннен ескірген белсенді IAM Access Key-лерді тексереді.
    Стандарт: CIS AWS Foundations Benchmark 1.14
    Қауіптілік: MEDIUM
    """
    findings: List[Finding] = []
    iam = session.client("iam")

    try:
        now = _get_utc_now()
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user.get("UserName")
                if not user_name:
                    continue

                try:
                    res = iam.list_access_keys(UserName=user_name)
                    for key in res.get("AccessKeyMetadata", []):
                        if key.get("Status") == "Active":
                            create_date = key.get("CreateDate")
                            if create_date:
                                # timezone-aware салыстыру
                                if create_date.tzinfo is None:
                                    create_date = create_date.replace(tzinfo=timezone.utc)
                                age_days = (now - create_date).days

                                if age_days > 90:
                                    key_id = key.get("AccessKeyId", "Белгісіз")
                                    findings.append(
                                        Finding(
                                            rule_id="IAM-003",
                                            title="90 күннен ескірген белсенді IAM Access Key анықталды",
                                            resource=f"arn:aws:iam::{user_name}/key/{key_id}",
                                            severity=Severity.MEDIUM,
                                            description=(
                                                f"'{user_name}' пайдаланушысының '{key_id}' қолжетімділік кілті "
                                                f"{age_days} күн бұрын жасалған және әлі ротацияланбаған. "
                                                f"Ескі кілттердің интернетке ағып кету немесе ұрлану ықтималдығы жоғары."
                                            ),
                                            recommendation=(
                                                "Қолжетімділік кілттерін кем дегенде 90 күн сайын тұрақты түрде "
                                                "жаңартып (ротациялап), ескірген немесе қажетсіз кілттерді өшіріңіз."
                                            ),
                                            standard="CIS AWS Foundations Benchmark 1.14",
                                        )
                                    )
                except ClientError as exc:
                    logger.warning("Access Keys тексеру қатесі [%s]: %s", user_name, exc)
    except ClientError as exc:
        logger.error("Пайдаланушылар тізімін алу қатесі (IAM-003): %s", exc)

    return findings


def _is_wildcard(val: Union[str, list, None]) -> bool:
    """Мән '*' немесе ['*'] екенін тексереді."""
    if val == "*":
        return True
    if isinstance(val, list) and "*" in val:
        return True
    return False


@register_check("IAM-004")
def check_iam_004_admin_privileges_policy(session: boto3.Session) -> List[Finding]:
    """
    IAM-004: Толық әкімшілік құқық беретін (Action '*' және Resource '*') IAM саясаттарын анықтайды.
    Стандарт: CIS AWS Foundations Benchmark 1.16
    Қауіптілік: CRITICAL
    """
    findings: List[Finding] = []
    iam = session.client("iam")

    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy.get("Arn")
                policy_name = policy.get("PolicyName", "Белгісіз")
                version_id = policy.get("DefaultVersionId")

                if not policy_arn or not version_id:
                    continue

                try:
                    pv = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                    doc = pv.get("PolicyVersion", {}).get("Document", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    has_full_admin = False
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            if _is_wildcard(stmt.get("Action")) and _is_wildcard(stmt.get("Resource")):
                                has_full_admin = True
                                break

                    if has_full_admin:
                        findings.append(
                            Finding(
                                rule_id="IAM-004",
                                title="IAM саясатында толық әкімшілік рұқсаттар (Action '*' және Resource '*') берілген",
                                resource=policy_arn,
                                severity=Severity.CRITICAL,
                                description=(
                                    f"'{policy_name}' басқарылатын саясатында (Customer Managed Policy) барлық әрекеттерге "
                                    f"және барлық ресурстарға (Effect: Allow, Action: *, Resource: *) шектеусіз рұқсат берілген. "
                                    f"Бұл ең аз артықшылық принципін (Least Privilege) бұзады."
                                ),
                                recommendation=(
                                    "Толық әкімшілік саясатты жойып, әрбір рөл мен пайдаланушыға тек қызметтік "
                                    "міндетіне қажетті нақты AWS әрекеттері мен ресурстарына ғана рұқсат беріңіз."
                                ),
                                standard="CIS AWS Foundations Benchmark 1.16",
                            )
                        )
                except ClientError as exc:
                    logger.warning("Саясат нұсқасын тексеру қатесі [%s]: %s", policy_name, exc)
    except ClientError as exc:
        logger.error("IAM саясаттарын тексеру қатесі (IAM-004): %s", exc)

    return findings


@register_check("IAM-005")
def check_iam_005_password_policy(session: boto3.Session) -> List[Finding]:
    """
    IAM-005: IAM құпиясөз саясатының (Password Policy) қауіпсіздік талаптарына сәйкестігін тексереді.
    Стандарт: CIS AWS Foundations Benchmark 1.8
    Қауіптілік: LOW
    """
    findings: List[Finding] = []
    iam = session.client("iam")

    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        min_length = policy.get("MinimumPasswordLength", 0)
        req_symbols = policy.get("RequireSymbols", False)
        req_numbers = policy.get("RequireNumbers", False)
        req_uppercase = policy.get("RequireUppercaseCharacters", False)
        req_lowercase = policy.get("RequireLowercaseCharacters", False)

        weak_reasons = []
        if min_length < 14:
            weak_reasons.append(f"құпиясөздің минималды ұзындығы жеткіліксіз ({min_length} < 14)")
        if not req_symbols:
            weak_reasons.append("арнайы таңбалар талап етілмейді")
        if not req_numbers:
            weak_reasons.append("сандар талап етілмейді")
        if not req_uppercase:
            weak_reasons.append("бас әріптер талап етілмейді")
        if not req_lowercase:
            weak_reasons.append("кіші әріптер талап етілмейді")

        if weak_reasons:
            findings.append(
                Finding(
                    rule_id="IAM-005",
                    title="IAM құпиясөз саясаты қауіпсіздік талаптарына толық сай емес",
                    resource="AWS:IAM:PasswordPolicy",
                    severity=Severity.LOW,
                    description=(
                        f"AWS есептік жазбасындағы құпиясөз саясаты әлсіз: {', '.join(weak_reasons)}. "
                        f"Бұл пайдаланушыларға қарапайым құпиясөздер орнатуға мүмкіндік береді."
                    ),
                    recommendation=(
                        "Құпиясөз саясатын күшейтіңіз: ұзындығын кемінде 14 таңбаға дейін арттырып, "
                        "бас/кіші әріптерді, сандарды және арнайы таңбаларды міндеттеңіз."
                    ),
                    standard="CIS AWS Foundations Benchmark 1.8",
                )
            )

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "NoSuchEntity":
            findings.append(
                Finding(
                    rule_id="IAM-005",
                    title="IAM құпиясөз саясаты мүлдем орнатылмаған",
                    resource="AWS:IAM:PasswordPolicy",
                    severity=Severity.LOW,
                    description=(
                        "Бұл AWS есептік жазбасында жеке құпиясөз саясаты (Password Policy) анықталмаған. "
                        "Пайдаланушылар әдепкі әлсіз баптаулармен жұмыс істеуде."
                    ),
                    recommendation=(
                        "CIS AWS стандартына сәйкес қатаң ережелері бар (ұзындығы 14+, сандар, таңбалар) "
                        "жаңа құпиясөз саясатын орнатыңыз."
                    ),
                    standard="CIS AWS Foundations Benchmark 1.8",
                )
            )
        else:
            logger.error("Құпиясөз саясатын тексеру қатесі (IAM-005): %s", exc)

    return findings
