#!/usr/bin/env python3
"""
Осал ортаны автоматты түрде түзету және қауіпсіздендіру скрипті (Cloud Remediation Engine).
Бұлттық ресурстарды CIS AWS Benchmark және AWS FSBP талаптарына сәйкестендіреді.

Жаңа мүмкіндіктері:
- --dry-run: өзгерістерді қолданбай, тек жоспарланған түзетулерді қарап шығу
- --trusted-cidr: еркін корпоративтік/VPN ішкі желісін көрсету (әдепкі: 10.0.0.0/8)
- --yes (-y): растау сұрауынсыз автоматты орындау
- --backup: түзету алдындағы күйді remediation_backup.json файлына сақтау
- Аудит журналы: барлық оқиғалар remediation_audit.log файлына жазылады
"""
import argparse
from datetime import datetime, timezone
import json
import logging
import os
import sys
import urllib.request
import boto3
from botocore.exceptions import ClientError

# Windows жүйесінде UTF-8 қолдау
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

_orig_print = print
def print(*args, **kwargs):
    if "flush" not in kwargs:
        kwargs["flush"] = True
    _orig_print(*args, **kwargs)

# Аудит журналын баптау
LOG_FILE = "remediation_audit.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)

DEFAULT_ENDPOINT = "http://localhost:4566"
DEFAULT_REGION = "us-east-1"
TEST_ACCESS_KEY = "test"
TEST_SECRET_KEY = "test"

# Ресурс атаулары
SG_NAMES = ["vulnerable-ssh-sg", "vulnerable-rdp-sg", "vulnerable-allports-sg"]
TAG_VOL_UNENCRYPTED = "vulnerable-unencrypted-volume"
TAG_VOL_ENCRYPTED = "safe-encrypted-volume"
BUCKET_VULN_NAME = "vulnerable-public-bucket"
BUCKET_SAFE_NAME = "safe-protected-bucket"
BUCKET_CT_LOGS = "cloudtrail-logs-bucket"
IAM_USER_CONSOLE = "vulnerable-console-user"
IAM_USER_API = "developer-api-user"
POLICY_ADMIN_NAME = "vulnerable-admin-wildcard-policy"
POLICY_SAFE_NAME = "safe-readonly-policy"
RDS_PUBLIC_ID = "vulnerable-public-db"
RDS_PRIVATE_ID = "safe-private-db"
TRAIL_NAME = "vulnerable-trail-no-validation"


def log_action(action: str, resource: str, details: str, dry_run: bool = False) -> None:
    """Аудит журналына оқиғаны жазу."""
    prefix = "[DRY-RUN] " if dry_run else ""
    msg = f"{prefix}{action} | Ресурс: {resource} | Толығырақ: {details}"
    logging.info(msg)


def check_emulator(endpoint_url: str) -> None:
    try:
        req = urllib.request.Request(endpoint_url, method="GET")
        with urllib.request.urlopen(req, timeout=3):
            pass
    except Exception as exc:
        print(f"[ҚАТЕ] AWS эмуляторы қолжетімсіз ({endpoint_url}): {exc}", file=sys.stderr)
        sys.exit(1)


def get_session(profile: str = None, endpoint_url: str = None) -> boto3.Session:
    if endpoint_url and "localhost" in endpoint_url or "4566" in (endpoint_url or ""):
        return boto3.Session(
            aws_access_key_id=TEST_ACCESS_KEY,
            aws_secret_access_key=TEST_SECRET_KEY,
            region_name=DEFAULT_REGION,
        )
    if profile:
        return boto3.Session(profile_name=profile, region_name=DEFAULT_REGION)
    return boto3.Session(region_name=DEFAULT_REGION)


def remediate_security_groups(ec2, trusted_cidr: str = "10.0.0.0/8", dry_run: bool = False, backup_data: dict = None) -> None:
    """1. Security Groups: 0.0.0.0/0 ережелерін өшіріп, сенімді CIDR рұқсат ету."""
    print(f"--- [1/6] Security Groups қауіпсіздендірілуде (Сенімді CIDR: {trusted_cidr}) ---")
    for sg_name in SG_NAMES:
        try:
            res = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])
            sgs = res.get("SecurityGroups", [])
            if not sgs:
                continue

            sg = sgs[0]
            sg_id = sg["GroupId"]

            if backup_data is not None:
                backup_data["security_groups"].append({
                    "group_id": sg_id,
                    "group_name": sg_name,
                    "ip_permissions": sg.get("IpPermissions", []),
                })

            revoke_perms = []
            for perm in sg.get("IpPermissions", []):
                has_open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                has_open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if has_open_v4 or has_open_v6:
                    revoke_perms.append(perm)

            if revoke_perms:
                if dry_run:
                    print(f"  [DRY-RUN] {sg_name} ({sg_id}): 0.0.0.0/0 ережелері жойылар еді")
                    log_action("REVOKE_INGRESS", sg_id, f"0.0.0.0/0 ережесін өшіру жоспарланды", dry_run=True)
                else:
                    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=revoke_perms)
                    print(f"  [-] {sg_name} ({sg_id}): 0.0.0.0/0 ашық ережелері жойылды")
                    log_action("REVOKE_INGRESS", sg_id, "0.0.0.0/0 ережесі сәтті өшірілді")

            # Қауіпсіз ішкі желі ережесін қосу
            from_port = 22 if "ssh" in sg_name else (3389 if "rdp" in sg_name else 443)
            new_perm = [
                {
                    "IpProtocol": "tcp",
                    "FromPort": from_port,
                    "ToPort": from_port,
                    "IpRanges": [{"CidrIp": trusted_cidr, "Description": "Trusted internal corporate network"}],
                }
            ]
            if dry_run:
                print(f"  [DRY-RUN] {sg_name}: қауіпсіз {trusted_cidr} рұқсаты қосылар еді")
                log_action("AUTHORIZE_INGRESS", sg_id, f"{trusted_cidr} порт {from_port} рұқсаты жоспарланды", dry_run=True)
            else:
                try:
                    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=new_perm)
                    print(f"  [+] {sg_name}: қауіпсіз {trusted_cidr} ішкі желілік рұқсаты орнатылды")
                    log_action("AUTHORIZE_INGRESS", sg_id, f"{trusted_cidr} порт {from_port} орнатылды")
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate":
                        print(f"  [!] SG рұқсат қосу қатесі: {exc}")

        except ClientError as exc:
            print(f"  [!] {sg_name} түзету кезінде қате: {exc}")


def remediate_ebs_volumes(ec2, dry_run: bool = False) -> None:
    """2. EBS: Шифрланбаған томды жойып, орнына шифрланған том жасау."""
    print("--- [2/6] EBS томдары қауіпсіздендірілуде ---")
    try:
        res = ec2.describe_volumes()
        for vol in res.get("Volumes", []):
            vol_id = vol["VolumeId"]
            if not vol.get("Encrypted", False) and vol.get("State") != "deleted":
                if dry_run:
                    print(f"  [DRY-RUN] Шифрланбаған EBS {vol_id} жойылып, орнына Encrypted: True көшірмесі жасалар еді")
                    log_action("RECREATE_VOLUME", vol_id, "Шифрланған жаңа том жасау жоспарланды", dry_run=True)
                    continue

                ec2.delete_volume(VolumeId=vol_id)
                print(f"  [-] Шифрланбаған EBS томы жойылды: {vol_id}")

                new_vol = ec2.create_volume(
                    AvailabilityZone="us-east-1a",
                    Size=10,
                    Encrypted=True,
                    TagSpecifications=[
                        {
                            "ResourceType": "volume",
                            "Tags": [{"Key": "Name", "Value": TAG_VOL_UNENCRYPTED}],
                        }
                    ],
                )
                print(f"  [+] Орнына шифрланған жаңа EBS томы құрылды: {new_vol['VolumeId']} (Encrypted: True)")
                log_action("RECREATE_VOLUME", new_vol["VolumeId"], f"Ескі {vol_id} орнына шифрланған том құрылды")
    except ClientError as exc:
        print(f"  [!] EBS түзету қатесі: {exc}")


def remediate_s3_buckets(s3, dry_run: bool = False) -> None:
    """3. S3: Барлық бакеттерде PAB, әдепкі шифрлау және нұсқалылықты қосу."""
    print("--- [3/6] S3 бакеттері қауіпсіздендірілуде ---")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            b_name = b["Name"]
            if dry_run:
                print(f"  [DRY-RUN] S3 бакеті {b_name}: PAB, SSE-AES256 және Versioning қосылар еді")
                log_action("S3_SECURITY_HARDEN", b_name, "PAB, SSE және Versioning баптау жоспарланды", dry_run=True)
                continue

            s3.put_public_access_block(
                Bucket=b_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            s3.put_bucket_encryption(
                Bucket=b_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
                },
            )
            s3.put_bucket_versioning(
                Bucket=b_name,
                VersioningConfiguration={"Status": "Enabled"},
            )
            print(f"  [+] S3 бакеті түзетілді ({b_name}): PAB, Encryption, Versioning қосылды")
            log_action("S3_SECURITY_HARDEN", b_name, "PAB, SSE және Versioning сәтті қосылды")
    except ClientError as exc:
        print(f"  [!] S3 түзету қатесі: {exc}")


def remediate_iam(iam, dry_run: bool = False) -> None:
    """4. IAM: Қауіпті саясатты жою, MFA байланыстыру, қатаң парольдік саясат орнату."""
    print("--- [4/6] IAM қауіпсіздендірілуде ---")
    if dry_run:
        print("  [DRY-RUN] IAM Wildcard саясаты жойылып, MFA қосылып, 14+ таңбалы құпиясөз саясаты орнатылар еді")
        log_action("IAM_REMEDIATION", "IAM-Global", "IAM тазалау және күшейту жоспарланды", dry_run=True)
        return

    # 1. Қауіпті Wildcard саясатын жою
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        for p in policies:
            if p["PolicyName"] == POLICY_ADMIN_NAME:
                iam.delete_policy(PolicyArn=p["Arn"])
                print(f"  [-] Қауіпті Wildcard саясаты жойылды: {POLICY_ADMIN_NAME}")
                log_action("DELETE_POLICY", POLICY_ADMIN_NAME, f"Wildcard саясаты өшірілді: {p['Arn']}")
    except ClientError as exc:
        print(f"  [!] IAM саясат жою қатесі: {exc}")

    # 2. MFA
    try:
        mfa_devices = iam.list_mfa_devices(UserName=IAM_USER_CONSOLE).get("MFADevices", [])
        if not mfa_devices:
            mfa_serial = None
            try:
                vmfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="vulnerable-user-mfa")
                mfa_serial = vmfa["VirtualMFADevice"]["SerialNumber"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                    account_id = "123456789012"
                    mfa_serial = f"arn:aws:iam::{account_id}:mfa/vulnerable-user-mfa"

            if mfa_serial:
                iam.enable_mfa_device(
                    UserName=IAM_USER_CONSOLE,
                    SerialNumber=mfa_serial,
                    AuthenticationCode1="123456",
                    AuthenticationCode2="654321",
                )
                print(f"  [+] {IAM_USER_CONSOLE} үшін виртуалды MFA сәтті қосылды")
                log_action("ENABLE_MFA", IAM_USER_CONSOLE, f"Виртуалды MFA құрылғысы қосылды: {mfa_serial}")
        else:
            print(f"  [*] {IAM_USER_CONSOLE} үшін MFA бұрыннан қосулы")
    except Exception as exc:
        print(f"  [!] MFA орнату сәтсіз болды ({exc}), консоль құпиясөзі өшірілуде...")
        try:
            iam.delete_login_profile(UserName=IAM_USER_CONSOLE)
            print(f"  [-] {IAM_USER_CONSOLE} консольдік кіру бейіні жойылды (қауіп залалсыздандырылды)")
            log_action("DELETE_LOGIN_PROFILE", IAM_USER_CONSOLE, "MFA сәтсіз болған соң консоль кіру профилі жойылды")
        except ClientError:
            pass

    # 3. Құпиясөз саясаты
    try:
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=5,
        )
        print("  [+] Қатаң IAM құпиясөз саясаты орнатылды (ұзындығы 14+, сандар, таңбалар)")
        log_action("UPDATE_PASSWORD_POLICY", "AccountPolicy", "CIS 1.8 қатаң құпиясөз саясаты орнатылды")
    except ClientError as exc:
        print(f"  [!] Құпиясөз саясатын орнату қатесі: {exc}")

    print("  [i] Root-аккаунт MFA: moto_server эмуляторында root MFA баптау API арқылы мүмкін емес, бұл қауіп платформа шектеуіне байланысты қалады.")


def remediate_rds(rds, dry_run: bool = False) -> None:
    """5. RDS: PubliclyAccessible = False орнату."""
    print("--- [5/6] RDS деректер қоры қауіпсіздендірілуде ---")
    try:
        dbs = rds.describe_db_instances().get("DBInstances", [])
        for db in dbs:
            db_id = db["DBInstanceIdentifier"]
            if db.get("PubliclyAccessible", False):
                if dry_run:
                    print(f"  [DRY-RUN] RDS '{db_id}': PubliclyAccessible = False етіп жабылар еді")
                    log_action("MODIFY_DB_INSTANCE", db_id, "PubliclyAccessible=False жабу жоспарланды", dry_run=True)
                    continue

                rds.modify_db_instance(
                    DBInstanceIdentifier=db_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True,
                )
                print(f"  [+] RDS '{db_id}': PubliclyAccessible = False етіп түзетілді")
                log_action("MODIFY_DB_INSTANCE", db_id, "PubliclyAccessible=False етіп жабылды")
    except ClientError as exc:
        print(f"  [!] RDS түзету қатесі: {exc}")


def remediate_cloudtrail(ct, dry_run: bool = False) -> None:
    """6. CloudTrail: Журналдауды және лог валидациясын қосу."""
    print("--- [6/6] CloudTrail журналдау қызметі қауіпсіздендірілуде ---")
    try:
        trails = ct.describe_trails().get("trailList", [])
        for t in trails:
            t_name = t.get("Name")
            if dry_run:
                print(f"  [DRY-RUN] CloudTrail '{t_name}': Log Validation және Multi-Region қосылар еді")
                log_action("UPDATE_TRAIL", t_name, "Валидация және журналдау қосу жоспарланды", dry_run=True)
                continue

            ct.update_trail(
                Name=t_name,
                EnableLogFileValidation=True,
                IsMultiRegionTrail=True,
            )
            ct.start_logging(Name=t_name)
            print(f"  [+] CloudTrail '{t_name}': Log Validation қосылды және журналдау белсендірілді")
            log_action("UPDATE_TRAIL", t_name, "Log Validation қосылды және start_logging орындалды")
    except ClientError as exc:
        print(f"  [!] CloudTrail түзету қатесі: {exc}")


def cleanup_all(ec2, s3, iam, rds, ct) -> None:
    """Барлық тесттік және түзетілген ресурстарды толық тазалау."""
    print("=== Ресурстарды толық тазалау басталды ===")
    for db_id in [RDS_PUBLIC_ID, RDS_PRIVATE_ID]:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
            print(f"  [-] RDS жойылды: {db_id}")
        except ClientError:
            pass

    try:
        ct.stop_logging(Name=TRAIL_NAME)
    except ClientError:
        pass
    try:
        ct.delete_trail(Name=TRAIL_NAME)
        print(f"  [-] Trail жойылды: {TRAIL_NAME}")
    except ClientError:
        pass

    for sg_name in SG_NAMES:
        try:
            ec2.delete_security_group(GroupName=sg_name)
            print(f"  [-] SG жойылды: {sg_name}")
        except ClientError:
            pass

    for tag in [TAG_VOL_UNENCRYPTED, TAG_VOL_ENCRYPTED]:
        try:
            res = ec2.describe_volumes(Filters=[{"Name": "tag:Name", "Values": [tag]}])
            for v in res.get("Volumes", []):
                if v.get("State") != "deleted":
                    ec2.delete_volume(VolumeId=v["VolumeId"])
                    print(f"  [-] EBS жойылды: {v['VolumeId']}")
        except ClientError:
            pass

    for b_name in [BUCKET_VULN_NAME, BUCKET_SAFE_NAME, BUCKET_CT_LOGS]:
        try:
            objs = s3.list_objects_v2(Bucket=b_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=b_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=b_name)
            print(f"  [-] S3 бакеті жойылды: {b_name}")
        except ClientError:
            pass

    try:
        iam.delete_account_password_policy()
        print("  [-] IAM құпиясөз саясаты өшірілді")
    except ClientError:
        pass

    for u_name in [IAM_USER_CONSOLE, IAM_USER_API]:
        try:
            mfa_devs = iam.list_mfa_devices(UserName=u_name).get("MFADevices", [])
            for d in mfa_devs:
                iam.deactivate_mfa_device(UserName=u_name, SerialNumber=d["SerialNumber"])
                try:
                    iam.delete_virtual_mfa_device(SerialNumber=d["SerialNumber"])
                except ClientError:
                    pass
            try:
                iam.delete_login_profile(UserName=u_name)
            except ClientError:
                pass
            keys = iam.list_access_keys(UserName=u_name).get("AccessKeyMetadata", [])
            for k in keys:
                iam.delete_access_key(UserName=u_name, AccessKeyId=k["AccessKeyId"])
            iam.delete_user(UserName=u_name)
            print(f"  [-] IAM пайдаланушысы жойылды: {u_name}")
        except ClientError:
            pass

    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        for p in policies:
            if p["PolicyName"] in [POLICY_ADMIN_NAME, POLICY_SAFE_NAME]:
                iam.delete_policy(PolicyArn=p["Arn"])
                print(f"  [-] Саясат жойылды: {p['PolicyName']}")
    except ClientError:
        pass

    print("=== Ресурстар толық тазартылды! ===")


def main() -> None:
    parser = argparse.ArgumentParser(description="Осал инфрақұрылымды автоматты түзету скрипті (Cloud Remediation Engine).")
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT, help=f"Эмулятор URL (әдепкі: {DEFAULT_ENDPOINT})")
    parser.add_argument("--profile", default=None, help="Нақты AWS пайдаланушы профилі")
    parser.add_argument("--trusted-cidr", default="10.0.0.0/8", help="SG үшін рұқсат етілген сенімді корпоративтік ішкі желі (әдепкі: 10.0.0.0/8)")
    parser.add_argument("--dry-run", action="store_true", help="Өзгерістерді қолданбай, тек жоспарланған әрекеттерді көрсету")
    parser.add_argument("--yes", "-y", action="store_true", help="Растау сұрауынсыз тікелей орындау")
    parser.add_argument("--backup", action="store_true", default=True, help="Түзету алдындағы күйді remediation_backup.json файлына сақтау")
    parser.add_argument("--skip-health-check", action="store_true", help="Эмулятор денсаулығын тексеруді өткізіп жіберу")
    parser.add_argument("--cleanup", action="store_true", help="Барлық тесттік немесе түзетілген ресурстарды өшіру")
    args = parser.parse_args()

    # Эмуляторды тексеру
    if args.endpoint_url and not args.skip_health_check and not args.profile:
        check_emulator(args.endpoint_url)

    # Растау сұрауы (Қауіпсіздік талабы)
    if not args.yes and not args.dry_run and not args.cleanup:
        try:
            confirm = input(f"⚠️ ЕСКЕРТУ: Бұл операция бұлттық ортаның конфигурациясын өзгертеді (Сенімді желі: {args.trusted_cidr}). Жалғастырасыз ба? (y/N): ")
            if confirm.strip().lower() not in ("y", "yes", "иә"):
                print("Операция тоқтатылды.")
                return
        except EOFError:
            pass

    session = get_session(profile=args.profile, endpoint_url=args.endpoint_url)
    kwargs = {"endpoint_url": args.endpoint_url} if args.endpoint_url else {}
    ec2 = session.client("ec2", **kwargs)
    s3 = session.client("s3", **kwargs)
    iam = session.client("iam", **kwargs)
    rds = session.client("rds", **kwargs)
    ct = session.client("cloudtrail", **kwargs)

    if args.cleanup:
        cleanup_all(ec2, s3, iam, rds, ct)
        return

    backup_data = {"timestamp": datetime.now(timezone.utc).isoformat(), "security_groups": []} if args.backup else None

    mode_label = "[DRY-RUN СЫНАҚ РЕЖИМІ]" if args.dry_run else "[ТОЛЫҚ РЕАЛИЗАЦИЯ РЕЖИМІ]"
    print(f"=== БҰЛТТЫҚ ОРТАНЫ ТҮЗЕТУ {mode_label} БАСТАЛДЫ ===")
    remediate_security_groups(ec2, trusted_cidr=args.trusted_cidr, dry_run=args.dry_run, backup_data=backup_data)
    remediate_ebs_volumes(ec2, dry_run=args.dry_run)
    remediate_s3_buckets(s3, dry_run=args.dry_run)
    remediate_iam(iam, dry_run=args.dry_run)
    remediate_rds(rds, dry_run=args.dry_run)
    remediate_cloudtrail(ct, dry_run=args.dry_run)

    if backup_data and not args.dry_run:
        try:
            with open("remediation_backup.json", "w", encoding="utf-8") as f:
                json.dump(backup_data, f, indent=2, default=str)
            print("  [+] Түзету алдындағы резервтік көшірме сақталды: remediation_backup.json")
        except Exception as e:
            print(f"  [!] Резервтік көшірмені сақтау қатесі: {e}")

    print(f"=== ОРТАНЫ ҚАУІПСІЗДЕНДІРУ АЯҚТАЛДЫ! Аудит логтары: {LOG_FILE} ===")


if __name__ == "__main__":
    main()
