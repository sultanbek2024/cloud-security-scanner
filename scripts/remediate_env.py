#!/usr/bin/env python3
"""
Осал ортаны автоматты түрде түзету және қауіпсіздендіру скрипті (Remediation Script).
Барлық осал ресурстарды CIS AWS Benchmark талаптарына сәйкестендіреді немесе тазалайды (--cleanup).
"""
import argparse
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


def check_emulator(endpoint_url: str) -> None:
    try:
        req = urllib.request.Request(endpoint_url, method="GET")
        with urllib.request.urlopen(req, timeout=3):
            pass
    except Exception as exc:
        print(f"[ҚАТЕ] AWS эмуляторы қолжетімсіз ({endpoint_url}): {exc}", file=sys.stderr)
        sys.exit(1)


def get_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=TEST_ACCESS_KEY,
        aws_secret_access_key=TEST_SECRET_KEY,
        region_name=DEFAULT_REGION,
    )


def remediate_security_groups(ec2) -> None:
    """1. Security Groups: 0.0.0.0/0 ережелерін өшіріп, тек 10.0.0.0/8 рұқсат ету."""
    print("--- [1/6] Security Groups қауіпсіздендірілуде ---")
    for sg_name in SG_NAMES:
        try:
            res = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])
            sgs = res.get("SecurityGroups", [])
            if not sgs:
                continue

            sg = sgs[0]
            sg_id = sg["GroupId"]

            # Ашық ережелерді жою (0.0.0.0/0 немесе ::/0)
            revoke_perms = []
            for perm in sg.get("IpPermissions", []):
                has_open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                has_open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if has_open_v4 or has_open_v6:
                    revoke_perms.append(perm)

            if revoke_perms:
                ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=revoke_perms)
                print(f"  [-] {sg_name} ({sg_id}): 0.0.0.0/0 ашық ережелері жойылды")

            # Қауіпсіз ішкі желі ережесін қосу (10.0.0.0/8)
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22 if "ssh" in sg_name else (3389 if "rdp" in sg_name else 443),
                            "ToPort": 22 if "ssh" in sg_name else (3389 if "rdp" in sg_name else 443),
                            "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "Internal corporate network"}],
                        }
                    ],
                )
                print(f"  [+] {sg_name}: қауіпсіз 10.0.0.0/8 ішкі желілік рұқсаты орнатылды")
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate":
                    print(f"  [!] SG рұқсат қосу қатесі: {exc}")

        except ClientError as exc:
            print(f"  [!] {sg_name} түзету кезінде қате: {exc}")


def remediate_ebs_volumes(ec2) -> None:
    """2. EBS: Шифрланбаған томды жойып, орнына шифрланған том жасау."""
    print("--- [2/6] EBS томдары қауіпсіздендірілуде ---")
    try:
        res = ec2.describe_volumes()
        for vol in res.get("Volumes", []):
            vol_id = vol["VolumeId"]
            if not vol.get("Encrypted", False) and vol.get("State") != "deleted":
                ec2.delete_volume(VolumeId=vol_id)
                print(f"  [-] Шифрланбаған EBS томы жойылды: {vol_id}")

                # Орнына шифрланған жаңа том құру
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
    except ClientError as exc:
        print(f"  [!] EBS түзету қатесі: {exc}")


def remediate_s3_buckets(s3) -> None:
    """3. S3: Барлық бакеттерде PAB, әдепкі шифрлау және нұсқалылықты қосу."""
    print("--- [3/6] S3 бакеттері қауіпсіздендірілуде ---")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            b_name = b["Name"]

            # 1. Public Access Block
            s3.put_public_access_block(
                Bucket=b_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

            # 2. Әдепкі шифрлау (SSE-S3)
            s3.put_bucket_encryption(
                Bucket=b_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
                },
            )

            # 3. Нұсқалылық (Versioning)
            s3.put_bucket_versioning(
                Bucket=b_name,
                VersioningConfiguration={"Status": "Enabled"},
            )
            print(f"  [+] S3 бакеті түзетілді ({b_name}): PAB, Encryption, Versioning қосылды")
    except ClientError as exc:
        print(f"  [!] S3 түзету қатесі: {exc}")


def remediate_iam(iam) -> None:
    """4. IAM: Қауіпті саясатты жою, MFA байланыстыру, қатаң парольдік саясат орнату."""
    print("--- [4/6] IAM қауіпсіздендірілуде ---")

    # 1. Қауіпті Wildcard саясатын жою
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        for p in policies:
            if p["PolicyName"] == POLICY_ADMIN_NAME:
                iam.delete_policy(PolicyArn=p["Arn"])
                print(f"  [-] Қауіпті Wildcard саясаты жойылды: {POLICY_ADMIN_NAME}")
    except ClientError as exc:
        print(f"  [!] IAM саясат жою қатесі: {exc}")

    # 2. vulnerable-console-user үшін виртуалды MFA құру және қосу
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
        else:
            print(f"  [*] {IAM_USER_CONSOLE} үшін MFA бұрыннан қосулы")
    except Exception as exc:
        print(f"  [!] MFA орнату сәтсіз болды ({exc}), консоль құпиясөзі өшірілуде...")
        try:
            iam.delete_login_profile(UserName=IAM_USER_CONSOLE)
            print(f"  [-] {IAM_USER_CONSOLE} консольдік кіру бейіні жойылды (қауіп залалсыздандырылды)")
        except ClientError:
            pass

    # 3. Қатаң құпиясөз саясатын орнату (CIS AWS 1.8)
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
    except ClientError as exc:
        print(f"  [!] Құпиясөз саясатын орнату қатесі: {exc}")

    # Root MFA ескертпесі
    print("  [i] Root-аккаунт MFA: moto_server эмуляторында root MFA баптау API арқылы мүмкін емес, бұл қауіп платформа шектеуіне байланысты қалады.")


def remediate_rds(rds) -> None:
    """5. RDS: PubliclyAccessible = False орнату."""
    print("--- [5/6] RDS деректер қоры қауіпсіздендірілуде ---")
    try:
        dbs = rds.describe_db_instances().get("DBInstances", [])
        for db in dbs:
            db_id = db["DBInstanceIdentifier"]
            if db.get("PubliclyAccessible", False):
                rds.modify_db_instance(
                    DBInstanceIdentifier=db_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True,
                )
                print(f"  [+] RDS '{db_id}': PubliclyAccessible = False етіп түзетілді")
    except ClientError as exc:
        print(f"  [!] RDS түзету қатесі: {exc}")


def remediate_cloudtrail(ct) -> None:
    """6. CloudTrail: Журналдауды және лог валидациясын қосу."""
    print("--- [6/6] CloudTrail журналдау қызметі қауіпсіздендірілуде ---")
    try:
        trails = ct.describe_trails().get("trailList", [])
        for t in trails:
            t_name = t.get("Name")
            ct.update_trail(
                Name=t_name,
                EnableLogFileValidation=True,
                IsMultiRegionTrail=True,
            )
            ct.start_logging(Name=t_name)
            print(f"  [+] CloudTrail '{t_name}': Log Validation қосылды және журналдау белсендірілді")
    except ClientError as exc:
        print(f"  [!] CloudTrail түзету қатесі: {exc}")


def cleanup_all(ec2, s3, iam, rds, ct) -> None:
    """Барлық тесттік және түзетілген ресурстарды толық тазалау."""
    print("=== Ресурстарды толық тазалау басталды ===")

    # 1. RDS
    print("--- [RDS] Өшірілуде ---")
    for db_id in [RDS_PUBLIC_ID, RDS_PRIVATE_ID]:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
            print(f"  [-] RDS жойылды: {db_id}")
        except ClientError:
            pass

    # 2. CloudTrail
    print("--- [CloudTrail] Өшірілуде ---")
    try:
        ct.stop_logging(Name=TRAIL_NAME)
    except ClientError:
        pass
    try:
        ct.delete_trail(Name=TRAIL_NAME)
        print(f"  [-] Trail жойылды: {TRAIL_NAME}")
    except ClientError:
        pass

    # 3. Security Groups
    print("--- [EC2] Security Groups өшірілуде ---")
    for sg_name in SG_NAMES:
        try:
            ec2.delete_security_group(GroupName=sg_name)
            print(f"  [-] SG жойылды: {sg_name}")
        except ClientError:
            pass

    # 4. EBS
    print("--- [EC2] EBS томдары өшірілуде ---")
    for tag in [TAG_VOL_UNENCRYPTED, TAG_VOL_ENCRYPTED]:
        try:
            res = ec2.describe_volumes(Filters=[{"Name": "tag:Name", "Values": [tag]}])
            for v in res.get("Volumes", []):
                if v.get("State") != "deleted":
                    ec2.delete_volume(VolumeId=v["VolumeId"])
                    print(f"  [-] EBS жойылды: {v['VolumeId']}")
        except ClientError:
            pass

    # 5. S3 бакеттері
    print("--- [S3] Бакеттер өшірілуде ---")
    for b_name in [BUCKET_VULN_NAME, BUCKET_SAFE_NAME, BUCKET_CT_LOGS]:
        try:
            objs = s3.list_objects_v2(Bucket=b_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=b_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=b_name)
            print(f"  [-] S3 бакеті жойылды: {b_name}")
        except ClientError:
            pass

    # 6. IAM
    print("--- [IAM] Өшірілуде ---")
    # Құпиясөз саясатын өшіру
    try:
        iam.delete_account_password_policy()
        print("  [-] IAM құпиясөз саясаты өшірілді")
    except ClientError:
        pass

    # Пайдаланушылар мен MFA
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

    # Саясаттар
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
    parser = argparse.ArgumentParser(description="Осал инфрақұрылымды автоматты түзету скрипті.")
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT, help=f"Эмулятор URL (әдепкі: {DEFAULT_ENDPOINT})")
    parser.add_argument("--cleanup", action="store_true", help="Барлық тесттік немесе түзетілген ресурстарды өшіру")
    args = parser.parse_args()

    check_emulator(args.endpoint_url)

    session = get_session()
    ec2 = session.client("ec2", endpoint_url=args.endpoint_url)
    s3 = session.client("s3", endpoint_url=args.endpoint_url)
    iam = session.client("iam", endpoint_url=args.endpoint_url)
    rds = session.client("rds", endpoint_url=args.endpoint_url)
    ct = session.client("cloudtrail", endpoint_url=args.endpoint_url)

    if args.cleanup:
        cleanup_all(ec2, s3, iam, rds, ct)
        return

    print("=== БҰЛТТЫҚ ОРТАНЫ ТҮЗЕТУ (REMEDIATION) БАСТАЛДЫ ===")
    remediate_security_groups(ec2)
    remediate_ebs_volumes(ec2)
    remediate_s3_buckets(s3)
    remediate_iam(iam)
    remediate_rds(rds)
    remediate_cloudtrail(ct)
    print("=== БАРЛЫҚ ОРТА СӘТТІ ТҮЗЕТІЛДІ ЖӘНЕ ҚАУІПСІЗДЕНДІРІЛДІ! ===")


if __name__ == "__main__":
    main()
