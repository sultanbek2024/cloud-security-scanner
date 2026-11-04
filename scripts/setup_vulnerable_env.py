#!/usr/bin/env python3
"""
AWS эмуляторын (moto_server / LocalStack) тестілеуге арналған осал және қауіпсіз
ресурстармен толтыру немесе тазалау скрипті (15 ереже үшін кеңейтілген).
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
import boto3
from botocore.exceptions import ClientError

# Windows жүйесінде қазақша әріптер дұрыс шығуы үшін UTF-8 қосу
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# Басып шығаруды жедел көрсету үшін print функциясын бейімдеу
_orig_print = print
def print(*args, **kwargs):
    if "flush" not in kwargs:
        kwargs["flush"] = True
    _orig_print(*args, **kwargs)

# Тұрақты параметрлер
DEFAULT_ENDPOINT = "http://localhost:4566"
DEFAULT_REGION = "us-east-1"
TEST_ACCESS_KEY = "test"
TEST_SECRET_KEY = "test"

# Ресурс атаулары
SG_SSH_NAME = "vulnerable-ssh-sg"
SG_RDP_NAME = "vulnerable-rdp-sg"
SG_ALL_NAME = "vulnerable-allports-sg"
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
TRAIL_VULN_NAME = "vulnerable-trail-no-validation"


def check_emulator_health(endpoint_url: str) -> None:
    """AWS эмуляторының қолжетімділігін тексереді."""
    try:
        req = urllib.request.Request(endpoint_url, method="GET")
        with urllib.request.urlopen(req, timeout=3):
            pass
    except Exception as exc:
        print(
            f"[ҚАТЕ] AWS эмуляторына ({endpoint_url}) қосылу мүмкін болмады!\n"
            f"Себебі: {exc}\n"
            f"Эмулятордың (moto_server) қосулы тұрғанын тексеріңіз.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_boto3_session() -> boto3.Session:
    """Тесттік кілттермен boto3 сессиясын құру."""
    return boto3.Session(
        aws_access_key_id=TEST_ACCESS_KEY,
        aws_secret_access_key=TEST_SECRET_KEY,
        region_name=DEFAULT_REGION,
    )


def setup_security_groups(ec2) -> None:
    """
    1. EC2-001: Ашық SSH (22)
    2. EC2-003: Ашық RDP (3389)
    3. EC2-004: Барлық трафикке ашық (-1)
    """
    print("--- [EC2] Security Groups бапталуда ---")

    # 1. SSH (22)
    try:
        res = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_SSH_NAME]}])
        if not res.get("SecurityGroups"):
            sg = ec2.create_security_group(GroupName=SG_SSH_NAME, Description="Open SSH port 22")
            ec2.authorize_security_group_ingress(
                GroupId=sg["GroupId"],
                IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
            )
            print(f"  [+] Қауіпті Security Group құрылды (SSH 22): {SG_SSH_NAME}")
        else:
            print(f"  [*] Security Group бұрыннан бар (SSH 22): {SG_SSH_NAME}")
    except ClientError as exc:
        print(f"  [!] {SG_SSH_NAME} қате: {exc}")

    # 2. RDP (3389)
    try:
        res = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_RDP_NAME]}])
        if not res.get("SecurityGroups"):
            sg = ec2.create_security_group(GroupName=SG_RDP_NAME, Description="Open RDP port 3389")
            ec2.authorize_security_group_ingress(
                GroupId=sg["GroupId"],
                IpPermissions=[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
            )
            print(f"  [+] Қауіпті Security Group құрылды (RDP 3389): {SG_RDP_NAME}")
        else:
            print(f"  [*] Security Group бұрыннан бар (RDP 3389): {SG_RDP_NAME}")
    except ClientError as exc:
        print(f"  [!] {SG_RDP_NAME} қате: {exc}")

    # 3. All Ports / All Traffic (EC2-004)
    try:
        res = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_ALL_NAME]}])
        if not res.get("SecurityGroups"):
            sg = ec2.create_security_group(GroupName=SG_ALL_NAME, Description="Open all traffic")
            ec2.authorize_security_group_ingress(
                GroupId=sg["GroupId"],
                IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
            )
            print(f"  [+] Қауіпті Security Group құрылды (All traffic): {SG_ALL_NAME}")
        else:
            print(f"  [*] Security Group бұрыннан бар (All traffic): {SG_ALL_NAME}")
    except ClientError as exc:
        print(f"  [!] {SG_ALL_NAME} қате: {exc}")


def setup_ebs_volumes(ec2) -> None:
    """
    EC2-002: Незашифрованный және зашифрованный EBS томдары.
    """
    print("--- [EC2] EBS томдары бапталуда ---")
    try:
        res = ec2.describe_volumes(Filters=[{"Name": "tag:Name", "Values": [TAG_VOL_UNENCRYPTED]}])
        active = [v for v in res.get("Volumes", []) if v.get("State") != "deleted"]
        if not active:
            vol = ec2.create_volume(
                AvailabilityZone="us-east-1a", Size=10, Encrypted=False,
                TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": TAG_VOL_UNENCRYPTED}]}]
            )
            print(f"  [+] Шифрланбаған EBS томы құрылды: {vol['VolumeId']}")
        else:
            print(f"  [*] Шифрланбаған EBS томы бұрыннан бар: {active[0]['VolumeId']}")
    except ClientError as exc:
        print(f"  [!] EBS қате: {exc}")

    try:
        res = ec2.describe_volumes(Filters=[{"Name": "tag:Name", "Values": [TAG_VOL_ENCRYPTED]}])
        active = [v for v in res.get("Volumes", []) if v.get("State") != "deleted"]
        if not active:
            vol = ec2.create_volume(
                AvailabilityZone="us-east-1a", Size=10, Encrypted=True,
                TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": TAG_VOL_ENCRYPTED}]}]
            )
            print(f"  [+] Қорғалған (шифрланған) EBS томы құрылды: {vol['VolumeId']}")
        else:
            print(f"  [*] Қорғалған EBS томы бұрыннан бар: {active[0]['VolumeId']}")
    except ClientError as exc:
        print(f"  [!] Шифрланған EBS қате: {exc}")


def setup_s3_buckets(s3) -> None:
    """
    S3-001 (Public Access Block), S3-002 (Default Encryption), S3-003 (Versioning).
    """
    print("--- [S3] Бакеттер бапталуда ---")
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    # Осал бакет: PAB жоқ, шифрлау жоқ, нұсқалылық жоқ
    if BUCKET_VULN_NAME not in existing:
        s3.create_bucket(Bucket=BUCKET_VULN_NAME)
        print(f"  [+] Осал S3 бакеті құрылды (PAB, Encryption, Versioning жоқ): {BUCKET_VULN_NAME}")
    else:
        print(f"  [*] Осал S3 бакеті бұрыннан бар: {BUCKET_VULN_NAME}")

    # Қауіпсіз бакет: PAB бар, шифрлау бар, нұсқалылық бар
    if BUCKET_SAFE_NAME not in existing:
        s3.create_bucket(Bucket=BUCKET_SAFE_NAME)
        s3.put_public_access_block(
            Bucket=BUCKET_SAFE_NAME,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True
            }
        )
        s3.put_bucket_encryption(
            Bucket=BUCKET_SAFE_NAME,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        )
        s3.put_bucket_versioning(
            Bucket=BUCKET_SAFE_NAME,
            VersioningConfiguration={"Status": "Enabled"}
        )
        print(f"  [+] Қорғалған S3 бакеті құрылды (PAB, SSE, Versioning қосулы): {BUCKET_SAFE_NAME}")
    else:
        print(f"  [*] Қорғалған S3 бакеті бұрыннан бар: {BUCKET_SAFE_NAME}")


def setup_iam(iam) -> None:
    """
    IAM-001 (MFA-сыз консоль), IAM-003 (Access Key), IAM-004 (Wildcard Policy), IAM-005 (Password Policy).
    """
    print("--- [IAM] Пайдаланушылар мен саясаттар бапталуда ---")

    # 1. IAM-001: Консоль құпиясөзі бар, бірақ MFA жоқ пайдаланушы
    try:
        iam.get_user(UserName=IAM_USER_CONSOLE)
    except ClientError:
        iam.create_user(UserName=IAM_USER_CONSOLE)
        print(f"  [+] Пайдаланушы құрылды: {IAM_USER_CONSOLE}")

    try:
        iam.get_login_profile(UserName=IAM_USER_CONSOLE)
    except ClientError:
        iam.create_login_profile(UserName=IAM_USER_CONSOLE, Password="SuperPassword2026!")
        print(f"  [+] Консоль құпиясөзі орнатылды (MFA-сыз): {IAM_USER_CONSOLE}")

    # 2. IAM-003: Access Key бар пайдаланушы
    try:
        iam.get_user(UserName=IAM_USER_API)
    except ClientError:
        iam.create_user(UserName=IAM_USER_API)
        print(f"  [+] Пайдаланушы құрылды: {IAM_USER_API}")

    keys = iam.list_access_keys(UserName=IAM_USER_API).get("AccessKeyMetadata", [])
    if not keys:
        iam.create_access_key(UserName=IAM_USER_API)
        print(f"  [+] Access Key құрылды: {IAM_USER_API}")

    # 3. IAM-004: Әкімшілік Wildcard саясаты (Action: *, Resource: *)
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        names = [p["PolicyName"] for p in policies]
        if POLICY_ADMIN_NAME not in names:
            admin_doc = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
            iam.create_policy(PolicyName=POLICY_ADMIN_NAME, PolicyDocument=json.dumps(admin_doc))
            print(f"  [+] Қауіпті Wildcard саясаты құрылды: {POLICY_ADMIN_NAME}")
        else:
            print(f"  [*] Wildcard саясаты бұрыннан бар: {POLICY_ADMIN_NAME}")

        if POLICY_SAFE_NAME not in names:
            safe_doc = {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::safe/*"}]
            }
            iam.create_policy(PolicyName=POLICY_SAFE_NAME, PolicyDocument=json.dumps(safe_doc))
            print(f"  [+] Қауіпсіз саясат құрылды: {POLICY_SAFE_NAME}")
    except ClientError as exc:
        print(f"  [!] IAM саясаттарын құру қатесі: {exc}")


def setup_rds(rds) -> None:
    """
    RDS-001: Жалпыға қолжетімді (Publicly Accessible) RDS данасы.
    """
    print("--- [RDS] Деректер қоры бапталуда ---")
    try:
        dbs = [db["DBInstanceIdentifier"] for db in rds.describe_db_instances().get("DBInstances", [])]

        if RDS_PUBLIC_ID not in dbs:
            rds.create_db_instance(
                DBInstanceIdentifier=RDS_PUBLIC_ID,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                PubliclyAccessible=True,
                AllocatedStorage=20,
            )
            print(f"  [+] Қауіпті ашық RDS құрылды (Publicly Accessible): {RDS_PUBLIC_ID}")
        else:
            print(f"  [*] Ашық RDS бұрыннан бар: {RDS_PUBLIC_ID}")

        if RDS_PRIVATE_ID not in dbs:
            rds.create_db_instance(
                DBInstanceIdentifier=RDS_PRIVATE_ID,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                PubliclyAccessible=False,
                AllocatedStorage=20,
            )
            print(f"  [+] Қорғалған жабық RDS құрылды: {RDS_PRIVATE_ID}")
        else:
            print(f"  [*] Жабық RDS бұрыннан бар: {RDS_PRIVATE_ID}")
    except ClientError as exc:
        print(f"  [!] RDS қате: {exc}")


def setup_cloudtrail(ct, s3) -> None:
    """
    CT-001 / CT-002: Лог валидациясы жоқ CloudTrail трейлі.
    """
    print("--- [CloudTrail] Журналдау қызметі бапталуда ---")
    try:
        # Лог бакетін тексеру
        existing_buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        if BUCKET_CT_LOGS not in existing_buckets:
            s3.create_bucket(Bucket=BUCKET_CT_LOGS)

        trails = [t.get("Name") for t in ct.describe_trails().get("trailList", [])]
        if TRAIL_VULN_NAME not in trails:
            ct.create_trail(
                Name=TRAIL_VULN_NAME,
                S3BucketName=BUCKET_CT_LOGS,
                EnableLogFileValidation=False,
            )
            print(f"  [+] Қауіпті CloudTrail трейлі құрылды (Log Validation өшірулі): {TRAIL_VULN_NAME}")
        else:
            print(f"  [*] CloudTrail трейлі бұрыннан бар: {TRAIL_VULN_NAME}")
    except ClientError as exc:
        print(f"  [!] CloudTrail қате: {exc}")


def cleanup_all(ec2, s3, iam, rds, ct) -> None:
    """Барлық құрылған тесттік ресурстарды өшіру."""
    print("=== Ресурстарды тазалау басталды ===")

    # 1. RDS тазалау
    print("--- [RDS] Өшірілуде ---")
    for db_id in [RDS_PUBLIC_ID, RDS_PRIVATE_ID]:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
            print(f"  [-] RDS жойылды: {db_id}")
        except ClientError:
            pass

    # 2. CloudTrail тазалау
    print("--- [CloudTrail] Өшірілуде ---")
    try:
        ct.delete_trail(Name=TRAIL_VULN_NAME)
        print(f"  [-] Trail жойылды: {TRAIL_VULN_NAME}")
    except ClientError:
        pass

    # 3. Security Groups
    print("--- [EC2] Security Groups өшірілуде ---")
    for sg_name in [SG_SSH_NAME, SG_RDP_NAME, SG_ALL_NAME]:
        try:
            ec2.delete_security_group(GroupName=sg_name)
            print(f"  [-] SG жойылды: {sg_name}")
        except ClientError:
            pass

    # 4. EBS Volumes
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

    # 6. IAM саясаттары мен пайдаланушылары
    print("--- [IAM] Өшірілуде ---")
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        for p in policies:
            if p["PolicyName"] in [POLICY_ADMIN_NAME, POLICY_SAFE_NAME]:
                iam.delete_policy(PolicyArn=p["Arn"])
                print(f"  [-] Саясат жойылды: {p['PolicyName']}")
    except ClientError:
        pass

    for u_name in [IAM_USER_CONSOLE, IAM_USER_API]:
        try:
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

    print("=== Ресурстар толық тазартылды! ===")


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS эмуляторын 15 тексеру үшін толтыру немесе тазалау скрипті.")
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT, help=f"Эмулятор URL (әдепкі: {DEFAULT_ENDPOINT})")
    parser.add_argument("--cleanup", action="store_true", help="Барлық тесттік ресурстарды өшіру")
    args = parser.parse_args()

    check_emulator_health(args.endpoint_url)

    session = get_boto3_session()
    ec2 = session.client("ec2", endpoint_url=args.endpoint_url)
    s3 = session.client("s3", endpoint_url=args.endpoint_url)
    iam = session.client("iam", endpoint_url=args.endpoint_url)
    rds = session.client("rds", endpoint_url=args.endpoint_url)
    ct = session.client("cloudtrail", endpoint_url=args.endpoint_url)

    if args.cleanup:
        cleanup_all(ec2, s3, iam, rds, ct)
        return

    print("=== AWS эмуляторын 15 тексеруге арналған ортамен толтыру басталды ===")
    setup_security_groups(ec2)
    setup_ebs_volumes(ec2)
    setup_s3_buckets(s3)
    setup_iam(iam)
    setup_rds(rds)
    setup_cloudtrail(ct, s3)
    print("=== Орта сәтті дайындалды! ===")


if __name__ == "__main__":
    main()
