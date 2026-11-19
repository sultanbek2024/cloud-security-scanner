"""
Configuration Drift Detection (Ауытқуды анықтау) қозғалтқышы.
Terraform бастапқы коды мен бұлттық ортаның (AWS) нақты күйін салыстырады.
"""
import logging
import re
from typing import List, Dict, Any, Tuple, Optional
from core.models import Finding
from iac.parser import TerraformResource

logger = logging.getLogger(__name__)


def correlate_and_detect_drift(
    live_findings: List[Finding],
    iac_resources: List[TerraformResource],
) -> List[Finding]:
    """
    Бұлттан табылған қауіптер (live_findings) мен Terraform кодын (iac_resources) салыстырып,
    конфигурациялық ауытқуларды (Configuration Drift) анықтайды:

    1. Бұлтта бар қауіп кодта қауіпсіз жазылған болса -> Тікелей DRIFT (рұқсатсыз қолмен өзгертілген).
    2. Бұлтта бар осал ресурс кодта мүлдем жоқ болса -> Shadow Infrastructure (кодтан тыс құрылған).

    :param live_findings: AWS ортасынан табылған қауіптер
    :param iac_resources: Terraform-да сипатталған ресурстар
    :return: Drift белгісі қойылған және жаңа Drift анықтамалары қосылған Finding тізімі
    """
    if not iac_resources:
        return live_findings

    # Terraform ресурстарын индекстеу
    iac_buckets: Dict[str, TerraformResource] = {}
    iac_security_groups: Dict[str, TerraformResource] = {}
    iac_db_instances: Dict[str, TerraformResource] = {}
    iac_ebs_volumes: Dict[str, TerraformResource] = {}

    for res in iac_resources:
        if res.resource_type == "aws_s3_bucket":
            b_name = str(res.config.get("bucket", res.resource_name)).strip('"\'')
            iac_buckets[b_name] = res
            iac_buckets[res.resource_name] = res

        elif res.resource_type == "aws_security_group":
            sg_name = str(res.config.get("name", res.resource_name)).strip('"\'')
            iac_security_groups[sg_name] = res
            iac_security_groups[res.resource_name] = res

        elif res.resource_type == "aws_db_instance":
            db_id = str(res.config.get("identifier", res.resource_name)).strip('"\'')
            iac_db_instances[db_id] = res
            iac_db_instances[res.resource_name] = res

        elif res.resource_type == "aws_ebs_volume":
            iac_ebs_volumes[res.resource_name] = res

    drift_detected_count = 0

    for finding in live_findings:
        # 1. Security Group (EC2-001, EC2-003, EC2-004)
        if finding.rule_id in ("EC2-001", "EC2-003", "EC2-004"):
            sg_matched_res = _match_security_group(finding.resource, iac_security_groups)
            if sg_matched_res:
                # Кодта бұл порт ашық жазылған ба?
                is_open_in_code = _is_sg_open_in_iac(sg_matched_res, finding.rule_id)
                if not is_open_in_code:
                    _mark_as_drift(
                        finding,
                        reason="Terraform кодында бұл порт ашылмаған. Өзгеріс бұлт консолінде (ClickOps) қолмен рұқсатсыз енгізілген!"
                    )
                    drift_detected_count += 1
            else:
                _mark_as_drift(
                    finding,
                    reason="Бұл Security Group Terraform кодында мүлдем жоқ (Shadow / Unmanaged Resource). Ол бұлтта кодтық бақылаусыз қолмен құрылған!"
                )
                drift_detected_count += 1

        # 2. S3 бакеттері (S3-001, S3-002, S3-003)
        elif finding.rule_id in ("S3-001", "S3-002", "S3-003"):
            bucket_name = _extract_bucket_name(finding.resource)
            if bucket_name in iac_buckets:
                b_res = iac_buckets[bucket_name]
                is_drift, drift_reason = _check_s3_drift(b_res, finding.rule_id)
                if is_drift:
                    _mark_as_drift(finding, reason=drift_reason)
                    drift_detected_count += 1
            else:
                _mark_as_drift(
                    finding,
                    reason="Бұл S3 бакеті Terraform кодында тіркелмеген (Shadow / Unmanaged Storage Bucket)!"
                )
                drift_detected_count += 1

        # 3. RDS (RDS-001)
        elif finding.rule_id == "RDS-001":
            matched_db = _match_rds_instance(finding.resource, iac_db_instances)
            if matched_db:
                pub = str(matched_db.config.get("publicly_accessible", "false")).strip('"\'').lower()
                if pub != "true":
                    _mark_as_drift(
                        finding,
                        reason="Terraform кодында дерекқор жабық (publicly_accessible=false), бірақ бұлтта қолмен интернетке ашылған!"
                    )
                    drift_detected_count += 1
            else:
                _mark_as_drift(
                    finding,
                    reason="Бұл RDS дерекқоры Terraform кодында мүлдем жоқ (Shadow Database)! Ол бұлтта қолмен құрылған."
                )
                drift_detected_count += 1

    logger.info("Drift талдауы аяқталды. Анықталған ауытқулар (Drift) саны: %d", drift_detected_count)
    return live_findings


def _extract_bucket_name(resource_str: str) -> str:
    """arn:aws:s3:::my-bucket немесе my-bucket жолынан атауын алады."""
    return resource_str.replace("arn:aws:s3:::", "").strip()


def _match_security_group(resource_str: str, iac_sgs: Dict[str, TerraformResource]) -> Optional[TerraformResource]:
    """
    Ресурс жолынан нақты сәйкес келетін IaC SG табады.
    Форматы: 'sg-335329e8fdebcde49 (vulnerable-ssh-sg) [us-east-1]'
    Дәл сәйкестікті тексереді (подстроковое false positive болдырмау үшін).
    """
    m = re.search(r'\(([^)]+)\)', resource_str)
    extracted_name = m.group(1).strip() if m else resource_str.strip()

    if extracted_name in iac_sgs:
        return iac_sgs[extracted_name]

    # Тікелей атаулармен тексеру
    for name, res in iac_sgs.items():
        if name == extracted_name:
            return res
    return None


def _match_rds_instance(resource_str: str, iac_dbs: Dict[str, TerraformResource]) -> Optional[TerraformResource]:
    """RDS инстансының атауын нақты сәйкестендіреді."""
    for db_name, db_res in iac_dbs.items():
        # Ресурс ішінде сөз шекарасы бойынша сәйкестік немесе толық теңдік
        pattern = r'(?:\b|_|-)' + re.escape(db_name) + r'(?:\b|_|-)'
        if db_name == resource_str or re.search(pattern, resource_str):
            return db_res
    return None


def _check_s3_drift(b_res: TerraformResource, rule_id: str) -> Tuple[bool, str]:
    """
    S3 ережесінің түріне қарай нақты Drift күйін анықтайды.
    """
    if rule_id == "S3-001":
        # Public Access Block
        acl = str(b_res.config.get("acl", "private")).strip('"\'')
        if acl not in ("public-read", "public-read-write"):
            return True, "Terraform кодында бакет қауіпсіз (private) деп жазылған, бірақ бұлтта қолмен жария қолжетімділік ашылған!"
        return False, ""

    elif rule_id == "S3-002":
        # Әдепкі шифрлау: кодта бапталған ба?
        sse = b_res.config.get("server_side_encryption_configuration")
        if sse is not None:
            return True, "Terraform кодында шифрлау (SSE) қосылған, бірақ бұлтта ол қолмен өшірілген!"
        # Егер кодтың өзінде шифрлау жазылмаса, бұл ауытқу емес, кодтағы қате
        return False, ""

    elif rule_id == "S3-003":
        # Нұсқалау (versioning)
        v_conf = b_res.config.get("versioning", {})
        if isinstance(v_conf, dict) and str(v_conf.get("enabled", "")).lower() == "true":
            return True, "Terraform кодында нұсқалау (versioning) қосылған, бірақ бұлтта ол өшірілген!"
        return False, ""

    return False, ""


def _is_sg_open_in_iac(sg_res: TerraformResource, rule_id: str) -> bool:
    """Security Group Terraform кодында осы қауіпті порт ашылған ба тексереді."""
    ingress_list = sg_res.config.get("ingress", [])
    if isinstance(ingress_list, dict):
        ingress_list = [ingress_list]

    for ing in ingress_list:
        if not isinstance(ing, dict):
            continue
        cidrs = ing.get("cidr_blocks", [])
        ipv6_cidrs = ing.get("ipv6_cidr_blocks", [])
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        if isinstance(ipv6_cidrs, str):
            ipv6_cidrs = [ipv6_cidrs]

        clean_cidrs = [str(c).strip('"\'') for c in list(cidrs) + list(ipv6_cidrs)]
        if not any(c in ("0.0.0.0/0", "::/0") for c in clean_cidrs):
            continue

        proto = str(ing.get("protocol", "")).strip('"\'').lower()
        from_port = ing.get("from_port")
        to_port = ing.get("to_port")
        try:
            if from_port is not None:
                from_port = int(str(from_port).strip('"\''))
            if to_port is not None:
                to_port = int(str(to_port).strip('"\''))
        except (ValueError, TypeError):
            pass

        if rule_id == "EC2-001":  # SSH
            if proto == "-1" or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                return True
        elif rule_id == "EC2-003":  # RDP
            if proto == "-1" or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port):
                return True
        elif rule_id == "EC2-004":  # All ports
            if proto == "-1" or (from_port in (0, 1) and to_port == 65535):
                return True

    return False


def _mark_as_drift(finding: Finding, reason: str) -> None:
    """Осалдық нысанына Drift белгісін және ескертуін жазады."""
    finding.is_drift = True
    if not finding.title.startswith("[DRIFT]"):
        finding.title = f"[DRIFT] {finding.title}"
    finding.description = f"⚠️ [КОНФИГУРАЦИЯЛЫҚ АУЫТҚУ (DRIFT)]:\n{reason}\n\nБастапқы сипаттамасы: {finding.description}"
