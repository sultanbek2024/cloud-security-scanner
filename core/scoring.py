"""
Бұлттық инфрақұрылымның қауіпсіздік деңгейін бағалау және ұпай есептеу модулі.
"""
from typing import Dict, List, Optional, Tuple
from core.models import Finding, Severity

# 15 негізгі ереженің әдепкі қауіптілік салмақтары
DEFAULT_RULE_SEVERITIES: Dict[str, Severity] = {
    # CRITICAL (10 балл) - 3 ереже = 30 (макс. айыппұл: 3 x 20 = 60)
    "IAM-002": Severity.CRITICAL,
    "IAM-004": Severity.CRITICAL,
    "RDS-001": Severity.CRITICAL,
    # HIGH (7 балл) - 5 ереже = 35 (макс. айыппұл: 5 x 14 = 70)
    "EC2-001": Severity.HIGH,
    "EC2-003": Severity.HIGH,
    "EC2-004": Severity.HIGH,
    "S3-001": Severity.HIGH,
    "CT-001": Severity.HIGH,
    # MEDIUM (4 балл) - 4 ереже = 16 (макс. айыппұл: 4 x 8 = 32)
    "EC2-002": Severity.MEDIUM,
    "S3-002": Severity.MEDIUM,
    "IAM-001": Severity.MEDIUM,
    "IAM-003": Severity.MEDIUM,
    # LOW (1 балл) - 3 ереже = 3 (макс. айыппұл: 3 x 2 = 6)
    "S3-003": Severity.LOW,
    "IAM-005": Severity.LOW,
    "CT-002": Severity.LOW,
}

# Барлық 15 ереженің шекті сыйымдылығы (Capacity = sum(2 * W_r)): 60 + 70 + 32 + 6 = 168
TOTAL_BENCHMARK_CAPACITY: int = sum(sev.weight * 2 for sev in DEFAULT_RULE_SEVERITIES.values())


def group_findings_by_severity(findings: List[Finding]) -> Dict[Severity, List[Finding]]:
    """
    Табылған осалдықтарды қауіптілік деңгейі (Severity) бойынша топтастырады.
    """
    grouped: Dict[Severity, List[Finding]] = {
        Severity.CRITICAL: [],
        Severity.HIGH: [],
        Severity.MEDIUM: [],
        Severity.LOW: [],
    }
    for finding in findings:
        if finding.severity in grouped:
            grouped[finding.severity].append(finding)
        else:
            grouped[finding.severity] = [finding]
    return grouped


def calculate_score(
    findings: List[Finding],
    total_checks: int = 15,
    rule_severities: Optional[Dict[str, Severity]] = None,
) -> Tuple[int, str]:
    """
    Инфрақұрылымның қауіпсіздік деңгейін (0-100 балл) және әріптік рейтингін (A/B/C/D/F) есептейді.
    
    Математикалық модель (Шекті сыйымдылық және кему заңы):
    1. Жүйенің толық сыйымдылығы (Capacity) = барлық тіркелген тексерулердің екі еселенген
       салмақтарының қосындысы (Capacity = sum(2 * W_r)).
       (Әдепкі 15 тексеру үшін: 3x20 + 5x14 + 4x8 + 3x2 = 168 балл).
    2. Бір ереже бойынша қайталанатын ресурстар үшін шекті кему заңы (diminishing penalty):
       P_r = W_r * (1 + 0.25 * min(n_r - 1, 4)).
       Бірінші ресурс ереженің 100% салмағын алады, қосымша әрбір ресурс +25% қосады (макс. +100%, яғни 2 * W_r).
    3. Айыппұл сыйымдылыққа қатысты пайызбен шегеріледі:
       Deduction = (sum(P_r) / Capacity) * 100.
       Score = max(0, min(100, 100 - round(Deduction))).
    4. Егер ортада кем дегенде бір CRITICAL осалдық қалса, рейтинг B деңгейінен жоғары бола алмайды
       (балл өзгермейді, бірақ рейтинг 'A' болса, 'B'-ға дейін төмендетіледі).

    Бағалау шкаласы:
      - 90 - 100: A (Үздік / Қауіпсіз, егер CRITICAL болмаса)
      - 80 - 89:  B (Жақсы)
      - 70 - 79:  C (Қанағаттанарлық)
      - 60 - 69:  D (Төмен деңгей)
      - 0  - 59:  F (Сыни қауіпті)
    """
    if not findings:
        return 100, "A"

    # Сыйымдылықты (Capacity) есептеу: sum(2 * W_r)
    if rule_severities:
        capacity = float(sum(s.weight * 2 for s in rule_severities.values()))
    elif total_checks != 15 and total_checks > 0:
        capacity = float(total_checks * (TOTAL_BENCHMARK_CAPACITY / 15.0))
    else:
        capacity = float(TOTAL_BENCHMARK_CAPACITY)

    capacity = max(1.0, capacity)

    # 1. Ережелер бойынша топтастыру
    rule_counts: Dict[str, Tuple[Severity, int]] = {}
    for finding in findings:
        rule_id = finding.rule_id
        if rule_id not in rule_counts:
            rule_counts[rule_id] = (finding.severity, 1)
        else:
            sev, count = rule_counts[rule_id]
            rule_counts[rule_id] = (sev, count + 1)

    # 2. Шекті кему заңымен айыппұл есептеу
    total_rule_penalty = 0.0
    for sev, count in rule_counts.values():
        base_weight = sev.weight
        marginal_multiplier = 1.0 + 0.25 * min(count - 1, 4)
        total_rule_penalty += base_weight * marginal_multiplier

    # 3. Нормаланған шегеру пайызы
    scaled_deduction = (total_rule_penalty / capacity) * 100.0
    final_score = max(0, min(100, int(round(100.0 - scaled_deduction))))

    if final_score >= 90:
        grade = "A"
    elif final_score >= 80:
        grade = "B"
    elif final_score >= 70:
        grade = "C"
    elif final_score >= 60:
        grade = "D"
    else:
        grade = "F"

    # 4. CRITICAL қауіп болса, рейтинг B деңгейінен жоғары бола алмайды
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    if has_critical and grade == "A":
        grade = "B"

    return final_score, grade
