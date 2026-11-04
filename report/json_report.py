"""
Сканерлеу нәтижелерін JSON форматында экспорттау модулі.
"""
import json
from datetime import datetime
from typing import Any, Dict, List

from core.models import Finding, Severity


def generate_json_report(
    findings: List[Finding],
    score: int,
    grade: str,
    output_path: str,
    provider: str = "aws",
    region: str = "us-east-1",
) -> None:
    """
    Сканерлеу қорытындыларын JSON файлына жазады.
    
    :param findings: Табылған осалдықтар тізімі
    :param score: Есептелген жалпы балл (0-100)
    :param grade: Әріптік рейтинг (A/B/C/D/F)
    :param output_path: Сақталатын файл жолы
    :param provider: Бұлттық провайдер атауы
    :param region: AWS аймағы
    """
    counts: Dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }

    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    report_data: Dict[str, Any] = {
        "metadata": {
            "scanner": "cloud-scanner",
            "scan_time": datetime.now().isoformat(),
            "provider": provider,
            "region": region,
        },
        "summary": {
            "score": score,
            "grade": grade,
            "total_findings": len(findings),
            "severity_counts": {
                "critical": counts[Severity.CRITICAL.value],
                "high": counts[Severity.HIGH.value],
                "medium": counts[Severity.MEDIUM.value],
                "low": counts[Severity.LOW.value],
            },
        },
        "findings": [finding.to_dict() for finding in findings],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
