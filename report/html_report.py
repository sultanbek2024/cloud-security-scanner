"""
Jinja2 арқылы заманауи интерактивті HTML-есеп жасау модулі.
"""
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader

from core.models import Finding, Severity


def generate_html_report(
    findings: List[Finding],
    score: int,
    grade: str,
    output_path: str,
    provider: str = "aws",
    region: str = "us-east-1",
) -> None:
    """
    Сканерлеу нәтижелері негізінде автономды HTML-есеп файлын жасайды.
    
    :param findings: Табылған осалдықтар тізімі
    :param score: Инфрақұрылымның жалпы балы (0-100)
    :param grade: Рейтинг (A/B/C/D/F)
    :param output_path: Сақталатын HTML файлының жолы
    :param provider: Бұлттық провайдер
    :param region: AWS аймағы
    """
    counts: Dict[str, int] = {
        "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
        "high": sum(1 for f in findings if f.severity == Severity.HIGH),
        "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "low": sum(1 for f in findings if f.severity == Severity.LOW),
    }

    template_dir = Path(__file__).resolve().parent
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("template.html")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rendered_html = template.render(
        findings=findings,
        score=score,
        grade=grade,
        severity_counts=counts,
        scan_time=scan_time,
        provider=provider,
        region=region,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
