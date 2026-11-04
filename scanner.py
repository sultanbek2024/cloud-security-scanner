#!/usr/bin/env python3
"""
Бұлттық инфрақұрылымның конфигурациялық осалдықтарын анықтайтын және
қауіпсіздік деңгейін бағалайтын консольдік бағдарлама (AWS Cloud Scanner).
"""
import argparse
import logging
import os
import sys
from typing import List
import boto3

from core.engine import ScanEngine
from core.models import Finding, Severity
from core.scoring import calculate_score, group_findings_by_severity
from report.html_report import generate_html_report
from report.json_report import generate_json_report

# Windows жүйесінде қазақша әріптер дұрыс шығуы үшін UTF-8 қосу
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    # Windows консолінде ANSI түстерін белсендіру
    os.system("")

# ANSI түстер коды
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"

SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def build_parser() -> argparse.ArgumentParser:
    """
    CLI аргументтер талдаушысын (argparse) құру.
    Барлық сипаттамалар қазақ тілінде көрсетіледі.
    """
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="AWS бұлттық инфрақұрылымының конфигурациялық қауіпсіздігін тексеретін автоматтандырылған құрал.",
        epilog="Мысал: python scanner.py --profile default --region us-east-1 --all-regions --output report.html",
    )

    parser.add_argument(
        "--provider",
        choices=["aws"],
        default="aws",
        help="Бұлттық қызмет көрсетуші провайдер (әдепкі бойынша: aws).",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Қолданылатын AWS CLI бейінінің (profile) атауы.",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="Тексерілетін негізгі AWS аймағы (әдепкі бойынша: us-east-1).",
    )
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="Барлық қолжетімді AWS аймақтары бойынша сканерлеуді іске қосу (EC2, RDS үшін).",
    )
    parser.add_argument(
        "--endpoint-url",
        type=str,
        default=None,
        help="Арнайы endpoint URL (LocalStack тестілеу үшін, мысалы: http://localhost:4566).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="report.html",
        help="Қалыптастырылатын есеп файлының жолы (әдепкі бойынша: report.html).",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Қосымша JSON есеп файлын бірге сақтау жолы (мысалы: report.json).",
    )
    parser.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Негізгі есеп беру форматы: html немесе json (әдепкі бойынша: html).",
    )
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Есепке енгізілетін минималды қауіптілік деңгейі (LOW, MEDIUM, HIGH, CRITICAL).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Толық журналдау режимін қосу (Debug logs).",
    )

    return parser


def create_boto3_session(
    profile: str | None,
    region: str,
    endpoint_url: str | None,
    all_regions: bool = False,
) -> boto3.Session:
    """
    Параметрлерге сәйкес boto3.Session данасын қалыптастырады.
    LocalStack немесе арнайы endpoint көрсетілсе, клиенттерді сәйкесінше баптайды.
    """
    session = boto3.Session(profile_name=profile, region_name=region)

    # Егер LocalStack / moto_server endpoint көрсетіліп, бірақ куәліктер табылмаса,
    # сұраныстарға қол қою үшін тесттік кілттерді орнату
    if endpoint_url and session.get_credentials() is None:
        session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name=region,
        )

    if endpoint_url:
        original_client = session.client

        def client_with_endpoint(service_name: str, *args, **kwargs):
            if "endpoint_url" not in kwargs:
                kwargs["endpoint_url"] = endpoint_url
            return original_client(service_name, *args, **kwargs)

        session.client = client_with_endpoint  # type: ignore[assignment]

    # Аймақтарды баптау
    if all_regions:
        try:
            ec2_client = session.client("ec2")
            resp = ec2_client.describe_regions(AllRegions=False)
            target_regs = [r["RegionName"] for r in resp.get("Regions", [])]
            session.target_regions = target_regs if target_regs else [region]  # type: ignore[attr-defined]
        except Exception:
            session.target_regions = [region]  # type: ignore[attr-defined]
    else:
        session.target_regions = [region]  # type: ignore[attr-defined]

    return session


def print_summary(
    findings: List[Finding],
    score: int,
    grade: str,
    total_checks: int,
    output_path: str,
    provider: str,
    region: str,
) -> None:
    """
    Консольге түрлі-түсті қорытынды нәтижелерді шығарады.
    """
    grouped = group_findings_by_severity(findings)
    crit_count = len(grouped.get(Severity.CRITICAL, []))
    high_count = len(grouped.get(Severity.HIGH, []))
    med_count = len(grouped.get(Severity.MEDIUM, []))
    low_count = len(grouped.get(Severity.LOW, []))

    grade_colors = {
        "A": COLOR_GREEN,
        "B": COLOR_BLUE,
        "C": COLOR_YELLOW,
        "D": COLOR_ORANGE,
        "F": COLOR_RED,
    }
    g_color = grade_colors.get(grade, COLOR_RESET)

    print()
    print(f"{COLOR_BOLD}{COLOR_CYAN}======================================================================{COLOR_RESET}")
    print(f"{COLOR_BOLD}         БҰЛТТЫҚ ҚАУІПСІЗДІК СКАНЕРІ (AWS Cloud Scanner){COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}======================================================================{COLOR_RESET}")
    print(f"  Провайдер: {COLOR_BOLD}{provider}{COLOR_RESET} | Аймақ: {COLOR_BOLD}{region}{COLOR_RESET} | Барлық тексерулер: {COLOR_BOLD}{total_checks}{COLOR_RESET}")
    print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"  {COLOR_BOLD}Тексеру қорытындысы:{COLOR_RESET}")
    print(f"    {COLOR_RED}[!] Сыни (CRITICAL):   {crit_count}{COLOR_RESET}")
    print(f"    {COLOR_ORANGE}[!] Жоғары (HIGH):     {high_count}{COLOR_RESET}")
    print(f"    {COLOR_YELLOW}[*] Орташа (MEDIUM):   {med_count}{COLOR_RESET}")
    print(f"    {COLOR_BLUE}[-] Төмен (LOW):       {low_count}{COLOR_RESET}")
    print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"  {COLOR_BOLD}Қауіпсіздік деңгейі:{COLOR_RESET}  {g_color}{COLOR_BOLD}{score} / 100 (Рейтинг: {grade}){COLOR_RESET}")
    print(f"  {COLOR_BOLD}Есеп сақталды:{COLOR_RESET}        {COLOR_GREEN}{output_path}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}======================================================================{COLOR_RESET}")
    print()


def main() -> int:
    """
    Бағдарламаның негізгі орындалу нүктесі.
    
    :return: 1 - егер CRITICAL немесе HIGH осалдық табылса; 0 - сәтті болса
    """
    parser = build_parser()
    args = parser.parse_args()

    # Журналдау деңгейін баптау
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        session = create_boto3_session(
            profile=args.profile,
            region=args.region,
            endpoint_url=args.endpoint_url,
            all_regions=args.all_regions,
        )
        if not args.endpoint_url and session.get_credentials() is None:
            print(
                f"{COLOR_YELLOW}[ЕСКЕРТУ] AWS куәліктері (credentials) табылмады. "
                f"'aws configure' орындаңыз немесе --endpoint-url арқылы LocalStack пайдаланыңыз.{COLOR_RESET}\n",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"{COLOR_RED}Қате: AWS сессиясын құру мүмкін болмады: {exc}{COLOR_RESET}", file=sys.stderr)
        return 1

    engine = ScanEngine(session=session)
    all_findings, total_checks = engine.run()

    # Минималды қауіптілік деңгейі бойынша сүзу
    filtered_findings = all_findings
    if args.min_severity:
        min_sev_enum = Severity(args.min_severity)
        min_threshold = SEVERITY_ORDER[min_sev_enum]
        filtered_findings = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= min_threshold]

    # Қауіпсіздік бағасын есептеу
    score, grade = calculate_score(filtered_findings, total_checks)

    region_display = f"all-regions ({len(getattr(session, 'target_regions', []))})" if args.all_regions else args.region

    # Есепті экспорттау
    try:
        if args.format == "json":
            generate_json_report(
                findings=filtered_findings,
                score=score,
                grade=grade,
                output_path=args.output,
                provider=args.provider,
                region=region_display,
            )
        else:
            generate_html_report(
                findings=filtered_findings,
                score=score,
                grade=grade,
                output_path=args.output,
                provider=args.provider,
                region=region_display,
            )

        # Егер қосымша JSON есебі сұралса және негізгі формат json болмаса
        if args.json_output and args.format != "json":
            generate_json_report(
                findings=filtered_findings,
                score=score,
                grade=grade,
                output_path=args.json_output,
                provider=args.provider,
                region=region_display,
            )
    except Exception as exc:
        print(f"{COLOR_RED}Қате: Есеп файлын сақтау сәтсіз аяқталды: {exc}{COLOR_RESET}", file=sys.stderr)
        return 1

    # Нәтижелерді консольге шығару
    print_summary(
        findings=filtered_findings,
        score=score,
        grade=grade,
        total_checks=total_checks,
        output_path=args.output,
        provider=args.provider,
        region=region_display,
    )

    # CI/CD үшін қайтару коды: CRITICAL немесе HIGH табылса, 1 қайтару
    has_critical_or_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for f in filtered_findings
    )
    return 1 if has_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
