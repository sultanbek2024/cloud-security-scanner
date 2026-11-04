#!/usr/bin/env python3
"""
Дипломдық жұмысқа арналған демонстрациялық сценарий (Сценарий «до/после»).
1. Осал ортаны сканерлейді -> report_before.html / report_before.json сақтайды.
2. Ремедиацияны (remediate_env.py) орындайды.
3. Қайта сканерлейді -> report_after.html / report_after.json сақтайды.
4. Консольге көрнекі салыстырмалы кестені шығарады.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

# Windows жүйесінде UTF-8 қосу
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    os.system("")

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BLUE = "\033[94m"

DEFAULT_ENDPOINT = "http://localhost:4566"
DEFAULT_REGION = "us-east-1"


def run_command(cmd_args: list[str]) -> int:
    """Команданы орындау."""
    res = subprocess.run(cmd_args, env=os.environ.copy())
    return res.returncode


def main() -> None:
    python_exe = sys.executable
    root_dir = Path(__file__).resolve().parent.parent

    scanner_path = str(root_dir / "scanner.py")
    remediate_path = str(root_dir / "scripts" / "remediate_env.py")

    report_before_html = str(root_dir / "report_before.html")
    report_before_json = str(root_dir / "report_before.json")
    report_after_html = str(root_dir / "report_after.html")
    report_after_json = str(root_dir / "report_after.json")

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{'='*70}{COLOR_RESET}")
    print(f"{COLOR_BOLD}   ДЕМОНСТРАЦИЯЛЫҚ СЦЕНАРИЙ: ТҮЗЕТУГЕ ДЕЙІН ЖӘНЕ КЕЙІН (BEFORE / AFTER){COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*70}{COLOR_RESET}\n")

    # 1-ҚАДАМ: Түзетуге дейінгі сканерлеу (HTML және JSON)
    print(f"{COLOR_BOLD}[1/3] Түзетуге дейінгі инфрақұрылымды сканерлеу...{COLOR_RESET}")
    run_command([python_exe, scanner_path, "--endpoint-url", DEFAULT_ENDPOINT, "--region", DEFAULT_REGION, "--output", report_before_html, "--format", "html"])
    run_command([python_exe, scanner_path, "--endpoint-url", DEFAULT_ENDPOINT, "--region", DEFAULT_REGION, "--output", report_before_json, "--format", "json"])

    # 2-ҚАДАМ: Автоматты түзетуді (Remediation) іске қосу
    print(f"\n{COLOR_BOLD}[2/3] Осал ортаны автоматты түзетуді орындау (remediate_env.py)...{COLOR_RESET}")
    run_command([python_exe, remediate_path, "--endpoint-url", DEFAULT_ENDPOINT])

    # 3-ҚАДАМ: Түзетуден кейінгі қайта сканерлеу
    print(f"\n{COLOR_BOLD}[3/3] Түзетуден кейінгі инфрақұрылымды қайта сканерлеу...{COLOR_RESET}")
    run_command([python_exe, scanner_path, "--endpoint-url", DEFAULT_ENDPOINT, "--region", DEFAULT_REGION, "--output", report_after_html, "--format", "html"])
    run_command([python_exe, scanner_path, "--endpoint-url", DEFAULT_ENDPOINT, "--region", DEFAULT_REGION, "--output", report_after_json, "--format", "json"])

    # Салыстырмалы есепті оқу
    try:
        with open(report_before_json, "r", encoding="utf-8") as f:
            data_before = json.load(f)
        with open(report_after_json, "r", encoding="utf-8") as f:
            data_after = json.load(f)
    except Exception as exc:
        print(f"[ҚАТЕ] JSON есептерін оқу мүмкін болмады: {exc}")
        return

    score_before = data_before["summary"]["score"]
    grade_before = data_before["summary"]["grade"]
    counts_before = data_before["summary"]["severity_counts"]

    score_after = data_after["summary"]["score"]
    grade_after = data_after["summary"]["grade"]
    counts_after = data_after["summary"]["severity_counts"]

    # Ережелер бойынша салыстыру
    rules_before = {f["rule_id"]: f["title"] for f in data_before.get("findings", [])}
    rules_after = {f["rule_id"]: f["title"] for f in data_after.get("findings", [])}

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{'='*70}{COLOR_RESET}")
    print(f"{COLOR_BOLD}         ҚОРЫТЫНДЫ САЛЫСТЫРУ КЕСТЕСІ (COMPARISON REPORT){COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*70}{COLOR_RESET}")
    print(f"  Көрсеткіш                      Түзетуге дейін       Түзетуден кейін")
    print(f"  --------------------------------------------------------------------")
    print(f"  Қауіпсіздік балы (Score):      {COLOR_RED}{score_before:>3} / 100 ({grade_before}){COLOR_RESET}        {COLOR_GREEN}{COLOR_BOLD}{score_after:>3} / 100 ({grade_after}){COLOR_RESET}")
    print(f"  Сыни қауіптер (CRITICAL):      {COLOR_RED}{counts_before['critical']:>5}{COLOR_RESET}              {COLOR_GREEN}{counts_after['critical']:>5}{COLOR_RESET}")
    print(f"  Жоғары қауіптер (HIGH):        {COLOR_RED}{counts_before['high']:>5}{COLOR_RESET}              {COLOR_GREEN}{counts_after['high']:>5}{COLOR_RESET}")
    print(f"  Орташа қауіптер (MEDIUM):      {COLOR_RED}{counts_before['medium']:>5}{COLOR_RESET}              {COLOR_GREEN}{counts_after['medium']:>5}{COLOR_RESET}")
    print(f"  Төмен қауіптер (LOW):          {COLOR_RED}{counts_before['low']:>5}{COLOR_RESET}              {COLOR_GREEN}{counts_after['low']:>5}{COLOR_RESET}")
    print(f"  Жалпы осалдық саны:            {COLOR_RED}{len(data_before.get('findings', [])):>5}{COLOR_RESET}              {COLOR_GREEN}{len(data_after.get('findings', [])):>5}{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'-'*70}{COLOR_RESET}")

    print(f"  {COLOR_BOLD}Ережелер мәртебесі:{COLOR_RESET}")
    all_seen_rules = sorted(set(list(rules_before.keys()) + list(rules_after.keys())))
    for r in all_seen_rules:
        if r in rules_before and r not in rules_after:
            print(f"    {COLOR_GREEN}[+] ТҮЗЕТІЛДІ:{COLOR_RESET} {r} - {rules_before[r]}")
        elif r in rules_after:
            note = "(эмуляторда root MFA API жоқ)" if r == "IAM-002" else ""
            print(f"    {COLOR_YELLOW}[!] ҚАЛДЫ:    {COLOR_RESET} {r} - {rules_after[r]} {note}")

    print(f"{COLOR_CYAN}{'-'*70}{COLOR_RESET}")
    print(f"  Есеп файлдары:")
    print(f"    - Түзетуге дейін: {COLOR_BLUE}{report_before_html}{COLOR_RESET}")
    print(f"    - Түзетуден кейін: {COLOR_GREEN}{report_after_html}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*70}{COLOR_RESET}\n")


if __name__ == "__main__":
    main()
