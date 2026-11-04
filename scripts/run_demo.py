#!/usr/bin/env python3
"""
Дипломдық жұмысқа арналған демонстрациялық сценарий (Сценарий «до/после»).
1. Осал ортаны бір рет сканерлейді -> бір мезетте report_before.html және report_before.json сақтайды.
2. Ремедиацияны (remediate_env.py) орындайды.
3. Қайта бір рет сканерлейді -> бір мезетте report_after.html және report_after.json сақтайды.
4. Консольге таза тураланған, бағандары анық бөлінген салыстырмалы кестені шығарады.
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

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{'='*76}{COLOR_RESET}")
    print(f"{COLOR_BOLD}     ДЕМОНСТРАЦИЯЛЫҚ СЦЕНАРИЙ: ТҮЗЕТУГЕ ДЕЙІН ЖӘНЕ КЕЙІН (BEFORE / AFTER){COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*76}{COLOR_RESET}\n")

    # 1-ҚАДАМ: Түзетуге дейінгі сканерлеу (бір сканерлеуде HTML және JSON бірге сақталады)
    print(f"{COLOR_BOLD}[1/3] Түзетуге дейінгі инфрақұрылымды сканерлеу...{COLOR_RESET}")
    run_command([
        python_exe, scanner_path,
        "--endpoint-url", DEFAULT_ENDPOINT,
        "--region", DEFAULT_REGION,
        "--output", report_before_html,
        "--json-output", report_before_json,
    ])

    # 2-ҚАДАМ: Автоматты түзетуді (Remediation) іске қосу
    print(f"\n{COLOR_BOLD}[2/3] Осал ортаны автоматты түзетуді орындау (remediate_env.py)...{COLOR_RESET}")
    run_command([python_exe, remediate_path, "--endpoint-url", DEFAULT_ENDPOINT])

    # 3-ҚАДАМ: Түзетуден кейінгі қайта сканерлеу (бір сканерлеуде HTML және JSON бірге сақталады)
    print(f"\n{COLOR_BOLD}[3/3] Түзетуден кейінгі инфрақұрылымды қайта сканерлеу...{COLOR_RESET}")
    run_command([
        python_exe, scanner_path,
        "--endpoint-url", DEFAULT_ENDPOINT,
        "--region", DEFAULT_REGION,
        "--output", report_after_html,
        "--json-output", report_after_json,
    ])

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

    # Бағандар енін қазақша жазулардың ұзындығына сай бекіту
    col1_w = 34  # Көрсеткіш
    col2_w = 18  # Түзетуге дейін
    col3_w = 18  # Түзетуден кейін

    def format_row(label: str, val_b: str, val_a: str, col_b=COLOR_RED, col_a=COLOR_GREEN) -> str:
        lbl_str = f"  {label:<{col1_w}}"
        # Сан немесе мәтінді ANSI кодтарына дейін туралау
        b_padded = f"{val_b:<{col2_w}}"
        a_padded = f"{val_a:<{col3_w}}"
        return f"{lbl_str}  {col_b}{b_padded}{COLOR_RESET}   {col_a}{a_padded}{COLOR_RESET}"

    hdr_c1 = f"  {'Көрсеткіш':<{col1_w}}"
    hdr_c2 = f"{'Түзетуге дейін':<{col2_w}}"
    hdr_c3 = f"{'Түзетуден кейін':<{col3_w}}"

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}{'='*76}{COLOR_RESET}")
    print(f"{COLOR_BOLD}         ҚОРЫТЫНДЫ САЛЫСТЫРУ КЕСТЕСІ (COMPARISON REPORT){COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*76}{COLOR_RESET}")
    print(f"{hdr_c1}  {COLOR_BOLD}{hdr_c2}{COLOR_RESET}   {COLOR_BOLD}{hdr_c3}{COLOR_RESET}")
    print(f"  {'-'*(col1_w + col2_w + col3_w + 5)}")

    print(format_row(
        "Қауіпсіздік балы (Score):",
        f"{score_before} / 100 ({grade_before})",
        f"{score_after} / 100 ({grade_after})",
        COLOR_RED,
        COLOR_GREEN + COLOR_BOLD
    ))
    print(format_row(
        "Сыни қауіптер (CRITICAL):",
        str(counts_before.get("critical", 0)),
        str(counts_after.get("critical", 0)),
    ))
    print(format_row(
        "Жоғары қауіптер (HIGH):",
        str(counts_before.get("high", 0)),
        str(counts_after.get("high", 0)),
    ))
    print(format_row(
        "Орташа қауіптер (MEDIUM):",
        str(counts_before.get("medium", 0)),
        str(counts_after.get("medium", 0)),
    ))
    print(format_row(
        "Төмен қауіптер (LOW):",
        str(counts_before.get("low", 0)),
        str(counts_after.get("low", 0)),
    ))
    print(format_row(
        "Жалпы осалдық саны:",
        str(len(data_before.get("findings", []))),
        str(len(data_after.get("findings", []))),
    ))
    print(f"{COLOR_CYAN}{'-'*76}{COLOR_RESET}")

    print(f"  {COLOR_BOLD}Ережелер мәртебесі:{COLOR_RESET}")
    all_seen_rules = sorted(set(list(rules_before.keys()) + list(rules_after.keys())))
    for r in all_seen_rules:
        if r in rules_before and r not in rules_after:
            print(f"    {COLOR_GREEN}[+] ТҮЗЕТІЛДІ:{COLOR_RESET} {r} - {rules_before[r]}")
        elif r in rules_after:
            note = "(эмуляторда root MFA API жоқ)" if r == "IAM-002" else ""
            print(f"    {COLOR_YELLOW}[!] ҚАЛДЫ:    {COLOR_RESET} {r} - {rules_after[r]} {note}")

    print(f"{COLOR_CYAN}{'-'*76}{COLOR_RESET}")
    print(f"  Есеп файлдары:")
    print(f"    - Түзетуге дейін: {COLOR_BLUE}{report_before_html}{COLOR_RESET}")
    print(f"    - Түзетуден кейін: {COLOR_GREEN}{report_after_html}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'='*76}{COLOR_RESET}\n")


if __name__ == "__main__":
    main()
