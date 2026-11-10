"""
FastAPI маршруттары мен эндпоинттері (API Endpoints).
"""
from datetime import datetime, timezone
import logging
import os
import tempfile
from typing import List, Dict, Any, Optional
import boto3
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import HTMLResponse

from core.engine import ScanEngine
from core.models import Finding, Severity
from core.scoring import calculate_score, group_findings_by_severity
from core.drift import correlate_and_detect_drift
from core.registry import get_registered_checks
from iac.scanner import scan_terraform, get_declared_resources
from report.html_report import generate_html_report
from report.json_report import generate_json_report
from api.schemas import ScanRequest, ScanResponse, FindingSchema, RuleInfoSchema

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Cloud Security Scanner"])

# Соңғы сканерлеу нәтижесін жадта кэштеу
LATEST_RESULTS: Dict[str, Any] = {}


def _create_session(req: ScanRequest) -> boto3.Session:
    """Бұлтпен байланыс орнату үшін boto3.Session данасын қалыптастырады."""
    kwargs: Dict[str, Any] = {"region_name": req.region}
    session = boto3.Session(**kwargs)

    # LocalStack немесе арнайы эмулятор көрсетілсе
    if req.endpoint_url:
        setattr(session, "endpoint_url", req.endpoint_url)

    if req.all_regions:
        setattr(session, "target_regions", ["us-east-1", "us-west-2", "eu-west-1"])
    else:
        setattr(session, "target_regions", [req.region])

    return session


@router.get("/health")
def health_check() -> Dict[str, str]:
    """Жүйенің жұмыс күйін тексеру."""
    return {"status": "ok", "service": "Cloud Security Scanner API", "version": "2.0.0"}


@router.get("/rules", response_model=List[RuleInfoSchema])
def list_rules() -> List[RuleInfoSchema]:
    """Жүйедегі барлық тіркелген қауіпсіздік ережелерінің тізімі."""
    checks = get_registered_checks()
    result = []
    for rule_id, func in checks.items():
        doc = func.__doc__ or "Сипаттамасы жоқ"
        first_line = doc.strip().split("\n")[0]
        result.append(RuleInfoSchema(rule_id=rule_id, description=first_line))
    return sorted(result, key=lambda x: x.rule_id)


@router.post("/scan", response_model=ScanResponse)
def run_scan(req: ScanRequest) -> ScanResponse:
    """
    Кешенді сканерлеуді іске қосу (AWS Runtime + Terraform IaC + Drift Detection).
    """
    global LATEST_RESULTS

    all_findings: List[Finding] = []
    total_checks = 0
    iac_resources = []

    # 1. IaC (Terraform) талдауы
    tmp_file_to_clean: Optional[str] = None
    try:
        iac_target = req.iac_path

        # Егер вебтен тікелей код жіберілсе, уақытша файлға жазу
        if req.iac_content and req.iac_content.strip():
            with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False, encoding="utf-8") as f:
                f.write(req.iac_content)
                tmp_file_to_clean = f.name
                iac_target = tmp_file_to_clean

        if iac_target and os.path.exists(iac_target):
            iac_findings = scan_terraform(iac_target)
            all_findings.extend(iac_findings)
            iac_resources = get_declared_resources(iac_target)
            total_checks += 4
    finally:
        if tmp_file_to_clean and os.path.exists(tmp_file_to_clean):
            try:
                os.remove(tmp_file_to_clean)
            except Exception:
                pass

    # 2. AWS Runtime сканерлеу
    try:
        session = _create_session(req)
        engine = ScanEngine(session=session)
        cloud_findings, checks_count = engine.run()
        all_findings.extend(cloud_findings)
        total_checks += checks_count
    except Exception as exc:
        logger.warning("AWS сессиясын орындау кезінде ескерту: %s", exc)

    # 3. Drift Detection
    if iac_resources:
        all_findings = correlate_and_detect_drift(all_findings, iac_resources)

    # Бағалау және топтастыру
    score, grade = calculate_score(all_findings, max(total_checks, 1))
    grouped = group_findings_by_severity(all_findings)
    sev_counts = {
        "critical": len(grouped.get(Severity.CRITICAL, [])),
        "high": len(grouped.get(Severity.HIGH, [])),
        "medium": len(grouped.get(Severity.MEDIUM, [])),
        "low": len(grouped.get(Severity.LOW, [])),
    }
    drift_count = sum(1 for f in all_findings if f.is_drift)
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Деректерді сөздік түріне дайындау
    findings_dicts = [f.to_dict() for f in all_findings]

    response_data = ScanResponse(
        score=score,
        grade=grade,
        total_checks=total_checks,
        findings_count=len(all_findings),
        drift_count=drift_count,
        severity_counts=sev_counts,
        scan_time=scan_time,
        provider=req.provider,
        region=req.region,
        findings=[FindingSchema(**d) for d in findings_dicts],
    )

    # HTML есепті генерациялау және кэштеу
    report_path = "report.html"
    try:
        generate_html_report(
            findings=all_findings,
            score=score,
            grade=grade,
            output_path=report_path,
            provider=req.provider,
            region=req.region,
        )
    except Exception as exc:
        logger.error("HTML есепті жасау кезінде қате: %s", exc)

    LATEST_RESULTS = response_data.model_dump()
    return response_data


@router.get("/results/latest")
def get_latest_results() -> Dict[str, Any]:
    """Соңғы орындалған сканерлеу нәтижесін алу."""
    if not LATEST_RESULTS:
        raise HTTPException(status_code=404, detail="Әзірше сканерлеу жүргізілген жоқ")
    return LATEST_RESULTS


@router.get("/report/html", response_class=HTMLResponse)
def get_html_report() -> HTMLResponse:
    """Генерацияланған HTML есепті браузерде тікелей ашу."""
    report_path = "report.html"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="HTML есеп файлы табылмады. Алдымен сканерлеуді іске қосыңыз.")
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)
