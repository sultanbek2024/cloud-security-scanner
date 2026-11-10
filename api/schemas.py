"""
FastAPI Pydantic сұлбалары (Data Schemas).
"""
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """
    Сканерлеуді іске қосу сұранысының үлгісі.
    """
    provider: str = Field(default="aws", description="Бұлттық провайдер (aws)")
    region: str = Field(default="us-east-1", description="AWS аймағы")
    all_regions: bool = Field(default=False, description="Барлық аймақтарды сканерлеу")
    endpoint_url: Optional[str] = Field(default=None, description="LocalStack / Moto URL (тестілеу үшін)")
    iac_path: Optional[str] = Field(default=None, description="Сервердегі Terraform файлы немесе папкасы")
    iac_content: Optional[str] = Field(default=None, description="Веб-интерфейстен тікелей енгізілген Terraform коды")
    demo_mode: bool = Field(default=False, description="Демо режимі (эмуляцияланған бұлттық ресурстар мен Drift-ті көрсету)")


class FindingSchema(BaseModel):
    """
    Анықталған конфигурациялық осалдық сұлбасы.
    """
    rule_id: str
    title: str
    resource: str
    severity: str
    severity_display: str
    description: str
    recommendation: str
    standard: str
    remediation_cli: str = ""
    remediation_terraform: str = ""
    is_drift: bool = False


class ScanResponse(BaseModel):
    """
    Сканерлеу нәтижесінің жиынтық жауабы.
    """
    score: int
    grade: str
    total_checks: int
    findings_count: int
    drift_count: int
    severity_counts: Dict[str, int]
    scan_time: str
    provider: str
    region: str
    findings: List[FindingSchema]


class RuleInfoSchema(BaseModel):
    """
    Қауіпсіздік ережесі туралы ақпарат.
    """
    rule_id: str
    description: str
