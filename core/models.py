"""
Бұлттық қауіпсіздік сканерінің деректер модельдері мен түрлері.
"""
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(str, Enum):
    """
    Қауіптілік деңгейлері (Severity levels).
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def display_name(self) -> str:
        """Қазақ тіліндегі бейнеленетін атауы."""
        names = {
            "CRITICAL": "Сыни",
            "HIGH": "Жоғары",
            "MEDIUM": "Орташа",
            "LOW": "Төмен",
        }
        return names.get(self.value, self.value)

    @property
    def weight(self) -> int:
        """Қауіпсіздік бағасын есептеуге арналған салмақ коэффициенті."""
        weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
        }
        return weights.get(self.value, 0)


@dataclass
class Finding:
    """
    Анықталған конфигурациялық осалдық моделі.
    
    :param rule_id: Ереженің бірегей коды (мысалы, 'EC2-001')
    :param title: Осалдықтың қысқаша атауы
    :param resource: Тексерілген бұлттық ресурс идентификаторы немесе ARN
    :param severity: Қауіптілік деңгейі
    :param description: Осалдықтың толық сипаттамасы мен қатері
    :param recommendation: Осалдықты жою және түзету бойынша ұсыныс
    :param standard: Сәйкес келетін қауіпсіздік стандарты (мысалы, 'CIS AWS Foundations Benchmark 5.2')
    """
    rule_id: str
    title: str
    resource: str
    severity: Severity
    description: str
    recommendation: str
    standard: str
    remediation_cli: str = ""
    remediation_terraform: str = ""
    is_drift: bool = False

    def to_dict(self) -> dict:
        """
        Модельді сөздік түріне түрлендіреді (JSON экспорт үшін).
        """
        data = asdict(self)
        data["severity"] = self.severity.value
        data["severity_display"] = self.severity.display_name
        data["is_drift"] = self.is_drift
        data["remediation_cli"] = self.remediation_cli
        data["remediation_terraform"] = self.remediation_terraform
        return data
