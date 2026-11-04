"""
Қауіпсіздік тексерулерін тіркеу механизмі (Registry).
"""
import logging
from typing import Callable, List
import boto3

from core.models import Finding

logger = logging.getLogger(__name__)

# Тексеру функциясының типі: boto3.Session қабылдап, list[Finding] қайтарады
CheckFunction = Callable[[boto3.Session], List[Finding]]

# Тіркелген барлық тексерулердің ішкі тізілімі: rule_id -> CheckFunction
_CHECKS_REGISTRY: dict[str, CheckFunction] = {}


def register_check(rule_id: str) -> Callable[[CheckFunction], CheckFunction]:
    """
    Тексеру функциясын жалпы тізілімге (registry) тіркейтін декоратор.
    
    :param rule_id: Ереженің бірегей идентификаторы (мысалы, 'EC2-001')
    :return: Тіркелген функцияны өзгеріссіз қайтаратын декоратор
    """
    def decorator(func: CheckFunction) -> CheckFunction:
        if rule_id in _CHECKS_REGISTRY:
            logger.warning("Ереже идентификаторы қайта тіркелуде: %s", rule_id)
        _CHECKS_REGISTRY[rule_id] = func
        setattr(func, "__rule_id__", rule_id)
        return func
    return decorator


def get_registered_checks() -> dict[str, CheckFunction]:
    """
    Барлық тіркелген тексерулердің көшірмесін қайтарады.
    
    :return: {rule_id: CheckFunction} сөздігі
    """
    return _CHECKS_REGISTRY.copy()
