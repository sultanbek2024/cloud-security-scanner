"""
Тексерулерді автоматты табу, орындау және қателерді өңдеу қозғалтқышы (Scan Engine).
"""
import importlib
import logging
import pkgutil
from typing import List, Tuple
import boto3

import checks
from core.models import Finding
from core.registry import get_registered_checks

logger = logging.getLogger(__name__)


def auto_discover_checks() -> None:
    """
    'checks' топтамасындағы барлық модульдерді динамикалық түрде жүктейді (import),
    нәтижесінде @register_check декораторымен белгіленген функциялар реестрге тіркеледі.
    """
    for _, module_name, is_pkg in pkgutil.iter_modules(checks.__path__):
        if not is_pkg:
            full_module_name = f"checks.{module_name}"
            try:
                importlib.import_module(full_module_name)
                logger.debug("Тексеру модулі сәтті жүктелді: %s", full_module_name)
            except Exception as exc:
                logger.error("Тексеру модулін жүктеу сәтсіз аяқталды [%s]: %s", full_module_name, exc, exc_info=True)


class ScanEngine:
    """
    Қауіпсіздік сканерін басқарушы негізгі класс.
    """

    def __init__(self, session: boto3.Session) -> None:
        """
        :param session: AWS-пен жұмыс істеуге арналған boto3.Session данасы
        """
        self.session = session
        auto_discover_checks()
        self.checks = get_registered_checks()

    def run(self) -> Tuple[List[Finding], int]:
        """
        Барлық тіркелген қауіпсіздік тексерулерін ретімен орындайды.
        Әрбір тексеру оқшауланған түрде орындалады: егер бір тексеру қатемен аяқталса,
        ол журналға жазылып, қалған тексерулер тоқтаусыз жалғасады.
        
        :return: (Анықталған осалдықтар тізімі, орындалған тексерулер саны)
        """
        all_findings: List[Finding] = []
        total_checks = len(self.checks)
        logger.info("Сканерлеу басталды. Тіркелген тексерулер саны: %d", total_checks)

        for rule_id, check_func in self.checks.items():
            logger.info("Тексеру орындалуда: %s", rule_id)
            try:
                findings = check_func(self.session)
                if findings:
                    all_findings.extend(findings)
                    logger.warning("Ереже бойынша осалдық анықталды [%s]: %d дана", rule_id, len(findings))
                else:
                    logger.debug("Ереже сәтті тексерілді, осалдық табылмады [%s]", rule_id)
            except Exception as exc:
                if exc.__class__.__name__ == "NoCredentialsError":
                    logger.error("Тексеру [%s]: AWS куәліктері (credentials) табылмады.", rule_id)
                else:
                    logger.error(
                        "Тексеру кезінде қате орын алды [%s]: %s",
                        rule_id,
                        exc,
                        exc_info=logger.isEnabledFor(logging.DEBUG),
                    )

        logger.info("Сканерлеу аяқталды. Барлығы табылған осалдықтар: %d", len(all_findings))
        return all_findings, total_checks
