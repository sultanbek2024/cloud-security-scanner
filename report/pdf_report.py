"""
Бұлттық қауіпсіздік аудит есебін PDF форматында генерациялау модулі.
Headless браузер (Chrome / Edge) немесе автономды fallback арқылы сапалы PDF жасайды.
"""
import os
import shutil
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger("cloudsec.report.pdf")


def generate_pdf_report(html_path: str = "report.html", pdf_path: str = "report.pdf") -> str:
    """
    HTML есептен тікелей құрылғыға жүктеп алуға арналған PDF файлын генерациялайды.
    
    :param html_path: Бастапқы HTML файлының жолы
    :param pdf_path: Жасалатын PDF файлының жолы
    :return: Жасалған PDF файлының абсолютті жолы
    """
    abs_html = os.path.abspath(html_path)
    abs_pdf = os.path.abspath(pdf_path)

    if not os.path.exists(abs_html):
        raise FileNotFoundError(f"HTML есеп файлы табылмады: {abs_html}")

    # 1-тәсіл: Chrome немесе Edge (Headless) арқылы нақты корпоративтік дизайнмен генерациялау
    browser_candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("chrome"),
        shutil.which("google-chrome"),
        shutil.which("msedge"),
        shutil.which("edge"),
    ]
    browser_exe = next((p for p in browser_candidates if p and os.path.exists(p)), None)

    if browser_exe:
        try:
            file_url = f"file:///{abs_html.replace(os.sep, '/')}"
            cmd = [
                browser_exe,
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={abs_pdf}",
                file_url,
            ]
            res = subprocess.run(cmd, capture_output=True, timeout=20)
            if res.returncode == 0 and os.path.exists(abs_pdf) and os.path.getsize(abs_pdf) > 0:
                logger.info("PDF есебі сәтті генерацияланды: %s (%d bytes)", abs_pdf, os.path.getsize(abs_pdf))
                return abs_pdf
        except Exception as e:
            logger.warning("Headless браузер арқылы PDF жасау ескертуі: %s", e)

    # 2-тәсіл: Егер браузер болмаса, ReportLab арқылы генерациялау
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        doc = SimpleDocTemplate(abs_pdf, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        styles = getSampleStyleSheet()
        elements = []

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor('#0056b3'),
            spaceAfter=12
        )
        elements.append(Paragraph("SATBAYEV UNIVERSITY - CloudSec Audit Report", title_style))
        elements.append(Paragraph("Бұлттық инфрақұрылымның қауіпсіздік аудит есебі", styles['Heading2']))
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Толық интерактивті есеп браузер интерфейсінде қолжетімді.", styles['Normal']))
        doc.build(elements)
        if os.path.exists(abs_pdf) and os.path.getsize(abs_pdf) > 0:
            return abs_pdf
    except Exception as e:
        logger.error("ReportLab арқылы PDF жасау қатесі: %s", e)

    if os.path.exists(abs_pdf) and os.path.getsize(abs_pdf) > 0:
        return abs_pdf

    raise RuntimeError("PDF есебін жасау мүмкін болмады.")
