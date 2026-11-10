"""
Terraform (HCL2) файлдарын парсингтеу және ресурстарды бөліп алу модулі.
"""
from dataclasses import dataclass, field
import glob
import logging
import os
from typing import Dict, List, Any
import hcl2

logger = logging.getLogger(__name__)


@dataclass
class TerraformResource:
    """
    Terraform манифестінде жарияланған бұлттық ресурс моделі.
    """
    resource_type: str        # Мысалы: 'aws_s3_bucket', 'aws_security_group'
    resource_name: str        # Мысалы: 'web_sg', 'data_storage'
    config: Dict[str, Any]    # Ресурстың ішкі баптаулары мен атрибуттары
    file_path: str = ""       # Ресурс анықталған .tf файлының жолы


def parse_terraform_file(file_path: str) -> List[TerraformResource]:
    """
    Бір .tf файлын парсингтеп, одан барлық resource анықтамаларын жинайды.
    """
    if not os.path.exists(file_path):
        logger.error("Terraform файлы табылмады: %s", file_path)
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = hcl2.load(f)
    except Exception as exc:
        logger.error("Terraform файлын оқу/парсингтеу кезінде қате [%s]: %s", file_path, exc)
        return []

    return _extract_resources_from_data(data, file_path)


def parse_terraform_dir(dir_path: str) -> List[TerraformResource]:
    """
    Берілген папкадағы барлық .tf файлдарын іздеп тауып, ресурстарын жинайды.
    """
    if not os.path.isdir(dir_path):
        logger.error("Көрсетілген жол папка емес немесе табылмады: %s", dir_path)
        return []

    resources: List[TerraformResource] = []
    pattern = os.path.join(dir_path, "**", "*.tf")
    tf_files = glob.glob(pattern, recursive=True)

    for tf_file in tf_files:
        file_resources = parse_terraform_file(tf_file)
        resources.extend(file_resources)

    return resources


def _extract_resources_from_data(data: Dict[str, Any], file_path: str) -> List[TerraformResource]:
    """
    hcl2 сөздігінен 'resource' блоктарын шығарып алып, TerraformResource нысандарына айналдырады.
    """
    resources: List[TerraformResource] = []
    raw_resources = data.get("resource", [])

    if isinstance(raw_resources, dict):
        raw_resources = [raw_resources]

    for item in raw_resources:
        if not isinstance(item, dict):
            continue

        for res_type, res_instances in item.items():
            if not isinstance(res_instances, dict):
                continue

            clean_type = str(res_type).strip('"\'')

            for res_name, res_config in res_instances.items():
                clean_name = str(res_name).strip('"\'')
                config_dict = res_config if isinstance(res_config, dict) else {}
                resources.append(
                    TerraformResource(
                        resource_type=clean_type,
                        resource_name=clean_name,
                        config=config_dict,
                        file_path=file_path,
                    )
                )

    return resources
