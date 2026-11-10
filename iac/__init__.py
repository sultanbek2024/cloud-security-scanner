"""
IaC (Infrastructure as Code) қауіпсіздігін талдау модулі.
Terraform (*.tf) файлдарындағы конфигурациялық осалдықтарды статикалық талдау (Shift-Left) үшін қолданылады.
"""
from iac.parser import parse_terraform_file, parse_terraform_dir, TerraformResource
from iac.scanner import scan_terraform, get_declared_resources

__all__ = [
    "parse_terraform_file",
    "parse_terraform_dir",
    "TerraformResource",
    "scan_terraform",
    "get_declared_resources",
]
