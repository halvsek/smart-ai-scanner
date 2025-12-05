"""
SMART AI Security Scanner - Aegis-ML
Advanced static model vulnerability scanner with no execution paths.

Industry-grade static analysis for AI/ML artifacts with comprehensive format support,
rule-based detection, and enterprise-ready reporting.

Author: SMART-01 AI Security Research Team
License: MIT
"""

__version__ = "2.0.0"
__author__ = "SMART-01 AI Security Research Team"

# Core components
from .core.registry import ScannerRegistry
from .core.base_scanner import BaseScanner
from .core.rules import RuleEngine
from .core.report import ConsoleRenderer, JsonRenderer, SarifRenderer, create_summary
from .core.sbom import SBOMGenerator
from .core.utils import find_ml_artifacts, calculate_entropy, detect_magic_bytes

# Scanner implementations
from .scanners import PickleScanner, ONNXScanner, SafeTensorsScanner

__all__ = [
    "ScannerRegistry",
    "BaseScanner",
    "RuleEngine", 
    "ConsoleRenderer",
    "JsonRenderer",
    "SarifRenderer",
    "create_summary",
    "SBOMGenerator",
    "find_ml_artifacts",
    "calculate_entropy", 
    "detect_magic_bytes",
    "PickleScanner",
    "ONNXScanner",
    "SafeTensorsScanner"
]

# Auto-register scanners
def _register_scanners():
    """Register all built-in scanners"""
    registry = ScannerRegistry()
    registry.register_scanner(PickleScanner)
    registry.register_scanner(ONNXScanner)
    registry.register_scanner(SafeTensorsScanner)
    return registry

# Create global registry instance
default_registry = _register_scanners()