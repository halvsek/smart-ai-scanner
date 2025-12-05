"""
Scanner registry for SMART AI Security Scanner
Central registry for all format-specific scanners
"""

import pathlib
import importlib
from typing import Dict, List, Type, Optional, Union, Any
from collections import defaultdict

from .base_scanner import BaseScanner


def _load_scanner(module_name: str, class_name: str):
    """Attempt to load a scanner class from multiple module resolution paths."""
    module_candidates = [
        f"smart_ai_scanner.scanners.{module_name}",
        f"scanners.{module_name}",
    ]
    for candidate in module_candidates:
        try:
            module = importlib.import_module(candidate)
            return getattr(module, class_name)
        except (ImportError, AttributeError):
            continue
    return None


AdvancedPickleScanner = _load_scanner("pickle_scanner", "AdvancedPickleScanner")
HAS_PICKLE_SCANNER = AdvancedPickleScanner is not None

AdvancedONNXScanner = _load_scanner("onnx_scanner", "AdvancedONNXScanner")
HAS_ONNX_SCANNER = AdvancedONNXScanner is not None

AdvancedTensorFlowScanner = _load_scanner("tensorflow_scanner", "AdvancedTensorFlowScanner")
HAS_TENSORFLOW_SCANNER = AdvancedTensorFlowScanner is not None

AdvancedKerasScanner = _load_scanner("keras_scanner", "AdvancedKerasScanner")
HAS_KERAS_SCANNER = AdvancedKerasScanner is not None

AdvancedPyTorchScanner = _load_scanner("pytorch_scanner", "AdvancedPyTorchScanner")
HAS_PYTORCH_SCANNER = AdvancedPyTorchScanner is not None

AdvancedTokenizerScanner = _load_scanner("tokenizer_scanner", "AdvancedTokenizerScanner")
HAS_TOKENIZER_SCANNER = AdvancedTokenizerScanner is not None

AdvancedXGBoostScanner = _load_scanner("xgboost_scanner", "AdvancedXGBoostScanner")
HAS_XGBOOST_SCANNER = AdvancedXGBoostScanner is not None

AdvancedLightGBMScanner = _load_scanner("lightgbm_scanner", "AdvancedLightGBMScanner")
HAS_LIGHTGBM_SCANNER = AdvancedLightGBMScanner is not None

SafeTensorsScanner = _load_scanner("safetensors_scanner", "AdvancedSafeTensorsScanner")
HAS_SAFETENSORS_SCANNER = SafeTensorsScanner is not None

AdvancedCatBoostScanner = _load_scanner("catboost_scanner", "AdvancedCatBoostScanner")
HAS_CATBOOST_SCANNER = AdvancedCatBoostScanner is not None

AdvancedGGUFScanner = _load_scanner("gguf_scanner", "AdvancedGGUFScanner")
HAS_GGUF_SCANNER = AdvancedGGUFScanner is not None

AdvancedCoreMLScanner = _load_scanner("coreml_scanner", "AdvancedCoreMLScanner")
HAS_COREML_SCANNER = AdvancedCoreMLScanner is not None


class ScannerRegistry:
    """Central registry for all ML model scanners."""

    def __init__(self):
        """Initialize scanner registry structures and register built-in scanners."""
        self._scanners: List[Type[BaseScanner]] = []
        self._format_map: Dict[str, List[Type[BaseScanner]]] = defaultdict(list)
        self._magic_bytes: Dict[bytes, List[Type[BaseScanner]]] = defaultdict(list)
        self._extensions: Dict[str, List[Type[BaseScanner]]] = defaultdict(list)

        # Format to extensions mapping
        self._format_extensions = {
            "pickle": [".pkl", ".pickle", ".dill", ".joblib"],
            "pytorch": [".pt", ".pth", ".ckpt", ".mar"],
            "onnx": [".onnx"],
            "keras": [".h5", ".keras"],
            "tensorflow": [".pb", ".pbtxt", ".tflite"],
            "safetensors": [".safetensors"],
            "xgboost": [".model", ".json", ".ubj"],
            "lightgbm": [".txt", ".model"],
            "catboost": [".cbm", ".bin"],
            "gguf": [".gguf", ".ggml"],
            "coreml": [".mlmodel", ".mlpackage"],
            "tokenizer": ["tokenizer.json", "vocab.txt", "vocab.json", "merges.txt"],
        }

        # Magic byte signatures for format detection
        self._magic_signatures = {
            b"\x80\x02": "pickle",  # Protocol 2
            b"\x80\x03": "pickle",  # Protocol 3
            b"\x80\x04": "pickle",  # Protocol 4
            b"\x80\x05": "pickle",  # Protocol 5
            b"\x08\x01\x12": "onnx",  # ONNX protobuf signature
            b"\x89HDF\r\n\x1a\n": "hdf5",  # HDF5 used by Keras
            b"saved_model": "tensorflow",  # TensorFlow SavedModel
            b"SAFETENSORS": "safetensors",
            b"GGUF": "gguf",
            b"GGML": "ggml",
            b"PK": "zip",  # Generic ZIP archive
        }

        self._register_builtin_scanners()

    def _register_builtin_scanners(self) -> None:
        """Register all built-in scanners that were successfully imported."""

        def _register(format_key: str, scanner_cls: Optional[Type[BaseScanner]]):
            if scanner_cls is None:
                return
            self._format_map[format_key].append(scanner_cls)
            self._scanners.append(scanner_cls)

        _register("pickle", AdvancedPickleScanner if HAS_PICKLE_SCANNER else None)
        _register("onnx", AdvancedONNXScanner if HAS_ONNX_SCANNER else None)
        _register("tensorflow", AdvancedTensorFlowScanner if HAS_TENSORFLOW_SCANNER else None)
        _register("keras", AdvancedKerasScanner if HAS_KERAS_SCANNER else None)
        _register("pytorch", AdvancedPyTorchScanner if HAS_PYTORCH_SCANNER else None)
        _register("tokenizer", AdvancedTokenizerScanner if HAS_TOKENIZER_SCANNER else None)
        _register("xgboost", AdvancedXGBoostScanner if HAS_XGBOOST_SCANNER else None)
        _register("lightgbm", AdvancedLightGBMScanner if HAS_LIGHTGBM_SCANNER else None)
        _register("catboost", AdvancedCatBoostScanner if HAS_CATBOOST_SCANNER else None)
        _register("gguf", AdvancedGGUFScanner if HAS_GGUF_SCANNER else None)
        _register("coreml", AdvancedCoreMLScanner if HAS_COREML_SCANNER else None)
        _register("safetensors", SafeTensorsScanner if HAS_SAFETENSORS_SCANNER else None)
    
    def register_scanner(
        self,
        scanner_class: Type[BaseScanner],
        formats: Optional[List[str]] = None,
        magic_signatures: Optional[List[bytes]] = None,
        extensions: Optional[List[str]] = None,
    ) -> None:
        """Register an additional scanner at runtime."""

        if not issubclass(scanner_class, BaseScanner):
            raise ValueError("Scanner must inherit from BaseScanner")

        if scanner_class not in self._scanners:
            self._scanners.append(scanner_class)

        if formats:
            for fmt in formats:
                self._format_map[fmt].append(scanner_class)

        if magic_signatures:
            for signature in magic_signatures:
                self._magic_bytes[signature].append(scanner_class)

        if extensions:
            for ext in extensions:
                self._extensions[ext.lower()].append(scanner_class)

    def detect_format(self, file_path: str) -> List[str]:
        """Detect file format(s) using extensions, magic bytes, and content analysis."""

        path = pathlib.Path(file_path)
        detected_formats: List[str] = []

        # Extension-based detection
        extension = path.suffix.lower()
        if path.name.lower() in ["tokenizer.json", "vocab.txt", "vocab.json", "merges.txt"]:
            detected_formats.append("tokenizer")

        for fmt, extensions in self._format_extensions.items():
            if extension in extensions and fmt not in detected_formats:
                detected_formats.append(fmt)

        # Magic byte detection
        try:
            with open(file_path, "rb") as handle:
                header = handle.read(32)
                for magic_bytes, fmt in self._magic_signatures.items():
                    if header.startswith(magic_bytes) and fmt not in detected_formats:
                        detected_formats.append(fmt)
        except (IOError, OSError):
            pass  # Cannot read file, rely on other mechanisms

        # Registered custom magic signatures
        try:
            with open(file_path, "rb") as handle:
                header = handle.read(64)
                for signature, scanners in self._magic_bytes.items():
                    if header.startswith(signature):
                        for scanner in scanners:
                            scanner_formats = getattr(scanner, "SUPPORTED_FORMATS", [])
                            for fmt in scanner_formats:
                                if fmt not in detected_formats:
                                    detected_formats.append(fmt)
        except (IOError, OSError):
            pass

        if not detected_formats:
            detected_formats = self._detect_by_content(file_path)

        return detected_formats if detected_formats else ["unknown"]

    def _detect_by_content(self, file_path: str) -> List[str]:
        """Detect format by inspecting textual content for known patterns."""

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                sample = handle.read(1024)

            if '"model_type"' in sample or '"architectures"' in sample:
                return ["huggingface_config"]

            if '"vocab_size"' in sample or '"tokenizer_class"' in sample:
                return ["tokenizer"]

            if '"trees"' in sample and '"split_feature"' in sample:
                return ["lightgbm"]

        except (UnicodeDecodeError, IOError):
            return []

        return []
    
    def get_scanners_for_format(self, format_name: str) -> List[Type[BaseScanner]]:
        """Get all scanners that can handle a specific format"""
        return self._format_map.get(format_name, [])
    
    def get_applicable_scanners(self, file_path: str) -> List[Type[BaseScanner]]:
        """Get all scanners applicable to a file based on format detection"""
        formats = self.detect_format(file_path)
        applicable_scanners = []
        
        for fmt in formats:
            scanners = self.get_scanners_for_format(fmt)
            applicable_scanners.extend(scanners)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_scanners = []
        for scanner in applicable_scanners:
            if scanner not in seen:
                seen.add(scanner)
                unique_scanners.append(scanner)
        
        return unique_scanners
    
    def scan_file(self, file_path: str, rule_engine) -> Dict[str, Any]:
        """
        Scan a single file with all applicable scanners
        Returns comprehensive scan results
        """
        path = pathlib.Path(file_path)
        
        if not path.exists():
            return {
                "file": str(path),
                "error": "File not found",
                "formats": [],
                "findings": [],
                "scanners_used": []
            }
        
        # Detect file formats
        detected_formats = self.detect_format(file_path)
        
        # Get file stats
        stat = path.stat()
        file_info = {
            "file": str(path),
            "size": stat.st_size,
            "formats": detected_formats,
            "findings": [],
            "scanners_used": [],
            "scan_time": None,
            "error": None
        }
        
        # Check file size policy
        size_check = rule_engine.check_file_size(stat.st_size)
        if not size_check.get("allowed", True):
            file_info["findings"].append(
                rule_engine.create_finding(
                    "resource_exhaustion",
                    size_check.get("severity", "MEDIUM"),
                    "File size exceeds policy limit",
                    size_check.get("reason", ""),
                    str(path),
                    "file_policy"
                )
            )
            
            # If strict policy blocks large files, don't scan content
            if rule_engine.get_policy_setting("block_dangerous_formats", False):
                return file_info
        
        # Get applicable scanners based on format
        applicable_scanners = self.get_applicable_scanners(file_path)
        
        # If no format-specific scanners, use generic scanners
        if not applicable_scanners:
            applicable_scanners = self._get_generic_scanners()
        
        # Run each applicable scanner
        import time
        start_time = time.time()
        
        for scanner_class in applicable_scanners:
            try:
                scanner = scanner_class(rule_engine)
                scanner_name = scanner.__class__.__name__
                file_info["scanners_used"].append(scanner_name)
                
                # Run the scanner
                findings = scanner.scan(file_path)
                
                # Add scanner info to each finding
                for finding in findings:
                    finding["scanner"] = scanner_name
                    finding["artifact"] = str(path)
                    finding["timestamp"] = time.time()
                
                file_info["findings"].extend(findings)
                
            except Exception as e:
                # Scanner failed, add error finding
                file_info["findings"].append(
                    rule_engine.create_finding(
                        "scanner_error",
                        "LOW",
                        f"Scanner {scanner_class.__name__} failed",
                        str(e),
                        str(path),
                        scanner_class.__name__
                    )
                )
        
        file_info["scan_time"] = time.time() - start_time
        return file_info
    
    def _get_generic_scanners(self) -> List[Type[BaseScanner]]:
        """Get scanners that can analyze any file (entropy, magic bytes, etc.)"""
        # These would be scanners that don't need format-specific knowledge
        return []  # Will be populated when scanners are implemented
    
    def scan_directory(self, directory_path: str, rule_engine, 
                      recursive: bool = True, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan all applicable files in a directory
        
        Args:
            directory_path: Path to directory to scan
            rule_engine: Rule engine instance
            recursive: Whether to scan subdirectories
            extensions: Optional list of extensions to filter by
        
        Returns:
            List of scan results for each file
        """
        from .utils import find_ml_artifacts
        
        # Find all ML artifacts in directory
        artifacts = find_ml_artifacts(directory_path, recursive)
        
        # Filter by extensions if specified
        if extensions:
            extensions_lower = [ext.lower() for ext in extensions]
            artifacts = [
                artifact for artifact in artifacts
                if pathlib.Path(artifact).suffix.lower() in extensions_lower
            ]
        
        # Scan each file
        results = []
        for artifact in artifacts:
            result = self.scan_file(artifact, rule_engine)
            results.append(result)
        
        return results
    
    def get_supported_formats(self) -> Dict[str, List[str]]:
        """Get all supported formats and their extensions"""
        return self._format_extensions.copy()
    
    def get_registered_scanners(self) -> List[str]:
        """Get list of registered scanner class names"""
        return [scanner.__name__ for scanner in self._scanners]
    
    def get_format_stats(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about detected formats in scan results"""
        format_counts = defaultdict(int)
        total_files = len(scan_results)
        total_findings = 0
        severity_counts = defaultdict(int)
        
        for result in scan_results:
            total_findings += len(result.get("findings", []))
            
            for fmt in result.get("formats", []):
                format_counts[fmt] += 1
            
            for finding in result.get("findings", []):
                severity = finding.get("severity", "UNKNOWN")
                severity_counts[severity] += 1
        
        return {
            "total_files": total_files,
            "total_findings": total_findings,
            "format_distribution": dict(format_counts),
            "severity_distribution": dict(severity_counts),
            "supported_formats": list(self._format_extensions.keys())
        }