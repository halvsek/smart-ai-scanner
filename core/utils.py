"""
Core utilities for SMART AI Security Scanner
File operations, hashing, entropy analysis, and artifact discovery
"""

import os
import pathlib
import hashlib
import math
import struct
from typing import Generator, Dict, Any, List, Optional
from collections import Counter

def find_ml_artifacts(directory: str, recursive: bool = True) -> List[str]:
    """
    Find all ML artifact files in a directory
    
    Args:
        directory: Directory path to search
        recursive: Whether to search subdirectories
    
    Returns:
        List of ML artifact file paths
    """
    
    # Known ML file extensions
    ml_extensions = {
        '.pkl', '.pickle', '.dill', '.joblib',  # Pickle family
        '.pt', '.pth', '.ckpt', '.mar',         # PyTorch
        '.onnx',                                # ONNX
        '.h5', '.keras',                        # Keras/HDF5
        '.pb', '.pbtxt', '.tflite',            # TensorFlow
        '.safetensors',                         # SafeTensors
        '.model', '.bin', '.cbm',              # Various model formats
        '.json', '.txt'                        # Config files (selective)
    }
    
    # Known ML filenames (regardless of extension)
    ml_filenames = {
        'tokenizer.json', 'vocab.txt', 'vocab.json', 'merges.txt',
        'config.json', 'pytorch_model.bin', 'tf_model.h5',
        'model.onnx', 'model.pb', 'saved_model.pb'
    }
    
    artifacts = []
    search_path = pathlib.Path(directory)
    
    if not search_path.exists():
        return artifacts
    
    # Search pattern based on recursive flag
    if recursive:
        pattern = "**/*"
    else:
        pattern = "*"
    
    for file_path in search_path.glob(pattern):
        if file_path.is_file():
            # Check by extension
            if file_path.suffix.lower() in ml_extensions:
                artifacts.append(str(file_path))
            # Check by filename
            elif file_path.name.lower() in ml_filenames:
                artifacts.append(str(file_path))
            # Check for model-like patterns in filename
            elif any(pattern in file_path.name.lower() for pattern in ['model', 'checkpoint', 'weights']):
                artifacts.append(str(file_path))
    
    return sorted(artifacts)
from collections import Counter

# Supported file extensions mapped to format types
EXT_MAP = {
    # Pickle family (DANGEROUS - never load directly)
    ".pkl": "pickle", ".pickle": "pickle", ".dill": "pickle", ".joblib": "pickle",
    
    # PyTorch (DANGEROUS - contains pickle)
    ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "pytorch", ".mar": "pytorch",
    
    # ONNX (safer but check for external data)
    ".onnx": "onnx",
    
    # Keras/TensorFlow (check for Lambda layers and unsafe deserialization)
    ".h5": "keras", ".keras": "keras",
    ".pb": "tensorflow", ".pbtxt": "tensorflow",
    
    # TensorFlow Lite
    ".tflite": "tflite",
    
    # SafeTensors (safest format but validate headers)
    ".safetensors": "safetensors",
    
    # Other ML formats
    ".gguf": "gguf", ".ggml": "gguf",
    ".model": "xgboost",
    ".bin": "lightgbm",  # or generic binary
    ".txt": "lightgbm",  # or config file
    ".cbm": "catboost",
    ".mlmodel": "coreml",
    
    # Tokenizer and config files
    ".json": "maybe_tokenizer",
    ".vocab": "tokenizer", ".bpe": "tokenizer", ".txt2": "tokenizer",
    
    # Documentation and metadata
    ".md": "metadata", ".txt": "metadata", ".rst": "metadata",
    ".yaml": "config", ".yml": "config", ".toml": "config",
    ".LICENSE": "license", ".license": "license"
}

def get_file_extension(path: pathlib.Path) -> str:
    """Get normalized file extension"""
    return path.suffix.lower()

def get_format_type(path: pathlib.Path) -> str:
    """Determine format type from file extension"""
    ext = get_file_extension(path)
    return EXT_MAP.get(ext, "unknown")

def walk_artifacts(root: pathlib.Path) -> Generator[pathlib.Path, None, None]:
    """
    Walk directory tree and yield ML artifacts.
    For files, yield the file itself.
    For directories, recursively find model files.
    """
    root = pathlib.Path(root)
    
    if root.is_file():
        yield root
        return
    
    # Walk directory tree
    for current_path, dirs, files in os.walk(root):
        current_path = pathlib.Path(current_path)
        
        # Check for special directory patterns (like SavedModel)
        if is_savedmodel_dir(current_path):
            yield current_path
            continue
        
        # Yield individual files that match our format patterns
        for file_name in files:
            file_path = current_path / file_name
            if should_scan_file(file_path):
                yield file_path

def should_scan_file(path: pathlib.Path) -> bool:
    """Determine if a file should be scanned based on extension and patterns"""
    if not path.is_file():
        return False
    
    # Check extension
    ext = get_file_extension(path)
    if ext in EXT_MAP:
        return True
    
    # Check special filename patterns
    name_lower = path.name.lower()
    
    # Tokenizer files
    if any(pattern in name_lower for pattern in [
        "tokenizer", "vocab", "merges", "config"
    ]):
        return True
    
    # Model card and documentation
    if any(pattern in name_lower for pattern in [
        "readme", "model_card", "license", "config"
    ]):
        return True
    
    # Binary files that might be models
    if path.stat().st_size > 1024 and not has_text_content(path):
        return True
    
    return False

def is_savedmodel_dir(path: pathlib.Path) -> bool:
    """Check if directory looks like a TensorFlow SavedModel"""
    if not path.is_dir():
        return False
    
    # Look for SavedModel signature files
    saved_model_pb = path / "saved_model.pb"
    saved_model_pbtxt = path / "saved_model.pbtxt"
    
    if saved_model_pb.exists() or saved_model_pbtxt.exists():
        return True
    
    # Check for variables directory
    variables_dir = path / "variables"
    if variables_dir.exists() and variables_dir.is_dir():
        return True
    
    return False

def has_text_content(path: pathlib.Path, sample_size: int = 1024) -> bool:
    """Check if file appears to contain text content"""
    try:
        with open(path, 'rb') as f:
            sample = f.read(sample_size)
        
        # Simple heuristic: if most bytes are printable ASCII, it's probably text
        if len(sample) == 0:
            return True  # Empty file, treat as text
        
        printable_count = sum(1 for b in sample if 32 <= b <= 126 or b in [9, 10, 13])
        ratio = printable_count / len(sample)
        
        return ratio > 0.8
    except:
        return False

def sha256_file(path: pathlib.Path, chunk_size: int = 1024*1024) -> str:
    """Calculate SHA256 hash of file"""
    hasher = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "unknown"

def md5_file(path: pathlib.Path, chunk_size: int = 1024*1024) -> str:
    """Calculate MD5 hash of file (for compatibility)"""
    hasher = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "unknown"

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    counts = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def analyze_file_entropy(path: pathlib.Path, chunk_size: int = 8192, max_chunks: int = 100) -> Dict[str, Any]:
    """Analyze entropy patterns in file to detect anomalies"""
    try:
        with open(path, 'rb') as f:
            entropies = []
            chunks_read = 0
            
            while chunks_read < max_chunks:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                entropy = calculate_entropy(chunk)
                entropies.append(entropy)
                chunks_read += 1
        
        if not entropies:
            return {"error": "No data read"}
        
        avg_entropy = sum(entropies) / len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        
        # Detect suspicious patterns
        low_entropy_chunks = sum(1 for e in entropies if e < 2.0)
        high_entropy_chunks = sum(1 for e in entropies if e > 7.0)
        
        return {
            "average_entropy": avg_entropy,
            "min_entropy": min_entropy,
            "max_entropy": max_entropy,
            "chunks_analyzed": len(entropies),
            "low_entropy_chunks": low_entropy_chunks,
            "high_entropy_chunks": high_entropy_chunks,
            "suspicious_low_entropy": low_entropy_chunks > len(entropies) * 0.1,
            "suspicious_high_entropy": high_entropy_chunks > len(entropies) * 0.1
        }
    except Exception as e:
        return {"error": str(e)}

def scan_for_magic_bytes(path: pathlib.Path, max_scan_size: int = 10*1024*1024) -> List[Dict[str, Any]]:
    """
    Scan file for embedded executable magic bytes (PE, ELF, Mach-O)
    This can detect EvilModel-style attacks where malware is hidden in model weights
    """
    magic_signatures = {
        "PE": [b"MZ"],  # Windows PE
        "ELF": [b"\x7fELF"],  # Linux ELF
        "Mach-O": [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"],
        "Java": [b"\xca\xfe\xba\xbe"],  # Java class file
        "ZIP": [b"PK\x03\x04", b"PK\x05\x06"],  # ZIP archive
        "RAR": [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
        "PDF": [b"%PDF"],
        "Script": [b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env"]
    }
    
    findings = []
    
    try:
        with open(path, 'rb') as f:
            data = f.read(max_scan_size)
        
        for sig_type, signatures in magic_signatures.items():
            for signature in signatures:
                offset = 0
                while True:
                    pos = data.find(signature, offset)
                    if pos == -1:
                        break
                    
                    findings.append({
                        "type": sig_type,
                        "signature": signature.hex(),
                        "offset": pos,
                        "context": data[max(0, pos-16):pos+len(signature)+16].hex()
                    })
                    
                    offset = pos + 1
    
    except Exception as e:
        findings.append({
            "type": "ERROR",
            "error": str(e)
                })
    
    return findings

def analyze_dimension_patterns(shape: List[int]) -> List[str]:
    """
    Analyze tensor dimensions for adversarial patterns
    Based on ML security research on dimension-based attacks
    """
    patterns = []
    
    if not shape or len(shape) == 0:
        return patterns
    
    # Check for extremely unbalanced dimensions (research indicator)
    max_dim = max(shape)
    min_dim = min(shape)
    if min_dim > 0 and max_dim / min_dim > 10000:
        patterns.append("Extreme dimension imbalance detected (potential adversarial structure)")
    
    # Check for suspicious dimension counts (>8D tensors are unusual)
    if len(shape) > 8:
        patterns.append(f"Unusual high-dimensional tensor ({len(shape)}D) - potential complexity attack")
    
    # Check for dimension repetition patterns (backdoor indicators)
    dim_counts = Counter(shape)
    repeated_dims = [dim for dim, count in dim_counts.items() if count > 3]
    if repeated_dims:
        patterns.append(f"Repeated dimension pattern: {repeated_dims} (potential backdoor indicator)")
    
    # Check for power-of-2 anomalies (evasion technique)
    power_of_2_dims = [dim for dim in shape if dim > 0 and (dim & (dim - 1)) == 0]
    if len(power_of_2_dims) > len(shape) * 0.8 and len(shape) > 2:
        patterns.append("Excessive power-of-2 dimensions (potential evasion pattern)")
    
    # Check for Fibonacci-like sequences (sophisticated attacks)
    if len(shape) >= 3 and is_fibonacci_like(shape):
        patterns.append("Fibonacci-like dimension sequence (advanced evasion technique)")
    
    return patterns

def detect_prime_dimension_attacks(shape: List[int]) -> List[str]:
    """
    Detect dimension patterns using prime numbers (research-based evasion)
    Based on "Adversarial Examples in the Physical World" and related work
    """
    findings = []
    
    if len(shape) < 2:
        return findings
    
    # Check for large prime dimensions (computational DoS)
    large_primes = [dim for dim in shape if dim > 1000 and is_likely_prime(dim)]
    if large_primes:
        findings.append(f"Large prime dimensions detected: {large_primes} (potential computational DoS)")
    
    # Check for all-prime patterns (sophisticated evasion)
    prime_dims = [dim for dim in shape if dim > 1 and is_likely_prime(dim)]
    if len(prime_dims) >= 3 and len(prime_dims) == len(shape):
        findings.append("All dimensions are prime numbers (advanced evasion technique)")
    
    return findings

def is_likely_prime(n: int) -> bool:
    """Simple primality test for dimension analysis"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    # Check odd divisors up to sqrt(n)
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def is_fibonacci_like(sequence: List[int]) -> bool:
    """Check if dimension sequence follows Fibonacci-like pattern"""
    if len(sequence) < 3:
        return False
    
    # Allow for some tolerance in the pattern
    tolerance_count = 0
    max_tolerance = len(sequence) // 3
    
    for i in range(2, len(sequence)):
        expected = sequence[i-2] + sequence[i-1]
        if abs(sequence[i] - expected) > expected * 0.1:  # 10% tolerance
            tolerance_count += 1
            if tolerance_count > max_tolerance:
                return False
    
    return True

def calculate_dimension_variance(shape: List[int]) -> float:
    """Calculate variance in tensor dimensions"""
    if len(shape) <= 1:
        return 0.0
    
    mean_dim = sum(shape) / len(shape)
    variance = sum((dim - mean_dim) ** 2 for dim in shape) / len(shape)
    return variance

def get_file_metadata(path: pathlib.Path) -> Dict[str, Any]:
    """Get comprehensive file metadata"""
    try:
        stat = path.stat()
        
        metadata = {
            "path": str(path),
            "name": path.name,
            "extension": get_file_extension(path),
            "format_type": get_format_type(path),
            "size_bytes": stat.st_size,
            "size_human": format_bytes(stat.st_size),
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
            "accessed": stat.st_atime,
            "sha256": sha256_file(path),
            "md5": md5_file(path)
        }
        
        # Add entropy analysis for binary files
        if not has_text_content(path) and stat.st_size > 0:
            metadata["entropy_analysis"] = analyze_file_entropy(path)
        
        # Scan for embedded executables in larger files
        if stat.st_size > 1024:
            magic_findings = scan_for_magic_bytes(path)
            if magic_findings:
                metadata["embedded_signatures"] = magic_findings
        
        return metadata
        
    except Exception as e:
        return {
            "path": str(path),
            "error": str(e)
        }

def format_bytes(size_bytes: int) -> str:
    """Format byte size as human readable string"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"

def safe_read_text_file(path: pathlib.Path, max_size: int = 1024*1024, encoding: str = 'utf-8') -> Optional[str]:
    """Safely read text file with size limits"""
    try:
        if path.stat().st_size > max_size:
            return None  # File too large
        
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
    except Exception:
        # Try with different encodings
        for fallback_encoding in ['latin-1', 'ascii']:
            try:
                with open(path, 'r', encoding=fallback_encoding, errors='ignore') as f:
                    return f.read()
            except Exception:
                continue
        return None

def safe_read_binary_chunk(path: pathlib.Path, offset: int = 0, size: int = 8192) -> Optional[bytes]:
    """Safely read binary chunk from file"""
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            return f.read(size)
    except Exception:
        return None

def is_suspicious_path(path_str: str) -> bool:
    """Check if path contains suspicious patterns (path traversal, etc.)"""
    suspicious_patterns = [
        "..", "/etc/", "/usr/", "/bin/", "/var/",
        "\\windows\\", "\\system32\\", "c:\\",
        "file://", "http://", "https://", "ftp://",
        "\x00", "\x1a", "\x1b"  # Null bytes and escape sequences
    ]
    
    path_lower = path_str.lower()
    return any(pattern in path_lower for pattern in suspicious_patterns)

def validate_tensor_dimensions(shape: List[int], dtype_size: int = 4) -> Dict[str, Any]:
    """
    Advanced tensor dimension validation for DoS and memory bomb detection
    Based on research from:
    - "Adversarial Weight Perturbations Help Robust Generalization" (Madry et al.)
    - "Model Extraction Attacks on Graph Neural Networks" (Zhang et al.)
    - Industrial ML security reports (Trail of Bits, HiddenLayer)
    """
    if not shape:
        return {"valid": True}
    
    try:
        # Calculate total elements with overflow detection
        total_elements = 1
        for dim in shape:
            if dim < 0:
                return {"valid": False, "reason": "Negative dimension (potential integer underflow attack)"}
            if dim > 2**31:  # Unreasonably large dimension
                return {"valid": False, "reason": "Dimension too large (potential memory bomb)"}
            if total_elements > 0 and dim > 0 and total_elements > (2**63 - 1) // dim:
                return {"valid": False, "reason": "Integer overflow in element calculation"}
            total_elements *= dim
        
        # Calculate memory requirements
        memory_bytes = total_elements * dtype_size
        memory_gb = memory_bytes / (1024**3)
        
        # Enhanced DoS detection based on real-world attacks
        max_elements_standard = 3_000_000_000  # 3B elements (standard)
        max_elements_extreme = 100_000_000_000  # 100B elements (extreme DoS)
        max_memory_gb = 64  # 64GB max reasonable
        max_memory_extreme = 512  # 512GB extreme DoS threshold
        
        # Check for various attack patterns
        findings = []
        risk_score = 0
        
        if total_elements > max_elements_extreme:
            findings.append("CRITICAL: Potential tensor bomb - element count exceeds realistic limits")
            risk_score += 30
        elif total_elements > max_elements_standard:
            findings.append("HIGH: Very large tensor - potential resource exhaustion")
            risk_score += 20
        
        if memory_gb > max_memory_extreme:
            findings.append("CRITICAL: Memory bomb detected - would exhaust system resources")
            risk_score += 35
        elif memory_gb > max_memory_gb:
            findings.append("HIGH: Excessive memory requirements detected")
            risk_score += 15
        
        # Detect suspicious dimension patterns (adversarial research indicators)
        suspicious_patterns = analyze_dimension_patterns(shape)
        if suspicious_patterns:
            findings.extend(suspicious_patterns)
            risk_score += len(suspicious_patterns) * 5
        
        # Check for prime dimension attacks (research-based)
        prime_risks = detect_prime_dimension_attacks(shape)
        if prime_risks:
            findings.extend(prime_risks)
            risk_score += 10
        
        return {
            "valid": risk_score < 30,  # Fail if risk too high
            "total_elements": total_elements,
            "memory_bytes": memory_bytes,
            "memory_gb": memory_gb,
            "risk_score": risk_score,
            "findings": findings,
            "dimension_analysis": {
                "max_dimension": max(shape) if shape else 0,
                "min_dimension": min(shape) if shape else 0,
                "dimension_count": len(shape),
                "dimension_variance": calculate_dimension_variance(shape)
            }
        }
        
    except (OverflowError, ValueError) as e:
        return {"valid": False, "reason": f"Calculation error (potential attack): {e}"}

def detect_magic_bytes(file_path: str, max_read: int = 1024) -> List[Dict[str, Any]]:
    """
    Detect magic bytes in a file to identify embedded formats or suspicious content
    
    Args:
        file_path: Path to the file to analyze
        max_read: Maximum bytes to read from start of file
    
    Returns:
        List of detected magic byte patterns with metadata
    """
    
    # Known magic byte signatures
    MAGIC_SIGNATURES = {
        # Archive/compression formats
        b'\x50\x4b\x03\x04': {'format': 'ZIP', 'severity': 'low', 'description': 'ZIP archive'},
        b'\x50\x4b\x05\x06': {'format': 'ZIP', 'severity': 'low', 'description': 'ZIP archive (empty)'},
        b'\x1f\x8b\x08': {'format': 'GZIP', 'severity': 'low', 'description': 'GZIP compressed data'},
        b'\x42\x5a\x68': {'format': 'BZIP2', 'severity': 'low', 'description': 'BZIP2 compressed data'},
        b'\x7f\x45\x4c\x46': {'format': 'ELF', 'severity': 'high', 'description': 'ELF executable'},
        
        # Executable formats (DANGEROUS)
        b'\x4d\x5a': {'format': 'PE', 'severity': 'critical', 'description': 'Windows PE executable'},
        b'\xfe\xed\xfa\xce': {'format': 'MACH-O', 'severity': 'critical', 'description': 'macOS Mach-O executable (32-bit)'},
        b'\xfe\xed\xfa\xcf': {'format': 'MACH-O', 'severity': 'critical', 'description': 'macOS Mach-O executable (64-bit)'},
        b'\xcf\xfa\xed\xfe': {'format': 'MACH-O', 'severity': 'critical', 'description': 'macOS Mach-O executable (reverse)'},
        
        # Script formats (SUSPICIOUS)
        b'#!/bin/sh': {'format': 'SHELL', 'severity': 'medium', 'description': 'Shell script'},
        b'#!/bin/bash': {'format': 'BASH', 'severity': 'medium', 'description': 'Bash script'},
        b'#!/usr/bin/python': {'format': 'PYTHON', 'severity': 'medium', 'description': 'Python script'},
        b'#!/usr/bin/env python': {'format': 'PYTHON', 'severity': 'medium', 'description': 'Python script'},
        
        # ML model formats
        b'ONNX': {'format': 'ONNX', 'severity': 'low', 'description': 'ONNX model file'},
        b'\x80\x02': {'format': 'PICKLE', 'severity': 'critical', 'description': 'Pickle protocol 2'},
        b'\x80\x03': {'format': 'PICKLE', 'severity': 'critical', 'description': 'Pickle protocol 3'},
        b'\x80\x04': {'format': 'PICKLE', 'severity': 'critical', 'description': 'Pickle protocol 4'},
        b'\x80\x05': {'format': 'PICKLE', 'severity': 'critical', 'description': 'Pickle protocol 5'},
        
        # PyTorch magic bytes
        b'PK\x03\x04': {'format': 'PYTORCH_ZIP', 'severity': 'high', 'description': 'PyTorch model (ZIP-based)'},
        
        # SafeTensors magic
        b'{"': {'format': 'SAFETENSORS_JSON', 'severity': 'low', 'description': 'Potential SafeTensors header'},
        
        # Java class files (can contain malicious code)
        b'\xca\xfe\xba\xbe': {'format': 'JAVA_CLASS', 'severity': 'high', 'description': 'Java class file'},
        
        # PDF (can contain JavaScript)
        b'%PDF-': {'format': 'PDF', 'severity': 'medium', 'description': 'PDF document'},
        
        # Office documents (can contain macros)
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'format': 'OLE', 'severity': 'medium', 'description': 'Microsoft Office document'},
    }
    
    findings = []
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read(max_read)
        
        # Check for magic byte signatures
        for magic_bytes, info in MAGIC_SIGNATURES.items():
            if data.startswith(magic_bytes):
                findings.append({
                    'offset': 0,
                    'magic_bytes': magic_bytes.hex(),
                    'format': info['format'],
                    'severity': info['severity'],
                    'description': info['description'],
                    'length': len(magic_bytes)
                })
            
            # Also check for magic bytes not at the start (embedded content)
            pos = data.find(magic_bytes, 1)  # Skip position 0
            while pos != -1:
                findings.append({
                    'offset': pos,
                    'magic_bytes': magic_bytes.hex(),
                    'format': info['format'],
                    'severity': 'high',  # Embedded content is more suspicious
                    'description': f"Embedded {info['description']} at offset {pos}",
                    'length': len(magic_bytes)
                })
                pos = data.find(magic_bytes, pos + 1)
        
        # Check for suspicious byte patterns
        if b'eval(' in data or b'exec(' in data:
            findings.append({
                'offset': data.find(b'eval(') if b'eval(' in data else data.find(b'exec('),
                'magic_bytes': '',
                'format': 'EVAL_EXEC',
                'severity': 'critical',
                'description': 'Suspicious eval/exec pattern found',
                'length': 5
            })
        
        # Check for base64 encoded content (common in attacks)
        import re
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
        for match in b64_pattern.finditer(data):
            if len(match.group()) > 100:  # Only flag long base64 strings
                findings.append({
                    'offset': match.start(),
                    'magic_bytes': '',
                    'format': 'BASE64',
                    'severity': 'medium',
                    'description': f'Long base64-encoded content ({len(match.group())} bytes)',
                    'length': len(match.group())
                })
        
    except (IOError, OSError) as e:
        findings.append({
            'offset': -1,
            'magic_bytes': '',
            'format': 'ERROR',
            'severity': 'high',
            'description': f'Error reading file: {e}',
            'length': 0
        })
    
    return findings