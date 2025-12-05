#!/usr/bin/env python3
"""
SMART-01 AI Security Scanner v2.0.0 - Unified CLI Implementation
Neural network threat detection framework with zero-execution security policy

This is the complete, unified implementation matching the CLI reference documentation.
All functionality is contained in this single file for simplicity and reliability.

Usage Examples:
  python smart-ai-scanner.py scan model.pkl
  python smart-ai-scanner.py scan ./models --recursive --policy strict
  python smart-ai-scanner.py scan model.pkl --format json -o results.json
  python smart-ai-scanner.py interactive
  python smart-ai-scanner.py info --scanners
  python smart-ai-scanner.py version

Author: SMART-01 AI Security Research Team
License: MIT
Version: 2.0.0
Repository: https://github.com/yourusername/smart-ai-scanner
"""

import argparse
import sys
import os
import pathlib
import time
import json
import traceback
import math
import fnmatch
import textwrap
import re
from collections import Counter
from typing import List, Optional, Dict, Any

# ============================================================================
# DEPENDENCY IMPORTS WITH GRACEFUL FALLBACKS
# ============================================================================

# Color support
try:
    from colorama import Fore, Style, Back, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLUE_EX = LIGHTGREEN_EX = LIGHTCYAN_EX = LIGHTWHITE_EX = ""
    class Style:
        BRIGHT = RESET_ALL = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

# Rich UI support (optional enhancement)
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Core scanning components (with fallbacks)
try:
    # Add current directory to path for imports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    
    from core.registry import ScannerRegistry
    from core.rules import RuleEngine
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

__version__ = "2.0.0"
__author__ = "SMART-01 AI Security Research Team"
__license__ = "MIT"
__repository__ = "https://github.com/yourusername/smart-ai-scanner"

REPORTS_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__))) / "reports"

# Security policies
SECURITY_POLICIES = {
    "strict": "Maximum security enforcement - blocks dangerous formats",
    "enterprise": "Balanced security for business environments (default)",
    "research": "Permissive mode for research and development",
    "forensics": "Analysis mode - comprehensive scanning"
}

# Supported formats with risk levels
SUPPORTED_FORMATS = {
    "CRITICAL": {
        "extensions": [".pkl", ".pickle", ".dill", ".joblib"],
        "description": "Pickle/Joblib - Arbitrary code execution risk"
    },
    "HIGH": {
        "extensions": [".pt", ".pth", ".ckpt", ".mar", ".h5", ".keras"],
        "description": "PyTorch/Keras - Unsafe serialization risk"
    },
    "MEDIUM": {
        "extensions": [".onnx", ".model", ".cbm", ".mlmodel", ".gguf", ".ggml"],
        "description": "ONNX/XGBoost/CatBoost/CoreML/GGUF - Custom operator risk"
    },
    "LOW": {
        "extensions": [".safetensors", "tokenizer.json", "vocab.txt", "vocab.json", "merges.txt"],
        "description": "SafeTensors/Tokenizer - Generally safe formats"
    }
}

# Available scanners
AVAILABLE_SCANNERS = [
    ("AdvancedPickleScanner", "CRITICAL", "Detects arbitrary code execution in pickle files"),
    ("AdvancedPyTorchScanner", "HIGH", "Analyzes PyTorch models for unsafe serialization"),
    ("AdvancedKerasScanner", "HIGH", "Scans Keras models for lambda layer exploits"),
    ("AdvancedLLMBackdoorScanner", "HIGH", "Detects LLM backdoors and token poisoning"),
    ("AdvancedONNXScanner", "MEDIUM", "Validates ONNX models for custom operators"),
    ("AdvancedXGBoostScanner", "MEDIUM", "XGBoost model security analysis"),
    ("AdvancedLightGBMScanner", "MEDIUM", "LightGBM model validation"),
    ("AdvancedCatBoostScanner", "MEDIUM", "CatBoost model inspection"),
    ("AdvancedCoreMLScanner", "MEDIUM", "CoreML model security analysis"),
    ("AdvancedGGUFScanner", "MEDIUM", "GGUF/GGML large language model analysis"),
    ("WeightPoisoningScanner", "MEDIUM", "Statistical weight tampering detection"),
    ("SafeTensorsScanner", "LOW", "SafeTensors format integrity validation"),
    ("AdvancedTokenizerScanner", "LOW", "Tokenizer configuration security analysis")
]

# ============================================================================
# UI AND BANNER FUNCTIONS
# ============================================================================

def create_professional_banner(use_colors: bool = True) -> str:
    """Create the professional SMART-01 banner"""
    
    banner_art = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ███████╗███╗   ███╗ █████╗ ██████╗ ████████╗        ██████╗  ██╗         ║
║     ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝       ██╔═████╗███║         ║
║     ███████╗██╔████╔██║███████║██████╔╝   ██║   █████╗ ██║██╔██║╚██║         ║
║     ╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║   ╚════╝ ████╔╝██║ ██║         ║
║     ███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║          ╚██████╔╝ ██║         ║
║     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝           ╚═════╝  ╚═╝         ║
║                                                                              ║
║     ARTIFICIAL INTELLIGENCE SECURITY RESEARCH FRAMEWORK                      ║
║     Neural Network Threat Detection  |  LLM Backdoor Analysis                ║
║     Static Analysis Engine  |  Zero-Execution Security Policy                ║
║                                                                              ║
║     Contact & Support: x.com/5m477  |  Research-Based ML Security            ║
╚══════════════════════════════════════════════════════════════════════════════╝"""
    
    if use_colors and COLORAMA_AVAILABLE:
        lines = banner_art.split('\n') 
        colored_banner = []
        
        for line in lines:
            if '███' in line or '██╗' in line or '██║' in line:
                colored_banner.append(f"{Fore.CYAN}{Style.BRIGHT}{line}{Style.RESET_ALL}")
            elif 'ARTIFICIAL' in line or 'Neural' in line or 'Static' in line:
                colored_banner.append(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            elif '╔' in line or '║' in line or '╚' in line:
                colored_banner.append(f"{Fore.WHITE}{Style.BRIGHT}{line}{Style.RESET_ALL}")
            else:
                colored_banner.append(line)
        
        banner = '\n'.join(colored_banner)
        
        # Add status indicators with proper padding
        status_width = 78
        banner += f"\n\n{Fore.GREEN}{Style.BRIGHT}┌─ SYSTEM STATUS {'─' * (status_width - 16)}┐{Style.RESET_ALL}\n"
        
        # Format each status line with proper spacing
        line1_left = f"{Fore.YELLOW}●{Style.RESET_ALL} ML Threat Detection"
        line1_right = f"{Fore.GREEN}●{Style.RESET_ALL} {len(AVAILABLE_SCANNERS)} Active Scanners"
        line1_padding = status_width - len("● ML Threat Detection") - len(f"● {len(AVAILABLE_SCANNERS)} Active Scanners") - 2
        banner += f"{Fore.GREEN}│{Style.RESET_ALL} {line1_left}" + " " * line1_padding + f"{line1_right} {Fore.GREEN}│{Style.RESET_ALL}\n"
        
        line2_left = f"{Fore.GREEN}●{Style.RESET_ALL} Zero Execution Policy"
        line2_right = f"{Fore.GREEN}●{Style.RESET_ALL} LLM Security Module"
        line2_padding = status_width - len("● Zero Execution Policy") - len("● LLM Security Module") - 2
        banner += f"{Fore.GREEN}│{Style.RESET_ALL} {line2_left}" + " " * line2_padding + f"{line2_right} {Fore.GREEN}│{Style.RESET_ALL}\n"
        
        line3_left = f"{Fore.CYAN}●{Style.RESET_ALL} Research-Based Framework"
        line3_right = f"{Fore.GREEN}●{Style.RESET_ALL} Production Ready"
        line3_padding = status_width - len("● Research-Based Framework") - len("● Production Ready") - 2
        banner += f"{Fore.GREEN}│{Style.RESET_ALL} {line3_left}" + " " * line3_padding + f"{line3_right} {Fore.GREEN}│{Style.RESET_ALL}\n"
        
        banner += f"{Fore.GREEN}└{'─' * (status_width - 2)}┘{Style.RESET_ALL}\n"
        
        return banner
    
    # No-color fallback with proper formatting
    status_banner = f"\n\n┌─ SYSTEM STATUS ──────────────────────────────────────────────────────────┐\n"
    status_banner += f"│ ● ML Threat Detection    ● {len(AVAILABLE_SCANNERS)} Active Scanners         │\n"
    status_banner += f"│ ● Zero Execution Policy   ● LLM Security Module         │\n"  
    status_banner += f"│ ● Research-Based Framework ● Production Ready           │\n"
    status_banner += f"└──────────────────────────────────────────────────────────────────────────┘\n"
    
    return banner_art + status_banner

def show_banner(use_colors: bool = True):
    """Display the professional banner"""
    print(create_professional_banner(use_colors))

def create_section_header_text(title: str, style: str = "info", use_colors: bool = True) -> str:
    """Create a section header"""
    if use_colors and COLORAMA_AVAILABLE:
        style_colors = {
            "info": Fore.LIGHTCYAN_EX,
            "scan": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        color = style_colors.get(style, Fore.LIGHTCYAN_EX)
        
        header = f"\n{color}{Style.BRIGHT}{'━' * 80}{Style.RESET_ALL}\n"
        header += f"{color}{Style.BRIGHT}▶ {title.upper()}{Style.RESET_ALL}\n"
        header += f"{color}{Style.BRIGHT}{'━' * 80}{Style.RESET_ALL}\n"
        return header
    else:
        return f"\n{'=' * 80}\n▶ {title.upper()}\n{'=' * 80}\n"

def create_status_panel_text(title: str, content: dict, use_colors: bool = True):
    """Create a status information panel with proper padding"""
    
    # Calculate proper width - minimum 60, maximum 100, based on content
    content_widths = [len(f"{k}: {v}") for k, v in content.items()]
    title_width = len(title)
    max_content_width = max(content_widths) if content_widths else 0
    
    # Set width with proper margins: 4 chars for padding + borders + some extra space
    width = max(60, min(100, max(title_width + 6, max_content_width + 8)))
    
    if use_colors and COLORAMA_AVAILABLE:
        # Create title bar with proper centering
        title_padding = width - len(title) - 4  # Account for border chars and spaces
        left_pad = title_padding // 2
        right_pad = title_padding - left_pad

        border_color = Fore.LIGHTCYAN_EX
        key_color = Fore.LIGHTWHITE_EX
        print(f"\n{border_color}{Style.BRIGHT}╭{'─' * left_pad} {title} {'─' * right_pad}╮{Style.RESET_ALL}")

        # Empty line for spacing
        print(f"{border_color}│{Style.RESET_ALL}" + " " * (width - 2) + f"{border_color}│{Style.RESET_ALL}")

        # Content lines with proper padding
        for key, value in content.items():
            content_text = f"  {key}: {value}"
            content_length = len(content_text)
            remaining_space = width - content_length - 2  # -2 for border chars

            if remaining_space < 0:
                # Truncate if too long
                content_text = content_text[:width-5] + "..."
                remaining_space = 0

            print(f"{border_color}│{Style.RESET_ALL}{key_color}{Style.BRIGHT}  {key}:{Style.RESET_ALL} {value}" + " " * remaining_space + f"{border_color}│{Style.RESET_ALL}")

        # Empty line for spacing
        print(f"{border_color}│{Style.RESET_ALL}" + " " * (width - 2) + f"{border_color}│{Style.RESET_ALL}")

        # Bottom border
        print(f"{border_color}╰{'─' * (width - 2)}╯{Style.RESET_ALL}")
    else:
        # Simple text fallback with consistent formatting
        print(f"\n┌─ {title} " + "─" * max(0, width - len(title) - 4) + "┐")
        print("│" + " " * (width - 2) + "│")
        
        for key, value in content.items():
            content_text = f"  {key}: {value}"
            content_length = len(content_text)
            remaining_space = width - content_length - 2
            
            if remaining_space < 0:
                content_text = content_text[:width-5] + "..."
                remaining_space = 0
            
            print(f"│{content_text}" + " " * remaining_space + "│")
        
        print("│" + " " * (width - 2) + "│")
        print("└" + "─" * (width - 2) + "┘")

def colorize_text(text: str, severity: str, use_colors: bool = True) -> str:
    """Add color to text based on severity"""
    if not use_colors or not COLORAMA_AVAILABLE:
        return text
    
    colors = {
        "CRITICAL": f"{Fore.RED}{Style.BRIGHT}",
        "HIGH": f"{Fore.YELLOW}{Style.BRIGHT}",
        "MEDIUM": f"{Fore.CYAN}",
        "LOW": f"{Fore.LIGHTCYAN_EX}",
        "SUCCESS": f"{Fore.GREEN}",
        "ERROR": f"{Fore.RED}",
        "INFO": f"{Fore.LIGHTWHITE_EX}{Style.BRIGHT}"
    }
    
    color = colors.get(severity.upper(), "")
    return f"{color}{text}{Style.RESET_ALL}"

# ============================================================================
# SECURITY ANALYSIS FUNCTIONS
# ============================================================================

def analyze_pickle_file(file_path: str, file_size: int) -> list:
    """Analyze pickle files for security threats"""
    findings = [{
        'level': 'CRITICAL',
        'scanner': 'AdvancedPickleScanner',
        'issue': 'Dangerous pickle format detected',
        'risk': 'Arbitrary code execution during deserialization',
        'cwe': 'CWE-502',
        'recommendation': 'Use SafeTensors or ONNX format instead'
    }]
    
    # Additional checks for large pickle files
    if file_size > 100 * 1024 * 1024:  # > 100MB
        findings.append({
            'level': 'HIGH',
            'scanner': 'AdvancedPickleScanner',
            'issue': 'Large pickle file detected',
            'risk': 'Potential for complex malicious payloads',
            'cwe': 'CWE-502'
        })
    
    return findings

def analyze_pytorch_file(file_path: str, file_size: int) -> list:
    """Analyze PyTorch files for security threats"""
    findings = [{
        'level': 'HIGH',
        'scanner': 'AdvancedPyTorchScanner',
        'issue': 'PyTorch model contains pickle data',
        'risk': 'Custom unpickler exploits possible',
        'cwe': 'CWE-502',
        'recommendation': 'Verify model source and consider SafeTensors conversion'
    }]
    
    # Check for potential LLM models
    if file_size > 100 * 1024 * 1024:  # > 100MB suggests LLM
        findings.append({
            'level': 'HIGH',
            'scanner': 'AdvancedLLMBackdoorScanner',
            'issue': 'Large language model detected - potential backdoor risk',
            'risk': 'Weight poisoning, prompt injection vulnerabilities',
            'cwe': 'CWE-506'
        })
    
    return findings

def analyze_keras_file(file_path: str, file_size: int) -> list:
    """Analyze Keras files for security threats"""
    return [{
        'level': 'HIGH',
        'scanner': 'AdvancedKerasScanner',
        'issue': 'Keras model requires validation',
        'risk': 'Lambda layers may contain arbitrary code',
        'cwe': 'CWE-94',
        'recommendation': 'Inspect model architecture for custom layers'
    }]

def analyze_onnx_file(file_path: str, file_size: int) -> list:
    """Analyze ONNX files for security threats"""
    return [{
        'level': 'MEDIUM',
        'scanner': 'AdvancedONNXScanner',
        'issue': 'ONNX model requires validation',
        'risk': 'Potential custom operators or external data references',
        'cwe': 'CWE-470',
        'recommendation': 'Verify custom operators and external data sources'
    }]

def analyze_safetensors_file(file_path: str, file_size: int) -> list:
    """Analyze SafeTensors files"""
    return [{
        'level': 'LOW',
        'scanner': 'SafeTensorsScanner',
        'issue': 'SafeTensors format validation',
        'risk': 'Generally safe but requires structure validation',
        'cwe': 'CWE-20',
        'recommendation': 'SafeTensors is the recommended safe format'
    }]

def analyze_json_file(file_path: str, file_name: str) -> list:
    """Analyze JSON configuration and tokenizer files"""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Tokenizer analysis
        if 'tokenizer' in file_name or file_name in ['vocab.txt', 'vocab.json', 'merges.txt']:
            suspicious_patterns = {
                # Critical patterns
                'eval(': 'Direct code evaluation',
                'exec(': 'Direct code execution',
                '__import__(': 'Dynamic module import',
                'subprocess.': 'System command execution',
                
                # Steganographic patterns
                '\\u200b': 'Zero-width space character',
                '\\u200c': 'Zero-width non-joiner',
                '\\u200d': 'Zero-width joiner',
                
                # Injection patterns
                'javascript:': 'JavaScript injection vector',
                '<script': 'Script tag injection',
                'onload=': 'Event handler injection'
            }
            
            found_patterns = []
            critical_patterns = []
            
            for pattern, desc in suspicious_patterns.items():
                if pattern in content.lower():
                    found_patterns.append(f"{pattern} ({desc})")
                    if pattern in ['eval(', 'exec(', '__import__', 'subprocess.']:
                        critical_patterns.append(pattern)
            
            if critical_patterns:
                findings.append({
                    'level': 'CRITICAL',
                    'scanner': 'AdvancedTokenizerScanner',
                    'issue': 'Critical tokenizer threats detected',
                    'risk': 'Code execution patterns in tokenizer configuration',
                    'cwe': 'CWE-94',
                    'details': found_patterns[:3]
                })
            elif found_patterns:
                findings.append({
                    'level': 'MEDIUM',
                    'scanner': 'AdvancedTokenizerScanner',
                    'issue': 'Suspicious tokenizer patterns detected',
                    'risk': 'Potential injection or manipulation vectors',
                    'cwe': 'CWE-20',
                    'details': found_patterns[:3]
                })
            elif len(content) > 10000:  # Large tokenizer
                findings.append({
                    'level': 'LOW',
                    'scanner': 'AdvancedTokenizerScanner',
                    'issue': 'Large tokenizer file requires review',
                    'risk': 'Complex tokenizers may hide sophisticated attacks',
                    'cwe': 'CWE-20'
                })
        
        # Configuration analysis
        elif 'config' in file_name:
            dangerous_configs = [
                ('trust_remote_code', 'CRITICAL', 'Allows arbitrary code execution from remote sources'),
                ('custom_code', 'CRITICAL', 'Custom code execution capability'),
                ('eval(', 'CRITICAL', 'Direct code evaluation in config'),
                ('exec(', 'CRITICAL', 'Direct code execution in config'),
                ('torch.jit', 'HIGH', 'PyTorch JIT compilation enabled'),
                ('subprocess', 'HIGH', 'System command execution capability')
            ]
            
            for config_item, severity, description in dangerous_configs:
                if config_item in content.lower():
                    # Special check for trust_remote_code enabled
                    if config_item == 'trust_remote_code' and 'true' in content.lower():
                        findings.append({
                            'level': 'CRITICAL',
                            'scanner': 'AdvancedLLMBackdoorScanner',
                            'issue': 'Configuration enables remote code execution',
                            'risk': 'trust_remote_code=True allows arbitrary code execution from Hugging Face Hub',
                            'cwe': 'CWE-94',
                            'recommendation': 'Set trust_remote_code=False or audit remote code'
                        })
                    else:
                        findings.append({
                            'level': severity,
                            'scanner': 'AdvancedLLMBackdoorScanner',
                            'issue': f'Dangerous configuration detected: {config_item}',
                            'risk': description,
                            'cwe': 'CWE-94' if severity == 'CRITICAL' else 'CWE-16'
                        })
    
    except Exception as e:
        findings.append({
            'level': 'MEDIUM',
            'scanner': 'FileAnalysisScanner',
            'issue': f'Unable to parse JSON file: {str(e)}',
            'risk': 'Malformed or obfuscated file data',
            'cwe': 'CWE-20'
        })
    
    return findings

def calculate_entropy(file_path: str, sample_size: int = 1024*1024) -> float:
    """Calculate Shannon entropy for weight poisoning detection"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)
        
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    except Exception:
        return 0.0

def scan_single_file(file_path: str, policy: str = "enterprise", use_colors: bool = True) -> dict:
    """Scan a single file for security threats"""
    
    path = pathlib.Path(file_path)
    
    if not path.exists():
        return {
            "file": str(path),
            "error": "File not found",
            "findings": [],
            "scan_time": 0
        }
    
    start_time = time.time()
    
    # Get file info
    stat = path.stat()
    file_size = stat.st_size
    file_ext = path.suffix.lower()
    file_name = path.name.lower()
    
    findings = []
    
    # Format-specific analysis
    if file_ext in ['.pkl', '.pickle', '.dill', '.joblib']:
        findings.extend(analyze_pickle_file(str(path), file_size))
    
    elif file_ext in ['.pt', '.pth', '.ckpt', '.mar']:
        findings.extend(analyze_pytorch_file(str(path), file_size))
    
    elif file_ext in ['.h5', '.keras']:
        findings.extend(analyze_keras_file(str(path), file_size))
    
    elif file_ext in ['.onnx']:
        findings.extend(analyze_onnx_file(str(path), file_size))
    
    elif file_ext in ['.safetensors']:
        findings.extend(analyze_safetensors_file(str(path), file_size))
    
    elif file_ext in ['.json'] or file_name in ['vocab.txt', 'vocab.json', 'merges.txt']:
        findings.extend(analyze_json_file(str(path), file_name))
    
    # Weight poisoning analysis for binary model files
    if file_ext in ['.bin', '.safetensors'] and file_size > 50 * 1024 * 1024:
        entropy = calculate_entropy(str(path))
        if entropy > 7.5:
            findings.append({
                'level': 'MEDIUM',
                'scanner': 'WeightPoisoningScanner',
                'issue': f'High entropy detected: {entropy:.3f}',
                'risk': 'Potential weight poisoning or obfuscation',
                'cwe': 'CWE-506'
            })
        elif entropy < 2.0:
            findings.append({
                'level': 'LOW',
                'scanner': 'WeightPoisoningScanner',
                'issue': 'Unusual weight patterns detected',
                'risk': 'Weights show unexpected uniformity',
                'cwe': 'CWE-20'
            })
    
    # Policy-based filtering
    if policy == "strict":
        # In strict mode, flag any format as requiring review
        if not findings and file_ext not in ['.safetensors']:
            findings.append({
                'level': 'MEDIUM',
                'scanner': 'PolicyScanner',
                'issue': 'File format requires strict policy review',
                'risk': 'Strict policy requires manual verification',
                'cwe': 'CWE-20'
            })
    
    scan_time = time.time() - start_time
    
    return {
        "file": str(path),
        "size": file_size,
        "findings": findings,
        "scan_time": scan_time,
        "scanners_used": list(set([f['scanner'] for f in findings]))
    }

# ============================================================================
# CLI ARGUMENT PARSER
# ============================================================================

def create_argument_parser() -> argparse.ArgumentParser:
    """Create comprehensive argument parser matching CLI reference"""
    
    parser = argparse.ArgumentParser(
        prog="smart-ai-scanner",
        description=f"SMART-01 AI Security Scanner v{__version__} - Neural network threat detection framework\n"
                   "Static analysis engine with zero-execution security policy for ML models",
        epilog="""Examples:
  smart-ai-scanner scan model.pkl
  smart-ai-scanner scan ./models --recursive --policy strict
  smart-ai-scanner scan model.pkl --format json -o results.json
  smart-ai-scanner interactive
  smart-ai-scanner info --scanners
  smart-ai-scanner version
  
For more information, visit: """ + __repository__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands', metavar='COMMAND')
    
    # === SCAN Command ===
    scan_parser = subparsers.add_parser(
        'scan', 
        help='Scan ML models for security vulnerabilities',
        description='Comprehensive security analysis of machine learning models'
    )
    scan_parser.add_argument('path', help='File or directory path to scan')
    scan_parser.add_argument('--recursive', '-r', action='store_true', 
                           help='Recursively scan directories (default: False)')
    scan_parser.add_argument('--policy', 
                           choices=['strict', 'enterprise', 'research', 'forensics'],
                           default='enterprise', 
                           help='Security policy level (default: enterprise)')
    scan_parser.add_argument('--format', 
                           choices=['console', 'json', 'sarif'],
                           default='console', 
                           help='Output format (default: console)')
    scan_parser.add_argument('--output', '-o', 
                           help='Output file path (default: stdout)')
    scan_parser.add_argument('--rules',
                           help='Custom rules YAML file')
    scan_parser.add_argument('--extensions', nargs='+', 
                           help='Filter by file extensions (e.g., .pkl .onnx .h5)')
    scan_parser.add_argument('--exclude', nargs='+',
                           help='Exclude paths (glob patterns)')
    scan_parser.add_argument('--sbom', 
                           help='Generate SBOM file path')
    scan_parser.add_argument('--no-colors', action='store_true',
                           help='Disable colored output')
    scan_parser.add_argument('--quiet', '-q', action='store_true',
                           help='Quiet mode: minimal output')
    scan_parser.add_argument('--verbose', '-v', action='store_true',
                           help='Verbose mode: detailed output')
    
    # === INFO Command ===
    info_parser = subparsers.add_parser(
        'info', 
        help='Display scanner capabilities and system information'
    )
    info_parser.add_argument('--formats', action='store_true',
                           help='List supported ML model formats')
    info_parser.add_argument('--scanners', action='store_true',
                           help='List available security scanners')
    info_parser.add_argument('--policies', action='store_true',
                           help='List security policies')
    
    # === VERSION Command ===
    version_parser = subparsers.add_parser(
        'version', 
        help='Show version and system information'
    )
    
    # === INTERACTIVE Command ===
    interactive_parser = subparsers.add_parser(
        'interactive', 
        help='Launch interactive scanning wizard'
    )
    
    return parser

# ============================================================================
# COMMAND HANDLERS
# ============================================================================

def handle_version_command(args) -> int:
    """Handle the version command"""
    
    show_banner(use_colors=not args.no_colors if hasattr(args, 'no_colors') else True)
    
    # System information
    system_info = {
        "Version": __version__,
        "Author": __author__,
        "License": __license__,
        "Python Version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "Platform": sys.platform,
        "Core Components": "Available" if CORE_AVAILABLE else "Built-in Mode",
        "Rich UI": "Available" if RICH_AVAILABLE else "Basic Text",
        "Colorama": "Available" if COLORAMA_AVAILABLE else "Not Available",
        "Active Scanners": str(len(AVAILABLE_SCANNERS))
    }
    
    create_status_panel_text("System Information", system_info, use_colors=True)
    
    print(f"Repository: {__repository__}")
    print(f"Documentation: See README.md and docs/ directory")
    print()
    
    return 0

def handle_info_command(args) -> int:
    """Handle the info command"""
    
    use_colors = not args.no_colors if hasattr(args, 'no_colors') else True
    show_banner(use_colors)
    
    if args.formats or not any([args.formats, args.scanners, args.policies]):
        print(create_section_header_text("Supported ML Model Formats", "info", use_colors))
        
        for risk_level, format_info in SUPPORTED_FORMATS.items():
            extensions = format_info["extensions"]
            description = format_info["description"]
            
            symbol = {"CRITICAL": "[!]", "HIGH": "[^]", "MEDIUM": "[~]", "LOW": "[i]"}[risk_level]
            header = f"{symbol} {risk_level} Risk:"
            print(colorize_text(header, risk_level, use_colors))
            print(f"    Extensions: {', '.join(extensions)}")
            print(f"    Description: {description}")
            print()
    
    if args.scanners:
        print(create_section_header_text("Available Security Scanners", "info", use_colors))
        
        current_risk = None
        for scanner, risk, description in AVAILABLE_SCANNERS:
            if risk != current_risk:
                current_risk = risk
                header = f"{risk} Risk Scanners:"
                print(colorize_text(header, risk, use_colors))
            
            status = "✓ Active"
            print(f"    • {scanner:<30} {description}")
            print(f"      {status}")
            print()
    
    if args.policies:
        print(create_section_header_text("Security Policies", "info", use_colors))
        
        for policy, description in SECURITY_POLICIES.items():
            policy_text = f"{policy.upper():<15} {description}"
            print(colorize_text(policy_text, "INFO", use_colors))
        print()
    
    return 0

def handle_scan_command(args) -> int:
    """Handle the scan command with comprehensive analysis"""
    
    use_colors = not args.no_colors
    
    # Show professional banner unless quiet or from interactive mode
    skip_banner = getattr(args, '_from_interactive', False)
    if not args.quiet and not skip_banner:
        show_banner(use_colors)
        print(create_section_header_text("Security Analysis Engine", "scan", use_colors))
    
    # Validate input path
    scan_path = pathlib.Path(args.path)
    if not scan_path.exists():
        error_msg = f"Path not found: {args.path}"
        print(colorize_text(f"[x] {error_msg}", "ERROR", use_colors))
        return 1

    target_basename = scan_path.stem if scan_path.is_file() else scan_path.name
    if not target_basename:
        try:
            target_basename = scan_path.resolve().name
        except Exception:
            target_basename = "scan_target"
    if not target_basename:
        target_basename = "scan_target"
    
    # Show configuration
    if not args.quiet:
        config_info = {
            "Target Path": str(scan_path),
            "Security Policy": args.policy.upper(),
            "Recursive Scan": "Yes" if args.recursive else "No",
            "Output Format": args.format.upper()
        }
        
        if args.extensions:
            config_info["File Extensions"] = ", ".join(args.extensions)
        
        create_status_panel_text("Scan Configuration", config_info, use_colors)
    
    registry = None
    rule_engine = None
    if CORE_AVAILABLE:
        try:
            rule_engine = RuleEngine(custom_rules_path=args.rules, policy=args.policy)
            registry = ScannerRegistry()
        except Exception as exc:
            registry = None
            rule_engine = None
            warning = f"Failed to initialize advanced scanning components: {exc}"
            print(colorize_text(f"[x] {warning}", "ERROR", use_colors))
            if not args.quiet:
                print(colorize_text("[i] Falling back to legacy scanning pipeline", "INFO", use_colors))

    # Perform scanning
    if scan_path.is_file():
        # Single file scan
        if registry and rule_engine:
            if not args.quiet and args.verbose:
                print(colorize_text("[i] Using advanced scanner registry", "INFO", use_colors))
            result = registry.scan_file(str(scan_path), rule_engine)
        else:
            result = scan_single_file(str(scan_path), args.policy, use_colors)

        if result.get("error"):
            print(colorize_text(f"[x] {result['error']}", "ERROR", use_colors))
            return 1

        return display_scan_results([result], args, use_colors, report_basename=target_basename)

    # Directory scan
    results = []
    files_scanned = 0

    if registry and rule_engine:
        if not args.quiet:
            print(colorize_text("[i] Scanning directory with advanced registry...", "INFO", use_colors))
        try:
            results = registry.scan_directory(
                str(scan_path),
                rule_engine,
                recursive=args.recursive,
                extensions=args.extensions
            )
        except Exception as exc:
            print(colorize_text(f"[x] Directory scan failed: {exc}", "ERROR", use_colors))
            return 1

        if args.exclude:
            exclude_patterns = [pattern.lower() for pattern in args.exclude]
            filtered_results = []
            for result in results:
                file_path_lower = str(result.get("file", "")).lower()
                if any(fnmatch.fnmatch(file_path_lower, pattern) for pattern in exclude_patterns):
                    continue
                filtered_results.append(result)
            results = filtered_results

        files_scanned = len(results)

        if not args.quiet and args.verbose:
            for result in results:
                file_name = pathlib.Path(result.get("file", "")).name
                if file_name:
                    print(f"  Scanned: {file_name}")
    else:
        if not args.quiet:
            print(colorize_text("[i] Scanning directory...", "INFO", use_colors))

        for file_path in scan_path.rglob("*") if args.recursive else scan_path.iterdir():
            if not file_path.is_file():
                continue

            if args.extensions and file_path.suffix.lower() not in [ext.lower() for ext in args.extensions]:
                continue

            if args.exclude:
                file_path_lower = str(file_path).lower()
                if any(fnmatch.fnmatch(file_path_lower, pattern.lower()) for pattern in args.exclude):
                    continue

            file_ext = file_path.suffix.lower()
            file_name = file_path.name.lower()

            is_ml_file = False
            for format_info in SUPPORTED_FORMATS.values():
                if file_ext in format_info["extensions"] or file_name in format_info["extensions"]:
                    is_ml_file = True
                    break

            if is_ml_file:
                result = scan_single_file(str(file_path), args.policy, use_colors)
                results.append(result)
                files_scanned += 1

                if not args.quiet and args.verbose:
                    print(f"  Scanned: {file_path.name}")

    if not args.quiet:
        print(colorize_text(f"[+] Scanned {files_scanned} files", "SUCCESS", use_colors))

    return display_scan_results(results, args, use_colors, report_basename=target_basename)

def _format_size_human(bytes_size: int) -> str:
    """Render bytes as human readable text"""
    if bytes_size is None:
        return "unknown"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_size)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024


def _render_artifact_panel(result: dict, use_colors: bool) -> None:
    """Pretty-print core artifact metadata in a status panel."""
    file_path = result.get("file", "unknown")
    file_name = pathlib.Path(file_path).name or "Artifact"
    formats = result.get("formats") or []
    scanners = result.get("scanners_used") or []
    scan_time = result.get("scan_time")
    info = {
        "Path": file_path,
        "Detected Formats": ", ".join(sorted(set(formats))) if formats else "Unknown",
        "Scanners Used": ", ".join(sorted(scanners)) if scanners else "None",
        "File Size": _format_size_human(result.get("size"))
    }
    if isinstance(scan_time, (int, float)) and scan_time >= 0:
        info["Scan Duration"] = f"{scan_time:.2f}s"
    create_status_panel_text(f"Artifact: {file_name}", info, use_colors)


def _print_wrapped(
    text: str,
    prefix: str,
    indent: int = 0,
    width: int = 98,
    severity: Optional[str] = None,
    use_colors: bool = True,
) -> None:
    """Print text using word wrapping with a prefix bullet and optional color."""
    if not text:
        return
    indent_str = " " * indent
    wrapper = textwrap.TextWrapper(
        width=width,
        initial_indent=indent_str + prefix,
        subsequent_indent=indent_str + "   "
    )
    for paragraph in text.strip().splitlines():
        if paragraph.strip():
            line = wrapper.fill(paragraph.strip())
            if severity:
                line = colorize_text(line, severity, use_colors)
            print(line)


def _render_metadata_block(label: str, items: list, highlight: str, use_colors: bool) -> None:
    """Print bullet list for metadata or forensic evidence sections."""
    if not items:
        return
    label_text = colorize_text(f"      {label}:", highlight, use_colors)
    print(label_text)
    for entry in items:
        _print_wrapped(str(entry), "- ", indent=8, severity=highlight, use_colors=use_colors)


def _summarize_metadata(metadata: dict) -> list:
    """Extract key metadata entries for display."""
    if not isinstance(metadata, dict):
        return []
    notable = []
    for key, value in metadata.items():
        if key == "forensic_evidence" or value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple, set)):
            value_list = list(value)
            if value_list and isinstance(value_list[0], dict):
                sample = value_list[0]
                sample_preview = ", ".join(f"{k}={v}" for k, v in list(sample.items())[:2])
                more = "…" if len(value_list) > 1 else ""
                notable.append(f"{key}: {len(value_list)} entries ({sample_preview}{more})")
            else:
                preview = ", ".join(str(item) for item in value_list[:3])
                more = "…" if len(value_list) > 3 else ""
                notable.append(f"{key}: {preview}{more}")
        elif isinstance(value, dict):
            preview_items = list(value.items())[:3]
            preview = ", ".join(f"{k}={v}" for k, v in preview_items)
            more = "…" if len(value) > 3 else ""
            notable.append(f"{key}: {{{preview}{more}}}")
        else:
            notable.append(f"{key}: {value}")
        if len(notable) >= 5:
            break
    return notable


def _summarize_forensics(metadata: dict) -> list:
    """Extract forensic evidence highlights."""
    if not isinstance(metadata, dict):
        return []
    forensic = metadata.get("forensic_evidence")
    if not isinstance(forensic, dict):
        return []
    highlights = []
    opcode_dumps = forensic.get("opcode_hex_dumps")
    if isinstance(opcode_dumps, list) and opcode_dumps:
        for sample in opcode_dumps[:2]:
            highlights.append(f"Opcode hex sample: {sample}")
    signatures = forensic.get("binary_signatures")
    if signatures:
        highlights.append(f"Binary signatures: {signatures}")
    confidence = forensic.get("detection_confidence")
    if confidence is not None:
        highlights.append(f"Detection confidence: {confidence}")
    patterns = forensic.get("patterns")
    if patterns:
        highlights.append(f"Patterns: {patterns}")
    return highlights


def _ensure_reports_dir() -> pathlib.Path:
    """Ensure the reports directory exists and return it."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _sanitize_report_name(name: str) -> str:
    """Sanitize target name for file-safe report naming."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip())
    return sanitized or "scan_report"


def _build_report_path(base_name: str, extension: str) -> pathlib.Path:
    """Construct a timestamped report path for the given base name and extension."""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    reports_dir = _ensure_reports_dir()
    sanitized = _sanitize_report_name(base_name)
    filename = f"{sanitized}_{timestamp}{extension}"
    return reports_dir / filename


def _build_console_report(results: list, args) -> str:
    """Generate a plain-text report mirroring console findings."""
    lines = []
    header = "SMART-01 Security Scan Report"
    lines.append(header)
    lines.append("=" * len(header))
    lines.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Target: {args.path}")
    lines.append(f"Policy: {args.policy}")
    lines.append(f"Format: {args.format}")
    lines.append("")

    total_findings = 0
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for result in results:
        file_path = result.get("file", "unknown")
        lines.append(f"Artifact: {file_path}")
        if result.get("error"):
            lines.append(f"  Error: {result['error']}")
            lines.append("")
            continue

        lines.append(f"  Size: {result.get('size', 'unknown')} bytes")
        formats = ", ".join(result.get("formats", [])) or "unknown"
        lines.append(f"  Detected Formats: {formats}")
        scanners = ", ".join(result.get("scanners_used", [])) or "none"
        lines.append(f"  Scanners Used: {scanners}")

        findings = result.get("findings", [])
        if not findings:
            lines.append("  Findings: none")
            lines.append("")
            continue

        lines.append("  Findings:")
        for idx, finding in enumerate(findings, start=1):
            severity = (finding.get("severity") or finding.get("level") or "UNKNOWN").upper()
            if severity in severity_totals:
                severity_totals[severity] += 1
            total_findings += 1
            summary = finding.get("summary") or finding.get("issue") or "Unspecified finding"
            lines.append(f"    {idx}. [{severity}] {summary}")

            detail = finding.get("detail")
            if isinstance(detail, str) and detail.strip():
                lines.append(f"       Detail: {detail.strip()}")

            cwe = finding.get("cwe")
            if cwe:
                lines.append(f"       CWE: {cwe}")

            recommendation = finding.get("recommendation")
            if recommendation:
                lines.append(f"       Recommendation: {recommendation}")

            metadata = finding.get("metadata") or {}
            if metadata:
                meta_preview = []
                for key, value in metadata.items():
                    if key == "forensic_evidence" or value in (None, "", [], {}):
                        continue
                    meta_preview.append(f"{key}={value}")
                    if len(meta_preview) >= 3:
                        break
                if meta_preview:
                    lines.append(f"       Indicators: {', '.join(meta_preview)}")
            lines.append("")

        lines.append("")

    lines.append("Summary")
    lines.append("-" * 7)
    lines.append(f"Total artifacts: {len(results)}")
    lines.append(f"Total findings: {total_findings}")
    for sev, count in severity_totals.items():
        lines.append(f"  {sev.title()}: {count}")

    return "\n".join(lines)


def display_scan_results(
    results: list,
    args,
    use_colors: bool = True,
    report_basename: Optional[str] = None
) -> int:
    """Display scan results with structured formatting and persist reports."""

    report_basename = report_basename or "scan_report"
    
    if args.format == 'json':
        # JSON output
        output_data = {
            "scan_metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "total_files": len(results),
                "policy": args.policy,
                "version": __version__
            },
            "results": results
        }
        
        json_output = json.dumps(output_data, indent=2)
        
        report_path = _build_report_path(report_basename, ".json")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(json_output)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(json_output)
            if not args.quiet:
                print(colorize_text(f"[+] Results saved to: {args.output}", "SUCCESS", use_colors))
        else:
            print(json_output)

        if not args.quiet:
            print(colorize_text(f"[+] Report saved to: {report_path}", "SUCCESS", use_colors))
        return 0
    
    elif args.format == 'sarif':
        # SARIF output (basic implementation)
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SMART-01",
                        "version": __version__
                    }
                },
                "results": []
            }]
        }
        
        for result in results:
            for finding in result.get("findings", []):
                sarif_data["runs"][0]["results"].append({
                    "ruleId": finding.get("cwe", "CWE-20"),
                    "level": finding["level"].lower(),
                    "message": {"text": finding["issue"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": result["file"]}
                        }
                    }]
                })
        
        sarif_output = json.dumps(sarif_data, indent=2)
        
        report_path = _build_report_path(report_basename, ".sarif")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(sarif_output)

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(sarif_output)
            if not args.quiet:
                print(colorize_text(f"[+] SARIF results saved to: {args.output}", "SUCCESS", use_colors))
        else:
            print(sarif_output)

        if not args.quiet:
            print(colorize_text(f"[+] Report saved to: {report_path}", "SUCCESS", use_colors))
        return 0
    
    else:
        # Console output
        if not args.quiet:
            print(create_section_header_text("Security Findings", "scan", use_colors))
        
        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for result in results:
            findings = result.get("findings", [])
            file_error = result.get("error")

            if not findings and not file_error:
                continue

            if not args.quiet:
                print()
                _render_artifact_panel(result, use_colors)

            if file_error:
                if not args.quiet:
                    print(colorize_text(f"[x] Scan error: {file_error}", "ERROR", use_colors))
                continue

            total_findings += len(findings)

            def _sev(find):
                return (find.get('severity') or find.get('level') or 'UNKNOWN').upper()

            severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for finding in findings:
                severity = _sev(finding)
                if severity in severity_groups:
                    severity_groups[severity].append(finding)
                else:
                    severity_groups.setdefault(severity, []).append(finding)

            critical_count += len(severity_groups.get("CRITICAL", []))
            high_count += len(severity_groups.get("HIGH", []))
            medium_count += len(severity_groups.get("MEDIUM", []))
            low_count += len(severity_groups.get("LOW", []))

            severity_order = [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            ] + [sev for sev in severity_groups.keys() if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}]

            for severity in severity_order:
                findings_list = severity_groups.get(severity, [])
                if not findings_list:
                    continue

                symbol = {"CRITICAL": "[!]", "HIGH": "[^]", "MEDIUM": "[~]", "LOW": "[i]"}.get(severity, "[i]")
                header_text = f"{symbol} {severity} – {len(findings_list)} finding{'s' if len(findings_list) > 1 else ''}"
                print(colorize_text(f"  {header_text}", severity, use_colors))

                for idx, finding in enumerate(findings_list, start=1):
                    summary = finding.get('summary') or finding.get('issue') or 'Unspecified finding'
                    _print_wrapped(summary, f"{idx}. ", indent=4, severity=severity, use_colors=use_colors)

                    detail = finding.get('detail')
                    if isinstance(detail, str) and detail.strip():
                        _print_wrapped(detail, "▸ ", indent=7, severity="INFO", use_colors=use_colors)

                    metadata = finding.get('metadata') or {}
                    indicator_lines = _summarize_metadata(metadata)
                    forensic_lines = _summarize_forensics(metadata)

                    if indicator_lines:
                        _render_metadata_block("Indicators", indicator_lines, "INFO", use_colors)
                    if forensic_lines:
                        _render_metadata_block("Forensic Evidence", forensic_lines, severity, use_colors)

                    if finding.get('cwe'):
                        _print_wrapped(f"CWE: {finding['cwe']}", "▸ ", indent=7, severity="INFO", use_colors=use_colors)
                    if finding.get('risk_score') is not None:
                        _print_wrapped(f"Risk Score: {finding['risk_score']}", "▸ ", indent=7, severity="HIGH" if severity == "CRITICAL" else severity, use_colors=use_colors)
                    if finding.get('recommendation'):
                        _print_wrapped(f"Recommendation: {finding['recommendation']}", "▸ ", indent=7, severity="HIGH" if severity in {"CRITICAL", "HIGH"} else "INFO", use_colors=use_colors)
                    if finding.get('scanner'):
                        _print_wrapped(f"Scanner: {finding['scanner']}", "▸ ", indent=7, severity="LOW", use_colors=use_colors)
                    print()
        
        # Summary
        if not args.quiet:
            print(create_section_header_text("Scan Summary", "info", use_colors))
            
            summary_info = {
                "Files Scanned": str(len(results)),
                "Total Findings": str(total_findings),
                "Critical": str(critical_count),
                "High": str(high_count),
                "Medium": str(medium_count),
                "Low": str(low_count)
            }
            
            create_status_panel_text("Results Summary", summary_info, use_colors)
            
            if critical_count > 0:
                print(colorize_text("[!] CRITICAL SECURITY ISSUES DETECTED", "CRITICAL", use_colors))
            elif high_count > 0:
                print(colorize_text("[^] HIGH PRIORITY SECURITY FINDINGS", "HIGH", use_colors))
            elif total_findings > 0:
                print(colorize_text("[i] SECURITY REVIEW RECOMMENDED", "MEDIUM", use_colors))
            else:
                print(colorize_text("[+] NO SECURITY ISSUES FOUND", "SUCCESS", use_colors))
        
        # Return appropriate exit code
        console_report = _build_console_report(results, args)
        report_path = _build_report_path(report_basename, ".txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(console_report)
        if not args.quiet:
            print(colorize_text(f"[+] Report saved to: {report_path}", "SUCCESS", use_colors))

        if critical_count > 0:
            return 1
        elif high_count > 0:
            return 2
        else:
            return 0

def handle_interactive_command(args) -> int:
    """Handle interactive mode with step-by-step wizard"""
    
    show_banner()
    print(create_section_header_text("Interactive Scanning Wizard", "info"))
    
    try:
        # Step 1: Target Selection
        print("TARGET SELECTION & VALIDATION")
        print("━" * 80)
        print("Enter 'quit' or 'exit' at any time to cancel")
        print()
        
        while True:
            try:
                target_path = input("Enter target file or directory path: ").strip()
            except (EOFError, KeyboardInterrupt):
                print(colorize_text("\n[!] Interactive session cancelled", "ERROR"))
                return 130
            
            if target_path.lower() in ['quit', 'exit', 'q']:
                print("Interactive session cancelled.")
                return 0
            
            if not target_path:
                print("Please enter a valid path.")
                continue
                
            path = pathlib.Path(target_path)
            if path.exists():
                print(colorize_text(f"[+] Target validated: {target_path}", "SUCCESS"))
                break
            else:
                print(colorize_text(f"[x] Path not found: {target_path}", "ERROR"))
                print("Please enter a valid file or directory path.")
        
        # Step 2: Security Policy
        print("\nSECURITY POLICY CONFIGURATION")
        print("━" * 80)
        print("1. STRICT     - Maximum security enforcement")
        print("2. ENTERPRISE - Production deployment ready (default)")
        print("3. RESEARCH   - Development and research focused") 
        print("4. FORENSICS  - Deep security investigation")
        
        while True:
            try:
                choice = input("Select policy (1-4) [2]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print(colorize_text("\n[!] Interactive session cancelled", "ERROR"))
                return 130
            
            if choice.lower() in ['quit', 'exit', 'q']:
                return 0
            
            if not choice:
                choice = "2"
            
            policy_map = {"1": "strict", "2": "enterprise", "3": "research", "4": "forensics"}
            if choice in policy_map:
                selected_policy = policy_map[choice]
                print(colorize_text(f"[+] Policy selected: {selected_policy.upper()}", "SUCCESS"))
                break
            else:
                print("Please enter 1, 2, 3, or 4")
        
        # Step 3: Analysis Configuration
        print("\nANALYSIS CONFIGURATION")
        print("━" * 80)
        
        # Output format
        print("Output formats:")
        print("1. CONSOLE - Rich terminal display (default)")
        print("2. JSON    - Machine-readable format")
        print("3. SARIF   - CI/CD integration format")
        
        while True:
            try:
                choice = input("Select format (1-3) [1]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print(colorize_text("\n[!] Interactive session cancelled", "ERROR"))
                return 130
            
            if choice.lower() in ['quit', 'exit', 'q']:
                return 0
                
            if not choice:
                choice = "1"
            
            format_map = {"1": "console", "2": "json", "3": "sarif"}
            if choice in format_map:
                output_format = format_map[choice]
                break
            else:
                print("Please enter 1, 2, or 3")
        
        # Other options
        try:
            recursive = input("Enable recursive directory scanning? (y/n) [y]: ").strip().lower()
            if recursive in ['quit', 'exit', 'q']:
                return 0
            recursive = recursive != 'n'
            
            verbose = input("Enable verbose technical output? (y/n) [n]: ").strip().lower()
            if verbose in ['quit', 'exit', 'q']:
                return 0
            verbose = verbose == 'y'
        except (EOFError, KeyboardInterrupt):
            print(colorize_text("\n[!] Interactive session cancelled", "ERROR"))
            return 130
        
        # Step 4: Configuration Summary
        print("\nCONFIGURATION SUMMARY")
        print("━" * 80)
        print(f"Target Path: {target_path}")
        print(f"Security Policy: {selected_policy.upper()}")
        print(f"Output Format: {output_format.upper()}")
        print(f"Recursive Scan: {'ENABLED' if recursive else 'DISABLED'}")
        print(f"Verbose Output: {'ENABLED' if verbose else 'DISABLED'}")
        
        # Confirmation
        try:
            proceed = input("\nProceed with analysis? (y/n) [y]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(colorize_text("\n[!] Interactive session cancelled", "ERROR"))
            return 130
            
        if proceed in ['n', 'no', 'quit', 'exit', 'q']:
            print("Analysis cancelled.")
            return 0
        
        # Step 5: Execute Scan
        print(colorize_text("\n[>] LAUNCHING AI SECURITY ANALYSIS ENGINE", "INFO"))
        print("[i] Initializing neural network threat detection...")
        
        # Create args object for scan command
        class InteractiveArgs:
            def __init__(self):
                self.path = target_path
                self.policy = selected_policy
                self.format = output_format
                self.recursive = recursive
                self.verbose = verbose
                self.quiet = False
                self.no_colors = False
                self.output = None
                self.extensions = None
                self.exclude = None
                self.sbom = None
                self.rules = None
        
        args = InteractiveArgs()
        args._from_interactive = True  # Skip banner in scan command
        return handle_scan_command(args)
        
    except KeyboardInterrupt:
        print(colorize_text("\n[!] Interactive session cancelled by user", "ERROR"))
        return 130
    except Exception as e:
        print(colorize_text(f"[ERROR] Interactive mode error: {e}", "ERROR"))
        return 1

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main() -> int:
    """Main CLI entry point"""
    
    parser = create_argument_parser()
    
    # Handle no arguments case
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    args = parser.parse_args()
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        # Route to appropriate handler
        if args.command == 'scan':
            return handle_scan_command(args)
        elif args.command == 'info':
            return handle_info_command(args)
        elif args.command == 'version':
            return handle_version_command(args)
        elif args.command == 'interactive':
            return handle_interactive_command(args)
        else:
            print(f"[ERROR] Unknown command: {args.command}")
            return 1
    
    except KeyboardInterrupt:
        print(colorize_text("\n[!] Operation interrupted by user", "ERROR"))
        return 130
    except Exception as e:
        print(colorize_text(f"[ERROR] Unexpected error: {e}", "ERROR"))
        if hasattr(args, 'verbose') and args.verbose:
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())