# SMART-01 AI Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-static%20analysis-green.svg)](https://github.com/halvsek/smart-ai-scanner)

**A defense-grade static analysis framework for machine learning model security**

SMART-01 performs comprehensive security analysis of AI/ML artifacts **without ever executing or loading untrusted models**. Built for production security environments with zero-execution security policy.

---

## Key Features

### Security-First Design
- **Static Analysis Only** - Never executes or loads untrusted models
- **No Code Execution** - Safe inspection using parsers and byte analysis
- **Comprehensive Coverage** - 12+ ML formats including Pickle, ONNX, PyTorch, Keras, SafeTensors
- **Defense-Grade** - Designed for production security environments

### Threat Detection

SMART-01 detects:
- **Pickle Deserialization Attacks** - Dangerous opcodes, code injection patterns
- **ONNX Security Issues** - Custom operators, external data references
- **PyTorch/Keras Risks** - Unsafe serialization, lambda layers
- **EvilModel Detection** - Embedded executables, magic byte analysis
- **Resource Exhaustion** - Large tensors, memory bombs, file size limits
- **Supply Chain Security** - Integrity checks, provenance validation

### Enterprise Features
- **Multi-Format Output** - Console, JSON, SARIF for CI/CD integration
- **Policy Engine** - Configurable security policies (Strict, Enterprise, Research, Forensics)
- **Professional UI** - Colored output with detailed findings and recommendations
- **Report Generation** - Automatic timestamped reports saved to `reports/` directory
- **Interactive Mode** - Step-by-step scanning wizard

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/halvsek/smart-ai-scanner.git
cd smart-ai-scanner

# Install dependencies
pip install -r requirements.txt

# Verify installation
python smart-ai-scanner.py version
```

### Basic Usage

```bash
# Scan a single model file
python smart-ai-scanner.py scan model.pkl

# Scan a directory recursively
python smart-ai-scanner.py scan ./models --recursive

# Use strict security policy with JSON output
python smart-ai-scanner.py scan ./models --policy strict --format json

# Interactive wizard mode (recommended for first-time users)
python smart-ai-scanner.py interactive

# View available scanners and formats
python smart-ai-scanner.py info --scanners --formats
```

### Quick Examples

```bash
# Production scan with SARIF output for CI/CD
python smart-ai-scanner.py scan ./models -r --policy strict --format sarif -o security.sarif

# Verbose scan with detailed output
python smart-ai-scanner.py scan ./models -v

# Scan only specific file types
python smart-ai-scanner.py scan ./models --extensions .pkl .h5 .onnx

# Quiet mode for automated pipelines
python smart-ai-scanner.py scan ./models -q --format json
```

---

## Supported Formats

| Format | Extensions | Risk Level | Description |
|--------|------------|------------|-------------|
| **Pickle** | `.pkl`, `.pickle`, `.dill`, `.joblib` | **CRITICAL** | Can execute arbitrary code |
| **PyTorch** | `.pt`, `.pth`, `.ckpt`, `.mar` | **CRITICAL** | Contains pickle data |
| **ONNX** | `.onnx` | **MEDIUM** | Custom operators possible |
| **Keras/TF** | `.h5`, `.keras`, `.pb` | **MEDIUM** | Lambda layers possible |
| **SafeTensors** | `.safetensors` | **LOW** | Safe by design |
| **XGBoost** | `.model`, `.json`, `.ubj` | **MEDIUM** | Binary format inspection |
| **LightGBM** | `.txt`, `.model` | **MEDIUM** | Text-based model files |
| **CatBoost** | `.cbm`, `.bin` | **MEDIUM** | Binary model format |
| **GGUF/GGML** | `.gguf`, `.ggml` | **MEDIUM** | Large language models |
| **CoreML** | `.mlmodel`, `.mlpackage` | **MEDIUM** | Apple ML format |
| **Tokenizers** | `tokenizer.json`, `vocab.txt` | **LOW** | Configuration files |

---

## Security Policies

### Strict Policy
- **Use Case**: Production environments, maximum security
- **Behavior**: Blocks dangerous formats, strict limits
- **File Size Limit**: 1GB
- **External Data**: Blocked

### Enterprise Policy (Default)
- **Use Case**: Business applications, balanced security
- **Behavior**: Warns on dangerous formats, reasonable limits
- **File Size Limit**: 10GB
- **External Data**: Allowed with validation

### Research Policy
- **Use Case**: Research and development environments
- **Behavior**: Permissive scanning, large file support
- **File Size Limit**: 100GB
- **External Data**: Allowed

### Forensics Policy
- **Use Case**: Security investigation and analysis
- **Behavior**: No blocking, comprehensive analysis
- **File Size Limit**: 1TB
- **External Data**: Allowed

---

## Detection Examples

### Dangerous Pickle Detection

```python
# This pickle file would be flagged:
import pickle
data = {
    'model': 'malicious',
    'exploit': eval('__import__("os").system("rm -rf /")')
}
```

**Scanner Output:**
```
[CRITICAL] Unsafe pickle opcodes detected
   Found dangerous opcodes: GLOBAL, REDUCE
   This pickle file can execute arbitrary code during loading.
   CWE: CWE-502 (Deserialization of Untrusted Data)
```

### ONNX Custom Operator Detection

```
[MEDIUM] Custom ONNX operators detected
   Found potentially dangerous operators: com.microsoft::FusedConv
   Custom operators may have unknown security implications.
   CWE: CWE-470 (Use of Externally-Controlled Input)
```

### EvilModel Detection

```
[CRITICAL] Embedded executable detected
   Found PE executable at offset 1024 in model file
   This indicates an EvilModel attack.
   CWE: CWE-506 (Embedded Malicious Code)
```

---

## Output Formats

### Console Output
Human-readable colored output with security recommendations:

```
SECURITY FINDINGS
─────────────────────────────────────────────────────────────────────
[CRITICAL] (2 findings)
  1. Unsafe pickle opcodes detected
     Found dangerous opcodes: GLOBAL, REDUCE
     File: malicious_model.pkl
     CWE: CWE-502
     Recommendation: Use SafeTensors or ONNX format instead

All scanned files: 15
Total findings: 3 (2 critical, 1 medium)
```

### JSON Output
Structured data for automation and integration:

```json
{
  "scan_metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "total_files": 15,
    "policy": "enterprise",
    "version": "2.0.0"
  },
  "results": [
    {
      "file": "model.pkl",
      "formats": ["pickle"],
      "findings": [
        {
          "severity": "CRITICAL",
          "summary": "Unsafe pickle opcodes detected",
          "cwe": "CWE-502",
          "recommendation": "Use SafeTensors format"
        }
      ]
    }
  ]
}
```

### SARIF Output
Industry-standard format for CI/CD integration:

```bash
python smart-ai-scanner.py scan ./models --format sarif -o results.sarif
```

---

## Command Reference

### Scan Command

```bash
python smart-ai-scanner.py scan <path> [options]

Options:
  --recursive, -r          Scan directories recursively
  --policy                 Security policy: strict|enterprise|research|forensics
  --format                 Output format: console|json|sarif
  --output, -o            Output file path
  --extensions            Filter by extensions (e.g., .pkl .onnx)
  --exclude               Exclude paths (glob patterns)
  --verbose, -v           Detailed output
  --quiet, -q             Minimal output
  --no-colors             Disable colored output
```

### Info Command

```bash
python smart-ai-scanner.py info [options]

Options:
  --formats               List supported formats
  --scanners              List available scanners
  --policies              List security policies
```

### Interactive Mode

```bash
python smart-ai-scanner.py interactive

# Step-by-step wizard for:
# - Target selection
# - Policy configuration
# - Output format selection
# - Recursive scanning options
```

### Version Command

```bash
python smart-ai-scanner.py version

# Displays:
# - Version information
# - System details
# - Active scanners count
# - Component status
```

---

## Reports

All scans automatically save reports to the `reports/` directory with timestamps:

```
reports/
├── model_name_20241215-143022.txt     # Console output
├── directory_name_20241215-143045.json # JSON output
└── scan_target_20241215-143100.sarif  # SARIF output
```

---

## Architecture

```
smart-ai-scanner/
├── smart-ai-scanner.py          # Main CLI entry point
├── core/
│   ├── base_scanner.py          # Abstract scanner base class
│   ├── registry.py              # Scanner discovery and orchestration
│   ├── rules.py                 # Policy engine and rule management
│   ├── report.py                # Report generation
│   ├── utils.py                 # Utility functions
│   └── opcode_analyzer.py       # Pickle bytecode analysis
├── scanners/
│   ├── pickle_scanner.py        # Pickle format scanner
│   ├── pytorch_scanner.py       # PyTorch model scanner
│   ├── onnx_scanner.py          # ONNX scanner
│   ├── keras_scanner.py         # Keras/HDF5 scanner
│   ├── safetensors_scanner.py   # SafeTensors scanner
│   └── ...                      # Other format scanners
├── rules/
│   ├── enterprise_policy.yaml   # Default policy rules
│   └── strict_policy.yaml       # Strict security rules
├── reports/                     # Auto-generated reports
└── docs/                        # Documentation
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Links

- **GitHub**: https://github.com/halvsek/smart-ai-scanner
- **Issues**: https://github.com/halvsek/smart-ai-scanner/issues
- **Documentation**: See `docs/` directory

---

## Acknowledgments

Built with security-first principles inspired by:
- Aegis-ML security framework
- OWASP ML Security guidelines
- Industry best practices for static analysis

---

**⚠️ Security Notice**: SMART-01 is a static analysis tool. While it detects many security issues, it should be part of a comprehensive security strategy that includes code review, dynamic analysis, and secure deployment practices.
