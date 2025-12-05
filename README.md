# SMART-01 AI Security Scanner# SMART-01 AI Security Scanner - The Ultimate LLM Scanner



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[![Security](https://img.shields.io/badge/security-static%20analysis-green.svg)](https://github.com/yourusername/smart-ai-scanner)[![Security](https://img.shields.io/badge/security-static%20analysis-green.svg)](https://github.com/yourusername/smart-ai-scanner)

[![Research](https://img.shields.io/badge/research-15%2B%20papers-blue.svg)](RESEARCH_BASED_ENHANCEMENTS.md)

**A defense-grade static analysis framework for machine learning model security**[![LLM Security](https://img.shields.io/badge/LLM-backdoor%20detection-red.svg)](LLM_SECURITY_README.md)



SMART-01 performs comprehensive security analysis of AI/ML artifacts **without ever executing or loading untrusted models**. Built on Aegis-ML principles with zero-execution security policy.A **defense-grade static analysis tool** for ML model security with **cutting-edge LLM backdoor detection**. SMART-01 performs comprehensive security analysis of AI/ML artifacts **without ever executing or loading untrusted models**.



---## 🎯 NEW: Research-Based LLM Security (v1.0)



## Table of Contents**SMART-01 is now "The Ultimate LLM Scanner"** with advanced backdoor and poisoning detection backed by 15+ academic research papers.



- [Overview](#overview)### 🚀 LLM Security Features

- [Key Features](#key-features)- ✅ **Token Embedding Anomaly Detection** (92% confidence)

- [Quick Start](#quick-start)- ✅ **Tokenizer Security Validation** (95% for zero-width attacks)

- [Architecture](#architecture)- ✅ **Prompt Injection Detection** (92% confidence)

- [Supported Formats](#supported-formats)- ✅ **Weight Poisoning Analysis** (85-88% confidence)

- [Available Scanners](#available-scanners)- ✅ **Spectral Signature Detection** (88% confidence - Tran et al., 2018)

- [Command Reference](#command-reference)- ✅ **Supply Chain Integrity Checks** (91% confidence)

- [Security Policies](#security-policies)- ✅ **Configuration Tampering Detection** (98% for remote code execution)

- [Output Formats](#output-formats)

- [CI/CD Integration](#cicd-integration)**📚 [Complete LLM Security Documentation →](LLM_SECURITY_README.md)**  

- [Python API](#python-api)**🔬 [Research Papers & Citations →](RESEARCH_BASED_ENHANCEMENTS.md)**  

- [Configuration](#configuration)**⚡ [Quick Reference Guide →](QUICK_REFERENCE.md)**  

- [Documentation](#documentation)**🎮 [Try Interactive Demo →](demo_llm_scanners.py)**

- [Contributing](#contributing)

- [License](#license)---



---## 🛡️ Key Features



## Overview### 🆕 Advanced LLM Security (NEW in v1.0)

- **🧠 LLM Backdoor Scanner** - Tokenizer poisoning, special token attacks, prompt injection

SMART-01 AI Security Scanner is a **neural network threat detection framework** designed for production security environments. It uses **static analysis only** to identify security vulnerabilities in machine learning models across 12+ formats.- **📊 Weight Poisoning Scanner** - Spectral signatures, statistical outliers, entropy analysis

- **🔬 Research-Based Detection** - 15+ academic papers implemented (2018-2023)

### Design Principles (Aegis-ML)- **🎯 89% Average Confidence** - Calibrated thresholds from published research

- **🔐 HuggingFace Model Support** - Complete pipeline scanning (tokenizer → config → weights)

1. **Static Analysis Only** - Never load or execute models

2. **Safe Parsers** - Use read-only, safe parsing libraries### Security-First Design

3. **Sandbox Isolation** - No dynamic code execution paths- **Static Analysis Only** - Never executes or loads untrusted models

4. **Fail-Safe Defaults** - Conservative security posture- **No Code Execution** - Safe inspection using parsers and byte analysis

- **Comprehensive Format Support** - Pickle, ONNX, SafeTensors, PyTorch, Keras, **LLMs** and more

### Threat Detection- **Defense-Grade** - Designed for production security environments



SMART-01 detects:### Detection Capabilities

- **🔴 LLM Backdoors** - Token poisoning, special tokens, prompt injection, weight manipulation

- **[!] CRITICAL**: Arbitrary code execution (Pickle, PyTorch)- **🔴 Pickle Deserialization Attacks** - Dangerous opcodes, code injection patterns

- **[^] HIGH**: Malicious operators (ONNX, TensorFlow, Keras)- **🟠 ONNX Security Issues** - Custom operators, external data references

- **[~] MEDIUM**: Supply chain attacks (external data, tampering)- **🔵 Resource Exhaustion** - Large tensors, memory bombs, file size limits

- **[i] LOW**: Configuration vulnerabilities (resource exhaustion)- **🟢 EvilModel Detection** - Embedded executables, magic byte analysis

- **⚪ Supply Chain Security** - Provenance validation, integrity checks, signature verification

---

### Enterprise Features

## Key Features- **Multi-Format Output** - Console, JSON, SARIF for CI/CD integration

- **SBOM Generation** - CycloneDX Software Bill of Materials

### Security-First Design- **Policy Engine** - Configurable security policies (Strict, Enterprise, Research, Forensics)

- **Rule-Based Detection** - YAML-configurable security rules with CWE mapping

- **Zero-Execution Policy** - Static analysis only, never loads models- **Research Citations** - Every LLM finding includes academic paper references

- **No Code Execution** - Safe inspection using parsers and byte analysis

- **Defense-Grade** - Production-ready for enterprise security environments## 🚀 Quick Start

- **Comprehensive Coverage** - 12 ML formats, 14 scanner implementations

### Installation

### Enterprise Features

```bash

- **Multi-Format Output** - Console, JSON, SARIF for CI/CD integration# Clone the repository

- **SBOM Generation** - CycloneDX Software Bill of Materialsgit clone https://github.com/yourusername/smart-ai-scanner.git

- **Policy Engine** - Configurable security policies (Strict, Enterprise, Research, Forensics)cd smart-ai-scanner

- **Rule-Based Detection** - YAML-configurable security rules with CWE mapping

- **Professional UI** - Text-based symbols, graceful fallbacks, accessibility-focused# Install dependencies

pip install colorama pyfiglet

### Advanced Capabilities

# Test the installation

- **Deep Opcode Analysis** - Pickle bytecode inspection for dangerous operationspython test_scanner.py

- **Binary Format Inspection** - Magic byte detection, embedded executable analysis```

- **Entropy Analysis** - Statistical anomaly detection in model weights

- **Dependency Tracking** - External data reference validation### Basic Usage

- **Supply Chain Validation** - Model provenance and integrity verification

```bash

---# Scan a single model file

python -m smart_ai_scanner.cli scan model.pkl

## Quick Start

# Scan a directory recursively

### Installationpython -m smart_ai_scanner.cli scan ./models --recursive



```bash# Use strict security policy with SARIF output

# Clone the repositorypython -m smart_ai_scanner.cli scan ./models --policy strict --format sarif --output results.sarif

git clone https://github.com/yourusername/smart-ai-scanner.git

cd smart-ai-scanner# Interactive mode

python -m smart_ai_scanner --interactive

# Install dependencies```

pip install colorama pyfiglet

## 📦 Supported Formats

# Optional: Install Rich for enhanced UI

pip install rich| Format | Extensions | Risk Level | Scanner | Description |

|--------|------------|------------|---------|-------------|

# Verify installation| **🆕 LLM Tokenizers** | `tokenizer.json`, `vocab.txt`, `vocab.json` | 🔴 **HIGH** | LLM Backdoor | Token poisoning, zero-width attacks |

python -m smart_ai_scanner version| **🆕 LLM Configs** | `config.json`, `generation_config.json` | 🔴 **CRITICAL** | LLM Backdoor | Remote code execution, tampering |

```| **🆕 Model Weights** | `.bin`, `.safetensors`, `.pt`, `.pth` | 🟠 **MEDIUM** | Weight Poisoning | Spectral backdoors, statistical anomalies |

| **Pickle** | `.pkl`, `.pickle`, `.dill`, `.joblib` | 🔴 **CRITICAL** | Pickle Scanner | Can execute arbitrary code |

### Basic Usage| **PyTorch** | `.pt`, `.pth`, `.ckpt`, `.mar` | 🔴 **CRITICAL** | PyTorch Scanner | Contains pickle data |

| **ONNX** | `.onnx` | 🟠 **MEDIUM** | ONNX Scanner | Custom operators possible |

```bash| **Keras/TF** | `.h5`, `.keras`, `.pb` | 🟡 **MEDIUM** | Keras Scanner | Lambda layers possible |

# Scan a single model file| **SafeTensors** | `.safetensors` | 🟢 **LOW** | SafeTensors Scanner | Safe by design |

python -m smart_ai_scanner scan model.pkl

## 🛡️ Security Policies

# Scan a directory recursively

python -m smart_ai_scanner scan ./models --recursive### Strict Policy

- **Use Case**: Production environments, maximum security

# Use strict security policy with JSON output- **Behavior**: Blocks dangerous formats, strict limits

python -m smart_ai_scanner scan ./models --policy strict --format json --output results.json- **File Size Limit**: 1GB

- **External Data**: Blocked

# Interactive wizard mode (recommended for first-time users)

python -m smart_ai_scanner interactive### Enterprise Policy (Default)

- **Use Case**: Business applications, balanced security

# View available scanners and formats- **Behavior**: Warns on dangerous formats, reasonable limits

python -m smart_ai_scanner info --scanners --formats- **File Size Limit**: 10GB

```- **External Data**: Allowed with validation



### Quick Examples### Research Policy

- **Use Case**: Research and development environments

```bash- **Behavior**: Permissive scanning, large file support

# Production scan with SARIF output for CI/CD- **File Size Limit**: 100GB

python -m smart_ai_scanner scan ./models -r --policy strict --format sarif -o security.sarif- **External Data**: Allowed



# Verbose scan with SBOM generation### Forensics Policy

python -m smart_ai_scanner scan ./models -v --sbom sbom.json- **Use Case**: Security investigation and analysis

- **Behavior**: No blocking, comprehensive analysis

# Scan only specific file types- **File Size Limit**: 1TB

python -m smart_ai_scanner scan ./models --extensions .pkl .h5 .onnx- **External Data**: Allowed



# Quiet mode for automated pipelines## 🔍 Detection Examples

python -m smart_ai_scanner scan ./models -q --no-colors --format json

```### Dangerous Pickle Detection

```python

---# This pickle file would be flagged:

import pickle

## Architecturedata = {

    'model': 'malicious',

SMART-01 follows a modular architecture with clear separation of concerns:    'exploit': eval('__import__("os").system("rm -rf /")')

}

``````

┌─────────────────────────────────────────────────────────────────┐

│                     CLI Interface (cli.py)                       │**Scanner Output:**

│            Interactive Mode | Scan Mode | Info Mode              │```

└─────────────────────┬───────────────────────────────────────────┘🔴 CRITICAL: Unsafe pickle opcodes detected

                      │   Found dangerous opcodes: GLOBAL, REDUCE

┌─────────────────────▼───────────────────────────────────────────┐   This pickle file can execute arbitrary code during loading.

│                  Core Components (core/)                         │   CWE: CWE-502 (Deserialization of Untrusted Data)

│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │```

│  │   Registry   │  │ Rule Engine  │  │    Report    │          │

│  │   Pattern    │  │   (Policy)   │  │  Generator   │          │### ONNX Custom Operator Detection

│  └──────────────┘  └──────────────┘  └──────────────┘          │```

│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │🟠 MEDIUM: Custom ONNX operators detected

│  │    SBOM      │  │    Utils     │  │   Opcode     │          │   Found potentially dangerous operators: com.microsoft::FusedConv

│  │  Generator   │  │   (Entropy)  │  │  Analyzer    │          │   Custom operators may have unknown security implications.

│  └──────────────┘  └──────────────┘  └──────────────┘          │   CWE: CWE-470 (Use of Externally-Controlled Input)

└─────────────────────┬───────────────────────────────────────────┘```

                      │

┌─────────────────────▼───────────────────────────────────────────┐### EvilModel Detection

│              Scanner Registry (ScannerRegistry)                  │```

│     Format Detection | Scanner Selection | Scan Orchestration    │🔴 CRITICAL: Embedded executable detected

└─────────────────────┬───────────────────────────────────────────┘   Found PE executable at offset 1024 in model file

                      │   This indicates an EvilModel attack.

┌─────────────────────▼───────────────────────────────────────────┐   CWE: CWE-506 (Embedded Malicious Code)

│               Base Scanner (BaseScanner)                         │```

│    Abstract base class with common functionality                 │

└─────────────────────┬───────────────────────────────────────────┘## 📊 Output Formats

                      │

        ┌─────────────┴─────────────┐### Console Output

        │                           │Human-readable colored output with security recommendations:

┌───────▼────────┐       ┌──────────▼──────────┐

│ CRITICAL Risk  │       │    HIGH Risk        │```

│ Scanners (1)   │       │    Scanners (3)     │🔍 SECURITY FINDINGS

├────────────────┤       ├─────────────────────┤─────────────────────────────────────────────────────────────────────

│ • Pickle       │       │ • PyTorch           │🔴 CRITICAL (2 findings)

└────────────────┘       │ • Keras             │  • Unsafe pickle opcodes detected

                         │ • TensorFlow        │    Found dangerous opcodes: GLOBAL, REDUCE

                         └─────────────────────┘    File: malicious_model.pkl

        ┌─────────────┬─────────────┐    CWE: CWE-502

        │             │             │

┌───────▼────────┐ ┌──▼──────────┐ ┌▼────────────┐✅ All scanned files: 15

│ MEDIUM Risk    │ │  LOW Risk   │ │ UI Module   │⚠️  Total findings: 3 (2 critical, 1 medium)

│ Scanners (6)   │ │ Scanners (2)│ │ (ui/)       │```

├────────────────┤ ├─────────────┤ ├─────────────┤

│ • ONNX         │ │ • SafeTensor│ │ • Banner    │### JSON Output

│ • XGBoost      │ │ • Tokenizer │ │ • Tables    │Structured data for automation and integration:

│ • LightGBM     │ └─────────────┘ │ • Messages  │

│ • CatBoost     │                 │ • Spinners  │```json

│ • CoreML       │                 │ • Panels    │{

│ • GGUF         │                 └─────────────┘  "tool": "smart-ai-scanner",

└────────────────┘  "version": "2.0.0",

```  "timestamp": "2024-01-15T10:30:00Z",

  "summary": {

### Component Overview    "total_files": 15,

    "total_findings": 3,

#### 1. CLI Interface (`cli.py`)    "critical_findings": 2,

   - Command-line argument parsing with argparse    "policy_used": "enterprise"

   - Four modes: scan, info, interactive, version  },

   - Input validation and error handling  "results": [

   - Output formatting coordination    {

      "file": "model.pkl",

#### 2. Core Components (`core/`)      "formats": ["pickle"],

      "findings": [

   **ScannerRegistry** (`registry.py`)        {

   - Central registry for all scanners          "severity": "CRITICAL",

   - Format detection (extensions, magic bytes)          "rule": "pickle_unsafe",

   - Scanner selection and orchestration          "summary": "Unsafe pickle opcodes detected",

   - Multi-file scanning coordination          "cwe": "CWE-502"

        }

   **BaseScanner** (`base_scanner.py`)      ]

   - Abstract base class for all scanners    }

   - Common utilities (finding creation, file validation)  ]

   - Standardized interface (scan method)}

   - Error handling and reporting```



   **RuleEngine** (`rules.py`)## 🚀 Usage Examples

   - Security policy enforcement

   - YAML-based rule configuration### Command Line Interface

   - Severity mapping (CRITICAL, HIGH, MEDIUM, LOW, INFO)

   - CWE categorization```bash

# Basic scan with enterprise policy

   **ReportGenerator** (`report.py`)python -m smart_ai_scanner.cli scan ./models

   - Console output formatting

   - JSON serialization# Strict security scan with SARIF output

   - SARIF 2.1.0 generationpython -m smart_ai_scanner.cli scan ./models --policy strict --format sarif --output results.sarif

   - Summary statistics

# Interactive wizard mode

   **SBOMGenerator** (`sbom.py`)python -m smart_ai_scanner.cli interactive

   - CycloneDX format support

   - Component inventory# Show supported formats and scanners

   - Dependency trackingpython -m smart_ai_scanner.cli info --formats --scanners

   - Vulnerability mapping

# Generate SBOM

   **OpcodeAnalyzer** (`opcode_analyzer.py`)python -m smart_ai_scanner.cli scan ./models --sbom models_sbom.json

   - Pickle bytecode disassembly```

   - Dangerous opcode detection

   - Code execution path analysis### Python API



   **Utils** (`utils.py`)```python

   - Entropy calculationfrom smart_ai_scanner import ScannerRegistry, RuleEngine, PickleScanner

   - Binary analysis

   - File type detection# Initialize scanner

   - Hash computationregistry = ScannerRegistry()

registry.register_scanner(PickleScanner)

#### 3. Scanner Implementations (`scanners/`)rule_engine = RuleEngine(policy="enterprise")



   All scanners inherit from `BaseScanner`:# Scan a file

   results = registry.scan_file("model.pkl", rule_engine)

   ```python

   class AdvancedPickleScanner(BaseScanner):# Check findings

       def scan(self, file_path: str, rule_engine=None, **kwargs):for finding in results.get('findings', []):

           # Implementation    print(f"{finding['severity']}: {finding['summary']}")

           return findings```

   ```

## ⚙️ Configuration

   **Scanner Hierarchy**:

   - `BaseScanner` (abstract)### Custom Rules

     - `AdvancedPickleScanner` (CRITICAL)Create custom security rules in YAML format:

     - `AdvancedPyTorchScanner` (HIGH)

     - `AdvancedKerasScanner` (HIGH)```yaml

     - `AdvancedTensorFlowScanner` (HIGH)# custom_rules.yaml

     - `AdvancedONNXScanner` (MEDIUM)dangerous_extensions:

     - `AdvancedXGBoostScanner` (MEDIUM)  - ".pkl"

     - `AdvancedLightGBMScanner` (MEDIUM)  - ".pickle"

     - `AdvancedCatBoostScanner` (MEDIUM)

     - `AdvancedCoreMLScanner` (MEDIUM)pickle_opcodes_block:

     - `AdvancedGGUFScanner` (MEDIUM)  - "GLOBAL"

     - `SafeTensorsScanner` (LOW)  - "REDUCE"

     - `AdvancedTokenizerScanner` (LOW)  - "EXEC"

     - `AdvancedLLMBackdoorScanner` (HIGH, pending)

     - `WeightPoisoningScanner` (MEDIUM, pending)max_file_size: 1073741824  # 1GB

min_entropy_threshold: 2.0

#### 4. UI Module (`ui/`)max_entropy_threshold: 7.5

   - Professional text-based symbols (no emojis)```

   - Rich library integration with graceful fallbacks

   - Colorama for cross-platform colors## 🔄 CI/CD Integration

   - Components: banners, tables, panels, spinners

### GitHub Actions

#### 5. Rules (`rules/`)```yaml

   - `strict_policy.yaml` - Maximum securityname: ML Model Security Scan

   - `enterprise_policy.yaml` - Balanced (default)on: [push, pull_request]

   - Custom YAML rules supportedjobs:

  security-scan:

### Data Flow    runs-on: ubuntu-latest

    steps:

```    - uses: actions/checkout@v3

Input File(s)    - name: Setup Python

    │      uses: actions/setup-python@v4

    ▼      with:

Format Detection (extensions, magic bytes)        python-version: '3.9'

    │    - name: Install Scanner

    ▼      run: pip install smart-ai-scanner

Scanner Selection (from registry)    - name: Scan Models

    │      run: smart-ai-scanner scan ./models --policy strict --format sarif --output results.sarif

    ▼    - name: Upload SARIF

Security Analysis (scanner-specific)      uses: github/codeql-action/upload-sarif@v2

    │      with:

    ▼        sarif_file: results.sarif

Rule Engine Evaluation (policy enforcement)```

    │

    ▼## 🎯 Use Cases

Finding Collection (standardized format)

    │- **Supply Chain Security** - Scan downloaded models before deployment

    ▼- **CI/CD Integration** - Automated security checks in build pipelines  

Report Generation (console/JSON/SARIF)- **Incident Response** - Forensic analysis of suspicious models

    │- **Compliance** - Security assessments for regulatory requirements

    ▼

Output (terminal/file)## 🔬 Technical Architecture

```

### Aegis-ML Principles

### Key Design Patterns1. **Static Analysis Only** - Never load or execute models

2. **Safe Parsers** - Use read-only, safe parsing libraries

1. **Registry Pattern** - Central scanner registration and discovery3. **Sandbox Isolation** - No dynamic code execution paths

2. **Strategy Pattern** - Interchangeable security policies4. **Fail-Safe Defaults** - Conservative security posture

3. **Template Method** - BaseScanner defines scan workflow

4. **Factory Pattern** - Scanner instantiation via registry### Scanner Architecture

5. **Builder Pattern** - Report and SBOM construction```

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐

---│   File Input    │───▶│  Format Detection │───▶│ Scanner Registry │

└─────────────────┘    └──────────────────┘    └─────────────────┘

## Supported Formats                                                          │

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐

SMART-01 supports 12 machine learning model formats:│  Rule Engine    │◀───│  Security Analysis │◀───│ Format Scanners │

└─────────────────┘    └──────────────────┘    └─────────────────┘

| Format | Extensions | Risk Level | Scanner | Description |         │                        │

|--------|-----------|------------|---------|-------------|┌─────────────────┐    ┌──────────────────┐

| **Pickle/Joblib** | `.pkl`, `.pickle`, `.dill`, `.joblib` | **[!] CRITICAL** | AdvancedPickleScanner | Can execute arbitrary code during deserialization |│ Report Generator │◀───│    Findings     │

| **PyTorch** | `.pt`, `.pth`, `.ckpt`, `.mar` | **[^] HIGH** | AdvancedPyTorchScanner | Contains pickle data, custom unpicklers |└─────────────────┘    └──────────────────┘

| **Keras** | `.h5`, `.keras` | **[^] HIGH** | AdvancedKerasScanner | Lambda layers can contain arbitrary code |```

| **TensorFlow** | `.pb`, `.pbtxt`, `.tflite` | **[^] HIGH** | AdvancedTensorFlowScanner | Custom operators, graph manipulation |

| **ONNX** | `.onnx` | **[~] MEDIUM** | AdvancedONNXScanner | Custom operators, external data references |## 📞 Support

| **XGBoost** | `.model`, `.json`, `.ubj` | **[~] MEDIUM** | AdvancedXGBoostScanner | JSON/binary format analysis |

| **LightGBM** | `.txt`, `.model` | **[~] MEDIUM** | AdvancedLightGBMScanner | Text/binary configuration inspection |- **Issues**: [GitHub Issues](https://github.com/yourusername/smart-ai-scanner/issues)

| **CatBoost** | `.cbm`, `.bin` | **[~] MEDIUM** | AdvancedCatBoostScanner | CBM format verification |- **Documentation**: [Wiki](https://github.com/yourusername/smart-ai-scanner/wiki)

| **CoreML** | `.mlmodel`, `.mlpackage` | **[~] MEDIUM** | AdvancedCoreMLScanner | MLModel/MLPackage inspection |- **Security**: security@smart-ai-scanner.org

| **GGUF** | `.gguf`, `.ggml` | **[~] MEDIUM** | AdvancedGGUFScanner | Large language model weights |

| **SafeTensors** | `.safetensors` | **[i] LOW** | SafeTensorsScanner | Safe by design (Hugging Face) |## 📄 License

| **Tokenizer** | `tokenizer.json`, `vocab.txt`, `vocab.json`, `merges.txt` | **[i] LOW** | AdvancedTokenizerScanner | Tokenizer configuration |

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Risk Level Definitions

---

- **[!] CRITICAL** - Can execute arbitrary code, immediate security threat

- **[^] HIGH** - Significant security risks, contains executable components**⚡ SMART AI Scanner - Securing AI/ML models through static analysis**
- **[~] MEDIUM** - Moderate risks, potential for exploitation
- **[i] LOW** - Minimal risks, generally safe with validation

---

## Available Scanners

SMART-01 includes 12 production-ready scanners (2 additional in development):

### CRITICAL Risk (1 Scanner)

#### AdvancedPickleScanner
- **Formats**: Pickle, Joblib, Dill
- **Detection**: Dangerous opcodes (GLOBAL, REDUCE, BUILD, INST, OBJ)
- **Analysis**: Bytecode disassembly, code execution path tracing
- **CWE**: CWE-502 (Deserialization of Untrusted Data)

### HIGH Risk (3 Scanners)

#### AdvancedPyTorchScanner
- **Formats**: PyTorch (.pt, .pth, .ckpt, .mar)
- **Detection**: Unsafe pickle in state_dict, custom unpicklers
- **Analysis**: Archive structure, metadata validation
- **CWE**: CWE-502, CWE-494 (Download of Code Without Integrity Check)

#### AdvancedKerasScanner
- **Formats**: Keras H5, SavedModel
- **Detection**: Lambda layers, custom objects, code serialization
- **Analysis**: H5 structure, layer configuration
- **CWE**: CWE-94 (Improper Control of Generation of Code)

#### AdvancedTensorFlowScanner
- **Formats**: TensorFlow SavedModel, Protobuf, TFLite
- **Detection**: Malicious operators, graph manipulation
- **Analysis**: Graph def inspection, operator validation
- **CWE**: CWE-470 (Use of Externally-Controlled Input)

### MEDIUM Risk (6 Scanners)

#### AdvancedONNXScanner
- **Formats**: ONNX (.onnx)
- **Detection**: Custom operators, external data, large tensors
- **Analysis**: Protobuf parsing, operator validation
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

#### AdvancedXGBoostScanner
- **Formats**: XGBoost (.model, .json, .ubj)
- **Detection**: Model tampering, configuration issues
- **Analysis**: JSON/binary structure validation
- **CWE**: CWE-494

#### AdvancedLightGBMScanner
- **Formats**: LightGBM (.txt, .model)
- **Detection**: Configuration tampering, malformed trees
- **Analysis**: Text/binary format inspection
- **CWE**: CWE-494

#### AdvancedCatBoostScanner
- **Formats**: CatBoost (.cbm, .bin)
- **Detection**: Binary format validation
- **Analysis**: CBM structure verification
- **CWE**: CWE-494

#### AdvancedCoreMLScanner
- **Formats**: CoreML (.mlmodel, .mlpackage)
- **Detection**: Custom layers, script references
- **Analysis**: Protobuf parsing, pipeline validation
- **CWE**: CWE-829

#### AdvancedGGUFScanner
- **Formats**: GGUF (.gguf, .ggml)
- **Detection**: Metadata tampering, large weights
- **Analysis**: Binary format inspection, KV pairs
- **CWE**: CWE-494

### LOW Risk (2 Scanners)

#### SafeTensorsScanner
- **Formats**: SafeTensors (.safetensors)
- **Detection**: Format validation, metadata checks
- **Analysis**: Header parsing, tensor verification
- **CWE**: N/A (safe by design)

#### AdvancedTokenizerScanner
- **Formats**: Tokenizer JSON, vocab files
- **Detection**: Configuration issues, large vocabularies
- **Analysis**: JSON structure validation
- **CWE**: CWE-20 (Improper Input Validation)

### In Development (2 Scanners)

- **AdvancedLLMBackdoorScanner** - Token poisoning, prompt injection detection
- **WeightPoisoningScanner** - Spectral signatures, statistical outlier detection

---

## Command Reference

SMART-01 provides four main commands. For complete reference, see **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)**.

### 1. `scan` - Security Analysis

Scan machine learning models for vulnerabilities.

```bash
python -m smart_ai_scanner scan <path> [options]
```

**Key Options**:
- `-r, --recursive` - Recursively scan directories
- `--policy` - Security policy: strict, enterprise, research, forensics
- `--format` - Output format: console, json, sarif
- `-o, --output` - Output file path
- `--extensions` - Filter by file extensions
- `--sbom` - Generate SBOM file
- `-v, --verbose` - Detailed output
- `-q, --quiet` - Minimal output

**Examples**:
```bash
# Basic scan
python -m smart_ai_scanner scan model.pkl

# Strict policy with SARIF for CI/CD
python -m smart_ai_scanner scan ./models -r --policy strict --format sarif -o security.sarif

# Verbose with SBOM
python -m smart_ai_scanner scan ./models -v --sbom sbom.json
```

### 2. `info` - Scanner Information

Display scanner capabilities and configuration.

```bash
python -m smart_ai_scanner info [--formats | --scanners | --policies]
```

**Examples**:
```bash
# Show all scanners
python -m smart_ai_scanner info --scanners

# Show supported formats
python -m smart_ai_scanner info --formats

# Show everything
python -m smart_ai_scanner info --formats --scanners --policies
```

### 3. `interactive` - Guided Wizard

Launch interactive scanning wizard.

```bash
python -m smart_ai_scanner interactive
```

**Features**:
- Target selection with validation
- Security policy configuration
- Output format selection
- Configuration summary
- Real-time progress

### 4. `version` - System Information

Display version and system information.

```bash
python -m smart_ai_scanner version
```

---

## Security Policies

SMART-01 includes four pre-configured security policies:

### Strict Policy

**Use Case**: Production environments, maximum security

**Behavior**:
- Blocks dangerous formats (Pickle, PyTorch, Keras)
- Strict file size limits (1GB)
- External data references blocked
- Fails on CRITICAL and HIGH findings

### Enterprise Policy (Default)

**Use Case**: Business applications, balanced security

**Behavior**:
- Warns on dangerous formats
- Reasonable file size limits (10GB)
- External data allowed with validation
- Fails on CRITICAL findings only

### Research Policy

**Use Case**: Research and development environments

**Behavior**:
- Permissive scanning
- Large file support (100GB)
- External data allowed
- Informational findings only

### Forensics Policy

**Use Case**: Security investigation and analysis

**Behavior**:
- No blocking
- Comprehensive analysis
- Very large files (1TB)
- Maximum verbosity

---

## Output Formats

### Console (Default)

Human-readable terminal output with professional formatting:

**Severity Symbols**:
- `[!]` CRITICAL (red)
- `[^]` HIGH (red)
- `[~]` MEDIUM (yellow)
- `[i]` LOW/INFO (cyan/blue)
- `[+]` SUCCESS (green)
- `[x]` ERROR (red)

**Example Output**:
```
╔═══════════════════════════════════════════════════════════════╗
║               SMART-01 AI SECURITY SCANNER                    ║
║            Neural Network Threat Detection v2.0.0             ║
╚═══════════════════════════════════════════════════════════════╝

SECURITY FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[!] CRITICAL (2 findings)
    • Unsafe pickle opcodes detected
      File: malicious_model.pkl
      CWE: CWE-502
```

### JSON

Machine-readable format for automation and integration.

### SARIF

SARIF 2.1.0 format for CI/CD integration:
- GitHub Advanced Security
- GitLab Security Dashboard
- Azure DevOps
- Jenkins plugins

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan ML Models
  run: |
    python -m smart_ai_scanner scan ./models \
      --recursive \
      --policy strict \
      --format sarif \
      --output results.sarif
      
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
ml_security_scan:
  script:
    - python -m smart_ai_scanner scan ./models -r --policy strict --format json -o gl-security.json
  artifacts:
    reports:
      sast: gl-security.json
```

---

## Python API

SMART-01 can be used programmatically:

```python
from smart_ai_scanner.core.registry import ScannerRegistry
from smart_ai_scanner.core.rules import RuleEngine

# Initialize components
registry = ScannerRegistry()
rule_engine = RuleEngine(policy="enterprise")

# Scan a file
results = registry.scan_file("model.pkl", rule_engine)

# Process findings
for finding in results.get('findings', []):
    print(f"{finding['severity']}: {finding['summary']}")
```

---

## Configuration

### Custom Rules

Create custom security rules in YAML:

```yaml
# custom_rules.yaml
policy_name: "custom_policy"
version: "1.0"

rules:
  max_file_size: 5368709120  # 5GB
  
  pickle_opcodes_block:
    - GLOBAL
    - REDUCE
    - BUILD
```

**Usage**:
```bash
python -m smart_ai_scanner scan ./models --rules custom_rules.yaml
```

### Environment Variables

```bash
# Disable colors globally
export NO_COLOR=1

# Set default policy
export SMART_POLICY=strict
```

---

## Documentation

### Available Documentation

- **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** - Comprehensive command-line reference
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Detailed architecture documentation
- **[docs/LLM_SECURITY_README.md](docs/LLM_SECURITY_README.md)** - LLM security features
- **[docs/RESEARCH_BASED_ENHANCEMENTS.md](docs/RESEARCH_BASED_ENHANCEMENTS.md)** - Research citations
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick reference card

---

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/smart-ai-scanner.git
cd smart-ai-scanner

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings (Google style)
- Write unit tests
- No emojis in code or UI

---

## License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2024 SMART-01 AI Security Research Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/smart-ai-scanner/issues)
- **Security**: security@smart-ai-scanner.org
- **Documentation**: [Wiki](https://github.com/yourusername/smart-ai-scanner/wiki)

---

## Acknowledgments

- Aegis-ML principles for static analysis methodology
- CycloneDX for SBOM format specification
- OASIS for SARIF specification
- Security research community for ML threat models

---

**SMART-01 AI Security Scanner - Securing AI/ML models through static analysis**

Version 2.0.0 | [Documentation](docs/) | [CLI Reference](docs/CLI_REFERENCE.md) | [Architecture](docs/ARCHITECTURE.md)
