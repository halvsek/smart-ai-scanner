# SMART-01 CLI Quick Reference Guide
## Command-Line Interface Documentation

---

## Overview

SMART-01 AI Security Scanner is a **neural network threat detection framework** with a **static analysis engine** and **zero-execution security policy**.

**Current Version**: 2.0.0  
**Active Scanners**: 12 (14 total, 2 pending registry)  
**Supported Formats**: 12 ML model formats  
**Security Policies**: 4 (strict, enterprise, research, forensics)

---

## Quick Start

```bash
# Scan a single model
smart-ai-scanner scan model.pkl

# Scan directory recursively
smart-ai-scanner scan ./models --recursive

# Interactive mode (recommended for first-time users)
smart-ai-scanner interactive

# View available scanners
smart-ai-scanner info --scanners
```

---

## Commands

### 1. `scan` - Security Analysis

Scan machine learning models for vulnerabilities.

**Syntax:**
```bash
smart-ai-scanner scan <path> [options]
```

**Positional Arguments:**
- `path` - File or directory path to scan

**Options:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--recursive` | `-r` | Recursively scan directories | False |
| `--policy` | | Security policy (see below) | enterprise |
| `--format` | | Output format (console/json/sarif) | console |
| `--output` | `-o` | Output file path | stdout |
| `--rules` | | Custom rules YAML file | (policy-based) |
| `--extensions` | | Filter by file extensions | (all) |
| `--exclude` | | Exclude paths (glob patterns) | (none) |
| `--sbom` | | Generate SBOM file | (disabled) |
| `--no-colors` | | Disable colored output | False |
| `--quiet` | `-q` | Minimal output | False |
| `--verbose` | `-v` | Detailed output | False |

**Security Policies:**
- `strict` - Maximum security enforcement, blocks dangerous formats
- `enterprise` - **Default**, balanced security for production
- `research` - Permissive for research/development environments
- `forensics` - Analysis mode, allows everything for investigation

**Output Formats:**
- `console` - **Default**, human-readable terminal output with colors
- `json` - Machine-readable JSON for automation/scripting
- `sarif` - SARIF 2.1.0 format for CI/CD integration (GitHub, GitLab, etc.)

**Examples:**
```bash
# Basic scan with default settings
smart-ai-scanner scan model.pkl

# Strict policy with JSON output
smart-ai-scanner scan model.pkl --policy strict --format json -o results.json

# Recursive directory scan with SARIF for CI/CD
smart-ai-scanner scan ./models --recursive --format sarif -o security.sarif

# Scan only specific extensions
smart-ai-scanner scan ./models --extensions .pkl .h5 .onnx

# Exclude test directories
smart-ai-scanner scan ./models --exclude tests/* temp/*

# Verbose scan with SBOM generation
smart-ai-scanner scan ./models -v --sbom sbom.json

# Quiet mode for CI/CD pipelines
smart-ai-scanner scan ./models -q --no-colors --format json
```

**Exit Codes:**
- `0` - Success, no critical findings
- `1` - Critical findings detected
- `2` - High severity findings detected
- `130` - Interrupted by user (Ctrl+C)

---

### 2. `info` - Scanner Information

Display scanner capabilities and configuration.

**Syntax:**
```bash
smart-ai-scanner info [--formats | --scanners | --policies]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--formats` | List all supported ML model formats and file extensions |
| `--scanners` | List all available scanners grouped by risk level |
| `--policies` | List all security policies with descriptions |

**Examples:**
```bash
# Show all available scanners
smart-ai-scanner info --scanners

# Show supported formats
smart-ai-scanner info --formats

# Show security policies
smart-ai-scanner info --policies

# Show everything (no flags)
smart-ai-scanner info --formats --scanners --policies
```

**Scanner Output Format:**
```
[!] CRITICAL Risk:
   • AdvancedPickleScanner - Pickle/Joblib files

[^] HIGH Risk:
   • AdvancedKerasScanner - Keras H5/SavedModel
   • AdvancedPyTorchScanner - PyTorch PT/PTH
   • AdvancedTensorFlowScanner - TensorFlow SavedModel/PB

[~] MEDIUM Risk:
   • AdvancedONNXScanner - ONNX models
   • (6 more scanners...)

[i] LOW Risk:
   • SafeTensorsScanner - SafeTensors format
   • AdvancedTokenizerScanner - Tokenizer JSON
```

---

### 3. `interactive` - Guided Wizard

Launch interactive scanning wizard with step-by-step configuration.

**Syntax:**
```bash
smart-ai-scanner interactive
```

**Features:**
- ✅ Target selection and validation
- ✅ Security policy configuration
- ✅ Output format selection
- ✅ Deep analysis options (opcode analysis, binary inspection)
- ✅ Recursive scanning configuration
- ✅ Verbose output toggle
- ✅ Configuration summary before execution

**Interactive Flow:**
1. **Target Selection** - Enter path, automatic validation
2. **Security Policy** - Choose from 4 policies
3. **Analysis Configuration** - Output format, deep analysis, recursion
4. **Configuration Summary** - Review before proceeding
5. **Execution** - Real-time scan with progress indicators

**Example Session:**
```
TARGET SELECTION & VALIDATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enter target file or directory path: ./models
[+] Target validated: models

SECURITY POLICY CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. STRICT     - Maximum security enforcement
2. ENTERPRISE - Production deployment ready
3. RESEARCH   - Development and research focused
4. FORENSICS  - Deep security investigation
Select policy (1-4) [2]: 1
[+] Policy selected: STRICT

ANALYSIS CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Output formats:
1. CONSOLE - Rich terminal display
2. JSON    - Machine-readable format
3. SARIF   - CI/CD integration format
Select format (1-3) [1]: 1
Enable deep opcode analysis? (y/n) [y]: y
Enable recursive directory scanning? (y/n) [y]: y
Enable verbose technical output? (y/n) [n]: n

CONFIGURATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target Path: ./models
Security Policy: STRICT
Output Format: CONSOLE
Deep Analysis: ENABLED
Recursive Scan: ENABLED
Verbose Output: DISABLED

Proceed with analysis? (y/n) [y]: y

[>] LAUNCHING AI SECURITY ANALYSIS ENGINE
[i] Initializing neural network threat detection...
```

**Exit Codes:**
- `0` - Successful scan completion
- `1` - User cancelled or error occurred

---

### 4. `version` - System Information

Display version, author, license, and repository information.

**Syntax:**
```bash
smart-ai-scanner version
```

**Output:**
```
Version: 2.0.0
Author: SMART-01 AI Security Research Team
License: MIT
Repository: https://github.com/yourusername/smart-ai-scanner
```

---

## Supported Formats

| Format | Extensions | Risk Level |
|--------|-----------|------------|
| **Pickle/Joblib** | .pkl, .pickle, .dill, .joblib | **CRITICAL** |
| **Keras** | .h5, .keras | **HIGH** |
| **PyTorch** | .pt, .pth, .ckpt, .mar | **HIGH** |
| **TensorFlow** | .pb, .pbtxt, .tflite | **HIGH** |
| **ONNX** | .onnx | MEDIUM |
| **XGBoost** | .model, .json, .ubj | MEDIUM |
| **LightGBM** | .txt, .model | MEDIUM |
| **CatBoost** | .cbm, .bin | MEDIUM |
| **CoreML** | .mlmodel, .mlpackage | MEDIUM |
| **GGUF** | .gguf, .ggml | MEDIUM |
| **SafeTensors** | .safetensors | LOW |
| **Tokenizer** | tokenizer.json, vocab.txt, vocab.json, merges.txt | LOW |

---

## Available Scanners (12 Active)

### CRITICAL Risk (1)
- **AdvancedPickleScanner** - Detects arbitrary code execution in Pickle/Joblib files

### HIGH Risk (3)
- **AdvancedKerasScanner** - Lambda layer code injection detection
- **AdvancedPyTorchScanner** - Custom unpickler exploit detection
- **AdvancedTensorFlowScanner** - Graph manipulation and malicious operators

### MEDIUM Risk (6)
- **AdvancedONNXScanner** - Custom operators and external data validation
- **AdvancedXGBoostScanner** - JSON/binary format analysis
- **AdvancedLightGBMScanner** - Text/binary configuration inspection
- **AdvancedCatBoostScanner** - CBM format verification
- **AdvancedCoreMLScanner** - MLModel/MLPackage inspection
- **AdvancedGGUFScanner** - Large language model weight analysis

### LOW Risk (2)
- **SafeTensorsScanner** - Safe serialization format (Hugging Face)
- **AdvancedTokenizerScanner** - Tokenizer configuration analysis

**Note**: 2 additional scanners (LLM Backdoor, Weight Poisoning) implemented but pending registry integration.

---

## Security Policies

| Policy | Use Case | Description |
|--------|----------|-------------|
| **strict** | Production | Maximum security, blocks dangerous formats |
| **enterprise** | Business | **Default**, balanced security for deployment |
| **research** | Development | Permissive for R&D environments |
| **forensics** | Investigation | Analysis mode, allows everything |

**Policy Rules Location:**
- `rules/strict_policy.yaml`
- `rules/enterprise_policy.yaml`
- Custom rules: `--rules custom.yaml`

---

## Output Formats

### Console (Default)
Human-readable terminal output with:
- ✅ Professional ASCII art banner
- ✅ Colored severity indicators
- ✅ Text-based symbols (no emojis)
- ✅ Rich tables (if Rich library available)
- ✅ Graceful fallback to plain text

**Symbols:**
- `[!]` CRITICAL (red)
- `[^]` HIGH (red)
- `[~]` MEDIUM (yellow)
- `[i]` LOW/INFO (blue/cyan)
- `[+]` SUCCESS (green)
- `[x]` ERROR (red)

### JSON
Machine-readable format for automation:
```json
{
  "scan_metadata": {
    "timestamp": "2024-12-01T10:30:00",
    "total_files": 5,
    "security_policy": "enterprise"
  },
  "summary": {
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 2
  },
  "results": [...]
}
```

### SARIF
SARIF 2.1.0 format for CI/CD integration:
- GitHub Advanced Security
- GitLab Security Dashboard
- Azure DevOps
- Jenkins plugins
- VS Code extensions

---

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Scan ML Models
  run: |
    pip install smart-ai-scanner
    smart-ai-scanner scan ./models \
      --recursive \
      --policy strict \
      --format sarif \
      --output results.sarif
      
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI Example
```yaml
ml_security_scan:
  script:
    - pip install smart-ai-scanner
    - smart-ai-scanner scan ./models -r --format json -o gl-security.json
  artifacts:
    reports:
      sast: gl-security.json
```

---

## Advanced Usage

### Custom Rules
Create custom security rules in YAML:

```yaml
# custom_rules.yaml
rules:
  - id: custom-pickle-ban
    name: "Ban all Pickle files"
    severity: CRITICAL
    pattern: "*.pkl"
    message: "Pickle files are banned in production"
    
  - id: model-size-limit
    name: "Model size limit"
    severity: HIGH
    max_size: 100MB
    message: "Model exceeds size limit"
```

Usage:
```bash
smart-ai-scanner scan ./models --rules custom_rules.yaml
```

### SBOM Generation
Generate Software Bill of Materials:

```bash
smart-ai-scanner scan ./models --sbom sbom.json
```

SBOM includes:
- Model inventory
- Format detection
- Dependency analysis
- Version information
- License detection (if available)

### Extension Filtering
Scan only specific file types:

```bash
# Only Pickle and ONNX
smart-ai-scanner scan ./models --extensions .pkl .onnx

# All Python-based formats
smart-ai-scanner scan ./models --extensions .pkl .h5 .pt .pth
```

### Path Exclusion
Exclude directories or patterns:

```bash
# Exclude test and temp directories
smart-ai-scanner scan ./models --exclude tests/* temp/* backup/*

# Exclude by pattern
smart-ai-scanner scan ./models --exclude "*.backup" "old_*"
```

---

## Environment Variables

```bash
# Disable colors globally
export NO_COLOR=1

# Set default policy
export SMART_POLICY=strict

# Custom rules directory
export SMART_RULES_DIR=/path/to/rules
```

---

## Troubleshooting

### Common Issues

**Issue**: "No module named 'rich'"
**Solution**: Rich is optional. Scanner works without it. Install with: `pip install rich`

**Issue**: Colors not working
**Solution**: Use `--no-colors` flag or set `NO_COLOR=1` environment variable

**Issue**: Scanner not detecting files
**Solution**: Check file extensions match supported formats. Use `--extensions` to specify.

**Issue**: Permission denied errors
**Solution**: Check file permissions. Run with appropriate user privileges.

### Debug Mode
```bash
# Enable verbose output
smart-ai-scanner scan ./models -v

# Combine with Python debug
python -v -m smart_ai_scanner.cli scan ./models
```

---

## Best Practices

### Production Deployments
```bash
# Use strict policy, SARIF output, no colors for CI/CD
smart-ai-scanner scan ./models \
  --recursive \
  --policy strict \
  --format sarif \
  --output security.sarif \
  --no-colors \
  --quiet
```

### Development/Testing
```bash
# Use enterprise policy, console output, verbose
smart-ai-scanner scan ./models \
  --recursive \
  --policy enterprise \
  --verbose
```

### Security Audits
```bash
# Use forensics policy, verbose, SBOM
smart-ai-scanner scan ./models \
  --recursive \
  --policy forensics \
  --format json \
  --output audit.json \
  --sbom sbom.json \
  --verbose
```

---

## Exit Codes Reference

| Code | Meaning |
|------|---------|
| 0 | Success, no critical findings |
| 1 | Critical findings detected or error occurred |
| 2 | High severity findings detected |
| 130 | Interrupted by user (Ctrl+C) |

---

## Support & Resources

- **Documentation**: See `README.md`, `ARCHITECTURE.md`
- **Examples**: See `examples/` directory
- **Rules**: See `rules/` directory
- **Issues**: GitHub Issues (repository URL in version command)
- **License**: MIT

---

## Quick Reference Card

```bash
# Essential Commands
smart-ai-scanner scan <path>              # Scan file/directory
smart-ai-scanner interactive              # Guided wizard
smart-ai-scanner info --scanners          # List scanners
smart-ai-scanner info --formats           # List formats
smart-ai-scanner version                  # Show version

# Common Flags
-r, --recursive       # Scan directories recursively
-v, --verbose         # Detailed output
-q, --quiet           # Minimal output
-o, --output FILE     # Save to file
--policy POLICY       # strict|enterprise|research|forensics
--format FORMAT       # console|json|sarif
--no-colors           # Disable colors

# Examples
smart-ai-scanner scan model.pkl --policy strict
smart-ai-scanner scan ./models -r --format json -o results.json
smart-ai-scanner scan ./models -v --sbom sbom.json
```

---

**Last Updated**: October 2025  
**Version**: 2.0.0  
**Status**: Production Ready
