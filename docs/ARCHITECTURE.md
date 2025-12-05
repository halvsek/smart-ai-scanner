# SMART-01 AI Security Scanner - Architecture Documentation

**Version**: 2.0.0  
**Last Updated**: December 2024  
**Status**: Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Scanner Architecture](#scanner-architecture)
5. [Data Flow](#data-flow)
6. [Design Patterns](#design-patterns)
7. [Module Specifications](#module-specifications)
8. [Extension Points](#extension-points)
9. [Security Considerations](#security-considerations)
10. [Performance Characteristics](#performance-characteristics)

---

## Overview

SMART-01 AI Security Scanner is built on **Aegis-ML principles** with a focus on:

- **Static Analysis Only** - Zero-execution security policy
- **Modular Architecture** - Clear separation of concerns
- **Extensibility** - Easy addition of new scanners and formats
- **Defense-Grade** - Production-ready security framework

### Key Design Goals

1. **Safety** - Never execute or load untrusted models
2. **Performance** - Fast scanning with minimal memory footprint
3. **Extensibility** - Plugin architecture for new scanners
4. **Maintainability** - Clear interfaces, minimal coupling
5. **Usability** - Professional CLI and API interfaces

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  CLI (cli.py)│  │   Python API │  │  Interactive  │          │
│  │              │  │              │  │     Mode      │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
└─────────┼──────────────────┼──────────────────┼─────────────────┘
          │                  │                  │
┌─────────▼──────────────────▼──────────────────▼──────────────────┐
│                         Core Layer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │   Registry   │  │ Rule Engine  │  │    Report    │            │
│  │   (Central)  │  │   (Policy)   │  │  Generator   │            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐            │
│  │    SBOM      │  │    Utils     │  │   Opcode     │            │
│  │  Generator   │  │   (Helpers)  │  │  Analyzer    │            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
└─────────┬────────────────────────────────────────────────────────┘
          │
┌─────────▼─────────────────────────────────────────────────────────┐
│                       Scanner Layer                               │
│  ┌──────────────────────────────────────────────────────┐         │
│  │               BaseScanner (Abstract)                  │        │
│  │  • scan() interface                                   │        │
│  │  • Common utilities (finding creation, validation)    │        │
│  │  • Error handling                                     │        │
│  └──────────────────┬───────────────────────────────────┘         │
│                     │                                             │
│       ┌─────────────┴─────────────┬─────────────┬────────────┐    │
│       │                           │             │            │    │
│  ┌────▼────┐  ┌─────────────┐  ┌─▼──────┐  ┌──▼──────┐  ┌─▼──┐    │
│  │CRITICAL │  │    HIGH     │  │ MEDIUM │  │   LOW   │  │... │    │
│  │Scanners │  │  Scanners   │  │Scanners│  │Scanners │  │    │    │
│  │  (1)    │  │    (3)      │  │  (6)   │  │   (2)   │  │    │    │
│  └─────────┘  └─────────────┘  └────────┘  └─────────┘  └────┘    │
└───────────────────────────────────────────────────────────────────┘
```

### Component Hierarchy

```
smart_ai_scanner/
│
├── cli.py                    # Command-line interface (entry point)
├── __init__.py              # Package initialization
├── __main__.py              # Module execution entry
│
├── core/                    # Core framework components
│   ├── base_scanner.py      # Abstract base scanner
│   ├── registry.py          # Scanner registry (central coordinator)
│   ├── rules.py             # Rule engine & policy enforcement
│   ├── report.py            # Report generation (console/JSON/SARIF)
│   ├── sbom.py              # SBOM generation (CycloneDX)
│   ├── opcode_analyzer.py   # Pickle opcode analysis
│   └── utils.py             # Utility functions (entropy, hashing)
│
├── scanners/                # Format-specific scanners
│   ├── __init__.py
│   ├── pickle_scanner.py    # CRITICAL: Pickle/Joblib
│   ├── pytorch_scanner.py   # HIGH: PyTorch models
│   ├── keras_scanner.py     # HIGH: Keras H5/SavedModel
│   ├── tensorflow_scanner.py # HIGH: TensorFlow SavedModel
│   ├── onnx_scanner.py      # MEDIUM: ONNX models
│   ├── xgboost_scanner.py   # MEDIUM: XGBoost
│   ├── lightgbm_scanner.py  # MEDIUM: LightGBM
│   ├── catboost_scanner.py  # MEDIUM: CatBoost
│   ├── coreml_scanner.py    # MEDIUM: CoreML
│   ├── gguf_scanner.py      # MEDIUM: GGUF/GGML
│   ├── safetensors_scanner.py # LOW: SafeTensors
│   ├── tokenizer_scanner.py # LOW: Tokenizers
│   ├── llm_backdoor_scanner.py # HIGH: LLM backdoors (pending)
│   └── weight_poisoning_scanner.py # MEDIUM: Weight poisoning (pending)
│
├── ui/                      # User interface components
│   ├── __init__.py          # UI module (banners, tables, messages)
│   └── (Rich/Colorama integration)
│
└── rules/                   # Security policy definitions
    ├── strict_policy.yaml   # Maximum security
    └── enterprise_policy.yaml # Balanced security (default)
```

---

## Core Components

### 1. Scanner Registry (`core/registry.py`)

**Purpose**: Central coordinator for all scanners

**Responsibilities**:
- Scanner registration and discovery
- Format detection (file extensions, magic bytes)
- Scanner selection and routing
- Multi-file scanning orchestration

**Key Classes**:

```python
class ScannerRegistry:
    """Central registry for all ML model scanners"""
    
    def __init__(self):
        self._scanners: List[Type[BaseScanner]] = []
        self._format_map: Dict[str, List[Type[BaseScanner]]] = {}
        self._magic_bytes: Dict[bytes, List[Type[BaseScanner]]] = {}
        self._extensions: Dict[str, List[Type[BaseScanner]]] = {}
    
    def register_scanner(
        self, 
        scanner_class: Type[BaseScanner],
        formats: List[str],
        extensions: List[str],
        magic_bytes: Optional[List[bytes]] = None
    ) -> None:
        """Register a scanner with format associations"""
        
    def scan_file(
        self, 
        file_path: str, 
        rule_engine: RuleEngine
    ) -> Dict[str, Any]:
        """Scan a single file"""
        
    def scan_directory(
        self,
        directory: str,
        recursive: bool,
        rule_engine: RuleEngine,
        extensions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan directory of files"""
```

**Format Detection Algorithm**:

```
1. Check file extension
   └─> Match in _extensions map → Return scanners

2. Read first 16 bytes (magic bytes)
   └─> Match in _magic_bytes map → Return scanners

3. Try all registered scanners
   └─> Scanner returns findings or skips

4. Return "unknown format" if no match
```

**Registration Process**:

```python
# Built-in scanners are registered on initialization
def _register_builtin_scanners(self):
    if HAS_PICKLE_SCANNER:
        self.register_scanner(
            AdvancedPickleScanner,
            formats=['pickle', 'joblib', 'dill'],
            extensions=['.pkl', '.pickle', '.joblib', '.dill'],
            magic_bytes=[b'\x80\x03', b'\x80\x04', b'\x80\x05']
        )
    
    # ... more scanners ...
```

### 2. Base Scanner (`core/base_scanner.py`)

**Purpose**: Abstract base class for all scanners

**Responsibilities**:
- Define scanner interface
- Provide common utilities
- Standardize finding format
- Error handling

**Key Classes**:

```python
class BaseScanner(ABC):
    """Base class that all scanners must implement"""
    
    def __init__(self, rule_engine=None):
        self.rule_engine = rule_engine
        self.findings = []
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Base security scanner"
    
    @abstractmethod
    def scan(
        self, 
        file_path: str, 
        rule_engine=None, 
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Scan a file and return list of findings
        
        Returns:
            List of finding dictionaries with:
            - severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            - rule: Rule identifier
            - summary: Short description
            - description: Detailed description
            - cwe: CWE identifier
            - file: File path
            - confidence: high, medium, low
        """
        raise NotImplementedError()
    
    def create_finding(
        self,
        severity: str,
        rule: str,
        summary: str,
        description: str,
        cwe: str = "",
        confidence: str = "high"
    ) -> Dict[str, Any]:
        """Create standardized finding dictionary"""
        return {
            'severity': severity,
            'rule': rule,
            'summary': summary,
            'description': description,
            'cwe': cwe,
            'confidence': confidence,
            'scanner': self.name,
            'scanner_version': self.version
        }
```

**Scanner Implementation Template**:

```python
class CustomScanner(BaseScanner):
    """Custom scanner for specific format"""
    
    def __init__(self, rule_engine=None):
        super().__init__(rule_engine)
        self.name = "CustomScanner"
        self.version = "1.0.0"
        self.description = "Scans custom format"
    
    def scan(self, file_path: str, rule_engine=None, **kwargs):
        findings = []
        
        try:
            # 1. Validate file
            if not self._validate_file(file_path):
                return findings
            
            # 2. Parse file (read-only, safe parsing)
            data = self._parse_file(file_path)
            
            # 3. Perform security checks
            if self._check_dangerous_pattern(data):
                findings.append(self.create_finding(
                    severity='HIGH',
                    rule='custom_dangerous_pattern',
                    summary='Dangerous pattern detected',
                    description='Found pattern X in section Y',
                    cwe='CWE-XXX'
                ))
            
            # 4. Check against rule engine
            if rule_engine:
                findings.extend(rule_engine.evaluate(data))
            
        except Exception as e:
            findings.append(self.create_finding(
                severity='INFO',
                rule='scan_error',
                summary='Scanner error',
                description=str(e)
            ))
        
        return findings
```

### 3. Rule Engine (`core/rules.py`)

**Purpose**: Security policy enforcement

**Responsibilities**:
- Load security policies from YAML
- Evaluate findings against policy rules
- Severity mapping and filtering
- CWE categorization

**Key Classes**:

```python
class RuleEngine:
    """Security policy enforcement engine"""
    
    def __init__(self, policy: str = "enterprise"):
        self.policy = policy
        self.rules = self._load_policy(policy)
    
    def _load_policy(self, policy: str) -> Dict[str, Any]:
        """Load policy from YAML file"""
        policy_file = f"rules/{policy}_policy.yaml"
        with open(policy_file) as f:
            return yaml.safe_load(f)
    
    def should_block(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding should block scan"""
        severity = finding.get('severity')
        
        if self.policy == 'strict':
            return severity in ['CRITICAL', 'HIGH']
        elif self.policy == 'enterprise':
            return severity == 'CRITICAL'
        else:
            return False
    
    def evaluate_file_size(self, file_size: int) -> Optional[Dict[str, Any]]:
        """Check file size against policy limits"""
        max_size = self.rules.get('max_file_size', 10737418240)  # 10GB
        
        if file_size > max_size:
            return {
                'severity': 'MEDIUM',
                'rule': 'file_size_exceeded',
                'summary': f'File size {file_size} exceeds limit {max_size}',
                'cwe': 'CWE-400'
            }
        return None
```

**Policy File Format** (`rules/enterprise_policy.yaml`):

```yaml
policy_name: "enterprise"
version: "1.0"
description: "Balanced security policy for production environments"

rules:
  # File size limits
  max_file_size: 10737418240  # 10GB
  
  # Pickle rules
  pickle_opcodes_warn:
    - GLOBAL
    - REDUCE
    - BUILD
  
  # Entropy thresholds
  min_entropy: 1.0
  max_entropy: 8.0
  
  # External data
  allow_external_data: true
  require_signature_validation: false
  
  # Blocking behavior
  block_on_severity:
    - CRITICAL

# Severity definitions
severity_levels:
  CRITICAL:
    description: "Immediate security threat, arbitrary code execution"
    action: "block"
  HIGH:
    description: "Significant security risk"
    action: "warn"
  MEDIUM:
    description: "Moderate security concern"
    action: "warn"
  LOW:
    description: "Minor security issue"
    action: "info"
```

### 4. Report Generator (`core/report.py`)

**Purpose**: Generate security reports in multiple formats

**Responsibilities**:
- Console output formatting
- JSON serialization
- SARIF 2.1.0 generation
- Summary statistics

**Key Classes**:

```python
class ReportGenerator:
    """Generate security scan reports"""
    
    def generate_console_report(
        self, 
        results: List[Dict[str, Any]]
    ) -> str:
        """Generate human-readable console report"""
        
    def generate_json_report(
        self, 
        results: List[Dict[str, Any]]
    ) -> str:
        """Generate JSON report for automation"""
        
    def generate_sarif_report(
        self, 
        results: List[Dict[str, Any]]
    ) -> str:
        """Generate SARIF 2.1.0 report for CI/CD"""
        
    def calculate_summary(
        self, 
        results: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Calculate summary statistics"""
        return {
            'total_files': len(results),
            'critical_count': sum(1 for r in results if r['severity'] == 'CRITICAL'),
            'high_count': sum(1 for r in results if r['severity'] == 'HIGH'),
            'medium_count': sum(1 for r in results if r['severity'] == 'MEDIUM'),
            'low_count': sum(1 for r in results if r['severity'] == 'LOW')
        }
```

**SARIF Output Structure**:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SMART-01 AI Security Scanner",
          "version": "2.0.0",
          "informationUri": "https://github.com/yourusername/smart-ai-scanner",
          "rules": [...]
        }
      },
      "results": [...]
    }
  ]
}
```

### 5. SBOM Generator (`core/sbom.py`)

**Purpose**: Generate Software Bill of Materials

**Responsibilities**:
- Component inventory
- Dependency tracking
- Vulnerability mapping
- CycloneDX format generation

**Key Classes**:

```python
class SBOMGenerator:
    """Generate CycloneDX SBOM"""
    
    def generate(
        self, 
        results: List[Dict[str, Any]]
    ) -> str:
        """Generate SBOM in CycloneDX JSON format"""
        
        components = []
        for result in results:
            components.append({
                'type': 'machine-learning-model',
                'name': result['file'],
                'version': result.get('version', 'unknown'),
                'purl': self._generate_purl(result),
                'hashes': result.get('hashes', []),
                'properties': [
                    {'name': 'format', 'value': result['format']},
                    {'name': 'scanner', 'value': result['scanner']}
                ]
            })
        
        return json.dumps({
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'components': components
        }, indent=2)
```

### 6. Opcode Analyzer (`core/opcode_analyzer.py`)

**Purpose**: Analyze Python pickle bytecode for dangerous operations

**Responsibilities**:
- Disassemble pickle bytecode
- Detect dangerous opcodes
- Trace code execution paths
- Identify code injection patterns

**Key Classes**:

```python
class OpcodeAnalyzer:
    """Analyze pickle opcodes for security issues"""
    
    DANGEROUS_OPCODES = {
        'GLOBAL': 'Imports global function/class',
        'REDUCE': 'Calls function with arguments',
        'BUILD': 'Constructs object with __setstate__',
        'INST': 'Creates class instance',
        'OBJ': 'Creates object with __setstate__',
        'NEWOBJ': 'Creates object with __new__',
        'NEWOBJ_EX': 'Creates object with extended args',
        'STACK_GLOBAL': 'Imports from stack'
    }
    
    def analyze(self, pickle_data: bytes) -> List[Dict[str, Any]]:
        """
        Analyze pickle bytecode
        
        Returns:
            List of findings with dangerous opcodes
        """
        findings = []
        
        try:
            # Disassemble pickle
            opcodes = pickletools.dis(io.BytesIO(pickle_data))
            
            # Check for dangerous opcodes
            for opcode in opcodes:
                if opcode.name in self.DANGEROUS_OPCODES:
                    findings.append({
                        'opcode': opcode.name,
                        'description': self.DANGEROUS_OPCODES[opcode.name],
                        'position': opcode.pos,
                        'argument': opcode.arg
                    })
        
        except Exception as e:
            findings.append({'error': str(e)})
        
        return findings
```

### 7. Utils (`core/utils.py`)

**Purpose**: Utility functions for scanning

**Functions**:

```python
def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    
    return entropy

def detect_magic_bytes(file_path: str) -> Optional[str]:
    """Detect file format from magic bytes"""
    with open(file_path, 'rb') as f:
        magic = f.read(16)
    
    # Pickle formats
    if magic[:2] in (b'\x80\x03', b'\x80\x04', b'\x80\x05'):
        return 'pickle'
    
    # HDF5 (Keras)
    if magic[:8] == b'\x89HDF\r\n\x1a\n':
        return 'hdf5'
    
    # ... more formats ...
    
    return None

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate file hash"""
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()
```

---

## Scanner Architecture

### Scanner Inheritance Hierarchy

```
BaseScanner (abstract)
│
├── AdvancedPickleScanner (CRITICAL)
│   ├── Formats: .pkl, .pickle, .joblib, .dill
│   ├── Detection: Opcode analysis
│   └── CWE: CWE-502
│
├── AdvancedPyTorchScanner (HIGH)
│   ├── Formats: .pt, .pth, .ckpt, .mar
│   ├── Detection: Pickle in state_dict
│   └── CWE: CWE-502, CWE-494
│
├── AdvancedKerasScanner (HIGH)
│   ├── Formats: .h5, .keras
│   ├── Detection: Lambda layers, custom objects
│   └── CWE: CWE-94
│
├── AdvancedTensorFlowScanner (HIGH)
│   ├── Formats: .pb, .pbtxt, .tflite
│   ├── Detection: Malicious operators
│   └── CWE: CWE-470
│
├── AdvancedONNXScanner (MEDIUM)
│   ├── Formats: .onnx
│   ├── Detection: Custom operators
│   └── CWE: CWE-829
│
├── AdvancedXGBoostScanner (MEDIUM)
├── AdvancedLightGBMScanner (MEDIUM)
├── AdvancedCatBoostScanner (MEDIUM)
├── AdvancedCoreMLScanner (MEDIUM)
├── AdvancedGGUFScanner (MEDIUM)
│
├── SafeTensorsScanner (LOW)
│   ├── Formats: .safetensors
│   ├── Detection: Format validation
│   └── CWE: N/A
│
├── AdvancedTokenizerScanner (LOW)
│   ├── Formats: tokenizer.json, vocab files
│   ├── Detection: Configuration issues
│   └── CWE: CWE-20
│
└── [Future Scanners]
    ├── AdvancedLLMBackdoorScanner (HIGH, pending)
    └── WeightPoisoningScanner (MEDIUM, pending)
```

### Scanner Interface Contract

Every scanner must:

1. **Inherit from BaseScanner**
2. **Implement scan() method**
3. **Return List[Dict[str, Any]]** with standardized findings
4. **Handle exceptions gracefully**
5. **Use read-only file operations only**

### Scanner Finding Format

```python
{
    'severity': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
    'rule': 'rule_identifier',
    'summary': 'Short description',
    'description': 'Detailed description',
    'cwe': 'CWE-XXX',
    'file': '/path/to/file',
    'confidence': 'high' | 'medium' | 'low',
    'scanner': 'ScannerName',
    'scanner_version': '1.0.0',
    'evidence': {
        # Scanner-specific evidence
        'opcodes': [...],
        'operators': [...],
        'etc': ...
    }
}
```

---

## Data Flow

### Scan Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CLI Entry Point (cli.py)                                     │
│    • Parse arguments                                            │
│    • Validate inputs                                            │
│    • Initialize components                                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Initialize Registry & Rule Engine                            │
│    registry = ScannerRegistry()                                 │
│    rule_engine = RuleEngine(policy="enterprise")                │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. File Discovery                                               │
│    • Single file: validate existence                            │
│    • Directory: walk tree, filter extensions                    │
│    • Apply exclusion patterns                                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. For Each File:                                               │
│    a. Format Detection                                          │
│       • Check extension                                         │
│       • Read magic bytes                                        │
│    b. Scanner Selection                                         │
│       • Lookup in registry                                      │
│       • Instantiate scanner                                     │
│    c. Execute Scan                                              │
│       • scanner.scan(file_path, rule_engine)                    │
│    d. Collect Findings                                          │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Rule Engine Evaluation                                       │
│    • Check file size                                            │
│    • Evaluate policy rules                                      │
│    • Determine blocking                                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Report Generation                                            │
│    • Aggregate findings                                         │
│    • Calculate statistics                                       │
│    • Format output (console/JSON/SARIF)                         │
│    • Generate SBOM (if requested)                               │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. Output                                                       │
│    • Print to console or write to file                          │
│    • Exit with appropriate code                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Interactive Mode Flow

```
User launches interactive mode
    │
    ▼
Display banner and system status
    │
    ▼
┌─────────────────────────────────────┐
│ Step 1: Target Selection            │
│ • Prompt for path                   │
│ • Validate existence                │
│ • Display file/directory info       │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ Step 2: Security Policy             │
│ • Show 4 policies                   │
│ • User selects (1-4)                │
│ • Display policy description        │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ Step 3: Analysis Configuration      │
│ • Output format (console/JSON/SARIF)│
│ • Deep analysis toggle              │
│ • Recursive scanning toggle         │
│ • Verbose output toggle             │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ Step 4: Configuration Summary       │
│ • Display all selections            │
│ • Confirm to proceed                │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ Step 5: Execute Scan                │
│ • Follow standard scan flow         │
│ • Display progress indicators       │
│ • Show results                      │
└─────────────────────────────────────┘
```

---

## Design Patterns

### 1. Registry Pattern

**Purpose**: Central scanner management

**Implementation**: `ScannerRegistry` maintains mappings of:
- File extensions → Scanners
- Magic bytes → Scanners
- Format names → Scanners

**Benefits**:
- Dynamic scanner discovery
- Easy addition of new scanners
- Format-based routing

### 2. Strategy Pattern

**Purpose**: Interchangeable security policies

**Implementation**: `RuleEngine` loads different YAML policies

**Benefits**:
- Flexible policy enforcement
- Easy policy customization
- Environment-specific rules

### 3. Template Method Pattern

**Purpose**: Define scanner workflow

**Implementation**: `BaseScanner` defines interface, subclasses implement

**Benefits**:
- Consistent scanner behavior
- Code reuse
- Standardized findings

### 4. Factory Pattern

**Purpose**: Scanner instantiation

**Implementation**: `ScannerRegistry.get_scanner_for_file()`

**Benefits**:
- Decoupled scanner creation
- Format-based selection
- Easy testing

### 5. Builder Pattern

**Purpose**: Complex report construction

**Implementation**: `ReportGenerator` builds reports incrementally

**Benefits**:
- Flexible report formats
- Incremental construction
- Format-specific builders

---

## Module Specifications

### CLI Module (`cli.py`)

**Lines**: ~3,300  
**Dependencies**: argparse, pathlib, sys

**Functions**:
- `create_argument_parser()` - Build argument parser
- `main()` - Entry point
- `handle_scan_command()` - Process scan command
- `handle_info_command()` - Process info command
- `handle_interactive_command()` - Process interactive mode
- `handle_version_command()` - Process version command

### UI Module (`ui/__init__.py`)

**Lines**: ~320  
**Dependencies**: Rich (optional), colorama (required)

**Constants**:
- `COLORS` - Color definitions
- `SEVERITY_STYLES` - Severity-to-symbol mapping

**Functions**:
- `create_banner()` - Generate ASCII art banner
- `create_section_header()` - Create section headers
- `create_success_message()` - Success messages
- `create_error_message()` - Error messages
- `create_info_message()` - Info messages
- `get_severity_icon()` - Get severity symbol
- `create_results_table()` - Build results table
- `create_status_panel()` - Status panel
- `create_progress_spinner()` - Progress indicator

---

## Extension Points

### Adding a New Scanner

1. **Create scanner file**: `scanners/new_scanner.py`

```python
from ..core.base_scanner import BaseScanner

class NewScanner(BaseScanner):
    def __init__(self, rule_engine=None):
        super().__init__(rule_engine)
        self.name = "NewScanner"
        self.version = "1.0.0"
    
    def scan(self, file_path: str, rule_engine=None, **kwargs):
        findings = []
        # Implementation
        return findings
```

2. **Register in registry**: `core/registry.py`

```python
from ..scanners.new_scanner import NewScanner

# In _register_builtin_scanners()
self.register_scanner(
    NewScanner,
    formats=['new_format'],
    extensions=['.new'],
    magic_bytes=[b'MAGIC']
)
```

3. **Add tests**: `tests/test_new_scanner.py`

### Adding a New Security Policy

1. **Create YAML file**: `rules/custom_policy.yaml`

```yaml
policy_name: "custom"
version: "1.0"
rules:
  max_file_size: 5368709120
  # ... more rules ...
```

2. **Use via CLI**:

```bash
python -m smart_ai_scanner scan ./models --rules rules/custom_policy.yaml
```

### Adding a New Output Format

1. **Extend ReportGenerator**: `core/report.py`

```python
def generate_xml_report(self, results):
    # XML generation logic
    pass
```

2. **Update CLI**: `cli.py`

```python
# Add to format choices
parser.add_argument('--format', choices=['console', 'json', 'sarif', 'xml'])
```

---

## Security Considerations

### Static Analysis Guarantees

1. **No Code Execution** - Models are never loaded into memory for execution
2. **Read-Only Operations** - All file operations are read-only
3. **Safe Parsers** - Use well-tested parsing libraries
4. **Sandboxing** - No subprocess execution, no eval/exec

### Threat Model

**In Scope**:
- Malicious model files (pickle, ONNX, etc.)
- Supply chain attacks (tampered models)
- Code injection (embedded executables)
- Resource exhaustion (large files)

**Out of Scope**:
- Model inference attacks
- Adversarial examples
- Model extraction
- Training data poisoning (detection only)

### Security Best Practices

1. **Input Validation** - Validate all file paths and arguments
2. **Error Handling** - Catch and report all exceptions
3. **Resource Limits** - Enforce file size limits
4. **Least Privilege** - Run with minimal permissions
5. **Logging** - Log security-relevant events

---

## Performance Characteristics

### Time Complexity

- **Single File Scan**: O(n) where n = file size
- **Directory Scan**: O(m * n) where m = number of files
- **Format Detection**: O(1) for extensions, O(k) for magic bytes

### Space Complexity

- **Memory Usage**: O(k) where k = chunk size (typically 4KB-16KB)
- **Peak Memory**: Minimal, files processed in chunks
- **No Model Loading**: Zero memory overhead from model weights

### Performance Optimizations

1. **Lazy Loading** - Scanners loaded on-demand
2. **Streaming I/O** - Files read in chunks
3. **Early Exit** - Stop on critical findings (if policy allows)
4. **Caching** - Format detection results cached

### Benchmarks (Approximate)

- **Small file (< 1MB)**: < 100ms
- **Medium file (1-100MB)**: 100ms - 2s
- **Large file (100MB - 1GB)**: 2s - 20s
- **Directory (100 files)**: 10s - 60s

---

## Future Enhancements

### Planned Features

1. **Additional Scanners**
   - AdvancedLLMBackdoorScanner (token poisoning)
   - WeightPoisoningScanner (spectral analysis)
   - JAX model support
   - Paddle Paddle support

2. **Enhanced Analysis**
   - ML-based anomaly detection
   - Cross-model comparison
   - Provenance tracking
   - Digital signatures

3. **Integrations**
   - VS Code extension
   - GitHub App
   - Docker image
   - Cloud scanning service

4. **Performance**
   - Parallel scanning
   - Distributed scanning
   - Incremental scanning
   - Caching layer

---

## Appendix

### Glossary

- **Aegis-ML**: Security framework for ML models emphasizing static analysis
- **SBOM**: Software Bill of Materials
- **SARIF**: Static Analysis Results Interchange Format
- **CWE**: Common Weakness Enumeration
- **Opcode**: Operation code in pickle bytecode

### References

- [OASIS SARIF Specification](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [CWE Database](https://cwe.mitre.org/)
- [Pickle Security Considerations](https://docs.python.org/3/library/pickle.html)

---

**SMART-01 AI Security Scanner Architecture v2.0.0**  
**Last Updated**: October 2025  
**Status**: Production Ready
