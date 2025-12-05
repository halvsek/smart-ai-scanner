"""
Rule engine for SMART AI Security Scanner
YAML-based rules with policy overlays and security frameworks
"""

import yaml
import pathlib
from typing import Dict, Any, List, Optional, Union

# Default security rules - these represent industry best practices
DEFAULT_RULES = {
    # File format policies
    "dangerous_extensions": [
        ".pkl", ".pickle", ".dill", ".joblib",  # Pickle family
        ".pt", ".pth", ".ckpt", ".mar"          # PyTorch (contains pickle)
    ],
    
    # Pickle security rules
    "pickle_opcodes_block": [
        "GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", 
        "STACK_GLOBAL", "REDUCE", "BUILD", "APPEND", "APPENDS"
    ],
    
    # ONNX security rules
    "onnx_forbidden_ops": [
        "Loop", "If", "Scan",                    # Control flow
        "com.microsoft::*",                       # Microsoft custom ops
        "ai.onnx.preview::*",                    # Preview ops
        "org.pytorch::*"                         # PyTorch custom ops
    ],
    
    # Keras/TensorFlow rules
    "keras_lambda_allowed": False,               # Lambda layers are dangerous
    "tf_custom_ops_allowed": False,              # Custom ops can be risky
    
    # File size and memory limits
    "external_data_max": 67_108_864,            # 64MB per external tensor
    "max_tensor_elems": 3_000_000_000,          # 3B elements max
    "max_file_size": 10_737_418_240,            # 10GB max file size
    
    # Tokenizer security
    "tokenizer_red_flags": [
        "\\x00", "\\x1a", "\\x1b",              # Control characters
        "file://", "http://", "https://",        # URLs
        "eval(", "exec(", "__import__"           # Code execution
    ],
    
    # Entropy thresholds for anomaly detection
    "min_entropy_threshold": 1.0,               # Very low entropy (suspicious)
    "max_entropy_threshold": 7.8,               # Very high entropy (encrypted/compressed)
    
    # Path traversal patterns
    "path_traversal_patterns": [
        "..", "/etc/", "/usr/", "/bin/", "/var/",
        "\\windows\\", "\\system32\\", "c:\\"
    ],
    
    # Magic byte signatures for embedded executables
    "executable_signatures": {
        "PE": ["4d5a"],                          # MZ header
        "ELF": ["7f454c46"],                     # ELF header
        "Mach-O": ["feedface", "feedfacf"],      # Mach-O headers
        "Java": ["cafebabe"]                     # Java class
    }
}

# Security policy presets
POLICY_PRESETS = {
    "strict": {
        "block_dangerous_formats": True,
        "allow_external_data": False,
        "max_file_size": 1_073_741_824,         # 1GB limit
        "require_safetensors": True,
        "block_custom_ops": True
    },
    
    "enterprise": {
        "block_dangerous_formats": False,        # Warn instead
        "allow_external_data": True,
        "max_file_size": 10_737_418_240,        # 10GB limit
        "require_safetensors": False,
        "block_custom_ops": False
    },
    
    "research": {
        "block_dangerous_formats": False,
        "allow_external_data": True,
        "max_file_size": 107_374_182_400,       # 100GB limit
        "require_safetensors": False,
        "block_custom_ops": False
    },
    
    "forensics": {
        "block_dangerous_formats": False,        # Analyze everything
        "allow_external_data": True,
        "max_file_size": 1_099_511_627_776,    # 1TB limit
        "require_safetensors": False,
        "block_custom_ops": False
    }
}

class RuleEngine:
    """
    Rule engine that loads YAML rules and applies security policies
    """
    
    def __init__(self, custom_rules_path: Optional[str] = None, policy: str = "enterprise"):
        """
        Initialize rule engine with optional custom rules and policy
        
        Args:
            custom_rules_path: Path to custom YAML rules file
            policy: Security policy preset (strict, enterprise, research, forensics)
        """
        self.rules = DEFAULT_RULES.copy()
        self.policy = policy
        self.policy_config = POLICY_PRESETS.get(policy, POLICY_PRESETS["enterprise"])
        
        # Load custom rules if provided
        if custom_rules_path:
            self._load_custom_rules(custom_rules_path)
        
        # Apply policy overrides
        self._apply_policy()
    
    def _load_custom_rules(self, rules_path: str):
        """Load custom rules from YAML file"""
        try:
            path = pathlib.Path(rules_path)
            if not path.exists():
                raise FileNotFoundError(f"Rules file not found: {rules_path}")
            
            with open(path, 'r', encoding='utf-8') as f:
                custom_rules = yaml.safe_load(f) or {}
            
            # Merge custom rules with defaults
            self.rules.update(custom_rules)
            
        except Exception as e:
            raise ValueError(f"Failed to load custom rules: {e}")
    
    def _apply_policy(self):
        """Apply policy-specific rule modifications"""
        if self.policy == "strict":
            # Stricter limits for strict policy
            self.rules["max_file_size"] = self.policy_config["max_file_size"]
            self.rules["external_data_max"] = 16_777_216  # 16MB
            
        elif self.policy == "forensics":
            # More permissive for forensic analysis
            self.rules["max_file_size"] = self.policy_config["max_file_size"]
            # Don't block anything, just analyze
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get rule value by key"""
        return self.rules.get(key, default)
    
    def get_policy_setting(self, key: str, default: Any = None) -> Any:
        """Get policy configuration setting"""
        return self.policy_config.get(key, default)
    
    def should_block_format(self, file_extension: str) -> bool:
        """Check if file format should be blocked based on policy"""
        if not self.policy_config.get("block_dangerous_formats", False):
            return False
        
        dangerous_exts = self.get("dangerous_extensions", [])
        return file_extension.lower() in dangerous_exts
    
    def is_forbidden_pickle_opcode(self, opcode: str) -> bool:
        """Check if pickle opcode is forbidden"""
        forbidden_opcodes = self.get("pickle_opcodes_block", [])
        return opcode in forbidden_opcodes
    
    def is_forbidden_onnx_op(self, op_name: str) -> bool:
        """Check if ONNX operator is forbidden"""
        forbidden_ops = self.get("onnx_forbidden_ops", [])
        
        for forbidden in forbidden_ops:
            if forbidden.endswith("*"):
                # Wildcard match
                prefix = forbidden[:-1]
                if op_name.startswith(prefix):
                    return True
            else:
                # Exact match
                if op_name == forbidden:
                    return True
        
        return False
    
    def check_file_size(self, size_bytes: int) -> Dict[str, Any]:
        """Check if file size is acceptable"""
        max_size = self.get("max_file_size", 10_737_418_240)
        
        if size_bytes > max_size:
            return {
                "allowed": False,
                "reason": f"File size {size_bytes:,} bytes exceeds limit {max_size:,} bytes",
                "severity": "HIGH"
            }
        
        return {"allowed": True}
    
    def check_tensor_size(self, total_elements: int, dtype_size: int = 4) -> Dict[str, Any]:
        """Check if tensor size is acceptable"""
        max_elements = self.get("max_tensor_elems", 3_000_000_000)
        memory_bytes = total_elements * dtype_size
        
        if total_elements > max_elements:
            return {
                "allowed": False,
                "reason": f"Tensor has {total_elements:,} elements, exceeds limit {max_elements:,}",
                "severity": "MEDIUM",
                "memory_gb": memory_bytes / (1024**3)
            }
        
        # Check memory usage
        memory_gb = memory_bytes / (1024**3)
        if memory_gb > 64:  # 64GB warning threshold
            return {
                "allowed": True,
                "reason": f"Large tensor requires {memory_gb:.1f}GB memory",
                "severity": "LOW",
                "memory_gb": memory_gb
            }
        
        return {"allowed": True, "memory_gb": memory_gb}
    
    def check_external_data_path(self, path: str) -> Dict[str, Any]:
        """Check if external data path is safe"""
        if not self.policy_config.get("allow_external_data", True):
            return {
                "allowed": False,
                "reason": "External data not allowed by policy",
                "severity": "HIGH"
            }
        
        # Check for path traversal
        traversal_patterns = self.get("path_traversal_patterns", [])
        path_lower = path.lower()
        
        for pattern in traversal_patterns:
            if pattern in path_lower:
                return {
                    "allowed": False,
                    "reason": f"Potential path traversal: {pattern} in {path}",
                    "severity": "CRITICAL"
                }
        
        return {"allowed": True}
    
    def check_entropy(self, entropy: float) -> Dict[str, Any]:
        """Check if entropy value is suspicious"""
        min_threshold = self.get("min_entropy_threshold", 1.0)
        max_threshold = self.get("max_entropy_threshold", 7.8)
        
        findings = []
        
        if entropy < min_threshold:
            findings.append({
                "type": "low_entropy",
                "reason": f"Very low entropy {entropy:.2f} may indicate padding or constant data",
                "severity": "LOW"
            })
        
        if entropy > max_threshold:
            findings.append({
                "type": "high_entropy", 
                "reason": f"Very high entropy {entropy:.2f} may indicate encryption or compression",
                "severity": "MEDIUM"
            })
        
        return {"findings": findings}
    
    def check_tokenizer_content(self, content: str) -> List[Dict[str, Any]]:
        """Check tokenizer content for suspicious patterns"""
        red_flags = self.get("tokenizer_red_flags", [])
        findings = []
        
        content_lower = content.lower()
        
        for flag in red_flags:
            if flag in content_lower:
                findings.append({
                    "pattern": flag,
                    "reason": f"Suspicious pattern in tokenizer: {flag}",
                    "severity": "MEDIUM" if flag.startswith("\\x") else "HIGH"
                })
        
        return findings
    
    def get_cwe_mapping(self, rule_type: str) -> str:
        """Get CWE (Common Weakness Enumeration) for rule type"""
        cwe_map = {
            "pickle_unsafe": "CWE-502",      # Deserialization of Untrusted Data
            "path_traversal": "CWE-22",      # Path Traversal
            "code_injection": "CWE-94",      # Code Injection
            "resource_exhaustion": "CWE-400", # Resource Exhaustion
            "unsafe_reflection": "CWE-470",   # Use of Externally-Controlled Input
            "buffer_overflow": "CWE-120",     # Buffer Copy without Checking Size
            "external_control": "CWE-426",    # Untrusted Search Path
            "information_leak": "CWE-200"     # Information Exposure
        }
        
        return cwe_map.get(rule_type, "CWE-693")  # Protection Mechanism Failure
    
    def create_finding(self, rule_type: str, severity: str, summary: str, 
                      detail: str = "", artifact: str = "", scanner: str = "") -> Dict[str, Any]:
        """Create a standardized finding dictionary"""
        return {
            "artifact": artifact,
            "scanner": scanner,
            "severity": severity,
            "rule": rule_type,
            "summary": summary,
            "detail": detail,
            "cwe": self.get_cwe_mapping(rule_type),
            "policy": self.policy,
            "timestamp": None  # Will be set by scanner
        }
    
    def export_rules(self) -> Dict[str, Any]:
        """Export current rules configuration"""
        return {
            "rules": self.rules.copy(),
            "policy": self.policy,
            "policy_config": self.policy_config.copy()
        }