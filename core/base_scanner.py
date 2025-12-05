"""
Base scanner class for SMART AI Security Scanner
Provides common functionality for all format-specific scanners
"""

import time
import os
from typing import Dict, List, Any, Optional
from pathlib import Path


class BaseScanner:
    """
    Base class that all scanners must implement
    
    Provides common utilities for:
    - Standardized finding creation
    - Error handling
    - File validation
    - Recommendation generation
    """
    
    def __init__(self, rule_engine=None):
        """
        Initialize scanner with optional rule engine
        
        Args:
            rule_engine: RuleEngine instance for policy enforcement
        """
        self.rule_engine = rule_engine
        self.findings = []
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Base security scanner"
    
    def scan(self, file_path: str, rule_engine=None, **kwargs) -> List[Dict[str, Any]]:
        """
        Scan a file and return list of findings
        
        Args:
            file_path: Path to file to scan
            rule_engine: Optional rule engine override
            **kwargs: Additional scanner-specific arguments
            
        Returns:
            List of finding dictionaries
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(f"{self.name} must implement scan() method")
    
    def can_scan(self, file_path: str) -> bool:
        """
        Check if this scanner can handle the given file
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if scanner can handle this file, False otherwise
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(f"{self.name} must implement can_scan() method")
    
    def get_supported_formats(self) -> List[str]:
        """
        Return list of file formats this scanner supports
        
        Returns:
            List of format names (e.g., ['pickle', 'joblib'])
            
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(f"{self.name} must implement get_supported_formats() method")
    
    def _create_finding(self, file_path: str, rule: str, severity: str, summary: str, 
                       detail: str, cwe: str, risk_score: int, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary
        
        Args:
            file_path: Path to the file with the finding
            rule: Rule ID that triggered the finding
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            summary: Brief one-line summary of the finding
            detail: Detailed technical explanation
            cwe: CWE identifier (e.g., 'CWE-502')
            risk_score: Numeric risk score (0-50)
            metadata: Optional additional metadata
            
        Returns:
            Standardized finding dictionary
        """
        return {
            "rule": rule,
            "severity": severity.upper(),
            "summary": summary,
            "detail": detail,
            "cwe": cwe,
            "recommendation": self._get_recommendation(rule, severity, risk_score),
            "risk_score": risk_score,
            "scanner": self.name,
            "artifact": file_path,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
    
    def _get_recommendation(self, rule: str, severity: str, risk_score: int) -> str:
        """
        Get appropriate remediation recommendation based on severity and risk score
        
        Args:
            rule: Rule ID
            severity: Severity level
            risk_score: Numeric risk score
            
        Returns:
            Human-readable recommendation string
        """
        severity_upper = severity.upper()
        
        if severity_upper == "CRITICAL" or risk_score >= 35:
            return ("IMMEDIATE ACTION REQUIRED: Do not use in production. "
                   "Quarantine file and investigate. Consider alternative formats like SafeTensors.")
        elif severity_upper == "HIGH" or risk_score >= 25:
            return ("HIGH PRIORITY: Review before use. Implement sandboxing if loading required. "
                   "Apply strict security controls.")
        elif severity_upper == "MEDIUM" or risk_score >= 15:
            return ("MEDIUM PRIORITY: Analyze further and implement additional security controls. "
                   "Monitor for suspicious behavior.")
        elif severity_upper == "LOW" or risk_score >= 5:
            return ("LOW PRIORITY: Document finding. Consider security hardening measures. "
                   "Monitor in production environment.")
        else:
            return "INFORMATIONAL: No immediate action required. Consider as part of security review."
    
    def _validate_file(self, file_path: str) -> tuple[bool, Optional[str]]:
        """
        Validate that file exists and is readable
        
        Args:
            file_path: Path to file to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        path = Path(file_path)
        
        if not path.exists():
            return False, f"File not found: {file_path}"
        
        if not path.is_file():
            return False, f"Path is not a file: {file_path}"
        
        if not os.access(file_path, os.R_OK):
            return False, f"File is not readable: {file_path}"
        
        file_size = path.stat().st_size
        if file_size == 0:
            return False, f"File is empty: {file_path}"
        
        return True, None
    
    def _create_error_finding(self, file_path: str, error: Exception, context: str = "") -> Dict[str, Any]:
        """
        Create a finding for scanner errors
        
        Args:
            file_path: Path to file being scanned
            error: Exception that occurred
            context: Optional context about where error occurred
            
        Returns:
            Error finding dictionary
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        detail = f"Scanner Error: {error_type}\n"
        if context:
            detail += f"Context: {context}\n"
        detail += f"Message: {error_msg}\n\n"
        detail += ("This error prevented complete security analysis. "
                  "The file may contain unusual structures or be corrupted. "
                  "Consider manual review or alternative analysis tools.")
        
        return self._create_finding(
            file_path=file_path,
            rule="SCANNER_ERROR",
            severity="LOW",
            summary=f"Scanner encountered {error_type} during analysis",
            detail=detail,
            cwe="CWE-693",
            risk_score=5,
            metadata={
                'error_type': error_type,
                'error_message': error_msg,
                'context': context,
                'category': 'Analysis Error'
            }
        )
    
    def _check_file_size(self, file_path: str, max_size_mb: int = 1000) -> Optional[Dict[str, Any]]:
        """
        Check if file size exceeds reasonable limits
        
        Args:
            file_path: Path to file to check
            max_size_mb: Maximum file size in MB (default: 1000MB = 1GB)
            
        Returns:
            Finding if file is too large, None otherwise
        """
        file_size = os.path.getsize(file_path)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        if file_size > max_size_bytes:
            return self._create_finding(
                file_path=file_path,
                rule="EXCESSIVE_FILE_SIZE",
                severity="MEDIUM",
                summary=f"File size ({file_size / (1024**2):.1f} MB) exceeds recommended limit",
                detail=(f"File size is {file_size:,} bytes ({file_size / (1024**2):.1f} MB), "
                       f"which exceeds the recommended maximum of {max_size_mb} MB. "
                       f"Large files may indicate: embedded payloads, supply chain tampering, "
                       f"or resource exhaustion attacks."),
                cwe="CWE-770",
                risk_score=15,
                metadata={
                    'file_size_bytes': file_size,
                    'file_size_mb': file_size / (1024**2),
                    'max_size_mb': max_size_mb,
                    'category': 'Resource Analysis'
                }
            )
        
        return None
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """
        Get information about this scanner
        
        Returns:
            Dictionary with scanner metadata
        """
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'supported_formats': self.get_supported_formats() if hasattr(self, 'get_supported_formats') else []
        }