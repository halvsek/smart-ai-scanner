"""
Report renderers for SMART AI Security Scanner
Supports console, JSON, SARIF, and other output formats
"""

import json
import time
import pathlib
import uuid
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback - no colors
    class _ForeColor:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class _Style:
        BRIGHT = DIM = RESET_ALL = ""
    Fore = _ForeColor()
    Style = _Style()

@dataclass
class ScanSummary:
    """Summary of scan results"""
    total_files: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    scan_duration: float
    policy_used: str
    formats_detected: List[str]
    scanners_used: List[str]

class BaseRenderer:
    """Base class for all report renderers"""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
    
    def render(self, results: List[Dict[str, Any]], summary: ScanSummary, 
               output_path: Optional[str] = None) -> str:
        """Render scan results to string format"""
        raise NotImplementedError("Subclasses must implement render()")
    
    def _get_severity_priority(self, severity: str) -> int:
        """Get numeric priority for severity levels"""
        priority_map = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }
        return priority_map.get(severity.upper(), 0)

class ConsoleRenderer(BaseRenderer):
    """Console output with colors and formatting"""
    
    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and COLORAMA_AVAILABLE
    
    def render(self, results: List[Dict[str, Any]], summary: ScanSummary, 
               output_path: Optional[str] = None) -> str:
        """Render results for console display"""
        output = []
        
        # Header
        output.append(self._render_header())
        
        # Summary
        output.append(self._render_summary(summary))
        
        # Results by severity
        output.append(self._render_findings_by_severity(results))
        
        # File details
        output.append(self._render_file_details(results))
        
        # Footer with recommendations
        output.append(self._render_footer(summary))
        
        rendered = "\n".join(output)
        
        # Save to file if requested
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Strip ANSI codes for file output
                import re
                clean_output = re.sub(r'\x1b\[[0-9;]*m', '', rendered)
                f.write(clean_output)
        
        return rendered
    
    def _render_header(self) -> str:
        """Render scan report header"""
        if not self.use_colors:
            return "=== SMART AI Security Scanner Report ==="
        
        return f"{Style.BRIGHT}{Fore.CYAN}=== SMART AI Security Scanner Report ==={Style.RESET_ALL}"
    
    def _render_summary(self, summary: ScanSummary) -> str:
        """Render scan summary"""
        lines = [
            "",
            "📊 SCAN SUMMARY",
            "─" * 50,
            f"Files Scanned: {summary.total_files}",
            f"Total Findings: {summary.total_findings}",
            f"Policy: {summary.policy_used}",
            f"Duration: {summary.scan_duration:.2f}s",
            ""
        ]
        
        # Severity breakdown with colors
        if summary.critical_findings > 0:
            color = Fore.RED if self.use_colors else ""
            reset = Style.RESET_ALL if self.use_colors else ""
            lines.append(f"{color}🔴 Critical: {summary.critical_findings}{reset}")
        
        if summary.high_findings > 0:
            color = Fore.YELLOW if self.use_colors else ""
            reset = Style.RESET_ALL if self.use_colors else ""
            lines.append(f"{color}🟠 High: {summary.high_findings}{reset}")
        
        if summary.medium_findings > 0:
            color = Fore.BLUE if self.use_colors else ""
            reset = Style.RESET_ALL if self.use_colors else ""
            lines.append(f"{color}🔵 Medium: {summary.medium_findings}{reset}")
        
        if summary.low_findings > 0:
            color = Fore.GREEN if self.use_colors else ""
            reset = Style.RESET_ALL if self.use_colors else ""
            lines.append(f"{color}🟢 Low: {summary.low_findings}{reset}")
        
        return "\n".join(lines)
    
    def _render_findings_by_severity(self, results: List[Dict[str, Any]]) -> str:
        """Render findings grouped by severity"""
        # Collect all findings
        all_findings = []
        for result in results:
            for finding in result.get("findings", []):
                finding["file"] = result["file"]
                all_findings.append(finding)
        
        if not all_findings:
            return "\n✅ No security issues found!\n"
        
        # Group by severity
        by_severity = {}
        for finding in all_findings:
            severity = finding.get("severity", "UNKNOWN").upper()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        lines = ["\n🔍 SECURITY FINDINGS", "─" * 50]
        
        # Render each severity group
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity not in by_severity:
                continue
            
            findings = by_severity[severity]
            color, icon = self._get_severity_style(severity)
            
            if self.use_colors:
                lines.append(f"\n{color}{icon} {severity} ({len(findings)} findings){Style.RESET_ALL}")
            else:
                lines.append(f"\n{icon} {severity} ({len(findings)} findings)")
            
            for finding in findings[:5]:  # Show first 5 findings per severity
                lines.append(f"  • {finding.get('summary', 'No summary')}")
                if finding.get("detail"):
                    lines.append(f"    {finding['detail']}")
                lines.append(f"    File: {pathlib.Path(finding['file']).name}")
                if finding.get("cwe"):
                    lines.append(f"    CWE: {finding['cwe']}")
                lines.append("")
            
            if len(findings) > 5:
                lines.append(f"  ... and {len(findings) - 5} more {severity.lower()} findings")
        
        return "\n".join(lines)
    
    def _render_file_details(self, results: List[Dict[str, Any]]) -> str:
        """Render per-file details"""
        if not results:
            return ""
        
        lines = ["\n📁 FILE DETAILS", "─" * 50]
        
        for result in results:
            file_path = pathlib.Path(result["file"])
            findings_count = len(result.get("findings", []))
            
            if findings_count == 0:
                status = "✅ Clean"
                color = Fore.GREEN if self.use_colors else ""
            else:
                status = f"⚠️  {findings_count} issues"
                color = Fore.YELLOW if self.use_colors else ""
            
            reset = Style.RESET_ALL if self.use_colors else ""
            
            lines.append(f"\n{color}{file_path.name}{reset}")
            lines.append(f"  Path: {file_path.parent}")
            lines.append(f"  Size: {result.get('size', 0):,} bytes")
            lines.append(f"  Formats: {', '.join(result.get('formats', ['unknown']))}")
            lines.append(f"  Scanners: {', '.join(result.get('scanners_used', []))}")
            lines.append(f"  Status: {status}")
            
            if result.get("error"):
                lines.append(f"  Error: {result['error']}")
        
        return "\n".join(lines)
    
    def _render_footer(self, summary: ScanSummary) -> str:
        """Render footer with recommendations"""
        lines = ["\n💡 RECOMMENDATIONS", "─" * 50]
        
        if summary.critical_findings > 0:
            lines.append("🔴 IMMEDIATE ACTION REQUIRED:")
            lines.append("  • Review all CRITICAL findings immediately")
            lines.append("  • Consider quarantining affected models")
            lines.append("  • Do not use models with critical security issues")
            lines.append("")
        
        if summary.high_findings > 0:
            lines.append("🟠 HIGH PRIORITY:")
            lines.append("  • Address HIGH severity findings before deployment")
            lines.append("  • Implement additional security controls")
            lines.append("")
        
        if summary.total_findings == 0:
            lines.append("✅ All scanned files passed security checks!")
            lines.append("  • Models appear safe for use")
            lines.append("  • Consider periodic rescanning")
            lines.append("")
        
        lines.extend([
            "📚 RESOURCES:",
            "  • OWASP ML Security: https://owasp.org/www-project-machine-learning-security-top-10/",
            "  • SafeTensors format: https://huggingface.co/docs/safetensors/",
            "  • Model security best practices: https://github.com/EthicalML/awesome-machine-learning-operations",
            f"\nScan completed at {self.timestamp}"
        ])
        
        return "\n".join(lines)
    
    def _get_severity_style(self, severity: str) -> tuple:
        """Get color and icon for severity level"""
        styles = {
            "CRITICAL": (Fore.RED, "🔴"),
            "HIGH": (Fore.YELLOW, "🟠"),
            "MEDIUM": (Fore.BLUE, "🔵"),
            "LOW": (Fore.GREEN, "🟢"),
            "INFO": (Fore.CYAN, "ℹ️")
        }
        return styles.get(severity.upper(), (Fore.WHITE, "⚪"))

class JsonRenderer(BaseRenderer):
    """JSON output renderer"""
    
    def render(self, results: List[Dict[str, Any]], summary: ScanSummary, 
               output_path: Optional[str] = None) -> str:
        """Render results as JSON"""
        output = {
            "tool": "smart-ai-scanner",
            "version": "1.0.0",
            "timestamp": self.timestamp,
            "summary": asdict(summary),
            "results": results
        }
        
        json_str = json.dumps(output, indent=2, ensure_ascii=False)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        
        return json_str

class SarifRenderer(BaseRenderer):
    """SARIF (Static Analysis Results Interchange Format) renderer"""
    
    def render(self, results: List[Dict[str, Any]], summary: ScanSummary, 
               output_path: Optional[str] = None) -> str:
        """Render results as SARIF JSON"""
        
        # Create SARIF structure
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SMART AI Security Scanner",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/yourusername/smart-ai-scanner",
                            "rules": self._generate_sarif_rules()
                        }
                    },
                    "results": self._generate_sarif_results(results),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": self.timestamp,
                            "endTimeUtc": datetime.now().isoformat()
                        }
                    ]
                }
            ]
        }
        
        json_str = json.dumps(sarif, indent=2, ensure_ascii=False)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
        
        return json_str
    
    def _generate_sarif_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions"""
        return [
            {
                "id": "pickle-unsafe-opcode",
                "shortDescription": {"text": "Unsafe pickle opcode detected"},
                "fullDescription": {"text": "Pickle file contains potentially dangerous opcodes that could execute arbitrary code during deserialization."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "deserialization", "pickle"]}
            },
            {
                "id": "onnx-custom-operator",
                "shortDescription": {"text": "Custom ONNX operator"},
                "fullDescription": {"text": "ONNX model contains custom operators that may pose security risks."},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["security", "onnx", "custom-ops"]}
            },
            {
                "id": "file-size-limit",
                "shortDescription": {"text": "File size exceeds policy limit"},
                "fullDescription": {"text": "Model file size exceeds configured policy limits."},
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["policy", "resource-exhaustion"]}
            }
        ]
    
    def _generate_sarif_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert scan results to SARIF format"""
        sarif_results = []
        
        for result in results:
            for finding in result.get("findings", []):
                sarif_result = {
                    "ruleId": finding.get("rule", "unknown"),
                    "message": {"text": finding.get("summary", "No description")},
                    "level": self._map_severity_to_sarif(finding.get("severity", "info")),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result["file"]
                                }
                            }
                        }
                    ]
                }
                
                # Add additional properties
                if finding.get("detail"):
                    sarif_result["message"]["text"] += f" {finding['detail']}"
                
                if finding.get("cwe"):
                    sarif_result["properties"] = {"cwe": finding["cwe"]}
                
                sarif_results.append(sarif_result)
        
        return sarif_results
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map our severity levels to SARIF levels"""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error", 
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note"
        }
        return mapping.get(severity.upper(), "note")

def create_summary(results: List[Dict[str, Any]], scan_duration: float, 
                  policy: str) -> ScanSummary:
    """Create a scan summary from results"""
    
    # Count findings by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_findings = 0
    formats_detected = set()
    scanners_used = set()
    
    for result in results:
        for finding in result.get("findings", []):
            severity = finding.get("severity", "LOW").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            total_findings += 1
        
        formats_detected.update(result.get("formats", []))
        scanners_used.update(result.get("scanners_used", []))
    
    return ScanSummary(
        total_files=len(results),
        total_findings=total_findings,
        critical_findings=severity_counts["CRITICAL"],
        high_findings=severity_counts["HIGH"],
        medium_findings=severity_counts["MEDIUM"],
        low_findings=severity_counts["LOW"],
        scan_duration=scan_duration,
        policy_used=policy,
        formats_detected=sorted(list(formats_detected)),
        scanners_used=sorted(list(scanners_used))
    )