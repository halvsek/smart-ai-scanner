"""
Software Bill of Materials (SBOM) generation for SMART AI Security Scanner
Generates CycloneDX-compliant SBOMs for ML models and attestation
"""

import json
import hashlib
import pathlib
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass

@dataclass
class Component:
    """Represents a component in the SBOM"""
    name: str
    version: str
    type: str  # "library", "application", "framework", "file", etc.
    bom_ref: str
    purl: Optional[str] = None
    description: Optional[str] = None
    hashes: Optional[Dict[str, str]] = None
    licenses: Optional[List[Dict[str, str]]] = None
    supplier: Optional[Dict[str, str]] = None
    properties: Optional[List[Dict[str, str]]] = None

@dataclass
class Vulnerability:
    """Represents a vulnerability in the SBOM"""
    id: str
    source: str
    severity: str
    summary: str
    detail: Optional[str] = None
    cwe: Optional[str] = None
    affects: Optional[List[str]] = None

class SBOMGenerator:
    """
    Generates CycloneDX Software Bill of Materials for ML models
    """
    
    def __init__(self, tool_name: str = "smart-ai-scanner", tool_version: str = "1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.timestamp = datetime.now().isoformat() + "Z"
    
    def generate_sbom(self, scan_results: List[Dict[str, Any]], 
                     output_path: Optional[str] = None) -> str:
        """
        Generate a complete SBOM from scan results
        
        Args:
            scan_results: List of scan result dictionaries
            output_path: Optional path to save SBOM JSON file
        
        Returns:
            SBOM as JSON string
        """
        
        # Generate unique SBOM identifier
        sbom_uuid = str(uuid.uuid4())
        
        # Create base SBOM structure
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{sbom_uuid}",
            "version": 1,
            "metadata": self._create_metadata(),
            "components": self._extract_components(scan_results),
            "vulnerabilities": self._extract_vulnerabilities(scan_results),
            "dependencies": self._extract_dependencies(scan_results),
            "properties": self._create_properties(scan_results)
        }
        
        # Convert to JSON
        sbom_json = json.dumps(sbom, indent=2, ensure_ascii=False)
        
        # Save to file if requested
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(sbom_json)
        
        return sbom_json
    
    def _create_metadata(self) -> Dict[str, Any]:
        """Create SBOM metadata section"""
        return {
            "timestamp": self.timestamp,
            "tools": [
                {
                    "vendor": "SMART AI Scanner",
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "hashes": [],
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://github.com/yourusername/smart-ai-scanner"
                        }
                    ]
                }
            ],
            "authors": [
                {
                    "name": "SMART AI Security Scanner",
                    "email": "security@example.com"
                }
            ],
            "supplier": {
                "name": "SMART AI Scanner Project",
                "url": ["https://github.com/yourusername/smart-ai-scanner"]
            }
        }
    
    def _extract_components(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract components from scan results"""
        components = []
        
        for result in scan_results:
            file_path = pathlib.Path(result["file"])
            
            # Create component for each scanned file
            component = {
                "type": "file",
                "bom-ref": str(uuid.uuid4()),
                "name": file_path.name,
                "version": "unknown",
                "description": f"ML model file ({', '.join(result.get('formats', ['unknown']))})",
                "hashes": self._calculate_file_hashes(result["file"]),
                "properties": [
                    {"name": "smart:file-size", "value": str(result.get("size", 0))},
                    {"name": "smart:formats", "value": ",".join(result.get("formats", []))},
                    {"name": "smart:scanners", "value": ",".join(result.get("scanners_used", []))},
                    {"name": "smart:scan-time", "value": str(result.get("scan_time", 0))}
                ]
            }
            
            # Add PURL if we can determine the ecosystem
            purl = self._generate_purl(file_path, result.get("formats", []))
            if purl:
                component["purl"] = purl
            
            # Add external references for known model hubs
            external_refs = self._generate_external_references(file_path, result)
            if external_refs:
                component["externalReferences"] = external_refs
            
            # Add licensing information if detected
            licenses = self._detect_licenses(result)
            if licenses:
                component["licenses"] = licenses
            
            components.append(component)
        
        return components
    
    def _extract_vulnerabilities(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from scan results"""
        vulnerabilities = []
        
        for result in scan_results:
            component_ref = f"file:{pathlib.Path(result['file']).name}"
            
            for finding in result.get("findings", []):
                vuln = {
                    "id": f"SMART-{uuid.uuid4().hex[:8].upper()}",
                    "source": {
                        "name": "SMART AI Scanner",
                        "url": "https://github.com/yourusername/smart-ai-scanner"
                    },
                    "ratings": [
                        {
                            "source": {"name": "SMART AI Scanner"},
                            "severity": finding.get("severity", "LOW").lower(),
                            "method": "other"
                        }
                    ],
                    "description": finding.get("summary", "Security finding"),
                    "detail": finding.get("detail", ""),
                    "affects": [{"ref": component_ref}],
                    "properties": [
                        {"name": "smart:rule", "value": finding.get("rule", "unknown")},
                        {"name": "smart:scanner", "value": finding.get("scanner", "unknown")}
                    ]
                }
                
                # Add CWE information if available
                if finding.get("cwe"):
                    vuln["cwes"] = [int(finding["cwe"].replace("CWE-", ""))]
                
                # Add CVSS score estimation based on severity
                cvss_score = self._estimate_cvss_score(finding.get("severity", "LOW"))
                if cvss_score:
                    vuln["ratings"][0]["score"] = cvss_score
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_dependencies(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract dependency relationships"""
        # For ML models, dependencies are typically minimal
        # This could be enhanced to detect framework dependencies
        dependencies = []
        
        for result in scan_results:
            file_path = pathlib.Path(result["file"])
            formats = result.get("formats", [])
            
            # Create basic dependency entry
            deps = []
            
            # Infer framework dependencies based on format
            if "pytorch" in formats:
                deps.append("pkg:pypi/torch")
            if "tensorflow" in formats or "keras" in formats:
                deps.append("pkg:pypi/tensorflow")
            if "onnx" in formats:
                deps.append("pkg:pypi/onnx")
            if "safetensors" in formats:
                deps.append("pkg:pypi/safetensors")
            
            if deps:
                dependencies.append({
                    "ref": f"file:{file_path.name}",
                    "dependsOn": deps
                })
        
        return dependencies
    
    def _create_properties(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Create global SBOM properties"""
        total_files = len(scan_results)
        total_findings = sum(len(r.get("findings", [])) for r in scan_results)
        
        formats = set()
        scanners = set()
        
        for result in scan_results:
            formats.update(result.get("formats", []))
            scanners.update(result.get("scanners_used", []))
        
        return [
            {"name": "smart:total-files", "value": str(total_files)},
            {"name": "smart:total-findings", "value": str(total_findings)},
            {"name": "smart:formats-detected", "value": ",".join(sorted(formats))},
            {"name": "smart:scanners-used", "value": ",".join(sorted(scanners))},
            {"name": "smart:scan-timestamp", "value": self.timestamp}
        ]
    
    def _calculate_file_hashes(self, file_path: str) -> List[Dict[str, str]]:
        """Calculate file hashes for integrity verification"""
        hashes = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Calculate multiple hash algorithms
            algorithms = ['sha256', 'sha1', 'md5']
            
            for algo in algorithms:
                hasher = hashlib.new(algo)
                hasher.update(content)
                hashes.append({
                    "alg": algo.upper(),
                    "content": hasher.hexdigest()
                })
        
        except (IOError, OSError):
            # File read error
            pass
        
        return hashes
    
    def _generate_purl(self, file_path: pathlib.Path, formats: List[str]) -> Optional[str]:
        """Generate Package URL (PURL) for the component"""
        
        # Try to infer PURL from file characteristics
        name = file_path.stem
        
        # Hugging Face models
        if "transformers" in str(file_path).lower() or "huggingface" in str(file_path).lower():
            return f"pkg:huggingface/{name}"
        
        # PyTorch Hub models
        if "pytorch" in formats and "hub" in str(file_path).lower():
            return f"pkg:pytorch/{name}"
        
        # TensorFlow Hub models
        if ("tensorflow" in formats or "keras" in formats) and "hub" in str(file_path).lower():
            return f"pkg:tensorflow/{name}"
        
        # Generic ML model
        if formats:
            primary_format = formats[0]
            return f"pkg:ml/{primary_format}/{name}"
        
        return None
    
    def _generate_external_references(self, file_path: pathlib.Path, 
                                    result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate external references for the component"""
        refs = []
        
        # Try to detect common model sources
        path_str = str(file_path).lower()
        
        if "huggingface" in path_str:
            refs.append({
                "type": "distribution",
                "url": f"https://huggingface.co/models?search={file_path.stem}"
            })
        
        if "pytorch" in path_str and "hub" in path_str:
            refs.append({
                "type": "distribution",
                "url": f"https://pytorch.org/hub/"
            })
        
        # Add documentation links based on format
        formats = result.get("formats", [])
        if "onnx" in formats:
            refs.append({
                "type": "documentation",
                "url": "https://onnx.ai/"
            })
        
        if "safetensors" in formats:
            refs.append({
                "type": "documentation", 
                "url": "https://huggingface.co/docs/safetensors/"
            })
        
        return refs
    
    def _detect_licenses(self, result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Detect licensing information from scan results"""
        # This is a simplified implementation
        # In practice, you might scan for license files or headers
        
        licenses = []
        
        # Default assumption for common ML frameworks
        formats = result.get("formats", [])
        
        if "huggingface" in str(result["file"]).lower():
            # Many HF models use Apache 2.0
            licenses.append({
                "license": {
                    "id": "Apache-2.0",
                    "name": "Apache License 2.0"
                }
            })
        
        return licenses
    
    def _estimate_cvss_score(self, severity: str) -> Optional[float]:
        """Estimate CVSS score based on severity"""
        score_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0
        }
        
        return score_map.get(severity.upper())
    
    def create_attestation(self, sbom_path: str, private_key_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a cryptographic attestation for the SBOM
        
        Args:
            sbom_path: Path to the SBOM file
            private_key_path: Optional path to private key for signing
        
        Returns:
            Attestation dictionary
        """
        
        # Calculate SBOM hash
        with open(sbom_path, 'rb') as f:
            sbom_content = f.read()
        
        sbom_hash = hashlib.sha256(sbom_content).hexdigest()
        
        attestation = {
            "statement": {
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": [
                    {
                        "name": pathlib.Path(sbom_path).name,
                        "digest": {
                            "sha256": sbom_hash
                        }
                    }
                ],
                "predicateType": "https://cyclonedx.org/attestation/v1",
                "predicate": {
                    "tool": {
                        "name": self.tool_name,
                        "version": self.tool_version
                    },
                    "timestamp": self.timestamp,
                    "analysis": {
                        "static": True,
                        "dynamic": False
                    }
                }
            }
        }
        
        # If private key provided, add signature (simplified)
        if private_key_path:
            # In a real implementation, you would use actual cryptographic signing
            attestation["signature"] = {
                "keyid": "smart-ai-scanner-key",
                "signature": f"mock-signature-{hashlib.sha256(json.dumps(attestation['statement']).encode()).hexdigest()[:16]}"
            }
        
        return attestation