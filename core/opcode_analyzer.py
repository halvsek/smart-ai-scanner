#!/usr/bin/env python3
"""
Advanced Opcode and Low-Level Binary Analysis Engine
Provides deep technical analysis of model files including opcode inspection,
memory layout analysis, and security vulnerability mapping.
"""

import os
import struct
import binascii
import hashlib
import pickle
import pickletools
import io
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    from hexdump import hexdump
    HAS_HEXDUMP = True
except ImportError:
    HAS_HEXDUMP = False

@dataclass
class OpcodeAnalysis:
    """Container for opcode analysis results"""
    opcode: str
    position: int
    instruction: str
    risk_level: str
    description: str
    memory_impact: Optional[int] = None
    security_implications: Optional[str] = None
    vulnerable_patterns: Optional[List[str]] = None

@dataclass
class MemoryLayout:
    """Memory layout analysis results"""
    segments: List[Dict[str, Any]]
    total_size: int
    suspicious_regions: List[Dict[str, Any]]
    entropy_map: Dict[str, float]

@dataclass
class SecurityMapping:
    """Security vulnerability mapping"""
    cve_mappings: List[str]
    attack_vectors: List[str]
    exploit_primitives: List[str]
    mitigation_strategies: List[str]

class AdvancedOpcodeAnalyzer:
    """
    Advanced opcode and binary analysis engine for ML models
    
    Performs deep technical analysis including:
    - Opcode-level inspection of serialized models
    - Memory layout analysis and vulnerability mapping
    - Binary structure analysis with entropy detection
    - Security primitive identification and risk assessment
    """
    
    # Dangerous pickle opcodes with detailed analysis
    DANGEROUS_OPCODES = {
        'GLOBAL': {
            'risk': 'CRITICAL',
            'description': 'Global object resolution - can import arbitrary modules',
            'patterns': ['__builtin__', 'builtins', 'os', 'subprocess', 'eval', 'exec'],
            'memory_impact': 'HIGH',
            'exploit_potential': 'Code execution via module import'
        },
        'REDUCE': {
            'risk': 'CRITICAL', 
            'description': 'Function call reduction - executes arbitrary callables',
            'patterns': ['system', 'popen', 'eval', 'exec', '__import__'],
            'memory_impact': 'MEDIUM',
            'exploit_potential': 'Direct function execution'
        },
        'BUILD': {
            'risk': 'HIGH',
            'description': 'Object construction - can instantiate dangerous classes',
            'patterns': ['socket', 'file', 'open', 'subprocess'],
            'memory_impact': 'MEDIUM',
            'exploit_potential': 'Object instantiation attacks'
        },
        'INST': {
            'risk': 'HIGH',
            'description': 'Instance creation - legacy dangerous constructor',
            'patterns': ['__builtin__', 'types', 'file'],
            'memory_impact': 'HIGH',
            'exploit_potential': 'Legacy constructor exploitation'
        },
        'OBJ': {
            'risk': 'MEDIUM',
            'description': 'Object creation from class and arguments',
            'patterns': ['socket', 'file', 'subprocess.Popen'],
            'memory_impact': 'MEDIUM',
            'exploit_potential': 'Controlled object construction'
        },
        'SETITEM': {
            'risk': 'LOW',
            'description': 'Dictionary/list item assignment',
            'patterns': ['__dict__', '__globals__'],
            'memory_impact': 'LOW',
            'exploit_potential': 'Namespace pollution'
        },
        'SETATTR': {
            'risk': 'MEDIUM',
            'description': 'Object attribute assignment',
            'patterns': ['__class__', '__dict__', '__module__'],
            'memory_impact': 'LOW',
            'exploit_potential': 'Object state manipulation'
        }
    }
    
    # Binary signatures for various model formats
    BINARY_SIGNATURES = {
        b'\x80\x02': 'Pickle Protocol 2',
        b'\x80\x03': 'Pickle Protocol 3', 
        b'\x80\x04': 'Pickle Protocol 4',
        b'\x80\x05': 'Pickle Protocol 5',
        b'\x89HDF\r\n\x1a\n': 'HDF5 Format',
        b'ONNX': 'ONNX Model',
        b'GGUF': 'GGUF Format',
        b'GGML': 'GGML Format',
        b'PK\x03\x04': 'ZIP Archive',
        b'\x08\x01\x12': 'Protocol Buffer'
    }
    
    def __init__(self):
        self.analysis_results = []
        self.memory_layout = None
        self.security_mapping = None
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive low-level analysis of a model file
        
        Returns detailed technical analysis including:
        - Opcode-level inspection
        - Memory layout analysis  
        - Security vulnerability mapping
        - Binary structure analysis
        """
        results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'format_detection': self._detect_format(file_path),
            'opcode_analysis': [],
            'memory_analysis': {},
            'security_mapping': {},
            'binary_analysis': {},
            'vulnerability_details': []
        }
        
        try:
            # Perform format-specific analysis
            file_format = results['format_detection']['primary_format']
            
            if file_format == 'pickle':
                results.update(self._analyze_pickle_opcodes(file_path))
            elif file_format == 'hdf5':
                results.update(self._analyze_hdf5_structure(file_path))
            elif file_format == 'onnx':
                results.update(self._analyze_protobuf_opcodes(file_path))
            
            # Universal binary analysis
            results['binary_analysis'] = self._analyze_binary_structure(file_path)
            results['memory_analysis'] = self._analyze_memory_layout(file_path)
            results['security_mapping'] = self._map_security_vulnerabilities(results)
            
        except Exception as e:
            results['analysis_error'] = str(e)
            
        return results
    
    def _detect_format(self, file_path: str) -> Dict[str, Any]:
        """Advanced format detection with confidence scoring"""
        with open(file_path, 'rb') as f:
            header = f.read(32)
        
        detection_results = {
            'primary_format': 'unknown',
            'confidence': 0.0,
            'signatures_found': [],
            'format_analysis': {}
        }
        
        # Check known signatures
        for signature, format_name in self.BINARY_SIGNATURES.items():
            if header.startswith(signature):
                detection_results['primary_format'] = format_name.lower().split()[0]
                detection_results['confidence'] = 0.95
                detection_results['signatures_found'].append({
                    'signature': signature.hex(),
                    'format': format_name,
                    'position': 0
                })
                break
        
        # Additional heuristic analysis
        if detection_results['primary_format'] == 'unknown':
            detection_results.update(self._heuristic_format_detection(file_path))
        
        return detection_results
    
    def _analyze_pickle_opcodes(self, file_path: str) -> Dict[str, Any]:
        """Deep opcode-level analysis of pickle files"""
        results = {
            'opcode_analysis': [],
            'pickle_details': {},
            'vulnerability_details': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Use pickletools for detailed opcode analysis
            opcodes_stream = io.StringIO()
            pickletools.dis(content, opcodes_stream)
            opcodes_output = opcodes_stream.getvalue()
            
            # Parse opcodes line by line for detailed analysis
            opcode_lines = opcodes_output.split('\n')
            position = 0
            
            for line in opcode_lines:
                if not line.strip():
                    continue
                    
                analysis = self._parse_opcode_line(line, position, content)
                if analysis:
                    results['opcode_analysis'].append(analysis.__dict__)
                    
                    # Check for vulnerabilities
                    if analysis.risk_level in ['CRITICAL', 'HIGH']:
                        vuln_detail = self._create_vulnerability_detail(analysis, content, position)
                        results['vulnerability_details'].append(vuln_detail)
                
                position += 1
            
            # Pickle-specific metadata
            results['pickle_details'] = self._extract_pickle_metadata(content)
            
        except Exception as e:
            results['analysis_error'] = f"Pickle analysis failed: {str(e)}"
        
        return results
    
    def _parse_opcode_line(self, line: str, position: int, content: bytes) -> Optional[OpcodeAnalysis]:
        """Parse individual opcode line for detailed analysis"""
        parts = line.strip().split()
        if not parts:
            return None
        
        # Extract opcode name (usually the first meaningful part)
        opcode_name = None
        for part in parts:
            if part.upper() in self.DANGEROUS_OPCODES:
                opcode_name = part.upper()
                break
            # Check partial matches for complex opcodes
            for dangerous_op in self.DANGEROUS_OPCODES:
                if dangerous_op in part.upper():
                    opcode_name = dangerous_op
                    break
        
        if not opcode_name:
            return None
        
        opcode_info = self.DANGEROUS_OPCODES[opcode_name]
        
        # Extract instruction details
        instruction = ' '.join(parts[1:]) if len(parts) > 1 else opcode_name
        
        # Look for vulnerable patterns in the instruction
        vulnerable_patterns = []
        for pattern in opcode_info['patterns']:
            if pattern.lower() in instruction.lower():
                vulnerable_patterns.append(pattern)
        
        return OpcodeAnalysis(
            opcode=opcode_name,
            position=position,
            instruction=instruction,
            risk_level=opcode_info['risk'],
            description=opcode_info['description'],
            memory_impact=self._estimate_memory_impact(instruction),
            security_implications=opcode_info['exploit_potential'],
            vulnerable_patterns=vulnerable_patterns
        )
    
    def _create_vulnerability_detail(self, analysis: OpcodeAnalysis, content: bytes, position: int) -> Dict[str, Any]:
        """Create detailed vulnerability mapping for an opcode"""
        return {
            'vulnerability_id': f"PICKLE_OPCODE_{analysis.opcode}_{position}",
            'severity': analysis.risk_level,
            'title': f"Dangerous {analysis.opcode} opcode detected",
            'description': analysis.description,
            'technical_details': {
                'opcode': analysis.opcode,
                'position': analysis.position,
                'instruction': analysis.instruction,
                'memory_impact': analysis.memory_impact,
                'patterns_detected': analysis.vulnerable_patterns
            },
            'exploit_scenario': self._generate_exploit_scenario(analysis),
            'mitigation': self._suggest_mitigation(analysis),
            'cwe_mapping': self._map_to_cwe(analysis),
            'binary_context': self._extract_binary_context(content, position)
        }
    
    def _analyze_binary_structure(self, file_path: str) -> Dict[str, Any]:
        """Analyze binary file structure and entropy"""
        results = {
            'file_size': os.path.getsize(file_path),
            'entropy_analysis': {},
            'suspicious_regions': [],
            'binary_patterns': [],
            'hex_dump_sample': ""
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Entropy analysis in chunks
            chunk_size = 1024
            entropy_map = {}
            
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i + chunk_size]
                entropy = self._calculate_entropy(chunk)
                entropy_map[f"offset_{i:08x}"] = entropy
                
                # Flag suspicious high-entropy regions
                if entropy > 7.5:  # Very high entropy suggests encryption/compression
                    results['suspicious_regions'].append({
                        'offset': i,
                        'size': len(chunk),
                        'entropy': entropy,
                        'reason': 'High entropy - possible encrypted/compressed data'
                    })
            
            results['entropy_analysis'] = entropy_map
            
            # Generate hex dump sample
            if HAS_HEXDUMP:
                hex_sample = hexdump(content[:256], result='return')
                results['hex_dump_sample'] = hex_sample
            else:
                # Fallback hex representation
                results['hex_dump_sample'] = binascii.hexlify(content[:128]).decode()
            
            # Look for binary patterns
            results['binary_patterns'] = self._find_binary_patterns(content)
            
        except Exception as e:
            results['analysis_error'] = f"Binary analysis failed: {str(e)}"
        
        return results
    
    def _analyze_memory_layout(self, file_path: str) -> Dict[str, Any]:
        """Analyze memory layout and potential overflow conditions"""
        results = {
            'segments': [],
            'total_size': 0,
            'alignment_analysis': {},
            'overflow_risks': []
        }
        
        try:
            file_size = os.path.getsize(file_path)
            results['total_size'] = file_size
            
            # Memory alignment analysis
            alignment_check = {
                '4_byte_aligned': file_size % 4 == 0,
                '8_byte_aligned': file_size % 8 == 0,
                '16_byte_aligned': file_size % 16 == 0,
                'page_aligned': file_size % 4096 == 0
            }
            results['alignment_analysis'] = alignment_check
            
            # Check for potential overflow conditions
            if file_size > 100 * 1024 * 1024:  # 100MB
                results['overflow_risks'].append({
                    'type': 'Large file size',
                    'risk': 'Memory exhaustion during loading',
                    'size': file_size,
                    'recommendation': 'Implement streaming or chunked loading'
                })
            
            # Analyze internal structure for memory segments
            with open(file_path, 'rb') as f:
                # Read in segments to understand memory layout
                segment_size = 64 * 1024  # 64KB segments
                segment_id = 0
                
                while True:
                    segment_data = f.read(segment_size)
                    if not segment_data:
                        break
                    
                    segment_info = {
                        'segment_id': segment_id,
                        'offset': segment_id * segment_size,
                        'size': len(segment_data),
                        'entropy': self._calculate_entropy(segment_data),
                        'null_bytes': segment_data.count(b'\x00'),
                        'printable_ratio': self._calculate_printable_ratio(segment_data)
                    }
                    
                    results['segments'].append(segment_info)
                    segment_id += 1
                    
                    if segment_id > 100:  # Limit analysis for very large files
                        break
            
        except Exception as e:
            results['analysis_error'] = f"Memory analysis failed: {str(e)}"
        
        return results
    
    def _map_security_vulnerabilities(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Map discovered issues to known security vulnerabilities"""
        mapping = {
            'cve_mappings': [],
            'attack_vectors': [],
            'exploit_primitives': [],
            'risk_assessment': {},
            'mitigation_strategies': []
        }
        
        # Map opcodes to CVEs
        for opcode_result in analysis_results.get('opcode_analysis', []):
            opcode = opcode_result.get('opcode', '')
            
            if opcode == 'GLOBAL':
                mapping['cve_mappings'].append('CVE-2019-16935')
                mapping['attack_vectors'].append('Arbitrary module import via GLOBAL opcode')
                mapping['exploit_primitives'].append('Code execution through __import__')
            
            elif opcode == 'REDUCE':
                mapping['cve_mappings'].append('CVE-2022-42969')
                mapping['attack_vectors'].append('Function call injection via REDUCE opcode')
                mapping['exploit_primitives'].append('Direct callable execution')
        
        # Risk assessment based on findings
        critical_count = sum(1 for r in analysis_results.get('vulnerability_details', []) 
                           if r.get('severity') == 'CRITICAL')
        high_count = sum(1 for r in analysis_results.get('vulnerability_details', []) 
                        if r.get('severity') == 'HIGH')
        
        mapping['risk_assessment'] = {
            'overall_risk': 'CRITICAL' if critical_count > 0 else 'HIGH' if high_count > 0 else 'MEDIUM',
            'critical_issues': critical_count,
            'high_issues': high_count,
            'exploitability': 'HIGH' if critical_count > 0 else 'MEDIUM'
        }
        
        # Mitigation strategies
        if critical_count > 0:
            mapping['mitigation_strategies'].extend([
                'Implement strict pickle protocol allowlisting',
                'Use SafeTensors or ONNX format instead of pickle',
                'Run models in sandboxed environments',
                'Implement runtime opcode filtering'
            ])
        
        return mapping
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters in binary data"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)
    
    def _estimate_memory_impact(self, instruction: str) -> int:
        """Estimate memory impact of an instruction"""
        # Simple heuristic based on instruction content
        if any(keyword in instruction.lower() for keyword in ['list', 'dict', 'array']):
            return 1024  # Moderate impact
        elif any(keyword in instruction.lower() for keyword in ['file', 'socket', 'subprocess']):
            return 4096  # High impact
        else:
            return 256   # Low impact
    
    def _generate_exploit_scenario(self, analysis: OpcodeAnalysis) -> str:
        """Generate realistic exploit scenario for an opcode"""
        scenarios = {
            'GLOBAL': f"Attacker can import arbitrary modules like 'os' or 'subprocess' and execute system commands",
            'REDUCE': f"Attacker can call arbitrary functions with controlled arguments, leading to code execution",
            'BUILD': f"Attacker can instantiate dangerous classes with controlled parameters",
            'INST': f"Legacy constructor allows bypassing modern security restrictions"
        }
        
        return scenarios.get(analysis.opcode, f"Opcode {analysis.opcode} allows unauthorized operations")
    
    def _suggest_mitigation(self, analysis: OpcodeAnalysis) -> List[str]:
        """Suggest specific mitigation strategies"""
        mitigations = {
            'GLOBAL': [
                "Implement module allowlisting",
                "Use RestrictedUnpickler with safe_globals",
                "Convert to SafeTensors format"
            ],
            'REDUCE': [
                "Filter dangerous callables",
                "Implement function allowlisting", 
                "Use sandboxed execution environment"
            ],
            'BUILD': [
                "Restrict dangerous class instantiation",
                "Implement type checking",
                "Use alternative serialization format"
            ]
        }
        
        return mitigations.get(analysis.opcode, ["Use alternative secure format", "Implement sandboxing"])
    
    def _map_to_cwe(self, analysis: OpcodeAnalysis) -> str:
        """Map opcode vulnerability to CWE"""
        cwe_mappings = {
            'GLOBAL': 'CWE-94: Improper Control of Generation of Code',
            'REDUCE': 'CWE-94: Improper Control of Generation of Code', 
            'BUILD': 'CWE-502: Deserialization of Untrusted Data',
            'INST': 'CWE-502: Deserialization of Untrusted Data'
        }
        
        return cwe_mappings.get(analysis.opcode, 'CWE-502: Deserialization of Untrusted Data')
    
    def _extract_binary_context(self, content: bytes, position: int) -> Dict[str, str]:
        """Extract binary context around a position"""
        start = max(0, position - 32)
        end = min(len(content), position + 32)
        context = content[start:end]
        
        return {
            'hex_context': binascii.hexlify(context).decode(),
            'ascii_context': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in context),
            'position': position,
            'context_start': start,
            'context_end': end
        }
    
    def _find_binary_patterns(self, content: bytes) -> List[Dict[str, Any]]:
        """Find interesting binary patterns"""
        patterns = []
        
        # Look for repeated sequences
        for i in range(len(content) - 8):
            sequence = content[i:i+8]
            if sequence.count(sequence[0]) == 8:  # All same byte
                patterns.append({
                    'type': 'repeated_byte',
                    'pattern': sequence.hex(),
                    'position': i,
                    'description': f"8 bytes of 0x{sequence[0]:02x}"
                })
        
        # Look for potential strings
        for i in range(len(content) - 4):
            if all(32 <= b <= 126 for b in content[i:i+4]):
                text = content[i:i+4].decode('ascii', errors='ignore')
                if len(text) >= 4:
                    patterns.append({
                        'type': 'ascii_string',
                        'pattern': text,
                        'position': i,
                        'description': f"ASCII string: {text}"
                    })
        
        return patterns[:20]  # Limit to first 20 patterns
    
    def _heuristic_format_detection(self, file_path: str) -> Dict[str, Any]:
        """Fallback heuristic format detection"""
        with open(file_path, 'rb') as f:
            content = f.read(1024)  # Read first 1KB
        
        # Simple heuristics
        if b'torch' in content.lower():
            return {'primary_format': 'pytorch', 'confidence': 0.7}
        elif b'tensorflow' in content.lower():
            return {'primary_format': 'tensorflow', 'confidence': 0.7}
        elif content.startswith(b'\x00\x00'):
            return {'primary_format': 'binary', 'confidence': 0.5}
        else:
            return {'primary_format': 'unknown', 'confidence': 0.0}
    
    def _extract_pickle_metadata(self, content: bytes) -> Dict[str, Any]:
        """Extract pickle-specific metadata"""
        metadata = {
            'protocol_version': None,
            'estimated_objects': 0,
            'dangerous_modules': [],
            'size_bytes': len(content)
        }
        
        # Detect protocol version
        if content.startswith(b'\x80'):
            metadata['protocol_version'] = content[1] if len(content) > 1 else 'unknown'
        
        # Count potential objects (rough estimate)
        metadata['estimated_objects'] = content.count(b'q\x00') + content.count(b'q\x01')
        
        # Look for dangerous module names
        dangerous_modules = [b'os', b'subprocess', b'eval', b'exec', b'__builtin__', b'builtins']
        for module in dangerous_modules:
            if module in content:
                metadata['dangerous_modules'].append(module.decode())
        
        return metadata
    
    def _analyze_hdf5_structure(self, file_path: str) -> Dict[str, Any]:
        """Analyze HDF5 file structure (placeholder)"""
        return {
            'hdf5_analysis': 'HDF5 analysis not yet implemented',
            'format_specific': 'hdf5'
        }
    
    def _analyze_protobuf_opcodes(self, file_path: str) -> Dict[str, Any]:
        """Analyze Protocol Buffer structure (placeholder)"""
        return {
            'protobuf_analysis': 'Protocol Buffer analysis not yet implemented', 
            'format_specific': 'protobuf'
        }