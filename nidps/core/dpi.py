import re
import hashlib
import json
import logging
import threading
import time
import os
import math
from collections import defaultdict, deque
from scapy.all import Raw, TCP, UDP, IP
import struct

class DeepPacketInspector:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.signatures = self.load_signatures()
        self.payload_cache = {}
        self.inspection_stats = defaultdict(int)
        self.dpi_active = False
        
    def load_signatures(self):
        """Load DPI signatures"""
        default_signatures = {
            "http_patterns": [
                r"GET\s+/(.*?)\s+HTTP",
                r"POST\s+/(.*?)\s+HTTP",
                r"Host:\s+(.*?)\r\n",
                r"User-Agent:\s+(.*?)\r\n"
            ],
            "malware_patterns": [
                r"cmd\.exe.*\/c",
                r"powershell.*-enc",
                r"eval\(",
                r"base64_decode",
                r"shell_exec",
                r"system\(",
                r"exec\(",
                r"wget\s+http",
                r"curl\s+http",
                r"nc\s+-l",
                r"netcat.*-l"
            ],
            "suspicious_strings": [
                "password",
                "admin",
                "root",
                "shell",
                "exploit",
                "vulnerability",
                "backdoor",
                "trojan",
                "virus",
                "malware"
            ],
            "file_signatures": {
                "exe": b"MZ",
                "pdf": b"%PDF",
                "zip": b"PK",
                "rar": b"Rar!",
                "gzip": b"\x1f\x8b",
                "tar": b"ustar"
            }
        }
        
        try:
            if os.path.exists("dpi_signatures.json"):
                with open("dpi_signatures.json", 'r') as f:
                    signatures = json.load(f)
                    return {**default_signatures, **signatures}
        except Exception as e:
            self.logger.error(f"Error loading DPI signatures: {e}")
        
        return default_signatures
    
    def inspect_packet(self, packet):
        """Perform deep packet inspection"""
        inspection_result = {
            'protocol': 'unknown',
            'application': 'unknown',
            'threats': [],
            'signatures': [],
            'risk_score': 0,
            'payload_analysis': {}
        }
        
        try:
            # Determine protocol
            if packet.haslayer(TCP):
                inspection_result['protocol'] = 'TCP'
                inspection_result.update(self._inspect_tcp_packet(packet))
            elif packet.haslayer(UDP):
                inspection_result['protocol'] = 'UDP'
                inspection_result.update(self._inspect_udp_packet(packet))
            elif packet.haslayer(IP):
                inspection_result['protocol'] = 'IP'
                inspection_result.update(self._inspect_ip_packet(packet))
            
            # Analyze payload
            if packet.haslayer(Raw):
                payload_analysis = self._analyze_payload(packet[Raw].load)
                inspection_result['payload_analysis'] = payload_analysis
                inspection_result['threats'].extend(payload_analysis.get('threats', []))
                inspection_result['signatures'].extend(payload_analysis.get('signatures', []))
            
            # Calculate risk score
            inspection_result['risk_score'] = self._calculate_dpi_risk_score(inspection_result)
            
            # Update statistics
            self.inspection_stats['packets_inspected'] += 1
            if inspection_result['threats']:
                self.inspection_stats['threats_detected'] += 1
            
        except Exception as e:
            self.logger.error(f"Error in packet inspection: {e}")
        
        return inspection_result
    
    def _inspect_tcp_packet(self, packet):
        """Inspect TCP packet"""
        result = {}
        tcp_layer = packet[TCP]
        
        # Determine application based on port
        if tcp_layer.dport == 80 or tcp_layer.dport == 8080:
            result['application'] = 'HTTP'
        elif tcp_layer.dport == 443:
            result['application'] = 'HTTPS'
        elif tcp_layer.dport == 22:
            result['application'] = 'SSH'
        elif tcp_layer.dport == 21:
            result['application'] = 'FTP'
        elif tcp_layer.dport == 25:
            result['application'] = 'SMTP'
        elif tcp_layer.dport == 53:
            result['application'] = 'DNS'
        else:
            result['application'] = f'Unknown TCP Port {tcp_layer.dport}'
        
        # Check for suspicious flags
        flags = str(tcp_layer.flags)
        if 'S' in flags and 'A' not in flags:
            result['signatures'].append('SYN packet (potential scan)')
        
        return result
    
    def _inspect_udp_packet(self, packet):
        """Inspect UDP packet"""
        result = {}
        udp_layer = packet[UDP]
        
        # Determine application based on port
        if udp_layer.dport == 53:
            result['application'] = 'DNS'
        elif udp_layer.dport == 67 or udp_layer.dport == 68:
            result['application'] = 'DHCP'
        elif udp_layer.dport == 123:
            result['application'] = 'NTP'
        else:
            result['application'] = f'Unknown UDP Port {udp_layer.dport}'
        
        return result
    
    def _inspect_ip_packet(self, packet):
        """Inspect IP packet"""
        result = {}
        ip_layer = packet[IP]
        
        # Check for fragmentation
        if ip_layer.frag != 0:
            result['signatures'].append('Fragmented IP packet')
        
        # Check TTL for potential OS fingerprinting
        if ip_layer.ttl <= 32:
            result['signatures'].append('Low TTL (potential scan)')
        
        return result
    
    def _analyze_payload(self, payload):
        """Analyze packet payload"""
        analysis = {
            'threats': [],
            'signatures': [],
            'file_type': None,
            'content_type': 'unknown'
        }
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            # Check for file signatures
            for file_type, signature in self.signatures['file_signatures'].items():
                if payload.startswith(signature):
                    analysis['file_type'] = file_type
                    analysis['signatures'].append(f'File signature: {file_type}')
                    break
            
            # Check for HTTP patterns
            for pattern in self.signatures['http_patterns']:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    analysis['content_type'] = 'HTTP'
                    analysis['signatures'].append(f'HTTP pattern: {pattern}')
                    break
            
            # Check for malware patterns
            for pattern in self.signatures['malware_patterns']:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    analysis['threats'].append({
                        'type': 'malware_pattern',
                        'pattern': pattern,
                        'severity': 'high'
                    })
            
            # Check for suspicious strings
            for suspicious_str in self.signatures['suspicious_strings']:
                if suspicious_str in payload_str:
                    analysis['threats'].append({
                        'type': 'suspicious_string',
                        'string': suspicious_str,
                        'severity': 'medium'
                    })
            
            # Check for encoded content
            if self._detect_encoding(payload_str):
                analysis['signatures'].append('Encoded content detected')
            
            # Check for binary data
            if self._is_binary_data(payload):
                analysis['content_type'] = 'binary'
                analysis['signatures'].append('Binary data detected')
            
            # Calculate payload entropy
            entropy = self._calculate_entropy(payload)
            if entropy > 7.5:  # High entropy might indicate encryption/encoding
                analysis['signatures'].append(f'High entropy: {entropy:.2f}')
            
        except Exception as e:
            self.logger.error(f"Error analyzing payload: {e}")
        
        return analysis
    
    def _detect_encoding(self, payload_str):
        """Detect encoded content"""
        # Check for base64
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', payload_str):
            return True
        
        # Check for hex encoding
        if re.search(r'[0-9a-fA-F]{20,}', payload_str):
            return True
        
        # Check for URL encoding
        if '%' in payload_str and len([c for c in payload_str if c == '%']) > 5:
            return True
        
        return False
    
    def _is_binary_data(self, payload):
        """Check if payload contains binary data"""
        try:
            # Check for null bytes
            if b'\x00' in payload:
                return True
            
            # Check for non-printable characters
            printable_ratio = sum(1 for b in payload if 32 <= b <= 126) / len(payload)
            return printable_ratio < 0.8
            
        except:
            return False
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0
            
            # Count byte frequencies
            byte_counts = defaultdict(int)
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except:
            return 0
    
    def _calculate_dpi_risk_score(self, inspection_result):
        """Calculate risk score based on DPI results"""
        risk_score = 0
        
        # Base risk
        risk_score += 10
        
        # Add threat risk
        for threat in inspection_result['threats']:
            if threat['severity'] == 'high':
                risk_score += 40
            elif threat['severity'] == 'medium':
                risk_score += 25
            else:
                risk_score += 10
        
        # Add signature risk
        for signature in inspection_result['signatures']:
            if 'malware' in signature.lower() or 'threat' in signature.lower():
                risk_score += 20
            elif 'scan' in signature.lower() or 'suspicious' in signature.lower():
                risk_score += 15
            else:
                risk_score += 5
        
        # Add application risk
        app = inspection_result.get('application', '').lower()
        high_risk_apps = ['ssh', 'ftp', 'telnet']
        if any(risk_app in app for risk_app in high_risk_apps):
            risk_score += 15
        
        return min(risk_score, 100)  # Cap at 100
    
    def get_inspection_stats(self):
        """Get DPI statistics"""
        return dict(self.inspection_stats)
    
    def update_signatures(self, new_signatures):
        """Update DPI signatures"""
        self.signatures.update(new_signatures)
        try:
            with open("dpi_signatures.json", 'w') as f:
                json.dump(self.signatures, f, indent=4)
            self.logger.info("DPI signatures updated")
        except Exception as e:
            self.logger.error(f"Failed to save DPI signatures: {e}")

if __name__ == "__main__":
    # Test DPI system
    from scapy.all import IP, TCP, Raw
    
    dpi = DeepPacketInspector()
    
    # Create test packet
    test_payload = b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
    test_packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(load=test_payload)
    
    result = dpi.inspect_packet(test_packet)
    print("DPI Result:", result) 