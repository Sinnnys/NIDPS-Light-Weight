import numpy as np
import pandas as pd
import json
import logging
import threading
import time
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import re

class AdvancedAnalytics:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.traffic_data = defaultdict(lambda: deque(maxlen=10000))
        self.threat_signatures = self.load_threat_signatures()
        self.anomaly_detectors = {}
        self.analytics_thread = None
        self.analytics_active = False
        self.traffic_patterns = defaultdict(int)
        self.ip_reputation = {}
        self.geo_data = {}
        
    def load_threat_signatures(self):
        """Load threat signatures from file"""
        default_signatures = {
            "malware_patterns": [
                r"cmd\.exe.*\/c",
                r"powershell.*-enc",
                r"eval\(",
                r"base64_decode",
                r"shell_exec",
                r"system\(",
                r"exec\("
            ],
            "suspicious_ips": [
                "185.220.101.0/24",  # Example suspicious range
                "45.95.147.0/24"
            ],
            "suspicious_domains": [
                "malware.example.com",
                "suspicious.domain.com"
            ],
            "port_scan_patterns": [
                {"ports": range(1, 1025), "time_window": 60, "threshold": 100},
                {"ports": range(1025, 65536), "time_window": 300, "threshold": 50}
            ]
        }
        
        try:
            if os.path.exists("threat_signatures.json"):
                with open("threat_signatures.json", 'r') as f:
                    signatures = json.load(f)
                    return {**default_signatures, **signatures}
        except Exception as e:
            self.logger.error(f"Error loading threat signatures: {e}")
        
        return default_signatures
    
    def start_analytics(self):
        """Start the analytics processing"""
        if self.analytics_active:
            return
        
        self.analytics_active = True
        self.analytics_thread = threading.Thread(target=self._analytics_loop, daemon=True)
        self.analytics_thread.start()
        self.logger.info("Advanced analytics started")
    
    def stop_analytics(self):
        """Stop the analytics processing"""
        self.analytics_active = False
        if self.analytics_thread:
            self.analytics_thread.join(timeout=5)
        self.logger.info("Advanced analytics stopped")
    
    def _analytics_loop(self):
        """Main analytics processing loop"""
        while self.analytics_active:
            try:
                self._analyze_traffic_patterns()
                self._detect_anomalies()
                self._update_threat_intelligence()
                time.sleep(60)  # Run analysis every minute
            except Exception as e:
                self.logger.error(f"Error in analytics loop: {e}")
                time.sleep(10)
    
    def process_packet(self, packet_data):
        """Process a packet for analytics"""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet_data)
            
            # Store in traffic data
            self.traffic_data['packets'].append(packet_info)
            
            # Update traffic patterns
            self._update_traffic_patterns(packet_info)
            
            # Check for threat signatures
            threats = self._check_threat_signatures(packet_info)
            
            # Perform anomaly detection
            anomalies = self._detect_packet_anomalies(packet_info)
            
            return {
                'threats': threats,
                'anomalies': anomalies,
                'risk_score': self._calculate_risk_score(packet_info, threats, anomalies)
            }
            
        except Exception as e:
            self.logger.error(f"Error processing packet for analytics: {e}")
            return {'threats': [], 'anomalies': [], 'risk_score': 0}
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        info = {
            'timestamp': datetime.now(),
            'source_ip': 'Unknown',
            'dest_ip': 'Unknown',
            'source_port': 0,
            'dest_port': 0,
            'protocol': 'Unknown',
            'packet_size': len(packet),
            'payload_hash': None,
            'flags': None
        }
        
        try:
            if packet.haslayer('IP'):
                info['source_ip'] = packet['IP'].src
                info['dest_ip'] = packet['IP'].dst
            
            if packet.haslayer('TCP'):
                info['protocol'] = 'TCP'
                info['source_port'] = packet['TCP'].sport
                info['dest_port'] = packet['TCP'].dport
                info['flags'] = str(packet['TCP'].flags)
            elif packet.haslayer('UDP'):
                info['protocol'] = 'UDP'
                info['source_port'] = packet['UDP'].sport
                info['dest_port'] = packet['UDP'].dport
            elif packet.haslayer('ICMP'):
                info['protocol'] = 'ICMP'
            
            # Extract payload for analysis
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                info['payload_hash'] = hashlib.md5(payload).hexdigest()
                info['payload_text'] = payload.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
        
        return info
    
    def _update_traffic_patterns(self, packet_info):
        """Update traffic pattern statistics"""
        # Update protocol distribution
        self.traffic_patterns[f"protocol_{packet_info['protocol']}"] += 1
        
        # Update port patterns
        if packet_info['dest_port'] > 0:
            self.traffic_patterns[f"port_{packet_info['dest_port']}"] += 1
        
        # Update IP patterns
        self.traffic_patterns[f"src_ip_{packet_info['source_ip']}"] += 1
        self.traffic_patterns[f"dst_ip_{packet_info['dest_ip']}"] += 1
        
        # Update packet size patterns
        size_range = (packet_info['packet_size'] // 100) * 100
        self.traffic_patterns[f"size_{size_range}"] += 1
    
    def _check_threat_signatures(self, packet_info):
        """Check packet against threat signatures"""
        threats = []
        
        try:
            # Check payload for malware patterns
            if 'payload_text' in packet_info:
                payload = packet_info['payload_text'].lower()
                for pattern in self.threat_signatures['malware_patterns']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        threats.append({
                            'type': 'malware_pattern',
                            'pattern': pattern,
                            'severity': 'high'
                        })
            
            # Check for suspicious IPs
            src_ip = packet_info['source_ip']
            for ip_range in self.threat_signatures['suspicious_ips']:
                if self._ip_in_range(src_ip, ip_range):
                    threats.append({
                        'type': 'suspicious_ip',
                        'ip': src_ip,
                        'range': ip_range,
                        'severity': 'medium'
                    })
            
            # Check for port scanning
            if self._detect_port_scan(packet_info):
                threats.append({
                    'type': 'port_scan',
                    'source_ip': src_ip,
                    'severity': 'medium'
                })
            
        except Exception as e:
            self.logger.error(f"Error checking threat signatures: {e}")
        
        return threats
    
    def _detect_port_scan(self, packet_info):
        """Detect port scanning activity"""
        src_ip = packet_info['source_ip']
        dest_port = packet_info['dest_port']
        
        # Get recent packets from this source IP
        recent_packets = [p for p in self.traffic_data['packets'] 
                         if p['source_ip'] == src_ip and 
                         (datetime.now() - p['timestamp']).seconds < 300]
        
        if len(recent_packets) > 50:  # Threshold for port scan detection
            unique_ports = len(set(p['dest_port'] for p in recent_packets))
            if unique_ports > 20:  # Multiple unique ports
                return True
        
        return False
    
    def _detect_packet_anomalies(self, packet_info):
        """Detect anomalies in packet data"""
        anomalies = []
        
        try:
            # Check for unusually large packets
            if packet_info['packet_size'] > 1500:
                anomalies.append({
                    'type': 'large_packet',
                    'size': packet_info['packet_size'],
                    'severity': 'low'
                })
            
            # Check for unusual protocols
            unusual_protocols = ['ICMP', 'IGMP']
            if packet_info['protocol'] in unusual_protocols:
                anomalies.append({
                    'type': 'unusual_protocol',
                    'protocol': packet_info['protocol'],
                    'severity': 'medium'
                })
            
            # Check for rapid packet bursts
            if self._detect_packet_burst(packet_info):
                anomalies.append({
                    'type': 'packet_burst',
                    'source_ip': packet_info['source_ip'],
                    'severity': 'medium'
                })
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
        
        return anomalies
    
    def _detect_packet_burst(self, packet_info):
        """Detect rapid packet bursts"""
        src_ip = packet_info['source_ip']
        
        # Count packets in last 10 seconds
        recent_packets = [p for p in self.traffic_data['packets'] 
                         if p['source_ip'] == src_ip and 
                         (datetime.now() - p['timestamp']).seconds < 10]
        
        return len(recent_packets) > 100  # Threshold for burst detection
    
    def _calculate_risk_score(self, packet_info, threats, anomalies):
        """Calculate risk score for packet"""
        risk_score = 0
        
        # Base risk
        risk_score += 10
        
        # Add threat risk
        for threat in threats:
            if threat['severity'] == 'high':
                risk_score += 50
            elif threat['severity'] == 'medium':
                risk_score += 30
            else:
                risk_score += 10
        
        # Add anomaly risk
        for anomaly in anomalies:
            if anomaly['severity'] == 'high':
                risk_score += 30
            elif anomaly['severity'] == 'medium':
                risk_score += 20
            else:
                risk_score += 10
        
        # Check IP reputation
        if packet_info['source_ip'] in self.ip_reputation:
            risk_score += self.ip_reputation[packet_info['source_ip']]
        
        return min(risk_score, 100)  # Cap at 100
    
    def _analyze_traffic_patterns(self):
        """Analyze overall traffic patterns"""
        try:
            # Convert to pandas for analysis
            if self.traffic_data['packets']:
                df = pd.DataFrame(list(self.traffic_data['packets']))
                
                # Protocol distribution
                protocol_dist = df['protocol'].value_counts()
                
                # Port analysis
                port_dist = df['dest_port'].value_counts().head(20)
                
                # IP analysis
                src_ip_dist = df['source_ip'].value_counts().head(20)
                dst_ip_dist = df['dest_ip'].value_counts().head(20)
                
                # Store analysis results
                self.analytics_results = {
                    'protocol_distribution': protocol_dist.to_dict(),
                    'top_ports': port_dist.to_dict(),
                    'top_source_ips': src_ip_dist.to_dict(),
                    'top_dest_ips': dst_ip_dist.to_dict(),
                    'total_packets': len(df),
                    'analysis_timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing traffic patterns: {e}")
    
    def _detect_anomalies(self):
        """Detect system-wide anomalies"""
        try:
            if not self.traffic_data['packets']:
                return
            
            df = pd.DataFrame(list(self.traffic_data['packets']))
            
            # Detect traffic spikes
            df['minute'] = df['timestamp'].dt.floor('min')
            traffic_by_minute = df.groupby('minute').size()
            
            if len(traffic_by_minute) > 10:
                mean_traffic = traffic_by_minute.mean()
                std_traffic = traffic_by_minute.std()
                
                # Detect spikes (2 standard deviations above mean)
                spikes = traffic_by_minute[traffic_by_minute > mean_traffic + 2*std_traffic]
                
                for timestamp, count in spikes.items():
                    self.logger.warning(f"Traffic spike detected at {timestamp}: {count} packets")
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence data"""
        try:
            # Update IP reputation based on recent activity
            if self.traffic_data['packets']:
                df = pd.DataFrame(list(self.traffic_data['packets']))
                
                # Calculate IP reputation scores
                for ip in df['source_ip'].unique():
                    ip_packets = df[df['source_ip'] == ip]
                    suspicious_count = len(ip_packets[ip_packets['protocol'].isin(['ICMP', 'IGMP'])])
                    
                    # Simple reputation scoring
                    reputation = min(suspicious_count * 10, 100)
                    self.ip_reputation[ip] = reputation
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {e}")
    
    def _ip_in_range(self, ip, ip_range):
        """Check if IP is in given range"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)
        except:
            return False
    
    def get_analytics_summary(self):
        """Get analytics summary"""
        return {
            'traffic_patterns': dict(self.traffic_patterns),
            'analytics_results': getattr(self, 'analytics_results', {}),
            'ip_reputation': self.ip_reputation,
            'total_packets_analyzed': len(self.traffic_data['packets'])
        }
    
    def get_threat_report(self):
        """Generate threat report"""
        threats_found = []
        
        if self.traffic_data['packets']:
            for packet_info in list(self.traffic_data['packets'])[-1000:]:  # Last 1000 packets
                threats = self._check_threat_signatures(packet_info)
                if threats:
                    threats_found.extend(threats)
        
        return {
            'total_threats': len(threats_found),
            'threats_by_type': pd.Series([t['type'] for t in threats_found]).value_counts().to_dict(),
            'threats_by_severity': pd.Series([t['severity'] for t in threats_found]).value_counts().to_dict(),
            'recent_threats': threats_found[-10:]  # Last 10 threats
        }

if __name__ == "__main__":
    # Test analytics system
    analytics = AdvancedAnalytics()
    analytics.start_analytics()
    
    print("Advanced analytics system started")
    print("Analytics summary:", analytics.get_analytics_summary()) 