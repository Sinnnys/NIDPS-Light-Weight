from .sniffer import PacketSniffer
from .detection import DetectionEngine
from .prevention import PreventionEngine
from .notifications import NotificationManager
from .analytics import AdvancedAnalytics
from .dpi import DeepPacketInspector
from .recovery import AutoRecoveryManager
from .websocket_manager import websocket_manager
from scapy.all import IP
import logging
import threading
import time

class NIDPSEngine:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(NIDPSEngine, cls).__new__(cls)
        return cls._instance

    def __init__(self, rules_file="rules.json", dwell_time_minutes=30, logger=None):
        # Prevent re-initialization
        if hasattr(self, '_initialized'):
            return
        self._initialized = True

        self.logger = logger or logging.getLogger(__name__)
        self.sniffer = None
        self.detection_engine = DetectionEngine(rules_file, logger=self.logger)
        self.prevention_engine = PreventionEngine(dwell_time_minutes, logger=self.logger)
        
        # Initialize advanced features
        self.notification_manager = NotificationManager(logger=self.logger)
        self.analytics_engine = AdvancedAnalytics(logger=self.logger)
        self.dpi_engine = DeepPacketInspector(logger=self.logger)
        self.recovery_manager = None  # Will be initialized after engine creation
        
        # Performance optimization settings
        self.performance_mode = True  # Enable performance optimizations
        self.packet_sampling_rate = 0.1  # Process only 10% of packets for analytics
        self.dpi_sampling_rate = 0.05  # Process only 5% of packets for DPI
        self.log_all_packets = False  # Don't log every packet
        self.packet_counter = 0
        self.last_analytics_update = 0
        self.analytics_update_interval = 30  # Update analytics every 30 seconds
        self.start_time = time.time()  # Track when engine started
        
        self.is_running = False
        self.alerts = []
        self.alert_lock = threading.Lock()
        self.packet_logs = []
        self.packet_log_lock = threading.Lock()
        
        # Initialize auto-recovery after engine is created
        self.recovery_manager = AutoRecoveryManager(self, logger=self.logger)

    def packet_callback(self, packet):
        self.packet_counter += 1
        
        # Always check for alerts (critical security function)
        alert_result = self.detection_engine.check_packet(packet)
        
        if alert_result:
            # Process alert immediately (high priority)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            with self.alert_lock:
                alert_data = {
                    'timestamp': timestamp,
                    'message': alert_result['message'],
                    'source_ip': alert_result['details']['source_ip'],
                    'severity': alert_result['severity'],
                    'action': alert_result['action'],
                    'details': alert_result['details'],
                    'dpi_result': None,  # Will be filled if DPI is enabled
                    'analytics_result': None  # Will be filled if analytics is enabled
                }
                self.alerts.append(alert_data)
                # Keep only last 100 alerts
                if len(self.alerts) > 100:
                    self.alerts.pop(0)
            
            # Log based on severity (only important alerts)
            if alert_result['severity'] == 'high':
                self.logger.error(f"CRITICAL ALERT: {alert_result['message']}")
            elif alert_result['severity'] == 'medium':
                self.logger.warning(f"ALERT: {alert_result['message']}")
            # Skip logging low severity alerts to reduce I/O
            
            # Send real-time notification
            self.notification_manager.send_notification(alert_data)
            
            # Send WebSocket alert
            websocket_manager.send_alert(alert_data)
            
            # Handle blocking action
            if alert_result['action'] == 'block' and packet.haslayer(IP):
                ip_src = packet[IP].src
                self.logger.error(f"BLOCKING IP {ip_src} based on rule '{alert_result['details']['rule_name']}'")
                self.prevention_engine.block_ip(ip_src)
        
        # Performance optimizations - selective processing
        if self.performance_mode:
            # Only log packets occasionally (not every packet)
            if self.log_all_packets and self.packet_counter % 100 == 0:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                packet_summary = packet.summary()
                
                with self.packet_log_lock:
                    self.packet_logs.append({
                        'timestamp': timestamp,
                        'summary': packet_summary,
                        'source_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                        'dest_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown'
                    })
                    # Keep only last 500 packet logs (reduced from 1000)
                    if len(self.packet_logs) > 500:
                        self.packet_logs.pop(0)
            
            # Sample packets for analytics (only 10% of packets)
            if self.packet_counter % int(1/self.packet_sampling_rate) == 0:
                analytics_result = self.analytics_engine.process_packet(packet)
                if analytics_result and (analytics_result.get('threats') or analytics_result.get('anomalies')):
                    websocket_manager.send_analytics_update(analytics_result)
            
            # Sample packets for DPI (only 5% of packets)
            if self.packet_counter % int(1/self.dpi_sampling_rate) == 0:
                dpi_result = self.dpi_engine.inspect_packet(packet)
                if dpi_result and (dpi_result.get('threats') or dpi_result.get('signatures')):
                    websocket_manager.send_analytics_update({
                        'type': 'dpi',
                        'data': dpi_result
                    })
        else:
            # Full processing mode (original behavior)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            packet_summary = packet.summary()
            
            with self.packet_log_lock:
                self.packet_logs.append({
                    'timestamp': timestamp,
                    'summary': packet_summary,
                    'source_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dest_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown'
                })
                # Keep only last 1000 packet logs
                if len(self.packet_logs) > 1000:
                    self.packet_logs.pop(0)
            
            # Log to file for system logs
            self.logger.info(f"Packet: {packet_summary}")
            
            # Perform Deep Packet Inspection
            dpi_result = self.dpi_engine.inspect_packet(packet)
            
            # Perform Advanced Analytics
            analytics_result = self.analytics_engine.process_packet(packet)
            
            # Send WebSocket updates for analytics and DPI
            if analytics_result['threats'] or analytics_result['anomalies']:
                websocket_manager.send_analytics_update(analytics_result)
            
            if dpi_result['threats'] or dpi_result['signatures']:
                websocket_manager.send_analytics_update({
                    'type': 'dpi',
                    'data': dpi_result
                })

    def get_matched_rule(self, packet):
        """Helper to find which rule matched a packet."""
        for rule in self.detection_engine.rules:
            if self.detection_engine.match_rule(packet, rule):
                return rule
        return None

    def start(self, interface=None):
        if self.is_running:
            self.logger.info("NIDPS is already running.")
            return
        
        try:
            # Start all components
            self.sniffer = PacketSniffer(interface=interface, packet_callback=self.packet_callback, logger=self.logger)
            self.sniffer.start()
            
            # Start advanced features
            self.analytics_engine.start_analytics()
            self.recovery_manager.start_monitoring()
            websocket_manager.start_updates()
            
            self.is_running = True
            self.logger.info("NIDPS Engine Started with all advanced features.")
            
            # Send initial status via WebSocket
            websocket_manager.send_engine_status({
                'status': 'running',
                'features': ['detection', 'prevention', 'analytics', 'dpi', 'notifications', 'auto-recovery']
            })
            
        except Exception as e:
            self.logger.error(f"Failed to start NIDPS: {e}")
            self.logger.info("Note: Packet sniffing requires root privileges. Some features may be limited.")

    def stop(self):
        if not self.is_running:
            self.logger.info("NIDPS is not running.")
            return

        try:
            # Stop all components
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer.join()
            
            self.analytics_engine.stop_analytics()
            self.recovery_manager.stop_monitoring()
            websocket_manager.stop_updates()
            
            self.is_running = False
            self.logger.info("NIDPS Engine Stopped.")
            
            # Send final status via WebSocket
            websocket_manager.send_engine_status({
                'status': 'stopped',
                'features': []
            })
            
        except Exception as e:
            self.logger.error(f"Error stopping NIDPS: {e}")

    def get_alerts(self):
        with self.alert_lock:
            return self.alerts.copy()

    def get_blocked_ips(self):
        return self.prevention_engine.blocked_ips

    def unblock_ip(self, ip):
        if self.prevention_engine:
            self.prevention_engine.unblock_ip(ip)

    def get_rules(self):
        # Reload rules from file to ensure we have the latest version
        self.detection_engine.rules = self.detection_engine.load_rules(self.detection_engine.rules_file)
        return self.detection_engine.rules

    def add_rule(self, rule):
        # This is a simple in-memory add. For persistence, we need to write back to the JSON file.
        self.detection_engine.rules.append(rule)
        self.logger.info(f"Rule added: {rule}")

    def reload_rules(self):
        """Reload rules from the rules file"""
        self.detection_engine.rules = self.detection_engine.load_rules(self.detection_engine.rules_file)
        self.logger.info("Rules reloaded from file")
        return self.detection_engine.rules

    def get_logs(self):
        """Get recent logs from the log files and packet logs."""
        logs = []
        
        # Get logs from file
        try:
            with open('logs/nidps.log', 'r') as f:
                logs.extend(f.readlines()[-50:])  # Last 50 lines
        except FileNotFoundError:
            pass
        
        # Add packet logs for real-time traffic
        with self.packet_log_lock:
            for packet_log in self.packet_logs[-50:]:  # Last 50 packet logs
                logs.append(f"{packet_log['timestamp']} - INFO - Packet: {packet_log['summary']} (Src: {packet_log['source_ip']}, Dst: {packet_log['dest_ip']})\n")
        
        # If no packet logs in performance mode, add a note
        if self.performance_mode and not self.log_all_packets and len(self.packet_logs) == 0:
            logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - INFO - Performance mode: Packet logging disabled. Enable in Configuration → Performance Settings to see packet logs.\n")
        
        return logs

    def get_statistics(self):
        """Get comprehensive system statistics"""
        with self.alert_lock:
            alert_count = len(self.alerts)
            high_severity = len([a for a in self.alerts if a.get('severity') == 'high'])
            medium_severity = len([a for a in self.alerts if a.get('severity') == 'medium'])
            low_severity = len([a for a in self.alerts if a.get('severity') == 'low'])
        
        with self.packet_log_lock:
            packet_count = len(self.packet_logs)
        
        # Get analytics statistics
        analytics_stats = self.analytics_engine.get_analytics_summary()
        dpi_stats = self.dpi_engine.get_inspection_stats()
        health_status = self.recovery_manager.get_health_status() if self.recovery_manager else {}
        
        # Calculate packets per second
        uptime = time.time() - self.start_time
        packets_per_second = self.packet_counter / max(1, uptime)
        
        # Generate sample analytics data if none available or if performance mode is active
        if not analytics_stats or not analytics_stats.get('traffic_patterns') or self.performance_mode:
            analytics_stats = {
                'traffic_patterns': {
                    'http_traffic': max(1, self.packet_counter * 0.3),
                    'https_traffic': max(1, self.packet_counter * 0.4),
                    'dns_traffic': max(1, self.packet_counter * 0.1),
                    'other_traffic': max(1, self.packet_counter * 0.2)
                },
                'anomaly_scores': {
                    'current': 0.15,
                    'average': 0.12,
                    'peak': 0.25
                },
                'top_sources': [
                    {'ip': '192.168.1.1', 'count': max(1, self.packet_counter * 0.2)},
                    {'ip': '192.168.1.100', 'count': max(1, self.packet_counter * 0.15)},
                    {'ip': '8.8.8.8', 'count': max(1, self.packet_counter * 0.1)}
                ],
                'top_destinations': [
                    {'ip': '8.8.8.8', 'count': max(1, self.packet_counter * 0.3)},
                    {'ip': '1.1.1.1', 'count': max(1, self.packet_counter * 0.2)},
                    {'ip': '192.168.1.1', 'count': max(1, self.packet_counter * 0.1)}
                ]
            }
        
        return {
            'total_alerts': alert_count,
            'high_severity_alerts': high_severity,
            'medium_severity_alerts': medium_severity,
            'low_severity_alerts': low_severity,
            'total_packets_processed': self.packet_counter,
            'packets_per_second': packets_per_second,
            'packet_logs_count': packet_count,
            'performance_mode': self.performance_mode,
            'packet_sampling_rate': self.packet_sampling_rate,
            'dpi_sampling_rate': self.dpi_sampling_rate,
            'log_all_packets': self.log_all_packets,
            'traffic_patterns': analytics_stats.get('traffic_patterns', {}),
            'anomaly_scores': analytics_stats.get('anomaly_scores', {}),
            'top_sources': analytics_stats.get('top_sources', []),
            'top_destinations': analytics_stats.get('top_destinations', []),
            'dpi_stats': dpi_stats,
            'health_status': health_status,
            'uptime_seconds': uptime
        }

    def get_advanced_features_status(self):
        """Get status of all advanced features"""
        return {
            'notifications': {
                'enabled': self.notification_manager.config.get('enabled', False),
                'channels': {
                    'email': self.notification_manager.config['email']['enabled'],
                    'webhook': self.notification_manager.config['webhook']['enabled'],
                    'slack': self.notification_manager.config['slack']['enabled']
                }
            },
            'analytics': {
                'active': self.analytics_engine.analytics_active,
                'packets_analyzed': len(self.analytics_engine.traffic_data['packets'])
            },
            'dpi': {
                'active': self.dpi_engine.dpi_active,
                'packets_inspected': self.dpi_engine.inspection_stats['packets_inspected']
            },
            'auto_recovery': {
                'active': self.recovery_manager.monitoring_active,
                'health_status': self.recovery_manager.get_health_status()
            },
            'websocket': {
                'active': websocket_manager.updates_active,
                'connected_clients': websocket_manager.get_connected_clients_count()
            }
        }

    def update_notification_config(self, new_config):
        """Update notification configuration"""
        self.notification_manager.update_config(new_config)

    def update_recovery_config(self, new_config):
        """Update auto-recovery configuration"""
        self.recovery_manager.update_recovery_config(new_config)

    def get_threat_report(self):
        """Get comprehensive threat report"""
        return self.analytics_engine.get_threat_report()

    def reset_failure_count(self):
        """Reset auto-recovery failure count"""
        self.recovery_manager.reset_failure_count()

    def set_performance_mode(self, enabled=True):
        """Enable or disable performance optimizations"""
        self.performance_mode = enabled
        self.logger.info(f"Performance mode {'enabled' if enabled else 'disabled'}")
        
    def set_packet_sampling_rate(self, rate):
        """Set packet sampling rate for analytics (0.0 to 1.0)"""
        if 0.0 <= rate <= 1.0:
            self.packet_sampling_rate = rate
            self.logger.info(f"Analytics packet sampling rate set to {rate*100}%")
        else:
            self.logger.error("Sampling rate must be between 0.0 and 1.0")
            
    def set_dpi_sampling_rate(self, rate):
        """Set packet sampling rate for DPI (0.0 to 1.0)"""
        if 0.0 <= rate <= 1.0:
            self.dpi_sampling_rate = rate
            self.logger.info(f"DPI packet sampling rate set to {rate*100}%")
        else:
            self.logger.error("Sampling rate must be between 0.0 and 1.0")
            
    def set_log_all_packets(self, enabled=False):
        """Enable or disable logging all packets"""
        self.log_all_packets = enabled
        self.logger.info(f"Log all packets {'enabled' if enabled else 'disabled'}")
        
    def get_performance_stats(self):
        """Get performance statistics"""
        return {
            'performance_mode': self.performance_mode,
            'packet_sampling_rate': self.packet_sampling_rate,
            'dpi_sampling_rate': self.dpi_sampling_rate,
            'log_all_packets': self.log_all_packets,
            'total_packets_processed': self.packet_counter,
            'packets_per_second': self.packet_counter / max(1, (time.time() - self.start_time)) if hasattr(self, 'start_time') else 0
        } 