from .sniffer import PacketSniffer
from .detection import DetectionEngine
from .prevention import PreventionEngine
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
        self.is_running = False
        self.alerts = []
        self.alert_lock = threading.Lock()

    def packet_callback(self, packet):
        alert = self.detection_engine.check_packet(packet)
        if alert:
            with self.alert_lock:
                self.alerts.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': alert,
                    'source_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown'
                })
                # Keep only last 100 alerts
                if len(self.alerts) > 100:
                    self.alerts.pop(0)
            
            self.logger.info(f"Alert: {alert}")
            
            # Simple prevention: block the source IP
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                # Check if the matched rule action is 'block'
                matched_rule = self.get_matched_rule(packet)
                if matched_rule and matched_rule.get('action') == 'block':
                     self.logger.info(f"Blocking IP {ip_src} based on rule '{matched_rule['rule_name']}'")
                     self.prevention_engine.block_ip(ip_src)

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
            self.sniffer = PacketSniffer(interface=interface, packet_callback=self.packet_callback, logger=self.logger)
            self.sniffer.start()
            self.is_running = True
            self.logger.info("NIDPS Engine Started.")
        except Exception as e:
            self.logger.error(f"Failed to start NIDPS: {e}")
            self.logger.info("Note: Packet sniffing requires root privileges. Some features may be limited.")

    def stop(self):
        if not self.is_running:
            self.logger.info("NIDPS is not running.")
            return

        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.join()
        self.is_running = False
        self.logger.info("NIDPS Engine Stopped.")

    def get_alerts(self):
        with self.alert_lock:
            return self.alerts.copy()

    def get_blocked_ips(self):
        return self.prevention_engine.blocked_ips

    def unblock_ip(self, ip):
        if self.prevention_engine:
            self.prevention_engine.unblock_ip(ip)

    def get_rules(self):
        return self.detection_engine.rules

    def add_rule(self, rule):
        # This is a simple in-memory add. For persistence, we need to write back to the JSON file.
        self.detection_engine.rules.append(rule)
        self.logger.info(f"Rule added: {rule}")

    def get_logs(self):
        """Get recent logs from the log files."""
        logs = []
        try:
            with open('logs/nidps.log', 'r') as f:
                logs.extend(f.readlines()[-50:])  # Last 50 lines
        except FileNotFoundError:
            pass
        return logs 