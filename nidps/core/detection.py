import json
import os
from scapy.all import TCP, ICMP, UDP, IP
import logging
import time
from collections import defaultdict, deque

class DetectionEngine:
    def __init__(self, rules_file, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.rules = self.load_rules(rules_file)
        self.rules_file = rules_file
        self.rate_limiters = defaultdict(lambda: deque())
        self.packet_counters = defaultdict(int)
        self.last_cleanup = time.time()

    def load_rules(self, rules_file):
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except FileNotFoundError:
            self.logger.error(f"Rules file not found at {rules_file}")
            return []
        except json.JSONDecodeError:
            self.logger.error(f"Could not decode JSON from rules file: {rules_file}")
            return []

    def cleanup_rate_limiters(self):
        """Clean up old rate limiter entries"""
        current_time = time.time()
        if current_time - self.last_cleanup > 60:  # Clean up every minute
            for key in list(self.rate_limiters.keys()):
                while self.rate_limiters[key] and current_time - self.rate_limiters[key][0] > 3600:  # 1 hour
                    self.rate_limiters[key].popleft()
            self.last_cleanup = current_time

    def check_rate_limit(self, rule, packet):
        """Check if a packet violates rate limiting rules"""
        if 'rate_limit' not in rule:
            return True
        
        rate_config = rule['rate_limit']
        max_attempts = rate_config.get('max_attempts', 10)
        time_window = rate_config.get('time_window', 60)
        
        # Create a unique key for this rule and source IP
        if packet.haslayer(IP):
            key = f"{rule['rule_name']}_{packet[IP].src}"
        else:
            key = f"{rule['rule_name']}_unknown"
        
        current_time = time.time()
        
        # Remove old entries
        while self.rate_limiters[key] and current_time - self.rate_limiters[key][0] > time_window:
            self.rate_limiters[key].popleft()
        
        # Check if we're over the limit
        if len(self.rate_limiters[key]) >= max_attempts:
            return False
        
        # Add current packet
        self.rate_limiters[key].append(current_time)
        return True

    def check_packet(self, packet):
        self.cleanup_rate_limiters()
        
        for rule in self.rules:
            if self.match_rule(packet, rule):
                # Check rate limiting
                if not self.check_rate_limit(rule, packet):
                    continue
                
                return self.trigger_action(packet, rule)
        return None

    def match_rule(self, packet, rule):
        proto = rule.get('protocol')
        conditions = rule.get('conditions', {})

        if proto == 'TCP' and packet.haslayer(TCP):
            return all(self.check_condition(packet[TCP], k, v) for k, v in conditions.items())
        elif proto == 'ICMP' and packet.haslayer(ICMP):
            return all(self.check_condition(packet[ICMP], k, v) for k, v in conditions.items())
        elif proto == 'UDP' and packet.haslayer(UDP):
            return all(self.check_condition(packet[UDP], k, v) for k, v in conditions.items())
        elif proto == 'IP' and packet.haslayer(IP):
            return all(self.check_condition(packet[IP], k, v) for k, v in conditions.items())
        elif proto == 'ANY':
            return all(self.check_condition(packet, k, v) for k, v in conditions.items())
        
        return False

    def check_condition(self, layer, key, value):
        if hasattr(layer, key):
            attr_value = getattr(layer, key)
            
            # Special case for TCP flags
            if key == 'flags' and isinstance(attr_value, int):
                return str(attr_value) == str(value) or layer.flags.match(str(value))
            
            # Handle list values (e.g., multiple ports)
            if isinstance(value, list):
                return attr_value in value
            
            # Handle comparison operators
            if isinstance(value, str) and value.startswith('>'):
                try:
                    threshold = int(value[1:])
                    return attr_value > threshold
                except (ValueError, TypeError):
                    pass
            
            if isinstance(value, str) and value.startswith('<'):
                try:
                    threshold = int(value[1:])
                    return attr_value < threshold
                except (ValueError, TypeError):
                    pass
            
            # Handle boolean values
            if isinstance(value, bool):
                return bool(attr_value) == value
            
            # Handle packet size
            if key == 'packet_size':
                packet_size = len(layer)
                if isinstance(value, str) and value.startswith('>'):
                    threshold = int(value[1:])
                    return packet_size > threshold
                return packet_size == value
            
            return attr_value == value
        
        # Handle packet-level attributes
        if key == 'packet_size':
            packet_size = len(layer)
            if isinstance(value, str) and value.startswith('>'):
                threshold = int(value[1:])
                return packet_size > threshold
            return packet_size == value
        
        return False

    def trigger_action(self, packet, rule):
        action = rule.get('action')
        severity = rule.get('severity', 'medium')
        
        # Create detailed alert message
        alert_details = {
            'rule_name': rule['rule_name'],
            'severity': severity,
            'action': action,
            'packet_summary': packet.summary(),
            'source_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
            'dest_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        }
        
        if packet.haslayer(TCP):
            alert_details['source_port'] = packet[TCP].sport
            alert_details['dest_port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            alert_details['source_port'] = packet[UDP].sport
            alert_details['dest_port'] = packet[UDP].dport
        
        log_message = f"Rule '{rule['rule_name']}' ({severity.upper()}) matched: {packet.summary()}"
        
        if action == 'log' or action == 'block':
            return {
                'message': log_message,
                'details': alert_details,
                'severity': severity,
                'action': action
            }
        return None

if __name__ == '__main__':
    # Example Usage
    from nidps.core.sniffer import PacketSniffer

    engine = DetectionEngine('../rules.json')

    def process_and_detect(packet):
        result = engine.check_packet(packet)
        if result:
            print(f"Alert: {result['message']}")

    sniffer = PacketSniffer(packet_callback=process_and_detect)
    print("Starting sniffer and detection engine...")
    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt:
        print("\nStopping sniffer and detection engine...")
        sniffer.stop()
        sniffer.join()
        print("Stopped.") 