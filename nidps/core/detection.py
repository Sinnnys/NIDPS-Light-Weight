import json
from scapy.all import TCP, ICMP
import logging

class DetectionEngine:
    def __init__(self, rules_file, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.rules = self.load_rules(rules_file)
        self.rules_file = rules_file

    def load_rules(self, rules_file):
        try:
            with open(rules_file, 'r') as f:
                return json.load(f).get('rules', [])
        except FileNotFoundError:
            self.logger.error(f"Rules file not found at {rules_file}")
            return []
        except json.JSONDecodeError:
            self.logger.error(f"Could not decode JSON from rules file: {rules_file}")
            return []

    def check_packet(self, packet):
        for rule in self.rules:
            if self.match_rule(packet, rule):
                return self.trigger_action(packet, rule)
        return None

    def match_rule(self, packet, rule):
        proto = rule.get('protocol')
        conditions = rule.get('conditions', {})

        if proto == 'TCP' and packet.haslayer(TCP):
            return all(self.check_condition(packet[TCP], k, v) for k, v in conditions.items())
        elif proto == 'ICMP' and packet.haslayer(ICMP):
            return all(self.check_condition(packet[ICMP], k, v) for k, v in conditions.items())
        
        # Add other protocols like UDP here
        
        return False

    def check_condition(self, layer, key, value):
        if hasattr(layer, key):
            # Special case for TCP flags
            if key == 'flags' and isinstance(getattr(layer, key), int):
                 # Scapy's flags can be finicky. This is a simple check.
                 return str(getattr(layer, key)) == str(value) or layer.flags.match(str(value))

            return getattr(layer, key) == value
        return False

    def trigger_action(self, packet, rule):
        action = rule.get('action')
        log_message = f"Rule '{rule['rule_name']}' matched on packet: {packet.summary()}"
        if action == 'log' or action == 'block':
            # The engine class now handles the logging, this just returns the message
            return log_message
        return None

if __name__ == '__main__':
    # Example Usage
    from nidps.core.sniffer import PacketSniffer

    engine = DetectionEngine('../rules.json')

    def process_and_detect(packet):
        engine.check_packet(packet)

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