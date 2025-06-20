import subprocess
import threading
import time
import logging
from datetime import datetime, timedelta

class PreventionEngine:
    def __init__(self, dwell_time_minutes=30, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.dwell_time_minutes = dwell_time_minutes
        self.blocked_ips = {}  # {ip: block_time}
        self.lock = threading.Lock()
        
        # Start the cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self.cleanup_thread.start()
        
        self.logger.info(f"Prevention Engine initialized with {dwell_time_minutes} minute dwell time")

    def block_ip(self, ip):
        """Block an IP address using UFW."""
        with self.lock:
            if ip in self.blocked_ips:
                self.logger.info(f"IP {ip} is already blocked")
                return False
            
            try:
                # Use UFW to block the IP
                result = subprocess.run(['ufw', 'deny', 'from', ip], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    self.blocked_ips[ip] = datetime.now()
                    self.logger.info(f"Successfully blocked IP: {ip}")
                    return True
                else:
                    self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"Timeout while blocking IP {ip}")
                return False
            except Exception as e:
                self.logger.error(f"Error blocking IP {ip}: {e}")
                return False

    def unblock_ip(self, ip):
        """Unblock an IP address using UFW."""
        with self.lock:
            if ip not in self.blocked_ips:
                self.logger.info(f"IP {ip} is not blocked")
                return False
            
            try:
                # Use UFW to allow the IP
                result = subprocess.run(['ufw', 'allow', 'from', ip], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    del self.blocked_ips[ip]
                    self.logger.info(f"Successfully unblocked IP: {ip}")
                    return True
                else:
                    self.logger.error(f"Failed to unblock IP {ip}: {result.stderr}")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"Timeout while unblocking IP {ip}")
                return False
            except Exception as e:
                self.logger.error(f"Error unblocking IP {ip}: {e}")
                return False

    def _cleanup_expired_blocks(self):
        """Background thread to automatically unblock IPs after dwell time."""
        while True:
            try:
                current_time = datetime.now()
                ips_to_unblock = []
                
                with self.lock:
                    for ip, block_time in self.blocked_ips.items():
                        if current_time - block_time > timedelta(minutes=self.dwell_time_minutes):
                            ips_to_unblock.append(ip)
                
                # Unblock expired IPs
                for ip in ips_to_unblock:
                    self.logger.info(f"Auto-unblocking IP {ip} after {self.dwell_time_minutes} minutes")
                    self.unblock_ip(ip)
                
                # Sleep for 1 minute before next check
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error in cleanup thread: {e}")
                time.sleep(60)

    def get_blocked_ips_info(self):
        """Get information about currently blocked IPs."""
        with self.lock:
            info = {}
            current_time = datetime.now()
            for ip, block_time in self.blocked_ips.items():
                time_remaining = self.dwell_time_minutes - (current_time - block_time).total_seconds() / 60
                info[ip] = {
                    'blocked_since': block_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'time_remaining': max(0, int(time_remaining))
                }
            return info

    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked."""
        with self.lock:
            return ip in self.blocked_ips

if __name__ == '__main__':
    # Example Usage
    engine = PreventionEngine(dwell_time_minutes=1)
    test_ip = "192.168.1.101"

    print("--- Testing IP Blocking ---")
    engine.block_ip(test_ip)
    
    # Check if the rule was added (manual check)
    # You can run `sudo iptables -L INPUT` in another terminal to verify
    
    print(f"\nWaiting for {engine.dwell_time_minutes} minutes for auto-unblock...")
    time.sleep(engine.dwell_time_minutes * 60 + 5)

    # Check if the rule was removed
    print(f"IP {test_ip} should now be unblocked.")
    print(f"Currently blocked IPs in engine: {list(engine.blocked_ips.keys())}")

    print("\n--- Testing Manual Unblock ---")
    test_ip_manual = "192.168.1.102"
    engine.block_ip(test_ip_manual)
    time.sleep(5)
    engine.unblock_ip(test_ip_manual)
    print(f"IP {test_ip_manual} should now be unblocked.")
    print(f"Currently blocked IPs in engine: {list(engine.blocked_ips.keys())}") 