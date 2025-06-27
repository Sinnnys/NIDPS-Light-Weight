#!/usr/bin/env python3
"""
NIDPS Real-Time Monitor
Monitor attacks and system performance during testing
"""

import time
import psutil
import requests
import json
from datetime import datetime
import threading
import os
import sys

class NIDPSMonitor:
    def __init__(self):
        self.base_url = "http://127.0.0.1:5000"
        self.monitoring = True
        self.attack_count = 0
        self.alert_count = 0
        self.start_time = time.time()
        
    def get_system_stats(self):
        """Get current system statistics"""
        try:
            response = requests.get(f"{self.base_url}/api/system_stats", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None
    
    def get_alerts(self):
        """Get current alerts"""
        try:
            response = requests.get(f"{self.base_url}/api/alerts", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []
    
    def get_engine_status(self):
        """Get engine status"""
        try:
            response = requests.get(f"{self.base_url}/api/engine_status", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def monitor_network_traffic(self):
        """Monitor network traffic in real-time"""
        print("\n🌐 Network Traffic Monitor")
        print("-" * 50)
        
        while self.monitoring:
            try:
                # Get network I/O stats
                net_io = psutil.net_io_counters()
                
                # Get system stats from NIDPS
                stats = self.get_system_stats()
                
                # Clear screen
                os.system('clear' if os.name == 'posix' else 'cls')
                
                print("🔍 NIDPS Real-Time Monitor")
                print("=" * 50)
                print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Uptime: {int(time.time() - self.start_time)}s")
                print("=" * 50)
                
                # System stats
                if stats:
                    print(f"CPU Usage: {stats.get('cpu_percent', 0):.1f}%")
                    print(f"Memory Usage: {stats.get('memory_percent', 0):.1f}%")
                    print(f"Disk Usage: {stats.get('disk_percent', 0):.1f}%")
                
                # Network stats
                print(f"\n📡 Network I/O:")
                print(f"  Bytes Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB")
                print(f"  Bytes Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB")
                print(f"  Packets Sent: {net_io.packets_sent}")
                print(f"  Packets Received: {net_io.packets_recv}")
                
                # Engine status
                engine_status = self.get_engine_status()
                if engine_status:
                    print(f"\n🚀 Engine Status:")
                    print(f"  Running: {engine_status.get('running', False)}")
                    print(f"  Packets Processed: {engine_status.get('packets_processed', 0)}")
                    print(f"  Alerts Generated: {engine_status.get('alerts_count', 0)}")
                
                # Recent alerts
                alerts = self.get_alerts()
                if alerts:
                    recent_alerts = alerts[:5]  # Show last 5 alerts
                    print(f"\n🚨 Recent Alerts ({len(alerts)} total):")
                    for alert in recent_alerts:
                        severity = alert.get('severity', 'unknown')
                        source = alert.get('source_ip', 'unknown')
                        timestamp = alert.get('timestamp', 'unknown')
                        print(f"  [{severity.upper()}] {source} - {timestamp}")
                
                # Performance indicators
                print(f"\n📊 Performance Indicators:")
                if stats:
                    cpu = stats.get('cpu_percent', 0)
                    memory = stats.get('memory_percent', 0)
                    
                    if cpu > 80:
                        print(f"  ⚠️  High CPU Usage: {cpu:.1f}%")
                    elif cpu > 60:
                        print(f"  🔶 Moderate CPU Usage: {cpu:.1f}%")
                    else:
                        print(f"  ✅ Normal CPU Usage: {cpu:.1f}%")
                    
                    if memory > 85:
                        print(f"  ⚠️  High Memory Usage: {memory:.1f}%")
                    elif memory > 70:
                        print(f"  🔶 Moderate Memory Usage: {memory:.1f}%")
                    else:
                        print(f"  ✅ Normal Memory Usage: {memory:.1f}%")
                
                print(f"\n💡 Press Ctrl+C to stop monitoring")
                
                time.sleep(2)  # Update every 2 seconds
                
            except KeyboardInterrupt:
                print("\n\n🛑 Monitoring stopped by user")
                self.monitoring = False
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")
                time.sleep(5)
    
    def monitor_logs(self):
        """Monitor NIDPS logs in real-time"""
        log_file = "logs/nidps.log"
        
        if not os.path.exists(log_file):
            print(f"❌ Log file not found: {log_file}")
            return
        
        print(f"\n📝 Monitoring logs: {log_file}")
        print("-" * 50)
        
        # Get initial file size
        with open(log_file, 'r') as f:
            f.seek(0, 2)  # Seek to end
            last_size = f.tell()
        
        while self.monitoring:
            try:
                with open(log_file, 'r') as f:
                    f.seek(last_size)
                    new_lines = f.readlines()
                    last_size = f.tell()
                    
                    for line in new_lines:
                        if line.strip():
                            # Highlight important events
                            if 'ALERT' in line or 'DETECTED' in line:
                                print(f"🚨 {line.strip()}")
                            elif 'ERROR' in line:
                                print(f"❌ {line.strip()}")
                            elif 'WARNING' in line:
                                print(f"⚠️  {line.strip()}")
                            else:
                                print(f"📝 {line.strip()}")
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Log monitoring error: {e}")
                time.sleep(5)
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        print("🚀 Starting NIDPS Real-Time Monitor")
        print("=" * 50)
        
        # Start network monitoring in main thread
        self.monitor_network_traffic()
        
        # Start log monitoring in separate thread
        log_thread = threading.Thread(target=self.monitor_logs, daemon=True)
        log_thread.start()
        
        try:
            while self.monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitor...")
            self.monitoring = False

def main():
    print("🔧 NIDPS Real-Time Monitor")
    print("Monitor your NIDPS system during attack testing")
    print("Make sure NIDPS is running before starting monitor")
    print()
    
    monitor = NIDPSMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main() 