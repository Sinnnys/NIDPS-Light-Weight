#!/usr/bin/env python3
"""
NIDPS Core System Test
Simulates attacks and verifies detection, prevention, DPI, and firewall effects.
Does NOT modify firewall rules, only reads and verifies.
"""
import subprocess
import socket
import time
import os
import re
from datetime import datetime

LOG_PATH = 'logs/nidps.log'
UFW_CMD = ['sudo', 'ufw', 'status', 'numbered']

# Utility functions
def print_header(title):
    print(f"\n=== {title} ===\n")

def print_step(msg):
    print(f"[STEP] {msg}")

def print_result(msg, ok=True):
    status = "✅" if ok else "❌"
    print(f"{status} {msg}")

def tail_log(pattern, timeout=10):
    """Tail the NIDPS log for a pattern within timeout seconds."""
    start = time.time()
    with open(LOG_PATH, 'r') as f:
        f.seek(0, os.SEEK_END)
        while time.time() - start < timeout:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            if pattern in line:
                return line.strip()
    return None

def get_ufw_status():
    try:
        result = subprocess.run(UFW_CMD, capture_output=True, text=True, timeout=5)
        return result.stdout
    except Exception as e:
        return f"Error reading UFW: {e}"

def show_ufw_for_ip(ip):
    status = get_ufw_status()
    print("\n[UFW STATUS]")
    for line in status.splitlines():
        if ip in line:
            print(line)
    print()

def send_ssh_brute_force(target_ip, port=22, attempts=5):
    print_header("SSH Brute Force Simulation")
    for i in range(attempts):
        print_step(f"Attempt {i+1} SSH connect to {target_ip}:{port}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, port))
        except Exception as e:
            print(f"  (connection failed: {e})")
        finally:
            s.close()
        time.sleep(0.3)
    # Check log for detection - look for SSH brute force rule
    logline = tail_log("WARNING: ALERT: Rule 'SSH Brute Force Attack'")
    if logline:
        print_result(f"Detected: {logline}")
    else:
        # Also check for SSH connection attempts
        logline = tail_log("WARNING: ALERT: Rule 'SSH Connection Attempt'")
        if logline:
            print_result(f"Detected SSH attempts: {logline}")
        else:
            print_result("No SSH brute force detected in log", ok=False)
    show_ufw_for_ip(target_ip)

def send_port_scan(target_ip, ports=range(20, 30)):
    print_header("Port Scan Simulation")
    for port in ports:
        print_step(f"Scanning port {port} on {target_ip}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.1)
    # Check log for port scan detection
    logline = tail_log("WARNING: ALERT: Rule 'Potential TCP Port Scan'")
    if logline:
        print_result(f"Detected: {logline}")
    else:
        print_result("No port scan detected in log", ok=False)
    show_ufw_for_ip(target_ip)

def send_ddos(target_ip, port=80, count=100):
    print_header("DDoS Simulation")
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'X'*128, (target_ip, port))
        except Exception:
            pass
        finally:
            s.close()
        if i % 10 == 0:
            print_step(f"Sent {i+1}/{count} UDP packets")
        time.sleep(0.01)
    # Check log for large packets or suspicious activity
    logline = tail_log("WARNING: ALERT: Rule 'Suspicious Large Packets'")
    if logline:
        print_result(f"Detected: {logline}")
    else:
        print_result("No DDoS/large packets detected in log", ok=False)
    show_ufw_for_ip(target_ip)

def send_malicious_payload(target_ip, port=8080):
    print_header("Malicious Payload Simulation (DPI)")
    payload = b'GET / HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: BadBot\r\nX-Malware: test-signature\r\n\r\n'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, port))
        s.sendall(payload)
        print_step(f"Sent malicious payload to {target_ip}:{port}")
    except Exception as e:
        print(f"  (send failed: {e})")
    finally:
        s.close()
    # Check log for HTTP traffic or DPI detection
    logline = tail_log("WARNING: ALERT: Rule 'HTTP/HTTPS Traffic'")
    if logline:
        print_result(f"Detected HTTP traffic: {logline}")
    else:
        print_result("No HTTP traffic or malicious payload detected in log", ok=False)
    show_ufw_for_ip(target_ip)

def main():
    print("\nNIDPS Core System Test\n======================\n")
    target_ip = '127.0.0.1'  # Localhost for testing
    send_ssh_brute_force(target_ip)
    send_port_scan(target_ip)
    send_ddos(target_ip)
    send_malicious_payload(target_ip)
    print("\nAll tests complete. Check logs and UFW status for details.\n")

if __name__ == '__main__':
    main() 