#!/bin/bash
# NIDPS Attacker Machine Setup Script
# Run this on your Parrot OS VM

echo "=== NIDPS Attacker Machine Setup ==="
echo "This script will install all necessary tools for testing NIDPS"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

echo "🔧 Updating package list..."
apt update

echo "🔧 Installing system tools..."
apt install -y nmap hping3 hydra python3-pip python3-venv

echo "🔧 Creating Python virtual environment..."
python3 -m venv nidps_attacker_env
source nidps_attacker_env/bin/activate

echo "🔧 Installing Python dependencies..."
pip install -r attacker_requirements.txt

echo "🔧 Setting up network configuration..."
# Configure network for testing
cat > /etc/network/interfaces.d/nidps-test << EOF
# NIDPS Test Network Configuration
auto eth0
iface eth0 inet static
    address 192.168.100.20
    netmask 255.255.255.0
    gateway 192.168.100.10
    dns-nameservers 8.8.8.8 8.8.4.4
EOF

echo "✅ Attacker machine setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Restart networking: sudo systemctl restart networking"
echo "2. Test connectivity: ping 192.168.100.10"
echo "3. Run attack tests: python3 attacker_test_suite.py"
echo ""
echo "📋 Available tools:"
echo "  - nmap: Network scanning"
echo "  - hping3: Packet crafting"
echo "  - hydra: Brute force attacks"
echo "  - Python scripts: Custom attack tests" 