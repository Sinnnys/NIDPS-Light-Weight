#!/bin/bash
# NIDPS Test Network Setup Script
# This script sets up a private network for testing NIDPS with real attacks

echo "=== NIDPS Test Network Setup ==="
echo "This script will configure your system for NIDPS testing"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Configuration
NIDPS_INTERFACE="eth0"  # Change this to your main network interface
TEST_NETWORK="192.168.100.0/24"
NIDPS_IP="192.168.100.10"
ATTACKER_IP="192.168.100.20"
TEST_INTERFACE="test0"

echo "📋 Configuration:"
echo "  NIDPS IP: $NIDPS_IP"
echo "  Attacker IP: $ATTACKER_IP"
echo "  Network: $TEST_NETWORK"
echo ""

# Create virtual network interface
echo "🔧 Creating virtual network interface..."
ip link add $TEST_INTERFACE type dummy
ip addr add $NIDPS_IP/24 dev $TEST_INTERFACE
ip link set $TEST_INTERFACE up

# Configure iptables for testing
echo "🔧 Configuring iptables for testing..."
iptables -t nat -A POSTROUTING -s $TEST_NETWORK -o $NIDPS_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $TEST_INTERFACE -o $NIDPS_INTERFACE -j ACCEPT
iptables -A FORWARD -i $NIDPS_INTERFACE -o $TEST_INTERFACE -j ACCEPT

# Enable IP forwarding
echo "🔧 Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Create test network configuration file
cat > /etc/nidps-test-network.conf << EOF
# NIDPS Test Network Configuration
NIDPS_IP=$NIDPS_IP
ATTACKER_IP=$ATTACKER_IP
TEST_NETWORK=$TEST_NETWORK
TEST_INTERFACE=$TEST_INTERFACE
EOF

echo "✅ Test network setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. On your attacking machine (Parrot OS VM), configure:"
echo "   - IP: $ATTACKER_IP"
echo "   - Gateway: $NIDPS_IP"
echo "   - Netmask: 255.255.255.0"
echo ""
echo "2. Run the NIDPS system:"
echo "   python run.py"
echo ""
echo "3. Run attack tests from the attacking machine"
echo ""
echo "4. To clean up, run: sudo ./cleanup_test_network.sh" 