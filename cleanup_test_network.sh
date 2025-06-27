#!/bin/bash
# NIDPS Test Network Cleanup Script

echo "=== NIDPS Test Network Cleanup ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Load configuration
if [ -f /etc/nidps-test-network.conf ]; then
    source /etc/nidps-test-network.conf
else
    echo "❌ Configuration file not found. Using defaults..."
    TEST_INTERFACE="test0"
    TEST_NETWORK="192.168.100.0/24"
    NIDPS_INTERFACE="eth0"
fi

echo "🧹 Cleaning up test network..."

# Remove iptables rules
echo "🔧 Removing iptables rules..."
iptables -t nat -D POSTROUTING -s $TEST_NETWORK -o $NIDPS_INTERFACE -j MASQUERADE 2>/dev/null
iptables -D FORWARD -i $TEST_INTERFACE -o $NIDPS_INTERFACE -j ACCEPT 2>/dev/null
iptables -D FORWARD -i $NIDPS_INTERFACE -o $TEST_INTERFACE -j ACCEPT 2>/dev/null

# Remove virtual interface
echo "🔧 Removing virtual interface..."
ip link del $TEST_INTERFACE 2>/dev/null

# Remove configuration file
echo "🔧 Removing configuration file..."
rm -f /etc/nidps-test-network.conf

echo "✅ Test network cleanup complete!" 