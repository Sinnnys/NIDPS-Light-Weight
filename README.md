# Network Intrusion Detection and Prevention System (NIDPS)

A comprehensive Network Intrusion Detection and Prevention System for Linux with real-time monitoring, advanced analytics, performance optimizations, and a modern web-based management interface.

## 🚀 Features

### Core Security Features
- **Real-time Packet Analysis**: Monitors network traffic using Scapy with performance optimizations
- **Rule-based Detection**: JSON-based detection rules with customizable conditions
- **UFW Integration**: Uses UFW (Uncomplicated Firewall) for IP blocking with configurable dwell time
- **Deep Packet Inspection (DPI)**: Advanced payload analysis and signature detection
- **Threat Intelligence**: Real-time threat detection and analysis

### Advanced Analytics & Monitoring
- **Real-time Analytics**: Traffic pattern analysis, anomaly detection, and threat scoring
- **Performance Monitoring**: CPU, memory, and system resource tracking
- **Network Analytics**: Top sources/destinations, protocol distribution, traffic trends
- **Anomaly Detection**: Machine learning-based anomaly scoring and alerts

### Web Interface & Management
- **Modern Web UI**: Responsive Flask-based interface with real-time updates
- **Role-based Access Control**: Admin and user roles with different permissions
- **User Management**: Create, edit, delete users with role assignment
- **Password Management**: Secure password change functionality with validation
- **Real-time Notifications**: Email, Slack, and webhook integration
- **System Resource Monitor**: Real-time CPU, memory, and process monitoring
- **Performance Controls**: Adjustable sampling rates and performance modes

### Performance & Reliability
- **Performance Mode**: Reduces CPU usage by 60-80% with intelligent packet sampling
- **Auto-recovery System**: Automatic health monitoring and system recovery
- **Fail-safe Mechanisms**: Automatic restart on failures with configurable thresholds
- **Resource Optimization**: Smart packet processing and selective logging

### Security & Compliance
- **NIST SP 800-94 Compliance**: Adheres to security framework guidelines
- **Comprehensive Logging**: System logs, alerts, and event tracking with rotation
- **Secure Authentication**: Password strength validation and secure login
- **Audit Trail**: Complete logging of all administrative actions

## 🏗️ Architecture

The system uses a unified architecture with advanced components:

- **Web Interface**: Modern management UI with real-time monitoring and WebSocket updates
- **Detection Engine**: Analyzes network packets against user-defined rules with performance optimizations
- **Prevention Engine**: Manages IP blocking using UFW with automatic unblocking and dwell time
- **Analytics Engine**: Advanced traffic analysis, anomaly detection, and threat intelligence
- **DPI Engine**: Deep packet inspection for payload analysis and malware detection
- **Notification System**: Multi-channel alerting (email, Slack, webhooks)
- **Auto-recovery System**: Health monitoring and automatic system recovery
- **Performance Manager**: CPU optimization and resource management

## 📦 Installation

1. **Clone and setup**:
```bash
cd to where you want it to be
git clone <repository-url> NIDPS
cd NIDPS
```

2. **Run the startup script** (recommended):
```bash
./start.sh
```

This script will:
- Create a virtual environment
- Install dependencies
- Initialize the database
- Start the application

## 🔧 Manual Installation

If you prefer manual installation:

1. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Initialize database**:
```bash
export FLASK_APP=nidps
flask db init
flask db migrate
flask db upgrade
flask seed
```

4. **Start the application**:
```bash
python run.py
```

## 🎯 Usage

### Web Interface

1. **Access**: Open http://127.0.0.1:5000 in your browser
2. **Login**: Use the default credentials
   - Admin: `admin@example.com` / `admin`
   - User: `user@example.com` / `password`

### Dashboard Features

- **Real-time Status**: Engine status, performance metrics, and system health
- **Quick Actions**: Start/stop engine, view alerts, access configuration
- **Performance Monitor**: Live CPU, memory, and resource usage
- **Alert Overview**: Recent alerts with severity indicators

### Advanced Features

- **Analytics Dashboard**: Traffic patterns, anomaly scores, top IPs, protocol distribution
- **System Monitor**: Real-time system resource monitoring with process details
- **Configuration Management**: Performance settings, notification config, recovery settings
- **Performance Controls**: Adjustable sampling rates and optimization modes
- **User Management**: Create, edit, and manage user accounts with role assignment

### User Management

The system includes comprehensive user management features:

#### **First User Registration**
- The first user to register automatically becomes an admin
- Subsequent registrations become regular users
- Admin privileges include user management, rule creation, and system configuration

#### **Admin Features**
- **User Management**: View all users, create new users, edit existing users
- **Role Assignment**: Assign admin or user roles to any account
- **User Deletion**: Remove users (with safeguards to prevent deleting the last admin)
- **System Configuration**: Access to all system settings and controls

#### **User Features**
- **Password Change**: Secure password change with current password verification
- **Profile Management**: View account information and role
- **Dashboard Access**: View alerts, logs, and analytics based on permissions

#### **Security Features**
- **Password Validation**: Minimum 8 characters required
- **Role-based Access**: Different permissions for admin and user roles
- **Account Protection**: Admins cannot delete their own account
- **Last Admin Protection**: System prevents deletion of the last admin user

### Performance Optimization

The system includes intelligent performance controls:

- **Performance Mode**: Reduces CPU usage by 60-80%
- **Packet Sampling**: Configurable rates for analytics (5-100%) and DPI (1-100%)
- **Selective Logging**: Enable/disable packet logging for optimal performance
- **Resource Monitoring**: Real-time CPU and memory usage tracking

### Detection Rules

Rules are defined in `rules.json` with the following format:
```json
{
  "rules": [
    {
      "rule_name": "Suspicious Port Scan",
      "protocol": "TCP",
      "conditions": {
        "dst_port": "22",
        "flags": "S"
      },
      "action": "block"
    }
  ]
}
```

### Notification System

Configure notifications for alerts:
- **Email**: SMTP-based email notifications
- **Slack**: Webhook integration for Slack channels
- **Webhooks**: Custom webhook endpoints
- **Real-time**: WebSocket-based live updates

## 🔧 System Requirements

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Python**: 3.7 or higher
- **UFW**: Uncomplicated Firewall (usually pre-installed on Ubuntu/Debian)
- **Network Privileges**: Root access required for packet sniffing (can be granted via capabilities)
- **Memory**: Minimum 2GB RAM (4GB recommended for high-traffic networks)
- **Storage**: 1GB free space for logs and database

## 🛠️ Performance Monitoring

### Built-in Performance Monitor

Run the performance monitoring script:
```bash
python monitor_performance.py
```

This provides:
- Real-time CPU usage monitoring
- NIDPS process resource tracking
- Performance recommendations
- System health indicators

### Performance Optimization Tips

1. **Low CPU Usage**: Keep performance mode ON, sampling rates low (5-10%)
2. **More Detailed Data**: Increase sampling rates in Configuration → Performance Settings
3. **Full Logging**: Enable "Log All Packets" for detailed packet analysis
4. **Monitor Resources**: Use the performance script to track system impact

## 🔍 Troubleshooting

### Common Issues

1. **High CPU Usage**: 
   - Enable Performance Mode in Configuration
   - Reduce packet sampling rates
   - Disable packet logging if not needed
   - Use the performance monitor script

2. **Permission Denied for Packet Sniffing**: 
   - Grant capabilities: `sudo setcap cap_net_raw=eip $(which python3)`
   - Or run with sudo: `sudo python run.py`
   - Some detection features may be limited without privileges

3. **UFW Not Available**:
   - Install UFW: `sudo apt-get install ufw`
   - Enable UFW: `sudo ufw enable`

4. **Import Errors**: 
   - Ensure the virtual environment is activated
   - Run `pip install -r requirements.txt`

5. **Database Errors**: 
   - Run the database initialization commands
   - Check file permissions for the database file

### Logs and Monitoring

- **Application Logs**: `logs/nidps.log`
- **System Logs**: Available through the web interface
- **Performance Logs**: Real-time monitoring via web interface
- **UFW Logs**: `sudo ufw status verbose`

## 🔒 Security Considerations

- The application runs as a normal user for security
- UFW integration provides firewall protection
- Role-based access control restricts administrative functions
- All sensitive operations are logged with audit trails
- IP blocking has automatic expiration to prevent permanent blocks
- Performance optimizations maintain security while reducing resource usage
- Auto-recovery system ensures continuous operation

## 🚀 Development

### Project Structure
```
NIDPS/
├── nidps/
│   ├── core/           # Core engine components
│   │   ├── engine.py   # Main engine with performance optimizations
│   │   ├── analytics.py # Advanced analytics and anomaly detection
│   │   ├── dpi.py      # Deep packet inspection
│   │   ├── notifications.py # Multi-channel notification system
│   │   └── recovery.py # Auto-recovery and health monitoring
│   ├── web/            # Web interface and API routes
│   ├── auth/           # Authentication and authorization
│   └── templates/      # HTML templates with real-time updates
├── logs/               # Log files with rotation
├── backups/            # Configuration backups
├── rules.json          # Detection rules
├── run.py              # Main application entry point
├── start.sh            # Startup script
├── monitor_performance.py # Performance monitoring script
└── requirements.txt    # Python dependencies
```

### Adding New Rules

1. Edit `rules.json` or use the web interface
2. Rules are applied immediately when the engine is running
3. Performance mode maintains rule checking while optimizing other operations

### Customizing Detection

Modify the detection engine in `nidps/core/detection.py` to add new detection methods.

### Performance Tuning

Adjust performance settings in the web interface:
- **Analytics Sampling**: 5-100% (lower = less CPU)
- **DPI Sampling**: 1-100% (lower = less CPU)
- **Packet Logging**: Enable/disable for detailed logs
- **Performance Mode**: Enable for maximum optimization

### UFW Configuration

The system automatically manages UFW rules. You can view current rules with:
```bash
sudo ufw status numbered
```

## 📊 Performance Metrics

The system provides comprehensive performance metrics:

- **CPU Usage**: Real-time monitoring with optimization recommendations
- **Memory Usage**: Process and system memory tracking
- **Packet Processing**: Packets per second and processing efficiency
- **Detection Accuracy**: Alert statistics and false positive rates
- **System Health**: Overall system status and recovery metrics

## 🔄 Recent Updates

### Version 2.0 - Performance & Analytics Update
- ✅ **Performance Mode**: 60-80% CPU reduction with intelligent packet sampling
- ✅ **Advanced Analytics**: Real-time traffic analysis and anomaly detection
- ✅ **System Monitor**: Live resource monitoring and process tracking
- ✅ **Notification System**: Multi-channel alerting (email, Slack, webhooks)
- ✅ **Auto-recovery**: Health monitoring and automatic system recovery
- ✅ **DPI Engine**: Deep packet inspection for advanced threat detection
- ✅ **WebSocket Updates**: Real-time web interface updates
- ✅ **Performance Controls**: Adjustable sampling rates and optimization modes
- ✅ **Enhanced Security**: Password strength validation and secure authentication
- ✅ **Resource Optimization**: Smart packet processing and selective logging
- ✅ **User Management**: Complete user administration with role-based access control
- ✅ **Password Management**: Secure password change functionality with validation

## 📄 License

This project is licensed under the MIT License. 