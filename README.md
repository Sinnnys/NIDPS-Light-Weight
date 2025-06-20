# Network Intrusion Detection and Prevention System (NIDPS)

A lightweight Network Intrusion Detection and Prevention System for Linux with real-time monitoring, detection, prevention, and a web-based management interface.

## Features

- **Real-time Packet Analysis**: Monitors network traffic using Scapy
- **Rule-based Detection**: JSON-based detection rules with customizable conditions
- **UFW Integration**: Uses UFW (Uncomplicated Firewall) for IP blocking with configurable dwell time
- **Web Interface**: Modern Flask-based web UI with real-time alerts and system logs
- **Role-based Access Control**: Admin and user roles with different permissions
- **Comprehensive Logging**: System logs, alerts, and event tracking
- **Unified Architecture**: Single application that runs everything together
- **NIST SP 800-94 Compliance**: Adheres to security framework guidelines

## Architecture

The system uses a unified architecture where everything runs in one application:

- **Web Interface**: Provides the management UI and real-time monitoring
- **Detection Engine**: Analyzes network packets against user-defined rules
- **Prevention Engine**: Manages IP blocking using UFW with automatic unblocking
- **Logging System**: Comprehensive logging of all system events

## Installation

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

## Manual Installation

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

## Usage

### Web Interface

1. **Access**: Open http://127.0.0.1:5000 in your browser
2. **Login**: Use the default credentials
   - Admin: `admin@example.com` / `admin`
   - User: `user@example.com` / `password`

### Features

- **Dashboard**: Real-time system status, engine controls, and quick actions
- **Alerts**: Real-time network intrusion alerts with source IP information
- **System Logs**: View all system logs with automatic refresh
- **Rules**: Manage detection rules (Admin only)
- **Blocked IPs**: View and manage blocked IP addresses with time remaining (Admin only)

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

### UFW Integration

The system uses UFW for IP blocking:
- Automatically blocks IPs when rules are triggered
- Configurable dwell time (default: 30 minutes)
- Automatic unblocking after dwell time expires
- Manual unblocking through the web interface

## System Requirements

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Python**: 3.7 or higher
- **UFW**: Uncomplicated Firewall (usually pre-installed on Ubuntu/Debian)
- **Network Privileges**: Root access required for packet sniffing (can be granted via capabilities)

## Troubleshooting

### Common Issues

1. **Permission Denied for Packet Sniffing**: 
   - The application will show a warning but continue running
   - Some detection features may be limited without root privileges
   - You can still manage rules and view logs

2. **UFW Not Available**:
   - Install UFW: `sudo apt-get install ufw`
   - Enable UFW: `sudo ufw enable`

3. **Import Errors**: 
   - Ensure the virtual environment is activated
   - Run `pip install -r requirements.txt`

4. **Database Errors**: 
   - Run the database initialization commands
   - Check file permissions for the database file

### Logs

- **Application Logs**: `logs/nidps.log`
- **System Logs**: Available through the web interface
- **UFW Logs**: `sudo ufw status verbose`

## Security Considerations

- The application runs as a normal user for security
- UFW integration provides firewall protection
- Role-based access control restricts administrative functions
- All sensitive operations are logged
- IP blocking has automatic expiration to prevent permanent blocks

## Development

### Project Structure
```
NIDPS/
├── nidps/
│   ├── core/           # Core engine components
│   ├── web/            # Web interface
│   ├── auth/           # Authentication
│   └── templates/      # HTML templates
├── logs/               # Log files
├── rules.json          # Detection rules
├── run.py              # Main application entry point
├── start.sh            # Startup script
└── requirements.txt    # Python dependencies
```

### Adding New Rules

1. Edit `rules.json` or use the web interface
2. Rules are applied immediately when the engine is running

### Customizing Detection

Modify the detection engine in `nidps/core/detection.py` to add new detection methods.

### UFW Configuration

The system automatically manages UFW rules. You can view current rules with:
```bash
sudo ufw status numbered
```

## License

This project is licensed under the MIT License. 