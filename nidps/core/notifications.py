import smtplib
import requests
import json
import logging
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

class NotificationManager:
    def __init__(self, config_file="notification_config.json", logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.config = self.load_config(config_file)
        self.notification_queue = []
        self.queue_lock = threading.Lock()
        self.notification_thread = threading.Thread(target=self._process_notifications, daemon=True)
        self.notification_thread.start()
        
    def load_config(self, config_file):
        """Load notification configuration"""
        default_config = {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_email": "",
                "to_emails": []
            },
            "webhook": {
                "enabled": False,
                "url": "",
                "headers": {}
            },
            "slack": {
                "enabled": False,
                "webhook_url": ""
            },
            "severity_threshold": "medium",
            "rate_limit": {
                "max_notifications_per_hour": 50,
                "cooldown_minutes": 5
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
        except Exception as e:
            self.logger.error(f"Error loading notification config: {e}")
        
        return default_config
    
    def send_notification(self, alert_data, notification_type="all"):
        """Queue a notification for sending"""
        with self.queue_lock:
            notification = {
                'timestamp': datetime.now(),
                'alert_data': alert_data,
                'type': notification_type
            }
            self.notification_queue.append(notification)
    
    def _process_notifications(self):
        """Background thread to process notifications"""
        while True:
            try:
                with self.queue_lock:
                    if self.notification_queue:
                        notification = self.notification_queue.pop(0)
                        self._send_notification(notification)
                
                time.sleep(1)  # Check every second
            except Exception as e:
                self.logger.error(f"Error processing notifications: {e}")
                time.sleep(5)
    
    def _send_notification(self, notification):
        """Send a notification through configured channels"""
        alert_data = notification['alert_data']
        severity = alert_data.get('severity', 'medium')
        
        # Check severity threshold
        severity_levels = {'low': 1, 'medium': 2, 'high': 3}
        threshold_level = severity_levels.get(self.config['severity_threshold'], 2)
        alert_level = severity_levels.get(severity, 1)
        
        if alert_level < threshold_level:
            return
        
        # Create notification message
        message = self._create_notification_message(alert_data)
        
        # Send through different channels
        if self.config['email']['enabled']:
            self._send_email_notification(message, alert_data)
        
        if self.config['webhook']['enabled']:
            self._send_webhook_notification(message, alert_data)
        
        if self.config['slack']['enabled']:
            self._send_slack_notification(message, alert_data)
    
    def _create_notification_message(self, alert_data):
        """Create a formatted notification message"""
        severity = alert_data.get('severity', 'medium').upper()
        rule_name = alert_data.get('details', {}).get('rule_name', 'Unknown Rule')
        source_ip = alert_data.get('source_ip', 'Unknown')
        message = alert_data.get('message', 'No message')
        timestamp = alert_data.get('timestamp', 'Unknown')
        
        return {
            'title': f"NIDPS Alert: {severity} - {rule_name}",
            'body': f"""
🚨 **NIDPS Security Alert**

**Severity:** {severity}
**Rule:** {rule_name}
**Source IP:** {source_ip}
**Time:** {timestamp}
**Message:** {message}

**Action Required:** {'BLOCK' if alert_data.get('action') == 'block' else 'MONITOR'}
            """.strip(),
            'severity': severity,
            'data': alert_data
        }
    
    def _send_email_notification(self, message, alert_data):
        """Send email notification"""
        try:
            email_config = self.config['email']
            if not email_config['username'] or not email_config['password']:
                return
            
            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = ', '.join(email_config['to_emails'])
            msg['Subject'] = message['title']
            
            msg.attach(MIMEText(message['body'], 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email notification sent for alert: {alert_data.get('details', {}).get('rule_name')}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
    
    def _send_webhook_notification(self, message, alert_data):
        """Send webhook notification"""
        try:
            webhook_config = self.config['webhook']
            
            payload = {
                'timestamp': datetime.now().isoformat(),
                'title': message['title'],
                'message': message['body'],
                'severity': message['severity'],
                'alert_data': alert_data
            }
            
            response = requests.post(
                webhook_config['url'],
                json=payload,
                headers=webhook_config['headers'],
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook notification sent for alert: {alert_data.get('details', {}).get('rule_name')}")
            else:
                self.logger.error(f"Webhook notification failed with status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
    
    def _send_slack_notification(self, message, alert_data):
        """Send Slack notification"""
        try:
            slack_config = self.config['slack']
            
            # Color coding based on severity
            color_map = {'LOW': '#36a64f', 'MEDIUM': '#ff9500', 'HIGH': '#ff0000'}
            color = color_map.get(message['severity'], '#36a64f')
            
            slack_payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": message['title'],
                        "text": message['body'],
                        "fields": [
                            {
                                "title": "Source IP",
                                "value": alert_data.get('source_ip', 'Unknown'),
                                "short": True
                            },
                            {
                                "title": "Action",
                                "value": alert_data.get('action', 'log').upper(),
                                "short": True
                            }
                        ],
                        "footer": "NIDPS Security System",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                slack_config['webhook_url'],
                json=slack_payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Slack notification sent for alert: {alert_data.get('details', {}).get('rule_name')}")
            else:
                self.logger.error(f"Slack notification failed with status {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
    
    def update_config(self, new_config):
        """Update notification configuration"""
        self.config.update(new_config)
        try:
            with open("notification_config.json", 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.info("Notification configuration updated")
        except Exception as e:
            self.logger.error(f"Failed to save notification config: {e}")

if __name__ == "__main__":
    # Test notification system
    notification_manager = NotificationManager()
    
    test_alert = {
        'severity': 'high',
        'source_ip': '192.168.1.100',
        'message': 'Test alert message',
        'action': 'block',
        'details': {'rule_name': 'Test Rule'},
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    notification_manager.send_notification(test_alert)
    print("Test notification queued") 