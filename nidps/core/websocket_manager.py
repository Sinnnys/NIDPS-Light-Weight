import json
import logging
import threading
import time
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room

class WebSocketManager:
    def __init__(self, app=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.socketio = None
        self.update_thread = None
        self.updates_active = False
        self.connected_clients = set()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize WebSocket with Flask app"""
        self.socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
        self._register_events()
    
    def _register_events(self):
        """Register WebSocket events"""
        if not self.socketio:
            return
        
        @self.socketio.on('connect')
        def handle_connect():
            self.logger.info(f"Client connected: {request.sid}")
            self.connected_clients.add(request.sid)
            emit('status', {'message': 'Connected to NIDPS real-time updates'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.logger.info(f"Client disconnected: {request.sid}")
            self.connected_clients.discard(request.sid)
        
        @self.socketio.on('join_dashboard')
        def handle_join_dashboard():
            join_room('dashboard')
            emit('status', {'message': 'Joined dashboard room'})
        
        @self.socketio.on('join_alerts')
        def handle_join_alerts():
            join_room('alerts')
            emit('status', {'message': 'Joined alerts room'})
        
        @self.socketio.on('join_logs')
        def handle_join_logs():
            join_room('logs')
            emit('status', {'message': 'Joined logs room'})
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            room = data.get('room')
            if room:
                leave_room(room)
                emit('status', {'message': f'Left room: {room}'})
    
    def start_updates(self):
        """Start real-time updates"""
        if self.updates_active:
            return
        
        self.updates_active = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        self.logger.info("WebSocket real-time updates started")
    
    def stop_updates(self):
        """Stop real-time updates"""
        self.updates_active = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        self.logger.info("WebSocket real-time updates stopped")
    
    def _update_loop(self):
        """Main update loop"""
        while self.updates_active:
            try:
                # Send periodic updates
                self._send_dashboard_updates()
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                self.logger.error(f"Error in WebSocket update loop: {e}")
                time.sleep(10)
    
    def _send_dashboard_updates(self):
        """Send dashboard updates"""
        if not self.socketio:
            return
        
        try:
            # Get current statistics (this would come from the engine)
            stats = {
                'timestamp': datetime.now().isoformat(),
                'connected_clients': len(self.connected_clients),
                'system_status': 'running'
            }
            
            self.socketio.emit('dashboard_update', stats, room='dashboard')
            
        except Exception as e:
            self.logger.error(f"Error sending dashboard updates: {e}")
    
    def send_alert(self, alert_data):
        """Send real-time alert to connected clients"""
        if not self.socketio:
            return
        
        try:
            alert_message = {
                'timestamp': datetime.now().isoformat(),
                'type': 'alert',
                'data': alert_data
            }
            
            self.socketio.emit('new_alert', alert_message, room='alerts')
            self.logger.info(f"Alert sent via WebSocket: {alert_data.get('message', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"Error sending alert via WebSocket: {e}")
    
    def send_log_update(self, log_data):
        """Send log updates to connected clients"""
        if not self.socketio:
            return
        
        try:
            log_message = {
                'timestamp': datetime.now().isoformat(),
                'type': 'log',
                'data': log_data
            }
            
            self.socketio.emit('log_update', log_message, room='logs')
            
        except Exception as e:
            self.logger.error(f"Error sending log update via WebSocket: {e}")
    
    def send_engine_status(self, status_data):
        """Send engine status updates"""
        if not self.socketio:
            return
        
        try:
            status_message = {
                'timestamp': datetime.now().isoformat(),
                'type': 'engine_status',
                'data': status_data
            }
            
            self.socketio.emit('engine_status', status_message, room='dashboard')
            
        except Exception as e:
            self.logger.error(f"Error sending engine status via WebSocket: {e}")
    
    def send_analytics_update(self, analytics_data):
        """Send analytics updates"""
        if not self.socketio:
            return
        
        try:
            analytics_message = {
                'timestamp': datetime.now().isoformat(),
                'type': 'analytics',
                'data': analytics_data
            }
            
            self.socketio.emit('analytics_update', analytics_message, room='dashboard')
            
        except Exception as e:
            self.logger.error(f"Error sending analytics update via WebSocket: {e}")
    
    def broadcast_message(self, message_type, data, room=None):
        """Broadcast message to all clients or specific room"""
        if not self.socketio:
            return
        
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'type': message_type,
                'data': data
            }
            
            if room:
                self.socketio.emit('broadcast', message, room=room)
            else:
                self.socketio.emit('broadcast', message)
                
        except Exception as e:
            self.logger.error(f"Error broadcasting message: {e}")
    
    def get_connected_clients_count(self):
        """Get number of connected clients"""
        return len(self.connected_clients)
    
    def run_socketio(self, host='0.0.0.0', port=5000, debug=False):
        """Run the SocketIO server"""
        if self.socketio:
            self.socketio.run(self.socketio.app, host=host, port=port, debug=debug)

# Global WebSocket manager instance
websocket_manager = WebSocketManager()

if __name__ == "__main__":
    # Test WebSocket manager
    from flask import Flask
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    websocket_manager.init_app(app)
    websocket_manager.start_updates()
    
    print("WebSocket manager started")
    
    # Test sending an alert
    test_alert = {
        'severity': 'high',
        'message': 'Test alert message',
        'source_ip': '192.168.1.100'
    }
    
    websocket_manager.send_alert(test_alert)
    print("Test alert sent") 