import threading
import time
import logging
import subprocess
import os
import signal
import psutil
from datetime import datetime, timedelta
import json

class AutoRecoveryManager:
    def __init__(self, engine_instance, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.engine = engine_instance
        self.monitoring_active = False
        self.health_check_thread = None
        self.recovery_config = self.load_recovery_config()
        self.health_history = []
        self.failure_count = 0
        self.last_recovery_time = None
        
    def load_recovery_config(self):
        """Load auto-recovery configuration"""
        default_config = {
            "enabled": True,
            "health_check_interval": 30,  # seconds
            "max_failures_before_recovery": 3,
            "recovery_cooldown": 300,  # 5 minutes
            "max_recovery_attempts": 5,
            "backup_rules_on_recovery": True,
            "system_resource_limits": {
                "max_cpu_percent": 80,
                "max_memory_percent": 85,
                "max_disk_percent": 90
            },
            "recovery_actions": [
                "restart_engine",
                "restart_sniffer",
                "clear_memory",
                "backup_config"
            ]
        }
        
        try:
            if os.path.exists("recovery_config.json"):
                with open("recovery_config.json", 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
        except Exception as e:
            self.logger.error(f"Error loading recovery config: {e}")
        
        return default_config
    
    def start_monitoring(self):
        """Start the health monitoring system"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.health_check_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
        self.health_check_thread.start()
        self.logger.info("Auto-recovery monitoring started")
    
    def stop_monitoring(self):
        """Stop the health monitoring system"""
        self.monitoring_active = False
        if self.health_check_thread:
            self.health_check_thread.join(timeout=5)
        self.logger.info("Auto-recovery monitoring stopped")
    
    def _health_monitor_loop(self):
        """Main health monitoring loop"""
        while self.monitoring_active:
            try:
                health_status = self._check_system_health()
                self.health_history.append({
                    'timestamp': datetime.now(),
                    'status': health_status
                })
                
                # Keep only last 100 health checks
                if len(self.health_history) > 100:
                    self.health_history.pop(0)
                
                # Check if recovery is needed
                if health_status['needs_recovery']:
                    self._trigger_recovery(health_status)
                
                time.sleep(self.recovery_config['health_check_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in health monitoring: {e}")
                time.sleep(10)
    
    def _check_system_health(self):
        """Check overall system health"""
        health_status = {
            'timestamp': datetime.now(),
            'engine_running': False,
            'sniffer_active': False,
            'memory_usage': 0,
            'cpu_usage': 0,
            'disk_usage': 0,
            'needs_recovery': False,
            'issues': []
        }
        
        try:
            # Check engine status
            health_status['engine_running'] = self.engine.is_running
            
            # Check sniffer status
            if hasattr(self.engine, 'sniffer') and self.engine.sniffer:
                health_status['sniffer_active'] = self.engine.sniffer.is_alive()
            
            # Check system resources
            health_status['memory_usage'] = psutil.virtual_memory().percent
            health_status['cpu_usage'] = psutil.cpu_percent(interval=1)
            health_status['disk_usage'] = psutil.disk_usage('/').percent
            
            # Check for issues
            if not health_status['engine_running']:
                health_status['issues'].append("Engine not running")
                health_status['needs_recovery'] = True
            
            if not health_status['sniffer_active'] and health_status['engine_running']:
                health_status['issues'].append("Sniffer not active")
                health_status['needs_recovery'] = True
            
            if health_status['memory_usage'] > self.recovery_config['system_resource_limits']['max_memory_percent']:
                health_status['issues'].append(f"High memory usage: {health_status['memory_usage']}%")
                health_status['needs_recovery'] = True
            
            if health_status['cpu_usage'] > self.recovery_config['system_resource_limits']['max_cpu_percent']:
                health_status['issues'].append(f"High CPU usage: {health_status['cpu_usage']}%")
            
            if health_status['disk_usage'] > self.recovery_config['system_resource_limits']['max_disk_percent']:
                health_status['issues'].append(f"High disk usage: {health_status['disk_usage']}%")
            
        except Exception as e:
            health_status['issues'].append(f"Health check error: {e}")
            health_status['needs_recovery'] = True
        
        return health_status
    
    def _trigger_recovery(self, health_status):
        """Trigger auto-recovery actions"""
        # Check cooldown
        if self.last_recovery_time:
            time_since_recovery = (datetime.now() - self.last_recovery_time).total_seconds()
            if time_since_recovery < self.recovery_config['recovery_cooldown']:
                return
        
        # Check max recovery attempts
        if self.failure_count >= self.recovery_config['max_recovery_attempts']:
            self.logger.error("Maximum recovery attempts reached. Manual intervention required.")
            return
        
        self.logger.warning(f"Auto-recovery triggered due to: {', '.join(health_status['issues'])}")
        
        try:
            # Backup configuration if enabled
            if self.recovery_config['backup_rules_on_recovery']:
                self._backup_configuration()
            
            # Perform recovery actions
            for action in self.recovery_config['recovery_actions']:
                if action == "restart_engine":
                    self._restart_engine()
                elif action == "restart_sniffer":
                    self._restart_sniffer()
                elif action == "clear_memory":
                    self._clear_memory()
                elif action == "backup_config":
                    self._backup_configuration()
            
            self.last_recovery_time = datetime.now()
            self.failure_count += 1
            
            self.logger.info("Auto-recovery completed successfully")
            
        except Exception as e:
            self.logger.error(f"Auto-recovery failed: {e}")
    
    def _restart_engine(self):
        """Restart the NIDPS engine"""
        try:
            self.logger.info("Restarting NIDPS engine...")
            
            # Stop current engine
            if self.engine.is_running:
                self.engine.stop()
                time.sleep(2)
            
            # Start engine
            self.engine.start()
            time.sleep(5)  # Wait for startup
            
            if self.engine.is_running:
                self.logger.info("Engine restart successful")
            else:
                raise Exception("Engine failed to start after restart")
                
        except Exception as e:
            self.logger.error(f"Engine restart failed: {e}")
            raise
    
    def _restart_sniffer(self):
        """Restart the packet sniffer"""
        try:
            self.logger.info("Restarting packet sniffer...")
            
            if hasattr(self.engine, 'sniffer') and self.engine.sniffer:
                # Stop current sniffer
                self.engine.sniffer.stop()
                time.sleep(1)
                
                # Create new sniffer
                from nidps.core.sniffer import PacketSniffer
                self.engine.sniffer = PacketSniffer(
                    packet_callback=self.engine.packet_callback,
                    logger=self.engine.logger
                )
                self.engine.sniffer.start()
                
                self.logger.info("Sniffer restart successful")
                
        except Exception as e:
            self.logger.error(f"Sniffer restart failed: {e}")
            raise
    
    def _clear_memory(self):
        """Clear memory and garbage collect"""
        try:
            import gc
            gc.collect()
            self.logger.info("Memory cleared")
        except Exception as e:
            self.logger.error(f"Memory clearing failed: {e}")
    
    def _backup_configuration(self):
        """Backup current configuration"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = "backups"
            
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            # Backup rules
            if os.path.exists("rules.json"):
                backup_path = f"{backup_dir}/rules_{timestamp}.json"
                with open("rules.json", 'r') as src, open(backup_path, 'w') as dst:
                    dst.write(src.read())
            
            # Backup config
            if os.path.exists("config.py"):
                backup_path = f"{backup_dir}/config_{timestamp}.py"
                with open("config.py", 'r') as src, open(backup_path, 'w') as dst:
                    dst.write(src.read())
            
            self.logger.info(f"Configuration backed up to {backup_dir}")
            
        except Exception as e:
            self.logger.error(f"Configuration backup failed: {e}")
    
    def get_health_status(self):
        """Get current health status"""
        if self.health_history:
            return self.health_history[-1]
        return self._check_system_health()
    
    def get_health_history(self):
        """Get health history"""
        return self.health_history
    
    def reset_failure_count(self):
        """Reset failure count (called after successful manual recovery)"""
        self.failure_count = 0
        self.logger.info("Failure count reset")
    
    def update_recovery_config(self, new_config):
        """Update recovery configuration"""
        self.recovery_config.update(new_config)
        try:
            with open("recovery_config.json", 'w') as f:
                json.dump(self.recovery_config, f, indent=4)
            self.logger.info("Recovery configuration updated")
        except Exception as e:
            self.logger.error(f"Failed to save recovery config: {e}")

if __name__ == "__main__":
    # Test auto-recovery system
    from nidps.core.engine import NIDPSEngine
    
    engine = NIDPSEngine()
    recovery_manager = AutoRecoveryManager(engine)
    
    print("Starting auto-recovery monitoring...")
    recovery_manager.start_monitoring()
    
    try:
        while True:
            time.sleep(10)
            health = recovery_manager.get_health_status()
            print(f"Health: {health['needs_recovery']} - Issues: {health['issues']}")
    except KeyboardInterrupt:
        print("Stopping auto-recovery monitoring...")
        recovery_manager.stop_monitoring() 