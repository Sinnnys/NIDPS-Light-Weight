from flask import render_template, current_app, flash, redirect, url_for, jsonify, session, request
from nidps.web import bp
from flask_login import login_required, current_user
from nidps.auth.decorators import admin_required
from nidps.web.forms import RuleForm
from nidps.core.engine import NIDPSEngine
import json
import os
import psutil
import time
from datetime import datetime, timedelta

# Global engine instance
engine = None

def get_engine():
    """Get the global engine instance or create a new one if needed."""
    global engine
    if engine is None:
        engine = NIDPSEngine()
    return engine

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    """Main dashboard page."""
    return render_template('index.html', title='Home')

@bp.route('/dashboard')
@login_required
def dashboard():
    engine = get_engine()
    status = "Running" if engine.is_running else "Not Running"
    stats = engine.get_statistics()
    return render_template('dashboard.html', title='Dashboard', status=status, stats=stats)

@bp.route('/alerts')
@login_required
def alerts():
    """Alerts page."""
    # Get alerts from the engine
    engine = get_engine()
    alerts_list = engine.get_alerts()
    return render_template('alerts.html', title='Alerts', alerts=alerts_list)

@bp.route('/logs')
@login_required
def logs():
    """Logs page."""
    # Get logs from the engine
    engine = get_engine()
    logs_list = engine.get_logs()
    return render_template('logs.html', title='System Logs', logs=logs_list)

@bp.route('/blocked_ips')
@admin_required
def blocked_ips():
    """Blocked IPs page."""
    # Get blocked IPs from the engine
    engine = get_engine()
    blocked_list = engine.get_blocked_ips()
    return render_template('blocked_ips.html', title='Blocked IPs', blocked_ips=blocked_list)

@bp.route('/unblock_ip/<ip>')
@admin_required
def unblock_ip(ip):
    engine = get_engine()
    if engine.prevention_engine.unblock_ip(ip):
        flash(f'IP {ip} has been unblocked.')
    else:
        flash(f'Failed to unblock IP {ip}.')
    return redirect(url_for('web.blocked_ips'))

@bp.route('/rules', methods=['GET', 'POST'])
@admin_required
def rules():
    engine = get_engine()
    
    form = RuleForm()
    if form.validate_on_submit():
        # Create new rule object
        conditions = {}
        if form.conditions.data:
            for item in form.conditions.data.split(','):
                if '=' in item:
                    k, v = item.split('=', 1)
                    conditions[k.strip()] = v.strip()
        
        new_rule = {
            "rule_name": form.rule_name.data,
            "protocol": form.protocol.data,
            "conditions": conditions,
            "action": form.action.data
        }
        
        # Add the new rule
        engine.add_rule(new_rule)
        
        # Save back to file
        rules_path = os.path.join(os.path.dirname(current_app.root_path), '..', 'rules.json')
        with open(rules_path, 'w') as f:
            json.dump({"rules": engine.get_rules()}, f, indent=4)

        # Reload rules in the engine to ensure consistency
        engine.reload_rules()

        flash('Rule added successfully!')
        return redirect(url_for('web.rules'))

    # Get current rules (this will reload from file)
    all_rules = engine.get_rules()
    return render_template('rules.html', title='Detection Rules', rules=all_rules, form=form)

@bp.route('/analytics')
@login_required
def analytics_page():
    """Analytics page."""
    # Get analytics data if available
    analytics_data = {}
    try:
        engine = get_engine()
        stats = engine.get_statistics()
        analytics_data = {
            'traffic_patterns': stats.get('traffic_patterns', {}),
            'anomaly_scores': stats.get('anomaly_scores', {}),
            'top_sources': stats.get('top_sources', []),
            'top_destinations': stats.get('top_destinations', [])
        }
    except:
        pass
    
    return render_template('analytics.html', analytics=analytics_data)

@bp.route('/system_monitor')
@login_required
def system_monitor():
    """System resource monitoring page."""
    return render_template('system_monitor.html')

@bp.route('/configuration')
@login_required
def configuration():
    """Configuration page."""
    return render_template('configuration.html')

# API Routes
@bp.route('/api/alerts')
@login_required
def api_alerts():
    """API endpoint to get alerts."""
    try:
        engine = get_engine()
        alerts = engine.get_alerts()
        return jsonify(alerts[-20:])  # Last 20 alerts
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/logs')
@login_required
def api_logs():
    """API endpoint to get logs."""
    try:
        engine = get_engine()
        logs = engine.get_logs()
        return jsonify(logs[-50:])  # Last 50 logs
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/start_engine', methods=['POST'])
@login_required
def api_start_engine():
    """API endpoint to start the NIDPS engine."""
    global engine
    
    try:
        if engine is None:
            engine = NIDPSEngine()
        
        if not engine.is_running:
            engine.start()
            return jsonify({'status': 'success', 'message': 'Engine started successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Engine is already running'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to start engine: {str(e)}'})

@bp.route('/api/stop_engine', methods=['POST'])
@login_required
def api_stop_engine():
    """API endpoint to stop the NIDPS engine."""
    global engine
    
    try:
        if engine and engine.is_running:
            engine.stop()
            return jsonify({'status': 'success', 'message': 'Engine stopped successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Engine is not running'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to stop engine: {str(e)}'})

@bp.route('/api/engine_status')
@login_required
def api_engine_status():
    """API endpoint to get engine status."""
    try:
        engine = get_engine()
        status = {
            'running': engine.is_running,
            'uptime': time.time() - engine.start_time if hasattr(engine, 'start_time') else 0,
            'packets_processed': getattr(engine, 'packet_counter', 0),
            'alerts_count': len(engine.alerts),
            'blocked_ips_count': len(engine.get_blocked_ips()),
            'performance_mode': getattr(engine, 'performance_mode', False),
            'features': {
                'detection': True,
                'prevention': True,
                'analytics': True,
                'dpi': True,
                'notifications': True,
                'auto_recovery': True
            }
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/system_stats')
@login_required
def api_system_stats():
    """API endpoint to get system statistics."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        # Memory usage
        memory = psutil.virtual_memory()
        # Disk usage
        disk = psutil.disk_usage('/')
        # Network I/O
        network = psutil.net_io_counters()
        stats = {
            'cpu': {
                'percent': cpu_percent,
                'count': psutil.cpu_count(),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'timestamp': time.time(),
            # Flat fields for frontend compatibility
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'network_percent': 0  # Not a percent, but placeholder for compatibility
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/nidps_stats')
@login_required
def api_nidps_stats():
    """API endpoint to get NIDPS-specific statistics."""
    try:
        engine = get_engine()
        stats = engine.get_statistics()
        
        # Add performance stats
        performance_stats = {
            'packet_counter': getattr(engine, 'packet_counter', 0),
            'performance_mode': getattr(engine, 'performance_mode', False),
            'packet_sampling_rate': getattr(engine, 'packet_sampling_rate', 1.0),
            'dpi_sampling_rate': getattr(engine, 'dpi_sampling_rate', 1.0),
            'log_all_packets': getattr(engine, 'log_all_packets', True),
            'uptime': time.time() - getattr(engine, 'start_time', time.time())
        }
        
        # Combine stats
        combined_stats = {
            'engine_stats': stats,
            'performance_stats': performance_stats,
            'alerts_summary': {
                'total': len(engine.alerts),
                'high': len([a for a in engine.alerts if a.get('severity') == 'high']),
                'medium': len([a for a in engine.alerts if a.get('severity') == 'medium']),
                'low': len([a for a in engine.alerts if a.get('severity') == 'low'])
            },
            'blocked_ips': len(engine.get_blocked_ips()),
            'rules_count': len(engine.get_rules())
        }
        
        return jsonify(combined_stats)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/process_list')
@login_required
def api_process_list():
    """API endpoint to get list of running processes."""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        
        return jsonify(processes[:20])  # Top 20 processes
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/analytics_data')
@login_required
def api_analytics_data():
    """API endpoint to get analytics data."""
    try:
        engine = get_engine()
        stats = engine.get_statistics()
        
        analytics_data = {
            'traffic_patterns': stats.get('traffic_patterns', {}),
            'anomaly_scores': stats.get('anomaly_scores', {}),
            'top_sources': stats.get('top_sources', []),
            'top_destinations': stats.get('top_destinations', []),
            'threat_analysis': stats.get('threat_analysis', {}),
            'performance_metrics': {
                'packets_processed': getattr(engine, 'packet_counter', 0),
                'sampling_rate': getattr(engine, 'packet_sampling_rate', 1.0),
                'performance_mode': getattr(engine, 'performance_mode', False)
            }
        }
        
        return jsonify(analytics_data)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/block_ip', methods=['POST'])
@login_required
def api_block_ip():
    """API endpoint to block an IP address."""
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({'status': 'error', 'message': 'IP address is required'})
        
        engine = get_engine()
        if engine.prevention_engine.block_ip(ip_address):
            return jsonify({'status': 'success', 'message': f'IP {ip_address} blocked successfully'})
        else:
            return jsonify({'status': 'error', 'message': f'Failed to block IP {ip_address}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/unblock_ip', methods=['POST'])
@login_required
def api_unblock_ip():
    """API endpoint to unblock an IP address."""
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({'status': 'error', 'message': 'IP address is required'})
        
        engine = get_engine()
        if engine.prevention_engine.unblock_ip(ip_address):
            return jsonify({'status': 'success', 'message': f'IP {ip_address} unblocked successfully'})
        else:
            return jsonify({'status': 'error', 'message': f'Failed to unblock IP {ip_address}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/delete_rule/<rule_name>')
@admin_required
def delete_rule(rule_name):
    """Delete a detection rule."""
    try:
        engine = get_engine()
        rules = engine.get_rules()
        
        # Find and remove the rule
        rules = [rule for rule in rules if rule.get('rule_name') != rule_name]
        
        # Save back to file
        rules_path = os.path.join(os.path.dirname(current_app.root_path), '..', 'rules.json')
        with open(rules_path, 'w') as f:
            json.dump({"rules": rules}, f, indent=4)
        
        # Reload rules in the engine to ensure consistency
        engine.reload_rules()
        
        flash(f'Rule "{rule_name}" deleted successfully!')
    except Exception as e:
        flash(f'Failed to delete rule: {str(e)}')
    
    return redirect(url_for('web.rules'))

@bp.route('/api/performance_stats')
@login_required
def api_performance_stats():
    """API endpoint to get performance statistics."""
    try:
        engine = get_engine()
        
        stats = {
            'performance_mode': getattr(engine, 'performance_mode', False),
            'packet_sampling_rate': getattr(engine, 'packet_sampling_rate', 1.0),
            'dpi_sampling_rate': getattr(engine, 'dpi_sampling_rate', 1.0),
            'log_all_packets': getattr(engine, 'log_all_packets', True),
            'packet_counter': getattr(engine, 'packet_counter', 0),
            'uptime': time.time() - getattr(engine, 'start_time', time.time()),
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/set_performance_mode', methods=['POST'])
@login_required
def api_set_performance_mode():
    """API endpoint to set performance mode."""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        engine = get_engine()
        engine.set_performance_mode(enabled)
        
        return jsonify({'status': 'success', 'message': f'Performance mode {"enabled" if enabled else "disabled"}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/set_packet_sampling', methods=['POST'])
@login_required
def api_set_packet_sampling():
    """API endpoint to set packet sampling rate."""
    try:
        data = request.get_json()
        rate = data.get('rate', 0.1)
        
        if not 0.01 <= rate <= 1.0:
            return jsonify({'status': 'error', 'message': 'Sampling rate must be between 0.01 and 1.0'})
        
        engine = get_engine()
        engine.set_packet_sampling_rate(rate)
        
        return jsonify({'status': 'success', 'message': f'Packet sampling rate set to {rate}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/set_logging_mode', methods=['POST'])
@login_required
def api_set_logging_mode():
    """API endpoint to set logging mode."""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        engine = get_engine()
        engine.set_log_all_packets(enabled)
        
        return jsonify({'status': 'success', 'message': f'Packet logging {"enabled" if enabled else "disabled"}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/notification_settings')
@login_required
def api_notification_settings():
    """API endpoint to get notification settings."""
    try:
        engine = get_engine()
        config = engine.notification_manager.config
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/system_health')
@login_required
def api_system_health():
    """API endpoint to get system health status."""
    try:
        # Get system stats
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        # Determine health status
        health_status = 'healthy'
        if cpu_percent > 80 or memory_percent > 80 or disk_percent > 90:
            health_status = 'warning'
        if cpu_percent > 95 or memory_percent > 95 or disk_percent > 95:
            health_status = 'critical'
        
        health_data = {
            'status': health_status,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent,
            'timestamp': time.time()
        }
        
        return jsonify(health_data)
    except Exception as e:
        return jsonify({'error': str(e)})

@bp.route('/api/rules_status')
@login_required
def api_rules_status():
    """API endpoint to get rules status and count."""
    try:
        engine = get_engine()
        rules = engine.get_rules()
        
        status = {
            'total_rules': len(rules),
            'rules': rules,
            'last_updated': time.time()
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}) 