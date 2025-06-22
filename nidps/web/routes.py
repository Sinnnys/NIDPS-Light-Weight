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

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    """Main dashboard page."""
    return render_template('index.html', title='Home')

@bp.route('/dashboard')
@login_required
def dashboard():
    engine = NIDPSEngine()
    status = "Running" if engine.is_running else "Not Running"
    stats = engine.get_statistics()
    return render_template('dashboard.html', title='Dashboard', status=status, stats=stats)

@bp.route('/alerts')
@login_required
def alerts():
    """Alerts page."""
    # Get alerts from the engine if it exists
    alerts_list = []
    if engine and hasattr(engine, 'alerts'):
        alerts_list = engine.alerts[-50:]  # Last 50 alerts
    else:
        # Fallback to creating a new engine instance
        temp_engine = NIDPSEngine()
        alerts_list = temp_engine.get_alerts()
    
    return render_template('alerts.html', title='Alerts', alerts=alerts_list)

@bp.route('/logs')
@login_required
def logs():
    """Logs page."""
    # Get logs from the engine if it exists
    logs_list = []
    if engine and hasattr(engine, 'packet_logs'):
        logs_list = engine.packet_logs[-100:]  # Last 100 logs
    else:
        # Fallback to creating a new engine instance
        temp_engine = NIDPSEngine()
        logs_list = temp_engine.get_logs()
    
    return render_template('logs.html', title='System Logs', logs=logs_list)

@bp.route('/blocked_ips')
@admin_required
def blocked_ips():
    """Blocked IPs page."""
    # Get blocked IPs from the engine if it exists
    blocked_list = []
    if engine and hasattr(engine, 'prevention_engine'):
        blocked_list = list(engine.prevention_engine.blocked_ips)
    else:
        # Fallback to creating a new engine instance
        temp_engine = NIDPSEngine()
        blocked_list = temp_engine.get_blocked_ips()
    
    return render_template('blocked_ips.html', title='Blocked IPs', blocked_ips=blocked_list)

@bp.route('/unblock_ip/<ip>')
@admin_required
def unblock_ip(ip):
    engine = NIDPSEngine()
    if engine.prevention_engine.unblock_ip(ip):
        flash(f'IP {ip} has been unblocked.')
    else:
        flash(f'Failed to unblock IP {ip}.')
    return redirect(url_for('web.blocked_ips'))

@bp.route('/rules', methods=['GET', 'POST'])
@admin_required
def rules():
    engine = NIDPSEngine()
    all_rules = engine.get_rules()

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

        flash('Rule added successfully!')
        return redirect(url_for('web.rules'))

    return render_template('rules.html', title='Detection Rules', rules=all_rules, form=form)

@bp.route('/analytics')
@login_required
def analytics_page():
    """Analytics page."""
    # Get analytics data if available
    analytics_data = {}
    try:
        temp_engine = NIDPSEngine()
        analytics_data = {
            'traffic_patterns': temp_engine.get_statistics().get('traffic_patterns', {}),
            'anomaly_scores': temp_engine.get_statistics().get('anomaly_scores', {}),
            'top_sources': temp_engine.get_statistics().get('top_sources', []),
            'top_destinations': temp_engine.get_statistics().get('top_destinations', [])
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
        if engine and hasattr(engine, 'alerts'):
            return jsonify(engine.alerts[-20:])  # Last 20 alerts
        else:
            # Fallback to creating a new engine instance
            temp_engine = NIDPSEngine()
            alerts = temp_engine.get_alerts()
            return jsonify(alerts[-20:])
    except:
        return jsonify([])

@bp.route('/api/logs')
@login_required
def api_logs():
    """API endpoint to get logs."""
    try:
        if engine and hasattr(engine, 'packet_logs'):
            return jsonify(engine.packet_logs[-50:])  # Last 50 logs
        else:
            # Fallback to creating a new engine instance
            temp_engine = NIDPSEngine()
            logs = temp_engine.get_logs()
            return jsonify(logs[-50:])
    except:
        return jsonify([])

@bp.route('/api/start_engine', methods=['POST'])
@login_required
def api_start_engine():
    """API endpoint to start the NIDPS engine."""
    global engine
    
    try:
        if engine is None:
            # Start the main engine
            engine = NIDPSEngine()
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
        if engine:
            engine.stop()
            engine = None
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
        if engine:
            return jsonify({
                'running': engine.is_running,
                'alerts_count': len(engine.get_alerts()) if hasattr(engine, 'get_alerts') else 0,
                'logs_count': len(engine.get_logs()) if hasattr(engine, 'get_logs') else 0,
                'blocked_ips_count': len(engine.get_blocked_ips()) if hasattr(engine, 'get_blocked_ips') else 0
            })
        else:
            return jsonify({
                'running': False,
                'alerts_count': 0,
                'logs_count': 0,
                'blocked_ips_count': 0
            })
    except:
        return jsonify({
            'running': False,
            'alerts_count': 0,
            'logs_count': 0,
            'blocked_ips_count': 0
        })

@bp.route('/api/system_stats')
@login_required
def api_system_stats():
    """API endpoint to get system statistics."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        
        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory_percent, 1),
            'disk_percent': round(disk_percent, 1),
            'memory_total': f"{memory.total / (1024**3):.1f} GB",
            'memory_used': f"{memory.used / (1024**3):.1f} GB",
            'disk_total': f"{disk.total / (1024**3):.1f} GB",
            'disk_used': f"{disk.used / (1024**3):.1f} GB"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/nidps_stats')
@login_required
def api_nidps_stats():
    """API endpoint to get NIDPS-specific statistics."""
    try:
        current_pid = os.getpid()
        process = psutil.Process(current_pid)
        
        # Get process info
        memory_info = process.memory_info()
        memory_usage = f"{memory_info.rss / (1024**2):.1f} MB"
        
        # Calculate uptime
        create_time = process.create_time()
        uptime_seconds = time.time() - create_time
        uptime = str(timedelta(seconds=int(uptime_seconds)))
        
        return jsonify({
            'pid': current_pid,
            'status': 'Running',
            'uptime': uptime,
            'memory_usage': memory_usage,
            'engine_running': engine.is_running if engine else False,
            'sniffer_active': engine.is_running if engine else False,
            'analytics_active': True,  # Default to True for now
            'recovery_active': True   # Default to True for now
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/process_list')
@login_required
def api_process_list():
    """API endpoint to get top processes by CPU usage."""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                proc_info = proc.info
                if proc_info['cpu_percent'] > 0:  # Only include processes with CPU usage
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent'],
                        'status': proc_info['status']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage and return top 10
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return jsonify(processes[:10])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/api/analytics_data')
@login_required
def api_analytics_data():
    """API endpoint to get analytics data."""
    try:
        temp_engine = NIDPSEngine()
        stats = temp_engine.get_statistics()
        return jsonify({
            'traffic_patterns': stats.get('traffic_patterns', {}),
            'anomaly_scores': stats.get('anomaly_scores', {}),
            'top_sources': stats.get('top_sources', []),
            'top_destinations': stats.get('top_destinations', [])
        })
    except:
        return jsonify({})

@bp.route('/api/block_ip', methods=['POST'])
@login_required
def api_block_ip():
    """API endpoint to block an IP address."""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'status': 'error', 'message': 'IP address is required'})
    
    try:
        temp_engine = NIDPSEngine()
        if hasattr(temp_engine, 'prevention_engine'):
            temp_engine.prevention_engine.block_ip(ip_address)
            return jsonify({'status': 'success', 'message': f'IP {ip_address} blocked successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Blocking functionality not available'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to block IP: {str(e)}'})

@bp.route('/api/unblock_ip', methods=['POST'])
@login_required
def api_unblock_ip():
    """API endpoint to unblock an IP address."""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'status': 'error', 'message': 'IP address is required'})
    
    try:
        temp_engine = NIDPSEngine()
        if hasattr(temp_engine, 'prevention_engine'):
            temp_engine.prevention_engine.unblock_ip(ip_address)
            return jsonify({'status': 'success', 'message': f'IP {ip_address} unblocked successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Unblocking functionality not available'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to unblock IP: {str(e)}'})

@bp.route('/delete_rule/<rule_name>')
@admin_required
def delete_rule(rule_name):
    engine = NIDPSEngine()
    rules = engine.get_rules()
    
    # Find and remove the rule
    rule_to_delete = next((rule for rule in rules if rule['rule_name'] == rule_name), None)
    if rule_to_delete:
        rules.remove(rule_to_delete)
        
        # Save back to file
        rules_path = os.path.join(os.path.dirname(current_app.root_path), '..', 'rules.json')
        with open(rules_path, 'w') as f:
            json.dump({"rules": rules}, f, indent=4)
        
        flash(f'Rule "{rule_name}" deleted.')
    else:
        flash(f'Rule "{rule_name}" not found.')
        
    return redirect(url_for('web.rules')) 