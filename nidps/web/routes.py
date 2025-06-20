from flask import render_template, current_app, flash, redirect, url_for, jsonify, session
from nidps.web import bp
from flask_login import login_required
from nidps.auth.decorators import admin_required
from nidps.web.forms import RuleForm
from nidps.core.engine import NIDPSEngine
import json
import os

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home')

@bp.route('/dashboard')
@login_required
def dashboard():
    engine = NIDPSEngine()
    status = "Running" if engine.is_running else "Not Running"
    return render_template('dashboard.html', title='Dashboard', status=status)

@bp.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html', title='Alerts')

@bp.route('/logs')
@login_required
def logs():
    engine = NIDPSEngine()
    log_entries = engine.get_logs()
    return render_template('logs.html', title='System Logs', logs=log_entries)

@bp.route('/blocked_ips')
@admin_required
def blocked_ips():
    engine = NIDPSEngine()
    blocked_info = engine.prevention_engine.get_blocked_ips_info()
    return render_template('blocked_ips.html', title='Blocked IPs', blocked=blocked_info)

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
        new_rule = {
            "rule_name": form.rule_name.data,
            "protocol": form.protocol.data,
            "conditions": {k.strip(): v.strip() for k, v in (item.split('=') for item in form.conditions.data.split(',')) if form.conditions.data},
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

@bp.route('/api/alerts')
@login_required
def api_alerts():
    engine = NIDPSEngine()
    alerts = engine.get_alerts()
    return jsonify(alerts)

@bp.route('/api/start_engine')
@admin_required
def api_start_engine():
    engine = NIDPSEngine()
    if not engine.is_running:
        engine.start()
        return jsonify({"status": "success", "message": "Engine started successfully"})
    else:
        return jsonify({"status": "error", "message": "Engine is already running"})

@bp.route('/api/stop_engine')
@admin_required
def api_stop_engine():
    engine = NIDPSEngine()
    if engine.is_running:
        engine.stop()
        return jsonify({"status": "success", "message": "Engine stopped successfully"})
    else:
        return jsonify({"status": "error", "message": "Engine is not running"})

@bp.route('/api/engine_status')
@login_required
def api_engine_status():
    engine = NIDPSEngine()
    return jsonify({
        "running": engine.is_running,
        "blocked_ips_count": len(engine.get_blocked_ips()),
        "alerts_count": len(engine.get_alerts())
    })

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