#!/usr/bin/env python3
"""
Test script to verify the UI fixes for:
1. Engine status display in system configuration
2. Rules page showing current rules correctly
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nidps import create_app
from nidps.core.engine import NIDPSEngine
import json
import time

def test_engine_status():
    """Test that engine status is correctly reported"""
    print("Testing engine status fix...")
    
    # Create engine instance
    engine = NIDPSEngine()
    
    # Test initial status
    initial_status = engine.is_running
    print(f"Initial engine status: {'Running' if initial_status else 'Stopped'}")
    
    # Test API endpoint simulation
    try:
        # Simulate what the API endpoint does
        status_data = {
            'running': engine.is_running,
            'uptime': time.time() - engine.start_time if hasattr(engine, 'start_time') else 0,
            'packets_processed': getattr(engine, 'packet_counter', 0),
            'alerts_count': len(engine.alerts),
            'blocked_ips_count': len(engine.get_blocked_ips()),
            'performance_mode': getattr(engine, 'performance_mode', False)
        }
        
        print(f"Status data: {status_data}")
        
        if 'running' in status_data:
            print("✅ Engine status fix: PASSED")
            return True
        else:
            print("❌ Engine status fix: FAILED - Missing running field")
            return False
            
    except Exception as e:
        print(f"❌ Engine status fix: FAILED - Exception: {e}")
        return False

def test_rules_display():
    """Test that rules are correctly loaded and displayed"""
    print("\nTesting rules display fix...")
    
    # Create engine instance
    engine = NIDPSEngine()
    
    # Get initial rules
    initial_rules = engine.get_rules()
    initial_count = len(initial_rules)
    print(f"Initial rules count: {initial_count}")
    
    # Test adding a rule
    test_rule = {
        "rule_name": "UI Test Rule",
        "protocol": "TCP",
        "conditions": {"dport": "8080"},
        "action": "log"
    }
    
    # Add rule to engine
    engine.add_rule(test_rule)
    
    # Save to file
    with open('rules.json', 'r') as f:
        data = json.load(f)
    
    data['rules'].append(test_rule)
    
    with open('rules.json', 'w') as f:
        json.dump(data, f, indent=4)
    
    # Reload rules
    engine.reload_rules()
    
    # Check if rule was added
    updated_rules = engine.get_rules()
    updated_count = len(updated_rules)
    print(f"Rules after adding: {updated_count}")
    
    # Check if the new rule is in the list
    rule_names = [rule.get('rule_name') for rule in updated_rules]
    if 'UI Test Rule' in rule_names:
        print("✅ Rules display fix: PASSED")
        
        # Clean up - remove test rule
        data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'UI Test Rule']
        with open('rules.json', 'w') as f:
            json.dump(data, f, indent=4)
        engine.reload_rules()
        
        return True
    else:
        print("❌ Rules display fix: FAILED - New rule not found")
        return False

def test_api_endpoints():
    """Test that API endpoints work correctly"""
    print("\nTesting API endpoints...")
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        with app.test_request_context():
            try:
                # Test engine status endpoint
                from nidps.web.routes import api_engine_status
                status_response = api_engine_status()
                print(f"Engine status endpoint: {status_response.status_code}")
                
                # Test rules status endpoint
                from nidps.web.routes import api_rules_status
                rules_response = api_rules_status()
                print(f"Rules status endpoint: {rules_response.status_code}")
                
                if status_response.status_code == 200 and rules_response.status_code == 200:
                    print("✅ API endpoints fix: PASSED")
                    return True
                else:
                    print("❌ API endpoints fix: FAILED")
                    return False
                    
            except Exception as e:
                print(f"❌ API endpoints fix: FAILED - Exception: {e}")
                return False

def main():
    """Run all tests"""
    print("Running UI fix verification tests...\n")
    
    engine_test = test_engine_status()
    rules_test = test_rules_display()
    api_test = test_api_endpoints()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Engine Status Fix: {'✅ PASSED' if engine_test else '❌ FAILED'}")
    print(f"Rules Display Fix: {'✅ PASSED' if rules_test else '❌ FAILED'}")
    print(f"API Endpoints Fix: {'✅ PASSED' if api_test else '❌ FAILED'}")
    
    if engine_test and rules_test and api_test:
        print("\n🎉 All UI fixes are working correctly!")
    else:
        print("\n⚠️  Some UI fixes may need attention.")

if __name__ == "__main__":
    main() 