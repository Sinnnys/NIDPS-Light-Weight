#!/usr/bin/env python3
"""
Test script to verify that rules are properly added and displayed
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nidps import create_app
from nidps.core.engine import NIDPSEngine
import json

def test_rules_addition():
    """Test that rules are properly added and displayed"""
    print("Testing rules addition and display...")
    
    # Create engine instance
    engine = NIDPSEngine()
    
    # Get initial rules
    initial_rules = engine.get_rules()
    initial_count = len(initial_rules)
    print(f"Initial rules count: {initial_count}")
    
    # Test adding a rule
    test_rule = {
        "rule_name": "Test Rule Fix",
        "protocol": "TCP",
        "conditions": {"dport": "8080"},
        "action": "log"
    }
    
    # Simulate the new logic: read from file, add rule, save back
    rules_path = 'rules.json'
    try:
        with open(rules_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"rules": [], "global_settings": {}}
    
    # Add the new rule to the file data
    data['rules'].append(test_rule)
    
    # Save back to file
    with open(rules_path, 'w') as f:
        json.dump(data, f, indent=4)
    
    # Reload rules in the engine
    engine.reload_rules()
    
    # Check if rule was added
    updated_rules = engine.get_rules()
    updated_count = len(updated_rules)
    print(f"Rules after adding: {updated_count}")
    
    # Check if the new rule is in the list
    rule_names = [rule.get('rule_name') for rule in updated_rules]
    if 'Test Rule Fix' in rule_names:
        print("✅ Rules addition: PASSED - New rule appears in list")
        
        # Clean up - remove test rule
        data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Test Rule Fix']
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        engine.reload_rules()
        
        return True
    else:
        print("❌ Rules addition: FAILED - New rule not found in list")
        print(f"Available rules: {rule_names}")
        return False

def test_rules_api():
    """Test the rules status API endpoint"""
    print("\nTesting rules status API...")
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        with app.test_request_context():
            try:
                # Test rules status endpoint
                from nidps.web.routes import api_rules_status
                response = api_rules_status()
                
                if response.status_code == 200:
                    data = response.get_json()
                    print(f"API Response: {data.get('total_rules')} rules in engine, {data.get('file_rules_count')} rules in file")
                    
                    if data.get('total_rules') == data.get('file_rules_count'):
                        print("✅ Rules API: PASSED - Engine and file rules match")
                        return True
                    else:
                        print("❌ Rules API: FAILED - Engine and file rules don't match")
                        return False
                else:
                    print(f"❌ Rules API: FAILED - HTTP {response.status_code}")
                    return False
                    
            except Exception as e:
                print(f"❌ Rules API test: FAILED - Exception: {e}")
                return False

def main():
    """Run all tests"""
    print("Running rules fix verification tests...\n")
    
    rules_test = test_rules_addition()
    api_test = test_rules_api()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Rules Addition: {'✅ PASSED' if rules_test else '❌ FAILED'}")
    print(f"Rules API: {'✅ PASSED' if api_test else '❌ FAILED'}")
    
    if rules_test and api_test:
        print("\n🎉 Rules fix is working correctly!")
    else:
        print("\n⚠️  Rules fix may need attention.")

if __name__ == "__main__":
    main() 