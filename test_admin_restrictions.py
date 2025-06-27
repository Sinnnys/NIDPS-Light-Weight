#!/usr/bin/env python3
"""
Test script to verify:
1. Engine controls are restricted to admin users only
2. Rules page displays correctly after adding rules
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nidps import create_app
from nidps.core.engine import NIDPSEngine
from nidps.auth.models import User, Role
import json

def test_admin_restrictions():
    """Test that engine control endpoints require admin access"""
    print("Testing admin restrictions for engine controls...")
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        with app.test_request_context():
            try:
                # Test start engine endpoint
                from nidps.web.routes import api_start_engine
                
                # This should fail without admin access
                response = api_start_engine()
                print(f"Start engine endpoint response: {response.status_code}")
                
                # Check if it returns 403 (Forbidden) or redirects to login
                if response.status_code in [403, 302, 401]:
                    print("✅ Admin restrictions: PASSED - Engine controls properly restricted")
                    return True
                else:
                    print("❌ Admin restrictions: FAILED - Engine controls not properly restricted")
                    return False
                    
            except Exception as e:
                print(f"❌ Admin restrictions test: FAILED - Exception: {e}")
                return False

def test_rules_display():
    """Test that rules are correctly displayed after adding"""
    print("\nTesting rules display after adding...")
    
    # Create engine instance
    engine = NIDPSEngine()
    
    # Get initial rules
    initial_rules = engine.get_rules()
    initial_count = len(initial_rules)
    print(f"Initial rules count: {initial_count}")
    
    # Test adding a rule
    test_rule = {
        "rule_name": "Admin Test Rule",
        "protocol": "TCP",
        "conditions": {"dport": "9090"},
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
    
    # Force reload rules
    engine.reload_rules()
    
    # Check if rule was added
    updated_rules = engine.get_rules()
    updated_count = len(updated_rules)
    print(f"Rules after adding: {updated_count}")
    
    # Check if the new rule is in the list
    rule_names = [rule.get('rule_name') for rule in updated_rules]
    if 'Admin Test Rule' in rule_names:
        print("✅ Rules display: PASSED - New rule appears in list")
        
        # Clean up - remove test rule
        data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Admin Test Rule']
        with open('rules.json', 'w') as f:
            json.dump(data, f, indent=4)
        engine.reload_rules()
        
        return True
    else:
        print("❌ Rules display: FAILED - New rule not found in list")
        print(f"Available rules: {rule_names}")
        return False

def test_rules_page_access():
    """Test that rules page requires admin access"""
    print("\nTesting rules page admin access...")
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        with app.test_request_context():
            try:
                # Test rules page endpoint
                from nidps.web.routes import rules
                
                # This should fail without admin access
                response = rules()
                print(f"Rules page endpoint response: {response.status_code if hasattr(response, 'status_code') else 'No status code'}")
                
                # Check if it returns 403 (Forbidden) or redirects to login
                if hasattr(response, 'status_code') and response.status_code in [403, 302, 401]:
                    print("✅ Rules page access: PASSED - Rules page properly restricted")
                    return True
                else:
                    print("❌ Rules page access: FAILED - Rules page not properly restricted")
                    return False
                    
            except Exception as e:
                print(f"❌ Rules page access test: FAILED - Exception: {e}")
                return False

def main():
    """Run all tests"""
    print("Running admin restrictions and rules display tests...\n")
    
    admin_test = test_admin_restrictions()
    rules_test = test_rules_display()
    access_test = test_rules_page_access()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Admin Restrictions: {'✅ PASSED' if admin_test else '❌ FAILED'}")
    print(f"Rules Display: {'✅ PASSED' if rules_test else '❌ FAILED'}")
    print(f"Rules Page Access: {'✅ PASSED' if access_test else '❌ FAILED'}")
    
    if admin_test and rules_test and access_test:
        print("\n🎉 All admin restrictions and rules fixes are working correctly!")
    else:
        print("\n⚠️  Some fixes may need attention.")

if __name__ == "__main__":
    main() 