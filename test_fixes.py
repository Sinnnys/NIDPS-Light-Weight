#!/usr/bin/env python3
"""
Test script to verify the fixes for:
1. Rules not updating after add/delete
2. Email validator error in user creation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nidps import create_app, db
from nidps.auth.models import User, Role
from nidps.core.engine import NIDPSEngine
from nidps.auth.forms import CreateUserForm
import json

def test_rules_fix():
    """Test that rules are properly reloaded after changes"""
    print("Testing rules management fix...")
    
    # Create engine instance
    engine = NIDPSEngine()
    
    # Get initial rules
    initial_rules = engine.get_rules()
    initial_count = len(initial_rules)
    print(f"Initial rules count: {initial_count}")
    
    # Test adding a rule
    test_rule = {
        "rule_name": "Test Rule",
        "protocol": "TCP",
        "conditions": {"dport": "80"},
        "action": "log"
    }
    
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
    
    # Test deleting a rule
    data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Test Rule']
    
    with open('rules.json', 'w') as f:
        json.dump(data, f, indent=4)
    
    # Reload rules
    engine.reload_rules()
    
    # Check if rule was removed
    final_rules = engine.get_rules()
    final_count = len(final_rules)
    print(f"Rules after deleting: {final_count}")
    
    # Check if the counts are correct
    if updated_count == initial_count + 1 and final_count == initial_count:
        print("✅ Rules management fix: PASSED")
        return True
    else:
        print("❌ Rules management fix: FAILED")
        print(f"Expected: {initial_count} -> {initial_count + 1} -> {initial_count}")
        print(f"Actual: {initial_count} -> {updated_count} -> {final_count}")
        return False

def test_email_validator_fix():
    """Test that email validation works properly"""
    print("\nTesting email validator fix...")
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        with app.test_request_context():
            # Test form validation
            form_data = {
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'testpass123',
                'confirm_password': 'testpass123',
                'role': 'user'
            }
            
            form = CreateUserForm(data=form_data)
            
            try:
                # This should not raise an exception if email_validator is installed
                is_valid = form.validate()
                print(f"Form validation result: {is_valid}")
                
                if not form.email.errors:
                    print("✅ Email validator fix: PASSED")
                    return True
                else:
                    print(f"❌ Email validator fix: FAILED - {form.email.errors}")
                    return False
                    
            except Exception as e:
                print(f"❌ Email validator fix: FAILED - Exception: {e}")
                return False

def main():
    """Run all tests"""
    print("Running fix verification tests...\n")
    
    rules_test = test_rules_fix()
    email_test = test_email_validator_fix()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Rules Management Fix: {'✅ PASSED' if rules_test else '❌ FAILED'}")
    print(f"Email Validator Fix: {'✅ PASSED' if email_test else '❌ FAILED'}")
    
    if rules_test and email_test:
        print("\n🎉 All fixes are working correctly!")
    else:
        print("\n⚠️  Some fixes may need attention.")

if __name__ == "__main__":
    main() 