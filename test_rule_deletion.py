#!/usr/bin/env python3
"""
Test script to verify rule deletion functionality
"""

import os
import json
import sys

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nidps.core.engine import NIDPSEngine

def test_rule_deletion():
    """Test that rules can be deleted correctly"""
    print("Testing rule deletion functionality...")
    
    # Initialize engine
    engine = NIDPSEngine()
    
    # Get initial rules count
    initial_rules = engine.get_rules()
    print(f"Initial rules count: {len(initial_rules)}")
    
    # Create a test rule to delete
    test_rule = {
        "rule_name": "Test Rule For Deletion",
        "protocol": "TCP",
        "conditions": {"dport": "8888"},
        "action": "log",
        "severity": "medium"
    }
    
    # Add the test rule to file
    rules_path = os.path.join(os.getcwd(), 'rules.json')
    print(f"Rules file path: {rules_path}")
    
    try:
        # Read current rules
        with open(rules_path, 'r') as f:
            data = json.load(f)
        
        print(f"Current rules in file: {len(data.get('rules', []))}")
        
        # Add test rule
        data['rules'].append(test_rule)
        
        # Save back to file
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Added test rule. Total rules: {len(data['rules'])}")
        
        # Reload rules in engine
        engine.reload_rules()
        rules_after_add = engine.get_rules()
        print(f"Rules after adding: {len(rules_after_add)}")
        
        # Verify test rule is there
        rule_names = [rule.get('rule_name') for rule in rules_after_add]
        if 'Test Rule For Deletion' not in rule_names:
            print("❌ Test rule not found after adding")
            return False
        
        print("✅ Test rule found after adding")
        
        # Now delete the rule (simulating the web route logic)
        print("\n=== DELETING RULE ===")
        
        # Remove the rule from the list
        data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Test Rule For Deletion']
        
        # Save back to file
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Deleted test rule. Total rules: {len(data['rules'])}")
        
        # Reload rules in engine
        engine.reload_rules()
        rules_after_delete = engine.get_rules()
        print(f"Rules after deletion: {len(rules_after_delete)}")
        
        # Verify test rule is gone
        rule_names_after_delete = [rule.get('rule_name') for rule in rules_after_delete]
        if 'Test Rule For Deletion' in rule_names_after_delete:
            print("❌ Test rule still found after deletion")
            return False
        
        print("✅ Test rule successfully deleted")
        return True
        
    except Exception as e:
        print(f"❌ Error during test: {e}")
        return False

def test_web_route_simulation():
    """Simulate the web route deletion logic"""
    print("\nTesting web route deletion simulation...")
    
    # Create a test rule
    test_rule = {
        "rule_name": "Web Route Deletion Test",
        "protocol": "UDP",
        "conditions": {"dport": "7777"},
        "action": "log"
    }
    
    # Add rule to file
    rules_path = os.path.join(os.getcwd(), 'rules.json')
    
    try:
        with open(rules_path, 'r') as f:
            data = json.load(f)
        
        data['rules'].append(test_rule)
        
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Added test rule. Total rules: {len(data['rules'])}")
        
        # Test deletion (simulating web route)
        engine = NIDPSEngine()
        engine.reload_rules()
        
        # Simulate deletion
        rules = engine.get_rules()
        original_count = len(rules)
        rules = [rule for rule in rules if rule.get('rule_name') != 'Web Route Deletion Test']
        new_count = len(rules)
        
        if original_count == new_count:
            print("❌ Rule not found for deletion")
            return False
        
        # Save back to file
        data['rules'] = rules
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        # Verify deletion
        engine.reload_rules()
        final_rules = engine.get_rules()
        rule_names = [rule.get('rule_name') for rule in final_rules]
        
        if 'Web Route Deletion Test' in rule_names:
            print("❌ Web route deletion simulation failed")
            return False
        else:
            print("✅ Web route deletion simulation successful")
            return True
            
    except Exception as e:
        print(f"❌ Error in web route simulation: {e}")
        return False

def main():
    """Run all tests"""
    print("Running rule deletion tests...\n")
    
    test1 = test_rule_deletion()
    test2 = test_web_route_simulation()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Basic Deletion: {'✅ PASSED' if test1 else '❌ FAILED'}")
    print(f"Web Route Simulation: {'✅ PASSED' if test2 else '❌ FAILED'}")
    
    if test1 and test2:
        print("\n🎉 All tests passed! Rule deletion is working correctly.")
    else:
        print("\n⚠️  Some tests failed. There may be an issue with rule deletion.")

if __name__ == "__main__":
    main() 