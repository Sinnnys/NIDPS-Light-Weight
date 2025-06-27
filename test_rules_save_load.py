#!/usr/bin/env python3
"""
Test script to verify rules save/load functionality
"""

import os
import json
import sys

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nidps.core.engine import NIDPSEngine

def test_rules_save_load():
    """Test that rules can be saved and loaded correctly"""
    print("Testing rules save/load functionality...")
    
    # Initialize engine
    engine = NIDPSEngine()
    
    # Get initial rules count
    initial_rules = engine.get_rules()
    print(f"Initial rules count: {len(initial_rules)}")
    
    # Create a test rule
    test_rule = {
        "rule_name": "Test Rule Save/Load",
        "protocol": "TCP",
        "conditions": {"dport": "9999"},
        "action": "log",
        "severity": "medium"
    }
    
    # Save the rule to file manually (simulating the web route)
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
        
        print(f"Saved {len(data['rules'])} rules to file")
        
        # Reload rules in engine
        engine.reload_rules()
        
        # Get rules again
        updated_rules = engine.get_rules()
        print(f"Updated rules count: {len(updated_rules)}")
        
        # Check if test rule is there
        rule_names = [rule.get('rule_name') for rule in updated_rules]
        if 'Test Rule Save/Load' in rule_names:
            print("✅ Test rule found in engine rules")
            
            # Remove test rule to restore original state
            data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Test Rule Save/Load']
            with open(rules_path, 'w') as f:
                json.dump(data, f, indent=4)
            
            # Reload again
            engine.reload_rules()
            final_rules = engine.get_rules()
            print(f"Final rules count: {len(final_rules)}")
            
            return True
        else:
            print("❌ Test rule not found in engine rules")
            print(f"Available rules: {rule_names}")
            return False
            
    except Exception as e:
        print(f"❌ Error during test: {e}")
        return False

def test_web_route_simulation():
    """Simulate the web route logic"""
    print("\nTesting web route simulation...")
    
    # Simulate form data
    form_data = {
        'rule_name': 'Web Route Test Rule',
        'protocol': 'UDP',
        'conditions': 'dport=53',
        'action': 'log'
    }
    
    # Create rule object (simulating the web route logic)
    conditions = {}
    if form_data['conditions']:
        for item in form_data['conditions'].split(','):
            if '=' in item:
                k, v = item.split('=', 1)
                conditions[k.strip()] = v.strip()
    
    new_rule = {
        "rule_name": form_data['rule_name'],
        "protocol": form_data['protocol'],
        "conditions": conditions,
        "action": form_data['action']
    }
    
    print(f"New rule object: {new_rule}")
    
    # Save to file (simulating web route)
    rules_path = os.path.join(os.getcwd(), 'rules.json')
    
    try:
        with open(rules_path, 'r') as f:
            data = json.load(f)
        
        data['rules'].append(new_rule)
        
        with open(rules_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Saved rule to file. Total rules: {len(data['rules'])}")
        
        # Test loading with engine
        engine = NIDPSEngine()
        engine.reload_rules()
        rules = engine.get_rules()
        
        rule_names = [rule.get('rule_name') for rule in rules]
        if 'Web Route Test Rule' in rule_names:
            print("✅ Web route simulation successful")
            
            # Clean up
            data['rules'] = [rule for rule in data['rules'] if rule.get('rule_name') != 'Web Route Test Rule']
            with open(rules_path, 'w') as f:
                json.dump(data, f, indent=4)
            
            return True
        else:
            print("❌ Web route simulation failed")
            return False
            
    except Exception as e:
        print(f"❌ Error in web route simulation: {e}")
        return False

def main():
    """Run all tests"""
    print("Running rules save/load tests...\n")
    
    test1 = test_rules_save_load()
    test2 = test_web_route_simulation()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"Basic Save/Load: {'✅ PASSED' if test1 else '❌ FAILED'}")
    print(f"Web Route Simulation: {'✅ PASSED' if test2 else '❌ FAILED'}")
    
    if test1 and test2:
        print("\n🎉 All tests passed! Rules save/load is working correctly.")
    else:
        print("\n⚠️  Some tests failed. There may be an issue with rules persistence.")

if __name__ == "__main__":
    main() 