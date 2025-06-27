#!/usr/bin/env python3
"""
Test script to verify file operations for rules.json
"""

import os
import json
import sys

def test_file_operations():
    """Test file read/write operations"""
    print("Testing file operations...")
    
    # Test current directory
    current_dir = os.getcwd()
    print(f"Current directory: {current_dir}")
    
    # Test rules.json path
    rules_path = 'rules.json'
    print(f"Rules file path: {rules_path}")
    
    # Check if file exists
    if os.path.exists(rules_path):
        print(f"✅ Rules file exists")
        
        # Check file permissions
        permissions = oct(os.stat(rules_path).st_mode)[-3:]
        print(f"File permissions: {permissions}")
        
        # Test reading
        try:
            with open(rules_path, 'r') as f:
                data = json.load(f)
            print(f"✅ Successfully read {len(data.get('rules', []))} rules from file")
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return False
        
        # Test writing
        try:
            # Create a backup
            backup_data = data.copy()
            
            # Add a test rule
            test_rule = {
                "rule_name": "File Test Rule",
                "protocol": "TCP",
                "conditions": {"dport": "9999"},
                "action": "log"
            }
            
            data['rules'].append(test_rule)
            
            # Save to file
            with open(rules_path, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"✅ Successfully wrote {len(data['rules'])} rules to file")
            
            # Verify by reading back
            with open(rules_path, 'r') as f:
                verify_data = json.load(f)
            print(f"✅ Verified: {len(verify_data.get('rules', []))} rules in file")
            
            # Check if test rule is there
            rule_names = [rule.get('rule_name') for rule in verify_data.get('rules', [])]
            if 'File Test Rule' in rule_names:
                print("✅ Test rule found in file")
                
                # Restore original data
                with open(rules_path, 'w') as f:
                    json.dump(backup_data, f, indent=4)
                print("✅ Restored original data")
                
                return True
            else:
                print("❌ Test rule not found in file")
                return False
                
        except Exception as e:
            print(f"❌ Error writing file: {e}")
            return False
    else:
        print(f"❌ Rules file does not exist")
        return False

def test_relative_path():
    """Test relative path resolution"""
    print("\nTesting relative path resolution...")
    
    # Test different path constructions
    paths_to_test = [
        'rules.json',
        './rules.json',
        '../rules.json',
        os.path.join(os.getcwd(), 'rules.json'),
        os.path.join(os.path.dirname(os.getcwd()), 'rules.json')
    ]
    
    for path in paths_to_test:
        if os.path.exists(path):
            print(f"✅ Found rules.json at: {path}")
            return path
        else:
            print(f"❌ Not found: {path}")
    
    return None

def main():
    """Run all tests"""
    print("Running file operation tests...\n")
    
    # Test path resolution
    rules_path = test_relative_path()
    
    # Test file operations
    file_test = test_file_operations()
    
    print(f"\n{'='*50}")
    print("TEST RESULTS:")
    print(f"File Operations: {'✅ PASSED' if file_test else '❌ FAILED'}")
    print(f"Rules Path: {rules_path if rules_path else '❌ NOT FOUND'}")
    
    if file_test:
        print("\n🎉 File operations are working correctly!")
    else:
        print("\n⚠️  File operations may need attention.")

if __name__ == "__main__":
    main() 