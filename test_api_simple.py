#!/usr/bin/env python3
"""
Simple API Test Script
Tests basic API functionality with detailed debug output
"""

import requests
import json
from bs4 import BeautifulSoup

def test_api_with_debug():
    """Test API endpoints with detailed debug output"""
    base_url = "http://127.0.0.1:5000"
    session = requests.Session()
    
    print("=== NIDPS API Debug Test ===")
    
    # Step 1: Test unauthenticated API call
    print("\n1. Testing unauthenticated API call:")
    try:
        response = session.get(f"{base_url}/api/engine_status")
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type')}")
        print(f"   Response length: {len(response.text)}")
        print(f"   Response preview: {response.text[:200]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Step 2: Get login page
    print("\n2. Getting login page:")
    try:
        login_response = session.get(f"{base_url}/auth/login")
        print(f"   Status: {login_response.status_code}")
        print(f"   Content-Type: {login_response.headers.get('content-type')}")
        
        # Parse CSRF token
        soup = BeautifulSoup(login_response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})
        if csrf_token and hasattr(csrf_token, 'get'):
            token = csrf_token.get('value')
            print(f"   CSRF token found: {token[:10] if token else 'None'}...")
        else:
            print("   No CSRF token found")
            return
    except Exception as e:
        print(f"   Error: {e}")
        return
    
    # Step 3: Login
    print("\n3. Attempting login:")
    try:
        login_data = {
            'csrf_token': token,
            'username': 'admin',
            'password': 'admin',
            'remember_me': False
        }
        
        login_response = session.post(f"{base_url}/auth/login", data=login_data, allow_redirects=False)
        print(f"   Login status: {login_response.status_code}")
        print(f"   Login headers: {dict(login_response.headers)}")
        
        if login_response.status_code == 302:
            print("   ✅ Login successful (redirect)")
        else:
            print("   ❌ Login failed")
            print(f"   Response: {login_response.text[:300]}...")
            return
    except Exception as e:
        print(f"   Error: {e}")
        return
    
    # Step 4: Test authenticated API calls
    print("\n4. Testing authenticated API calls:")
    api_endpoints = [
        '/api/engine_status',
        '/api/system_stats',
        '/api/alerts',
        '/api/logs'
    ]
    
    for endpoint in api_endpoints:
        print(f"\n   Testing {endpoint}:")
        try:
            response = session.get(f"{base_url}{endpoint}")
            print(f"     Status: {response.status_code}")
            print(f"     Content-Type: {response.headers.get('content-type')}")
            print(f"     Response length: {len(response.text)}")
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    print(f"     ✅ Valid JSON response")
                    print(f"     JSON keys: {list(json_data.keys()) if isinstance(json_data, dict) else 'Not a dict'}")
                except json.JSONDecodeError:
                    print(f"     ❌ Invalid JSON")
                    print(f"     Response preview: {response.text[:200]}...")
            else:
                print(f"     ❌ HTTP {response.status_code}")
                print(f"     Response preview: {response.text[:200]}...")
                
        except Exception as e:
            print(f"     Error: {e}")
    
    # Step 5: Test dashboard access
    print("\n5. Testing dashboard access:")
    try:
        response = session.get(f"{base_url}/dashboard")
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type')}")
        if response.status_code == 200:
            print("   ✅ Dashboard accessible")
        else:
            print("   ❌ Dashboard not accessible")
    except Exception as e:
        print(f"   Error: {e}")

if __name__ == "__main__":
    test_api_with_debug() 