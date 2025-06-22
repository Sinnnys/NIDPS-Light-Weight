#!/usr/bin/env python3
"""
Simple API Debug Script
Tests API endpoints to see what's being returned
"""

import requests
import json
from bs4 import BeautifulSoup

def test_api_endpoint(url, session=None):
    """Test an API endpoint and show the response"""
    print(f"\n🔍 Testing: {url}")
    print("-" * 50)
    
    try:
        if session:
            response = session.get(url)
        else:
            response = requests.get(url)
        
        print(f"Status Code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('content-type', 'Not specified')}")
        print(f"Response Length: {len(response.text)} characters")
        
        # Try to parse as JSON
        try:
            json_data = response.json()
            print("✅ Valid JSON Response:")
            print(json.dumps(json_data, indent=2)[:500] + "..." if len(json.dumps(json_data, indent=2)) > 500 else "")
        except json.JSONDecodeError:
            print("❌ Not valid JSON")
            print("Response Preview:")
            print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
            
            # Check if it's HTML
            if '<html' in response.text.lower():
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.find('title')
                if title:
                    print(f"HTML Title: {title.text}")
                
                # Look for error messages
                error_messages = soup.find_all(['h1', 'p'])
                for msg in error_messages:
                    if any(keyword in msg.text.lower() for keyword in ['error', 'forbidden', 'unauthorized', 'not found']):
                        print(f"Error Message: {msg.text.strip()}")
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"❌ Request failed: {e}")
        return False

def main():
    print("=== NIDPS API Debug Test ===")
    print("Testing API endpoints to identify issues...")
    
    base_url = "http://127.0.0.1:5000"
    
    # Test without session first
    print("\n📋 Testing without authentication:")
    test_api_endpoint(f"{base_url}/api/engine_status")
    test_api_endpoint(f"{base_url}/api/system_stats")
    
    # Test with session (login first)
    print("\n📋 Testing with authentication:")
    session = requests.Session()
    
    # Try to login
    print("\n🔐 Attempting login...")
    try:
        login_response = session.get(f"{base_url}/auth/login")
        if login_response.status_code == 200:
            print("✅ Login page accessible")
            
            # Try to get CSRF token
            soup = BeautifulSoup(login_response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrf_token'})
            if csrf_token and hasattr(csrf_token, 'get'):
                token = csrf_token.get('value')
                if token:
                    print(f"✅ CSRF token found: {token[:10]}...")
                    
                    # Try to login
                    login_data = {
                        'csrf_token': token,
                        'username': 'admin',
                        'password': 'admin'
                    }
                    
                    login_post = session.post(f"{base_url}/auth/login", data=login_data)
                    print(f"Login POST status: {login_post.status_code}")
                    
                    if login_post.status_code == 302:  # Redirect after successful login
                        print("✅ Login appears successful")
                    else:
                        print("❌ Login failed")
                        print(f"Response: {login_post.text[:200]}...")
                else:
                    print("❌ CSRF token value is empty")
            else:
                print("❌ No CSRF token found")
        else:
            print(f"❌ Login page not accessible: {login_response.status_code}")
    except Exception as e:
        print(f"❌ Login attempt failed: {e}")
    
    # Test authenticated endpoints
    print("\n🔍 Testing authenticated endpoints:")
    test_api_endpoint(f"{base_url}/api/engine_status", session)
    test_api_endpoint(f"{base_url}/api/system_stats", session)
    test_api_endpoint(f"{base_url}/api/alerts", session)
    test_api_endpoint(f"{base_url}/api/logs", session)

if __name__ == "__main__":
    main() 