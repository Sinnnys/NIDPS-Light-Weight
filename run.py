#!/usr/bin/env python
"""
NIDPS - Network Intrusion Detection and Prevention System
Main application entry point
"""

import os
import sys
from nidps import create_app, db
from nidps.auth.models import User, Role
import click

# Create the Flask application
app = create_app()

@app.cli.command("seed")
def seed():
    """Seed the database with initial data."""
    # Create roles
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin')
        db.session.add(admin_role)

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user')
        db.session.add(user_role)

    # Create admin user
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', email='admin@example.com', role=admin_role)
        admin_user.set_password('admin')
        db.session.add(admin_user)

    db.session.commit()
    print("Database seeded!")

def main():
    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    print("=== NIDPS - Network Intrusion Detection and Prevention System ===")
    print("Starting web interface...")
    print("The application will be available at: http://127.0.0.1:5000")
    print("Note: Packet sniffing features require root privileges.")
    print("You can start/stop the engine from the web interface.")
    print("Press Ctrl+C to stop the application.")
    print("=" * 70)
    
    # Run the Flask application
    app.run(host='0.0.0.0', port=5000, debug=False)

def make_shell_context():
    return {'db': db, 'User': User, 'Role': Role}

if __name__ == '__main__':
    main() 