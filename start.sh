#!/bin/bash

echo "=== NIDPS - Network Intrusion Detection and Prevention System ==="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Initialize database if needed
if [ ! -f "nidps.db" ]; then
    echo "Initializing database..."
    export FLASK_APP=nidps
    flask db init
    flask db migrate
    flask db upgrade
    python -c "from nidps import create_app, db; from nidps.auth.models import User, Role; app = create_app(); app.app_context().push(); db.create_all(); admin_role = Role(name='admin'); user_role = Role(name='user'); db.session.add(admin_role); db.session.add(user_role); admin_user = User(username='admin', email='admin@example.com', role=admin_role); admin_user.set_password('admin'); db.session.add(admin_user); db.session.commit(); print('Database seeded!')"
fi

echo ""
echo "Starting NIDPS..."
echo "The web interface will be available at: http://127.0.0.1:5000"
echo "Default credentials: admin@example.com / admin"
echo ""
echo "Press Ctrl+C to stop the application."
echo ""

# Run the application
python run.py 