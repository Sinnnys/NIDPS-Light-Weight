from functools import wraps
from flask_login import current_user
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.role or current_user.role.name != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function 