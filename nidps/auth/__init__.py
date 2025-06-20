from flask import Blueprint

bp = Blueprint('auth', __name__)

from nidps.auth import routes, models 