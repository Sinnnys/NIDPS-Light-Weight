import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
login.login_view = 'auth.login'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login.init_app(app)

    # The NIDPS Engine is now run as a separate service.
    # The web app will interact with it via logs and the database.

    # Register blueprints here
    from nidps.web import bp as web_bp
    app.register_blueprint(web_bp)

    from nidps.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Error handlers for API routes
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Not found', 'status': 'error'}), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Forbidden', 'status': 'error'}), 403

    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/nidps.log', maxBytes=10240,
                                           backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('NIDPS startup')

    return app 