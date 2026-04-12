"""
FlexEdgeAdmin — Flask-SQLAlchemy database instance.

Import `db` from this module in models and anywhere that needs DB access.
Initialize with `db.init_app(app)` in the Flask app factory.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
