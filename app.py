from flask import Flask
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from models import db
from datetime import timedelta

import os


load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///auth.sqlite3")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS", False)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY","dev-jwt-key")
app.config["JWT_ACCESS_TOKEN_EXPIRY"] = timedelta(minutes=1)
app.config["JWT_REFRESH_TOKEN_EXPIRY"] = timedelta(days=7)

app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
app.config["JWT_COOKIE_SECURE"] = False          # True if HTTPS only
app.config["JWT_COOKIE_SAMESITE"] = "Lax"        # can be Strict/None
app.config["JWT_COOKIE_CSRF_PROTECT"] = False 


db.init_app(app)
migrate = Migrate(app, db)

from views import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)