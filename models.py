from sqlalchemy import Enum
from sqlalchemy.orm import validates
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import hashlib
# from app import bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

ROLE_USER = "user"
ROLE_MANAGER = "manager"
ROLE_ADMIN = "admin"
VALID_ROLES = {ROLE_USER, ROLE_MANAGER, ROLE_ADMIN}


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(Enum(*VALID_ROLES, name="role_enum"), nullable=False, default=ROLE_USER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, rounds=8).decode()

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    @validates("role")
    def validate_role(self, key, value):
        if value not in VALID_ROLES:
            raise ValueError(f"Invalid role: {value}. Must be one of {VALID_ROLES}")
        return value
    
class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=True, default="No content provided")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    author = db.relationship("User", backref="posts")


