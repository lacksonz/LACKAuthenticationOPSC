from datetime import datetime, timedelta
from .database import db
from passlib.hash import bcrypt
import secrets

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)


class OAuthClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False)
    client_secret = db.Column(db.String(128), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)

    @staticmethod
    def generate():
        return (
            secrets.token_hex(16),
            secrets.token_hex(32)
        )


class AuthCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    client_id = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    @staticmethod
    def generate_expires(minutes=10):
        return datetime.utcnow() + timedelta(minutes=minutes)


class RefreshToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    client_id = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

    @staticmethod
    def generate_expires(days=30):
        return datetime.utcnow() + timedelta(days=days)
