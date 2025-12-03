import jwt
import secrets
from datetime import datetime, timedelta
from flask import current_app

def create_access_token(user_id):
    exp = datetime.utcnow() + timedelta(seconds=current_app.config["ACCESS_TOKEN_EXP"])
    return jwt.encode(
        {"sub": user_id, "exp": exp},
        current_app.config["JWT_SECRET"],
        algorithm="HS256"
    )

def create_refresh_token():
    return secrets.token_hex(64)

def verify_jwt(token):
    try:
        data = jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=["HS256"]
        )
        return data
    except:
        return None

def generate_code():
    return secrets.token_hex(32)
