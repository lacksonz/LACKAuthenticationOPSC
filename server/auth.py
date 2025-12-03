from flask import Blueprint, request, jsonify
from datetime import datetime
from .database import db
from .models import User, OAuthClient, AuthCode, RefreshToken
from .utils import create_access_token, create_refresh_token, generate_code

auth = Blueprint("auth", __name__)

@auth.post("/register")
def register():
    data = request.json
    if User.query.filter_by(email=data["email"]).first():
        return {"error": "Email exists"}, 400
    u = User(email=data["email"])
    u.set_password(data["password"])
    db.session.add(u)
    db.session.commit()
    return {"success": True}

@auth.post("/login")
def login():
    data = request.json
    u = User.query.filter_by(email=data["email"]).first()
    if not u or not u.check_password(data["password"]):
        return {"error": "Invalid login"}, 400
    return {"user_id": u.id}

@auth.post("/authorize")
def authorize():
    data = request.json
    user_id = data.get("user_id")
    client_id = data.get("client_id")

    client = OAuthClient.query.filter_by(client_id=client_id).first()
    if not client:
        return {"error": "Invalid client"}, 400

    code_str = generate_code()
    code = AuthCode(
        code=code_str,
        user_id=user_id,
        client_id=client_id,
        expires_at=AuthCode.generate_expires()
    )

    db.session.add(code)
    db.session.commit()

    return {"code": code_str}

@auth.post("/token")
def token():
    data = request.json
    grant_type = data.get("grant_type")

    if grant_type == "authorization_code":
        code = AuthCode.query.filter_by(code=data.get("code")).first()
        if not code or code.expires_at < datetime.utcnow():
            return {"error": "Invalid code"}, 400

        access = create_access_token(code.user_id)
        refresh = create_refresh_token()

        rt = RefreshToken(
            token=refresh,
            user_id=code.user_id,
            client_id=code.client_id,
            expires_at=RefreshToken.generate_expires()
        )

        db.session.add(rt)
        db.session.delete(code)
        db.session.commit()

        return {"access_token": access, "refresh_token": refresh}

    elif grant_type == "refresh_token":
        token_str = data.get("refresh_token")
        rt = RefreshToken.query.filter_by(token=token_str, revoked=False).first()

        if not rt or rt.expires_at < datetime.utcnow():
            return {"error": "Invalid refresh"}, 400

        new_access = create_access_token(rt.user_id)
        new_refresh = create_refresh_token()

        rt.revoked = True

        new_rt = RefreshToken(
            token=new_refresh,
            user_id=rt.user_id,
            client_id=rt.client_id,
            expires_at=RefreshToken.generate_expires()
        )

        db.session.add(new_rt)
        db.session.commit()

        return {"access_token": new_access, "refresh_token": new_refresh}

    return {"error": "Invalid grant type"}, 400
