import os
from dotenv import load_dotenv


load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///lackson_auth.db")


    JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-jwt")


    ACCESS_TOKEN_EXP = int(os.environ.get("ACCESS_TOKEN_EXP", 900))          # 15 minutes
    REFRESH_TOKEN_EXP = int(os.environ.get("REFRESH_TOKEN_EXP", 2592000))    # 30 days
