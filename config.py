import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY              = os.environ.get("SECRET_KEY", "dev-secret-change-me")
   

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_HTTPONLY    = True
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") != "development"
    SESSION_COOKIE_SAMESITE    = "Lax"

    # Database
    SQLALCHEMY_DATABASE_URI        = os.environ.get("DATABASE_URL", "sqlite:///instance/users.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Auth0
    AUTH0_DOMAIN        = os.environ.get("AUTH0_DOMAIN", "dev-16cf0iiguw088wbm.au.auth0.com")
    AUTH0_CLIENT_ID     = os.environ.get("AUTH0_CLIENT_ID")
    AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
    AUTH0_CALLBACK_URL  = os.environ.get("AUTH0_CALLBACK_URL", "https://combine-authentication-a4vl.vercel.app/callback")
    APP_BASE_URL        = os.environ.get("APP_BASE_URL",  "https://combine-authentication-a4vl.vercel.app")
  

    # Token settings (mirrors what you set in Auth0 dashboard)
    ACCESS_TOKEN_LIFETIME_SECONDS  = 86400      # 1 day
    REFRESH_TOKEN_LIFETIME_SECONDS = 86400      # 1 day

    # Cron protection
    CRON_SECRET = os.environ.get("CRON_SECRET", "")
