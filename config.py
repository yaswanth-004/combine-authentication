import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # Session — must work on Vercel (HTTPS, cross-site redirect from Auth0)
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_HTTPONLY    = True
    SESSION_COOKIE_SECURE      = True
    SESSION_COOKIE_SAMESITE    = "None"

    # Auth0
    AUTH0_DOMAIN        = os.environ.get("AUTH0_DOMAIN", "dev-16cf0iiguw088wbm.au.auth0.com")
    AUTH0_CLIENT_ID     = os.environ.get("AUTH0_CLIENT_ID")
    AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
    APP_BASE_URL        = os.environ.get("APP_BASE_URL", "https://combine-authentication-a4vl.vercel.app")

    # AUTH0_CALLBACK_URL is built dynamically in __init__.py from the request host
    # so it always matches whichever Vercel URL the user is visiting
    AUTH0_CALLBACK_URL  = os.environ.get("AUTH0_CALLBACK_URL", "")

    # Cron
    CRON_SECRET = os.environ.get("CRON_SECRET", "")
