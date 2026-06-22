"""
app/__init__.py
---------------
Flask application factory.
All routes live here. Uses Auth0 PKCE Authorization Code Flow.
"""
import os, json, base64, hashlib, secrets, urllib.parse
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from flask import (Flask, redirect, request, session,
                   url_for, render_template, flash)
from config import Config

# Import DB helpers — path is at project root
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database import init_db, save_user, get_user_by_email, update_tokens, send_session_expired_email, get_all_users


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _make_pkce():
    verifier  = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload section without verifying signature (Auth0 already verified it)."""
    part = token.split(".")[1]
    part += "=" * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def init_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    # Init DB on startup
    init_db()

    AUTH0_DOMAIN        = app.config["AUTH0_DOMAIN"]
    AUTH0_CLIENT_ID     = app.config["AUTH0_CLIENT_ID"]
    AUTH0_CLIENT_SECRET = app.config["AUTH0_CLIENT_SECRET"]
    AUTH0_CALLBACK_URL  = app.config["AUTH0_CALLBACK_URL"]

    # ------------------------------------------------------------------
    # Login guard decorator
    # ------------------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_email" not in session:
                flash("Please log in to access this page.", "info")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    # ------------------------------------------------------------------
    # Public routes
    # ------------------------------------------------------------------

    @app.route("/")
    def open_home():
        """Home page — public. Shows different content when logged in."""
        user = None
        if "user_email" in session:
            user = get_user_by_email(session["user_email"])
        return render_template("home.html", user=user)

    @app.route("/home")
    def home():
        user = None
        if "user_email" in session:
            user = get_user_by_email(session["user_email"])
        return render_template("home.html", user=user)

    @app.route("/contact")
    def contact():
        user = None
        if "user_email" in session:
            user = get_user_by_email(session["user_email"])
        return render_template("contact.html", user=user)

    @app.route("/register")
    def register():
        """Register page — explains that Auth0 Universal Login handles this."""
        if "user_email" in session:
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    # ------------------------------------------------------------------
    # Auth0 login — starts PKCE flow
    # ------------------------------------------------------------------

    @app.route("/login")
    def login():
        if "user_email" in session:
            return redirect(url_for("dashboard"))

        verifier, challenge = _make_pkce()
        state = secrets.token_urlsafe(16)
        session["pkce_verifier"] = verifier
        session["oauth_state"]   = state

        params = {
            "response_type":         "code",
            "client_id":             AUTH0_CLIENT_ID,
            "redirect_uri":          AUTH0_CALLBACK_URL,
            # openid = ID token, profile = name/picture, email = email,
            # offline_access = refresh token
            "scope":                 "openid profile email offline_access",
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
            # This tells Auth0 Universal Login to show Google button
            "connection":            "google-oauth2",
        }
        auth_url = f"https://{AUTH0_DOMAIN}/authorize?" + urllib.parse.urlencode(params)
        return redirect(auth_url)

    @app.route("/login/email")
    def login_email():
        """Alternate login — shows Auth0 Universal Login page (all options)."""
        if "user_email" in session:
            return redirect(url_for("dashboard"))

        verifier, challenge = _make_pkce()
        state = secrets.token_urlsafe(16)
        session["pkce_verifier"] = verifier
        session["oauth_state"]   = state

        params = {
            "response_type":         "code",
            "client_id":             AUTH0_CLIENT_ID,
            "redirect_uri":          AUTH0_CALLBACK_URL,
            "scope":                 "openid profile email offline_access",
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"https://{AUTH0_DOMAIN}/authorize?" + urllib.parse.urlencode(params)
        return redirect(auth_url)

    # ------------------------------------------------------------------
    # Auth0 callback — receives auth code, exchanges for tokens
    # ------------------------------------------------------------------

    @app.route("/callback")
    def callback():
        # 1. Check for errors from Auth0
        error = request.args.get("error")
        if error:
            desc = request.args.get("error_description", error)
            flash(f"Login error: {desc}", "danger")
            return redirect(url_for("login"))

        # 2. Validate CSRF state
        if request.args.get("state") != session.pop("oauth_state", None):
            flash("Security check failed (state mismatch). Please try again.", "danger")
            return redirect(url_for("login"))

        # 3. Get the auth code and PKCE verifier
        code     = request.args.get("code")
        verifier = session.pop("pkce_verifier", None)
        if not code or not verifier:
            flash("Missing authorization code. Please try again.", "danger")
            return redirect(url_for("login"))

        # 4. Exchange auth code + verifier → tokens (server-to-server, never in browser)
        token_resp = requests.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type":    "authorization_code",
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "code":          code,
                "redirect_uri":  AUTH0_CALLBACK_URL,
                "code_verifier": verifier,
            },
            timeout=15,
        )
        if not token_resp.ok:
            flash(f"Token exchange failed: {token_resp.text}", "danger")
            return redirect(url_for("login"))

        tokens        = token_resp.json()
        access_token  = tokens["access_token"]          # short-lived JWT
        refresh_token = tokens.get("refresh_token", "") # long-lived
        id_token      = tokens["id_token"]              # user identity JWT
        expires_in    = tokens.get("expires_in", 86400)

        # 5. Decode ID token payload → extract email + username
        #    Auth0 already validated the ID token's signature with RS256.
        #    We decode the payload (middle section) to read the claims.
        claims   = _decode_jwt_payload(id_token)
        email    = claims.get("email", "")
        username = claims.get("name", "") or email.split("@")[0]
        picture  = claims.get("picture", "")

        # 6. Calculate expiry time
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()

        # 7. Save to DB — email + username are unique identifiers
        save_user(
            email=email,
            username=username,
            picture=picture,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
        )

        # 8. Store email in session (session is server-side signed cookie)
        session.permanent = True
        session["user_email"]    = email
        session["user_username"] = username
        session["user_picture"]  = picture

        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------
    # Protected routes (login_required)
    # ------------------------------------------------------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = get_user_by_email(session["user_email"])
        return render_template("dashboard.html", user=user)

    @app.route("/profile")
    @login_required
    def profile():
        user = get_user_by_email(session["user_email"])
        return render_template("profile.html", user=user)

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    @app.route("/logout")
    def logout():
        session.clear()
        # Auth0 clears its own session and redirects back to our login page
        params = {
            "returnTo":  url_for("login", _external=True),
            "client_id": AUTH0_CLIENT_ID,
        }
        return redirect(f"https://{AUTH0_DOMAIN}/v2/logout?" + urllib.parse.urlencode(params))

    # ------------------------------------------------------------------
    # Cron endpoint — POST /internal/refresh-tokens
    # Call this once per day from cron-job.org with header X-Cron-Secret
    # ------------------------------------------------------------------

    @app.route("/internal/refresh-tokens", methods=["POST"])
    def refresh_tokens_cron():
        secret = request.headers.get("X-Cron-Secret", "")
        if not secret or secret != app.config.get("CRON_SECRET", ""):
            return {"error": "unauthorized"}, 401

        users   = get_all_users()
        now     = datetime.now(timezone.utc)
        results = []

        for user in users:
            exp = datetime.fromisoformat(user["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)

            # Skip if token is still valid for > 1 hour
            if now < exp - timedelta(hours=1):
                results.append({"email": user["email"], "status": "valid"})
                continue

            # Try refreshing
            r = requests.post(
                f"https://{AUTH0_DOMAIN}/oauth/token",
                json={
                    "grant_type":    "refresh_token",
                    "client_id":     AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "refresh_token": user["refresh_token"],
                },
                timeout=15,
            )
            if r.ok:
                t       = r.json()
                new_exp = (datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 86400))).isoformat()
                update_tokens(
                    user["email"],
                    t["access_token"],
                    t.get("refresh_token", user["refresh_token"]),
                    new_exp,
                )
                results.append({"email": user["email"], "status": "refreshed"})
            else:
                # Refresh token expired — notify user by email
                send_session_expired_email(user["email"], user["username"])
                results.append({"email": user["email"], "status": "expired — email sent"})

        return {"checked": len(results), "results": results}, 200

    return app
