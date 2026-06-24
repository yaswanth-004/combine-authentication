import os, json, base64, hashlib, secrets, urllib.parse, hmac
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from flask import (Flask, redirect, request, session,
                   url_for, render_template, flash,
                   get_flashed_messages, jsonify)
from config import Config

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database import init_db, save_user, get_user_by_email, update_tokens, send_session_expired_email, get_all_users


# ── PKCE helpers ────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _make_pkce():
    verifier  = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def _decode_jwt_payload(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))

# Pack verifier into state so no session needed between /login and /callback
def _make_state(verifier: str, secret: str) -> str:
    nonce   = secrets.token_urlsafe(16)
    payload = _b64url((verifier + "|" + nonce).encode())
    sig     = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig

def _unpack_state(state: str, secret: str) -> str:
    try:
        payload, sig = state.rsplit(".", 1)
    except ValueError:
        raise ValueError("Malformed state")
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("State signature mismatch")
    raw = _b64url_decode(payload).decode()
    return raw.split("|")[0]


# ── App factory ─────────────────────────────────────────────────────────────

def init_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    init_db()

    AUTH0_DOMAIN        = app.config["AUTH0_DOMAIN"]
    AUTH0_CLIENT_ID     = app.config["AUTH0_CLIENT_ID"]
    AUTH0_CLIENT_SECRET = app.config["AUTH0_CLIENT_SECRET"]
    SECRET_KEY          = app.config["SECRET_KEY"]

    def get_callback_url():
        """Always build callback URL from the actual request host."""
        return f"https://{request.host}/callback"

    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_email" not in session:
                flash("Please log in to access this page.", "info")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    # ── Public routes ────────────────────────────────────────────────────────

    @app.route("/")
    def open_home():
        user = get_user_by_email(session["user_email"]) if "user_email" in session else None
        return render_template("home.html", user=user)

    @app.route("/home")
    def home():
        user = get_user_by_email(session["user_email"]) if "user_email" in session else None
        return render_template("home.html", user=user)

    @app.route("/contact")
    def contact():
        user = get_user_by_email(session["user_email"]) if "user_email" in session else None
        return render_template("contact.html", user=user)

    @app.route("/register")
    def register():
        if "user_email" in session:
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    # ── Login ────────────────────────────────────────────────────────────────

    @app.route("/login")
    def login():
        if "user_email" in session:
            return redirect(url_for("dashboard"))
        verifier, challenge = _make_pkce()
        state        = _make_state(verifier, SECRET_KEY)
        callback_url = get_callback_url()
        params = {
            "response_type":         "code",
            "client_id":             AUTH0_CLIENT_ID,
            "redirect_uri":          callback_url,
            "scope":                 "openid profile email offline_access",
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
            "connection":            "google-oauth2",
        }
        return redirect(f"https://{AUTH0_DOMAIN}/authorize?" + urllib.parse.urlencode(params))

    @app.route("/login/email")
    def login_email():
        if "user_email" in session:
            return redirect(url_for("dashboard"))
        verifier, challenge = _make_pkce()
        state        = _make_state(verifier, SECRET_KEY)
        callback_url = get_callback_url()
        params = {
            "response_type":         "code",
            "client_id":             AUTH0_CLIENT_ID,
            "redirect_uri":          callback_url,
            "scope":                 "openid profile email offline_access",
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        return redirect(f"https://{AUTH0_DOMAIN}/authorize?" + urllib.parse.urlencode(params))

    # ── Callback ─────────────────────────────────────────────────────────────

    @app.route("/callback")
    def callback():
        # Auth0 returned an error
        error = request.args.get("error")
        if error:
            desc = request.args.get("error_description", error)
            flash(f"Auth0 error: {desc}", "danger")
            return redirect(url_for("login"))

        # Unpack verifier from state (no session needed)
        state = request.args.get("state", "")
        try:
            verifier = _unpack_state(state, SECRET_KEY)
        except ValueError as e:
            flash(f"Security check failed ({e}). Please try again.", "danger")
            return redirect(url_for("login"))

        code = request.args.get("code")
        if not code:
            flash("Missing authorization code. Please try again.", "danger")
            return redirect(url_for("login"))

        # Exchange code for tokens
        callback_url = get_callback_url()
        token_resp = requests.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type":    "authorization_code",
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "code":          code,
                "redirect_uri":  callback_url,
                "code_verifier": verifier,
            },
            timeout=15,
        )

        if not token_resp.ok:
            flash(f"Token exchange failed: {token_resp.text}", "danger")
            return redirect(url_for("login"))

        tokens       = token_resp.json()
        id_token     = tokens.get("id_token", "")
        access_token = tokens.get("access_token", "")
        refresh_token= tokens.get("refresh_token", "")
        expires_in   = tokens.get("expires_in", 86400)

        claims   = _decode_jwt_payload(id_token)
        email    = claims.get("email", "")
        username = claims.get("name", "") or email.split("@")[0]
        picture  = claims.get("picture", "")
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()

        save_user(
            email=email, username=username, picture=picture,
            access_token=access_token, refresh_token=refresh_token,
            expires_at=expires_at,
        )

        session.permanent    = True
        session["user_email"]    = email
        session["user_username"] = username
        session["user_picture"]  = picture

        flash(f"Welcome, {username}!", "success")
        return redirect(url_for("dashboard"))

    # ── Protected routes ─────────────────────────────────────────────────────

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

    # ── Logout ───────────────────────────────────────────────────────────────

    @app.route("/logout")
    def logout():
        session.clear()
        params = {
            "returnTo":  f"https://{request.host}/login",
            "client_id": AUTH0_CLIENT_ID,
        }
        return redirect(f"https://{AUTH0_DOMAIN}/v2/logout?" + urllib.parse.urlencode(params))

    # ── Debug page (shows live config — REMOVE AFTER FIXING) ─────────────────

    @app.route("/debug")
    def debug():
        callback_url = get_callback_url()
        secret_ok    = SECRET_KEY != "dev-secret-change-me"
        client_ok    = bool(AUTH0_CLIENT_ID and len(AUTH0_CLIENT_ID) > 5)
        secret_id_ok = bool(AUTH0_CLIENT_SECRET and len(AUTH0_CLIENT_SECRET) > 5)

        rows = [
            ("AUTH0_DOMAIN",          AUTH0_DOMAIN,          "✅" if AUTH0_DOMAIN else "❌ NOT SET"),
            ("AUTH0_CLIENT_ID",       AUTH0_CLIENT_ID or "", "✅" if client_ok else "❌ NOT SET"),
            ("AUTH0_CLIENT_SECRET",   f"{'*'*8} ({len(AUTH0_CLIENT_SECRET or '')} chars)", "✅" if secret_id_ok else "❌ NOT SET"),
            ("SECRET_KEY",            f"{SECRET_KEY[:6]}... ({len(SECRET_KEY)} chars)", "✅ custom" if secret_ok else "⚠️ still default"),
            ("request.host",          request.host,          "✅"),
            ("callback_url",          callback_url,          "✅"),
            ("SESSION_COOKIE_SAMESITE", str(app.config.get("SESSION_COOKIE_SAMESITE")), ""),
            ("SESSION_COOKIE_SECURE", str(app.config.get("SESSION_COOKIE_SECURE")), ""),
        ]

        table = "".join(
            f"<tr><td><b>{k}</b></td><td>{v}</td><td>{s}</td></tr>"
            for k, v, s in rows
        )

        return f"""<!DOCTYPE html><html><body style="font-family:monospace;padding:2rem;background:#f5f5f5">
        <h2>🔍 Live Debug Info</h2>
        <table border=1 cellpadding=8 style="border-collapse:collapse;background:white">
          <tr><th>Key</th><th>Value</th><th>Status</th></tr>
          {table}
        </table>
        <br>
        <a href="/debug/token-test" style="background:#007bff;color:white;padding:.6rem 1.2rem;text-decoration:none;border-radius:4px">
          ▶ Test Auth0 Token Endpoint
        </a>
        &nbsp;
        <a href="/debug/auth0-check" style="background:#28a745;color:white;padding:.6rem 1.2rem;text-decoration:none;border-radius:4px">
          ▶ Check Auth0 App Settings
        </a>
        </body></html>"""

    @app.route("/debug/token-test")
    def debug_token_test():
        callback_url = get_callback_url().replace("/debug/token-test", "/callback")
        r = requests.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json={
                "grant_type":    "authorization_code",
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "code":          "FAKE_TEST_CODE",
                "redirect_uri":  callback_url,
                "code_verifier": "FAKE_VERIFIER_FOR_TEST",
            },
            timeout=15,
        )
        data = r.json()
        error = data.get("error", "")
        diagnosis = ""
        if error == "invalid_grant":
            diagnosis = "✅ Good — Auth0 is reachable and credentials are correct. 'invalid_grant' just means our test code is fake."
        elif error == "unauthorized_client":
            diagnosis = "❌ AUTH0_CLIENT_ID or AUTH0_CLIENT_SECRET is wrong in Vercel env vars."
        elif error == "access_denied":
            diagnosis = "❌ Client secret is wrong."
        elif "not found" in str(data).lower():
            diagnosis = "❌ AUTH0_CLIENT_ID is wrong — app not found in Auth0."
        else:
            diagnosis = f"⚠️ Unexpected response — check AUTH0_DOMAIN, CLIENT_ID, CLIENT_SECRET"

        return f"""<!DOCTYPE html><html><body style="font-family:monospace;padding:2rem">
        <h2>Token Endpoint Test</h2>
        <p><b>URL tested:</b> https://{AUTH0_DOMAIN}/oauth/token</p>
        <p><b>HTTP Status:</b> {r.status_code}</p>
        <p><b>Response:</b></p>
        <pre style="background:#f0f0f0;padding:1rem">{json.dumps(data, indent=2)}</pre>
        <h3>Diagnosis: {diagnosis}</h3>
        <br><a href="/debug">← Back</a>
        </body></html>"""

    @app.route("/debug/auth0-check")
    def debug_auth0_check():
        callback_url = get_callback_url().replace("/debug/auth0-check", "/callback")
        return f"""<!DOCTYPE html><html><body style="font-family:monospace;padding:2rem">
        <h2>Auth0 Checklist</h2>
        <p>Go to <a href="https://manage.auth0.com" target="_blank">manage.auth0.com</a>
        → Applications → Your App → Settings and verify:</p>
        <ol style="line-height:2">
          <li><b>Allowed Callback URLs</b> must contain exactly:<br>
              <code style="background:#ffe;padding:4px">{callback_url}</code></li>
          <li><b>Allowed Logout URLs</b> must contain:<br>
              <code style="background:#ffe;padding:4px">https://{request.host}</code></li>
          <li><b>Allowed Web Origins</b> must contain:<br>
              <code style="background:#ffe;padding:4px">https://{request.host}</code></li>
          <li>Google Social Connection must be <b>enabled</b> for this app</li>
          <li>Your Vercel env vars must have:<br>
              <code>AUTH0_CLIENT_ID</code>, <code>AUTH0_CLIENT_SECRET</code>, <code>SECRET_KEY</code></li>
        </ol>
        <br><a href="/debug">← Back</a>
        </body></html>"""

    # ── Cron ─────────────────────────────────────────────────────────────────

    @app.route("/internal/refresh-tokens", methods=["POST"])
    def refresh_tokens_cron():
        if request.headers.get("X-Cron-Secret", "") != app.config.get("CRON_SECRET", ""):
            return {"error": "unauthorized"}, 401
        users   = get_all_users()
        now     = datetime.now(timezone.utc)
        results = []
        for user in users:
            exp = datetime.fromisoformat(user["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now < exp - timedelta(hours=1):
                results.append({"email": user["email"], "status": "valid"})
                continue
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
                t = r.json()
                new_exp = (datetime.now(timezone.utc) + timedelta(seconds=t.get("expires_in", 86400))).isoformat()
                update_tokens(user["email"], t["access_token"], t.get("refresh_token", user["refresh_token"]), new_exp)
                results.append({"email": user["email"], "status": "refreshed"})
            else:
                send_session_expired_email(user["email"], user["username"])
                results.append({"email": user["email"], "status": "expired"})
        return {"checked": len(results), "results": results}, 200

    return app
