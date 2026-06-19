# combine_authentication

Flask + Auth0 PKCE authentication app with Google login, JWT token storage, and automatic refresh.

## Project structure

```
combine_authentication/
├── app/
│   ├── __init__.py          ← All Flask routes + PKCE logic
│   └── templates/
│       ├── base.html
│       ├── home.html
│       ├── login.html       ← Google sign-in button
│       ├── register.html
│       ├── dashboard.html   ← Protected — shows tokens
│       ├── profile.html     ← Protected
│       ├── contact.html
│       └── error.html
├── database.py              ← SQLite: save/get/update users + tokens
├── config.py                ← All settings from .env
├── run.py                   ← Entry point
├── requirements.txt
├── vercel.json              ← Vercel deployment config
└── .env                     ← Your secrets (never commit this)
```

## Setup

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/combine-authentication
cd combine-authentication
pip install -r requirements.txt
```

### 2. Fill in .env

```
AUTH0_DOMAIN=dev-16cf0iiguw088wbm.au.auth0.com
AUTH0_CLIENT_ID=UF6Rh8x099aGS3hyij77Sq3Wp6lp6csN
AUTH0_CLIENT_SECRET=your_secret_here
AUTH0_CALLBACK_URL=https://combine-authentication.vercel.app/callback
APP_BASE_URL=https://combine-authentication.vercel.app
SECRET_KEY=any-long-random-string
FLASK_SECRET_KEY=same-or-different-long-random-string
CRON_SECRET=random-secret-for-cron-job
```

### 3. Run locally

```bash
python run.py
# Visit http://localhost:5000
```

### 4. Deploy to Vercel

```bash
npm i -g vercel
vercel
```

Add all .env values as Vercel Environment Variables in the dashboard.

### 5. Set up daily token refresh (cron-job.org — free)

- URL: `https://combine-authentication.vercel.app/internal/refresh-tokens`
- Method: POST
- Header: `X-Cron-Secret: your-cron-secret`
- Schedule: Once per day

## Auth0 dashboard checklist

- [x] Application type: Regular Web Application
- [x] Callback URL: `https://combine-authentication.vercel.app/callback`
- [x] Logout URL: `https://combine-authentication.vercel.app`
- [x] Web Origins: `https://combine-authentication.vercel.app`
- [x] Authentication method: Client Secret (Post)
- [x] Refresh token rotation: ON
- [x] Google social connection: enabled + connected to this app
- [x] Scope `offline_access` requested (gives refresh token)

## Google Console checklist

- [x] Redirect URI: `https://dev-16cf0iiguw088wbm.au.auth0.com/login/callback`
- [x] Client ID + Secret pasted into Auth0 Google connection
