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


### 3. Run locally

```bash
python run.py
# Visit http://localhost:5000
```


Add all .env values as Vercel Environment Variables in the dashboard.

