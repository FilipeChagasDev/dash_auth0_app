# Dash Auth0 App

This repository contains a minimal Plotly Dash application integrated with Auth0 authentication. It is intended to serve as a starter template for building larger, production-ready Dash apps that require secure user login and authentication.

## What’s inside

* **Dash app** with a tiny UI: shows the authenticated user profile and a “Say Hello” button that greets the user by name.
* **Auth0 integration** (OAuth 2.0/OpenID Connect) implemented with `Authlib`.
* **Cookie-based session** plus a few helper functions to read user info anywhere in your app.
* Minimal, readable code you can extend.

**Files**

* `app.py` – the Dash app (layout + a demo callback).
* `auth0.py` – Auth0 integration for Flask/Dash (login, callback, logout, helpers).

---

## How it works (high level)

1. **First visit**
   Any request to the app is wrapped and checked: if the user isn’t authenticated, we redirect them to Auth0’s **/authorize** endpoint.

2. **Auth0 login**
   The user signs in on Auth0. Auth0 then redirects back to your app’s callback URL with an authorization code.

3. **Token exchange & userinfo**
   The app exchanges the code for tokens at **/oauth/token**, then calls **/userinfo** to get the profile (name, email, picture, etc.). It stores key fields in cookies and the access token in the Flask session.

4. **Using the profile in Dash**
   The Dash layout can read the user profile (e.g., show the first/last name, email, avatar) and your callbacks can use that too. A **Logout** link routes the user through Auth0’s logout and back to your app.

---

## Requirements

* Python 3.8+
* An Auth0 tenant & application (Regular Web Application)

---

## Installation

```bash
# 1) Clone
git clone https://github.com/your-username/your-repo.git
cd your-repo

# 2) (Recommended) Create a virtual environment
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

# 3) Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file in the project root based on the example below:

```ini
# .env (example)
FLASK_SECRET_KEY=your_flask_secret_key_here

# Auth0 application credentials
AUTH0_AUTH_CLIENT_ID=your_auth0_client_id
AUTH0_AUTH_CLIENT_SECRET=your_auth0_client_secret

# Auth0 endpoints (replace <your-tenant> with your Auth0 domain, e.g. dev-xxxxxx.us.auth0.com)
AUTH0_AUTH_URL=https://<your-tenant>/authorize
AUTH0_AUTH_TOKEN_URI=https://<your-tenant>/oauth/token
AUTH0_AUTH_USER_INFO_URL=https://<your-tenant>/userinfo
AUTH0_LOGOUT_URL=https://<your-tenant>/v2/logout

# Requested scopes (keep at least: openid profile email)
AUTH0_AUTH_SCOPE=openid profile email

# API Audience (Identifier from Auth0 > APIs)
AUTH0_API_AUDIENCE=https://your-api-identifier

# Protect Flask routes (must be "true" or "false")
AUTH_FLASK_ROUTES=true
```

> Tip: In production, set these as real environment variables in your hosting platform instead of using `.env`.

---

## Running locally

```bash
python app.py
```

Open the app at [http://127.0.0.1:8050/](http://127.0.0.1:8050/) (or [http://localhost:8050/](http://localhost:8050/)).
You’ll be redirected to Auth0 to log in. After a successful login you’ll land back on the app and see your profile.

---

## Auth0 dashboard setup

1. **Create an Application**

   * Go to **Applications → Applications → Create Application**.
   * Name it (e.g., “Dash App”) and choose **Regular Web Application**.

2. **Allowed URLs**

   * **Allowed Callback URLs**

     * `http://127.0.0.1:8050/login/callback`
     * `http://localhost:8050/login/callback`
   * **Allowed Logout URLs**

     * `http://127.0.0.1:8050/`
     * `http://localhost:8050/`
   * **Allowed Web Origins**

     * `http://127.0.0.1:8050`
     * `http://localhost:8050`

3. **Copy credentials**

   * From the application settings, copy **Client ID**, **Client Secret**, and your **Auth0 Domain** (e.g., `dev-xxxxxx.us.auth0.com`) into your `.env`.

4. **(Optional) Create an API**

   * Go to **Applications → APIs → Create API**.
   * Set an **Identifier** (this becomes your **API Audience**, e.g., `https://your-api-identifier`).
   * Put that identifier in `AUTH0_API_AUDIENCE` in your `.env`.
   * Ensure your application is allowed to request this API (default is fine for local dev).

5. **Scopes**

   * Keep `AUTH0_AUTH_SCOPE` as `openid profile email` unless you need extra scopes for your API.

---

## Code walkthrough

### `auth0.py` (authentication layer)

* **Initialization**
  The `Auth0Auth(app, ...)` constructor reads credentials and endpoints from environment variables, configures Flask session, and registers:

  * `GET /login/callback` – handles the OAuth authorization code callback.
  * `GET /logout/` – clears cookies/session and redirects through Auth0 logout back to your app.

* **Route protection**
  All views (including the Dash index) are wrapped. If a user isn’t authorized, the wrapper triggers the Auth0 login flow. Once authorized, requests pass through normally.

* **Login flow**
  The app creates an authorization URL with your **audience** and **scope**, saves state in the session, and redirects to Auth0. After Auth0 redirects back, the app exchanges the code for tokens, calls `/userinfo`, stores profile fields in cookies, and saves the access token in the session.

* **Helper functions**

  * `get_user_info()` returns a dict with `name`, `nickname`, `email`, `given_name`, `family_name`, `picture`, `access_token`.
  * Convenience getters like `get_user_email()`, `get_user_first_name()`, etc., are provided for granular access.

### `app.py` (the Dash app)

* **Layout**
  Shows a small page with:

  * A **Logout** link (`/logout`).
  * A **Profile Data** block that prints the user info from `get_user_info()`.
  * A **“Say Hello”** button and an output div.

* **Callback**
  On click, the callback reads the user profile and prints “Hello, {first} {last}”.

---

## Customization tips

* **Access token use**
  Use `get_user_info()["access_token"]` to call your own API (the audience you configured). For requests from the server (Python), pass it in the `Authorization: Bearer <token>` header.

* **Authorization/roles**
  You can add an “authorization hook” pattern or check custom claims in the ID/access token to gate parts of your UI or callbacks.

* **UI & navigation**
  Replace the basic `html.Div` with your full layout, multipage navigation, and components. Because authentication wraps the index, your pages all benefit from the same protection.

* **Toggling Flask route protection**
  Set `AUTH_FLASK_ROUTES=false` if you need to expose custom unprotected routes (e.g., health checks). Keep it `true` for most cases.

---

## Troubleshooting

* **403 on pages**
  Usually means the user isn’t authenticated yet or the session/cookies were cleared. Try reloading; you should be redirected to Auth0.

* **Callback/Logout errors**
  Double-check the **Allowed Callback URLs** and **Allowed Logout URLs** in Auth0 exactly match your app’s URLs (including scheme and port).

* **“invalid\_client” or “unauthorized\_client”**
  Ensure `AUTH0_AUTH_CLIENT_ID`, `AUTH0_AUTH_CLIENT_SECRET`, and the correct Auth0 **Domain** are set.

* **Audience mismatch**
  If calling your API returns 401, verify that `AUTH0_API_AUDIENCE` matches the API’s **Identifier** and that your app requests that audience.

---

## License

MIT — feel free to use this as a base for your own projects.
