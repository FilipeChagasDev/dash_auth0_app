"""
Auth0 for Plotly Dash

Based on: https://github.com/dbrambilla13/dash-auth0-auth.

This module provides authentication for Flask and Dash applications using Auth0 as the identity provider.
It defines an abstract Auth class and a concrete Auth0Auth implementation that handles OAuth2 login, logout, and user session management.
User information is stored in cookies and can be accessed via helper functions.

Usage in a Dash App:
--------------------
1. Set required Auth0 and Flask environment variables:
    ```
    FLASK_SECRET_KEY="<some secret key>"

    AUTH0_AUTH_URL="https://<your tenant url>/authorize"
    AUTH0_AUTH_SCOPE="openid profile email"
    AUTH0_AUTH_TOKEN_URI="https://<your tenant url>/oauth/token"
    AUTH0_AUTH_USER_INFO_URL="https://<your tenant url>/userinfo"
    AUTH0_AUTH_CLIENT_ID="<your app client id>"
    AUTH0_AUTH_CLIENT_SECRET="<your app client secret>"
    AUTH0_LOGOUT_URL="https://<your tenant url>/v2/logout"
    AUTH0_API_AUDIENCE="<your_api_audience_identifier>"
    AUTH_FLASK_ROUTES="true"
    ```

2. Initialize your Dash app and wrap it with Auth0Auth:
    ```python
    import auth0

    app = dash.Dash(__name__, server=True)
    auth = auth0.Auth0Auth(app)
    ```

3. Protect your routes and access user info:
    - The index and all routes are protected by default.
    - Use helper functions like `get_user_info()` to access authenticated user data.

4. Set `AUTH_FLASK_ROUTES=true` in your environment to enable route protection.

5. Configure your application in Auth0:
    - Create a new application in the Auth0 dashboard.
    - Set the application type to "Regular Web Application".
    - In "Allowed Callback URLs", add: `http://localhost:8050/login/callback` and `http://127.0.0.1:8050/login/callback` (or your app's URL).
    - In "Allowed Logout URLs", add: `http://localhost:8050/` and `http://127.0.0.1:8050/` (or your app's URL).
    - In "Allowed Web Origins", add: `http://localhost:8050` and `http://127.0.0.1:8050` (or your app's URL).
    - Copy the "Client ID" and "Client Secret" to use in your environment variables.
    - Use your Auth0 domain (e.g., `dev-xxxxxx.us.auth0.com`) to configure the authorization, token, userinfo, and logout URLs.

6. How to find your API Audience URL:
    - In the Auth0 dashboard, go to "APIs" in the sidebar.
    - Select or create an API for your application.
    - The "Identifier" field of the API is your API Audience URL (e.g., `https://myapi.example.com`).
    - Use this value for the `AUTH0_API_AUDIENCE` environment variable.
"""

from __future__ import absolute_import
from abc import ABCMeta, abstractmethod
from six import iteritems, add_metaclass
import os

import flask
from flask import url_for

from authlib.integrations.requests_client import OAuth2Session
from urllib.parse import urlencode, urljoin

from dotenv import load_dotenv
load_dotenv()


# Cookie expiry time
COOKIE_EXPIRY = 60 * 60 * 24 * 14 # 14 days

# Cookie names
COOKIE_AUTH_USER_NAME = 'AUTH-USER'
COOKIE_AUTH_ACCESS_TOKEN = 'AUTH-TOKEN'
COOKIE_AUTH_NICKNAME = 'AUTH-NICKNAME'
COOKIE_AUTH_EMAIL = 'AUTH-EMAIL'
COOKIE_AUTH_FIRST_NAME = 'AUTH-FIRST-NAME'
COOKIE_AUTH_LAST_NAME = 'AUTH-LAST-NAME'
COOKIE_AUTH_PICTURE_URL = 'AUTH-PICTURE-URL'

# Auth0 state key
AUTH_STATE_KEY = 'auth_state'

# Auth0 callback URL
AUTH_REDIRECT_URI = '/login/callback'


@add_metaclass(ABCMeta)
class Auth(object):
    """
    Handles authentication for the application.
    """
    def __init__(self, app, authorization_hook=None, _overwrite_index=True):
        """
        Initialize the authentication handler for the given app.
        Args:
            app: The application instance to be protected.
            authorization_hook (callable, optional): A function to be called for authorization checks. Defaults to None.
            _overwrite_index (bool, optional): Whether to overwrite the index view and protect views. Defaults to True.
        Attributes:
            app: Stores the application instance.
            _index_view_name: The name of the index view, derived from app configuration.
            _auth_hooks: List of authorization hooks to be used for access control.
        """
        self.app = app
        self._index_view_name = app.config['routes_pathname_prefix']
        if _overwrite_index:
            self._overwrite_index()
            self._protect_views()
        self._index_view_name = app.config['routes_pathname_prefix']
        self._auth_hooks = [authorization_hook] if authorization_hook else []


    def _overwrite_index(self):
        """
        Overwrites the Flask application's index view function with an authentication wrapper.
        This method retrieves the original index view function from the Flask app's server,
        wraps it with an authentication handler, and replaces the original function with the wrapped version.
        This ensures that authentication is enforced when accessing the index route.
        Returns:
            None
        """
        original_index = self.app.server.view_functions[self._index_view_name]

        self.app.server.view_functions[self._index_view_name] = \
            self.index_auth_wrapper(original_index)


    def _protect_views(self):
        """
        Wraps all registered view functions in the application with an authentication wrapper,
        except for the index view. This ensures that all views require authentication unless
        explicitly whitelisted. Intended to be used for protecting views from unauthorized access.
        TODO:
            - Allow users to whitelist specific views if they add their own.
        Returns:
            None
        """
        # TODO - allow users to white list in case they add their own views
        for view_name, view_method in iteritems(
                self.app.server.view_functions):
            if view_name != self._index_view_name:
                self.app.server.view_functions[view_name] = \
                    self.auth_wrapper(view_method)


    def is_authorized_hook(self, func):
        """
        Registers a function as an authorization hook.
        The provided function will be appended to the list of authorization hooks
        and can be used to perform custom authorization logic.
        Args:
            func (callable): The function to register as an authorization hook.
        Returns:
            callable: The same function that was passed in, for decorator usage.
        """
        self._auth_hooks.append(func)
        return func


    @abstractmethod
    def is_authorized(self):
        pass


    @abstractmethod
    def auth_wrapper(self, f):
        pass


    @abstractmethod
    def index_auth_wrapper(self, f):
        pass


    @abstractmethod
    def login_request(self):
        pass


class Auth0Auth(Auth):
    """
    Auth0 authentication handler.
    """
    def __init__(self, 
            app, 
            client_id = os.environ.get('AUTH0_AUTH_CLIENT_ID'),
            client_secret = os.environ.get('AUTH0_AUTH_CLIENT_SECRET'),
            logout_url = os.environ.get('AUTH0_LOGOUT_URL'),
            auth_flask_routes = os.environ.get('AUTH_FLASK_ROUTES', "false"),
            auth_url = os.environ.get('AUTH0_AUTH_URL'),
            auth_scope = os.environ.get('AUTH0_AUTH_SCOPE'),
            auth_token_uri = os.environ.get('AUTH0_AUTH_TOKEN_URI'),
            auth_user_info_url = os.environ.get('AUTH0_AUTH_USER_INFO_URL'),
            api_audience = os.environ.get('AUTH0_API_AUDIENCE'),
        ):
        """
        Initializes the authentication handler for the given Flask app.
        Sets up the secret key and session type for the Flask server configuration.
        Registers routes for login callback and logout functionality.
        Args:
            app: The Flask application instance to configure authentication for.
            cliend_id (str, optional): Auth0 client ID. Defaults to value from 'AUTH0_AUTH_CLIENT_ID' environment variable.
            client_secret (str, optional): Auth0 client secret. Defaults to value from 'AUTH0_AUTH_CLIENT_SECRET' environment variable.
            logout_url (str, optional): URL to redirect to after logout. Defaults to value from 'AUTH0_LOGOUT_URL' environment variable.
            auth_flask_routes (str, optional): Whether to register Flask authentication routes ('true' or 'false'). Defaults to value from 'AUTH_FLASK_ROUTES' environment variable.
            auth_url (str, optional): Auth0 authorization URL. Defaults to value from 'AUTH0_AUTH_URL' environment variable.
            auth_scope (str, optional): Auth0 authorization scope. Defaults to value from 'AUTH0_AUTH_SCOPE' environment variable.
            auth_token_uri (str, optional): Auth0 token URI. Defaults to value from 'AUTH0_AUTH_TOKEN_URI' environment variable.
            auth_user_info_url (str, optional): Auth0 user info URL. Defaults to value from 'AUTH0_AUTH_USER_INFO_URL' environment variable.
            api_audience (str, optional): Auth0 API audience. Defaults to value from 'AUTH0_API_AUDIENCE' environment variable.
        """
        assert client_id is not None, "AUTH0_AUTH_CLIENT_ID must be set in environment variables"
        assert client_secret is not None, "AUTH0_AUTH_CLIENT_SECRET must be set in environment variables"
        assert logout_url is not None, "AUTH0_LOGOUT_URL must be set in environment variables"
        assert auth_flask_routes is not None, "AUTH_FLASK_ROUTES must be set in environment variables"
        assert auth_flask_routes.lower() in ['true', 'false'], "AUTH_FLASK_ROUTES must be 'true' or 'false'"
        assert auth_url is not None, "AUTH0_AUTH_URL must be set in environment variables"
        assert auth_scope is not None, "AUTH0_AUTH_SCOPE must be set in environment variables"
        assert auth_token_uri is not None, "AUTH0_AUTH_TOKEN_URI must be set in environment variables"
        assert auth_user_info_url is not None, "AUTH0_AUTH_USER_INFO_URL must be set in environment variables"
        assert api_audience is not None, "AUTH0_API_AUDIENCE must be set in environment variables"

        # Auth0 client credentials
        self.client_id = client_id
        self.client_secret = client_secret
        self.logout_url = logout_url
        self.auth_flask_routes = True if auth_flask_routes.lower() == 'true' else False
        self.auth_url = auth_url
        self.auth_scope = auth_scope
        self.auth_token_uri = auth_token_uri
        self.auth_user_info_url = auth_user_info_url
        self.api_audience = api_audience

        Auth.__init__(self, app)

        app.server.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
        app.server.config['SESSION_TYPE'] = 'filesystem'

        @app.server.route('/login/callback')
        def callback():
            return self.login_callback()

        @app.server.route('/logout/')
        def logout():
            return self.logout()


    def is_authorized(self):
        """
        Checks if the current user is authorized based on cookies and session data.
        Retrieves the username and access token from cookies. If either is missing,
        authorization fails. Otherwise, verifies that the session token for the user
        matches the access token from the cookie.
        Returns:
            bool: True if the user is authorized, False otherwise.
        """
        user = flask.request.cookies.get(COOKIE_AUTH_USER_NAME)
        token = flask.request.cookies.get(COOKIE_AUTH_ACCESS_TOKEN)
        if not user or not token:
            return False
        return flask.session.get(user) == token


    def login_request(self):
        """
        Initiates the OAuth2 login flow by creating an authorization URL and redirecting the user to the authentication provider.
        This method constructs the redirect URI, initializes an OAuth2 session, and generates the authorization URL with the required audience and scope.
        It stores the current request URL and OAuth2 state in the Flask session for later validation, then redirects the user to the authentication provider.
        Returns:
            flask.Response: A redirect response to the authentication provider's authorization URL.
        """
        redirect_uri = urljoin(flask.request.base_url, AUTH_REDIRECT_URI) 

        session = OAuth2Session(
            self.client_id,
            self.client_secret,
            scope=self.auth_scope,
            redirect_uri=redirect_uri            
        )
        
        uri, state = session.create_authorization_url(
            self.auth_url,
            audience=self.api_audience
        )

        flask.session['REDIRECT_URL'] = flask.request.url
        flask.session[AUTH_STATE_KEY] = state
        flask.session.permanent = False

        return flask.redirect(uri, code=302)


    def auth_wrapper(self, f):
        """
        Decorator that wraps a Flask route handler to enforce authorization.
        If AUTH_FLASK_ROUTES is enabled, checks if the current user is authorized using
        the is_authorized() method. If not authorized, returns a 403 Forbidden response.
        Otherwise, proceeds to execute the original route handler.
        Args:
            f (callable): The Flask route handler function to be wrapped.
        Returns:
            callable: The wrapped function with authorization enforcement.
        """
        def wrap(*args, **kwargs):
            if self.auth_flask_routes:
                if not self.is_authorized():
                    return flask.Response(status=403)
            response = f(*args, **kwargs)
            return response

        return wrap


    def index_auth_wrapper(self, original_index):
        """
        Wraps the given index function with an authorization check.
        If the user is authorized, calls the original index function with the provided arguments.
        Otherwise, initiates a login request.
        Args:
            original_index (callable): The original index function to be wrapped.
        Returns:
            callable: A wrapped function that performs an authorization check before calling the original index function.
        """

        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap


    def login_callback(self):
        """
        Handles the callback from the Auth0 authentication flow.
        This method processes the response from Auth0 after a user attempts to log in.
        It checks for errors, handles denied access, and processes successful authentication.
        If authentication is successful, it fetches the user's token and user information,
        sets relevant cookies, and redirects the user to the intended URL.
        Returns:
            str or flask.Response: A message indicating the result of the authentication,
            or a Flask redirect response with user information set in cookies.
        """
        if 'error' in flask.request.args:
            if flask.request.args.get('error') == 'access_denied':
                return 'You denied access.'
            return 'Error encountered.'

        if 'code' not in flask.request.args and 'state' not in flask.request.args:
            return self.login_request()
        else:
            # user is successfully authenticated
            auth0 = self.__get_auth(state=flask.session[AUTH_STATE_KEY])
            try:
                token = auth0.fetch_token(
                    self.auth_token_uri,
                    client_secret=self.client_secret,
                    authorization_response=flask.request.url
                )
            except Exception as e:
                return e.__dict__

            auth0 = self.__get_auth(token=token)
            resp = auth0.get(self.auth_user_info_url)
            if resp.status_code == 200:
                user_data = resp.json()
                r = flask.redirect(flask.session['REDIRECT_URL'])
                r.set_cookie(COOKIE_AUTH_USER_NAME, user_data['name'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_ACCESS_TOKEN, token['access_token'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_NICKNAME, user_data['nickname'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_EMAIL, user_data['email'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_FIRST_NAME, user_data.get('given_name', ''), max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_LAST_NAME, user_data.get('family_name',''), max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_PICTURE_URL, user_data.get('picture',''), max_age=COOKIE_EXPIRY)
                flask.session[user_data['name']] = token['access_token']
                return r

            return 'Could not fetch your information.'


    @staticmethod
    def __get_auth(state=None, token=None, client_id=os.getenv('AUTH0_AUTH_CLIENT_ID')):
        """
        Create and return an OAuth2Session instance based on provided state or token.
        Args:
            state (str, optional): The OAuth2 state parameter for CSRF protection. Defaults to None.
            token (dict, optional): An existing OAuth2 token for session authentication. Defaults to None.
            client_id (str, optional): The Auth0 client ID. Defaults to the environment variable.
        Returns:
            OAuth2Session: An instance of OAuth2Session configured with the given state or token.
        Notes:
            - If `token` is provided, returns a session authenticated with the token.
            - If `state` is provided (and no token), returns a session with the state and redirect URI.
            - If neither is provided, returns a session with only the redirect URI.
        """
        if token:
            return OAuth2Session(client_id, token=token)
        if state:
            return OAuth2Session(
                client_id,
                state=state,
                redirect_uri=urljoin(flask.request.base_url, AUTH_REDIRECT_URI)
            )
        return OAuth2Session(
            client_id,
            redirect_uri=urljoin(flask.request.base_url, AUTH_REDIRECT_URI),
        )


    @staticmethod
    def logout(client_id=os.getenv('AUTH0_AUTH_CLIENT_ID'), logout_url=os.getenv('AUTH0_LOGOUT_URL')):
        """
        Logs out the current user by clearing the session data and deleting authentication-related cookies.
        Redirects the user to the Auth0 logout endpoint with appropriate parameters.
        Args:
            client_id (str): The Auth0 client ID.
            logout_url (str): The Auth0 logout URL.
        Returns:
            flask.Response: A redirect response to the Auth0 logout endpoint with cookies deleted.
        """
        # Clear session stored data
        flask.session.clear()
        
        # Redirect user to logout endpoint
        return_url = flask.request.host_url
        params = {'returnTo': return_url, 'client_id': client_id}
        r = flask.redirect(logout_url + '?' + urlencode(params))
        r.delete_cookie(COOKIE_AUTH_USER_NAME)
        r.delete_cookie(COOKIE_AUTH_ACCESS_TOKEN)
        r.delete_cookie(COOKIE_AUTH_NICKNAME)
        r.delete_cookie(COOKIE_AUTH_EMAIL)
        r.delete_cookie(COOKIE_AUTH_FIRST_NAME)
        r.delete_cookie(COOKIE_AUTH_LAST_NAME)
        r.delete_cookie(COOKIE_AUTH_PICTURE_URL)
        
        return r
    

def get_user_name():
    """
    Retrieves the authenticated user's name from the request cookies.
    Returns:
        str or None: The value of the COOKIE_AUTH_USER_NAME cookie if present, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_USER_NAME)


def get_user_nickname():
    """
    Retrieves the user's nickname from the authentication cookie.
    Returns:
        str or None: The nickname of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_NICKNAME)


def get_user_email():
    """
    Retrieves the authenticated user's email from the request cookies.
    Returns:
        str or None: The email of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_EMAIL)


def get_user_first_name():
    """
    Retrieves the authenticated user's first name from the request cookies.
    Returns:
        str or None: The first name of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_FIRST_NAME)


def get_user_last_name():
    """
    Retrieves the authenticated user's last name from the request cookies.
    Returns:
        str or None: The last name of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_LAST_NAME)


def get_user_picture_url():
    """
    Retrieves the authenticated user's picture URL from the request cookies.
    Returns:
        str or None: The picture URL of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_PICTURE_URL)


def get_user_access_token():
    """
    Retrieves the authenticated user's access token from the request cookies.
    Returns:
        str or None: The access token of the authenticated user if present in the cookie, otherwise None.
    """
    return flask.request.cookies.get(COOKIE_AUTH_ACCESS_TOKEN)


def get_user_info():
    """
    Gathers user information from the request cookies.
    Returns:
        dict: A dictionary containing the user's information.
    """
    return {
        "name": get_user_name(),
        "nickname": get_user_nickname(),
        "email": get_user_email(),
        "given_name": get_user_first_name(),
        "family_name": get_user_last_name(),
        "picture": get_user_picture_url(),
        "access_token": get_user_access_token(),
    }