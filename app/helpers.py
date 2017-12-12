import os
import httplib
import json
import urllib2 as http
from base64 import b64encode
from functools import wraps
from flask import abort, g, redirect, request, url_for
from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer
from werkzeug import url_encode
from werkzeug.security import safe_str_cmp


def get_or_create_key(filename):
    try:
        app.logger.debug('Trying to open key file  {:s}'.format(filename))
        with open(filename, 'r') as f:
            app.logger.debug('Database key file exists')
            key = f.read()
    except IOError:
        app.logger.debug('No keyfile found. Creating new keyfile {:s}'.format(filename))
        key = os.urandom(64)
        key = b64encode(key)
        with open(filename, 'w') as f:
            f.write(key)
    return key


from app import app
from models import Session, User


def user_from_credentials():
    auth = request.authorization
    if not auth:
        return None
    username = auth.username
    password = auth.password

    if username is None or password is None:
        return None

    username = username.strip()
    salt = User.get_salt(username)
    if not salt:
        return None

    _, hashed_password = User.create_hashed_password(salt, password)
    user = User.get_and_validate_user(username, hashed_password)
    return user


def user_from_session():
    g.session_token = request.cookies.get(Session.SESSION_KEY)
    return Session.active_user(g.session_token)


def authentication_required(admin=False, redirect_to_login=True):
    def _authentication_required(func):
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            user, csrf_token = user_from_session()
            if user:
                app.logger.debug(
                    "Login via session cookie for {:s}".format(user.username))
                g.csrf_token = csrf_token
                response = csrf_protection()
                if response:
                    return response
            else:
                # Fallback on HTTP Basic Auth
                user = user_from_credentials()
                if not user:
                    if redirect_to_login:
                        return redirect(url_for('login'))
                    return abort(httplib.UNAUTHORIZED)

            g.user = user
            if admin and not user.is_admin:
                return abort(httplib.UNAUTHORIZED)

            return func(*args, **kwargs)
        return func_wrapper
    return _authentication_required


def csrf_protection():
    if request.method not in app.config['CSRF_METHODS']:
        return

    # Get the CSRF token
    form_csrf_token = request.form.get('csrf-token')
    if not form_csrf_token:
        return abort(httplib.BAD_REQUEST)

    session_csrf_token = g.get('csrf_token')
    if not session_csrf_token:
        return abort(httplib.BAD_REQUEST)

    signer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        signer.loads(form_csrf_token, max_age=app.config['MAX_CSRF_TOKEN_AGE'])
    except SignatureExpired:
        from views import logout
        return logout()
    except BadData:
        abort(httplib.BAD_REQUEST)

    match = safe_str_cmp(form_csrf_token, session_csrf_token)
    if not match:
        return abort(httplib.BAD_REQUEST)


def unautenticated_csrf_protection(func):
    @wraps(func)
    def wrapper(*args, **kwds):
        if request.method not in app.config['CSRF_METHODS']:
            g.csrf_cookie = Session.create_csrf_token()
            return func(*args, **kwds)

        # First CSRF token from the form
        form_csrf_token = request.form.get('csrf-token')
        if not form_csrf_token:
            app.logger.debug('No form token')
            abort(httplib.BAD_REQUEST)

        # Second CSRF token from the cookie
        cookie_csrf_token = request.cookies.get(Session.CSRF_KEY)
        if not cookie_csrf_token:
            app.logger.debug('No cookie')
            abort(httplib.BAD_REQUEST)

        signer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            signer.loads(form_csrf_token, max_age=app.config['MAX_CSRF_TOKEN_AGE'])
        except SignatureExpired:
            app.logger.debug('Signature invalid')
            abort(abort(httplib.BAD_REQUEST))
        except BadData:
            app.logger.debug('bad data')
            abort(abort(httplib.BAD_REQUEST))

        match = safe_str_cmp(form_csrf_token, cookie_csrf_token)
        if not match:
            app.logger.debug('No fmatch')
            abort(httplib.BAD_REQUEST)
        return func(*args, **kwds)
    return wrapper


def validate_recaptcha(response, remote_ip):
    data = url_encode({
        'secret': app.config.get('RECAPTCHA_SECRET_KEY', ''),
        'remoteip': remote_ip,
        'response': response
    })
    http_response = http.urlopen('https://www.google.com/recaptcha/api/siteverify', data.encode('utf-8'))
    if http_response.code != httplib.OK:
        return False

    json_resp = json.loads(http_response.read().encode('utf-8'))
    if json_resp["success"]:
        return True

    return False
