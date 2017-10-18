import httplib
from functools import wraps
from flask import g, request, redirect, url_for, abort
from models import Session, User
from app import app


def user_from_credentials():
    auth = request.authorization
    if not auth:
        return None
    username = auth.username
    password = auth.password

    if username is None or password is None:
        return None

    app.logger.debug('Find User from credentials: username: {:s}, PW: {:s}'.format(username, password))

    username = username.strip()
    salt = User.get_salt(username)
    if not salt:
        return None

    app.logger.debug('Found salt for user')

    _, hashed_password = User.create_hashed_password(salt, password)
    user = User.get_and_validate_user(username, hashed_password)
    return user


def user_from_session():
    g.session_token = request.cookies.get(Session.SESSION_KEY)
    return Session.active_user(g.session_token)


def get_user():
    session_user = user_from_session()
    if session_user is not None:
        app.logger.debug("Session found for '" + session_user.username + "'")
        return session_user
    credentials_user = user_from_credentials()
    return credentials_user


def authentication_required(admin=False, redirect_to_login=True):
    def _authentication_required(func):
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            user = get_user()
            if user is None or (admin and not user.is_admin):
                if redirect_to_login:
                    return redirect(url_for('login', next=request.url))
                return abort(httplib.UNAUTHORIZED)
            g.user = user
            return func(*args, **kwargs)
        return func_wrapper
    return _authentication_required
