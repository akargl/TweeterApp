from functools import wraps
from flask import g, request, redirect, url_for, abort
from models import Session


def get_user():
    g.session_token = request.cookies.get(Session.SESSION_KEY)
    return Session.active_user(g.session_token)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user()
        if user is None:
            return redirect(url_for('login', next=request.url))
        g.user = user

        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user()
        if user is None:
            return redirect(url_for('login', next=request.url))
        if not user.is_admin:
            abort(401)
        g.user = user
        return f(*args, **kwargs)
    return decorated_function
