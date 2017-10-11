from flask import request, redirect, url_for, make_response, g
from app import app
from helpers import login_required, admin_required
from models import Session, User

# Todos:
#
# Minimal template engine
# Session handling
#   + Expirary date for cookies
# Public messages
# Private Conversations
# Admin Features
#
# Deployment via Docker
# Readme
# Sample Content
# Tests
# Remove sensitive debug output (e.g. passwords)
# Size limits for database entries


@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    for k, v in request.cookies.items():
        app.logger.debug(k)
        app.logger.debug(v)

    # Displays login form if no session as active, else message feed is displayed
    # Post: params[content, file]
    return "Flasky " + g.user.username


@app.route("/login", methods=['GET', 'POST'])
def login():
    # Post: params[username, password]
    if request.method == 'GET':
        return "Login"
    else:
        username = request.form['username']
        password = request.form['password']
        # Todo: XSS sanitizing

        app.logger.debug("User: {:s}:{:s}".format(username, password))
        user = Session.active_user(request.cookies.get(Session.SESSION_KEY))
        if user:
            # Already logged in
            return redirect(url_for('index'))

        salt = User.get_salt(username)
        if not salt:
            # User not found
            return "User not found"

        _, hashed_password = User.create_hashed_password(salt, password)

        # Todo: Constant time implementation
        user = User.get_and_validate_user(username, hashed_password)
        if not user:
            # Todo: error handling
            return "Invalid password"

        result, session_token = Session.new_session(user)
        if not result:
            # Todo: Add error handling
            pass

        # Make the response and set the cookie
        url = url_for(request.args.get('next', 'index'))
        response = make_response(redirect(url))
        app.logger.debug("session_token: {:s}".format(session_token))
        response.set_cookie(Session.SESSION_KEY, session_token)

        return response


@app.route("/logout")
@login_required
def logout():
    Session.delete(g.user.id, g.session_token)
    return redirect(url_for('login'))


def render_register(errors=[]):
    return "Register " + " ".join(errors)


@app.route("/register", methods=['GET', 'POST'])
def register():
    # Post: params[username, password]
    user = Session.active_user(request.cookies.get(Session.SESSION_KEY))
    if user:
        # Already logged in
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_register()
    else:
        errors = []
        username = request.form['username']
        password = request.form['password']

        # Todo: XSS sanitizing

        # Check password policy
        if len(username) < 1 or len(username) > User.MAX_USERNAME_LEN:
            errors.append('Length of username invalid. Maximum length: {:d}'.format(User.MAX_USERNAME_LEN))
        # Todo: Check username for characters and numbers only
        if len(password) < User.MIN_PASSWORD_LEN or len(password) > User.MAX_PASSWORD_LEN:
            errors.append('Invalid password length. Minimum length: {:d}, Maximum length: {:d}'.format(User.MIN_PASSWORD_LEN, User.MAX_PASSWORD_LEN))

        if len(errors):
            return render_register(errors)

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, salt, hashed_password)
        if not user:
            # User already exists
            errors.append('User already exists')
            return render_register(errors)

        return redirect(url_for('login'))


@app.route("/deregister")
@login_required
def deregister():
    Session.delete_all(g.user.id)
    g.user.delete()
    g.user = None
    return redirect(url_for('login'))


@app.route("/messages", methods=['GET', 'POST'])
@login_required
def messages():
    # Post: params[receipient, content, file]
    return ""

@app.route("/messages/<int:id>")
@login_required
def message():
    return ""

@app.route("/api/file/<string:id>")
@login_required
def file():
    return ""

@app.route("/api/users")
@admin_required
def get_users():
    return ""

@app.route("/api/users/<int:id>", methods=['GET', 'PUT', 'DELETE'])
@admin_required
def get_user():
    # PUT: params[is_admin]
    return ""
