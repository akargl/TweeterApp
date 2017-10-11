from flask import request, redirect, url_for, make_response, g, abort
from app import app
from helpers import login_required, admin_required
from models import Session, User, Post, Message
from templates import TemplateManager

# TODO:
#
# Minimal template engine
# Session handling
#   + Expirary date for cookies
# Admin Features
#  + What happens if we delete the last admin?
#
# Deployment via Docker
# Readme
# Sample Content
# Tests
# Remove sensitive debug output (e.g. passwords)
# User pbkdf2 for password hash
#
# Database:
# Foreign key handling
# Size limits for database entries

def render_index(errors=[]):
    posts = Post.get_posts_by_user_id(g.user.id)
    resp = ""
    if len(errors):
        resp + "Errors: " + " ".join(errors)
    resp += "Content: " + " ".join(p.content for p in posts)
    return resp


@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    # Post: params[content, file]
    if request.method == 'GET':
        return render_index()
    else:
        content = request.form['content']
        # TODO: XSS sanitizing
        post = Post.create(g.user.id, content)
        if not post:
            return render_index(['Could not create post'])
        return render_index()


@app.route("/login", methods=['GET', 'POST'])
def login():
    # Post: params[username, password]
    if request.method == 'GET':
        return TemplateManager.get_login_template()
    else:
        username = request.form['username']
        password = request.form['password']
        # TODO: XSS sanitizing

        app.logger.debug("User: {:s}:{:s}".format(username, password))
        user = Session.active_user(request.cookies.get(Session.SESSION_KEY))
        if user:
            # Already logged in
            return redirect(url_for('index'), code=303)

        salt = User.get_salt(username)
        if not salt:
            # User not found
            return TemplateManager.get_login_template(["User not found"])

        _, hashed_password = User.create_hashed_password(salt, password)

        # TODO: Constant time implementation
        user = User.get_and_validate_user(username, hashed_password)
        if not user:
            # TODO: error handling
            return TemplateManager.get_login_template(["Invalid password"])

        result, session_token = Session.new_session(user)
        if not result:
            # TODO: Add error handling
            pass

        # Make the response and set the cookie
        url = url_for(request.args.get('next', 'index'))
        response = make_response(redirect(url, code=303))
        app.logger.debug("session_token: {:s}".format(session_token))
        response.set_cookie(Session.SESSION_KEY, session_token)

        return response


@app.route("/logout")
@login_required
def logout():
    Session.delete(g.user.id, g.session_token)
    return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    # Post: params[username, password]
    user = Session.active_user(request.cookies.get(Session.SESSION_KEY))
    if user:
        # Already logged in
        return redirect(url_for('index'))

    if request.method == 'GET':
        return TemplateManager.get_register_template()
    else:
        errors = []
        username = request.form['username']
        password = request.form['password']

        # TODO: XSS sanitizing

        # Check password policy
        if len(username) < 1 or len(username) > User.MAX_USERNAME_LEN:
            errors.append('Length of username invalid. Maximum length: {:d}'.format(User.MAX_USERNAME_LEN))
        # TODO: Check username for characters and numbers only
        if len(password) < User.MIN_PASSWORD_LEN or len(password) > User.MAX_PASSWORD_LEN:
            errors.append('Invalid password length. Minimum length: {:d}, Maximum length: {:d}'.format(User.MIN_PASSWORD_LEN, User.MAX_PASSWORD_LEN))

        if len(errors):
            return TemplateManager.get_register_template(errors)

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, salt, hashed_password)
        if not user:
            # User already exists
            errors.append('User already exists')
            return TemplateManager.get_register_template(errors)

        return redirect(url_for('login'), code=303)


@app.route("/deregister")
@login_required
def deregister():
    g.user.delete()
    g.user = None
    return redirect(url_for('login'))


def render_messages(error=None):
    messages = Message.get_messages_by_user_id(g.user.id)
    resp = ""
    if error:
        resp = "Error: " + error
    resp += "Messages: " + " ".join(m.content for m in messages)
    return resp


@app.route("/messages", methods=['GET', 'POST'])
@login_required
def messages():
    # Post: params[receipient, content, file]
    if request.method == 'GET':
        return render_messages()
    else:
        recipient_id = int(request.form['recipient_id'])
        content = request.form['content']
        file = request.files.get('file', None)
        # TODO: XSS handling
        recipient = User.get_user_by_id(recipient_id)
        if not recipient:
            # Invalid recipient
            return render_messages('Invalid recipient')

        status = Message.create(g.user.id, recipient_id, content, file)
        if not status:
            return render_messages('Could not send message')

        return redirect(url_for('messages'), code=303)


@app.route("/messages/<int:id>")
@login_required
def message():
    return ""


@app.route("/users/")
@login_required
def users():
    users = User.get_all()
    return " ".join(u.username for u in users)


@app.route("/users/<int:id>", methods=['GET', 'PUT', 'DELETE'])
def user(id):
    app.logger.debug("Request " + request.method)
    if request.method == 'GET':
        return get_user(id)
    else:
        return update_delete_user(id)


@login_required
def get_user(id):
    user = User.get_user_by_id(id)
    if not user:
        abort(404)

    posts = Post.get_posts_by_user_id(user.id)
    resp = "User: " + user.username
    resp += " Content " + " ".join(p.content for p in posts)
    return resp


@admin_required
def update_delete_user(id):
    user = User.get_user_by_id(id)
    if not user:
        abort(404)

    if request.method == 'PUT':
        # TODO: XSS handling
        is_admin = request.form['is_admin'] == "1"
        user.change_role(is_admin)
        return redirect(url_for('user', id=id), code=303)
    else:
        # TODO: user.delete() kills all sessions. Does this have a side effect
        # for currently active users?
        user.delete()
        return redirect(url_for('users'), code=303)


@app.route("/api/file/<string:id>")
@login_required
def api_get_file():
    return ""


@app.route("/api/users")
@admin_required
def api_get_users():
    # TODO: #Different auth handling the API?
    return ""
