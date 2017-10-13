import os
import httplib
from flask import request, redirect, url_for, make_response, g, abort, send_from_directory, jsonify
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
# Size limits for database entries

"""
# Security considerations
## Password storage/User authentication
* concatenate password with random salt -> hash it -> store hash and salt in db
* TODO: use slow/resource intensive hash algo (e.g. scrypt or bcrypt)
* Sessions: generate random token -> set cookie. User presents cookie with token to authenticate requests
* TODO: set Httponly flag in session cookie to prevent theft via js

## SQL Injection
* prepared statements for all sql queries

## XSS Injection
* escape/sanitize all user generated data before output
* escaping depends on usage context
* TODO: Escape before db insertion as well?
    - Need to specify beforehand in which context the data will/can be used
    - Double escape on output. We shouldn't rely on all data in the db being already escaped.
* TODO: safeguard against forgotten output escaping

## CSRF
* TODO: Check headers to verify request is same origin
    * Source: Origin or Referer header
    * Target: Host or X-Forwarded-Host header
    * Target must be source
* TODO: second layer (double cookie, extra token,...)
"""

@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    # Post: params[content, file]
    if request.method == 'GET':
        posts = Post.get_posts()
        return TemplateManager.get_index_template(posts)
    else:
        post_content = request.form['post_content']
        # TODO: XSS sanitizing
        post = Post.create(g.user.id, post_content)
        if not post:
            posts = Post.get_posts()
            return TemplateManager.get_index_template(posts, ["Could not create post"])

        posts = Post.get_posts()
        return TemplateManager.get_index_template(posts, []), httplib.CREATED


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
            return redirect(url_for('index'), code=httplib.SEE_OTHER)

        salt = User.get_salt(username)
        if not salt:
            # User not found
            return TemplateManager.get_login_template(["Invalid Login or password."])

        _, hashed_password = User.create_hashed_password(salt, password)

        user = User.get_and_validate_user(username, hashed_password)
        if not user:
            return TemplateManager.get_login_template(["Invalid Login or password."])

        result, session_token = Session.new_session(user)
        if not result:
            return TemplateManager.get_login_template(["Could not create session"])

        # Make the response and set the cookie
        url = url_for(request.args.get('next', 'index'))
        response = make_response(redirect(url, code=httplib.SEE_OTHER))
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
        app.logger.debug("Received register request")
        errors = []
        # TODO: Why is this changed to get? When not providing the request
        # with the correct form parameters, a 400 Bad Request is rendered
        username = request.form['username']
        password = request.form['password']

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        # TODO: XSS sanitizing

        errors = User.verify_credential_policy(username, password)
        if len(errors):
            return TemplateManager.get_register_template(errors)

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, salt, hashed_password)
        if not user:
            errors.append('User already exists')
            return TemplateManager.get_register_template(errors)

        return redirect(url_for('login'), code=httplib.SEE_OTHER)


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
    # Post: params[recipient, content, file]
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

        return render_messages(), httplib.CREATED


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
    user = User.get_user_by_id(id)
    if not user:
        abort(httplib.NOT_FOUND)

    if request.method == 'GET':
        return get_user(user)
    else:
        return update_delete_user(user)


@login_required
def get_user(user):
    posts = Post.get_posts_by_user_id(user.id)
    resp = "User: " + user.username
    resp += " Content " + " ".join(p.content for p in posts)
    return resp


@admin_required
def update_delete_user(user):
    if request.method == 'PUT':
        # TODO: XSS handling
        is_admin = request.form['is_admin'] == "1"
        user.change_role(is_admin)
        return redirect(url_for('user', id=user.id), code=httplib.SEE_OTHER)
    else:
        # TODO: user.delete() kills all sessions. Does this have a side effect
        # for currently active users?
        user.delete()
        return redirect(url_for('users'), code=httplib.SEE_OTHER)


# TODO: Add authentication
@app.route("/api/file/<path:filename>")
# @login_required
def api_get_file(filename):
    # Get absolute path of the file
    upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])

    abs_filename = os.path.join(upload_folder, filename)
    app.logger.debug("Requested file {:s}".format(abs_filename))

    # Don't serve symlinks
    if os.path.islink(abs_filename):
        app.logger.debug("Requested file {:s} is a symlink".format(abs_filename))
        abort(httplib.NOT_FOUND)

    return send_from_directory(upload_folder, filename, as_attachment=True)


@app.route("/api/users")
# @admin_required
def api_get_users():
    # TODO: #Different auth handling the API?
    app.logger.debug(app.config['JSONIFY_MIMETYPE'])

    return jsonify([e.serialize() for e in User.get_all()])
