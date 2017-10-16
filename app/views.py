import os
import httplib
from flask import request, redirect, url_for, make_response, g, abort, send_file, jsonify
from app import app
from helpers import authentication_required
from models import Session, User, Post, Message, FileWrapper
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
* set Httponly flag in session cookie to prevent theft via js

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
@authentication_required()
def index():
    # Post: params[content, file]
    if request.method == 'GET':
        posts = Post.get_posts()
        return TemplateManager.get_index_template(posts)
    else:
        post_content = request.form['post_content']
        # TODO: XSS sanitizing

        posts = Post.get_posts()

        attachment_name = None
        if request.files.get('post_attachment'):
            attachment = request.files['post_attachment']
            if attachment.filename != '':
                if not FileWrapper.is_allowed_file(attachment):
                    return TemplateManager.get_index_template(posts, ["Invalid attachment"])
                f_wrapper = FileWrapper.create(attachment, False)
                if f_wrapper is None:
                    return TemplateManager.get_index_template(posts, ["Invalid attachment"])
                attachment_name = f_wrapper.get_filename()

        if post_content.strip() == "" and attachment_name is None:
            return TemplateManager.get_index_template(posts, ["Post can't be empty"])
        post = Post.create(g.user.id, post_content, attachment_name)
        if not post:
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

        username = username.strip()

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
        response.set_cookie(Session.SESSION_KEY, session_token, httponly=True)

        return response


@app.route("/logout")
@authentication_required()
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
        username = request.form['username']
        password = request.form['password']

        username = username.strip()

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        # TODO: XSS sanitizing

        errors = User.verify_credential_policy(username, password)
        if len(errors):
            return TemplateManager.get_register_template(errors)

        app.logger.debug("User: {:s}:{:s}".format(username, password))

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, salt, hashed_password)
        if user is None:
            errors.append('User already exists')
            return TemplateManager.get_register_template(errors)

        return redirect(url_for('login'), code=httplib.SEE_OTHER)


@app.route("/deregister")
@authentication_required()
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
@authentication_required()
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
@authentication_required()
def message():
    return ""


@app.route("/users/")
@authentication_required()
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


@authentication_required()
def get_user(user):
    posts = Post.get_posts_by_user_id(user.id)
    resp = "User: " + user.username
    resp += " Content " + " ".join(p.content for p in posts)
    return resp


#@admin_required
@authentication_required(admin=True)
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

@app.route("/api/file/<path:filename>")
@authentication_required(redirect_to_login=False)
def api_get_file(filename):

    f_wrapper = FileWrapper.get_by_filename(filename)
    if f_wrapper is None:
        return abort(httplib.NOT_FOUND)
    storage_path = f_wrapper.get_storagepath()

    app.logger.debug("Requested file {:s}".format(storage_path))

    # Don't serve symlinks
    if os.path.islink(storage_path):
        app.logger.debug("Requested file {:s} is a symlink".format(storage_path))
        abort(httplib.FORBIDDEN)

    return send_file(storage_path)


@app.route("/api/users")
@authentication_required(admin=True, redirect_to_login=False)
def api_get_users():
    #authenticate_api_user(True)

    return jsonify([e.serialize() for e in User.get_all()])
