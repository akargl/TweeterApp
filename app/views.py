import os
import httplib
import datetime
from flask import request, redirect, url_for, make_response, g, abort, send_file, jsonify
from app import app
from helpers import authentication_required
from models import Session, User, Post, Message, FileWrapper
from templates import TemplateManager

"""
# Security considerations
## Password storage/User authentication
* concatenate password with random salt -> hash it -> store hash and salt in db
* use slow/resource intensive hash algo (e.g. scrypt or bcrypt)
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

@app.after_request
def apply_headers(response):
    # Enable XSS protection for Google Chrome and Internet Explorer
    response.headers["X-XSS-Protection"] = '1; mode=block'
    # Disallow embedding of the site into other pages via <frame>,...
    response.headers["X-Frame-Options"] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # No downgrade attacks. Everything HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    csp_policy = "default-src 'none'; font-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self';"
    response.headers['Content-Security-Policy'] = csp_policy
    return response


@app.route("/", methods=['GET', 'POST'])
@authentication_required()
def index():
    # Post: params[content, file]
    if request.method == 'GET':
        posts = Post.get_all()
        return TemplateManager.get_index_template(posts)
    else:
        post_content = request.form['post_content'].strip()
        posts = Post.get_all()

        attachment = request.files.get('attachment')
        if attachment:
            errors = FileWrapper.is_valid_file(attachment)
            if len(errors):
                return TemplateManager.get_index_template(posts, errors)

        if post_content == "" and (attachment is None or (
                attachment is not None and attachment.filename == '')):
            return TemplateManager.get_index_template(
                posts, ["Post can't be empty"])

        filename = None
        if attachment:
            wrapper = FileWrapper.create(attachment, [g.user.id], False)
            if not wrapper:
                return TemplateManager.get_index_template(
                    posts, ['Could not upload file'])
            filename = wrapper.get_filename()

        post = Post.create(g.user.id, post_content, filename)
        if not post:
            return TemplateManager.get_index_template(
                posts, ["Could not create post"])

        # Get new posts
        posts = Post.get_all()
        return TemplateManager.get_index_template(posts, []), httplib.CREATED


@app.route("/login", methods=['GET', 'POST'])
def login():
    # Post: params[username, password]
    if request.method == 'GET':
        # If the user is already logged in, just display the index
        user, _ = Session.active_user(request.cookies.get(Session.SESSION_KEY))
        if user:
            # Already logged in
            return redirect(url_for('index'))

        return TemplateManager.get_login_template()
    else:
        username = request.form['username'].strip()
        password = request.form['password']

        user, _ = Session.active_user(request.cookies.get(Session.SESSION_KEY))
        if user:
            # Already logged in
            return redirect(url_for('index'), code=httplib.SEE_OTHER)

        salt = User.get_salt(username)
        if not salt:
            # User not found
            return TemplateManager.get_login_template(
                ["Invalid Login or password."])

        _, hashed_password = User.create_hashed_password(salt, password)
        user = User.get_and_validate_user(username, hashed_password)
        if not user:
            return TemplateManager.get_login_template(
                ["Invalid Login or password."])

        result, session_token, csrf_token = Session.new_session(user)
        if not result:
            return TemplateManager.get_login_template(
                ["Could not create session"])

        # Make the response and set the cookie
        url = url_for('index')
        response = make_response(redirect(url, code=httplib.SEE_OTHER))

        expire_date = datetime.datetime.now()
        expire_date = expire_date + \
            datetime.timedelta(days=app.config['MAX_SESSION_AGE_DAYS'])
        response.set_cookie(Session.SESSION_KEY, session_token, httponly=True,
                            expires=expire_date)
        return response


@app.route("/logout", methods=['POST'])
@authentication_required()
def logout():
    Session.delete(g.user.id, g.session_token)
    return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    # Post: params[username, password]
    user, _ = Session.active_user(request.cookies.get(Session.SESSION_KEY))
    if user:
        # Already logged in
        return redirect(url_for('index'))

    if request.method == 'GET':
        return TemplateManager.get_register_template()
    else:
        errors = []
        username = request.form['username'].strip()
        password = request.form['password']

        errors = User.verify_credential_policy(username, password)
        if len(errors):
            return TemplateManager.get_register_template(errors)

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, salt, hashed_password)
        if user is None:
            errors.append('User already exists')
            return TemplateManager.get_register_template(errors)

        return redirect(url_for('login'), code=httplib.SEE_OTHER)


@app.route("/deregister", methods=['POST'])
@authentication_required()
def deregister():
    g.user.delete()
    g.user = None
    return redirect(url_for('login'))


@app.route("/messages", methods=['GET', 'POST'])
@authentication_required()
def messages():
    # Post: params[recipient, content, file]
    if request.method == 'GET':
        messages = Message.get_messages_for_user_id(g.user.id)
        return TemplateManager.get_messages_template(messages)
    else:
        message_content = request.form['message_content'].strip()
        recipient_name = request.form['message_recipient'].strip()

        messages = Message.get_messages_for_user_id(g.user.id)

        recipient = User.get_user_by_name(recipient_name)
        if not recipient:
            return TemplateManager.get_messages_template(
                messages, ["Unknown recipient"])

        attachment = request.files.get('attachment')
        if attachment:
            errors = FileWrapper.is_valid_file(attachment)
            if len(errors):
                return TemplateManager.get_messages_template(messages, errors)
        if message_content == "" and (attachment is None or (
                attachment is not None and attachment.filename == '')):
            return TemplateManager.get_messages_template(
                messages, ["Message can't be empty"])

        filename = None
        if attachment:
            wrapper = FileWrapper.create(
                attachment, [g.user.id, recipient.id], True)
            if not wrapper:
                return TemplateManager.get_index_template(
                    posts, ['Could not upload file'])
            filename = wrapper.get_filename()

        message = Message.create(
            g.user.id, recipient.id, message_content, filename)
        if not message:
            return TemplateManager.get_messages_template(
                messages, ["Could not create message"])

        messages = Message.get_messages_for_user_id(g.user.id)
        return TemplateManager.get_messages_template(messages), httplib.CREATED


@app.route("/administration", methods=['GET'])
@authentication_required(admin=True)
def administration():
    users = User.get_all()
    return TemplateManager.get_administration_template(users, [])


@app.route("/users/<int:id>", methods=['PUT', 'DELETE'])
@authentication_required(admin=True)
def user(id):
    app.logger.debug("Request " + request.method)
    user = User.get_user_by_id(id)
    if not user:
        abort(httplib.NOT_FOUND)

    if user.is_admin:
        abort(httplib.UNAUTHORIZED)

    if request.method == 'PUT':
        is_admin = request.form['is_admin'] == "1"
        status = user.change_role(is_admin)
        # TODO: if status is None -> error?
    elif request.method == 'DELETE':
        user.delete()
    return ('', httplib.NO_CONTENT)


@app.route("/api/files")
@authentication_required(redirect_to_login=False)
def api_files():
    """ Get a json list of all accessible files """
    files = FileWrapper.get_files(g.user.id)
    return jsonify([f.serialize() for f in files])


@app.route("/api/files/<path:filename>")
@authentication_required(redirect_to_login=False)
def api_get_file(filename):
    f_wrapper = FileWrapper.get_by_filename(filename, g.user.id)
    if f_wrapper is None:
        return abort(httplib.NOT_FOUND)
    storage_path = f_wrapper.get_storagepath()

    app.logger.debug("Requested file {:s}".format(storage_path))

    # Don't serve symlinks
    if os.path.islink(storage_path):
        app.logger.debug(
            "Requested file {:s} is a symlink".format(storage_path))
        abort(httplib.FORBIDDEN)

    return send_file(storage_path)


@app.route("/api/users")
@authentication_required(admin=True, redirect_to_login=False)
def api_get_users():
    return jsonify([e.serialize() for e in User.get_all()])
