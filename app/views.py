import os
import httplib
import datetime
import requests
from base64 import b64encode
from flask import request, redirect, url_for, make_response, g, abort, send_file, jsonify, flash
from app import app
from helpers import authentication_required, validate_recaptcha, unautenticated_csrf_protection
from models import Session, User, Post, Message, FileWrapper, PasswordRecoveryTokens
from templates import TemplateManager


def set_cookie(response, key, value, timeout):
    expire_date = datetime.datetime.now()
    expire_date = expire_date + \
        datetime.timedelta(seconds=timeout)
    response.set_cookie(key, value, httponly=True, expires=expire_date, secure=True)


@app.before_request
def csp_generate_nonce():
    nonce = os.urandom(32)
    g.csp_nonce = b64encode(nonce).decode('utf-8')


@app.after_request
def apply_headers(response):
    csrf_cookie = g.get('csrf_cookie')
    if csrf_cookie:
        set_cookie(response, Session.CSRF_KEY, csrf_cookie, app.config['MAX_CSRF_TOKEN_AGE'])

    # Enable XSS protection for Google Chrome and Internet Explorer
    response.headers["X-XSS-Protection"] = '1; mode=block'
    # Disallow embedding of the site into other pages via <frame>,...
    response.headers["X-Frame-Options"] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Download-Options'] = 'noopen'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # No downgrade attacks. Everything HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    csp_nonce = g.get('csp_nonce', '')
    csp_policy = "default-src 'none'; " \
                 "font-src 'self' data:; " \
                 "style-src 'self' 'unsafe-hashed-attributes' 'sha256-MammJ3J+TGIHdHxYsGLjD6DzRU0ZmxXKZ2DvTePAF0o=' 'sha256-6iA6WDOL1mgUULZ6GSs2OOfP4eMuu6iI5agxCjK2m2A=' 'sha256-+zzuded9+DHoztKyASJeCkVU0gxvYNWMUIQM7x//CB4=' 'sha256-ldCXMle1JJUAD9eAjLdSuPIgIBcTcBecWlaXs0A2y4M=' 'sha256-WCg1a4AhMGgFRCQG5w+hgG+Q2j8Ygrbd+2dgjByIOIU=' 'sha256-Awu6hl63MCY3jiYHaDclrL7Lic9KcEalXm2o/i3e0v8='; " \
                 "script-src 'self' 'nonce-{0}'; " \
                 "img-src 'self' data:;" \
                 "child-src www.google.com; " \
                 "connect-src 'self'; " \
                 "report-uri {1}".format(csp_nonce, app.config.get('CSP_REPORT_URI', ''))
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
@unautenticated_csrf_protection
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

        if app.config.get('RECAPTCHA_ENABLED', False):
            response = request.form.get('g-recaptcha-response', '')
            if not response:
                return TemplateManager.get_login_template(["Invalid Captcha"])

            remote_ip = request.remote_addr
            if not validate_recaptcha(response, remote_ip):
                return TemplateManager.get_login_template(["Invalid Captcha"])

        user = User.check_password(username, password)
        if not user:
            return TemplateManager.get_login_template(
                ["Invalid Login or password"])

        result, session_token, csrf_token = Session.new_session(user)
        if not result:
            return TemplateManager.get_login_template(
                ["Could not create session"])

        # Make the response and set the cookie
        url = url_for('index')
        response = make_response(redirect(url, code=httplib.SEE_OTHER))

        set_cookie(response, Session.SESSION_KEY, session_token, app.config['MAX_SESSION_AGE'])
        return response


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        return TemplateManager.get_reset_password_template()
    elif request.method == 'POST':
        email = request.form['email'].strip()

        user = User.get_user_by_email(email)
        if user:
            token = PasswordRecoveryTokens.create(user)
            if not token:
                return

            app.logger.debug("Token is {:s}".format(token.token))
            
            key = 'key-3092d1f7006c44cbc64c2aa22f700c0d'
            request_url = 'https://api.mailgun.net/v3/sandboxb047e885447c44809620ff0b68b4d6ce.mailgun.org/messages'
            
            request = requests.post(request_url, auth=('api', key), data={
                'from': 'noreply@tweeterapp.com',
                'to': user.email,
                'subject': 'Tweeter - Password Recovery Token',
                'html': '<a href={:s}/update_password/{:s}>Reset your password by clicking this link</a>'.format(request.host, token)
            })
       
        # First step create a random token
        # Store this token associated with the user
        # Send this url with token,
        # build a view view where the user can enter the new password
        app.logger.debug('If your email address exists in our database, you will receive a password recovery link at your email address in a few minutes.')
        return redirect(url_for('index'))


@app.route("/update_password/<token>", methods=['GET', 'POST'])
def update_password(token):
    token = PasswordRecoveryTokens.get_token(token)
    if not token:
        app.logger.debug('Invalid reset token')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return TemplateManager.get_update_password_template(token.token)
    elif request.method == 'POST':
        password = request.form['password']
        errors = user.update_password(password)
        if len(errors):
            app.logger.debug(errors)
            app.logger.debug('Could not update password')
        # Delete the used token
        token.delete()
        return redirect(url_for('login'))


@app.route("/logout", methods=['POST'])
@authentication_required()
def logout():
    Session.delete(g.user.id, g.session_token)

    return ("", httplib.NO_CONTENT)


@app.route("/register", methods=['GET', 'POST'])
@unautenticated_csrf_protection
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
        email = request.form['email'].strip()
        password = request.form['password']

        if app.config.get('RECAPTCHA_ENABLED', False):
            response = request.form.get('g-recaptcha-response', '')
            if not response:
                return TemplateManager.get_register_template(["Invalid Captcha"])

            remote_ip = request.remote_addr
            if not validate_recaptcha(response, remote_ip):
                return TemplateManager.get_register_template(["Invalid Captcha"])

        errors = User.verify_credential_policy(username, password)
        if len(errors):
            return TemplateManager.get_register_template(errors)

        salt, hashed_password = User.create_salt_and_hashed_password(password)
        user = User.create(username, email, salt, hashed_password)
        if user is None:
            errors.append('User already exists')
            return TemplateManager.get_register_template(errors)

        return redirect(url_for('login'), code=httplib.SEE_OTHER)


@app.route("/deregister", methods=['GET', 'POST'])
@authentication_required()
def deregister():
    if request.method == 'GET':
        return TemplateManager.get_deregister_template()
    elif request.method == 'POST':
        password = request.form['user_password']
        app.logger.debug("Request " + request.method)

        if not User.check_password(g.user.username, password):
            return TemplateManager.get_deregister_template(['Invalid password'])

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
    password = request.form.get('password', "")
    if not User.check_password(g.user.username, password):
        abort(httplib.UNAUTHORIZED)

    user = User.get_user_by_id(id)
    if not user:
        abort(httplib.NOT_FOUND)

    #can't delete or demote other admins
    if user.is_admin:
        abort(httplib.UNAUTHORIZED)

    if request.method == 'PUT':
        is_admin = request.form['is_admin'] == "1"
        status = user.change_role(is_admin)
    elif request.method == 'DELETE':
        user.delete()
    return ('', httplib.NO_CONTENT)


@app.route("/api/files")
@authentication_required(redirect_to_login=False)
def api_files():
    """ Get a json list of all accessible files """
    files = FileWrapper.get_files(g.user.id)
    return jsonify([f.serialize() for f in files])


@app.route("/api/files/<int:fileid>")
@authentication_required(redirect_to_login=False)
def api_get_file(fileid):
    f_wrapper = FileWrapper.get_by_id(fileid, g.user.id)
    if f_wrapper is None:
        return abort(httplib.NOT_FOUND)
    storage_path = f_wrapper.get_storagepath()

    app.logger.debug("Requested file {:s}".format(storage_path))

    # Don't serve symlinks
    if os.path.islink(storage_path):
        app.logger.debug(
            "Requested file {:s} is a symlink".format(storage_path))
        abort(httplib.FORBIDDEN)

    return send_file(storage_path, as_attachment=True, 
                     attachment_filename=f_wrapper.get_filename())


@app.route("/api/users")
@authentication_required(admin=True, redirect_to_login=False)
def api_get_users():
    return jsonify([e.serialize() for e in User.get_all()])
